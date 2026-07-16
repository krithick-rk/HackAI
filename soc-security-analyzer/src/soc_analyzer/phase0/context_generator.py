import os
import sys
import re
import json
import subprocess
import http.client
from typing import Dict, Any, List, Set, Tuple
from src.soc_analyzer.common.fs_utils import write_json_artifact, read_json_artifact
from src.soc_analyzer.preprocessing.comment_stripper import strip_comments

# Keywords for secret signals
SECRET_KEYWORDS = ["key", "secret", "password", "priv", "credential"]

# LLM Fallback Client
def call_llm_fallback(module_name: str, files: List[str]) -> Dict[str, Any] | None:
    """
    Reads the module source files and prompts an LLM to parse them if Python extraction fails.
    Prioritizes Anthropic, then Gemini, then OpenAI.
    """
    api_keys = {
        "anthropic": os.environ.get("ANTHROPIC_API_KEY"),
        "gemini": os.environ.get("GEMINI_API_KEY"),
        "openai": os.environ.get("OPENAI_API_KEY")
    }
    
    # Read files content
    src_content = ""
    for f in files:
        if os.path.exists(f):
            try:
                with open(f, 'r', encoding='utf-8', errors='ignore') as fh:
                    src_content += f"// File: {os.path.basename(f)}\n" + fh.read() + "\n\n"
            except Exception:
                pass
                
    if not src_content:
        return None
        
    prompt = f"""You are an expert hardware security engineer. Parse the following SystemVerilog/Verilog source code files for the module '{module_name}' and extract its structural context.
Return ONLY a valid JSON object matching this schema (do not include markdown wrapping or explanation):
{{
  "ports": [
    {{"name": "port_name", "direction": "input|output|inout", "width": "[width:0] or simple string", "type": "logic|wire|etc"}}
  ],
  "instantiations": [
    {{"module_name": "child_module", "instance_name": "u_child"}}
  ],
  "assignments": [
    {{"target": "lhs_signal", "sources": ["rhs_signal1", "rhs_signal2"]}}
  ],
  "clocks": ["clk_signal_name"],
  "resets": ["rst_signal_name"]
}}

Here is the source code:
{src_content}
"""

    response_text = ""
    
    try:
        if api_keys["anthropic"]:
            print(f"   [LLM Fallback] Using Anthropic (Claude) for module {module_name}...")
            conn = http.client.HTTPSConnection("api.anthropic.com")
            headers = {
                "x-api-key": api_keys["anthropic"],
                "anthropic-version": "2023-06-01",
                "content-type": "application/json"
            }
            payload = {
                "model": "claude-3-5-sonnet-20240620",
                "max_tokens": 4000,
                "messages": [{"role": "user", "content": prompt}]
            }
            conn.request("POST", "/v1/messages", json.dumps(payload), headers)
            res = conn.getresponse()
            data = res.read().decode("utf-8")
            resp_obj = json.loads(data)
            response_text = resp_obj["content"][0]["text"]
            
        elif api_keys["gemini"]:
            print(f"   [LLM Fallback] Using Gemini for module {module_name}...")
            conn = http.client.HTTPSConnection("generativelanguage.googleapis.com")
            headers = {"content-type": "application/json"}
            payload = {
                "contents": [{"parts": [{"text": prompt}]}]
            }
            url = f"/v1beta/models/gemini-2.5-flash:generateContent?key={api_keys['gemini']}"
            conn.request("POST", url, json.dumps(payload), headers)
            res = conn.getresponse()
            data = res.read().decode("utf-8")
            resp_obj = json.loads(data)
            response_text = resp_obj["candidates"][0]["content"]["parts"][0]["text"]
            
        elif api_keys["openai"]:
            print(f"   [LLM Fallback] Using OpenAI for module {module_name}...")
            conn = http.client.HTTPSConnection("api.openai.com")
            headers = {
                "Authorization": f"Bearer {api_keys['openai']}",
                "content-type": "application/json"
            }
            payload = {
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 4000
            }
            conn.request("POST", "/v1/chat/completions", json.dumps(payload), headers)
            res = conn.getresponse()
            data = res.read().decode("utf-8")
            resp_obj = json.loads(data)
            response_text = resp_obj["choices"][0]["message"]["content"]
        else:
            print(f"   [LLM Fallback] No API key present. Fallback to Python-only parsing.")
            return None
            
        # Extract JSON from response text
        match = re.search(r"\{.*\}", response_text, re.DOTALL)
        if match:
            return json.loads(match.group(0))
        return json.loads(response_text)
    except Exception as e:
        print(f"   [LLM Fallback] Failed to get response or parse JSON: {e}")
        return None

# Pure Python fallback parser
def fallback_python_parse(files: List[str], module_name: str) -> Dict[str, Any]:
    """
    Parses Verilog/SystemVerilog files using regex to extract ports, instantiations,
    assignments, and clock/reset signals.
    """
    ports = []
    instantiations = []
    assignments = []
    clocks = set()
    resets = set()
    
    # Simple regexes
    port_pattern = re.compile(r"\b(input|output|inout)\s+(?:wire|reg|logic)?\s*(\[[^\]]+\])?\s*(\w+)", re.IGNORECASE)
    # Match instantiations: mod_name inst_name (...)
    inst_pattern = re.compile(r"\b([a-zA-Z_]\w*)\s+(?:#\s*\([^)]*\)\s*)?([a-zA-Z_]\w*)\s*\(")
    # Match assignments: assign lhs = rhs;
    assign_pattern = re.compile(r"\bassign\s+([a-zA-Z_]\w*(?:\.\w+)*)\s*=\s*([^;]+);")
    # Match non-blocking/blocking inside always blocks: lhs <= rhs; or lhs = rhs;
    always_assign_pattern = re.compile(r"\b([a-zA-Z_]\w*)\s*(<=|=)\s*([^;]+);")
    
    # Set of reserved keywords to skip module instantiations on
    reserved = {"module", "package", "generate", "begin", "if", "else", "case", "assign", "always", "initial", "always_ff", "always_comb", "always_latch", "assert", "cover", "assume"}

    for f in files:
        if not os.path.exists(f):
            continue
        try:
            with open(f, 'r', encoding='utf-8', errors='ignore') as fh:
                content = strip_comments(fh.read())
            
            # Find ports
            for match in port_pattern.finditer(content):
                dir_, width, p_name = match.groups()
                ports.append({
                    "name": p_name.strip(),
                    "direction": dir_.strip().lower(),
                    "width": (width or "").strip(),
                    "type": "logic"
                })
                # Detect clocks/resets
                plow = p_name.lower()
                if "clk" in plow or "clock" in plow:
                    clocks.add(p_name.strip())
                if "rst" in plow or "reset" in plow:
                    resets.add(p_name.strip())
            
            # Find instantiations
            for match in inst_pattern.finditer(content):
                m_name, i_name = match.groups()
                if m_name not in reserved and i_name not in reserved:
                    # Filter out standard keywords/types
                    if m_name not in ["logic", "wire", "reg", "integer", "parameter", "localparam", "input", "output", "inout", "struct", "union", "enum"]:
                        instantiations.append({
                            "module_name": m_name.strip(),
                            "instance_name": i_name.strip()
                        })
                        
            # Find assign statements
            for match in assign_pattern.finditer(content):
                target, rhs = match.groups()
                # Find variable names in RHS
                sources = re.findall(r"\b([a-zA-Z_]\w*)\b", rhs)
                # Filter out numbers and SV keywords
                sources = [s for s in sources if not s.isdigit() and s not in reserved]
                assignments.append({
                    "target": target.strip(),
                    "sources": list(set(sources))
                })
                
            # Find assignments in always blocks
            for match in always_assign_pattern.finditer(content):
                target, op, rhs = match.groups()
                if target not in reserved:
                    sources = re.findall(r"\b([a-zA-Z_]\w*)\b", rhs)
                    sources = [s for s in sources if not s.isdigit() and s not in reserved]
                    assignments.append({
                        "target": target.strip(),
                        "sources": list(set(sources))
                    })
                    
        except Exception as e:
            print(f"Error parsing file {f}: {e}")
            
    return {
        "ports": ports,
        "instantiations": instantiations,
        "assignments": assignments,
        "clocks": list(clocks),
        "resets": list(resets)
    }

# Slang AST JSON parser
def parse_slang_ast(ast_json_path: str) -> Dict[str, Any] | None:
    """
    Parses a Slang AST JSON file and extracts port, instantiation, and assignment data.
    """
    if not os.path.exists(ast_json_path):
        return None
        
    try:
        with open(ast_json_path, 'r', encoding='utf-8') as f:
            root = json.load(f)
            
        ports = []
        instantiations = []
        assignments = []
        clocks = set()
        resets = set()
        
        # Recursive node walker
        def walk(node):
            if not isinstance(node, dict):
                return
                
            kind = node.get("kind", "")
            
            # Extract ports
            if kind == "Port":
                p_name = node.get("name", "")
                dir_ = node.get("direction", "input")
                if p_name:
                    ports.append({
                        "name": p_name,
                        "direction": dir_.lower(),
                        "width": "",
                        "type": "logic"
                    })
                    plow = p_name.lower()
                    if "clk" in plow or "clock" in plow:
                        clocks.add(p_name)
                    if "rst" in plow or "reset" in plow:
                        resets.add(p_name)
                        
            # Extract instantiations
            elif kind == "Instance":
                inst_name = node.get("name", "")
                definition = node.get("definition", "")
                if inst_name and definition:
                    instantiations.append({
                        "module_name": definition,
                        "instance_name": inst_name
                    })
                    
            # Extract assignments
            elif kind == "AssignmentExpression" or kind == "Assignment":
                lhs = node.get("left", {})
                rhs = node.get("right", {})
                lhs_name = lhs.get("name", "") if isinstance(lhs, dict) else ""
                
                # Gather RHS symbols
                sources = []
                def collect_symbols(expr):
                    if not isinstance(expr, dict):
                        return
                    if expr.get("kind") in ("ValueExpression", "NamedValueExpression", "Identifier"):
                        n = expr.get("name", "")
                        if n:
                            sources.append(n)
                    for k, v in expr.items():
                        if isinstance(v, dict):
                            collect_symbols(v)
                        elif isinstance(v, list):
                            for item in v:
                                collect_symbols(item)
                                
                collect_symbols(rhs)
                if lhs_name:
                    assignments.append({
                        "target": lhs_name,
                        "sources": list(set(sources))
                    })
                    
            # Walk children
            for k, v in node.items():
                if isinstance(v, dict):
                    walk(v)
                elif isinstance(v, list):
                    for item in v:
                        walk(item)
                        
        walk(root)
        return {
            "ports": ports,
            "instantiations": instantiations,
            "assignments": assignments,
            "clocks": list(clocks),
            "resets": list(resets)
        }
    except Exception as e:
        print(f"Error parsing Slang AST JSON {ast_json_path}: {e}")
        return None

# Context generation orchestration
def generate_context(output_dir: str):
    """
    Main entry point for Phase 0.3 Context Generation.
    Iterates through validated modules, generates AST JSON dumps,
    resolves context maps via Slang AST / Fallback Python / LLM, and
    aggregates results into a single context_artifact.json.
    """
    output_dir = os.path.abspath(output_dir)
    shared_dir = os.path.join(output_dir, "shared")
    ast_dir = os.path.join(shared_dir, "ast_cache")
    per_module_dir = os.path.join(output_dir, "per_module")
    
    os.makedirs(ast_dir, exist_ok=True)
    
    if not os.path.exists(per_module_dir):
        print(f"Error: per_module directory does not exist: {per_module_dir}")
        return
        
    modules = os.listdir(per_module_dir)
    print(f"Running Context Generation for {len(modules)} modules...")
    
    module_contexts = {}
    
    for mod in modules:
        mod_path = os.path.join(per_module_dir, mod)
        status_file = os.path.join(mod_path, "validation_status.json")
        map_file = os.path.join(mod_path, "invocation_map.json")
        
        if not os.path.exists(status_file) or not os.path.exists(map_file):
            continue
            
        with open(status_file, "r") as sf:
            status_data = json.load(sf)
        with open(map_file, "r") as mf:
            inv_map = json.load(mf)
            
        slang_info = inv_map.get("slang", {})
        slang_status = status_data.get("slang", "FAILED")
        
        files = slang_info.get("files", [])
        include_paths = slang_info.get("include_paths", [])
        
        ast_json_path = os.path.join(ast_dir, f"{mod}.json")
        ast_success = False
        parsed_data = None
        
        # 1. Attempt Slang AST dump if slang succeeded
        if slang_status in ("VALIDATED", "NEEDS_STUB", "PARTIAL") and files:
            # We construct Slang CLI args to dump AST
            cmd = ["slang", "--single-unit", "--relax-enum-conversions", "--timescale=1ns/1ps", "-Wno-multiple-cont-assigns", "--compat=all", "--ast-json", ast_json_path, "--ast-json-source-info"]
            for p in include_paths:
                cmd += ["-I", p]
            cmd += files
            
            try:
                res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
                if os.path.exists(ast_json_path):
                    parsed_data = parse_slang_ast(ast_json_path)
                    if parsed_data:
                        ast_success = True
            except Exception as e:
                print(f"   Slang AST dump execution failed for {mod}: {e}")
                
        # 2. Fallback to Python regex parser if Slang AST failed
        if not ast_success:
            print(f"   [Fallback] Running Python regex parser for module '{mod}'...")
            parsed_data = fallback_python_parse(files, mod)
            
        # 3. Fallback to LLM if Python parser returned empty/minimal data or failed
        if not parsed_data or (not parsed_data["ports"] and not parsed_data["instantiations"]):
            print(f"   [Fallback] Module '{mod}' has incomplete context. Triggering LLM fallback...")
            llm_data = call_llm_fallback(mod, files)
            if llm_data:
                parsed_data = llm_data
                
        # Store context
        if parsed_data:
            module_contexts[mod] = parsed_data
            
    # Aggregate into context_artifact.json
    print("Aggregating contexts into context_artifact.json...")
    
    # Compute module hierarchy
    hierarchy = {}
    for mod_name, context in module_contexts.items():
        children = [inst["module_name"] for inst in context.get("instantiations", [])]
        hierarchy[mod_name] = children
        
    # Build global signal flow graph representation
    signal_flow_graph = {
        "nodes": [],
        "edges": []
    }
    nodes_set = set()
    for mod_name, context in module_contexts.items():
        # Add internal assignments
        for assign in context.get("assignments", []):
            target = f"{mod_name}.{assign['target']}"
            if target not in nodes_set:
                signal_flow_graph["nodes"].append({"id": target, "module": mod_name})
                nodes_set.add(target)
            for src in assign.get("sources", []):
                src_node = f"{mod_name}.{src}"
                if src_node not in nodes_set:
                    signal_flow_graph["nodes"].append({"id": src_node, "module": mod_name})
                    nodes_set.add(src_node)
                signal_flow_graph["edges"].append({"source": src_node, "target": target})
                
    # Build trust boundaries and tag secrets
    trust_boundaries = {}
    secret_signals = []
    
    for mod_name, context in module_contexts.items():
        # 1. Define trust boundaries
        mlow = mod_name.lower()
        if any(x in mlow for x in ["key", "aes", "otbn", "crypto", "entropy", "hsm", "security"]):
            trust_boundaries[mod_name] = "HIGH_TRUST"
        elif any(x in mlow for x in ["uart", "spi", "gpio", "pinmux"]):
            trust_boundaries[mod_name] = "EXTERNAL_IO"
        else:
            trust_boundaries[mod_name] = "INTERNAL_LOGIC"
            
        # 2. Tag secret signals
        for port in context.get("ports", []):
            pname = port["name"]
            if any(k in pname.lower() for k in SECRET_KEYWORDS):
                secret_signals.append({
                    "module": mod_name,
                    "signal": pname,
                    "type": "port",
                    "direction": port["direction"]
                })
        for assign in context.get("assignments", []):
            target = assign["target"]
            if any(k in target.lower() for k in SECRET_KEYWORDS):
                secret_signals.append({
                    "module": mod_name,
                    "signal": target,
                    "type": "internal"
                })
                
    # Build per-module compressed summaries
    module_summaries = {}
    for mod_name, context in module_contexts.items():
        ports_summary = ", ".join([f"{p['name']} ({p['direction']})" for p in context.get("ports", [])[:10]])
        if len(context.get("ports", [])) > 10:
            ports_summary += " ..."
        inst_summary = ", ".join([f"{i['module_name']} as {i['instance_name']}" for i in context.get("instantiations", [])])
        
        summary = f"Module: {mod_name}\n"
        summary += f"Trust Boundary: {trust_boundaries.get(mod_name, 'INTERNAL_LOGIC')}\n"
        summary += f"Ports: {ports_summary or 'None'}\n"
        summary += f"Instantiates: {inst_summary or 'None'}\n"
        if context.get("clocks"):
            summary += f"Clocks: {', '.join(context['clocks'])}\n"
        
        module_summaries[mod_name] = summary
        
    context_artifact = {
        "module_hierarchy": hierarchy,
        "signal_flow_graph": signal_flow_graph,
        "ports_and_interfaces": {m: c.get("ports", []) for m, c in module_contexts.items()},
        "instantiations": {m: c.get("instantiations", []) for m, c in module_contexts.items()},
        "clock_domains": {m: c.get("clocks", []) for m, c in module_contexts.items()},
        "trust_boundaries": trust_boundaries,
        "secret_signals": secret_signals,
        "module_summaries": module_summaries
    }
    
    write_json_artifact(context_artifact, os.path.join(shared_dir, "context_artifact.json"))
    print(f"Context Generation complete. Generated context_artifact.json in {shared_dir}.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 context_generator.py <output_dir>")
        sys.exit(1)
    generate_context(sys.argv[1])
