import os
import sys
import json
import http.client
from typing import Dict, Any, List
from src.soc_analyzer.common.fs_utils import write_json_artifact, read_json_artifact
from src.soc_analyzer.phase0.tool_validator import validate_tool_for_module

def call_llm_for_repair(prompt: str) -> str:
    """Queries the LLM using available API keys (Anthropic, Gemini, OpenAI)."""
    api_keys = {
        "anthropic": os.environ.get("ANTHROPIC_API_KEY"),
        "gemini": os.environ.get("GEMINI_API_KEY"),
        "openai": os.environ.get("OPENAI_API_KEY")
    }

    response_text = ""
    try:
        if api_keys["anthropic"]:
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
            print("   [LLM Repair] No API key present. Cannot contact LLM.")
            return ""
    except Exception as e:
        print(f"   [LLM Repair] HTTP request failed: {e}")
        return ""

    return response_text.strip()

def load_prompt_template() -> str:
    """Resolves and loads the repair prompt template."""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    proj_root = os.path.abspath(os.path.join(current_dir, "..", "..", ".."))
    prompt_path = os.path.join(proj_root, "src", "soc_analyzer", "prompts", "repair_prompt.txt")
    if os.path.exists(prompt_path):
        with open(prompt_path, 'r', encoding='utf-8') as f:
            return f.read()
    raise FileNotFoundError(f"Prompt template not found at: {prompt_path}")

def run_interactive_repair_loop(
    module_name: str,
    tool_name: str,
    output_dir: str,
    status_file: str,
    map_file: str
) -> bool:
    """
    Orchestrates the interactive repair loop for a specific module × tool failure.
    Communicates with LLM, requests human consent for file access/validation execution,
    and updates status on success.
    """
    # 1. Load initial maps & reports
    inv_map = read_json_artifact(map_file)
    status_data = read_json_artifact(status_file)
    tool_info = inv_map.get(tool_name, {})

    failure_report_path = os.path.join(output_dir, "per_module", module_name, f"failure_report_{tool_name}.json")
    if not os.path.exists(failure_report_path):
        print(f"   No failure report found for {module_name} ({tool_name}). Skipping.")
        return False

    failure_data = read_json_artifact(failure_report_path)
    error_logs = failure_data.get("raw_output", "")
    failing_command = failure_data.get("command", "")

    # Gather source files content for context
    source_files_context = ""
    for f in tool_info.get("files", []):
        if os.path.exists(f):
            try:
                with open(f, 'r', encoding='utf-8', errors='ignore') as fh:
                    source_files_context += f"// File: {f}\n{fh.read()}\n\n"
            except Exception:
                pass

    template = load_prompt_template()
    history_context = ""
    max_iterations = 4

    for iteration in range(1, max_iterations + 1):
        print(f"\n---> [Iteration {iteration}/{max_iterations}] Querying LLM for module '{module_name}' tool '{tool_name}'...")
        
        prompt = template.format(
            tool_name=tool_name,
            module_name=module_name,
            source_files=source_files_context,
            failing_command=failing_command,
            error_logs=error_logs
        )
        if history_context:
            prompt += f"\n\n[Interactive History]:\n{history_context}"

        response = call_llm_for_repair(prompt)
        if not response:
            print("   Empty response from LLM. Aborting loop.")
            break

        # Sanitize markdown block wrapping if present
        if response.startswith("```"):
            lines = response.splitlines()
            if lines[0].startswith("```json") or lines[0] == "```":
                lines = lines[1:]
            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]
            response = "\n".join(lines).strip()

        # Parse JSON
        try:
            decision = json.loads(response)
        except Exception as e:
            print(f"   Failed to parse LLM response as JSON. Raw Response:\n{response}\nError: {e}")
            break

        print(f"   AI Diagnostic: {decision.get('diagnostic')}")
        action = decision.get("action_required")

        if action == "read_file":
            req_file = decision.get("requested_file")
            if not req_file:
                print("   AI requested 'read_file' but did not specify a filename. Aborting.")
                break
            
            # Interactive permission request
            print(f"\n[AI Request] The AI wants to read file: {req_file}")
            choice = input("Grant permission to read? [y/N]: ").strip().lower()
            if choice == 'y':
                if os.path.exists(req_file):
                    try:
                        with open(req_file, 'r', encoding='utf-8', errors='ignore') as rf:
                            file_content = rf.read()
                        print(f"   [System] Read {len(file_content)} characters from {req_file}.")
                        history_context += f"\nFile content for {req_file}:\n{file_content}\n"
                    except Exception as fe:
                        history_context += f"\nFailed to read file {req_file}: {fe}\n"
                else:
                    print(f"   File does not exist: {req_file}")
                    history_context += f"\nRequested file {req_file} does not exist on filesystem.\n"
            else:
                print("   Permission denied by user.")
                history_context += f"\nPermission DENIED by user to read file {req_file}.\n"

        elif action == "run_validation":
            fix = decision.get("proposed_fix", {})
            fix_type = fix.get("type", "none")
            
            if fix_type == "none":
                print("   AI specified run_validation but no fix details were proposed. Aborting.")
                break

            # Apply proposed fix to tool_info dictionary
            stubs_dir = os.path.join(output_dir, "per_module", module_name, "stubs")
            if fix_type == "stub":
                stub_name = fix.get("target_stub_name")
                stub_content = fix.get("stub_content")
                if not stub_name or not stub_content:
                    print("   Invalid stub parameters. Aborting.")
                    break
                os.makedirs(stubs_dir, exist_ok=True)
                stub_file = os.path.join(stubs_dir, f"{stub_name}.sv")
                
                # Write stub
                with open(stub_file, 'w', encoding='utf-8') as sf:
                    sf.write(stub_content)
                print(f"   [System] Wrote proposed stub: {stub_file}")
                
                if stub_file not in tool_info["files"]:
                    tool_info["files"].append(stub_file)

            elif fix_type == "include_path":
                inc_path = fix.get("new_include_path")
                if inc_path:
                    if inc_path not in tool_info["include_paths"]:
                        tool_info["include_paths"].append(inc_path)
                    print(f"   [System] Added include path: {inc_path}")

            elif fix_type == "command_flag":
                flags = fix.get("new_command_flags", [])
                for flag in flags:
                    if flag not in tool_info["base_command"]:
                        tool_info["base_command"] += f" {flag}"
                print(f"   [System] Appended command flags: {flags}")

            # Interactive permission request for command execution
            print(f"\n[AI Request] Proposed re-validation command using the suggested fix.")
            choice = input(f"Allow executing validation command for tool '{tool_name}'? [y/N]: ").strip().lower()
            if choice == 'y':
                print(f"   Running validation subprocess...")
                status, summary, history, updated_files = validate_tool_for_module(
                    module_name, tool_name, tool_info, output_dir
                )
                
                print(f"   Validation Result: status={status}, summary={summary}")
                
                # Save details
                tool_info["status"] = status
                tool_info["validation_output_summary"] = summary
                tool_info["files"] = updated_files
                inv_map[tool_name] = tool_info
                write_json_artifact(inv_map, map_file)
                
                status_data[tool_name] = status
                write_json_artifact(status_data, status_file)

                # Write remediation report
                remediation_report = {
                    "tool": tool_name,
                    "diagnostic": decision.get("diagnostic"),
                    "proposed_fix": fix,
                    "final_status": status,
                    "final_summary": summary
                }
                write_json_artifact(
                    remediation_report,
                    os.path.join(output_dir, "per_module", module_name, f"failure_remediation_{tool_name}.json")
                )

                if status in ("VALIDATED", "PARTIAL", "NEEDS_STUB"):
                    print(f"\n[Success] Module '{module_name}' successfully repaired! Status is now {status}.")
                    return True
                else:
                    # Update logs and run again
                    error_logs = history[-1].get("raw_output", "")
                    failing_command = history[-1].get("command", "")
                    history_context += f"\nPrevious fix attempt failed. New error logs:\n{error_logs}\n"
            else:
                print("   Validation command execution denied by user. Aborting.")
                break
        else:
            print("   AI specified action_required as 'none' or unknown action. Aborting.")
            break

    return False

def repair_failed_modules(output_dir: str):
    """
    Scans for failed/unavailable tools in validated modules and runs the
    interactive repair flow.
    """
    output_dir = os.path.abspath(output_dir)
    per_module_dir = os.path.join(output_dir, "per_module")
    if not os.path.exists(per_module_dir):
        print("No per_module directory found.")
        return

    modules = os.listdir(per_module_dir)
    failed_count = 0
    repaired_count = 0

    print(f"\n=== Running Interactive Tool Validation Repairer ===")
    for mod in modules:
        mod_dir = os.path.join(per_module_dir, mod)
        status_file = os.path.join(mod_dir, "validation_status.json")
        map_file = os.path.join(mod_dir, "invocation_map.json")

        if not os.path.exists(status_file) or not os.path.exists(map_file):
            continue

        status_data = read_json_artifact(status_file)
        
        # Look for FAILED or TOOL_UNAVAILABLE status
        for tool, status in list(status_data.items()):
            if status in ("FAILED", "TOOL_UNAVAILABLE"):
                failed_count += 1
                print(f"\nFound failure: module '{mod}' -> tool '{tool}' is '{status}'")
                success = run_interactive_repair_loop(mod, tool, output_dir, status_file, map_file)
                if success:
                    repaired_count += 1

    print(f"\n=== Repairer Complete: {repaired_count}/{failed_count} failures resolved ===")
