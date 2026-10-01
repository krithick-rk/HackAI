import re
import os

def inline_prim_util(content: str) -> str:
    while True:
        idx = content.find("prim_util_pkg::vbits")
        if idx == -1: break
        start_paren = content.find("(", idx)
        if start_paren == -1: break
        paren_count = 1
        scan_idx = start_paren + 1
        while paren_count > 0 and scan_idx < len(content):
            char = content[scan_idx]
            if char == "(": paren_count += 1
            elif char == ")": paren_count -= 1
            scan_idx += 1
        if paren_count == 0:
            expr = content[start_paren+1 : scan_idx-1].strip()
            replacement = f"(({expr}) == 1 ? 1 : $clog2({expr}))"
            content = content[:idx] + replacement + content[scan_idx:]
        else: break
            
    while True:
        idx = content.find("prim_util_pkg::ceil_div")
        if idx == -1: break
        start_paren = content.find("(", idx)
        if start_paren == -1: break
        paren_count = 1
        scan_idx = start_paren + 1
        while paren_count > 0 and scan_idx < len(content):
            char = content[scan_idx]
            if char == "(": paren_count += 1
            elif char == ")": paren_count -= 1
            scan_idx += 1
        if paren_count == 0:
            args_str = content[start_paren+1 : scan_idx-1].strip()
            level = 0
            comma_idx = -1
            for i, c in enumerate(args_str):
                if c == "(": level += 1
                elif c == ")": level -= 1
                elif c == "," and level == 0:
                    comma_idx = i
                    break
            if comma_idx != -1:
                arg1 = args_str[:comma_idx].strip()
                arg2 = args_str[comma_idx+1:].strip()
                replacement = f"((({arg1}) + ({arg2}) - 1) / ({arg2}))"
                content = content[:idx] + replacement + content[scan_idx:]
            else: break
        else: break
    return content

def preprocess_sv_for_yosys(content: str) -> str:
    content = inline_prim_util(content)
    def repl_inside(match):
        val = match.group(1).strip()
        elems_str = match.group(2)
        elems = [e.strip() for e in elems_str.split(",")]
        return "(" + " || ".join(f"{val} == {e}" for e in elems) + ")"
    content = re.sub(r"(\w+)\s+inside\s*\{\s*([^}]+)\s*\}", repl_inside, content)
    
    lines = content.splitlines()
    new_lines = []
    current_func = None
    func_start_rx = re.compile(r"\bfunction\s+(?:automatic\s+)?(?:[\w\s\[\]:]+)?\b(\w+)\s*(?:\(|;)")
    func_end_rx = re.compile(r"\bendfunction\b")
    for line in lines:
        m_start = func_start_rx.search(line)
        if m_start: current_func = m_start.group(1)
        if current_func and "return " in line:
            indent = line[:line.find("return")]
            expr = line[line.find("return") + 7:].strip()
            line = f"{indent}{current_func} = {expr}"
        if func_end_rx.search(line): current_func = None
        new_lines.append(line)
        
    content = "\n".join(new_lines)
    content = re.sub(r"\bendfunction\s*:\s*\w+", "endfunction", content)
    content = re.sub(r"\bendtask\s*:\s*\w+", "endtask", content)
    content = re.sub(r"\bendpackage\s*:\s*\w+", "endpackage", content)
    
    def repl_struct(match):
        inner = match.group(1)
        inner_cleaned = re.sub(r"\b\w+\s*:(?!:)\s*", "", inner)
        return "'{" + inner_cleaned + "}"
    content = re.sub(r"'\s*\{([^}]+)\}", repl_struct, content)
    
    def repl_param_array(match):
        kw, msb, lsb, name, size = match.group(1), match.group(2), match.group(3), match.group(4), match.group(5).strip()
        w_val = int(msb) - int(lsb) + 1 if msb else 1
        w_expr = str(w_val) if msb else "1"
        try:
            new_dim = f"[{int(size) * w_val}-1:0]"
        except:
            new_dim = f"[({size}) * {w_expr}-1:0]"
        return f"{kw} logic {new_dim} {name} = {{"
    content = re.sub(r"\b(parameter|localparam)\s+logic\s*(?:\[\s*(\d+)\s*:\s*(\d+)\s*\])?\s*(\w+)\s*\[([^\]]+)\]\s*=\s*'\s*\{", repl_param_array, content)
    content = re.sub(r"'\s*\{\s*default\s*:\s*([^}]+)\}", r"\1", content)
    return content

file_path = "src/soc_analyzer/phase0/synthesis_orchestrator.py"
with open(file_path, "r") as f:
    orig = f.read()

# Add the functions to the file before `run_shared_synthesis`
target_str = "def run_shared_synthesis(config: SynthesisConfig) -> dict:"
import inspect
code_to_insert = inspect.getsource(inline_prim_util) + "\n" + inspect.getsource(preprocess_sv_for_yosys) + "\n\n"
orig = orig.replace(target_str, code_to_insert + target_str)

# Now apply this preprocessing inside `run_shared_synthesis` right before `ys_path` creation
preprocessing_hook = """
    # Preprocess all RTL files
    preproc_dir = os.path.join(config.output_dir, "preproc_rtl")
    os.makedirs(preproc_dir, exist_ok=True)
    new_rtl = []
    
    # Prepend assert fix
    assert_fix = os.path.join(os.path.dirname(config.design_dir), "workspace", "yosys_assert_fix.svh")
    if os.path.exists(assert_fix):
        new_rtl.append(assert_fix)
        
    for f in rtl_files:
        if not os.path.exists(f): continue
        with open(f, "r") as rf:
            content = rf.read()
        content = preprocess_sv_for_yosys(content)
        out_f = os.path.join(preproc_dir, os.path.basename(f) + "_" + str(hash(f))[-6:] + ".sv")
        with open(out_f, "w") as wf:
            wf.write(content)
        new_rtl.append(out_f)
    
    rtl_files = new_rtl
"""

target_ys = "    ys_path = os.path.join(config.output_dir, \"synth.ys\")"
orig = orig.replace(target_ys, preprocessing_hook + "\n" + target_ys)

with open(file_path, "w") as f:
    f.write(orig)
