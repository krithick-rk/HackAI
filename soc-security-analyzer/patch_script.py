import os
import re

file_path = "src/soc_analyzer/phase0/synthesis_orchestrator.py"
with open(file_path, "r") as f:
    content = f.read()

# 1. Add os.makedirs in _emit_event
content = content.replace(
    '    if output_dir:\n        with open(os.path.join(output_dir, "phase0_events.jsonl"), "a") as f:\n            f.write(line + "\\n")',
    '    if output_dir:\n        os.makedirs(output_dir, exist_ok=True)\n        with open(os.path.join(output_dir, "phase0_events.jsonl"), "a") as f:\n            f.write(line + "\\n")'
)

# 2. Add syntax error catching to auto_generate_stubs
content = content.replace(
    '    p4 = re.compile(r"([^:]+\\.sv):\\d+: ERROR: error in generate")',
    '    p4 = re.compile(r"([^:]+\\.sv):\\d+: ERROR: error in generate")\n    p5 = re.compile(r"([^:]+\\.sv):\\d+: ERROR: syntax error")'
)

content = content.replace(
    '        if m4:\n            f = m4.group(1)\n            file_errors.setdefault(f, set()).add("error in generate")\n            continue',
    '        if m4:\n            f = m4.group(1)\n            file_errors.setdefault(f, set()).add("error in generate")\n            continue\n\n        m5 = p5.search(err)\n        if m5:\n            f = m5.group(1)\n            file_errors.setdefault(f, set()).add("syntax error")\n            continue'
)

patch_code = """        patched = False
        if "syntax error" in reasons:
            def repl_struct(match):
                inner = match.group(1)
                inner_cleaned = re.sub(r"\\\\b\\\\w+\\\\s*:(?!:)\\\\s*", "", inner)
                return "'{" + inner_cleaned + "}"
            content_str = re.sub(r"'\\\\s*\\\\{([^}]+)\\\\}", repl_struct, content_str)
            
            def repl_param_array(match):
                kw, msb, lsb, name, size = match.group(1), match.group(2), match.group(3), match.group(4), match.group(5).strip()
                w_val = int(msb) - int(lsb) + 1 if msb else 1
                w_expr = str(w_val) if msb else "1"
                try:
                    new_dim = f"[{int(size) * w_val}-1:0]"
                except:
                    new_dim = f"[({size}) * {w_expr}-1:0]"
                return f"{kw} logic {new_dim} {name} = {{"
            content_str = re.sub(r"\\\\b(parameter|localparam)\\\\s+logic\\\\s*(?:\\\\[\\\\s*(\\\\d+)\\\\s*:\\\\s*(\\\\d+)\\\\s*\\\\])?\\\\s*(\\\\w+)\\\\s*\\\\[([^\\\\]]+)\\\\]\\\\s*=\\\\s*'\\\\s*\\\\{", repl_param_array, content_str)
            
            content_str = re.sub(r"\\\\bendfunction\\\\s*:\\\\s*\\\\w+", "endfunction", content_str)
            content_str = re.sub(r"\\\\bendtask\\\\s*:\\\\s*\\\\w+", "endtask", content_str)
            content_str = re.sub(r"\\\\bendpackage\\\\s*:\\\\s*\\\\w+", "endpackage", content_str)
            
            patched = True
            
        if patched:
            with open(filepath, "w") as f:
                f.write(content_str)
                
        if "error in generate" in reasons:"""

content = content.replace(
    '        try:\n            with open(filepath, "r") as f:\n                content = f.read()\n        except:\n            continue\n            \n        if "error in generate" in reasons:',
    '        try:\n            with open(filepath, "r") as f:\n                content_str = f.read()\n        except:\n            continue\n            \n' + patch_code
)

with open(file_path, "w") as f:
    f.write(content)

