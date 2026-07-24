import os
import re

file_path = "src/soc_analyzer/phase0/synthesis_orchestrator.py"
with open(file_path, "r") as f:
    content = f.read()

# Replace the specific regex for unpacked arrays in preprocess_sv_for_yosys
old_regex = r"    content = re.sub(r\"\\b(parameter|localparam)\\s+logic\\s*(?:\\[\\s*(\\d+)\\s*:\\s*(\\d+)\\s*\\])?\\s*(\\w+)\\s*\\[([^\\]]+)\\]\\s*=\\s*'\\s*\\{\", repl_param_array, content)"

new_regex = r"""    def repl_unpacked(match):
        kw = match.group(1)
        type_str = match.group(2)
        name = match.group(3)
        return f"{kw} {type_str} {name} = {{"
    content = re.sub(r"\b(parameter|localparam)\s+([\w_]+)\s+(\w+)\s*\[[^\]]+\]\s*=\s*'\s*\{", repl_unpacked, content)
    content = re.sub(r"\b(parameter|localparam)\s+logic\s*(?:\[\s*(\d+)\s*:\s*(\d+)\s*\])?\s*(\w+)\s*\[([^\]]+)\]\s*=\s*'\s*\{", repl_param_array, content)
"""

content = content.replace(old_regex, new_regex)

with open(file_path, "w") as f:
    f.write(content)

