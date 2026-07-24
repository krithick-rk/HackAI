import re
import os

file_path = "src/soc_analyzer/phase0/synthesis_orchestrator.py"
with open(file_path, "r") as f:
    content = f.read()

new_logic = """    content = re.sub(r"parameter pmp_cfg_t PmpCfgRst.*?};", "", content, flags=re.DOTALL)
    content = re.sub(r"parameter logic \\[[^\\]]+\\] PmpAddrRst.*?};", "", content, flags=re.DOTALL)
    content = re.sub(r"parameter pmp_mseccfg_t PmpMseccfgRst.*?;", "", content, flags=re.DOTALL)
"""

# Insert at the end of preprocess_sv_for_yosys
content = content.replace(
    'content = re.sub(r"\'\\s*\\{\\s*default\\s*:\\s*([^}]+)\\}", r"\\1", content)',
    'content = re.sub(r"\'\\s*\\{\\s*default\\s*:\\s*([^}]+)\\}", r"\\1", content)\n' + new_logic
)

with open(file_path, "w") as f:
    f.write(content)

