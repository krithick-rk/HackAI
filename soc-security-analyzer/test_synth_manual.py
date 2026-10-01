import sys
import os

from soc_analyzer.phase0.synthesis_orchestrator import SynthesisConfig, run_shared_synthesis

workspace_dir = "/home/hackdac/Documents/AI/hackAI/soc-security-analyzer/workspace"
output_dir = os.path.join(workspace_dir, "opentitan_artifacts", "netlist")
os.makedirs(output_dir, exist_ok=True)

c = SynthesisConfig(
    top_module="chip_earlgrey_asic",
    output_dir=output_dir,
    fusesoc_cores_root=os.path.join(workspace_dir, "hw"),
    fusesoc_core_name="lowrisc:systems:chip_earlgrey_asic:0.1"
)

res = run_shared_synthesis(c)
print(res)
