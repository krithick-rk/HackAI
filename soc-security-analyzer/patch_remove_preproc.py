import re
import os

file_path = "src/soc_analyzer/phase0/synthesis_orchestrator.py"
with open(file_path, "r") as f:
    content = f.read()

# Remove the preprocessing logic entirely
old_preprocessing_hook = """
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
                content_str = rf.read()
            content_str = preprocess_sv_for_yosys(content_str)
            out_f = os.path.join(preproc_dir, os.path.basename(f) + "_" + str(hash(f))[-6:] + ".sv")
            with open(out_f, "w") as wf:
                wf.write(content_str)
            new_rtl.append(out_f)
        
        rtl_files = new_rtl
"""

# The file might have `content = preprocess_sv_for_yosys(content)` instead of `content_str`
content = re.sub(r"\s*# Preprocess all RTL files.*?rtl_files = new_rtl\n", "", content, flags=re.DOTALL)

with open(file_path, "w") as f:
    f.write(content)

