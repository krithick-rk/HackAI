import os
import tempfile
import pytest
from src.soc_analyzer.phase0.dependency_scanner import scan_dependencies

def test_dependency_scanner_simple():
    # Create temp files representing design modules
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create an include file
        inc_file = os.path.join(tmpdir, "my_include.vh")
        with open(inc_file, 'w', encoding='utf-8') as f:
            f.write("// simple include\n")
            
        # Create a package file
        pkg_file = os.path.join(tmpdir, "my_pkg.sv")
        with open(pkg_file, 'w', encoding='utf-8') as f:
            f.write("package my_pkg;\n  localparam int VAL = 1;\nendpackage\n")
            
        # Create a module file that includes the include and imports package
        mod_file = os.path.join(tmpdir, "my_mod.sv")
        with open(mod_file, 'w', encoding='utf-8') as f:
            f.write(
                "`include \"my_include.vh\"\n"
                "import my_pkg::*;\n"
                "module my_mod;\n"
                "  sub_mod #( .P(8) ) u_sub (\n"
                "    .clk(1'b0)\n"
                "  );\n"
                "endmodule\n"
            )
            
        # Create the sub-module file
        sub_mod_file = os.path.join(tmpdir, "sub_mod.sv")
        with open(sub_mod_file, 'w', encoding='utf-8') as f:
            f.write("module sub_mod;\nendmodule\n")
            
        # Run scanner
        files_to_scan = [pkg_file, mod_file, sub_mod_file]
        graph, ambiguities = scan_dependencies(files_to_scan, include_dirs=[tmpdir])
        
        # Verify graph files structure
        mod_abs = os.path.abspath(mod_file)
        assert mod_abs in graph["files"]
        assert os.path.abspath(inc_file) in graph["files"][mod_abs]["includes"]
        assert "my_pkg" in graph["files"][mod_abs]["package_imports"]
        assert "sub_mod" in graph["files"][mod_abs]["instantiations"]
        
        # Verify modules structure
        assert "my_mod" in graph["modules"]
        assert "sub_mod" in graph["modules"]
        assert graph["modules"]["my_mod"]["defined_in"] == mod_abs
        assert "sub_mod" in graph["modules"]["my_mod"]["instantiates"]
        assert graph["modules"]["sub_mod"]["instantiated_by"] == ["my_mod"]
        
        # Verify ambiguities
        # Should detect parameterized instantiation
        param_ambigs = [a for a in ambiguities if a["type"] == "PARAMETERIZED_INSTANTIATION"]
        assert len(param_ambigs) > 0
        assert param_ambigs[0]["file"] == mod_abs
