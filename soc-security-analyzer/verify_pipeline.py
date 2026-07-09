import os
import sys
from soc_analyzer.phase0.dependency_scanner import scan_dependencies_and_write
from soc_analyzer.phase0.invocation_map_builder import build_and_write_invocation_maps
from soc_analyzer.phase0.tool_validator import validate_environment

def main():
    rtl_dir = "fixtures/sample_rtl"
    if not os.path.exists(rtl_dir):
        print(f"Error: {rtl_dir} directory not found.")
        sys.exit(1)
        
    files = [os.path.abspath(os.path.join(rtl_dir, f)) for f in os.listdir(rtl_dir) if f.endswith(('.v', '.sv'))]
    output_dir = "workspace/phase0_artifacts"
    
    print("1. Running Dependency Scanner...")
    graph, ambiguities = scan_dependencies_and_write(files, include_dirs=[rtl_dir], output_dir=output_dir)
    print(f"   Generated dependency graph for {len(graph['files'])} files.")
    print(f"   Found {len(ambiguities)} ambiguities.")
    
    print("2. Running Invocation Map Builder...")
    maps = build_and_write_invocation_maps(graph, output_dir=output_dir)
    print(f"   Generated invocation maps for {len(maps)} modules.")
    
    print("3. Running Tool Validator (Health Check)...")
    validate_environment(output_dir)
    print("   Validation completed successfully.")
    
    # Check outputs
    shared_dir = os.path.join(output_dir, "shared")
    print("\nVerifying output artifacts:")
    print(f"   dependency_graph.json exists: {os.path.exists(os.path.join(shared_dir, 'dependency_graph.json'))}")
    print(f"   ambiguities.json exists: {os.path.exists(os.path.join(shared_dir, 'ambiguities.json'))}")
    
    for mod in maps.keys():
        mod_dir = os.path.join(output_dir, "per_module", mod)
        print(f"   Module '{mod}':")
        print(f"      invocation_map.json exists: {os.path.exists(os.path.join(mod_dir, 'invocation_map.json'))}")
        print(f"      validation_status.json exists: {os.path.exists(os.path.join(mod_dir, 'validation_status.json'))}")

if __name__ == "__main__":
    main()
