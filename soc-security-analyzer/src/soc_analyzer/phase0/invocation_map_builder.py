import os
from typing import Dict, Set, Tuple, List, Any
from soc_analyzer.common.fs_utils import write_json_artifact
from soc_analyzer.common.schemas import PerModuleInvocationMap, ToolInvocationInfo

def get_transitive_dependencies(module_name: str, modules_map: dict, visited: Set[str] = None) -> Tuple[Set[str], Set[str]]:
    """Recursively finds all modules instantiated by module_name and the files defining them."""
    if visited is None:
        visited = set()
        
    if module_name in visited:
        return set(), set()
        
    visited.add(module_name)
    
    child_modules = set()
    child_files = set()
    
    if module_name in modules_map:
        insts = modules_map[module_name].get("instantiates", [])
        for child in insts:
            child_modules.add(child)
            if child in modules_map:
                child_file = modules_map[child].get("defined_in")
                if child_file:
                    child_files.add(os.path.abspath(child_file))
                
                # Recursive fetch
                sub_mods, sub_files = get_transitive_dependencies(child, modules_map, visited)
                child_modules.update(sub_mods)
                child_files.update(sub_files)
                
    return child_modules, child_files

def get_transitive_includes(file_path: str, files_map: dict, visited: Set[str] = None) -> Set[str]:
    """Recursively gathers all absolute paths of files included by the specified file."""
    if visited is None:
        visited = set()
        
    if file_path in visited:
        return set()
        
    visited.add(file_path)
    
    includes = set()
    norm_path = os.path.abspath(file_path)
    
    if norm_path in files_map:
        inc_files = files_map[norm_path].get("includes", [])
        for inc in inc_files:
            inc_abs = os.path.abspath(inc)
            includes.add(inc_abs)
            includes.update(get_transitive_includes(inc_abs, files_map, visited))
            
    return includes

def build_invocation_maps(dependency_graph: dict) -> Dict[str, PerModuleInvocationMap]:
    """
    Constructs the unvalidated invocation maps for all defined modules in the dependency graph.
    """
    files_map = {os.path.abspath(k): v for k, v in dependency_graph.get("files", {}).items()}
    modules_map = dependency_graph.get("modules", {})
    
    invocation_maps = {}
    
    worker_note_verbatim = (
        "base_command is a validated starting point — worker may add or change flags "
        "as analysis requires. Include paths and companion files must be preserved."
    )
    
    for mod_name, mdata in modules_map.items():
        defining_file_raw = mdata.get("defined_in")
        if not defining_file_raw:
            continue
            
        defining_file = os.path.abspath(defining_file_raw)
        
        # 1. Transitive child modules and their defining files
        _, child_files = get_transitive_dependencies(mod_name, modules_map)
        child_files_clean = {f for f in child_files if f != defining_file}
        
        # 2. Transitive include files across target module and its companions
        all_involved_files = child_files_clean | {defining_file}
        all_includes = set()
        for f in all_involved_files:
            all_includes.update(get_transitive_includes(f, files_map))
            
        # 3. Directories of those includes
        include_paths = sorted(list({os.path.dirname(inc) for inc in all_includes}))
        
        # 4. Companions: basenames of child files
        required_companions = sorted(list({os.path.basename(cf) for cf in child_files_clean}))
        
        # 5. File arrays for commands
        # Slang and Verilator require the target file and all child companion files
        full_file_list = [defining_file] + sorted(list(child_files_clean))
        # Verible checks file-by-file
        verible_file_list = [defining_file]
        
        # Setup slang
        slang_info: ToolInvocationInfo = {
            "base_command": "slang --lint-only",
            "files": full_file_list,
            "include_paths": include_paths,
            "required_companions": required_companions,
            "stubs_required": [],
            "status": "UNVALIDATED",
            "validation_output_summary": None,
            "worker_note": worker_note_verbatim
        }
        
        # Setup verilator
        verilator_info: ToolInvocationInfo = {
            "base_command": "verilator --lint-only -Wall",
            "files": full_file_list,
            "include_paths": include_paths,
            "required_companions": required_companions,
            "stubs_required": [],
            "status": "UNVALIDATED",
            "validation_output_summary": None,
            "worker_note": worker_note_verbatim
        }
        
        # Setup verible
        verible_info: ToolInvocationInfo = {
            "base_command": "verible-verilog-lint",
            "files": verible_file_list,
            "include_paths": include_paths,
            "required_companions": required_companions,
            "stubs_required": [],
            "status": "UNVALIDATED",
            "validation_output_summary": None,
            "worker_note": worker_note_verbatim
        }
        
        invocation_maps[mod_name] = {
            "module": mod_name,
            "slang": slang_info,
            "verilator": verilator_info,
            "verible": verible_info
        }
        
    return invocation_maps

def build_and_write_invocation_maps(dependency_graph: dict, output_dir: str) -> Dict[str, PerModuleInvocationMap]:
    """Generates invocation maps and writes each to /per_module/<module>/invocation_map.json."""
    maps = build_invocation_maps(dependency_graph)
    
    for mod_name, map_entry in maps.items():
        dest_path = os.path.join(output_dir, "per_module", mod_name, "invocation_map.json")
        write_json_artifact(map_entry, dest_path)
        
    return maps
