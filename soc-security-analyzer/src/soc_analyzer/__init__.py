import sys
import os

# Ensure repository root is on sys.path so 'src.soc_analyzer' imports resolve cleanly
_cur_dir = os.path.dirname(os.path.abspath(__file__))
_src_dir = os.path.dirname(_cur_dir)
_repo_dir = os.path.dirname(_src_dir)
if _repo_dir not in sys.path:
    sys.path.insert(0, _repo_dir)

# SoC Analyzer core package
__version__ = "2.0.0"
