import os
import json
import tempfile
import pytest
from soc_analyzer.phase0.fuzzing_recommender import HeuristicFuzzingRecommender

@pytest.fixture
def mock_manifest():
    return {
        "slices": [
            {"instance": "aes_core", "cells": 8000},
            {"instance": "uart_top", "cells": 1200},
            {"instance": "gpio_block", "cells": 200},
            {"instance": "rv_core_ibex", "cells": 15000},
            {"instance": "dmi_jtag", "cells": 600},
            {"instance": "tiny_glue", "cells": 5},
            {"instance": "flash_ctrl$chip_earlgrey", "cells": 5000} # should be ignored due to $
        ]
    }

def test_heuristic_fuzzing_recommender(mock_manifest):
    with tempfile.TemporaryDirectory() as tmpdir:
        manifest_path = os.path.join(tmpdir, "manifest.json")
        output_path = os.path.join(tmpdir, "fuzzing_candidates.json")
        
        with open(manifest_path, "w") as f:
            json.dump(mock_manifest, f)
            
        recommender = HeuristicFuzzingRecommender(manifest_path, output_path)
        candidates = recommender.generate_recommendations(top_n=3)
        
        # Verify total candidates processed (6 valid ones, flash_ctrl skipped)
        assert len(candidates) == 6
        
        # Verify ranking (aes_core should be top due to crypto keyword 20 + core keyword 10 + size 10 = 40)
        assert candidates[0]["module_name"] == "aes_core"
        assert candidates[0]["score"] == 40
        assert candidates[0]["rank"] == 1
        assert "Security/Crypto" in candidates[0]["reasoning"]
        assert candidates[0]["recommended"] is True
        
        # rv_core_ibex (core -> 10 + size 10 = 20)
        assert candidates[1]["module_name"] == "rv_core_ibex"
        assert candidates[1]["score"] == 20
        assert candidates[1]["recommended"] is True
        
        # uart_top (uart -> 15 + size 2 = 17) or dmi_jtag (dmi/jtag -> 15 + size 1 = 16)
        # Verify the top 3 are recommended
        assert candidates[2]["recommended"] is True
        
        # 4th should NOT be recommended since top_n is 3
        assert candidates[3]["recommended"] is False
        
        # gpio_block has no keywords, so score is just size (0 points since < 500 cells)
        gpio = next(c for c in candidates if c["module_name"] == "gpio_block")
        assert gpio["score"] == 0
        
        # tiny_glue has 5 cells, score 0
        glue = next(c for c in candidates if c["module_name"] == "tiny_glue")
        assert glue["score"] == 0
        
        # Check that the JSON was actually written
        assert os.path.exists(output_path)
        with open(output_path, "r") as f:
            data = json.load(f)
            assert "fuzzing_candidates" in data
            assert len(data["fuzzing_candidates"]) == 6
