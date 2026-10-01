import json
import os
import re
from typing import List, Dict

class HeuristicFuzzingRecommender:
    """
    Analyzes the Phase 0.4 synthesis manifest and deterministically scores
    modules to recommend them for Phase 3b Fuzzing.
    """
    
    CRYPTO_KEYWORDS = ["aes", "rsa", "kmac", "crypto", "otp", "rom", "key", "hmac", "sha"]
    INTERFACE_KEYWORDS = ["jtag", "dmi", "uart", "spi", "i2c", "usb", "pinmux", "padctrl", "eth", "flash"]
    CTRL_KEYWORDS = ["core", "cpu", "ctrl", "bus", "xbar", "sys"]
    
    def __init__(self, manifest_path: str, output_path: str):
        self.manifest_path = manifest_path
        self.output_path = output_path
        
    def _score_module(self, name: str, cells: int) -> dict:
        score = 0
        reasons = []
        
        name_lower = name.lower()
        
        # Keyword checks
        crypto_matches = [k for k in self.CRYPTO_KEYWORDS if k in name_lower]
        if crypto_matches:
            score += 20
            reasons.append(f"Security/Crypto related ({', '.join(crypto_matches)})")
            
        if any(k in name_lower for k in self.INTERFACE_KEYWORDS):
            score += 15
            reasons.append("External Interface boundary")
            
        if any(k in name_lower for k in self.CTRL_KEYWORDS):
            score += 10
            reasons.append("Processor or Controller")
            
        # Ignore completely empty or monolithic modules
        if cells > 0:
            size_score = min(10, cells // 500)
            if size_score > 0:
                score += size_score
                reasons.append("High cell complexity")
                
        reason_str = " and ".join(reasons) if reasons else "No specific risk markers identified"
        
        return {
            "module_name": name,
            "score": score,
            "reasoning": reason_str,
            "cells": cells
        }

    def generate_recommendations(self, top_n: int = 10) -> List[Dict]:
        if not os.path.exists(self.manifest_path):
            raise FileNotFoundError(f"Manifest not found: {self.manifest_path}")
            
        with open(self.manifest_path, 'r') as f:
            manifest = json.load(f)
            
        slices = manifest.get("slices", [])
        
        scored_modules = []
        for s in slices:
            name = s.get("instance", "")
            # Skip internal yosys generated modules (containing $)
            if "$" in name or not name:
                continue
                
            cells = s.get("cells", 0)
            scored = self._score_module(name, cells)
            scored_modules.append(scored)
            
        # Sort by score descending
        scored_modules.sort(key=lambda x: x["score"], reverse=True)
        
        # Assign rank and 'recommended' boolean
        final_list = []
        for i, mod in enumerate(scored_modules):
            final_list.append({
                "module_name": mod["module_name"],
                "rank": i + 1,
                "score": mod["score"],
                "reasoning": mod["reasoning"],
                "recommended": i < top_n and mod["score"] > 0
            })
            
        # Save to output path
        os.makedirs(os.path.dirname(self.output_path), exist_ok=True)
        with open(self.output_path, 'w') as f:
            json.dump({"fuzzing_candidates": final_list}, f, indent=2)
            
        return final_list
