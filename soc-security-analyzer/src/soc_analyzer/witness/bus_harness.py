"""
Generic Register-IP Bus Harness Generator (Stage 7).
Generates Verilog testbenches and driver logic for bus-attached hardware DUTs.
Enforces separation of attacker inputs, environment tie-offs, and read-only internal observation.
"""

from __future__ import annotations
import os
from typing import Dict, List, Optional, Any, Set

from src.soc_analyzer.design_db.schemas import ModuleDefinition, PortFact
from .schemas import Scenario, HarnessCategory
from .harness_fit import HarnessFitResult
from .bus_adapter import BaseBusAdapter, get_bus_adapter


class GenericBusHarnessGenerator:
    """
    Generates deterministic Verilog testbench wrappers connecting a bus adapter to the DUT.
    """

    @classmethod
    def generate_verilog_harness(
        cls,
        module_def: ModuleDefinition,
        fit_result: HarnessFitResult,
        scenario: Scenario,
        output_dir: str,
    ) -> str:
        """
        Generate standalone SystemVerilog testbench file (tb_<module>.sv).
        Returns the absolute path to the generated testbench.
        """
        os.makedirs(output_dir, exist_ok=True)
        tb_path = os.path.join(output_dir, f"tb_{module_def.name}.sv")
        bus_adapter = get_bus_adapter(fit_result.bus_type)

        lines: List[str] = [
            "`timescale 1ns/1ps",
            f"module tb_{module_def.name};",
            "  logic clk;",
            "  logic rst_n;",
            "",
            "  // Clock generation (100MHz)",
            "  initial clk = 0;",
            "  always #5 clk = ~clk;",
            "",
            "  // DUT Port Signals",
        ]

        # Declare signals for DUT ports
        port_wires: List[str] = []
        dut_connections: List[str] = []

        for p_name, p_fact in module_def.ports.items():
            cat = fit_result.port_categories.get(p_name, HarnessCategory.UNKNOWN)
            width_spec = f"[{int(p_fact.width)-1}:0]" if p_fact.width and p_fact.width != "1" else ""

            if cat == HarnessCategory.CLOCK:
                dut_connections.append(f"    .{p_name}(clk)")
            elif cat == HarnessCategory.RESET:
                dut_connections.append(f"    .{p_name}(rst_n)")
            else:
                sig_name = f"dut_{p_name}"
                port_wires.append(f"  logic {width_spec} {sig_name};")
                dut_connections.append(f"    .{p_name}({sig_name})")

        lines.extend(port_wires)
        lines.append("")
        lines.append(f"  // Instantiate DUT: {module_def.name}")
        lines.append(f"  {module_def.name} u_dut (")
        lines.append(",\n".join(dut_connections))
        lines.append("  );")
        lines.append("")

        # Environment tie-offs
        lines.append("  // Environment tie-offs (from scenario)")
        for p_name, cat in fit_result.port_categories.items():
            if cat in (HarnessCategory.LIFECYCLE, HarnessCategory.OTP, HarnessCategory.ENTROPY, HarnessCategory.KEY_SIDELOAD):
                env_val = scenario.environment_inputs.get(p_name, 0)
                lines.append(f"  assign dut_{p_name} = {env_val};")

        # Initial stimulus procedure
        lines.append("")
        lines.append("  initial begin")
        lines.append('    $display("[TB] Starting generic bus harness simulation");')
        lines.append("    rst_n = 0;")
        lines.append("    #20 rst_n = 1;")
        lines.append("    #10;")

        # Translate scenario stimulus sequence into cycle delays and assignments
        for op in scenario.stimulus_sequence:
            cycle_delay = max(1, op.cycle)
            lines.append(f"    #10; // cycle {op.cycle}: {op.operation.value}")
            signals = bus_adapter.translate_op(op)
            for s_name, s_val in signals.items():
                if f"dut_{s_name}" in port_wires or any(f" {s_name};" in w for w in port_wires):
                    lines.append(f"    dut_{s_name} = {s_val};")

        lines.append("    #50;")
        lines.append('    $display("[TB] Simulation completed successfully");')
        lines.append("    $finish;")
        lines.append("  end")
        lines.append("endmodule")

        with open(tb_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

        return tb_path
