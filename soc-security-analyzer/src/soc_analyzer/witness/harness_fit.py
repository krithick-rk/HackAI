"""
Target DUT Interface Classification and Harness Fit Scanner (Stage 7).
Deterministically scans module ports and interface types from DesignDB to determine
if a generic bus harness can attach to the DUT.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set

from src.soc_analyzer.design_db.schemas import DesignDB, ModuleDefinition, PortFact
from .schemas import HarnessFitStatus, HarnessCategory


@dataclass
class HarnessFitResult:
    """Detailed outcome of a target DUT harness fit scan."""
    status: HarnessFitStatus
    module_name: str
    port_categories: Dict[str, HarnessCategory] = field(default_factory=dict)
    bus_type: Optional[str] = None  # "TL_UL", "GENERIC_REG", None
    assumptions: List[str] = field(default_factory=list)
    unsupported_reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "module_name": self.module_name,
            "port_categories": {k: v.value for k, v in self.port_categories.items()},
            "bus_type": self.bus_type,
            "assumptions": self.assumptions,
            "unsupported_reasons": self.unsupported_reasons,
        }


class HarnessFitScanner:
    """
    Deterministic interface classifier for hardware DUTs.
    """

    @classmethod
    def scan_module(cls, module_def: ModuleDefinition) -> HarnessFitResult:
        port_categories: Dict[str, HarnessCategory] = {}
        has_clock = False
        has_reset = False
        has_bus_slave = False
        bus_type: Optional[str] = None
        assumptions: List[str] = []
        unsupported_reasons: List[str] = []

        # 1. Classify each port
        for port_name, port_fact in module_def.ports.items():
            cat = cls._classify_port(port_name, port_fact)
            port_categories[port_name] = cat

            if cat == HarnessCategory.CLOCK:
                has_clock = True
            elif cat == HarnessCategory.RESET:
                has_reset = True
            elif cat == HarnessCategory.BUS_SLAVE:
                has_bus_slave = True
                p_lower = port_name.lower()
                if "tl_i" in p_lower or "tl_o" in p_lower or "tlul" in p_lower:
                    bus_type = "TL_UL"
                elif bus_type is None:
                    bus_type = "GENERIC_REG"

        # Also check module clocks and resets list if ports were partially elaborated
        if not has_clock and module_def.clocks:
            has_clock = True
        if not has_reset and module_def.resets:
            has_reset = True

        # Check for environment dependencies
        for p, cat in port_categories.items():
            if cat in (HarnessCategory.LIFECYCLE, HarnessCategory.OTP, HarnessCategory.ENTROPY, HarnessCategory.KEY_SIDELOAD):
                assumptions.append(f"environment_stub_required:{p}:{cat.value}")
            elif cat == HarnessCategory.MEMORY:
                assumptions.append(f"sram_memory_stub_required:{p}")

        # 2. Determine Harness Fit Status
        if not has_bus_slave:
            unsupported_reasons.append("no_bus_slave_interface_detected")
            return HarnessFitResult(
                status=HarnessFitStatus.HARNESS_UNSUPPORTED,
                module_name=module_def.name,
                port_categories=port_categories,
                bus_type=None,
                assumptions=assumptions,
                unsupported_reasons=unsupported_reasons,
            )

        if not has_clock or not has_reset:
            assumptions.append("missing_explicit_clk_rst_ports; using_default_clocking")

        if any(cat == HarnessCategory.BUS_MASTER for cat in port_categories.values()):
            assumptions.append("bus_master_ports_present; generic_harness_operates_as_slave_only")

        if assumptions:
            status = HarnessFitStatus.SUPPORTED_WITH_ASSUMPTIONS
        else:
            status = HarnessFitStatus.SUPPORTED

        return HarnessFitResult(
            status=status,
            module_name=module_def.name,
            port_categories=port_categories,
            bus_type=bus_type or "GENERIC_REG",
            assumptions=assumptions,
            unsupported_reasons=unsupported_reasons,
        )

    @classmethod
    def _classify_port(cls, port_name: str, port_fact: PortFact) -> HarnessCategory:
        p = port_name.lower()

        # Clock
        if any(x in p for x in ("clk", "clock")):
            return HarnessCategory.CLOCK

        # Reset
        if any(x in p for x in ("rst", "reset")):
            return HarnessCategory.RESET

        # Bus Slave (TL-UL or Generic Register Bus)
        if any(x in p for x in ("tl_i", "tl_o", "tlul", "reg_we", "reg_addr", "reg_wdata", "reg_rdata", "bus_i", "bus_o")):
            return HarnessCategory.BUS_SLAVE
        if (p in ("we", "wd", "q", "re", "addr", "wdata", "rdata", "req", "rsp") and
                port_fact.direction in ("input", "output")):
            return HarnessCategory.BUS_SLAVE

        # Bus Master
        if any(x in p for x in ("tl_d_i", "tl_d_o", "host_req", "master_out")):
            return HarnessCategory.BUS_MASTER

        # Alert
        if "alert" in p:
            return HarnessCategory.ALERT

        # Lifecycle
        if any(x in p for x in ("lc_", "lifecycle")):
            return HarnessCategory.LIFECYCLE

        # OTP
        if "otp" in p:
            return HarnessCategory.OTP

        # Entropy
        if any(x in p for x in ("entropy", "edn")):
            return HarnessCategory.ENTROPY

        # Key Sideload
        if any(x in p for x in ("sideload", "keymgr", "key_i")):
            return HarnessCategory.KEY_SIDELOAD

        # Pins / GPIOs
        if any(x in p for x in ("cio_", "pin", "pad", "gpio")):
            return HarnessCategory.PIN

        # Interrupts
        if any(x in p for x in ("intr", "irq")):
            return HarnessCategory.INTERRUPT

        # Memory / SRAM
        if any(x in p for x in ("sram", "bram", "mem_")):
            return HarnessCategory.MEMORY

        return HarnessCategory.UNKNOWN
