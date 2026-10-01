"""
Configurable Bus Adapter Interface (Stage 7).
Translates generic bus read/write/idle/reset operations into hardware bus signal assignments.
Supports TL-UL (TileLink Uncached-Lite) and Generic Register buses without hardcoded addresses.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

from .schemas import StimulusOp, StimulusOpType


class BaseBusAdapter(ABC):
    """Abstract base for protocol-specific bus signal drivers."""

    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    def generate_idle(self) -> Dict[str, Any]:
        """Generate signals for bus idle cycle."""
        pass

    @abstractmethod
    def generate_reset(self) -> Dict[str, Any]:
        """Generate signals for bus reset cycle."""
        pass

    @abstractmethod
    def generate_read(self, addr: int, priv_level: str = "UNPRIVILEGED") -> Dict[str, Any]:
        """Generate signals for a bus read transaction."""
        pass

    @abstractmethod
    def generate_write(self, addr: int, data: int, mask: int = 0xFFFFFFFF, priv_level: str = "UNPRIVILEGED") -> Dict[str, Any]:
        """Generate signals for a bus write transaction."""
        pass

    def translate_op(self, op: StimulusOp, priv_level: str = "UNPRIVILEGED") -> Dict[str, Any]:
        """Translate a StimulusOp into hardware port assignments."""
        if op.operation == StimulusOpType.RESET:
            return self.generate_reset()
        elif op.operation == StimulusOpType.IDLE:
            return self.generate_idle()
        elif op.operation == StimulusOpType.READ:
            addr = int(op.arguments.get("addr", 0))
            p = op.arguments.get("priv_level", priv_level)
            return self.generate_read(addr, p)
        elif op.operation == StimulusOpType.WRITE:
            addr = int(op.arguments.get("addr", 0))
            data = int(op.arguments.get("data", 0))
            mask = int(op.arguments.get("mask", 0xFFFFFFFF))
            p = op.arguments.get("priv_level", priv_level)
            return self.generate_write(addr, data, mask, p)
        elif op.operation == StimulusOpType.SET_ENVIRONMENT:
            # Environment inputs are passed directly to environment ports
            return dict(op.arguments)
        return self.generate_idle()


class TLULBusAdapter(BaseBusAdapter):
    """
    TileLink Uncached-Lite (TL-UL) Bus Adapter.
    Maps operations to standard TL-UL A-channel host request signals.
    """

    def __init__(self):
        super().__init__("TL_UL")

    def generate_idle(self) -> Dict[str, Any]:
        return {
            "tl_i_a_valid": 0,
            "tl_i_a_opcode": 0,
            "tl_i_a_address": 0,
            "tl_i_a_data": 0,
            "tl_i_a_mask": 0,
            "tl_i_d_ready": 1,
        }

    def generate_reset(self) -> Dict[str, Any]:
        signals = self.generate_idle()
        signals["rst_n"] = 0
        return signals

    def generate_read(self, addr: int, priv_level: str = "UNPRIVILEGED") -> Dict[str, Any]:
        # TL-UL Opcode 4 = Get (Read)
        return {
            "tl_i_a_valid": 1,
            "tl_i_a_opcode": 4,
            "tl_i_a_address": addr,
            "tl_i_a_data": 0,
            "tl_i_a_mask": 0xF,
            "tl_i_d_ready": 1,
            "tl_i_a_user_priv": 1 if priv_level == "PRIVILEGED" else 0,
        }

    def generate_write(self, addr: int, data: int, mask: int = 0xFFFFFFFF, priv_level: str = "UNPRIVILEGED") -> Dict[str, Any]:
        # TL-UL Opcode 0 = PutFullData / PutPartialData
        tl_mask = mask & 0xF if mask <= 0xF else 0xF
        return {
            "tl_i_a_valid": 1,
            "tl_i_a_opcode": 0,
            "tl_i_a_address": addr,
            "tl_i_a_data": data,
            "tl_i_a_mask": tl_mask,
            "tl_i_d_ready": 1,
            "tl_i_a_user_priv": 1 if priv_level == "PRIVILEGED" else 0,
        }


class GenericRegBusAdapter(BaseBusAdapter):
    """
    Generic Register Bus Adapter for subreg or simple memory-mapped peripherals.
    """

    def __init__(self):
        super().__init__("GENERIC_REG")

    def generate_idle(self) -> Dict[str, Any]:
        return {
            "we": 0,
            "re": 0,
            "addr": 0,
            "wdata": 0,
            "wd": 0,
        }

    def generate_reset(self) -> Dict[str, Any]:
        return {
            "rst_n": 0,
            "we": 0,
            "re": 0,
            "addr": 0,
            "wdata": 0,
            "wd": 0,
        }

    def generate_read(self, addr: int, priv_level: str = "UNPRIVILEGED") -> Dict[str, Any]:
        return {
            "we": 0,
            "re": 1,
            "addr": addr,
            "wdata": 0,
            "wd": 0,
        }

    def generate_write(self, addr: int, data: int, mask: int = 0xFFFFFFFF, priv_level: str = "UNPRIVILEGED") -> Dict[str, Any]:
        return {
            "we": 1,
            "re": 0,
            "addr": addr,
            "wdata": data,
            "wd": data,
        }


def get_bus_adapter(bus_type: Optional[str]) -> BaseBusAdapter:
    """Factory for bus adapters."""
    if bus_type == "TL_UL":
        return TLULBusAdapter()
    return GenericRegBusAdapter()
