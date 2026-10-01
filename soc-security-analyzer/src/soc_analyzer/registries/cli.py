"""
Command-Line Interface for Security Registries.
Supports listing, validating, proposing, approving, and rejecting registry entries.
"""

from __future__ import annotations
import argparse
import sys
import os
import json
from .schemas import RegistryType, ApprovalStatus
from .manager import SecurityRegistries


def main(args: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SoC Security Analyzer Registry Manager")
    parser.add_argument("--dir", default="config/registries", help="Path to registry directory")
    
    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # validate
    subparsers.add_parser("validate", help="Validate all registries in directory")

    # list
    list_p = subparsers.add_parser("list", help="List registered entries")
    list_p.add_argument("--type", choices=["attackers", "assets", "declassifiers", "all"], default="all")

    # list-proposals
    subparsers.add_parser("list-proposals", help="List all pending or evaluated proposals")

    # approve
    app_p = subparsers.add_parser("approve", help="Approve a registry proposal")
    app_p.add_argument("proposal_id", help="Proposal ID to approve")
    app_p.add_argument("--approver", default="security_officer", help="Approver identity")
    app_p.add_argument("--notes", default="", help="Review notes")

    # reject
    rej_p = subparsers.add_parser("reject", help="Reject a registry proposal")
    rej_p.add_argument("proposal_id", help="Proposal ID to reject")
    rej_p.add_argument("--reason", default="", help="Rejection rationale")

    parsed = parser.parse_args(args)
    if not parsed.command:
        parser.print_help()
        return 0

    mgr = SecurityRegistries()
    if os.path.exists(parsed.dir):
        mgr.load_from_directory(parsed.dir)

    if parsed.command == "validate":
        errors = mgr.validate_all()
        if errors:
            print("Validation FAILED with errors:")
            for err in errors:
                print(f"  - {err}")
            return 1
        print(f"Registries in '{parsed.dir}' are VALID (no errors).")
        return 0

    elif parsed.command == "list":
        if parsed.type in ("attackers", "all"):
            print("=== Attackers ===")
            for a in mgr.attackers.list():
                print(f"  [{a.id}] {a.name} ({a.privilege_level}) - status={a.approval_status.value}")
        if parsed.type in ("assets", "all"):
            print("=== Assets ===")
            for ast in mgr.assets.list():
                print(f"  [{ast.id}] {ast.name} ({ast.asset_type}, {ast.sensitivity}) - status={ast.approval_status.value}")
        if parsed.type in ("declassifiers", "all"):
            print("=== Declassifiers ===")
            for d in mgr.declassifiers.list():
                print(f"  [{d.id}] {d.source_asset_id} -> {d.sink_target} ({d.allowed_transformation}) - status={d.approval_status.value}")
        return 0

    elif parsed.command == "list-proposals":
        print(f"Proposals ({len(mgr.proposals)}):")
        for pid, p in mgr.proposals.items():
            print(f"  [{pid}] type={p.registry_type.value} status={p.status.value} confidence={p.confidence:.2f} reason='{p.reason}'")
        return 0

    elif parsed.command == "approve":
        try:
            entry = mgr.approve_proposal(parsed.proposal_id, approver=parsed.approver, notes=parsed.notes)
            mgr.save_to_directory(parsed.dir)
            print(f"Proposal '{parsed.proposal_id}' successfully APPROVED as {type(entry).__name__} id='{entry.id}'.")
            return 0
        except Exception as e:
            print(f"Error approving proposal: {e}", file=sys.stderr)
            return 1

    elif parsed.command == "reject":
        try:
            mgr.reject_proposal(parsed.proposal_id, reason=parsed.reason)
            mgr.save_to_directory(parsed.dir)
            print(f"Proposal '{parsed.proposal_id}' successfully REJECTED.")
            return 0
        except Exception as e:
            print(f"Error rejecting proposal: {e}", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
