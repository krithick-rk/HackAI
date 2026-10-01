"""
Stage 2: Security Registries Unit and Integration Tests.
Tests common registry mechanics, AttackerRegistry, AssetRegistry,
DeclassifierRegistry, HJSON extraction, AI proposal guards, and DesignDB integration.
"""

import os
import json
import tempfile
import pytest

from src.soc_analyzer.registries import (
    SecurityRegistries,
    AttackerRegistry,
    AssetRegistry,
    DeclassifierRegistry,
    HjsonRegisterExtractor,
    AttackerEntry,
    AttackerBoundary,
    AssetEntry,
    RegisterMetadata,
    FieldMetadata,
    DeclassifierEntry,
    ProvenanceInfo,
    ProvenanceType,
    ApprovalStatus,
    RegistryType,
)
from src.soc_analyzer.design_db import DesignDB, ShippedConfig


# ---------------------------------------------------------------------------
# 1. Common Registry Tests
# ---------------------------------------------------------------------------

def test_common_registry_valid_load_and_save():
    mgr = SecurityRegistries()
    mgr.load_from_directory("config/registries")
    assert len(mgr.attackers.list()) >= 5
    assert len(mgr.assets.list()) >= 4
    assert len(mgr.declassifiers.list()) >= 2
    assert mgr.validate_all() == []

    with tempfile.TemporaryDirectory() as tmp_dir:
        # Save to YAML
        mgr.save_to_directory(tmp_dir, fmt="yaml")
        assert os.path.exists(os.path.join(tmp_dir, "attackers.yaml"))
        assert os.path.exists(os.path.join(tmp_dir, "assets.yaml"))
        assert os.path.exists(os.path.join(tmp_dir, "declassifiers.yaml"))

        # Load back into fresh manager
        mgr2 = SecurityRegistries()
        mgr2.load_from_directory(tmp_dir)
        assert len(mgr2.attackers.list()) == len(mgr.attackers.list())
        assert len(mgr2.assets.list()) == len(mgr.assets.list())
        assert len(mgr2.declassifiers.list()) == len(mgr.declassifiers.list())
        assert mgr2.validate_all() == []


def test_common_registry_malformed_schema():
    with tempfile.TemporaryDirectory() as tmp_dir:
        bad_yaml = os.path.join(tmp_dir, "attackers.yaml")
        with open(bad_yaml, "w", encoding="utf-8") as f:
            f.write("attackers:\n  - missing_id_field: true\n")

        mgr = SecurityRegistries()
        with pytest.raises(Exception):
            mgr.load_from_directory(tmp_dir)


def test_common_registry_duplicate_id_rejected():
    reg = AttackerRegistry()
    entry1 = AttackerEntry(
        id="ATTACKER_A",
        name="Attacker A",
        description="test",
        capabilities=["bus_read"],
        boundary=AttackerBoundary(boundary_type="BUS"),
        privilege_level="UNPRIVILEGED",
        allowed_stimulus=[],
        provenance=ProvenanceInfo(provenance_type=ProvenanceType.CONFIG),
    )
    reg.add(entry1)

    entry2 = AttackerEntry(
        id="ATTACKER_A",  # Duplicate ID!
        name="Duplicate A",
        description="duplicate",
        capabilities=["bus_write"],
        boundary=AttackerBoundary(boundary_type="BUS"),
        privilege_level="PRIVILEGED",
        allowed_stimulus=[],
        provenance=ProvenanceInfo(provenance_type=ProvenanceType.CONFIG),
    )
    with pytest.raises(ValueError, match=r"(?i)duplicate attacker id"):
        reg.add(entry2)


def test_common_registry_unknown_reference_reported():
    mgr = SecurityRegistries()
    # Add an asset referencing non-existent attacker in allowed_observers
    asset = AssetEntry(
        id="TEST_ASSET",
        name="Test Asset",
        asset_type="KEY",
        sensitivity="CRITICAL",
        source_path="reg:test",
        allowed_observers=["SW_NONEXISTENT_ATTACKER"],
        provenance=ProvenanceInfo(provenance_type=ProvenanceType.CONFIG),
        approval_status=ApprovalStatus.APPROVED,
    )
    mgr.assets.add(asset)

    # Add a declassifier referencing non-existent source asset
    declass = DeclassifierEntry(
        id="DECL_INVALID",
        source_asset_id="GHOST_ASSET_404",
        sink_target="EXTERNAL_PIN",
        allowed_transformation="HASH",
        justification="test",
        provenance=ProvenanceInfo(provenance_type=ProvenanceType.CONFIG),
        approval_status=ApprovalStatus.APPROVED,
    )
    mgr.declassifiers.add(declass)

    errors = mgr.validate_all()
    assert len(errors) >= 2
    assert any("references unknown attacker 'SW_NONEXISTENT_ATTACKER'" in e for e in errors)
    assert any("references unknown source_asset_id 'GHOST_ASSET_404'" in e for e in errors)


def test_common_registry_deterministic_serialization():
    reg = AssetRegistry()
    asset = AssetEntry(
        id="ASSET_1",
        name="Test 1",
        asset_type="KEY",
        sensitivity="HIGH",
        source_path="reg:0x10",
        safe_default_value="0x0",
        provenance=ProvenanceInfo(provenance_type=ProvenanceType.CONFIG, author="architect"),
        approval_status=ApprovalStatus.APPROVED,
    )
    reg.add(asset)
    d1 = reg.to_dict()
    d2 = reg.to_dict()
    assert json.dumps(d1, sort_keys=True) == json.dumps(d2, sort_keys=True)
    assert d1["assets"][0]["id"] == "ASSET_1"


# ---------------------------------------------------------------------------
# 2. Attacker Registry Tests
# ---------------------------------------------------------------------------

def test_attacker_registry_capabilities_and_boundary_parsing():
    entry_dict = {
        "id": "SW_UNPRIV",
        "name": "UNPRIVILEGED_SW",
        "description": "Unprivileged user code",
        "capabilities": ["bus_read", "bus_write"],
        "boundary": {
            "boundary_type": "BUS",
            "protocol": "TL_UL",
            "description": "TileLink Uncached-Lite bus",
        },
        "privilege_level": "UNPRIVILEGED",
        "allowed_stimulus": ["register_read", "register_write"],
        "provenance": {
            "provenance_type": "CONFIG",
            "source": "config/registries/attackers.yaml",
            "author": "analyst",
        },
        "approval_status": "APPROVED",
        "enabled": True,
    }
    entry = AttackerEntry.from_dict(entry_dict)
    assert entry.id == "SW_UNPRIV"
    assert "bus_read" in entry.capabilities
    assert "bus_write" in entry.capabilities
    assert entry.boundary.boundary_type == "BUS"
    assert entry.boundary.protocol == "TL_UL"
    assert entry.provenance.provenance_type == ProvenanceType.CONFIG
    assert entry.is_authoritative is True


# ---------------------------------------------------------------------------
# 3. Asset Registry & HJSON Mapping Tests
# ---------------------------------------------------------------------------

def test_asset_registry_hjson_mapping_and_fields():
    sample_hjson = """
    {
      name: "aes",
      registers: [
        {
          name: "CTRL_AUX_REGWEN",
          desc: "Auxiliary Control Register Write Enable",
          swaccess: "rw0c",
          hwaccess: "hro",
          offset: "0x04",
          resval: "1",
          fields: [
            {
              bits: "0",
              name: "EN",
              desc: "Write enable bit",
              resval: "1"
            }
          ]
        },
        {
          multireg: {
            name: "KEY_SHARE0",
            desc: "Initial Key Register Share 0",
            count: 2,
            swaccess: "wo",
            hwaccess: "hro",
            resval: "0",
            fields: [
              { bits: "31:0", name: "KEY", desc: "Key bits" }
            ]
          }
        }
      ]
    }
    """
    extractor = HjsonRegisterExtractor(auto_approve=False)
    assets = extractor.parse_hjson_text(sample_hjson, source_file="dummy.hjson", module_name="aes")

    # Should have extracted 1 single reg + 2 multiregs = 3 assets
    assert len(assets) == 3

    # Check CTRL_AUX_REGWEN
    regwen_asset = [a for a in assets if a.id == "AES_CTRL_AUX_REGWEN"][0]
    assert regwen_asset.name == "aes.CTRL_AUX_REGWEN"
    assert regwen_asset.asset_type == "SECURITY_CONFIG_REG"
    assert regwen_asset.sensitivity == "HIGH"
    assert regwen_asset.safe_default_value == "1"
    assert regwen_asset.register_metadata.swaccess == "rw0c"
    assert regwen_asset.register_metadata.hwaccess == "hro"
    assert regwen_asset.register_metadata.address_offset == "0x04"
    assert len(regwen_asset.register_metadata.fields) == 1
    assert regwen_asset.register_metadata.fields[0].name == "EN"
    assert regwen_asset.register_metadata.fields[0].bits == "0"
    assert regwen_asset.approval_status == ApprovalStatus.PROPOSED
    assert regwen_asset.provenance.provenance_type == ProvenanceType.HJSON
    # By default, extracted HJSON assets are candidate proposals, NOT authoritative anchors!
    assert regwen_asset.is_authoritative is False

    # Check multireg
    k0 = [a for a in assets if a.id == "AES_KEY_SHARE0_0"][0]
    k1 = [a for a in assets if a.id == "AES_KEY_SHARE0_1"][0]
    assert k0.asset_type == "KEY"
    assert k1.asset_type == "KEY"
    assert k0.register_metadata.swaccess == "wo"


# ---------------------------------------------------------------------------
# 4. Declassifier Registry Tests
# ---------------------------------------------------------------------------

def test_declassifier_registry_reference_and_approval():
    assets = AssetRegistry()
    assets.add(AssetEntry(
        id="ASSET_KEY",
        name="Key Asset",
        asset_type="KEY",
        sensitivity="CRITICAL",
        source_path="reg:key",
        provenance=ProvenanceInfo(provenance_type=ProvenanceType.CONFIG),
        approval_status=ApprovalStatus.APPROVED,
    ))

    declass_reg = DeclassifierRegistry()
    dec = DeclassifierEntry(
        id="DECL_AES",
        source_asset_id="ASSET_KEY",
        sink_target="SW_UNPRIV",
        allowed_transformation="AES_ENCRYPT",
        justification="Transforms plaintext/key to ciphertext",
        provenance=ProvenanceInfo(provenance_type=ProvenanceType.CONFIG),
        approval_status=ApprovalStatus.APPROVED,
    )
    declass_reg.add(dec)

    # Valid reference
    errs = declass_reg.validate_references(assets)
    assert errs == []
    assert dec.is_authoritative is True


# ---------------------------------------------------------------------------
# 5. Security Guard & AI Proposal Tests
# ---------------------------------------------------------------------------

def test_security_ai_proposal_cannot_become_approved_automatically():
    mgr = SecurityRegistries()
    prop = mgr.propose(
        registry_type=RegistryType.ASSET,
        proposed_entry={
            "id": "AI_SUGGESTED_KEY",
            "name": "crypto_key",
            "asset_type": "KEY",
            "sensitivity": "HIGH",
            "source_path": "wire:key_wire",
            "provenance": {
                "provenance_type": "AI_PROPOSAL",
                "description": "Suggested based on signal name",
            },
        },
        reason="Detected 'key' substring in RTL",
        confidence=0.45,
    )

    # Status must be PROPOSED (unapproved)
    assert prop.status == ApprovalStatus.PROPOSED
    assert prop.proposal_id in mgr.proposals

    # Cannot be treated as an authoritative anchor in the registry
    assert mgr.assets.get("AI_SUGGESTED_KEY") is None


def test_security_unapproved_asset_cannot_be_authoritative_anchor():
    # Asset in PROPOSED state
    candidate = AssetEntry(
        id="CANDIDATE_ASSET",
        name="Candidate",
        asset_type="KEY",
        sensitivity="HIGH",
        source_path="reg:candidate",
        provenance=ProvenanceInfo(provenance_type=ProvenanceType.HJSON),
        approval_status=ApprovalStatus.PROPOSED,
    )
    assert candidate.is_authoritative is False

    # AI proposal attempting to pretend to be approved without human verification
    fake_approved = AssetEntry(
        id="FAKE_APPROVED",
        name="Fake",
        asset_type="KEY",
        sensitivity="HIGH",
        source_path="reg:fake",
        provenance=ProvenanceInfo(provenance_type=ProvenanceType.AI_PROPOSAL),
        approval_status=ApprovalStatus.APPROVED,
    )
    # is_authoritative MUST return False because provenance is AI_PROPOSAL
    assert fake_approved.is_authoritative is False


def test_security_unknown_registry_data_does_not_become_positive_security_fact():
    db = DesignDB(design_name="dummy_soc")
    assert db.get_asset("NONEXISTENT_ASSET") is None
    assert db.is_asset_approved("NONEXISTENT_ASSET") is False
    assert db.is_asset_authoritative("NONEXISTENT_ASSET") is False
    assert db.get_provenance("NONEXISTENT_ASSET") is None


# ---------------------------------------------------------------------------
# 6. Proposal Workflow: Human Approval & Rejection
# ---------------------------------------------------------------------------

def test_proposal_workflow_propose_approve_reject():
    mgr = SecurityRegistries()
    prop = mgr.propose(
        registry_type=RegistryType.ASSET,
        proposed_entry={
            "id": "PROPOSED_DEBUG_REG",
            "name": "dbg_ctrl",
            "asset_type": "DEBUG_CONTROL",
            "sensitivity": "HIGH",
            "source_path": "reg:dbg_ctrl",
            "provenance": {"provenance_type": "AI_PROPOSAL"},
        },
        reason="Contains JTAG unlock control",
        confidence=0.88,
    )

    # Approve with explicit human reviewer
    entry = mgr.approve_proposal(prop.proposal_id, approver="lead_architect", notes="Verified against design spec")
    assert entry.id == "PROPOSED_DEBUG_REG"
    assert entry.approval_status == ApprovalStatus.APPROVED
    assert entry.provenance.provenance_type == ProvenanceType.HUMAN_APPROVED
    assert entry.provenance.author == "lead_architect"
    assert entry.is_authoritative is True
    assert mgr.assets.get("PROPOSED_DEBUG_REG") is not None

    # Test rejection workflow on a second proposal
    prop2 = mgr.propose(
        registry_type=RegistryType.ATTACKER,
        proposed_entry={
            "id": "ATTACKER_ALIEN",
            "name": "alien_laser",
            "capabilities": ["space_blast"],
            "boundary": {"boundary_type": "EXTERNAL"},
            "privilege_level": "EXTERNAL",
            "provenance": {"provenance_type": "AI_PROPOSAL"},
        },
        reason="Alien space ray threat",
        confidence=0.1,
    )
    mgr.reject_proposal(prop2.proposal_id, reason="Out of scope threat model")
    assert mgr.proposals[prop2.proposal_id].status == ApprovalStatus.REJECTED
    with pytest.raises(ValueError, match="Cannot approve proposal .* previously REJECTED"):
        mgr.approve_proposal(prop2.proposal_id, approver="lead_architect")


# ---------------------------------------------------------------------------
# 7. DesignDB Integration & Registry Queries
# ---------------------------------------------------------------------------

def test_design_db_answers_registry_queries():
    mgr = SecurityRegistries()
    mgr.load_from_directory("config/registries")

    db = DesignDB(design_name="secure_soc")
    db.attach_registries(mgr)

    # 1. Which attackers exist?
    attackers = db.get_attackers()
    assert len(attackers) >= 5
    attacker_ids = [a.id for a in attackers]
    assert "SW_UNPRIV" in attacker_ids
    assert "SW_PRIV" in attacker_ids
    assert "EXTERNAL_PIN" in attacker_ids

    # 2. Which assets are registered?
    assets = db.get_assets()
    assert len(assets) >= 4
    asset_ids = [a.id for a in assets]
    assert "ASSET_CTRL_REGWEN" in asset_ids
    assert "ASSET_AES_KEY" in asset_ids

    # 3. Which declassifiers are approved?
    declassifiers = db.get_declassifiers(only_approved=True)
    assert len(declassifiers) >= 2
    assert any(d.id == "DECL_AES_CIPHERTEXT" for d in declassifiers)

    # 4. What is the provenance of this asset?
    prov = db.get_provenance("ASSET_CTRL_REGWEN")
    assert prov is not None
    assert prov.provenance_type == ProvenanceType.CONFIG

    # 5. Is this asset approved?
    assert db.is_asset_approved("ASSET_CTRL_REGWEN") is True
    assert db.is_asset_authoritative("ASSET_CTRL_REGWEN") is True

    # 6. Negative checks
    assert db.is_asset_approved("NONEXISTENT") is False
    assert db.is_asset_authoritative("NONEXISTENT") is False


def test_design_db_serialization_with_registries():
    mgr = SecurityRegistries()
    mgr.load_from_directory("config/registries")

    db = DesignDB(design_name="secure_soc")
    db.attach_registries(mgr)

    with tempfile.TemporaryDirectory() as tmp_dir:
        json_file = os.path.join(tmp_dir, "db_with_regs.json")
        db.save_json(json_file)

        # Load back
        loaded = DesignDB.load_json(json_file)
        assert loaded.design_name == "secure_soc"
        assert len(loaded.get_attackers()) == len(db.get_attackers())
        assert len(loaded.get_assets()) == len(db.get_assets())
        assert len(loaded.get_declassifiers()) == len(db.get_declassifiers())
        assert loaded.is_asset_authoritative("ASSET_CTRL_REGWEN") is True


def test_real_opentitan_hjson_ingestion():
    aes_hjson_path = "/home/hackdac/opentitan/hw/ip/aes/data/aes.hjson"
    if not os.path.exists(aes_hjson_path):
        pytest.skip("OpenTitan aes.hjson not found on this machine")

    mgr = SecurityRegistries()
    mgr.ingest_hjson(aes_hjson_path, module_name="aes")

    # Ingested assets should be in PROPOSED status
    assert len(mgr.assets.list(only_approved=False)) >= 10
    # None should be approved by default (candidate metadata only)
    assert len(mgr.assets.list(only_approved=True)) == 0

    # Verify specific register metadata
    ctrl_asset = mgr.assets.get("AES_CTRL_SHADOWED")
    assert ctrl_asset is not None
    assert ctrl_asset.register_metadata.shadowed is True
    assert ctrl_asset.provenance.provenance_type == ProvenanceType.HJSON
    assert ctrl_asset.is_authoritative is False
