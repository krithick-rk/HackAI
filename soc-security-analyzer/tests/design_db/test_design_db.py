"""
Focused unit tests for Stage 1: design_db foundation.
Tests source snapshots, Slang elaboration, definition-instance mapping,
parameter resolution, clock/reset facts, analyzability, and error handling.
"""

import os
import tempfile
import pytest
from src.soc_analyzer.design_db import (
    DesignDB,
    DesignDBBuilder,
    SourceManager,
    AnalyzabilityClassifier,
    AnalyzabilityLevel,
    ShippedConfig,
    SourceLocation,
    ModuleDefinition,
)


@pytest.fixture
def sample_fixture_path():
    path = os.path.abspath("fixtures/sample_rtl/module_with_keyword_comment.sv")
    assert os.path.exists(path)
    return path


@pytest.fixture
def temp_hierarchy_files():
    """Creates a temporary 2-module hierarchy for testing definition/instance mapping & parameters."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        sub_file = os.path.join(tmp_dir, "sub_core.sv")
        with open(sub_file, "w", encoding="utf-8") as f:
            f.write("""// Sub module
module sub_core #(
    parameter int DATA_WIDTH = 8
) (
    input clk,
    input rst_n,
    input [DATA_WIDTH-1:0] data_in,
    output reg [DATA_WIDTH-1:0] data_out
);
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            data_out <= '0;
        end else begin
            data_out <= data_in;
        end
    end
endmodule
""")

        top_file = os.path.join(tmp_dir, "top_soc.sv")
        with open(top_file, "w", encoding="utf-8") as f:
            f.write("""// Top module
module top_soc #(
    parameter int TOP_WIDTH = 16
) (
    input clk,
    input rst_n,
    input [TOP_WIDTH-1:0] sys_in,
    output [TOP_WIDTH-1:0] sys_out
);
    sub_core #(
        .DATA_WIDTH(TOP_WIDTH)
    ) u_sub (
        .clk(clk),
        .rst_n(rst_n),
        .data_in(sys_in),
        .data_out(sys_out)
    );
endmodule
""")

        yield [top_file, sub_file]


def test_source_snapshot_hash_and_lines(sample_fixture_path):
    mgr = SourceManager()
    snap = mgr.capture_file(sample_fixture_path)

    # 1. Snapshot metadata
    assert snap.file_path == sample_fixture_path
    assert len(snap.source_hash) == 64  # SHA256 hex string
    assert snap.line_count > 0
    assert snap.byte_size > 0
    assert snap.is_canonical is True

    # 2. Hash stability & integrity
    assert mgr.verify_integrity(sample_fixture_path) is True

    # 3. Exact line preservation without normalization or stripping
    lines = mgr.get_lines(sample_fixture_path, start_line=1, end_line=5)
    assert len(lines) == 5
    assert "module module_with_keyword_comment" in lines[0]
    assert "Contains security keyword" in lines[3]  # Original comment must be preserved exactly!


def test_definition_instance_mapping_and_parameters(temp_hierarchy_files):
    builder = DesignDBBuilder()
    db = builder.build_from_files(temp_hierarchy_files, top_module="top_soc")

    # 1. Definitions exist for both top and sub
    assert "top_soc" in db.definitions
    assert "sub_core" in db.definitions

    # 2. Instance hierarchy exists
    top_inst = db.instances.get("top_soc")
    assert top_inst is not None
    assert top_inst.module_name == "top_soc"
    assert "top_soc.u_sub" in top_inst.children

    sub_inst = db.instances.get("top_soc.u_sub")
    assert sub_inst is not None
    assert sub_inst.module_name == "sub_core"
    assert sub_inst.parent_path == "top_soc"

    # 3. Bidirectional mapping
    sub_def = db.definitions["sub_core"]
    assert "top_soc.u_sub" in sub_def.instances

    # 4. Parameter resolution
    assert "DATA_WIDTH" in sub_inst.resolved_parameters or "DATA_WIDTH" in sub_def.parameters


def test_clock_and_reset_extraction(sample_fixture_path):
    builder = DesignDBBuilder()
    db = builder.build_from_files([sample_fixture_path])

    mod_def = db.definitions["module_with_keyword_comment"]

    # 1. Clock facts
    assert len(mod_def.clocks) >= 1
    clk_names = [c.signal_name for c in mod_def.clocks]
    assert "clk" in clk_names
    assert mod_def.clocks[0].edge == "posedge"

    # 2. Reset facts
    assert len(mod_def.resets) >= 1
    rst_names = [r.signal_name for r in mod_def.resets]
    assert "rst_n" in rst_names
    assert mod_def.resets[0].active_level == "low"


def test_guarded_connectivity(sample_fixture_path):
    builder = DesignDBBuilder()
    db = builder.build_from_files([sample_fixture_path])

    conn = db.connectivity.get("module_with_keyword_comment")
    assert conn is not None
    assert len(conn.edges) >= 1

    targets = [e.target_signal for e in conn.edges]
    assert "key_ready" in targets


def test_analyzability_classification():
    classifier = AnalyzabilityClassifier()

    # 1. Clean module with informative names
    loc = SourceLocation(file="clean.sv", line=1)
    clean_def = ModuleDefinition(
        name="crypto_aes_engine",
        file_path="clean.sv",
        source_hash="abcd",
        location=loc,
        parameters={"KEY_LENGTH": "256"},
        ports={
            "clk": None, "rst_ni": None, "cipher_data_in": None,
            "cipher_data_out": None, "key_valid_i": None, "ready_o": None
        },
        instantiated_modules=["aes_sbox", "aes_mix_cols"],
    )
    res_clean = classifier.assess_module(clean_def, [], elaboration_status="SUCCESS")
    assert res_clean.level == AnalyzabilityLevel.NORMAL
    assert res_clean.overall_score >= 0.70

    # 2. Obfuscated module with stripped/mangled names
    obf_def = ModuleDefinition(
        name="_01_",
        file_path="obf.sv",
        source_hash="1234",
        location=loc,
        ports={f"x{i}": None for i in range(10)},
        instantiated_modules=[],
    )
    res_obf = classifier.assess_module(obf_def, [], elaboration_status="WARNINGS")
    assert res_obf.level in (AnalyzabilityLevel.DEGRADED, AnalyzabilityLevel.HIGHLY_OBFUSCATED)

    # 3. Configurable thresholds
    res_default = classifier.assess_module(clean_def, [], elaboration_status="WARNINGS")
    assert res_default.level == AnalyzabilityLevel.NORMAL

    custom_classifier = AnalyzabilityClassifier(config={"degraded_score_threshold": 0.95})
    res_custom = custom_classifier.assess_module(clean_def, [], elaboration_status="WARNINGS")
    assert res_custom.level == AnalyzabilityLevel.DEGRADED


def test_malformed_unsupported_input_handling():
    with tempfile.TemporaryDirectory() as tmp_dir:
        bad_file = os.path.join(tmp_dir, "broken.sv")
        with open(bad_file, "w", encoding="utf-8") as f:
            f.write("module broken_syntax ( ; missing everything")

        builder = DesignDBBuilder()
        # Must not crash; should handle gracefully
        db = builder.build_from_files([bad_file], top_module="broken_syntax")
        assert db is not None
        # File snapshot should still be recorded
        assert os.path.abspath(bad_file) in db.source_snapshots


def test_design_db_serialization_roundtrip(sample_fixture_path):
    builder = DesignDBBuilder()
    db = builder.build_from_files([sample_fixture_path])

    with tempfile.TemporaryDirectory() as tmp_dir:
        json_path = os.path.join(tmp_dir, "design_db.json")
        db.save_json(json_path)

        assert os.path.exists(json_path)
        loaded = DesignDB.load_json(json_path)

        assert loaded.design_name == db.design_name
        assert loaded.active_config == db.active_config
        assert len(loaded.definitions) == len(db.definitions)
        assert len(loaded.instances) == len(db.instances)
        assert len(loaded.source_snapshots) == len(db.source_snapshots)
