"""
Persistent SQLite Finding Store (Stage 6).
Provides durable relational storage for findings, evidence references,
instance manifestations, state transitions, and deduplication lookups.
"""

from __future__ import annotations
import sqlite3
import json
import os
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timezone

from .schemas import (
    Finding,
    FindingStatus,
    FindingLane,
    FindingReason,
    Severity,
    EvidenceItem,
    EvidenceType,
    VerificationStatus,
    InstanceManifestation,
)
from .state_machine import StateTransitionValidator
from .dedup import merge_duplicate_finding


class SQLiteFindingStore:
    """
    Lightweight, durable SQLite store for findings and structured evidence.
    """

    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        if db_path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self._init_tables()

    def _init_tables(self) -> None:
        with self.conn:
            self.conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT PRIMARY KEY,
                title TEXT,
                weakness_class TEXT,
                severity TEXT,
                source TEXT,
                source_channel TEXT,
                file TEXT,
                line_start INTEGER,
                line_end INTEGER,
                definition_id TEXT,
                instance_path TEXT,
                configuration TEXT,
                asset_id TEXT,
                attacker_id TEXT,
                status TEXT,
                lane TEXT,
                parked_reason TEXT,
                reachability_json TEXT,
                witness_refs_json TEXT,
                cwe TEXT,
                cwe_source TEXT,
                dedup_signature TEXT,
                created_at TEXT,
                updated_at TEXT,
                metadata_json TEXT
            )
            """)

            self.conn.execute("""
            CREATE TABLE IF NOT EXISTS evidence (
                evidence_id TEXT PRIMARY KEY,
                finding_id TEXT,
                evidence_type TEXT,
                producer TEXT,
                artifact_reference TEXT,
                hash TEXT,
                configuration TEXT,
                instance_path TEXT,
                description TEXT,
                verification_status TEXT,
                created_at TEXT,
                metadata_json TEXT,
                FOREIGN KEY (finding_id) REFERENCES findings(finding_id)
            )
            """)

            self.conn.execute("""
            CREATE TABLE IF NOT EXISTS manifestations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id TEXT,
                instance_path TEXT,
                configuration TEXT,
                file_path TEXT,
                line_start INTEGER,
                line_end INTEGER,
                deviating_json TEXT,
                first_seen TEXT,
                FOREIGN KEY (finding_id) REFERENCES findings(finding_id)
            )
            """)

            # Indices for rapid querying
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_fnd_dedup ON findings(dedup_signature)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_fnd_lane ON findings(lane)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_fnd_weakness ON findings(weakness_class)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_fnd_instance ON findings(instance_path)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_ev_finding ON evidence(finding_id)")

    def create_finding(self, finding: Finding) -> Finding:
        with self.conn:
            self.conn.execute("""
            INSERT INTO findings (
                finding_id, title, weakness_class, severity, source, source_channel,
                file, line_start, line_end, definition_id, instance_path, configuration,
                asset_id, attacker_id, status, lane, parked_reason, reachability_json,
                witness_refs_json, cwe, cwe_source, dedup_signature, created_at, updated_at,
                metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                finding.finding_id,
                finding.title,
                finding.weakness_class,
                finding.severity.value,
                finding.source,
                finding.source_channel,
                finding.file,
                finding.line_range[0],
                finding.line_range[1],
                finding.definition_id,
                finding.instance_path,
                finding.configuration,
                finding.asset_id,
                finding.attacker_id,
                finding.status.value,
                finding.lane.value,
                finding.parked_reason.value,
                json.dumps(finding.reachability_result) if finding.reachability_result else None,
                json.dumps(finding.witness_refs),
                finding.cwe,
                finding.cwe_source,
                finding.dedup_signature,
                finding.created_at,
                finding.updated_at,
                json.dumps(finding.metadata),
            ))

            for ev in finding.evidence_refs:
                self._insert_evidence(finding.finding_id, ev)

            for man in finding.manifestations:
                self._insert_manifestation(finding.finding_id, man)

        return finding

    def update_finding(self, finding: Finding) -> Finding:
        finding.updated_at = datetime.now(timezone.utc).isoformat()
        with self.conn:
            self.conn.execute("""
            UPDATE findings SET
                title = ?, weakness_class = ?, severity = ?, source = ?, source_channel = ?,
                file = ?, line_start = ?, line_end = ?, definition_id = ?, instance_path = ?,
                configuration = ?, asset_id = ?, attacker_id = ?, status = ?, lane = ?,
                parked_reason = ?, reachability_json = ?, witness_refs_json = ?, cwe = ?,
                cwe_source = ?, dedup_signature = ?, updated_at = ?, metadata_json = ?
            WHERE finding_id = ?
            """, (
                finding.title,
                finding.weakness_class,
                finding.severity.value,
                finding.source,
                finding.source_channel,
                finding.file,
                finding.line_range[0],
                finding.line_range[1],
                finding.definition_id,
                finding.instance_path,
                finding.configuration,
                finding.asset_id,
                finding.attacker_id,
                finding.status.value,
                finding.lane.value,
                finding.parked_reason.value,
                json.dumps(finding.reachability_result) if finding.reachability_result else None,
                json.dumps(finding.witness_refs),
                finding.cwe,
                finding.cwe_source,
                finding.dedup_signature,
                finding.updated_at,
                json.dumps(finding.metadata),
                finding.finding_id,
            ))

            # Resync evidence & manifestations
            self.conn.execute("DELETE FROM evidence WHERE finding_id = ?", (finding.finding_id,))
            for ev in finding.evidence_refs:
                self._insert_evidence(finding.finding_id, ev)

            self.conn.execute("DELETE FROM manifestations WHERE finding_id = ?", (finding.finding_id,))
            for man in finding.manifestations:
                self._insert_manifestation(finding.finding_id, man)

        return finding

    def _insert_evidence(self, finding_id: str, ev: EvidenceItem) -> None:
        self.conn.execute("""
        INSERT OR REPLACE INTO evidence (
            evidence_id, finding_id, evidence_type, producer, artifact_reference,
            hash, configuration, instance_path, description, verification_status,
            created_at, metadata_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ev.evidence_id,
            finding_id,
            ev.evidence_type.value,
            ev.producer,
            ev.artifact_reference,
            ev.hash,
            ev.configuration,
            ev.instance_path,
            ev.description,
            ev.verification_status.value,
            ev.created_at,
            json.dumps(ev.metadata),
        ))

    def _insert_manifestation(self, finding_id: str, man: InstanceManifestation) -> None:
        self.conn.execute("""
        INSERT INTO manifestations (
            finding_id, instance_path, configuration, file_path, line_start,
            line_end, deviating_json, first_seen
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            finding_id,
            man.instance_path,
            man.configuration,
            man.file_path,
            man.line_range[0],
            man.line_range[1],
            json.dumps(man.deviating_attributes),
            man.first_seen,
        ))

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        cursor = self.conn.execute("SELECT * FROM findings WHERE finding_id = ?", (finding_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return self._row_to_finding(row)

    def get_by_dedup_signature(self, dedup_sig: str) -> Optional[Finding]:
        cursor = self.conn.execute(
            "SELECT * FROM findings WHERE dedup_signature = ? AND status != 'DUPLICATE' LIMIT 1",
            (dedup_sig,)
        )
        row = cursor.fetchone()
        if not row:
            return None
        return self._row_to_finding(row)

    def list_findings(
        self,
        status: Optional[FindingStatus] = None,
        lane: Optional[FindingLane] = None,
        weakness_class: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[Finding]:
        query = "SELECT * FROM findings WHERE 1=1"
        params: List[Any] = []
        if status:
            query += " AND status = ?"
            params.append(status.value)
        if lane:
            query += " AND lane = ?"
            params.append(lane.value)
        if weakness_class:
            query += " AND weakness_class = ?"
            params.append(weakness_class)
        query += " ORDER BY created_at ASC"
        if limit:
            query += " LIMIT ?"
            params.append(limit)

        cursor = self.conn.execute(query, params)
        return [self._row_to_finding(r) for r in cursor.fetchall()]

    def add_evidence(self, finding_id: str, evidence: EvidenceItem) -> None:
        finding = self.get_finding(finding_id)
        if not finding:
            raise KeyError(f"Finding {finding_id} not found")
        finding.evidence_refs.append(evidence)
        self.update_finding(finding)

    def add_manifestation(self, finding_id: str, manifestation: InstanceManifestation) -> None:
        finding = self.get_finding(finding_id)
        if not finding:
            raise KeyError(f"Finding {finding_id} not found")
        finding.manifestations.append(manifestation)
        self.update_finding(finding)

    def merge_duplicate(self, primary_id: str, duplicate: Finding) -> Finding:
        primary = self.get_finding(primary_id)
        if not primary:
            raise KeyError(f"Primary finding {primary_id} not found")

        merged_primary = merge_duplicate_finding(primary, duplicate)
        self.update_finding(merged_primary)
        # Store duplicate record as well
        self.create_finding(duplicate)
        return merged_primary

    def transition_state(
        self,
        finding_id: str,
        new_status: FindingStatus,
        new_lane: Optional[FindingLane] = None,
        reason: FindingReason = FindingReason.NONE,
        is_ai: bool = False,
    ) -> Finding:
        finding = self.get_finding(finding_id)
        if not finding:
            raise KeyError(f"Finding {finding_id} not found")

        StateTransitionValidator.validate_transition(
            finding=finding,
            new_status=new_status,
            new_lane=new_lane,
            is_ai_origin=is_ai,
        )

        finding.status = new_status
        if new_lane:
            finding.lane = new_lane
        finding.parked_reason = reason
        return self.update_finding(finding)

    def query_by_lane(self, lane: FindingLane) -> List[Finding]:
        return self.list_findings(lane=lane)

    def query_by_weakness_class(self, weakness_class: str) -> List[Finding]:
        return self.list_findings(weakness_class=weakness_class)

    def query_by_instance(self, instance_path: str) -> List[Finding]:
        cursor = self.conn.execute("""
        SELECT DISTINCT f.* FROM findings f
        LEFT JOIN manifestations m ON f.finding_id = m.finding_id
        WHERE f.instance_path = ? OR m.instance_path = ?
        """, (instance_path, instance_path))
        return [self._row_to_finding(r) for r in cursor.fetchall()]

    def _row_to_finding(self, row: sqlite3.Row) -> Finding:
        f_id = row["finding_id"]

        # Fetch evidence
        ev_cursor = self.conn.execute("SELECT * FROM evidence WHERE finding_id = ?", (f_id,))
        evidence_refs: List[EvidenceItem] = []
        for er in ev_cursor.fetchall():
            evidence_refs.append(EvidenceItem(
                evidence_id=er["evidence_id"],
                evidence_type=EvidenceType(er["evidence_type"]),
                producer=er["producer"],
                artifact_reference=er["artifact_reference"],
                hash=er["hash"],
                configuration=er["configuration"],
                instance_path=er["instance_path"],
                description=er["description"],
                verification_status=VerificationStatus(er["verification_status"]),
                created_at=er["created_at"],
                metadata=json.loads(er["metadata_json"] or "{}"),
            ))

        # Fetch manifestations
        man_cursor = self.conn.execute("SELECT * FROM manifestations WHERE finding_id = ?", (f_id,))
        manifestations: List[InstanceManifestation] = []
        for mr in man_cursor.fetchall():
            manifestations.append(InstanceManifestation(
                instance_path=mr["instance_path"],
                configuration=mr["configuration"],
                file_path=mr["file_path"],
                line_range=(mr["line_start"], mr["line_end"]),
                deviating_attributes=json.loads(mr["deviating_json"] or "{}"),
                first_seen=mr["first_seen"],
            ))

        reach_dict = json.loads(row["reachability_json"]) if row["reachability_json"] else None
        witness_list = json.loads(row["witness_refs_json"] or "[]")
        meta_dict = json.loads(row["metadata_json"] or "{}")

        return Finding(
            finding_id=f_id,
            title=row["title"],
            weakness_class=row["weakness_class"],
            severity=Severity(row["severity"]),
            source=row["source"],
            source_channel=row["source_channel"],
            file=row["file"],
            line_range=(row["line_start"], row["line_end"]),
            definition_id=row["definition_id"],
            instance_path=row["instance_path"],
            configuration=row["configuration"],
            asset_id=row["asset_id"],
            attacker_id=row["attacker_id"],
            status=FindingStatus(row["status"]),
            lane=FindingLane(row["lane"]),
            parked_reason=FindingReason(row["parked_reason"]),
            evidence_refs=evidence_refs,
            reachability_result=reach_dict,
            witness_refs=witness_list,
            cwe=row["cwe"],
            cwe_source=row["cwe_source"],
            dedup_signature=row["dedup_signature"],
            manifestations=manifestations,
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            metadata=meta_dict,
        )

    def close(self) -> None:
        self.conn.close()
