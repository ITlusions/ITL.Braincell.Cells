"""LLM-based AI triage agent for vulnerability reports.

Scope (per RoE — ITL.Amalia/docs/engagements/RoE-ITlusions-Testlab-2026.md §11):
this agent only reasons over findings already recorded in BrainCell's own
vuln_reports cell. It does not scan third-party systems, does not build or
fuzz binaries, and never reaches outside the BrainCell database.

Unlike a fixed-threshold rule engine, decisions are produced by an LLM given
the finding's full context (CVE, CVSS, affected component/versions,
description) and asked to reason about real-world exploitability and
escalation priority, returning a structured, validated decision.
"""
import json
import os
from typing import Literal

from pydantic import BaseModel, Field
from pydantic_ai import Agent
from sqlalchemy.orm import Session

from itl_braincell_cells_security.cells.incidents.model import SecurityIncident

from .model import VulnReport

_MODEL = os.environ.get("SECURITY_AGENT_MODEL", "openai:gpt-4o-mini")

_SYSTEM_PROMPT = (
    "You are a security triage analyst reviewing a single vulnerability finding "
    "already recorded in an internal vulnerability database. Decide whether it "
    "should be escalated to the incident-response team now, needs a human to "
    "review it before any action, or can stay open as low priority. Only reason "
    "about the information given — never assume access to scan, exploit, or "
    "contact any system."
)


class TriageDecision(BaseModel):
    """Structured decision returned by the LLM for one finding."""

    decision: Literal["escalate", "needs_review", "no_action"]
    confidence: Literal["high", "medium", "low"]
    reasoning: str = Field(description="Short justification for the decision")


_triage_agent = Agent(
    _MODEL,
    output_type=TriageDecision,
    system_prompt=_SYSTEM_PROMPT,
)


class VulnReportTriageAgent:
    """Reviews open vulnerability reports and lets an LLM decide the next step.

    - decision == "escalate"     -> creates a `SecurityIncident`, report.status = "triaged".
    - decision == "needs_review" -> report.status = "needs_review".
    - decision == "no_action"    -> left open, untouched.

    Every decision (including the LLM's reasoning) is stored on the report's
    `meta_data["ai_triage"]` field for auditability.
    """

    def __init__(self, db: Session, batch_size: int = 25) -> None:
        self._db = db
        self._batch_size = batch_size

    def run(self) -> dict:
        open_reports = (
            self._db.query(VulnReport)
            .filter(VulnReport.status == "open")
            .order_by(VulnReport.created_at.asc())
            .limit(self._batch_size)
            .all()
        )

        escalated, needs_review, no_action, failed = [], [], [], []

        for report in open_reports:
            try:
                decision = self._reason_about(report)
            except Exception as exc:  # noqa: BLE001 - one bad call must not abort the batch
                failed.append({"id": str(report.id), "error": str(exc)})
                continue

            report.meta_data = {
                **(report.meta_data or {}),
                "ai_triage": decision.dict(),
            }

            if decision.decision == "escalate":
                self._escalate(report, decision)
                escalated.append(str(report.id))
            elif decision.decision == "needs_review":
                report.status = "needs_review"
                needs_review.append(str(report.id))
            else:
                no_action.append(str(report.id))

        self._db.commit()

        return {
            "reviewed_count": len(open_reports),
            "escalated_count": len(escalated),
            "needs_review_count": len(needs_review),
            "no_action_count": len(no_action),
            "failed_count": len(failed),
            "escalated_ids": escalated,
            "needs_review_ids": needs_review,
            "failed": failed,
        }

    def _reason_about(self, report: VulnReport) -> TriageDecision:
        finding = {
            "title": report.title,
            "description": report.description,
            "cve_id": report.cve_id,
            "cvss_score": report.cvss_score,
            "severity": report.severity,
            "affected_component": report.affected_component,
            "affected_versions": report.affected_versions,
        }

        result = _triage_agent.run_sync(json.dumps(finding))
        return result.output

    def _escalate(self, report: VulnReport, decision: TriageDecision) -> None:
        incident = SecurityIncident(
            title=f"Escalated finding: {report.title}",
            description=(
                f"Auto-escalated by AI triage agent from vuln_reports ({report.id}).\n"
                f"CVE: {report.cve_id or 'n/a'}, CVSS: {report.cvss_score}, "
                f"component: {report.affected_component or 'n/a'}.\n"
                f"Agent reasoning: {decision.reasoning}"
            ),
            severity=report.severity,
            status="open",
            attack_vector=None,
            meta_data={"source_vuln_report_id": str(report.id), "auto_escalated": True},
        )
        self._db.add(incident)
        report.status = "triaged"
