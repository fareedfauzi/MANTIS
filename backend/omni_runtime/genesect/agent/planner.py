"""Host-owned planning state for autonomous agent runs."""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass, field


PENDING = "pending"
IN_PROGRESS = "in_progress"
COMPLETE = "complete"
BLOCKED = "blocked"


@dataclass
class PlanStep:
    id: str
    title: str
    status: str = PENDING
    evidence: list = field(default_factory=list)
    result: str = ""
    updated_at: float = field(default_factory=time.time)

    def to_dict(self):
        data = asdict(self)
        data["updated_at_iso"] = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.updated_at)
        )
        return data


class AgentPlan:
    """A compact host-owned checklist used to steer and audit the agent."""

    def __init__(self, objective="", mode="interactive"):
        self.objective = str(objective or "")
        self.mode = str(mode or "interactive")
        self.created_at = time.time()
        self.steps = []

    def reset(self, objective="", mode="interactive", target_count=0):
        self.objective = str(objective or "")
        self.mode = str(mode or "interactive")
        self.created_at = time.time()
        self.steps = self._default_steps(self.mode, target_count)

    def _default_steps(self, mode, target_count=0):
        titles = [
            "Establish binary and function context",
            "Collect direct code evidence",
            "Record evidence-backed findings",
            "Synthesize final answer with uncertainty",
        ]
        if mode == "autonomous_full":
            titles = [
                "Build binary-wide coverage target list",
                "Analyze ready functions with code and evidence",
                "Record function summaries and rename decisions",
                "Validate coverage and unresolved failures",
                "Synthesize final binary-wide report",
            ]
        elif mode in ("focused", "interactive"):
            titles = [
                "Understand analyst request",
                "Collect the smallest sufficient evidence",
                "Check durable memory and current observations",
                "Synthesize direct answer",
            ]
        elif mode == "legacy_bulk":
            titles = [
                "Enumerate leaf functions",
                "Analyze queued functions",
                "Apply reviewed metadata changes",
                "Export batch report",
            ]
        return [PlanStep(uuid.uuid4().hex[:12], title) for title in titles]

    def mark(self, title_contains, status, evidence=None, result=""):
        needle = str(title_contains or "").lower()
        for step in self.steps:
            if needle in step.title.lower():
                step.status = status
                if evidence:
                    step.evidence = list(dict.fromkeys(step.evidence + list(evidence)))[:20]
                if result:
                    step.result = str(result)[:2000]
                step.updated_at = time.time()
                return step
        return None

    def start_next(self):
        for step in self.steps:
            if step.status == PENDING:
                step.status = IN_PROGRESS
                step.updated_at = time.time()
                return step
        return None

    def complete_for_tool(self, tool, args=None, result_status=""):
        tool = str(tool or "")
        evidence = []
        if args and args.get("ea"):
            evidence.append(str(args.get("ea")))
        if tool in {"binary_overview", "list_segments", "list_imports", "list_exports", "list_entrypoints"}:
            self.mark("context", COMPLETE, evidence, tool)
            self.mark("target list", COMPLETE, evidence, tool)
        if tool in {"function_info", "function_evidence", "decompile", "disassemble", "basic_blocks", "stack_layout"}:
            self.mark("code evidence", COMPLETE, evidence, tool)
            self.mark("ready functions", IN_PROGRESS, evidence, tool)
            self.mark("sufficient evidence", COMPLETE, evidence, tool)
        if tool in {"record_finding"}:
            self.mark("findings", COMPLETE, evidence, tool)
        if tool in {"record_function_analysis"}:
            self.mark("function summaries", IN_PROGRESS, evidence, tool)
            self.mark("rename decisions", IN_PROGRESS, evidence, tool)
        if result_status == "error":
            self.mark("unresolved failures", IN_PROGRESS, evidence, tool)
        self.start_next()

    def complete_final(self):
        for step in self.steps:
            if step.status != COMPLETE:
                step.status = COMPLETE
                step.updated_at = time.time()

    def block_current(self, reason):
        for step in self.steps:
            if step.status == IN_PROGRESS:
                step.status = BLOCKED
                step.result = str(reason or "")[:2000]
                step.updated_at = time.time()
                return step
        if self.steps:
            self.steps[-1].status = BLOCKED
            self.steps[-1].result = str(reason or "")[:2000]
            self.steps[-1].updated_at = time.time()
            return self.steps[-1]
        return None

    def progress(self):
        total = len(self.steps)
        if not total:
            return {"total": 0, "complete": 0, "blocked": 0, "ratio": 0.0}
        complete = sum(1 for step in self.steps if step.status == COMPLETE)
        blocked = sum(1 for step in self.steps if step.status == BLOCKED)
        return {
            "total": total,
            "complete": complete,
            "blocked": blocked,
            "ratio": round(complete / float(total), 4),
        }

    def to_dict(self):
        return {
            "objective": self.objective,
            "mode": self.mode,
            "created_at": self.created_at,
            "progress": self.progress(),
            "steps": [step.to_dict() for step in self.steps],
        }

    def prompt_text(self):
        if not self.steps:
            return ""
        lines = ["HOST PLAN"]
        for index, step in enumerate(self.steps, 1):
            lines.append("%d. [%s] %s" % (index, step.status, step.title))
            if step.result:
                lines.append("   note: " + step.result[:240])
        return "\n".join(lines)

    def export_json(self):
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)
