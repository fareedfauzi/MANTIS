"""Self-reflection and recovery guidance for autonomous agent runs."""

from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field


@dataclass
class Reflection:
    id: str
    kind: str
    severity: str
    message: str
    guidance: str
    evidence: list = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self):
        data = asdict(self)
        data["timestamp_iso"] = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.timestamp)
        )
        return data


class AgentReflector:
    """Detect stalled behavior and produce bounded host guidance."""

    def __init__(self, max_reflections=200):
        self.max_reflections = max(1, int(max_reflections))
        self.reflections = []

    def reset(self):
        self.reflections = []

    def add(self, kind, severity, message, guidance, evidence=None):
        reflection = Reflection(
            id=uuid.uuid4().hex[:12],
            kind=str(kind or "reflection"),
            severity=str(severity or "info"),
            message=str(message or "")[:1000],
            guidance=str(guidance or "")[:2000],
            evidence=[str(item)[:500] for item in (evidence or [])[:12]],
        )
        self.reflections.append(reflection)
        del self.reflections[:-self.max_reflections]
        return reflection

    def after_round(
        self,
        session,
        plan,
        all_calls_repeated=False,
        task_profile="",
        pending_count=0,
    ):
        emitted = []
        if all_calls_repeated:
            emitted.append(self.add(
                "repeated_tool_loop",
                "warning",
                "The last tool batch repeated prior calls without new evidence.",
                "Do not repeat the same tool arguments. Use cached observations, switch to a different evidence source, "
                "or provide the final answer if enough evidence exists.",
            ))
        no_progress = int(getattr(session, "consecutive_no_progress", 0) or 0)
        if no_progress >= 1:
            emitted.append(self.add(
                "no_progress_round",
                "warning" if no_progress == 1 else "error",
                "The last round did not add new successful evidence.",
                "Choose one untried, concrete tool call that can change the evidence ledger. If no such call exists, "
                "return a final answer with explicit uncertainty.",
                evidence=["consecutive_no_progress=%d" % no_progress],
            ))
        if task_profile == "autonomous_full" and pending_count:
            emitted.append(self.add(
                "coverage_gap",
                "info",
                "%d function(s) still need coverage." % int(pending_count),
                "Continue with the host-selected pending function. Complete one function with function_evidence plus "
                "decompile or disassemble before moving to another function.",
            ))
        if plan:
            progress = plan.progress()
            if progress.get("blocked"):
                emitted.append(self.add(
                    "blocked_plan_step",
                    "warning",
                    "The host plan contains a blocked step.",
                    "Resolve the blocked step directly or explain why it cannot be completed with current evidence.",
                    evidence=[str(progress)],
                ))
        return emitted

    def guidance_text(self, reflections=None):
        items = list(reflections if reflections is not None else self.reflections[-3:])
        if not items:
            return ""
        lines = ["HOST REFLECTION"]
        for item in items[-3:]:
            lines.append("- %s: %s" % (item.kind, item.guidance))
        return "\n".join(lines)

    def to_list(self):
        return [item.to_dict() for item in self.reflections]
