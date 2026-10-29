"""Agent loop helpers decoupled from IDA UI widgets."""

from __future__ import annotations

from .events import AgentEventLog
from .planner import AgentPlan
from .tools import ToolRegistry
from genesect.agent_runtime import (
    normalize_tool_call,
    parse_agent_response,
    result_status,
)


class AgentOrchestrator:
    """Small coordination layer for parsing, validation, and event capture.

    Phase 1 intentionally leaves IDA-specific execution in the existing UI
    module. This object provides the stable seam that later phases can expand
    into planning, memory, and goal management without rewriting widgets.
    """

    def __init__(
        self,
        root_ea,
        session,
        policy,
        tool_registry,
        event_log=None,
        goal_store=None,
        goal_id="",
        plan=None,
    ):
        self.root_ea = int(root_ea)
        self.session = session
        self.policy = policy
        self.tool_registry = tool_registry if isinstance(tool_registry, ToolRegistry) else ToolRegistry(tool_registry)
        self.event_log = event_log or AgentEventLog()
        self.goal_store = goal_store
        self.goal_id = str(goal_id or "")
        self.plan = plan or AgentPlan()
        if self.goal_store and self.goal_id:
            self.event_log.attach_goal(self.goal_store, self.goal_id)

    def attach_goal(self, goal_store, goal_id):
        self.goal_store = goal_store
        self.goal_id = str(goal_id or "")
        self.event_log.attach_goal(goal_store, goal_id)

    def reset(self, session=None, policy=None):
        if session is not None:
            self.session = session
        if policy is not None:
            self.policy = policy
        self.event_log.clear()
        self.event_log.append(
            "run_started",
            root_ea=f"0x{self.root_ea:X}",
            mission=getattr(self.session, "mission", ""),
        )

    def reset_plan(self, objective="", mode="interactive", target_count=0):
        self.plan.reset(objective, mode, target_count)
        self.plan.start_next()
        self.event_log.append("plan_reset", plan=self.plan.to_dict())

    def plan_prompt(self):
        return self.plan.prompt_text()

    @staticmethod
    def safe_args(args):
        return dict(args) if isinstance(args, dict) else {}

    def parse_response(self, response):
        self.event_log.append("model_response", response=str(response or "")[:20000])
        envelope, error = parse_agent_response(response)
        if error:
            self.event_log.append("protocol_error", error=error)
        else:
            self.event_log.append("envelope", action=envelope.get("action"))
        return envelope, error

    def validate_call(self, call):
        tool_name = call.get("tool") if isinstance(call, dict) else ""
        args = call.get("args", {}) if isinstance(call, dict) else {}
        normalized, error = normalize_tool_call(
            tool_name,
            args,
            self.root_ea,
            self.tool_registry.descriptions(),
        )
        if error:
            self.event_log.append(
                "tool_rejected",
                tool=str(tool_name or ""),
                args=args if isinstance(args, dict) else {},
                reason=error,
            )
        else:
            self.event_log.append(
                "tool_validated",
                tool=normalized["tool"],
                args=normalized["args"],
            )
        return normalized, error

    def record_tool_result(self, tool, args, result, replayed=False):
        status = result_status(result)
        text = str(result or "")
        safe_args = self.safe_args(args)
        self.plan.complete_for_tool(tool, safe_args, status)
        self.event_log.append(
            "tool_result",
            tool=str(tool),
            args=safe_args,
            status=status,
            replayed=bool(replayed),
            result_preview=text[:2000],
        )
        return status

    def record_final(self, report, accepted=True, reason=""):
        if accepted:
            self.plan.complete_final()
        else:
            self.plan.block_current(reason)
        self.event_log.append(
            "final_report",
            accepted=bool(accepted),
            reason=str(reason or ""),
            report_preview=str(report or "")[:4000],
            plan=self.plan.to_dict(),
        )

    def export_events_json(self):
        return self.event_log.export_json()
