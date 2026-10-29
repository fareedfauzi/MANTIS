"""Dependency-free state model used by every bulk workflow."""

import json
from dataclasses import asdict, dataclass, field
from enum import Enum


class BatchStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    DEFERRED = "deferred"
    FAILED = "failed"
    SKIPPED = "skipped"


TERMINAL = {BatchStatus.COMPLETE, BatchStatus.DEFERRED, BatchStatus.FAILED, BatchStatus.SKIPPED}


@dataclass
class BatchItem:
    key: str
    label: str
    status: BatchStatus = BatchStatus.PENDING
    selected: bool = True
    reason: str = ""
    context_chars: int = 0
    result: object = None
    tags: list = field(default_factory=list)
    risk: str = ""

    def transition(self, status, reason=""):
        status = BatchStatus(status)
        allowed = {
            BatchStatus.PENDING: {BatchStatus.RUNNING, BatchStatus.SKIPPED, BatchStatus.DEFERRED},
            BatchStatus.RUNNING: TERMINAL,
            BatchStatus.DEFERRED: {BatchStatus.PENDING, BatchStatus.RUNNING, BatchStatus.SKIPPED},
            BatchStatus.FAILED: {BatchStatus.PENDING, BatchStatus.RUNNING, BatchStatus.SKIPPED},
            BatchStatus.COMPLETE: {BatchStatus.PENDING},
            BatchStatus.SKIPPED: {BatchStatus.PENDING},
        }
        if status != self.status and status not in allowed[self.status]:
            raise ValueError(f"invalid batch transition: {self.status.value} -> {status.value}")
        self.status, self.reason = status, str(reason or "")


@dataclass
class BatchSession:
    workflow: str
    items: list = field(default_factory=list)
    batch_size: int = 10
    concurrency: int = 1
    paused: bool = False
    cancelled: bool = False

    def counts(self):
        counts = {status.value: 0 for status in BatchStatus}
        for item in self.items:
            counts[item.status.value] += 1
        return counts

    def estimate(self):
        selected = [item for item in self.items if item.selected and item.status in {BatchStatus.PENDING, BatchStatus.DEFERRED, BatchStatus.FAILED}]
        requests = (len(selected) + max(1, self.batch_size) - 1) // max(1, self.batch_size)
        return {"items": len(selected), "requests": requests, "context_chars": sum(max(0, item.context_chars) for item in selected)}

    def retry_failed(self):
        for item in self.items:
            if item.status in {BatchStatus.FAILED, BatchStatus.DEFERRED}:
                item.transition(BatchStatus.PENDING)
                item.selected = True

    def applicable(self):
        return [item for item in self.items if item.selected and item.status == BatchStatus.COMPLETE and item.result is not None]

    def to_json(self):
        data = asdict(self)
        for item in data["items"]:
            item["status"] = item["status"].value if isinstance(item["status"], BatchStatus) else item["status"]
        return json.dumps(data, ensure_ascii=False)

    @classmethod
    def from_json(cls, value):
        data = json.loads(value)
        items = [BatchItem(**{**item, "status": BatchStatus(item.get("status", "pending"))}) for item in data.pop("items", [])]
        return cls(items=items, **data)


def resolve_unique_names(proposals, existing=()):
    """Resolve duplicates deterministically in input order."""
    used, resolved = set(existing), {}
    for key, raw_name in proposals:
        base = str(raw_name).strip()
        candidate, suffix = base, 2
        while candidate in used:
            candidate = f"{base}_{suffix}"
            suffix += 1
        used.add(candidate)
        resolved[key] = candidate
    return resolved
