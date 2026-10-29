"""Tool registry metadata for agent planning and policy gates."""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    category: str = "unknown"
    scope: str = "ida"
    requires_confirmation: bool = False

    def to_dict(self):
        return asdict(self)


class ToolRegistry:
    """A discoverable registry for tools available to the agent."""

    def __init__(self, tools=None):
        self._tools = {}
        for tool in tools or ():
            self.register(tool)

    @classmethod
    def from_catalog(cls, catalog, categories=None, confirmation_categories=None):
        categories = categories or {}
        confirmation_categories = set(confirmation_categories or ())
        registry = cls()
        for name, description in sorted(dict(catalog or {}).items()):
            category = categories.get(name, "unknown")
            registry.register(ToolSpec(
                name=str(name),
                description=str(description),
                category=category,
                requires_confirmation=category in confirmation_categories,
            ))
        return registry

    def register(self, tool):
        if not isinstance(tool, ToolSpec):
            tool = ToolSpec(**dict(tool))
        self._tools[tool.name] = tool
        return tool

    def has(self, name):
        return str(name) in self._tools

    def get(self, name):
        return self._tools.get(str(name))

    def names(self):
        return tuple(sorted(self._tools))

    def descriptions(self):
        return {name: self._tools[name].description for name in self.names()}

    def to_list(self):
        return [self._tools[name].to_dict() for name in self.names()]
