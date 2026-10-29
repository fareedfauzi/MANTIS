"""Pure workspace state machines used by the dockable Qt view."""


class NavigationStack:
    def __init__(self, limit=50):
        self.limit = max(2, int(limit))
        self.items = []
        self.index = -1

    @property
    def can_back(self):
        return self.index > 0

    @property
    def can_forward(self):
        return 0 <= self.index < len(self.items) - 1

    def record(self, value):
        if self.index >= 0 and self.items[self.index] == value:
            return False
        if self.index < len(self.items) - 1:
            self.items = self.items[:self.index + 1]
        self.items.append(value)
        if len(self.items) > self.limit:
            self.items = self.items[-self.limit:]
        self.index = len(self.items) - 1
        return True

    def back(self):
        if not self.can_back:
            return None
        self.index -= 1
        return self.items[self.index]

    def forward(self):
        if not self.can_forward:
            return None
        self.index += 1
        return self.items[self.index]


class RequestGate:
    def __init__(self):
        self.generation = 0

    def advance(self):
        self.generation += 1
        return self.generation

    def issue(self, owner):
        return self.generation, owner

    def accepts(self, token, owner):
        return bool(token and token[0] == self.generation and token[1] == owner)
