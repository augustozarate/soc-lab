class ActionRegistry:

    def __init__(self):

        self.handlers = {}

    # =========================

    def register(self, action_type, handler):

        self.handlers[action_type] = handler

    # =========================

    def get(self, action_type):

        return self.handlers.get(action_type)

    # =========================

    def exists(self, action_type):

        return action_type in self.handlers
