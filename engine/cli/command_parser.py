import shlex


class UnknownCommandError(ValueError):
    pass


class CommandParser:

    def __init__(self, command_tree):
        self.tree = command_tree

    def parse(self, raw):

        tokens = shlex.split(raw)

        if not tokens:
            return None

        result = {
            "command": None,
            "subcommand": None,
            "args": [],
            "flags": {}
        }

        cmd = tokens.pop(0)

        if cmd not in self.tree:
            raise UnknownCommandError(
                cmd
            )

        result["command"] = cmd

        # subcommand opcional
        if tokens:
            possible_sub = tokens[0]

            if possible_sub in self.tree[cmd]:
                result["subcommand"] = tokens.pop(0)

        # args + flags
        while tokens:
            t = tokens.pop(0)

            if t.startswith("--"):
                key = t[2:]
                val = True

                if tokens and not tokens[0].startswith("--"):
                    val = tokens.pop(0)

                result["flags"][key] = val
            else:
                result["args"].append(t)

        return result
