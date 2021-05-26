import json
import textwrap
from enum import Enum

from jsonify import jsonify


class IssueLevel(Enum):
    INFO = 1
    WARN = 2
    ERR = 3

    def __lt__(self, other):
        return self.value < other.value


class Bulletin:
    name: str = None
    description: str = None
    data = None
    level: IssueLevel

    def __lt__(self, other):
        return self.level < other.level

    def __init__(self, name: str, description: str, data, level: IssueLevel):
        self.name = name
        self.description = description
        self.data = data
        self.level = level

    def __hash__(self):
        return hash(self.name)

    def __eq__(self, other):
        return self.name == other.name

    def __repr__(self):
        n_l = max(len(str(self.level)), len(self.name)+2)
        if n_l % 2 != 0:
            n_l += 1

        lvl_name = str(self.level.name)
        lvl_name_len = len(lvl_name)
        lvl_name_pad = "=" * int((n_l - lvl_name_len)/2)
        lvl_header = f"{lvl_name_pad} {lvl_name} {lvl_name_pad}"

        name = str(self.name)
        name_len = len(name)
        name_pad = "=" * int((n_l - name_len)/2)
        header = f"{name_pad} {name} {name_pad}"

        lines = list()
        lines.append(lvl_header)
        lines.append(header)
        if self.description is not None:
            lines.append("")
            lines.append(textwrap.fill(self.description))
        if self.data is not None:
            lines.append("")
            lines.append(jsonify(self.data))
        lines.append("")
        return "\n".join(lines)
