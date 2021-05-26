from typing import List

from Bulletin import Bulletin, IssueLevel
from jsonify import jsonify


def generate_html(bulletins: List[Bulletin], output: str):
    with open("report_template.html", "r") as rt:
        template = "\n".join(rt.readlines())

        lines = list()

        for i, b in enumerate(bulletins):
            lines.append("<tr>")
            lines.append(f"<td class='font-weight-bold'>{i}</td>")

            if b.level == IssueLevel.INFO:
                lines.append(f"<td class='text-info'>{b.level.name}</td>")

            if b.level == IssueLevel.WARN:
                lines.append(f"<td class='text-warning'>{b.level.name}</td>")

            if b.level == IssueLevel.ERR:
                lines.append(f"<td class='text-danger font-weight-bold'>{b.level.name}</td>")

            lines.append(f"<td>{b.name}</td>")
            lines.append(f"<td>{b.description}</td>")
            if b.data is None:
                lines.append(f"<td></td>")
            else:
                lines.append(f"<td><pre>{jsonify(b.data)}</pre></td>")
            lines.append("</tr>")

        l = "\n".join(lines)
        template = template.replace("<!--REPLACEME-->", l)
        with open(output + ".html", "w") as output_file:
            output_file.write(template)