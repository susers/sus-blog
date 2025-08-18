import yaml

TEMPLATE = """<table class="members">
  <tbody>
  {rows}
  </tbody>
</table>"""

ROW_TEMPLATE = """  <tr>
    <td class="avatar">
      ![]({avatar}){{.avatar}}
    </td>
    <td>
      <a href="{homepage}">{name}</a>
      <p>{role}</p>
    </td>
  </tr>"""


def generate_html(members):
    rows = []
    for m in members:
        rows.append(
            ROW_TEMPLATE.format(
                name=m["name"],
                role=m["role"],
                homepage=m["homepage"],
                avatar=m["avatar"],
            )
        )
    return TEMPLATE.format(rows="\n".join(rows))


if __name__ == "__main__":
    with open("content/about/members.yaml", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    for member in data.get("members", []):
        if "avatar" not in member:
            member["avatar"] = "../logo.jpg"
        elif member["avatar"] == "github":
            username = member["name"]
            # use GitHub avatar URL
            member["avatar"] = f"https://github.com/{username}.png"
            if "homepage" not in member:
                member["homepage"] = f"https://github.com/{username}"
        if "homepage" not in member:
            member["homepage"] = "#"

    html = generate_html(data["members"])
    with open("content/about/index.tmpl.md", "r", encoding="utf-8") as f:
        tmpl = f.read()
    with open("content/about/index.md", "w", encoding="utf-8") as f:
        f.write(
            "---\ncomment: DO NOT MODIFY BY HAND, USE scripts/gen_members_table.py "
            + tmpl.replace("{{members_table}}", html)
        )

    print("Generated members")
