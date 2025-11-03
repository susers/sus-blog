import re
import yaml
import urllib.parse
from pathlib import Path


def parse_front_matter(text):
    """Extract YAML front matter and body from markdown."""
    if text.startswith("---"):
        parts = text.split("---", 2)
        if len(parts) >= 3:
            front_matter = yaml.safe_load(parts[1]) or {}
            body = parts[2].lstrip("\n")
            return front_matter, body
    return {}, text


def rewrite_images_and_links(body, title):
    """Rewrite image and link markdown."""
    prefix = f"https://seusus.com/{urllib.parse.quote(title)}/"

    def repl_img(m):
        alt, url = m.groups()
        # Skip if already absolute
        if re.match(r"https?://", url):
            return m.group(0)
        new_url = prefix + url.lstrip("./")
        return f"![{alt}]({new_url})"

    body = re.sub(r"!\[([^\]]*)\]\(([^)]+)\)", repl_img, body)

    # Replace external links with just text
    body = re.sub(r"(?<!!)\[([^\]]*)\]\((https?://[^)]+)\)", r"\2", body)

    return body


def process_markdown_file(path: Path):
    text = path.read_text(encoding="utf-8")
    front, body = parse_front_matter(text)

    # use dirname of input file as title
    title = path.parent.name or "Untitled"
    new_body = rewrite_images_and_links(body, title)

    result = f"# {front['title']}\n\n{new_body}"
    return result


def main(input_file, output_file=None):
    path = Path(input_file)
    new_md = process_markdown_file(path)

    if output_file:
        Path(output_file).write_text(new_md, encoding="utf-8")
    else:
        print(new_md)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print(f"Usage: {Path(sys.argv[0]).name} input.md [output.md]")
        sys.exit(1)
    main(*sys.argv[1:])
