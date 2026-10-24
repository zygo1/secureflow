import re


def escape_markdown(value: str | None) -> str:
    """Escape untrusted text for Markdown report fields."""
    if not value:
        return ""

    # Prevent HTML tags from being interpreted by Markdown renderers.
    value = value.replace("&", "&amp;")
    value = value.replace("<", "&lt;")
    value = value.replace(">", "&gt;")

    # Escape Markdown syntax characters.
    value = re.sub(r"([\\`*_{}\[\]()#+\-.!|~])", r"\\\1", value)

    # Keep finding content on a single line.
    value = " ".join(value.split())

    return value
