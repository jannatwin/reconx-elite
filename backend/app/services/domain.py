import re
from urllib.parse import urlparse

DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def _host_from_user_input(value: str) -> str:
    """Pull a bare hostname from a hostname, URL, or browser-bar paste."""
    raw = value.strip()
    if not raw:
        raise ValueError("Domain is required")

    if "://" in raw or raw.startswith("//"):
        url = raw if "://" in raw else f"http:{raw}"
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            raise ValueError("Invalid domain format")
        return host

    segment = raw.split("/")[0].split("?")[0].split("#")[0].strip()
    if not segment:
        raise ValueError("Invalid domain format")

    if "@" in segment:
        segment = segment.rsplit("@", 1)[-1].strip()

    if ":" in segment:
        segment = segment.split(":", 1)[0].strip()

    return segment


def normalize_domain(value: str) -> str:
    host = _host_from_user_input(value)
    domain = host.strip().lower().rstrip(".")
    forbidden = (
        " ",
        "/",
        "\\",
        ":",
        "@",
        "?",
        "&",
        ";",
        "|",
        "$",
        "`",
        "'",
        '"',
        "(",
        ")",
    )
    if any(ch in domain for ch in forbidden):
        raise ValueError("Invalid domain format")
    if len(domain) > 253:
        raise ValueError("Domain too long")
    if not DOMAIN_RE.fullmatch(domain):
        raise ValueError("Invalid domain format")
    return domain
