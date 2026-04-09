# Vulnerability report template

Replace bracketed sections. Submit **only** through the program’s official channel. Attach screenshots or video for high/critical issues.

## Title

[One line: vulnerability type + affected asset + user impact — e.g. “IDOR on `/api/v1/invoices/{id}` exposes other users’ invoices”]

## Severity

- **Rating:** [Critical / High / Medium / Low / Informational]
- **CVSS vector (optional):** [e.g. CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N]
- **Rationale:** [Why this score; what an attacker gains]

## Affected scope

- **In-scope asset:** [hostname / app name from program]
- **Component:** [web / API / mobile API / etc.]
- **Endpoint(s):** [method + path]

## Description

[Explain the flaw for a developer who did not write the code: root cause, missing check, wrong assumption.]

## Steps to reproduce

1. [Account setup: create user A / B if needed — use throwaway emails]
2. [Exact navigation or HTTP request]
3. [Parameter/value changed]
4. [Observed result proving impact]

**Raw HTTP (optional but helpful)**

```http
[Request copied from Burp — redact tokens or use fresh session with rotated secrets]
```

**Evidence**

- [Screenshot or short video description attached]

## Impact

[Who is affected; what data or actions; realistic attacker scenario; business impact in one short paragraph.]

## Remediation

[Specific fix: e.g. authorize by `resource.owner_id == current_user.id`, parameterized queries, output encoding, SSRF allowlist, rotate secrets if leaked.]

## References (optional)

- [CWE or OWASP link if relevant]

---

## Program-specific checklist (before submit)

- [ ] Finding is **in scope** (hostname + vuln class).
- [ ] Repro works on a **clean** session today.
- [ ] No unnecessary **real user** data in the report.
- [ ] No **out-of-scope** systems or techniques used to obtain the evidence.
- [ ] Severity matches program **guidance** (not inflated).
