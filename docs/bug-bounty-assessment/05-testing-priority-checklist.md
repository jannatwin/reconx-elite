# Testing checklist (impact-first)

Use two **test accounts** (A and B) when testing horizontal access. Stay within [01-policy-intake.md](01-policy-intake.md) rules. Prefer **manual verification**; use Collaborator / Interactsh only where blind issues are plausible and allowed.

## Priority 1 — Authentication and authorization

- [ ] **IDOR:** For each user-specific resource in [04-attack-surface-map.md](04-attack-surface-map.md), swap IDs between A and B; try alternate verbs (GET/PUT/PATCH/DELETE).
- [ ] **Broken access control:** Hit admin/management paths as a normal user; try unauthenticated requests to authenticated APIs.
- [ ] **JWT:** Inspect structure (alg, claims); test `none`/confusion/kid/`jku` only if relevant to the stack; verify expiry enforcement.
- [ ] **OAuth:** `state`, `redirect_uri`, code reuse, token leakage via Referer — if OAuth is in use.
- [ ] **Password reset:** Token entropy, reuse, Host header influence on reset links — if exposed.
- [ ] **MFA bypass:** Direct navigation to post-auth routes; backup codes; rate limits — if applicable.

## Priority 2 — Injection

- [ ] **SQLi:** Parameters from `urls-with-params.txt` and API bodies; time-based confirmation where needed.
- [ ] **XSS:** Reflected/stored/DOM; match payload to context (HTML attribute, JS string, JSON).
- [ ] **SSRF:** URL-like parameters; escalate only to **allowed** proof targets (Collaborator / designated callback).
- [ ] **Command injection:** Features that invoke OS commands (convert, ping, import).
- [ ] **XXE:** XML/SOAP/SVG/office uploads — if present.
- [ ] **SSTI:** Template-like fields (emails, exports, reports).

## Priority 3 — Sensitive data exposure

- [ ] Sensitive paths (read-only HEAD/GET): `/.env`, `/.git/HEAD`, config dumps — **stop** if you hit secrets; report per program process.
- [ ] **Swagger/OpenAPI/GraphQL introspection** — if discovery is in scope.
- [ ] Verbose errors / stack traces (typed wrong inputs).

## Priority 4 — Subdomain takeover

- [ ] For in-scope subdomains, review CNAME chains for dangling records; verify with program’s preferred proof (HTTP takeover vs DNS-only).

## Priority 5 — Business logic

- [ ] Price/coupon/credit flows (negative values, replay, race on redemption).
- [ ] Multi-step flows (skip steps, reorder steps).
- [ ] Mass assignment on JSON update endpoints (`role`, `admin`, `verified`, etc.).

## Priority 6 — Infrastructure and configuration

- [ ] **CORS:** `Origin` reflection with `Credentials` — pair with XSS impact.
- [ ] **Open redirect** — chain with OAuth/session if applicable.
- [ ] **Security headers** — note severity per program (often low alone).

## Chaining (document when relevant)

- [ ] Open redirect + OAuth code theft
- [ ] Self-XSS + CSRF (only if program accepts)
- [ ] SSRF + cloud metadata (only where legal and in scope)
- [ ] IDOR + highly sensitive data → severity justification

---

**Next step:** Document valid findings in [06-report-template.md](06-report-template.md).
