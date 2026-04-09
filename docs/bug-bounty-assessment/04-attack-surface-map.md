# Attack surface map

Fill this while you browse the **in-scope** app with Burp proxied and scope locked ([02-asset-scope-burp.md](02-asset-scope-burp.md)). Goal: know **where auth, objects, and money** live before deep testing.

## Tech stack (per host)

| Host | Framework / CMS / API style | Auth mechanism | CDN / WAF (if visible) |
|------|-----------------------------|----------------|-------------------------|
| | | (session / JWT / OAuth / API key) | |

**Fingerprinting aids:** response headers, cookies, JS bundles, error pages, `wafw00f` (only on in-scope URLs).

## Authentication entry points

| URL / flow | Purpose | Notes (e.g. MFA, SSO) |
|------------|---------|------------------------|
| | Login | |
| | Register | |
| | Password reset | |
| | OAuth / SSO callback | |
| | API token issuance | |

## Object identifiers (for IDOR matrices)

Document patterns you see in URLs and JSON:

| Resource | ID format (int / UUID / slug) | Example endpoint | Roles that should differ |
|----------|-------------------------------|------------------|----------------------------|
| | | | |

## API surface

| Base path | Auth | Interesting methods | Notes |
|-----------|------|----------------------|--------|
| | | GET/POST/... | |

**Discovery sources:** Burp sitemap, JS files (linkfinder), `/openapi.json`, `/swagger`, `/api/docs`, GraphQL `/graphql` (introspection only if allowed).

## File upload

| Endpoint | Allowed types | Storage / URL pattern | Served back how? |
|----------|---------------|------------------------|-------------------|
| | | | |

## Redirects and open-redirect candidates

| Parameter name | Example URL | OAuth-related? |
|----------------|---------------|------------------|
| | | |

## Reflection / user input (XSS candidates)

| Location | Parameter or field | Context (HTML/JS/JSON) |
|----------|--------------------|-------------------------|
| | | |

## Cloud / third-party (only if in scope)

| Asset type | Name / URL | Notes |
|------------|------------|--------|
| S3 / blob / Firebase | | |

---

**Next step:** Work through [05-testing-priority-checklist.md](05-testing-priority-checklist.md).
