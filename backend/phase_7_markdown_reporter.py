"""Phase 7: Markdown Reporter - Generate professional vulnerability reports."""

from datetime import datetime
from pathlib import Path
from typing import Any


class MarkdownReportGenerator:
    """Generate executive-quality Markdown reports with structured findings."""

    def __init__(self, report_dir: str = "./reports"):
        self.report_dir = Path(report_dir)
        self.report_dir.mkdir(exist_ok=True)

    def generate_report(
        self,
        target: str,
        all_findings: dict[str, list[dict[str, Any]]],
        manifest_data: dict[str, Any],
    ) -> str:
        """Generate complete Markdown report from all phases."""

        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        report_filename = f'report_{target.replace(".", "_")}_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.md'
        report_path = self.report_dir / report_filename

        markdown = f"""# Security Assessment Report
**Target:** {target}  
**Generated:** {timestamp}

---

## Executive Summary

This report documents the results of a comprehensive autonomous vulnerability assessment conducted against {target} using the ReconX-Elite 7-Phase Tactical Scanning Pipeline.

### Key Metrics
- **Total Vulnerabilities Found:** {self._count_findings(all_findings)}
- **Critical Severity:** {self._count_by_severity(all_findings, 'CRITICAL')}
- **High Severity:** {self._count_by_severity(all_findings, 'HIGH')}
- **Medium Severity:** {self._count_by_severity(all_findings, 'MEDIUM')}
- **Low Severity:** {self._count_by_severity(all_findings, 'LOW')}

---

## Scope & Asset Inventory

### Reconnaissance Phase Results (Phase 1 & 2)
"""

        # Phase 1: Recon results
        context = manifest_data.get("context_tree", {})
        report_filename = f'report_{target.replace(".", "_")}_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.md'

        markdown += f"""
**Subdomains Discovered:** {len(context.get('subdomains', []))}
- Total: {len(context.get('subdomains', []))}
- Examples: {', '.join(context.get('subdomains', [])[:5])}

**Live Hosts:** {len(context.get('live_hosts', []))}
- Total: {len(context.get('live_hosts', []))}

**Open Ports:** {self._format_ports(context.get('open_ports', []))}

**Cloud Infrastructure:** {len(context.get('cloud_buckets', []))} cloud bucket(s) discovered

**Related Entities:** {len(context.get('subsidiaries', []))} subsidiary/related company found

---

## Technology Stack Analysis

### Identified Technologies
"""

        tech_stack = context.get("tech_stack", {})
        for tech, version in tech_stack.items():
            markdown += f"- **{tech}:** {version}\n"

        markdown += f"""

### Low-Hanging Fruit (Version-Based CVEs)
{self._format_cve_findings(context.get('cve_findings', []))}

---

## API Surface

### Endpoint Mapping
{self._format_api_endpoints(context.get('api_endpoints', []))}

---

## Vulnerability Findings

### Critical Severity
{self._format_findings_by_type(all_findings, 'CRITICAL')}

### High Severity
{self._format_findings_by_type(all_findings, 'HIGH')}

### Medium Severity
{self._format_findings_by_type(all_findings, 'MEDIUM')}

### Low Severity
{self._format_findings_by_type(all_findings, 'LOW')}

---

## Proof of Concepts

### Reproducible Test Cases
{self._format_pocs(context.get('pocs', []))}

---

## Remediation & Recommendations

1. **Immediate Actions (Critical):**
   - Address all CRITICAL severity findings immediately
   - Implement emergency patching plan
   - Deploy WAF rules for known exploitation patterns

2. **Short-Term (30 days):**
   - Patch all HIGH severity vulnerabilities
   - Implement input validation and output encoding
   - Enable security logging

3. **Long-Term (90 days):**
   - Implement secure SDLC practices
   - Conduct regular security training
   - Setup continuous vulnerability scanning

---

## Assessment Methodology

This assessment was conducted using the ReconX-Elite 7-Phase Autonomous Pipeline:

1. **Phase 1:** Recursive Recon & Shadow Asset Mapping
2. **Phase 2:** Context-Aware Tech Profiling & CVE Analysis
3. **Phase 3:** Authenticated State Analysis (IDOR)
4. **Phase 4:** Vulnerability-Specific Tactical Strikes
5. **Phase 5:** Advanced Injection Testing (GraphQL/Prompt)
6. **Phase 6:** Automated PoC Generation
7. **Phase 7:** Adaptive Reporting

---

## Disclaimer

This report is for authorized security assessment purposes only. Unauthorized access is illegal.

"""

        # Save report
        with open(report_path, "w") as f:
            f.write(markdown)

        return markdown

    def _count_findings(self, all_findings: dict[str, list[dict[str, Any]]]) -> int:
        """Count total findings."""
        count = 0
        for findings_list in all_findings.values():
            if isinstance(findings_list, list):
                count += len(findings_list)
        return count

    def _count_by_severity(
        self, all_findings: dict[str, list[dict[str, Any]]], severity: str
    ) -> int:
        """Count findings by severity."""
        count = 0
        for findings_list in all_findings.values():
            if isinstance(findings_list, list):
                for finding in findings_list:
                    if (
                        isinstance(finding, dict)
                        and finding.get("severity") == severity
                    ):
                        count += 1
        return count

    def _format_ports(self, open_ports: list[dict[str, Any]]) -> str:
        """Format open ports for report."""
        if not open_ports:
            return "None discovered"

        formatted = []
        for entry in open_ports:
            host = entry.get("host", "unknown")
            ports = entry.get("ports", [])
            formatted.append(f"- {host}: {', '.join(map(str, ports))}")

        return "\n".join(formatted[:10])

    def _format_cve_findings(self, cve_findings: list[dict[str, Any]]) -> str:
        """Format CVE findings."""
        if not cve_findings:
            return "No critical version-based CVEs found."

        formatted = []
        for cve in cve_findings[:5]:
            severity = cve.get("severity", "UNKNOWN")
            software = cve.get("software", "unknown")
            cve_id = cve.get("cve", "unknown")
            title = cve.get("title", "N/A")
            formatted.append(f"- **[{severity}]** {software}: {cve_id} - {title}")

        return "\n".join(formatted) if formatted else "No CVEs found."

    def _format_api_endpoints(self, api_endpoints: list[dict[str, Any]]) -> str:
        """Format API endpoints."""
        if not api_endpoints:
            return "No API endpoints identified."

        formatted = []
        for endpoint in api_endpoints[:10]:
            endpoint_type = endpoint.get("type", "REST")
            path = endpoint.get("path", "unknown")
            formatted.append(f"- [{endpoint_type}] `{path}`")

        return "\n".join(formatted)

    def _format_findings_by_type(
        self, all_findings: dict[str, list[dict[str, Any]]], severity: str
    ) -> str:
        """Format findings by severity."""
        formatted = []
        for vuln_type, findings_list in all_findings.items():
            if isinstance(findings_list, list):
                for finding in findings_list:
                    if (
                        isinstance(finding, dict)
                        and finding.get("severity") == severity
                    ):
                        title = finding.get("title", finding.get("type", "Unknown"))
                        endpoint = finding.get("endpoint", "N/A")
                        impact = finding.get("impact", "N/A")
                        formatted.append(
                            f"""#### {title}
**Location:** `{endpoint}`  
**Impact:** {impact}

"""
                        )

        return (
            "\n".join(formatted) if formatted else f"No {severity} severity findings."
        )

    def _format_pocs(self, pocs: list[dict[str, Any]]) -> str:
        """Format PoCs for report."""
        if not pocs:
            return "No PoCs generated."

        formatted = []
        for poc in pocs[:5]:
            poc_type = poc.get("finding_type", "Unknown")
            curl = poc.get("curl", "")
            formatted.append(
                f"""#### {poc_type}

\`\`\`bash
{curl.strip()}
\`\`\`

"""
            )

        return "\n".join(formatted)
