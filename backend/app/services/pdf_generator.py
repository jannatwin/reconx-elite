import io
from datetime import datetime, timezone
from typing import List, Dict, Any

from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor, black, white, grey
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT


class PDFReportGenerator:
    """Generate comprehensive PDF reports for ReconX Elite scan results."""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom styles for the PDF report."""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Title'],
            fontSize=24,
            spaceAfter=30,
            textColor=HexColor('#2E4057'),
            alignment=TA_CENTER
        ))
        
        # Header style
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading1'],
            fontSize=16,
            spaceAfter=12,
            spaceBefore=20,
            textColor=HexColor('#2E4057'),
            borderWidth=0,
            borderColor=HexColor('#2E4057'),
            borderPadding=5
        ))
        
        # Subheader style
        self.styles.add(ParagraphStyle(
            name='SubSectionHeader',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceAfter=8,
            spaceBefore=15,
            textColor=HexColor('#048A81')
        ))
        
        # Critical severity style
        self.styles.add(ParagraphStyle(
            name='CriticalSeverity',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=white,
            backColor=HexColor('#DC2626'),
            borderWidth=1,
            borderColor=HexColor('#DC2626'),
            borderPadding=3
        ))
        
        # High severity style
        self.styles.add(ParagraphStyle(
            name='HighSeverity',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=white,
            backColor=HexColor('#EA580C'),
            borderWidth=1,
            borderColor=HexColor('#EA580C'),
            borderPadding=3
        ))
        
        # Medium severity style
        self.styles.add(ParagraphStyle(
            name='MediumSeverity',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=black,
            backColor=HexColor('#FCD34D'),
            borderWidth=1,
            borderColor=HexColor('#FCD34D'),
            borderPadding=3
        ))
        
        # Low severity style
        self.styles.add(ParagraphStyle(
            name='LowSeverity',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=black,
            backColor=HexColor('#86EFAC'),
            borderWidth=1,
            borderColor=HexColor('#86EFAC'),
            borderPadding=3
        ))
    
    def _get_severity_style(self, severity: str) -> ParagraphStyle:
        """Get the appropriate style based on vulnerability severity."""
        severity_lower = severity.lower()
        if severity_lower == 'critical':
            return self.styles['CriticalSeverity']
        elif severity_lower == 'high':
            return self.styles['HighSeverity']
        elif severity_lower == 'medium':
            return self.styles['MediumSeverity']
        else:
            return self.styles['LowSeverity']
    
    def generate_report(self, report_data: Dict[str, Any]) -> bytes:
        """Generate a complete PDF report from scan data."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
        
        story = []
        
        # Title page
        story.extend(self._create_title_page(report_data))
        story.append(PageBreak())
        
        # Executive summary
        story.extend(self._create_executive_summary(report_data))
        
        # Subdomains section
        if report_data.get('scan', {}).get('subdomains'):
            story.extend(self._create_subdomains_section(report_data['scan']['subdomains']))
        
        # Endpoints section
        if report_data.get('scan', {}).get('endpoints'):
            story.extend(self._create_endpoints_section(report_data['scan']['endpoints']))
        
        # Vulnerabilities section
        if report_data.get('scan', {}).get('vulnerabilities'):
            story.extend(self._create_vulnerabilities_section(report_data['scan']['vulnerabilities']))
        
        # JavaScript assets section
        if report_data.get('scan', {}).get('javascript_assets'):
            story.extend(self._create_javascript_section(report_data['scan']['javascript_assets']))
        
        # Attack paths section
        if report_data.get('scan', {}).get('attack_paths'):
            story.extend(self._create_attack_paths_section(report_data['scan']['attack_paths']))
        
        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()
    
    def _create_title_page(self, report_data: Dict[str, Any]) -> List:
        """Create the title page of the report."""
        story = []
        
        # Main title
        story.append(Paragraph("ReconX Elite Security Report", self.styles['CustomTitle']))
        story.append(Spacer(1, 0.5 * inch))
        
        # Target information
        target = report_data.get('target', {})
        story.append(Paragraph(f"<b>Target Domain:</b> {target.get('domain', 'N/A')}", self.styles['Heading2']))
        story.append(Spacer(1, 0.2 * inch))
        
        # Scan information
        scan = report_data.get('scan', {})
        scan_date = scan.get('created_at', '')
        if scan_date:
            try:
                dt = datetime.fromisoformat(scan_date.replace('Z', '+00:00'))
                formatted_date = dt.strftime('%B %d, %Y at %I:%M %p UTC')
                story.append(Paragraph(f"<b>Scan Date:</b> {formatted_date}", self.styles['Normal']))
            except:
                story.append(Paragraph(f"<b>Scan Date:</b> {scan_date}", self.styles['Normal']))
        
        story.append(Spacer(1, 0.2 * inch))
        story.append(Paragraph(f"<b>Report Generated:</b> {datetime.now(timezone.utc).strftime('%B %d, %Y at %I:%M %p UTC')}", self.styles['Normal']))
        
        # Summary statistics
        story.append(Spacer(1, 0.5 * inch))
        story.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        
        stats_data = [
            ['Metric', 'Count'],
            ['Subdomains Discovered', str(len(scan.get('subdomains', [])))],
            ['Live Endpoints Found', str(len(scan.get('endpoints', [])))],
            ['Vulnerabilities Identified', str(len(scan.get('vulnerabilities', [])))],
            ['JavaScript Assets Analyzed', str(len(scan.get('javascript_assets', [])))],
            ['Attack Paths Identified', str(len(scan.get('attack_paths', [])))],
        ]
        
        stats_table = Table(stats_data, colWidths=[3*inch, 1.5*inch])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#2E4057')),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#F8F9FA')),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#DEE2E6'))
        ]))
        
        story.append(stats_table)
        
        return story
    
    def _create_executive_summary(self, report_data: Dict[str, Any]) -> List:
        """Create executive summary section."""
        story = []
        
        story.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        
        vulnerabilities = report_data.get('scan', {}).get('vulnerabilities', [])
        
        # Severity breakdown
        critical_count = len([v for v in vulnerabilities if v.get('severity', '').lower() == 'critical'])
        high_count = len([v for v in vulnerabilities if v.get('severity', '').lower() == 'high'])
        medium_count = len([v for v in vulnerabilities if v.get('severity', '').lower() == 'medium'])
        low_count = len([v for v in vulnerabilities if v.get('severity', '').lower() == 'low'])
        
        summary_text = f"""
        The reconnaissance scan for {report_data.get('target', {}).get('domain', 'N/A')} identified 
        {len(vulnerabilities)} potential security issues. This includes {critical_count} critical, 
        {high_count} high, {medium_count} medium, and {low_count} low severity findings.
        """
        
        story.append(Paragraph(summary_text, self.styles['Normal']))
        story.append(Spacer(1, 0.3 * inch))
        
        # Top vulnerabilities
        if vulnerabilities:
            story.append(Paragraph("Critical Findings", self.styles['SubSectionHeader']))
            
            critical_vulns = [v for v in vulnerabilities if v.get('severity', '').lower() in ['critical', 'high']]
            for vuln in critical_vulns[:5]:  # Top 5 critical/high findings
                story.append(Paragraph(
                    f"• <b>{vuln.get('template_id', 'Unknown')}</b> - {vuln.get('description', 'No description')[:100]}...",
                    self.styles['Normal']
                ))
        
        return story
    
    def _create_subdomains_section(self, subdomains: List[Dict]) -> List:
        """Create subdomains section."""
        story = []
        
        story.append(Paragraph("Discovered Subdomains", self.styles['SectionHeader']))
        
        # Filter live subdomains
        live_subdomains = [s for s in subdomains if s.get('is_live', False)]
        takeover_candidates = [s for s in subdomains if s.get('takeover_candidate', False)]
        
        story.append(Paragraph(f"Total subdomains discovered: {len(subdomains)}", self.styles['Normal']))
        story.append(Paragraph(f"Live subdomains: {len(live_subdomains)}", self.styles['Normal']))
        if takeover_candidates:
            story.append(Paragraph(f"⚠️ Subdomain takeover candidates: {len(takeover_candidates)}", self.styles['HighSeverity']))
        
        story.append(Spacer(1, 0.2 * inch))
        
        # Subdomains table
        subdomain_data = [['Subdomain', 'Status', 'Environment', 'CDN/WAF']]
        
        for subdomain in subdomains[:20]:  # Limit to first 20
            status = "Live" if subdomain.get('is_live', False) else "Non-live"
            env = subdomain.get('environment', 'Unknown')
            cdn_waf = []
            if subdomain.get('cdn'):
                cdn_waf.append(subdomain['cdn'])
            if subdomain.get('waf'):
                cdn_waf.append(subdomain['waf'])
            cdn_waf_str = ", ".join(cdn_waf) if cdn_waf else "None"
            
            subdomain_data.append([
                subdomain.get('hostname', 'N/A'),
                status,
                env,
                cdn_waf_str
            ])
        
        if len(subdomains) > 20:
            subdomain_data.append([f"... and {len(subdomains) - 20} more", "", "", ""])
        
        table = Table(subdomain_data, colWidths=[2.5*inch, 1*inch, 1*inch, 1.5*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#2E4057')),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#F8F9FA')),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#DEE2E6')),
            ('FONTSIZE', (0, 1), (-1, -1), 8)
        ]))
        
        story.append(table)
        story.append(Spacer(1, 0.3 * inch))
        
        return story
    
    def _create_endpoints_section(self, endpoints: List[Dict]) -> List:
        """Create endpoints section."""
        story = []
        
        story.append(Paragraph("Discovered Endpoints", self.styles['SectionHeader']))
        
        # High-priority endpoints
        high_priority = [e for e in endpoints if e.get('priority_score', 0) > 7]
        interesting_endpoints = [e for e in endpoints if e.get('is_interesting', False)]
        
        story.append(Paragraph(f"Total endpoints discovered: {len(endpoints)}", self.styles['Normal']))
        story.append(Paragraph(f"High-priority endpoints: {len(high_priority)}", self.styles['Normal']))
        story.append(Paragraph(f"Interesting endpoints: {len(interesting_endpoints)}", self.styles['Normal']))
        
        story.append(Spacer(1, 0.2 * inch))
        
        # High-priority endpoints table
        if high_priority:
            story.append(Paragraph("High-Priority Endpoints", self.styles['SubSectionHeader']))
            
            endpoint_data = [['URL', 'Category', 'Priority', 'Tags']]
            
            for endpoint in high_priority[:15]:  # Top 15 high-priority
                url = endpoint.get('url', 'N/A')
                if len(url) > 50:
                    url = url[:47] + "..."
                
                category = endpoint.get('category', 'Unknown')
                priority = str(endpoint.get('priority_score', 0))
                tags = ", ".join(endpoint.get('tags', [])[:3])  # First 3 tags
                
                endpoint_data.append([url, category, priority, tags])
            
            table = Table(endpoint_data, colWidths=[2.5*inch, 1*inch, 0.8*inch, 1.7*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#048A81')),
                ('TEXTCOLOR', (0, 0), (-1, 0), white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('BACKGROUND', (0, 1), (-1, -1), HexColor('#F8F9FA')),
                ('GRID', (0, 0), (-1, -1), 1, HexColor('#DEE2E6')),
                ('FONTSIZE', (0, 1), (-1, -1), 8)
            ]))
            
            story.append(table)
            story.append(Spacer(1, 0.3 * inch))
        
        return story
    
    def _create_vulnerabilities_section(self, vulnerabilities: List[Dict]) -> List:
        """Create vulnerabilities section."""
        story = []
        
        story.append(Paragraph("Security Vulnerabilities", self.styles['SectionHeader']))
        
        if not vulnerabilities:
            story.append(Paragraph("No vulnerabilities were identified during the scan.", self.styles['Normal']))
            return story
        
        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_vulns = sorted(vulnerabilities, key=lambda v: severity_order.get(v.get('severity', 'low').lower(), 5))
        
        # Group by severity
        by_severity = {}
        for vuln in sorted_vulns:
            severity = vuln.get('severity', 'unknown').lower()
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(vuln)
        
        # Summary table
        summary_data = [['Severity', 'Count']]
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = len(by_severity.get(severity, []))
            if count > 0:
                summary_data.append([severity.title(), str(count)])
        
        summary_table = Table(summary_data, colWidths=[2*inch, 1*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#2E4057')),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#F8F9FA')),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#DEE2E6'))
        ]))
        
        story.append(summary_table)
        story.append(Spacer(1, 0.3 * inch))
        
        # Detailed vulnerabilities
        for severity, vulns in by_severity.items():
            if not vulns:
                continue
                
            story.append(Paragraph(f"{severity.title()} Severity Vulnerabilities", self.styles['SubSectionHeader']))
            
            for i, vuln in enumerate(vulns[:10]):  # Limit to 10 per severity
                vuln_style = self._get_severity_style(severity)
                
                # Vulnerability header
                story.append(Paragraph(
                    f"{i+1}. {vuln.get('template_id', 'Unknown Template')}",
                    vuln_style
                ))
                
                # Vulnerability details
                story.append(Paragraph(f"<b>URL:</b> {vuln.get('matched_url', 'N/A')}", self.styles['Normal']))
                story.append(Paragraph(f"<b>Confidence:</b> {vuln.get('confidence', 'N/A')}", self.styles['Normal']))
                story.append(Paragraph(f"<b>Description:</b> {vuln.get('description', 'No description available')}", self.styles['Normal']))
                
                # Evidence if available
                evidence = vuln.get('evidence_json')
                if evidence and isinstance(evidence, dict):
                    if 'request' in evidence:
                        story.append(Paragraph("<b>Evidence Request:</b>", self.styles['Normal']))
                        story.append(Paragraph(str(evidence['request'])[:200] + "...", self.styles['Code']))
                
                story.append(Spacer(1, 0.2 * inch))
            
            if len(vulns) > 10:
                story.append(Paragraph(f"... and {len(vulns) - 10} more {severity} severity findings", self.styles['Normal']))
            
            story.append(Spacer(1, 0.3 * inch))
        
        return story
    
    def _create_javascript_section(self, javascript_assets: List[Dict]) -> List:
        """Create JavaScript assets section."""
        story = []
        
        story.append(Paragraph("JavaScript Assets Analysis", self.styles['SectionHeader']))
        
        # Assets with secrets
        assets_with_secrets = [js for js in javascript_assets if js.get('secrets_json')]
        
        story.append(Paragraph(f"Total JavaScript assets analyzed: {len(javascript_assets)}", self.styles['Normal']))
        story.append(Paragraph(f"Assets containing potential secrets: {len(assets_with_secrets)}", self.styles['Normal']))
        
        if assets_with_secrets:
            story.append(Spacer(1, 0.2 * inch))
            story.append(Paragraph("⚠️ Potential Secrets Found", self.styles['SubSectionHeader']))
            
            for asset in assets_with_secrets[:10]:  # Top 10
                story.append(Paragraph(
                    f"<b>{asset.get('url', 'N/A')}</b>",
                    self.styles['Normal']
                ))
                
                secrets = asset.get('secrets_json', {})
                if isinstance(secrets, dict):
                    for secret_type, secret_list in secrets.items():
                        if secret_list and isinstance(secret_list, list):
                            story.append(Paragraph(
                                f"  • {secret_type}: {len(secret_list)} potential matches",
                                self.styles['Normal']
                            ))
                
                story.append(Spacer(1, 0.1 * inch))
        
        # Endpoint extraction results
        total_extracted_endpoints = sum(
            len(js.get('extracted_endpoints', [])) for js in javascript_assets
        )
        
        if total_extracted_endpoints > 0:
            story.append(Spacer(1, 0.2 * inch))
            story.append(Paragraph(f"Endpoints extracted from JavaScript: {total_extracted_endpoints}", self.styles['Normal']))
        
        return story
    
    def _create_attack_paths_section(self, attack_paths: List[Dict]) -> List:
        """Create attack paths section."""
        story = []
        
        story.append(Paragraph("Attack Path Analysis", self.styles['SectionHeader']))
        
        if not attack_paths:
            story.append(Paragraph("No attack paths were identified during the analysis.", self.styles['Normal']))
            return story
        
        # Sort by score
        sorted_paths = sorted(attack_paths, key=lambda p: p.get('score', 0), reverse=True)
        
        story.append(Paragraph(f"Total attack paths identified: {len(attack_paths)}", self.styles['Normal']))
        story.append(Spacer(1, 0.2 * inch))
        
        # Top attack paths
        for i, path in enumerate(sorted_paths[:5]):  # Top 5 attack paths
            severity_style = self._get_severity_style(path.get('severity', 'low'))
            
            story.append(Paragraph(
                f"{i+1}. {path.get('title', 'Untitled Attack Path')}",
                severity_style
            ))
            
            story.append(Paragraph(f"<b>Severity:</b> {path.get('severity', 'Unknown')}", self.styles['Normal']))
            story.append(Paragraph(f"<b>Score:</b> {path.get('score', 0)}", self.styles['Normal']))
            story.append(Paragraph(f"<b>Summary:</b> {path.get('summary', 'No summary available')}", self.styles['Normal']))
            
            # Attack steps
            steps = path.get('steps_json', [])
            if steps and isinstance(steps, list):
                story.append(Paragraph("<b>Attack Steps:</b>", self.styles['Normal']))
                for j, step in enumerate(steps[:5]):  # First 5 steps
                    if isinstance(step, dict):
                        step_desc = step.get('description', f"Step {j+1}")
                        story.append(Paragraph(f"  {j+1}. {step_desc}", self.styles['Normal']))
            
            story.append(Spacer(1, 0.3 * inch))
        
        if len(attack_paths) > 5:
            story.append(Paragraph(f"... and {len(attack_paths) - 5} additional attack paths", self.styles['Normal']))
        
        return story
