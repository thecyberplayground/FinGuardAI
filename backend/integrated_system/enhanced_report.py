"""
Enhanced Report Generator for FinGuardAI

This module creates comprehensive vulnerability assessment reports
with financial impact analysis, detailed remediation steps, and 
support for multiple output formats.
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

from .report_templates import HTML_REPORT_TEMPLATE, EXECUTIVE_SUMMARY_TEMPLATE

logger = logging.getLogger("finguardai.enhanced_report")

class EnhancedReportGenerator:
    """Generates enhanced security reports with actionable remediation steps."""
    
    def __init__(self, report_dir: str = "reports", env: str = "prod"):
        """
        Initialize the report generator
        
        Args:
            report_dir: Directory where reports will be saved
            env: Environment (dev, test, prod)
        """
        self.report_dir = report_dir
        self.env = env
        os.makedirs(report_dir, exist_ok=True)
        
        # Initialize environment-specific settings
        self.settings = self._load_environment_settings(env)
    
    def _load_environment_settings(self, env: str) -> Dict[str, Any]:
        """
        Load environment-specific settings for reports
        
        Args:
            env: Environment (dev, test, prod)
            
        Returns:
            Dictionary containing environment-specific settings
        """
        # Define default settings for different environments
        default_settings = {
            "dev": {
                "include_debug_info": True,
                "detailed_recommendations": False,
                "risk_scoring_method": "simple",
                "company_name": "FinGuardAI Development"
            },
            "test": {
                "include_debug_info": False,
                "detailed_recommendations": True,
                "risk_scoring_method": "detailed",
                "company_name": "FinGuardAI Testing"
            },
            "prod": {
                "include_debug_info": False,
                "detailed_recommendations": True,
                "risk_scoring_method": "comprehensive",
                "company_name": "FinGuardAI"
            }
        }
        
        # Use prod settings as fallback
        return default_settings.get(env, default_settings["prod"])
        
    def generate_report(
        self, 
        scan_results: Dict[str, Any], 
        target: str, 
        report_format: str = "html",
        include_financial_impact: bool = True
    ) -> str:
        """
        Generate a comprehensive vulnerability report
        
        Args:
            scan_results: Results from vulnerability scanner
            target: The target that was scanned
            report_format: Format of the report (html, text, json)
            include_financial_impact: Whether to include financial impact analysis
            
        Returns:
            Path to the generated report file
        """
        if report_format == "html":
            return self._generate_html_report(scan_results, target, include_financial_impact)
        elif report_format == "text":
            return self._generate_text_report(scan_results, target, include_financial_impact)
        elif report_format == "json":
            return self._generate_json_report(scan_results, target)
        else:
            raise ValueError(f"Unsupported report format: {report_format}")
    
    def _generate_html_report(
        self, 
        scan_results: Dict[str, Any], 
        target: str,
        include_financial_impact: bool = True
    ) -> str:
        """Generate an HTML report with visualizations and detailed remediation steps"""
        report_id = f"report_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        report_filename = os.path.join(self.report_dir, f"{report_id}.html")
        
        # Count vulnerabilities by severity
        vulnerabilities = scan_results.get("vulnerabilities", [])
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "unknown").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Generate executive summary
        total_vulns = sum(severity_counts.values())
        
        # Top issues summary
        top_issues = []
        if vulnerabilities:
            critical_vulns = [v for v in vulnerabilities if v.get("severity", "").lower() == "critical"]
            high_vulns = [v for v in vulnerabilities if v.get("severity", "").lower() == "high"]
            
            top_issues = (critical_vulns + high_vulns)[:3]
            
        top_issues_text = ""
        if top_issues:
            top_issues_text = "Key issues include: " + ", ".join(
                f"{vuln.get('name', 'Unknown vulnerability')} ({vuln.get('severity', 'unknown').upper()})"
                for vuln in top_issues
            )
        
        # Get financial impact data if available
        fin_score = "N/A"
        risk_level = "unknown"
        
        if include_financial_impact and "financial_impact" in scan_results:
            financial_impact = scan_results["financial_impact"]
            fin_score = financial_impact.get("overall_score", 0)
            
            if fin_score >= 80:
                risk_level = "critical"
            elif fin_score >= 60:
                risk_level = "high"
            elif fin_score >= 40:
                risk_level = "medium"
            elif fin_score >= 20:
                risk_level = "low"
            else:
                risk_level = "minimal"
        
        # Format executive summary
        executive_summary = EXECUTIVE_SUMMARY_TEMPLATE.format(
            target=target,
            total_vulns=total_vulns,
            critical=severity_counts["critical"],
            high=severity_counts["high"],
            medium=severity_counts["medium"],
            low=severity_counts["low"],
            fin_score=fin_score,
            risk_level=risk_level.upper(),
            top_issues_summary=top_issues_text
        )
        
        # Generate financial impact section
        financial_risk_table = ""
        regulations_section = ""
        financial_recommendations = ""
        financial_summary = ""
        
        if include_financial_impact and "financial_impact" in scan_results:
            financial_impact = scan_results["financial_impact"]
            financial_summary = financial_impact.get("summary", "")
            
            # Format risk table
            for risk_name, risk_data in financial_impact.get("risk_levels", {}).items():
                risk_level_str = risk_data.get("level", "unknown").upper()
                risk_score = risk_data.get("score", 0)
                
                financial_risk_table += f"""
                <tr>
                    <td>{risk_name.replace('_', ' ').title()}</td>
                    <td><span class="badge badge-{risk_data.get('level', 'low')}">{risk_level_str}</span></td>
                    <td>{risk_score}/100</td>
                </tr>
                """
            
            # Format regulations
            affected_regulations = financial_impact.get("affected_regulations", [])
            if affected_regulations:
                regulations_section = """
                <h3>Regulatory Compliance Impact</h3>
                <p>The following regulations may be impacted:</p>
                <ul>
                """
                
                for reg in affected_regulations:
                    regulations_section += f"<li>{reg}</li>"
                
                regulations_section += "</ul>"
            
            # Format recommendations
            for rec in financial_impact.get("recommendations", []):
                financial_recommendations += f"<li>{rec}</li>"
        
        # Format vulnerabilities sections
        critical_vulnerabilities = self._format_vulnerabilities_html(
            [v for v in vulnerabilities if v.get("severity", "").lower() == "critical"]
        )
        
        high_vulnerabilities = self._format_vulnerabilities_html(
            [v for v in vulnerabilities if v.get("severity", "").lower() == "high"]
        )
        
        # Format technologies list
        technologies_list = ""
        detected_techs = scan_results.get("detected_technologies", [])
        if not detected_techs and "open_ports" in scan_results:
            # Try to extract from open ports if not explicitly provided
            for port_data in scan_results["open_ports"].values():
                if "product" in port_data and port_data["product"]:
                    product = port_data["product"]
                    version = port_data.get("version", "")
                    if product not in detected_techs:
                        detected_techs.append(f"{product} {version}".strip())
        
        for tech in detected_techs:
            technologies_list += f"<li>{tech}</li>"
        
        # Format open ports
        open_ports_list = ""
        for port, data in scan_results.get("open_ports", {}).items():
            service = data.get("name", "unknown")
            open_ports_list += f'<div class="port-item">{port}/{service}</div>'
        
        # Format database section
        database_section = ""
        if "database_security" in scan_results:
            db_security = scan_results["database_security"]
            db_servers = db_security.get("database_servers", [])
            
            if db_servers:
                database_section = """
                <div class="section">
                    <h2>Database Security Analysis</h2>
                    <table>
                        <tr>
                            <th>Database Type</th>
                            <th>Port</th>
                            <th>Version</th>
                            <th>Security Issues</th>
                        </tr>
                """
                
                for db in db_servers:
                    db_type = db.get("type", "Unknown")
                    db_port = db.get("port", "Unknown")
                    db_version = db.get("version", "Unknown")
                    db_issues_count = len(db.get("security_issues", []))
                    
                    database_section += f"""
                    <tr>
                        <td>{db_type}</td>
                        <td>{db_port}</td>
                        <td>{db_version}</td>
                        <td>{db_issues_count}</td>
                    </tr>
                    """
                
                database_section += "</table>"
                
                # Add recommendations
                db_recommendations = db_security.get("recommendations", [])
                if db_recommendations:
                    database_section += """
                    <div class="recommendations">
                        <h3>Database Security Recommendations</h3>
                        <ul>
                    """
                    
                    for rec in db_recommendations:
                        database_section += f"<li>{rec}</li>"
                    
                    database_section += """
                        </ul>
                    </div>
                    """
                
                database_section += "</div>"
        
        # Format web security section
        web_security_section = ""
        if "web_security" in scan_results:
            web_security = scan_results["web_security"]
            web_servers = web_security.get("web_servers", [])
            
            if web_servers:
                web_security_section = """
                <div class="section">
                    <h2>Web Security Analysis</h2>
                    <table>
                        <tr>
                            <th>Web Server</th>
                            <th>Port</th>
                            <th>Version</th>
                        </tr>
                """
                
                for web in web_servers:
                    web_product = web.get("product", "Unknown")
                    web_port = web.get("port", "Unknown")
                    web_version = web.get("version", "Unknown")
                    
                    web_security_section += f"""
                    <tr>
                        <td>{web_product}</td>
                        <td>{web_port}</td>
                        <td>{web_version}</td>
                    </tr>
                    """
                
                web_security_section += "</table>"
                
                # Add issues summary
                web_security_section += f"""
                <h3>Web Security Issues Summary</h3>
                <div class="summary-box">
                    <div class="summary-item critical-box">
                        <h3>CRITICAL</h3>
                        <div class="count">{web_security.get("summary", {}).get("critical_issues", 0)}</div>
                    </div>
                    <div class="summary-item high-box">
                        <h3>HIGH</h3>
                        <div class="count">{web_security.get("summary", {}).get("high_issues", 0)}</div>
                    </div>
                    <div class="summary-item medium-box">
                        <h3>MEDIUM</h3>
                        <div class="count">{web_security.get("summary", {}).get("medium_issues", 0)}</div>
                    </div>
                    <div class="summary-item low-box">
                        <h3>LOW</h3>
                        <div class="count">{web_security.get("summary", {}).get("low_issues", 0)}</div>
                    </div>
                </div>
                """
                
                # Add security issues
                sec_issues = web_security.get("security_issues", [])
                if sec_issues:
                    web_security_section += "<h3>Web Security Issues</h3>"
                    
                    for issue in sec_issues[:5]:  # Show top 5 issues
                        issue_type = issue.get("type", "unknown").replace("_", " ").title()
                        issue_severity = issue.get("severity", "low")
                        issue_desc = issue.get("description", "No description available")
                        
                        web_security_section += f"""
                        <div class="vuln-item severity-{issue_severity}">
                            <div class="vuln-title">
                                {issue_type} <span class="badge badge-{issue_severity}">{issue_severity.upper()}</span>
                            </div>
                            <p>{issue_desc}</p>
                        </div>
                        """
                
                # Add recommendations
                web_recommendations = web_security.get("recommendations", [])
                if web_recommendations:
                    web_security_section += """
                    <div class="recommendations">
                        <h3>Web Security Recommendations</h3>
                        <ul>
                    """
                    
                    for rec in web_recommendations:
                        web_security_section += f"<li>{rec}</li>"
                    
                    web_security_section += """
                        </ul>
                    </div>
                    """
                
                web_security_section += "</div>"
        
        # Format remediation sections
        critical_remediation = ""
        high_remediation = ""
        medium_remediation = ""
        
        # Compile all recommendations
        all_recs = []
        
        # From vulnerabilities
        for vuln in vulnerabilities:
            if "recommendation" in vuln:
                severity = vuln.get("severity", "medium").lower()
                vuln_name = vuln.get("name", "Unknown vulnerability")
                rec = f"{vuln_name}: {vuln['recommendation']}"
                all_recs.append((severity, rec))
        
        # From database security
        if "database_security" in scan_results:
            db_recs = scan_results["database_security"].get("recommendations", [])
            for rec in db_recs:
                all_recs.append(("medium", rec))
        
        # From web security
        if "web_security" in scan_results:
            web_recs = scan_results["web_security"].get("recommendations", [])
            for rec in web_recs:
                all_recs.append(("medium", rec))
        
        # From financial impact
        if "financial_impact" in scan_results:
            fin_recs = scan_results["financial_impact"].get("recommendations", [])
            for rec in fin_recs:
                all_recs.append(("high", rec))
        
        # Sort and format remediation items
        for severity, rec in all_recs:
            if severity == "critical":
                critical_remediation += f"<li>{rec}</li>"
            elif severity == "high":
                high_remediation += f"<li>{rec}</li>"
            else:
                medium_remediation += f"<li>{rec}</li>"
        
        # Replace all placeholders in the template
        html_content = HTML_REPORT_TEMPLATE
        replacements = {
            "{{TARGET}}": target,
            "{{SCAN_DATE}}": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "{{REPORT_ID}}": report_id,
            "{{EXECUTIVE_SUMMARY}}": executive_summary,
            "{{CRITICAL_COUNT}}": str(severity_counts["critical"]),
            "{{HIGH_COUNT}}": str(severity_counts["high"]),
            "{{MEDIUM_COUNT}}": str(severity_counts["medium"]),
            "{{LOW_COUNT}}": str(severity_counts["low"]),
            "{{FINANCIAL_SCORE}}": str(fin_score),
            "{{FINANCIAL_SUMMARY}}": financial_summary,
            "{{FINANCIAL_RISK_TABLE}}": financial_risk_table,
            "{{REGULATIONS_SECTION}}": regulations_section,
            "{{FINANCIAL_RECOMMENDATIONS}}": financial_recommendations,
            "{{CRITICAL_VULNERABILITIES}}": critical_vulnerabilities,
            "{{HIGH_VULNERABILITIES}}": high_vulnerabilities,
            "{{TECHNOLOGIES_LIST}}": technologies_list,
            "{{OPEN_PORTS_LIST}}": open_ports_list,
            "{{DATABASE_SECTION}}": database_section,
            "{{WEB_SECURITY_SECTION}}": web_security_section,
            "{{CRITICAL_REMEDIATION}}": critical_remediation,
            "{{HIGH_REMEDIATION}}": high_remediation,
            "{{MEDIUM_REMEDIATION}}": medium_remediation,
            "{{REPORT_TIME}}": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        for placeholder, value in replacements.items():
            html_content = html_content.replace(placeholder, value)
        
        # Write the HTML report
        with open(report_filename, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated: {report_filename}")
        return report_filename
    
    def _generate_text_report(
        self, 
        scan_results: Dict[str, Any], 
        target: str,
        include_financial_impact: bool = True
    ) -> str:
        """Generate a plain text report with detailed findings and remediation steps"""
        report_id = f"report_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        report_filename = os.path.join(self.report_dir, f"{report_id}.txt")
        
        # Build text report
        report_lines = [
            "=" * 80,
            f"FINGUARDAI VULNERABILITY ASSESSMENT REPORT",
            "=" * 80,
            f"Target: {target}",
            f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Report ID: {report_id}",
            "=" * 80,
            "",
            "EXECUTIVE SUMMARY",
            "-" * 80
        ]
        
        # Count vulnerabilities by severity
        vulnerabilities = scan_results.get("vulnerabilities", [])
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "unknown").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        total_vulns = sum(severity_counts.values())
        report_lines.append(f"Total vulnerabilities found: {total_vulns}")
        report_lines.append(f"- Critical: {severity_counts['critical']}")
        report_lines.append(f"- High: {severity_counts['high']}")
        report_lines.append(f"- Medium: {severity_counts['medium']}")
        report_lines.append(f"- Low: {severity_counts['low']}")
        report_lines.append("")
        
        # Add financial impact if available
        if include_financial_impact and "financial_impact" in scan_results:
            financial_impact = scan_results["financial_impact"]
            fin_score = financial_impact.get("overall_score", 0)
            fin_summary = financial_impact.get("summary", "")
            
            report_lines.append("FINANCIAL IMPACT ASSESSMENT")
            report_lines.append("-" * 80)
            report_lines.append(f"Overall Financial Risk Score: {fin_score}/100")
            report_lines.append(f"{fin_summary}")
            report_lines.append("")
            
            report_lines.append("Risk Breakdown:")
            for risk_name, risk_data in financial_impact.get("risk_levels", {}).items():
                report_lines.append(f"- {risk_name.replace('_', ' ').title()}: {risk_data.get('level', 'unknown').upper()} ({risk_data.get('score', 0)}/100)")
            
            affected_regulations = financial_impact.get("affected_regulations", [])
            if affected_regulations:
                report_lines.append("")
                report_lines.append("Affected Regulations:")
                for reg in affected_regulations:
                    report_lines.append(f"- {reg}")
            
            report_lines.append("")
            report_lines.append("Financial Risk Recommendations:")
            for rec in financial_impact.get("recommendations", []):
                report_lines.append(f"- {rec}")
            
            report_lines.append("")
        
        # Add vulnerabilities details
        report_lines.append("VULNERABILITY DETAILS")
        report_lines.append("-" * 80)
        
        for severity in ["critical", "high", "medium", "low"]:
            severity_vulns = [v for v in vulnerabilities if v.get("severity", "").lower() == severity]
            
            if severity_vulns:
                report_lines.append(f"\n{severity.upper()} SEVERITY VULNERABILITIES:")
                
                for i, vuln in enumerate(severity_vulns, 1):
                    report_lines.append(f"\n{i}. {vuln.get('name', 'Unknown vulnerability')}")
                    report_lines.append(f"   Description: {vuln.get('description', 'No description available')}")
                    
                    if "port" in vuln:
                        report_lines.append(f"   Port: {vuln.get('port', 'N/A')}")
                    
                    if "cve_id" in vuln:
                        report_lines.append(f"   CVE ID: {vuln.get('cve_id', 'N/A')}")
                    
                    if "recommendation" in vuln:
                        report_lines.append(f"   Recommendation: {vuln.get('recommendation', 'No recommendation available')}")
        
        # Add systems overview
        report_lines.append("\nSYSTEMS AND TECHNOLOGIES")
        report_lines.append("-" * 80)
        
        detected_techs = scan_results.get("detected_technologies", [])
        if detected_techs:
            report_lines.append("\nDetected Technologies:")
            for tech in detected_techs:
                report_lines.append(f"- {tech}")
        
        open_ports = scan_results.get("open_ports", {})
        if open_ports:
            report_lines.append("\nOpen Ports:")
            for port, data in open_ports.items():
                service = data.get("name", "unknown")
                product = data.get("product", "")
                version = data.get("version", "")
                
                port_info = f"- {port}/{service}"
                if product:
                    port_info += f" ({product}"
                    if version:
                        port_info += f" {version}"
                    port_info += ")"
                
                report_lines.append(port_info)
        
        # Add database security section
        if "database_security" in scan_results:
            db_security = scan_results["database_security"]
            db_servers = db_security.get("database_servers", [])
            
            if db_servers:
                report_lines.append("\nDATABASE SECURITY ANALYSIS")
                report_lines.append("-" * 80)
                
                for db in db_servers:
                    db_type = db.get("type", "Unknown")
                    db_port = db.get("port", "Unknown")
                    db_version = db.get("version", "Unknown")
                    
                    report_lines.append(f"\n{db_type} Database (Port {db_port}, Version {db_version}):")
                    
                    db_issues = db.get("security_issues", [])
                    if db_issues:
                        report_lines.append("Security Issues:")
                        for issue in db_issues:
                            issue_desc = issue.get("description", "No description")
                            issue_severity = issue.get("severity", "unknown").upper()
                            report_lines.append(f"- [{issue_severity}] {issue_desc}")
                
                report_lines.append("\nDatabase Security Recommendations:")
                for rec in db_security.get("recommendations", []):
                    report_lines.append(f"- {rec}")
        
        # Add web security section
        if "web_security" in scan_results:
            web_security = scan_results["web_security"]
            web_servers = web_security.get("web_servers", [])
            
            if web_servers:
                report_lines.append("\nWEB SECURITY ANALYSIS")
                report_lines.append("-" * 80)
                
                for web in web_servers:
                    web_product = web.get("product", "Unknown")
                    web_port = web.get("port", "Unknown")
                    web_version = web.get("version", "Unknown")
                    
                    report_lines.append(f"\n{web_product} Web Server (Port {web_port}, Version {web_version})")
                
                security_issues = web_security.get("security_issues", [])
                if security_issues:
                    report_lines.append("\nWeb Security Issues:")
                    for issue in security_issues:
                        issue_type = issue.get("type", "unknown").replace("_", " ").title()
                        issue_severity = issue.get("severity", "unknown").upper()
                        issue_desc = issue.get("description", "No description available")
                        
                        report_lines.append(f"- [{issue_severity}] {issue_type}: {issue_desc}")
                
                report_lines.append("\nWeb Security Recommendations:")
                for rec in web_security.get("recommendations", []):
                    report_lines.append(f"- {rec}")
        
        # Add remediation plan
        report_lines.append("\nPRIORITIZED REMEDIATION PLAN")
        report_lines.append("-" * 80)
        
        # Compile all recommendations
        all_recs = []
        
        # From vulnerabilities
        for vuln in vulnerabilities:
            if "recommendation" in vuln:
                severity = vuln.get("severity", "medium").lower()
                vuln_name = vuln.get("name", "Unknown vulnerability")
                rec = f"{vuln_name}: {vuln['recommendation']}"
                all_recs.append((severity, rec))
        
        # From specialized modules
        for module_name in ["database_security", "web_security", "financial_impact"]:
            if module_name in scan_results:
                module_recs = scan_results[module_name].get("recommendations", [])
                severity = "high" if module_name == "financial_impact" else "medium"
                
                for rec in module_recs:
                    all_recs.append((severity, rec))
        
        # Group by severity
        critical_recs = [rec for sev, rec in all_recs if sev == "critical"]
        high_recs = [rec for sev, rec in all_recs if sev == "high"]
        medium_recs = [rec for sev, rec in all_recs if sev == "medium"]
        
        # Add to report
        if critical_recs:
            report_lines.append("\nCritical Priority (Address within 24 hours):")
            for i, rec in enumerate(critical_recs, 1):
                report_lines.append(f"{i}. {rec}")
        
        if high_recs:
            report_lines.append("\nHigh Priority (Address within 1 week):")
            for i, rec in enumerate(high_recs, 1):
                report_lines.append(f"{i}. {rec}")
        
        if medium_recs:
            report_lines.append("\nMedium Priority (Address within 1 month):")
            for i, rec in enumerate(medium_recs, 1):
                report_lines.append(f"{i}. {rec}")
        
        # Add footer
        report_lines.append("\n" + "=" * 80)
        report_lines.append("Generated by FinGuardAI Integrated Vulnerability Assessment System")
        report_lines.append(f"Report generation time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("=" * 80)
        
        # Write the text report
        with open(report_filename, "w", encoding="utf-8") as f:
            f.write("\n".join(report_lines))
        
        logger.info(f"Text report generated: {report_filename}")
        return report_filename
    
    def _generate_json_report(self, scan_results: Dict[str, Any], target: str) -> str:
        """Generate a JSON format report with all scan details"""
        report_id = f"report_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        report_filename = os.path.join(self.report_dir, f"{report_id}.json")
        
        # Create report structure
        report_data = {
            "report_id": report_id,
            "target": target,
            "scan_date": datetime.now().isoformat(),
            "scan_results": scan_results
        }
        
        # Write the JSON report
        with open(report_filename, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)
        
        logger.info(f"JSON report generated: {report_filename}")
        return report_filename
    
    def _format_vulnerabilities_html(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Format vulnerabilities for HTML display"""
        if not vulnerabilities:
            return "<p>No vulnerabilities found in this category.</p>"
        
        formatted_html = ""
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "unknown").lower()
            name = vuln.get("name", "Unknown vulnerability")
            description = vuln.get("description", "No description available")
            
            vuln_html = f"""
            <div class="vuln-item severity-{severity}">
                <div class="vuln-title">
                    {name} <span class="badge badge-{severity}">{severity.upper()}</span>
                </div>
                <p>{description}</p>
            """
            
            # Add port if available
            if "port" in vuln:
                vuln_html += f"<p><strong>Port:</strong> {vuln['port']}</p>"
            
            # Add CVE ID if available
            if "cve_id" in vuln:
                vuln_html += f'<p><strong>CVE ID:</strong> <a href="https://nvd.nist.gov/vuln/detail/{vuln["cve_id"]}" target="_blank">{vuln["cve_id"]}</a></p>'
            
            # Add recommendation if available
            if "recommendation" in vuln:
                vuln_html += f"""
                <div class="recommendations">
                    <h4>Recommendation</h4>
                    <p>{vuln['recommendation']}</p>
                </div>
                """
            
            vuln_html += "</div>"
            formatted_html += vuln_html
        
        return formatted_html
