# FinGuardAI Usage Guide

This guide provides practical examples for using the FinGuardAI integrated vulnerability analysis system.

## Quick Start

### 1. Basic Vulnerability Analysis

To run a basic vulnerability analysis on a target:

```bash
python backend/finguard_integrated_analysis.py --target example.com
```

This will:
- Perform active scanning to detect technologies
- Conduct passive monitoring for additional fingerprinting
- Fetch vulnerabilities from NVD
- Generate timeframe-based predictions
- Provide remediation recommendations
- Output results to the console

### 2. Analyzing Financial Sector Applications

For financial sector applications, use the comprehensive timeframe option:

```bash
python backend/finguard_integrated_analysis.py --target bank-example.com --timeframes comprehensive
```

### 3. Saving Reports for Compliance

To save reports for compliance purposes:

```bash
python backend/finguard_integrated_analysis.py --target financial-portal.com --format json --output compliance_reports/may_2025_scan.json
```

## Example Workflow

### Step 1: Initial Assessment

Run a quick assessment to identify technologies and immediate threats:

```bash
python backend/finguard_integrated_analysis.py --target portal.lcu.edu.ng --timeframes short --scan-speed fast
```

### Step 2: Detailed Analysis

Perform a comprehensive analysis with all features:

```bash
python backend/finguard_integrated_analysis.py --target portal.lcu.edu.ng --timeframes comprehensive --format text --output reports/portal_lcu_full_analysis.txt
```

### Step 3: Focus on Exploitable Vulnerabilities

Check specifically for exploitable vulnerabilities:

```bash
python backend/finguard_integrated_analysis.py --target portal.lcu.edu.ng --min-cvss 9.0 --no-trends
```

## API Usage Examples

### Using the Integrated Analyzer in Scripts

```python
from backend.integrated_system.integrated_analyzer import IntegratedAnalyzer

def analyze_multiple_targets(targets):
    analyzer = IntegratedAnalyzer()
    results = {}
    
    for target in targets:
        print(f"Analyzing {target}...")
        target_results = analyzer.analyze_target(target)
        results[target] = target_results
        
        # Generate and save report
        report = analyzer.generate_report(target_results, format="text")
        with open(f"reports/{target.replace('.', '_')}_report.txt", "w") as f:
            f.write(report)
    
    return results

# Example usage
targets = ["example1.com", "example2.com", "example3.com"]
all_results = analyze_multiple_targets(targets)
```

### Direct NVD API Integration

For specific vulnerability checks:

```python
from backend.ml.remediation.nvd_advanced_search import NVDAdvancedSearch

# Initialize with your API key
advanced_search = NVDAdvancedSearch(api_key="your-api-key")

# Check for recent critical WordPress vulnerabilities
wordpress_vulns = advanced_search.search_recent_critical_vulnerabilities(
    days_back=30,
    technology_filter="wordpress"
)

# Check for exploitable nginx vulnerabilities
nginx_exploits = advanced_search.search_exploited_vulnerabilities(technology="nginx")

# Analyze vulnerability trends for PHP
php_trends = advanced_search.get_vulnerability_trends(technology="php", time_periods=3)
```

## Common Use Cases

### 1. Pre-Deployment Security Testing

Before deploying a new application:

```bash
python backend/finguard_integrated_analysis.py --target staging.example.com --timeframes comprehensive --format json --output pre_deployment_reports/security_assessment.json
```

### 2. Regular Security Audits

For regular security audits (e.g., monthly):

```bash
python backend/finguard_integrated_analysis.py --target production.example.com --timeframes long --format text --output audit_reports/monthly_$(date +%Y_%m).txt
```

### 3. Emergency Vulnerability Assessment

When a critical vulnerability is announced:

```bash
python backend/finguard_integrated_analysis.py --target critical-system.example.com --timeframes short --min-cvss 9.0 --scan-speed fast
```

## Customizing the Analysis

You can customize various aspects of the analysis:

### Custom Port Scanning

```bash
python backend/finguard_integrated_analysis.py --target example.com --ports 80,443,8080,8443,3000,9000
```

### Focusing on Specific Timeframes

```bash
# Short-term vulnerabilities only (1 day)
python backend/finguard_integrated_analysis.py --target example.com --timeframes short

# Medium-term vulnerabilities (1 day, 1 week)
python backend/finguard_integrated_analysis.py --target example.com --timeframes medium

# Long-term vulnerabilities (1 day, 1 week, 30 days)
python backend/finguard_integrated_analysis.py --target example.com --timeframes long

# Comprehensive analysis (1 day, 1 week, 10 days, 30 days, 90 days)
python backend/finguard_integrated_analysis.py --target example.com --timeframes comprehensive
```

## Interpreting Results

The analysis output includes:

1. **Detected Technologies**: Technologies identified through active and passive means
2. **Vulnerability Predictions**: Vulnerabilities organized by timeframe
3. **Remediation Recommendations**: Actionable steps to address vulnerabilities
4. **Exploit Analysis**: Information about vulnerabilities with known exploits
5. **Trend Analysis**: Vulnerability trends for detected technologies

Pay special attention to:
- Critical vulnerabilities (CVSS score 9.0+)
- Vulnerabilities with known exploits
- Technologies with increasing vulnerability trends

## Troubleshooting

### API Rate Limiting

If you encounter rate limiting issues:
- Ensure you're using a valid NVD API key
- Reduce the number of technologies being analyzed
- Use shorter timeframes for analysis
- Use the cached results when possible

### Scan Timeouts

For large targets:
- Use faster scan speeds for initial assessment
- Limit port scanning to essential ports
- Split analysis into multiple smaller targets

### Missing Technologies

If technologies aren't being detected:
- Check that the target is accessible
- Try both active and passive monitoring
- Add custom technology mappings in the configuration

## Next Steps

Once you've identified vulnerabilities:

1. Prioritize remediation based on:
   - CVSS score
   - Exploitability
   - Business impact

2. Implement recommended mitigations

3. Rescan to verify remediation

4. Schedule regular scans for continuous monitoring
