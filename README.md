# FinGuardAI Integrated Vulnerability Analysis System

![FinGuardAI Logo](assets/finguardai-logo.png)

## Overview

FinGuardAI is a comprehensive vulnerability analysis system specifically designed for financial sector cybersecurity. It integrates active scanning, passive monitoring, and machine learning models powered by the National Vulnerability Database (NVD) API to provide precise vulnerability predictions and actionable remediation recommendations.

The system combines multiple sources of intelligence to identify vulnerabilities in web applications, servers, and infrastructure components with a focus on the unique security requirements of financial institutions.

## Key Features

- **Integrated Analysis Pipeline**: Combines active scanning, passive monitoring and NVD data for comprehensive assessment
- **Timeframe-Based Predictions**: Predicts vulnerabilities within specific timeframes (1-day, 1-week, 10-day, etc.)
- **CVSS Vector Analysis**: Detailed analysis of CVSS vectors for comprehensive vulnerability assessment
- **Financial Impact Assessment**: Evaluates financial and operational impact of identified vulnerabilities
- **Exploitability Checking**: Identifies vulnerabilities with known exploits in the wild
- **Remediation Recommendations**: Provides actionable recommendations to address vulnerabilities
- **Trend Analysis**: Analyzes vulnerability trends for technologies over time
- **Multiple Output Formats**: Produces reports in various formats (text, JSON, HTML)

## System Architecture

The FinGuardAI system consists of several integrated components:

```
FinGuardAI
│
├── Active Scanner
│   └── Technology detection through direct scanning
│
├── Passive Monitor
│   └── Technology fingerprinting without direct scanning
│
├── NVD Integration
│   ├── Basic NVD Client
│   ├── Advanced Search Capabilities
│   └── CVSS Vector Analysis
│
└── Integrated Analysis Engine
    ├── Technology Merging
    ├── Vulnerability Prediction
    ├── Remediation Recommendation
    ├── Exploit Analysis
    └── Trend Analysis
```

## Installation

### Prerequisites

- Python 3.8+ (for direct installation)
- Docker and Docker Compose (for containerized deployment)
- Access to NVD API (API key required for full functionality)
- Network access to scan targets

### Setup (Direct Installation)

1. Clone the repository:
   ```bash
   git clone https://github.com/your-organization/finguardai.git
   cd finguardai
   ```

2. Install dependencies:
   ```bash
   pip install -r backend/requirements.txt
   npm install
   ```

3. Set up your NVD API key (optional but recommended):
   ```bash
   export NVD_API_KEY="your-api-key-here"
   ```

4. Create necessary directories:
   ```bash
   mkdir -p cache logs reports scan_results monitoring_results
   ```

### Docker Deployment

FinGuardAI can be deployed as a containerized application using Docker and Docker Compose:

1. Build and start the containers:
   ```bash
   docker-compose up -d --build
   ```

2. Access the application:
   - Frontend UI: http://localhost:3000
   - Backend API: http://localhost:5001

3. View logs:
   ```bash
   # View frontend logs
   docker-compose logs -f frontend
   
   # View backend logs
   docker-compose logs -f backend
   ```

4. Stop the containers:
   ```bash
   docker-compose down
   ```

### Production Deployment

For production environments, consider the following additional steps:

1. Set proper environment variables in a `.env` file or through your container orchestration platform
2. Use a reverse proxy (like Nginx or Traefik) to handle SSL termination
3. Consider using Docker Swarm or Kubernetes for orchestration in larger deployments

## Usage

### Command Line Interface

The main entry point for the integrated system is `finguard_integrated_analysis.py`:

```bash
python backend/finguard_integrated_analysis.py --target example.com --format text
```

#### Options

- `--target, -t`: Target to analyze (domain, IP, or URL) [required]
- `--output, -o`: Output file path for the report
- `--format, -f`: Output format - `text`, `json`, or `html` (default: text)
- `--timeframes`: Timeframe preset - `short`, `medium`, `long`, or `comprehensive`
- `--min-cvss`: Minimum CVSS score for highlighting vulnerabilities (default: 7.0)
- `--no-exploits`: Skip checking for exploitable vulnerabilities
- `--no-trends`: Skip vulnerability trend analysis
- `--ports`: Custom comma-separated list of ports to scan
- `--scan-speed`: Scan speed/intensity - `fast`, `normal`, or `thorough` (default: normal)

### Example Commands

Simple analysis of a single target:
```bash
python backend/finguard_integrated_analysis.py --target bank-example.com
```

Comprehensive analysis with all features:
```bash
python backend/finguard_integrated_analysis.py --target financial-portal.com --timeframes comprehensive --format json --output reports/financial-portal-report.json
```

Quick assessment without trend analysis:
```bash
python backend/finguard_integrated_analysis.py --target quick-check.com --timeframes short --no-trends --scan-speed fast
```

## Module Reference

### Active Scanner (`active_scanner.py`)

The active scanning component performs direct scanning of targets to identify technologies and potential vulnerabilities.

```python
from backend.integrated_system.active_scanner import ActiveScanner

scanner = ActiveScanner()
results = scanner.scan_target("example.com")
technologies = scanner.extract_technologies(results)
```

### Passive Monitor (`passive_monitor.py`)

The passive monitoring component identifies technologies without direct scanning, using techniques like HTTP header analysis and signature matching.

```python
from backend.integrated_system.passive_monitor import PassiveMonitor

monitor = PassiveMonitor()
results = monitor.monitor_target("example.com")
technologies = monitor.extract_technologies(results)
```

### NVD Integration (`nvd_integration.py`)

This component integrates with the NVD API to provide comprehensive vulnerability data and predictions.

```python
from backend.integrated_system.nvd_integration import NVDIntegration

nvd = NVDIntegration()
vulns = nvd.get_vulnerabilities_for_technology("apache", "2.4.51")
recommendations = nvd.get_remediation_recommendations("nginx", "1.20.1")
```

### CVSS Analyzer (`cvss_analyzer.py`)

Provides detailed analysis of CVSS vectors from NVD data, extracting vulnerability characteristics and assessing financial impact.

```python
from backend.ml.remediation.cvss_analyzer import parse_cvss_vector, assess_financial_impact

cvss_data = parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
impact = assess_financial_impact(cvss_data)
```

### Integrated Analyzer (`integrated_analyzer.py`)

The core component that combines all other components to provide comprehensive vulnerability analysis.

```python
from backend.integrated_system.integrated_analyzer import IntegratedAnalyzer

analyzer = IntegratedAnalyzer()
results = analyzer.analyze_target("example.com")
report = analyzer.generate_report(results, format="text")
```

## Advanced Features

### Financial Impact Assessment

The system assesses the potential financial impact of vulnerabilities based on CVSS vectors, categorizing risks into areas such as:

- Data breach risk
- Operational disruption
- Financial loss potential
- Regulatory risk
- Remediation complexity

### Exploit Intelligence

FinGuardAI checks for vulnerabilities with known exploits in the wild, providing critical intelligence for prioritizing remediation efforts.

### Vulnerability Trends

The system analyzes vulnerability trends for technologies over time, helping to identify increasing or decreasing risk patterns and inform strategic decisions.

### Enhanced Reporting

Reports can be generated in multiple formats (text, JSON, HTML) with varying levels of detail, suitable for different audiences from technical teams to executive management.

## Configuration

Configuration settings can be found in `backend/integrated_system/config.py`. Key configurable options include:

- NVD API settings
- Logging configuration
- Default scan parameters
- Default analysis parameters
- Financial sector specific settings

## Troubleshooting

### Common Issues

1. **API Rate Limiting**: If you receive rate limiting errors from the NVD API, consider:
   - Using an API key
   - Reducing the number of requests
   - Increasing the cache TTL

2. **Scan Timeout**: For large or complex targets, try:
   - Reducing the scan scope (fewer ports)
   - Using a faster scan speed
   - Breaking the target into smaller components

3. **Missing Technologies**: If technologies aren't being detected:
   - Try both active and passive scanning methods
   - Add custom technology mappings in the configuration

### Logging

Logs are stored in the `logs` directory. The primary log file is `integrated_analyzer.log`, which contains detailed information about the analysis process, API calls, and any errors encountered.

## Contributing

Contributions to FinGuardAI are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- National Vulnerability Database (NVD) for vulnerability data
- Various open-source scanning and fingerprinting libraries
- Financial sector cybersecurity standards and frameworks

---

**FinGuardAI** - Advanced Vulnerability Analysis for Financial Institutions
