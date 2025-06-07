# FinGuardAI: Updated Product Requirements Document (PRD)

## 1. Introduction

### 1.1 Purpose
FinGuardAI is an ML-powered cybersecurity platform built to protect single-branch banks by automating vulnerability assessment and penetration testing (VAPT). It delivers real-time threat detection, vulnerability scanning, and actionable fix suggestions through a modern interface, reducing breach costs and enhancing security workflows.

### 1.2 Target Users
- **Primary**: Cybersecurity staff and managers at single-branch banks needing efficient, automated VAPT.
- **Secondary**: Development teams maintaining and extending the platform.

### 1.3 Problem Statement
Single-branch banks lack affordable, automated tools to proactively identify vulnerabilities, predict risks, and apply fixes, leaving them exposed to breaches that cost time and money. Existing solutions are either too complex, expensive, or lack predictive insights and modern usability.

### 1.4 Goals
- Reduce breach costs through proactive VAPT with environment-specific scanning profiles.
- Provide a clean, intuitive UI with real-time scan feedback and reporting.
- Automate threat detection and vulnerability identification using integrated scanning and ML processing.
- Offer actionable recommendations and remediation steps for identified vulnerabilities.
- Support different operational environments (development, testing, production).

## 2. Features and Requirements (Current Implementation)

### 2.1 User Interface
**Overview**: A React-based dashboard with dark/light mode capabilities.

**Requirements**:
- Functional light/dark mode toggle.
- Dashboard with scan status, progress indicators, and result visualization.
- Built with React, Next.js, and Tailwind CSS.

### 2.2 Authentication
**Overview**: Simple authentication for platform access.

**Requirements**:
- Basic authentication mechanism.
- Role-based access (planned for future).

### 2.3 Integrated Scanning Engine
**Overview**: Consolidated vulnerability scanning with nmap integration and automated processing of results.

**Requirements**:
- **Integrated Scanning**:
  - Primary tool: Nmap with comprehensive script capabilities
  - Consolidated approach merging vulnerability testing and port scanning
  - Scan depths: Basic (ports/services) and deep (versions, vulnerabilities)
  - Environment-specific configurations (dev/test/prod)
  - Support for different scan intensities (stealthy, normal, aggressive)
- **Real-time Monitoring**:
  - WebSocket-based real-time scan status via Socket.IO
  - Progress tracking and live result display
  - Immediate notification of detected vulnerabilities
  - Live updates to dashboard via Socket.IO
- **Results Processing**:
  - Automated XML parsing and structured result storage
  - Direct feed into ML analysis pipeline
  - Financial impact assessment based on detected vulnerabilities
  - Severity classification with CVSS scoring integration

### 2.4 ML-Driven Analysis
**Overview**: Directly processes scan results for threat detection, vulnerability prediction, and remediation recommendations.

**Requirements**:
- **Integrated Processing**: Directly processes nmap scan results through ML pipeline
- **Threat Detection**: Classification based on scan patterns using trained models
- **Vulnerability Prediction**: Identifies potential vulnerabilities based on detected system configurations
- **Fix Recommendations**: Provides specific remediation steps for each identified vulnerability
- **NVD Integration**: Leverages National Vulnerability Database to enrich scan findings
- **Environment Support**: Configurable models/settings for dev, test, and production environments

### 2.5 Dashboard
**Overview**: Central hub for monitoring and analysis.

**Requirements**:
- **Scan Section**: Target input, scan controls and real-time progress
- **Results Section**: Interactive display of scan findings
- **Reports Section**: Previous scan results and generated reports
- **Settings**: Environment configuration and scan parameters

### 2.6 Reporting
**Overview**: Comprehensive reporting with enhanced data flow to dashboard.

**Requirements**:
- **Multiple formats**: HTML, text, and JSON outputs
- **Detailed vulnerability information**: Complete findings with severity levels
- **Direct dashboard integration**: Scan results properly populated to reports page
- **Remediation recommendations**: Actionable fix suggestions for each finding
- **Financial impact analysis**: Cost-benefit assessment for financial sector clients
- **Report persistence**: Reports stored and accessible through dashboard interface
- **Data visualization**: Visual representation of scan findings with severity indicators

### 2.7 Integration
**Overview**: Hooks into existing security tools.

**Requirements**:
- REST API endpoints for programmatic access
- Integration with NVD database for vulnerability information
- Socket.IO for real-time scan status updates

## 3. Non-Functional Requirements

### 3.1 Performance
- Active scans: Variable based on target scope and network conditions
- Scan result processing: <5 seconds per scan
- ML predictions: <2 seconds per analysis

### 3.2 Usability
- Intuitive scan initiation and monitoring
- Clear presentation of results with severity indicators
- Actionable remediation steps

### 3.3 Security
- Configuration data stored separately by environment
- Scan results stored in dedicated directories
- Cached vulnerability data for improved performance

### 3.4 Scalability
- Environment-specific configurations for different deployment scales
- Modular architecture for component extension or replacement

## 4. Current Architecture

### 4.1 Directory Structure
```
finguardai-admin/
├── app/                # Frontend React application
├── backend/            # Backend Python services
│   ├── integrated_system/  # Core vulnerability scanning components
│   ├── ml/             # Machine learning components
│   └── archive/        # Older implementations (not in active use)
├── config/             # Environment configurations
├── reports/            # Generated reports
└── scan.py            # Main entry point for scanning
```

### 4.2 Component Overview

#### Integrated Scanning Components
- `scan.py`: Primary entry point for the consolidated scanning system
- `vulnerability_scanner.py`: Core scanning engine using nmap with integrated vulnerability testing
- `enhanced_report.py`: Advanced report generation with ML-processed data
- `use-scan-socket.tsx`: Real-time scan progress and result handling

#### Machine Learning Integration
- Direct processing of scan results through ML pipeline
- Integration with vulnerability scanners for immediate analysis
- Automatic classification and prediction based on scan data
- Recommendation engine for identified vulnerabilities

#### Analysis Components
- `financial_impact_analyzer.py`: Financial risk assessment
- Automated vulnerability-to-fix mapping system
- Severity classification with business impact assessment

#### Web Application
- Flask-based API server with Socket.IO for real-time updates
- React/Next.js frontend with dashboard components
- Dedicated reports page with proper data integration
- Real-time scan monitoring and result visualization

## 5. Technical Details

### 5.1 Tech Stack
- **Frontend**: React, Next.js, Tailwind CSS
- **Backend**: Flask (Python), Socket.IO for real-time communications
- **ML**: Scikit-Learn, Pandas, NumPy, Joblib for model persistence
- **Primary Tools**: Integrated Nmap-based scanning engine
- **Data Storage**: JSON-based result storage, SQLite for persistent data
- **Real-time Monitoring**: WebSocket connections with progress tracking

### 5.2 Data Sources
- Integrated scan results from Nmap vulnerability testing
- NVD database for comprehensive vulnerability information and fixes
- Scan results directly fed to ML models
- Environment-specific configuration settings
- Historical scan data for trend analysis

### 5.3 Environment Support
- Development: Lightweight scanning for rapid iteration
- Testing: Comprehensive scanning in controlled environments
- Production: Full-featured scanning with enhanced security measures

## 6. Future Roadmap

### 6.1 Short-term Improvements
- Fix dashboard reports page data flow issues
- Enhanced error handling for scan failures
- Improve ML model accuracy for vulnerability prediction
- Better visualization of scan results and remediation steps

### 6.2 Mid-term Development
- Additional scanning capabilities integration
- Enhanced vulnerability-to-fix mapping accuracy
- Expanded dashboard visualizations with interactive elements
- Improved real-time monitoring capabilities

### 6.3 Long-term Vision
- Multi-location scanning support
- Advanced threat hunting capabilities
- Cloud deployment options
- Automated remediation implementation
