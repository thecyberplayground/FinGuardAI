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
- Automate threat detection and vulnerability identification using real scan data.
- Offer recommendations and remediation steps for identified vulnerabilities.
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

### 2.3 Scanning Engine
**Overview**: Automated vulnerability scanning and passive monitoring for network assets.

**Requirements**:
- **Active Scans**:
  - Primary tool: Nmap with advanced script capabilities
  - Scan depths: Basic (ports/services) and deep (versions, vulnerabilities)
  - Environment-specific configurations (dev/test/prod)
  - Support for different scan intensities (stealthy, normal, aggressive)
- **Passive Monitoring**:
  - Real-time network monitoring with Socket.IO communications
  - Port monitoring and connection tracking
  - Traffic pattern analysis for anomaly detection
  - Live updates to dashboard via Socket.IO
- **Results Analysis**:
  - XML parsing and structured result storage
  - Financial impact assessment
  - Severity classification

### 2.4 ML-Driven Analysis
**Overview**: Uses network traffic and scan data to detect threats.

**Requirements**:
- **Threat Detection**: Classification based on traffic patterns using RandomForest classifier
- **Vulnerability Assessment**: Evaluates scan results for security weaknesses
- **Model Training**: Dynamically trains on first use if model doesn't exist 
- **Environment Support**: Different models/settings for dev, test, and production

### 2.5 Dashboard
**Overview**: Central hub for monitoring and analysis.

**Requirements**:
- **Scan Section**: Target input, scan controls and real-time progress
- **Results Section**: Interactive display of scan findings
- **Reports Section**: Previous scan results and generated reports
- **Settings**: Environment configuration and scan parameters

### 2.6 Reporting
**Overview**: Detailed insights with output options.

**Requirements**:
- Multiple formats: HTML, text, and JSON
- Detailed vulnerability information with severity levels
- Remediation recommendations
- Financial impact analysis for financial sector clients

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

#### Scanning Components
- `scan.py`: Primary entry point for vulnerability scanning
- `vulnerability_scanner.py`: Core scanning engine using nmap
- `enhanced_report.py`: Advanced report generation

#### Machine Learning Components
- `threat_model.py`: Network threat detection model
- `detect_threats.py`: Threat detection implementation 

#### Analysis Components
- `financial_impact_analyzer.py`: Financial risk assessment
- `vulnerability_predictor.py`: Vulnerability prediction engine

#### Web Application
- Flask-based API server with Socket.IO for real-time updates
- React frontend with dashboard components

## 5. Technical Details

### 5.1 Tech Stack
- **Frontend**: React, Next.js, Tailwind CSS
- **Backend**: Flask (Python), Socket.IO
- **ML**: Scikit-Learn, Pandas, NumPy, Joblib
- **Primary Tools**: Nmap for comprehensive scanning
- **Data Storage**: JSON-based result storage, SQLite for persistent data

### 5.2 Data Sources
- Network scan results from Nmap
- NVD data for vulnerability information
- ML training data (CICIDS dataset)

### 5.3 Environment Support
- Development: Lightweight scanning for rapid iteration
- Testing: Comprehensive scanning in controlled environments
- Production: Full-featured scanning with enhanced security measures

## 6. Future Roadmap

### 6.1 Short-term Improvements
- Enhanced error handling and logging
- Improved documentation
- More comprehensive test coverage

### 6.2 Mid-term Development
- Additional scanning tools integration (OpenVAS, Nikto)
- Enhanced ML models with more data sources
- Expanded dashboard visualizations

### 6.3 Long-term Vision
- Multi-location scanning support
- Advanced threat hunting capabilities
- Cloud deployment options
