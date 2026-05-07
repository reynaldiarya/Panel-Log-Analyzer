# Security Log Analytics

A professional-grade Streamlit application for server access log analysis and machine learning-powered anomaly detection.

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-blue.svg" />
  <img src="https://img.shields.io/badge/Python-3.9+-3776AB.svg" />
  <img src="https://img.shields.io/badge/Streamlit-1.54+-FF4B4B.svg" />
  <a href="LICENSE">
    <img alt="License" src="https://img.shields.io/badge/license-MIT-yellow.svg" target="_blank" />
  </a>
  <a href="https://codecov.io/gh/reynaldiarya/Security-Log-Analytics">
    <img src="https://codecov.io/gh/reynaldiarya/Security-Log-Analytics/branch/main/graph/badge.svg" />
  </a>
</p>

## Description

Security Log Analytics provides a robust solution for security engineers and system administrators to analyze server access logs from platforms like Apache, Nginx, cPanel, and DirectAdmin. By leveraging machine learning algorithms, it identifies suspicious traffic patterns and potential security threats that traditional rule-based systems might miss. The platform transforms raw, complex log data into actionable intelligence, helping teams proactively secure their web infrastructure against distributed attacks, scanners, and unauthorized access attempts.

## Features

- **Advanced Log Parsing** - Seamlessly process standard combined log formats with high-performance regex parsing
- **ML-Powered Anomaly Detection** - Identify sophisticated attack patterns using Scikit-learn's Isolation Forest algorithm
- **CDN Intelligence** - Built-in detection for major providers including Cloudflare, Bunny CDN, AWS CloudFront, and more
- **Bot & Crawler Identification** - Automatically distinguish between legitimate search engine bots and potential malicious actors
- **Interactive Security Dashboard** - Visualize traffic trends, HTTP status distributions, and request volumes through dynamic Plotly charts
- **Granular IP Reputation** - Deep behavioral analysis of individual IPs including request rates, 4xx/5xx ratios, and method distributions
- **Configurable Threat Scoring** - Adjustable contamination parameters to fine-tune detection sensitivity for different environments
- **White-label Support** - Native CIDR-based whitelisting to exclude trusted internal networks from security alerts

## Tech Stack

- **Core Engine**: Python 3.9+
- **Frontend Framework**: Streamlit 1.54+
- **Machine Learning**: Scikit-learn (Isolation Forest, StandardScaler)
- **Data Engineering**: Pandas, NumPy
- **Visualization**: Plotly Express
- **Networking**: ipaddress (CIDR validation)

## Installation Guide

### Prerequisites

- Python 3.9 or higher
- pip (Python package manager)
- Virtual environment (recommended)

### Steps

1. Clone the repository to your local machine

```bash
git clone https://github.com/reynaldiarya/Security-Log-Analytics.git
cd Security-Log-Analytics
```

2. Create and activate a virtual environment

```bash
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate
```

3. Install the required dependencies

```bash
pip install -r requirements.txt
```

4. Launch the application

```bash
streamlit run app.py
```

The application will be accessible in your browser at `http://localhost:8501`.

## Configuration

The application is designed for plug-and-play usage, but several internal configurations can be adjusted within `app.py` for advanced use cases.

### Detection Parameters

| Variable | Description | Default |
|----------|-------------|---------|
| `ANOMALY_CONTAMINATION` | The expected proportion of outliers in the data | `0.05` |
| `RANDOM_STATE` | Seed for reproducible ML results | `42` |
| `LOG_PATTERN` | Regex pattern for log parsing | Combined Log Format |

### Whitelisting

Users can input a list of IP addresses or CIDR ranges directly in the sidebar during runtime to exclude them from the anomaly detection engine.

## Usage

### Analyzing Logs

1. **Upload**: Drag and drop your `.log` or `.txt` file into the sidebar upload area.
2. **Parameters**: Configure the "Anomaly Detection Sensitivity" (contamination factor) based on your traffic volume.
3. **Whitelist**: Add known safe IPs (e.g., your office IP or monitoring services) to prevent false positives.
4. **Analysis**:
   - Review the **Security Metrics** cards for immediate high-level status.
   - Inspect the **Traffic Trend** to spot sudden spikes in volume.
   - Examine the **Anomaly Alerts** section for specific IPs flagged as High, Medium, or Low risk.
5. **Reputation**: Select a suspicious IP from the dropdown to see its specific behavioral signature and reputation score.

### Supported Log Format

The parser expects the Nginx/Apache Combined Log Format:
`127.0.0.1 - - [01/Jan/2026:00:00:01 +0000] "GET /api/v1/resource HTTP/1.1" 200 1234 "https://referer.com" "Mozilla/5.0..."`

## Project Structure

```text
/
├── app.py                # Main application logic and Streamlit UI
├── requirements.txt      # Project dependencies and version constraints
├── LICENSE               # MIT License terms
└── README.md             # Project documentation
```

## Scripts / Commands

| Command | Description |
|---------|-------------|
| `streamlit run app.py` | Starts the production-ready dashboard locally |
| `pip install -r requirements.txt` | Installs all necessary Python libraries |
| `python -m pytest` | Run automated tests (if configured) |

## Contributing

Professional contributions are welcome to enhance the detection engine or parser compatibility.

1. Fork the repository
2. Create a specific feature branch (`git checkout -b feature/improvement-name`)
3. Commit your changes with clear, descriptive messages
4. Push to the branch (`git push origin feature/improvement-name`)
5. Open a well-documented Pull Request

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for detailed terms and conditions.

## Author

Reynaldi Arya