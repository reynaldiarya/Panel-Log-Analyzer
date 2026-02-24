<p align="center">
  <img src="https://streamlit.io/images/brand/streamlit-logo-primary-colormark-lighttext.png" width="120" alt="Streamlit Logo">
</p>

<h1 align="center">Security Log Analytics Dashboard</h1>

<p align="center">
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python Version"></a>
  <a href="https://streamlit.io/"><img src="https://img.shields.io/badge/Streamlit-1.54+-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white" alt="Streamlit Version"></a>
  <a href="https://scikit-learn.org/"><img src="https://img.shields.io/badge/scikit--learn-1.8+-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white" alt="Sklearn Version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License"></a>
</p>

<p align="center">
  A Streamlit-based web application for analyzing server access logs with ML-powered anomaly detection using <strong>Isolation Forest</strong> algorithm.
</p>

---

## ✨ Key Features

### 📊 Traffic Analytics

- Real-time traffic trend visualization
- HTTP status code distribution
- Top IP addresses by request count
- HTTP methods distribution
- Top URLs accessed

### 🤖 ML Anomaly Detection

- Isolation Forest algorithm for detecting suspicious IPs
- Configurable anomaly sensitivity (contamination rate)
- Threat level classification (High, Medium, Low Risk)
- Anomaly score distribution visualization

### 🛡️ IP Whitelist & CDN Detection

- **Automatic CDN Detection**: Recognizes IPs from major CDN providers
  - Cloudflare, Bunny CDN, AWS CloudFront, Google Cloud CDN
  - Fastly, Akamai, StackPath, KeyCDN, CDN77, Sucuri
- **IP Whitelist**: Manual exclusion of trusted IPs/ranges
  - Support for single IPs (e.g., `192.168.1.1`)
  - Support for CIDR ranges (e.g., `10.0.0.0/8`)
- **Bot Detection**: Recognizes major search engine crawlers
  - Googlebot, Bingbot, DuckDuckBot, and more

### 🔍 IP Reputation Analysis

- Automatic reputation scoring per IP
- Behavior-based indicators
- CDN attribution display

### 🔍 Attack Pattern Analysis

- Potential scanning activity detection (high 404 errors)
- Brute-force activity detection (high POST requests)
- IP-based behavior profiling

### 🛡️ Log Parsing

- Apache Combined Log Format support
- Nginx Access Log Format support
- cPanel/DirectAdmin standard access logs
- UTF-8 and Latin-1 encoding support

### 📥 Export & Filtering

- Download anomaly reports as CSV
- Date range filtering
- HTTP status code filtering
- **File extension filtering** - Filter by URL file extensions (`.php`, `.html`, `.js`, `.css`, images, etc.)
- **URL keyword filtering** - Include or exclude URLs containing specific keywords

## 🛠️ Tech Stack

| Technology   | Version |
| ------------ | ------- |
| Python       | ^3.9    |
| Streamlit    | ^1.54   |
| Pandas       | ^2.3    |
| Plotly       | ^6.5    |
| scikit-learn | ^1.8    |
| NumPy        | ^2.4    |

## 📦 Dependencies

### Core Dependencies

| Package                                   | Version  | Description                 |
| ----------------------------------------- | -------- | --------------------------- |
| [streamlit](https://streamlit.io/)        | >=1.54.0 | Web framework for data apps |
| [pandas](https://pandas.pydata.org/)      | >=2.3.3  | Data manipulation library   |
| [plotly](https://plotly.com/python/)      | >=6.5.2  | Interactive visualization   |
| [scikit-learn](https://scikit-learn.org/) | >=1.8.0  | Machine learning library    |
| [numpy](https://numpy.org/)               | >=2.4.2  | Numerical computing library |

## 📋 Requirements

- Python >= 3.9
- pip package manager
- Access log files (Apache/Nginx format)

## 🚀 Installation

### 1. Clone Repository

```bash
git clone https://github.com/reynaldiarya/Security-Log-Analytics.git
cd Security-Log-Analytics
```

### 2. Create Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run Application

```bash
streamlit run app.py
```

Access the application at: `http://localhost:8501`

## 📝 Log Format

The application expects Apache/Nginx Combined Log Format:

```
192.168.1.1 - - [10/Oct/2023:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"
```

### Fields Parsed

| Field      | Description                   |
| ---------- | ----------------------------- |
| IP         | Client IP address             |
| Timestamp  | Request date and time         |
| Method     | HTTP method (GET, POST, etc.) |
| URL        | Requested URL path            |
| Status     | HTTP status code              |
| Size       | Response size in bytes        |
| Referer    | HTTP Referer header           |
| User Agent | Client user agent string      |

## ⚙️ Configuration

| Parameter               | Default | Description                      |
| ----------------------- | ------- | -------------------------------- |
| `ANOMALY_CONTAMINATION` | 0.05    | Expected proportion of anomalies |
| `RANDOM_STATE`          | 42      | Random seed for reproducibility  |

Adjust contamination via the UI slider (0.01 - 0.20).

## 🔍 Data Filtering

### Status Code Filter

Filter log entries by HTTP status code category:
- 2xx (Success)
- 3xx (Redirect)
- 4xx (Client Error)
- 5xx (Server Error)

### File Extension Filter

Filter log entries by URL file extension:

| Extension | Description |
| --------- | ----------- |
| `.php` | PHP scripts |
| `.html/.htm` | HTML pages |
| `.js` | JavaScript files |
| `.css` | Stylesheets |
| `.jpg/.jpeg/.png/.gif/.svg` | Image files |
| `.json/.xml` | Data files |
| `.txt/.pdf/.zip` | Documents & archives |

Select multiple extensions or choose "All" to disable filtering.

### URL Keyword Filter

Filter by URL keywords with two modes:

| Mode | Description |
| ---- | ----------- |
| **Include** | Show only URLs containing specified keywords |
| **Exclude** | Hide URLs containing specified keywords |

Example keywords (one per line):
```
/admin
/wp-login.php
/api/
.xmlrpc.php
```

## 🎯 Anomaly Detection Features

The application extracts the following features per IP for anomaly detection:

| Feature               | Description                           |
| --------------------- | ------------------------------------- |
| `request_count`       | Total number of requests              |
| `unique_urls`         | Number of unique URLs accessed        |
| `error_4xx_ratio`     | Ratio of 4xx errors to total requests |
| `error_5xx_ratio`     | Ratio of 5xx errors to total requests |
| `avg_request_size`    | Average response size                 |
| `requests_per_second` | Request rate                          |
| `post_ratio`          | Ratio of POST requests                |
| `unique_user_agents`  | Number of unique user agents          |

### Threat Levels

| Level       | Criteria                        |
| ----------- | ------------------------------- |
| High Risk   | Anomaly score > 90th percentile |
| Medium Risk | Anomaly score > 75th percentile |
| Low Risk    | Anomaly score ≤ 75th percentile |

## 🛡️ Whitelist & CDN Detection

### Supported CDN Providers

| Provider        | Detection Method |
| --------------- | ---------------- |
| Cloudflare      | IP Range Match   |
| Bunny CDN       | IP Range Match   |
| AWS CloudFront  | IP Range Match   |
| Google Cloud CDN| IP Range Match   |
| Fastly          | IP Range Match   |
| Akamai          | IP Range Match   |
| StackPath       | IP Range Match   |
| KeyCDN          | IP Range Match   |
| CDN77           | IP Range Match   |
| Sucuri          | IP Range Match   |

### IP Whitelist Usage

Enter IPs to exclude from anomaly detection (one per line):

```
192.168.1.1
10.0.0.0/8
172.16.0.0/12
```

### IP Reputation Indicators

| Indicator              | Impact on Reputation |
| ---------------------- | -------------------- |
| Known CDN IP           | Trusted (-50 pts)    |
| Known Bot/Crawler      | Trusted (-30 pts)    |
| High 4xx Error Ratio   | Suspicious (+20 pts) |
| High Request Rate      | Suspicious (+25 pts) |
| Multiple User Agents   | Questionable (+15 pts) |

## 📁 Folder Structure

```
Security-Log-Analytics/
├── app.py              # Main Streamlit application
├── requirements.txt    # Python dependencies
├── LICENSE             # MIT License
└── README.md           # Documentation
```

## 🔧 Development

### Running Locally

```bash
streamlit run app.py --server.port 8501
```

### Code Style

Follow PEP 8 guidelines for Python code formatting.

## 🤝 Contributing

Contributions are welcome! Please fork this repository and create a pull request for any improvements or bug fixes.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the [MIT License](LICENSE).

## 🙏 Credits

- [Streamlit](https://streamlit.io/) - The fastest way to build data apps
- [scikit-learn](https://scikit-learn.org/) - Machine Learning in Python
- [Plotly](https://plotly.com/) - Modern Visualization for the Data Era

---

<p align="center">
  Made with ❤️ for Security Analysts
</p>
