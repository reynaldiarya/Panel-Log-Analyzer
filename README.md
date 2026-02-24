<p align="center">
  <img src="https://raw.githubusercontent.com/streamlit/streamlit/master/frontend/public/favicon.ico" width="120" alt="Streamlit Logo">
</p>

<h1 align="center">Security Log Analytics Dashboard</h1>

<p align="center">
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python Version"></a>
  <a href="https://streamlit.io/"><img src="https://img.shields.io/badge/Streamlit-1.28+-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white" alt="Streamlit Version"></a>
  <a href="https://scikit-learn.org/"><img src="https://img.shields.io/badge/scikit--learn-1.3+-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white" alt="Sklearn Version"></a>
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

## 🛠️ Tech Stack

| Technology | Version |
| ---------- | ------- |
| Python     | ^3.9    |
| Streamlit  | ^1.28   |
| Pandas     | ^2.0    |
| Plotly     | ^5.18   |
| scikit-learn | ^1.3  |
| NumPy      | ^1.24   |

## 📦 Dependencies

### Core Dependencies

| Package                                           | Version | Description                      |
| ------------------------------------------------- | ------- | -------------------------------- |
| [streamlit](https://streamlit.io/)                | >=1.28.0| Web framework for data apps      |
| [pandas](https://pandas.pydata.org/)              | >=2.0.0 | Data manipulation library        |
| [plotly](https://plotly.com/python/)              | >=5.18.0| Interactive visualization         |
| [scikit-learn](https://scikit-learn.org/)         | >=1.3.0 | Machine learning library         |
| [numpy](https://numpy.org/)                       | >=1.24.0| Numerical computing library       |

## 📋 Requirements

- Python >= 3.9
- pip package manager
- Access log files (Apache/Nginx format)

## 🚀 Installation

### 1. Clone Repository

```bash
git clone https://github.com/your-username/panel-log-analyzer.git
cd panel-log-analyzer
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

| Field       | Description                |
| ----------- | -------------------------- |
| IP          | Client IP address          |
| Timestamp   | Request date and time      |
| Method      | HTTP method (GET, POST, etc.) |
| URL         | Requested URL path         |
| Status      | HTTP status code           |
| Size        | Response size in bytes     |
| Referer     | HTTP Referer header        |
| User Agent  | Client user agent string   |

## ⚙️ Configuration

| Parameter              | Default | Description                          |
| ---------------------- | ------- | ------------------------------------ |
| `ANOMALY_CONTAMINATION`| 0.05    | Expected proportion of anomalies     |
| `RANDOM_STATE`         | 42      | Random seed for reproducibility      |

Adjust contamination via the UI slider (0.01 - 0.20).

## 🎯 Anomaly Detection Features

The application extracts the following features per IP for anomaly detection:

| Feature              | Description                              |
| -------------------- | ---------------------------------------- |
| `request_count`      | Total number of requests                 |
| `unique_urls`        | Number of unique URLs accessed           |
| `error_4xx_ratio`    | Ratio of 4xx errors to total requests    |
| `error_5xx_ratio`    | Ratio of 5xx errors to total requests    |
| `avg_request_size`   | Average response size                    |
| `requests_per_second`| Request rate                             |
| `post_ratio`         | Ratio of POST requests                   |
| `unique_user_agents` | Number of unique user agents             |

### Threat Levels

| Level       | Criteria                        |
| ----------- | ------------------------------- |
| High Risk   | Anomaly score > 90th percentile |
| Medium Risk | Anomaly score > 75th percentile |
| Low Risk    | Anomaly score ≤ 75th percentile |

## 📁 Folder Structure

```
panel-log-analyzer/
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