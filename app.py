"""
Security Log Analytics Dashboard
A Streamlit application for analyzing server access logs (cPanel/DirectAdmin)
with ML-based anomaly detection using Isolation Forest.

Author: Senior Python Security Developer
"""

import re
import io
from datetime import datetime
from typing import Optional, Tuple

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# ============================================================================
# CONFIGURATION
# ============================================================================

LOG_PATTERN = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+'
    r'(?P<identd>-|\S+)\s+'
    r'(?P<user>-|\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\w+)\s+(?P<url>[^\s]*)\s*(?:HTTP/[\d.]+)?"\s+'
    r'(?P<status>\d+)\s+'
    r'(?P<size>\d+|-)\s+'
    r'"(?P<referer>[^"]*)"\s+'
    r'"(?P<user_agent>[^"]*)"'
)

ANOMALY_CONTAMINATION = 0.05
RANDOM_STATE = 42

# ============================================================================
# LOG PARSER MODULE
# ============================================================================

def parse_log_line(line: str) -> Optional[dict]:
    """
    Parse a single log line in Apache/Nginx Combined Log Format.
    
    Args:
        line: Raw log line string
        
    Returns:
        Dictionary with parsed fields or None if parsing fails
    """
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None
    
    data = match.groupdict()
    
    try:
        timestamp_str = data['timestamp']
        data['timestamp'] = datetime.strptime(
            timestamp_str.split()[0], 
            '%d/%b/%Y:%H:%M:%S'
        )
    except (ValueError, IndexError):
        data['timestamp'] = None
    
    data['status'] = int(data['status']) if data['status'].isdigit() else 0
    data['size'] = int(data['size']) if data['size'].isdigit() else 0
    
    return data


def parse_log_file(file_content: bytes) -> Tuple[pd.DataFrame, int]:
    """
    Parse entire log file content into a DataFrame.
    
    Args:
        file_content: Raw bytes of log file
        
    Returns:
        Tuple of (DataFrame with parsed logs, count of failed parses)
    """
    try:
        text = file_content.decode('utf-8', errors='replace')
    except Exception:
        text = file_content.decode('latin-1', errors='replace')
    
    lines = text.strip().split('\n')
    parsed_records = []
    failed_count = 0
    
    for line in lines:
        if not line.strip():
            continue
            
        record = parse_log_line(line)
        if record:
            parsed_records.append(record)
        else:
            failed_count += 1
    
    if not parsed_records:
        return pd.DataFrame(), failed_count
    
    df = pd.DataFrame(parsed_records)
    
    if 'timestamp' in df.columns and df['timestamp'].notna().any():
        df = df.sort_values('timestamp').reset_index(drop=True)
    
    return df, failed_count


def validate_log_format(df: pd.DataFrame) -> bool:
    """
    Validate if DataFrame contains expected log columns.
    
    Args:
        df: DataFrame to validate
        
    Returns:
        True if valid, False otherwise
    """
    required_columns = {'ip', 'timestamp', 'method', 'url', 'status', 'user_agent'}
    return not df.empty and required_columns.issubset(df.columns)


# ============================================================================
# FEATURE ENGINEERING FOR ML
# ============================================================================

def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Extract features for anomaly detection from parsed log data.
    
    Features extracted per IP:
    - request_count: Total number of requests
    - unique_urls: Number of unique URLs accessed
    - error_4xx_ratio: Ratio of 4xx errors to total requests
    - error_5xx_ratio: Ratio of 5xx errors to total requests
    - avg_request_size: Average response size
    - unique_methods: Number of unique HTTP methods used
    - post_ratio: Ratio of POST requests (potential brute-force indicator)
    - error_404_count: Count of 404 errors (potential scanning indicator)
    
    Args:
        df: DataFrame with parsed log data
        
    Returns:
        DataFrame with features per IP
    """
    if df.empty:
        return pd.DataFrame()
    
    features = df.groupby('ip').agg(
        request_count=('ip', 'count'),
        unique_urls=('url', 'nunique'),
        error_4xx_count=('status', lambda x: (x.astype(int) // 100 == 4).sum()),
        error_5xx_count=('status', lambda x: (x.astype(int) // 100 == 5).sum()),
        error_404_count=('status', lambda x: (x == 404).sum()),
        avg_request_size=('size', 'mean'),
        unique_methods=('method', 'nunique'),
        post_count=('method', lambda x: (x.str.upper() == 'POST').sum()),
        get_count=('method', lambda x: (x.str.upper() == 'GET').sum()),
        min_timestamp=('timestamp', 'min'),
        max_timestamp=('timestamp', 'max'),
        unique_user_agents=('user_agent', 'nunique')
    ).reset_index()
    
    features['error_4xx_ratio'] = features['error_4xx_count'] / features['request_count']
    features['error_5xx_ratio'] = features['error_5xx_count'] / features['request_count']
    features['post_ratio'] = features['post_count'] / features['request_count']
    features['get_ratio'] = features['get_count'] / features['request_count']
    
    if 'min_timestamp' in features.columns and 'max_timestamp' in features.columns:
        features['time_span_seconds'] = (
            features['max_timestamp'] - features['min_timestamp']
        ).dt.total_seconds().replace(0, 1)
        features['requests_per_second'] = features['request_count'] / features['time_span_seconds']
    else:
        features['requests_per_second'] = features['request_count']
    
    features = features.fillna(0)
    
    return features


# ============================================================================
# ANOMALY DETECTION MODULE
# ============================================================================

def detect_anomalies(features_df: pd.DataFrame, contamination: float = ANOMALY_CONTAMINATION) -> pd.DataFrame:
    """
    Detect anomalous IPs using Isolation Forest algorithm.
    
    Args:
        features_df: DataFrame with extracted features
        contamination: Expected proportion of anomalies in dataset
        
    Returns:
        DataFrame with anomaly scores and predictions
    """
    if features_df.empty or len(features_df) < 2:
        return features_df.assign(anomaly_score=0, is_anomaly=False)
    
    feature_columns = [
        'request_count', 'unique_urls', 'error_4xx_ratio', 'error_5xx_ratio',
        'avg_request_size', 'unique_methods', 'post_ratio', 
        'requests_per_second', 'error_404_count', 'unique_user_agents'
    ]
    
    available_features = [col for col in feature_columns if col in features_df.columns]
    
    if not available_features:
        return features_df.assign(anomaly_score=0, is_anomaly=False)
    
    X = features_df[available_features].values
    
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=RANDOM_STATE,
        n_jobs=-1
    )
    
    predictions = model.fit_predict(X_scaled)
    scores = model.score_samples(X_scaled)
    
    result_df = features_df.copy()
    result_df['anomaly_score'] = -scores
    result_df['is_anomaly'] = predictions == -1
    
    risk_scores = result_df['anomaly_score'].quantile([0.75, 0.9])
    
    def classify_threat(row):
        if not row['is_anomaly']:
            return 'Normal'
        elif row['anomaly_score'] > risk_scores[0.9]:
            return 'High Risk'
        elif row['anomaly_score'] > risk_scores[0.75]:
            return 'Medium Risk'
        else:
            return 'Low Risk'
    
    result_df['threat_level'] = result_df.apply(classify_threat, axis=1)
    
    return result_df


# ============================================================================
# DASHBOARD VISUALIZATION MODULE
# ============================================================================

def render_metrics(df: pd.DataFrame):
    """
    Render KPI metrics cards at the top of dashboard.
    
    Args:
        df: DataFrame with parsed log data
    """
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            label="Total Requests",
            value=f"{len(df):,}",
            delta=None
        )
    
    with col2:
        unique_ips = df['ip'].nunique() if not df.empty else 0
        st.metric(
            label="Unique IPs",
            value=f"{unique_ips:,}",
            delta=None
        )
    
    with col3:
        if not df.empty:
            error_404 = (df['status'] == 404).sum()
        else:
            error_404 = 0
        st.metric(
            label="404 Errors",
            value=f"{error_404:,}",
            delta=None
        )
    
    with col4:
        if not df.empty:
            error_5xx = df['status'].apply(lambda x: 500 <= int(x) < 600).sum()
        else:
            error_5xx = 0
        st.metric(
            label="5xx Errors",
            value=f"{error_5xx:,}",
            delta=None
        )


def render_traffic_chart(df: pd.DataFrame):
    """
    Render line chart showing traffic trends over time.
    
    Args:
        df: DataFrame with parsed log data
    """
    if df.empty or 'timestamp' not in df.columns:
        st.info("No timestamp data available for traffic chart.")
        return
    
    df_time = df.dropna(subset=['timestamp']).copy()
    
    if df_time.empty:
        st.info("No valid timestamp data for visualization.")
        return
    
    df_time['time_bucket'] = df_time['timestamp'].dt.floor('H')
    
    time_series = df_time.groupby('time_bucket').size().reset_index(name='requests')
    
    fig = px.line(
        time_series,
        x='time_bucket',
        y='requests',
        title='Traffic Trend (Requests per Hour)',
        labels={'time_bucket': 'Time', 'requests': 'Requests'},
        markers=True
    )
    
    fig.update_layout(
        height=350,
        xaxis_title='Time',
        yaxis_title='Number of Requests',
        hovermode='x unified'
    )
    
    st.plotly_chart(fig, use_container_width=True)


def render_status_distribution(df: pd.DataFrame):
    """
    Render pie chart of HTTP status code distribution.
    
    Args:
        df: DataFrame with parsed log data
    """
    if df.empty:
        st.info("No data for status code distribution.")
        return
    
    def categorize_status(code):
        code = int(code)
        if code < 200:
            return '1xx (Informational)'
        elif code < 300:
            return '2xx (Success)'
        elif code < 400:
            return '3xx (Redirect)'
        elif code < 500:
            return '4xx (Client Error)'
        else:
            return '5xx (Server Error)'
    
    df['status_category'] = df['status'].apply(categorize_status)
    status_counts = df['status_category'].value_counts().reset_index()
    status_counts.columns = ['Category', 'Count']
    
    fig = px.pie(
        status_counts,
        values='Count',
        names='Category',
        title='HTTP Status Code Distribution',
        hole=0.4
    )
    
    fig.update_layout(height=350)
    st.plotly_chart(fig, use_container_width=True)


def render_top_ips(df: pd.DataFrame, top_n: int = 10):
    """
    Render table and bar chart of top IP addresses by request count.
    
    Args:
        df: DataFrame with parsed log data
        top_n: Number of top IPs to display
    """
    if df.empty:
        st.info("No data for top IPs analysis.")
        return
    
    ip_stats = df.groupby('ip').agg(
        request_count=('ip', 'count'),
        unique_urls=('url', 'nunique'),
        error_4xx=('status', lambda x: (x.astype(int) // 100 == 4).sum())
    ).reset_index()
    
    ip_stats = ip_stats.sort_values('request_count', ascending=False).head(top_n)
    
    col_chart, col_table = st.columns([1, 1])
    
    with col_chart:
        fig = px.bar(
            ip_stats.head(10),
            x='request_count',
            y='ip',
            orientation='h',
            title=f'Top {min(10, len(ip_stats))} IPs by Request Count',
            labels={'request_count': 'Requests', 'ip': 'IP Address'},
            color='request_count',
            color_continuous_scale='Blues'
        )
        fig.update_layout(height=350, yaxis={'categoryorder': 'total ascending'})
        st.plotly_chart(fig, use_container_width=True)
    
    with col_table:
        st.dataframe(
            ip_stats.style.format({
                'request_count': '{:,}',
                'unique_urls': '{:,}',
                'error_4xx': '{:,}'
            }),
            use_container_width=True,
            height=350
        )


def render_method_distribution(df: pd.DataFrame):
    """
    Render bar chart of HTTP methods distribution.
    
    Args:
        df: DataFrame with parsed log data
    """
    if df.empty:
        return
    
    method_counts = df['method'].value_counts().reset_index()
    method_counts.columns = ['Method', 'Count']
    
    fig = px.bar(
        method_counts,
        x='Method',
        y='Count',
        title='HTTP Methods Distribution',
        color='Count',
        color_continuous_scale='Viridis'
    )
    
    fig.update_layout(height=300)
    st.plotly_chart(fig, use_container_width=True)


def render_anomaly_alerts(anomaly_df: pd.DataFrame):
    """
    Render anomaly detection results and alerts.
    
    Args:
        anomaly_df: DataFrame with anomaly detection results
    """
    st.subheader("🚨 Anomaly Detection Alerts")
    
    if anomaly_df.empty:
        st.info("No data available for anomaly detection.")
        return
    
    anomalies = anomaly_df[anomaly_df['is_anomaly'] == True].copy()
    
    if anomalies.empty:
        st.success("✅ No anomalies detected in the analyzed log data.")
        return
    
    threat_counts = anomalies['threat_level'].value_counts()
    
    cols = st.columns(4)
    cols[0].metric("Total Anomalies", len(anomalies))
    cols[1].metric("High Risk", threat_counts.get('High Risk', 0), delta_color="inverse")
    cols[2].metric("Medium Risk", threat_counts.get('Medium Risk', 0), delta_color="inverse")
    cols[3].metric("Low Risk", threat_counts.get('Low Risk', 0))
    
    st.divider()
    
    high_risk = anomalies[anomalies['threat_level'] == 'High Risk']
    if not high_risk.empty:
        st.markdown("### 🔴 High Risk IPs (Potential Attacks)")
        
        display_cols = [
            'ip', 'request_count', 'error_4xx_ratio', 'error_404_count',
            'requests_per_second', 'post_ratio', 'unique_user_agents', 'anomaly_score'
        ]
        available_cols = [col for col in display_cols if col in high_risk.columns]
        
        st.dataframe(
            high_risk[available_cols].sort_values('anomaly_score', ascending=False),
            use_container_width=True
        )
    
    medium_risk = anomalies[anomalies['threat_level'] == 'Medium Risk']
    if not medium_risk.empty:
        st.markdown("### 🟡 Medium Risk IPs")
        
        display_cols = [
            'ip', 'request_count', 'error_4xx_ratio', 'error_404_count',
            'requests_per_second', 'anomaly_score'
        ]
        available_cols = [col for col in display_cols if col in medium_risk.columns]
        
        with st.expander(f"View {len(medium_risk)} Medium Risk IPs", expanded=False):
            st.dataframe(
                medium_risk[available_cols].sort_values('anomaly_score', ascending=False),
                use_container_width=True
            )
    
    low_risk = anomalies[anomalies['threat_level'] == 'Low Risk']
    if not low_risk.empty:
        with st.expander(f"View {len(low_risk)} Low Risk IPs", expanded=False):
            display_cols = ['ip', 'request_count', 'anomaly_score']
            available_cols = [col for col in display_cols if col in low_risk.columns]
            st.dataframe(low_risk[available_cols], use_container_width=True)
    
    st.divider()
    
    st.markdown("### 📊 Anomaly Score Distribution")
    
    fig = px.histogram(
        anomaly_df,
        x='anomaly_score',
        color='is_anomaly',
        title='Distribution of Anomaly Scores',
        labels={'anomaly_score': 'Anomaly Score', 'is_anomaly': 'Is Anomaly'},
        nbins=50
    )
    fig.update_layout(height=350)
    st.plotly_chart(fig, use_container_width=True)


def render_attack_indicators(df: pd.DataFrame):
    """
    Render potential attack pattern analysis.
    
    Args:
        df: DataFrame with parsed log data
    """
    st.subheader("🔍 Attack Pattern Analysis")
    
    if df.empty:
        st.info("No data for attack pattern analysis.")
        return
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**Potential Scanning Activity** (High 404 errors from single IP)")
        
        scan_suspects = df[df['status'] == 404].groupby('ip').size()
        scan_suspects = scan_suspects[scan_suspects >= 10].sort_values(ascending=False)
        
        if not scan_suspects.empty:
            st.dataframe(
                scan_suspects.reset_index().head(10).rename(columns={0: '404_Count'}),
                use_container_width=True
            )
        else:
            st.info("No suspicious scanning patterns detected.")
    
    with col2:
        st.markdown("**Potential Brute-Force Activity** (High POST requests)")
        
        post_suspects = df[df['method'].str.upper() == 'POST'].groupby('ip').agg({
            'url': 'count',
            'status': lambda x: (x.astype(int) // 100 == 4).sum()
        }).rename(columns={'url': 'post_count', 'status': 'failed_attempts'})
        
        post_suspects = post_suspects[
            (post_suspects['post_count'] >= 10) | 
            (post_suspects['failed_attempts'] >= 5)
        ].sort_values('post_count', ascending=False)
        
        if not post_suspects.empty:
            st.dataframe(post_suspects.head(10), use_container_width=True)
        else:
            st.info("No suspicious brute-force patterns detected.")


def render_dashboard(df: pd.DataFrame, anomaly_df: pd.DataFrame):
    """
    Render the complete dashboard with all visualizations.
    
    Args:
        df: DataFrame with parsed log data
        anomaly_df: DataFrame with anomaly detection results
    """
    st.title("🛡️ Security Log Analytics Dashboard")
    st.markdown("Analyze server access logs with ML-powered anomaly detection")
    
    st.divider()
    
    render_metrics(df)
    
    st.divider()
    
    col1, col2 = st.columns([2, 1])
    with col1:
        render_traffic_chart(df)
    with col2:
        render_status_distribution(df)
    
    st.divider()
    st.subheader("🌐 Top IP Addresses")
    render_top_ips(df)
    
    st.divider()
    
    col1, col2 = st.columns(2)
    with col1:
        render_method_distribution(df)
    with col2:
        st.markdown("**Top URLs Accessed**")
        if not df.empty:
            top_urls = df['url'].value_counts().head(10).reset_index()
            top_urls.columns = ['URL', 'Count']
            st.dataframe(top_urls, use_container_width=True, height=300)
    
    st.divider()
    
    render_anomaly_alerts(anomaly_df)
    
    st.divider()
    
    render_attack_indicators(df)


# ============================================================================
# MAIN APPLICATION
# ============================================================================

def main():
    """
    Main application entry point.
    """
    st.set_page_config(
        page_title="Security Log Analytics",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    with st.sidebar:
        st.header("📁 Log File Upload")
        uploaded_file = st.file_uploader(
            "Upload access.log file",
            type=['log', 'txt'],
            help="Upload Apache/Nginx access log file in Combined Log Format"
        )
        
        st.divider()
        
        st.header("⚙️ ML Settings")
        contamination = st.slider(
            "Anomaly Sensitivity",
            min_value=0.01,
            max_value=0.20,
            value=ANOMALY_CONTAMINATION,
            step=0.01,
            help="Higher values detect more anomalies but may increase false positives"
        )
        
        st.divider()
        
        st.header("📊 Filters")
        
        date_filter = st.checkbox("Enable Date Filter", value=False)
        date_range = None
        if date_filter:
            date_range = st.date_input("Select Date Range", [])
        
        status_filter = st.multiselect(
            "Filter by Status Code",
            options=['2xx', '3xx', '4xx', '5xx'],
            default=['2xx', '3xx', '4xx', '5xx']
        )
        
        st.divider()
        
        st.markdown("""
        ### ℹ️ About
        This tool analyzes server access logs for:
        - Traffic patterns
        - Security anomalies
        - Potential attacks
        
        **Supported Formats:**
        - Apache Combined Log
        - Nginx Access Log
        """)
    
    if uploaded_file is None:
        st.title("🛡️ Security Log Analytics Dashboard")
        st.markdown("""
        Welcome to the Security Log Analytics Dashboard!
        
        **Getting Started:**
        1. Upload your `access.log` file using the sidebar
        2. Adjust ML sensitivity if needed
        3. Review the analytics and anomaly alerts
        
        **Supported Log Formats:**
        - Apache Combined Log Format
        - Nginx Access Log Format
        - cPanel/DirectAdmin standard access logs
        """)
        
        st.info("👆 Please upload a log file to begin analysis.")
        return
    
    with st.spinner("Parsing log file..."):
        file_content = uploaded_file.read()
        df, failed_count = parse_log_file(file_content)
    
    if failed_count > 0:
        st.warning(f"⚠️ {failed_count} lines could not be parsed and were skipped.")
    
    if not validate_log_format(df):
        st.error("""
        ❌ **Invalid Log Format**
        
        The uploaded file does not appear to be a valid Apache/Nginx access log.
        
        **Expected format (Combined Log Format):**
        ```
        192.168.1.1 - - [10/Oct/2023:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"
        ```
        """)
        return
    
    if status_filter:
        def status_in_filter(code):
            code = int(code) // 100
            return f"{code}xx" in status_filter
        df = df[df['status'].apply(status_in_filter)]
    
    if date_filter and date_range and len(date_range) == 2:
        start_date = pd.Timestamp(date_range[0])
        end_date = pd.Timestamp(date_range[1]) + pd.Timedelta(days=1)
        df = df[(df['timestamp'] >= start_date) & (df['timestamp'] < end_date)]
    
    with st.spinner("Running anomaly detection..."):
        features_df = extract_features(df)
        anomaly_df = detect_anomalies(features_df, contamination=contamination)
    
    render_dashboard(df, anomaly_df)
    
    with st.sidebar:
        st.divider()
        st.markdown("### 📥 Export Results")
        
        if st.button("Download Anomaly Report"):
            csv = anomaly_df[anomaly_df['is_anomaly']].to_csv(index=False)
            st.download_button(
                label="Download CSV",
                data=csv,
                file_name="anomaly_report.csv",
                mime="text/csv"
            )


if __name__ == "__main__":
    main()