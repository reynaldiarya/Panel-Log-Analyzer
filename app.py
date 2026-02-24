"""
Security Log Analytics Dashboard
A Streamlit application for analyzing server access logs (cPanel/DirectAdmin)
with ML-based anomaly detection using Isolation Forest.

Author: Senior Python Security Developer
"""

import ipaddress
import logging
import re
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

import pandas as pd
import plotly.express as px
import streamlit as st
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
# CDN & TRUSTED IP RANGES
# ============================================================================

CDN_IP_RANGES: Dict[str, List[str]] = {
    'Cloudflare': [
        '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
        '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
        '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
        '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'
    ],
    'Bunny CDN': [
        '87.249.128.0/19', '87.249.137.0/24', '93.123.39.0/24', '185.93.0.0/20',
        '185.232.64.0/22', '193.239.84.0/23', '193.239.86.0/23', '194.36.16.0/22',
        '195.20.12.0/22', '195.181.168.0/23', '195.181.170.0/23', '45.66.208.0/22',
        '91.121.72.0/24', '91.134.192.0/21', '149.7.16.0/20', '162.253.56.0/22',
        '172.105.48.0/20', '192.241.192.0/20', '198.98.48.0/20', '206.189.16.0/20',
        '64.227.0.0/17', '67.205.128.0/18', '68.183.0.0/16', '74.208.0.0/16',
        '89.58.0.0/17', '89.187.160.0/21', '178.62.128.0/17', '178.239.160.0/20',
        '188.166.0.0/16', '209.97.128.0/18', '216.239.32.0/19'
    ],
    'AWS CloudFront': [
        '13.249.0.0/14', '18.68.0.0/16', '18.154.0.0/15', '18.164.0.0/15',
        '52.46.0.0/17', '52.82.128.0/19', '52.84.0.0/14', '54.182.0.0/16',
        '54.192.0.0/12', '99.84.0.0/16', '99.86.0.0/16', '108.138.0.0/15',
        '116.129.224.0/19', '130.176.0.0/16', '143.204.0.0/16'
    ],
    'Google Cloud CDN': [
        '34.64.0.0/10', '35.184.0.0/13', '35.192.0.0/14', '35.196.0.0/15',
        '35.198.0.0/16', '35.199.0.0/17', '35.199.128.0/18', '35.200.0.0/13',
        '35.208.0.0/12', '104.154.0.0/15', '104.196.0.0/14', '107.167.160.0/19',
        '107.178.192.0/18', '130.211.0.0/16', '146.148.0.0/17'
    ],
    'Fastly': [
        '23.185.0.0/16', '23.192.0.0/11', '104.156.64.0/18', '104.156.128.0/18',
        '146.75.0.0/17', '151.101.0.0/16', '157.52.64.0/18', '167.82.0.0/17',
        '167.82.128.0/20', '167.82.160.0/20', '167.82.224.0/20', '172.111.128.0/18',
        '185.31.16.0/22', '199.27.72.0/21', '199.232.0.0/16'
    ],
    'Akamai': [
        '23.0.0.0/12', '23.32.0.0/11', '23.64.0.0/14', '23.72.0.0/13',
        '72.246.0.0/16', '72.247.0.0/16', '88.221.0.0/16', '92.122.0.0/15',
        '96.6.0.0/15', '96.16.0.0/15', '104.64.0.0/10', '107.178.0.0/16',
        '184.24.0.0/13', '184.50.0.0/15', '23.192.0.0/11'
    ],
    'StackPath': [
        '151.139.0.0/16', '209.182.192.0/18', '64.125.64.0/18', '64.78.144.0/20',
        '67.228.0.0/16', '69.164.192.0/19', '74.207.224.0/19', '96.126.96.0/19',
        '108.59.0.0/16', '198.58.96.0/19', '208.93.192.0/21'
    ],
    'KeyCDN': [
        '79.127.216.0/21', '178.255.152.0/21', '185.172.148.0/22', '37.186.192.0/21',
        '185.42.144.0/22', '193.105.60.0/22', '194.242.12.0/22'
    ],
    'CDN77': [
        '37.235.32.0/21', '89.187.168.0/21', '185.93.208.0/20', '195.47.192.0/19',
        '2a02:6b8::/32'
    ],
    'Sucuri': [
        '192.88.134.0/23', '192.88.136.0/23', '208.109.0.0/16', '192.124.249.0/24'
    ]
}

BOT_USER_AGENTS: List[str] = [
    'googlebot', 'bingbot', 'slurp', 'duckduckbot', 'baiduspider', 'yandexbot',
    'sogou', 'exabot', 'facebot', 'facebookexternalhit', 'ia_archiver',
    'twitterbot', 'linkedinbot', 'pinterest', 'applebot', 'semrushbot',
    'ahrefsbot', 'mj12bot', 'dotbot', 'pingdom', 'uptimerobot', 'statuscake'
]


def ip_in_network(ip: str, network: str) -> bool:
    """
    Check if an IP address is within a CIDR network range.
    
    Args:
        ip: IP address to check
        network: CIDR notation network (e.g., '192.168.0.0/16')
        
    Returns:
        True if IP is in network, False otherwise
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        network_obj = ipaddress.ip_network(network, strict=False)
        return ip_obj in network_obj
    except (ValueError, TypeError):
        return False


def detect_cdn(ip: str) -> Optional[str]:
    """
    Detect if an IP belongs to a known CDN provider.
    
    Args:
        ip: IP address to check
        
    Returns:
        CDN provider name or None if not detected
    """
    for cdn_name, networks in CDN_IP_RANGES.items():
        for network in networks:
            if ip_in_network(ip, network):
                return cdn_name
    return None


def detect_bot(user_agent: str) -> bool:
    """
    Check if a user agent string belongs to a known bot/crawler.
    
    Args:
        user_agent: User agent string
        
    Returns:
        True if detected as bot, False otherwise
    """
    if not user_agent or user_agent == '-':
        return False
    ua_lower = user_agent.lower()
    return any(bot in ua_lower for bot in BOT_USER_AGENTS)


def build_whitelist_networks(whitelist_ips: List[str]) -> Set[str]:
    """
    Build a set of networks from IP whitelist for efficient lookup.
    
    Args:
        whitelist_ips: List of IP addresses or CIDR ranges
        
    Returns:
        Set of normalized IP addresses/ranges
    """
    networks = set()
    for item in whitelist_ips:
        item = item.strip()
        if not item:
            continue
        if '/' in item:
            networks.add(item)
        else:
            networks.add(f"{item}/32")
    return networks


def is_ip_whitelisted(ip: str, whitelist_networks: Set[str]) -> bool:
    """
    Check if an IP is in the whitelist.
    
    Args:
        ip: IP address to check
        whitelist_networks: Set of CIDR networks
        
    Returns:
        True if whitelisted, False otherwise
    """
    for network in whitelist_networks:
        if ip_in_network(ip, network):
            return True
    return False


def get_ip_reputation(ip: str, df: pd.DataFrame) -> Dict:
    """
    Analyze IP reputation based on behavior patterns.
    
    Args:
        ip: IP address to analyze
        df: DataFrame with log data
        
    Returns:
        Dictionary with reputation indicators
    """
    ip_data = df[df['ip'] == ip]
    
    if ip_data.empty:
        return {'reputation': 'Unknown', 'indicators': []}
    
    indicators = []
    reputation_score = 0
    
    cdn_name = detect_cdn(ip)
    if cdn_name:
        indicators.append(f"CDN: {cdn_name}")
        reputation_score -= 50
    
    unique_uas = ip_data['user_agent'].nunique()
    if unique_uas > 5:
        indicators.append(f"Multiple user agents ({unique_uas})")
        reputation_score += 15
    
    error_4xx = (ip_data['status'].astype(int) // 100 == 4).sum()
    total_requests = len(ip_data)
    if total_requests > 0 and error_4xx / total_requests > 0.5:
        indicators.append(f"High 4xx ratio ({error_4xx}/{total_requests})")
        reputation_score += 20
    
    requests_per_second = total_requests
    if 'timestamp' in ip_data.columns:
        time_span = (ip_data['timestamp'].max() - ip_data['timestamp'].min()).total_seconds()
        if time_span > 0:
            requests_per_second = total_requests / time_span
    
    if requests_per_second > 10:
        indicators.append(f"High request rate ({requests_per_second:.1f}/s)")
        reputation_score += 25
    
    if total_requests > 1000:
        indicators.append(f"High volume ({total_requests} requests)")
        reputation_score += 10
    
    first_ua = ip_data['user_agent'].iloc[0] if not ip_data.empty else ''
    if detect_bot(first_ua):
        indicators.append("Known bot/crawler")
        reputation_score -= 30
    
    if reputation_score >= 50:
        reputation = 'Suspicious'
    elif reputation_score >= 25:
        reputation = 'Questionable'
    elif reputation_score <= -30:
        reputation = 'Trusted'
    else:
        reputation = 'Neutral'
    
    return {
        'reputation': reputation,
        'score': reputation_score,
        'indicators': indicators,
        'cdn': cdn_name
    }

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


@st.cache_data(show_spinner=False)
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
        logger.warning("No records parsed from log file")
        return pd.DataFrame(), failed_count
    
    df = pd.DataFrame(parsed_records)
    
    if 'timestamp' in df.columns and df['timestamp'].notna().any():
        df = df.sort_values('timestamp').reset_index(drop=True)
    
    logger.info(f"Successfully parsed {len(df)} log records, {failed_count} failed")
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

@st.cache_data(show_spinner=False)
def detect_anomalies(
    features_df: pd.DataFrame, 
    contamination: float = ANOMALY_CONTAMINATION,
    whitelist_networks: tuple = (),
    skip_cdn_ips: bool = True
) -> pd.DataFrame:
    """
    Detect anomalous IPs using Isolation Forest algorithm.
    
    Args:
        features_df: DataFrame with extracted features
        contamination: Expected proportion of anomalies in dataset
        whitelist_networks: Tuple of CIDR networks to exclude from detection
        skip_cdn_ips: Whether to exclude known CDN IPs from anomalies
        
    Returns:
        DataFrame with anomaly scores and predictions
    """
    if features_df.empty or len(features_df) < 2:
        return features_df.assign(anomaly_score=0, is_anomaly=False, threat_level='Normal', is_cdn=False, is_whitelisted=False)
    
    whitelist_set = set(whitelist_networks) if whitelist_networks else set()
    
    features_df['is_cdn'] = features_df['ip'].apply(lambda x: detect_cdn(x) is not None)
    features_df['is_whitelisted'] = features_df['ip'].apply(lambda x: is_ip_whitelisted(x, whitelist_set))
    
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
    
    if skip_cdn_ips:
        result_df.loc[result_df['is_cdn'], 'is_anomaly'] = False
    if whitelist_set:
        result_df.loc[result_df['is_whitelisted'], 'is_anomaly'] = False
    
    risk_scores = result_df[result_df['is_anomaly']]['anomaly_score'].quantile([0.75, 0.9]) if result_df['is_anomaly'].any() else [0, 0]
    
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


def render_anomaly_alerts(anomaly_df: pd.DataFrame, df: pd.DataFrame):
    """
    Render anomaly detection results and alerts.
    
    Args:
        anomaly_df: DataFrame with anomaly detection results
        df: Original DataFrame with log data for reputation analysis
    """
    st.subheader("🚨 Anomaly Detection Alerts")
    
    if anomaly_df.empty:
        st.info("No data available for anomaly detection.")
        return
    
    cdn_count = anomaly_df['is_cdn'].sum() if 'is_cdn' in anomaly_df.columns else 0
    whitelisted_count = anomaly_df['is_whitelisted'].sum() if 'is_whitelisted' in anomaly_df.columns else 0
    
    col_info1, col_info2 = st.columns(2)
    with col_info1:
        if cdn_count > 0:
            st.info(f"ℹ️ {cdn_count} IPs detected as known CDN (excluded from anomalies)")
    with col_info2:
        if whitelisted_count > 0:
            st.info(f"ℹ️ {whitelisted_count} IPs in whitelist (excluded from anomalies)")
    
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


def render_ip_reputation(anomaly_df: pd.DataFrame, df: pd.DataFrame, top_n: int = 20):
    """
    Render IP reputation analysis section.
    
    Args:
        anomaly_df: DataFrame with anomaly detection results
        df: Original DataFrame with log data
        top_n: Number of top IPs to display
    """
    st.subheader("🔍 IP Reputation Analysis")
    
    if anomaly_df.empty:
        st.info("No data available for reputation analysis.")
        return
    
    ip_reputation_data = []
    
    for _, row in anomaly_df.head(top_n).iterrows():
        ip = row['ip']
        reputation = get_ip_reputation(ip, df)
        ip_reputation_data.append({
            'IP': ip,
            'Reputation': reputation['reputation'],
            'CDN': reputation['cdn'] or '-',
            'Request Count': row.get('request_count', 0),
            'Score': reputation.get('score', 0),
            'Indicators': ', '.join(reputation['indicators'][:3]) if reputation['indicators'] else '-'
        })
    
    if ip_reputation_data:
        reputation_df = pd.DataFrame(ip_reputation_data)
        
        def color_reputation(val):
            if val == 'Trusted':
                return 'background-color: #d4edda'
            elif val == 'Suspicious':
                return 'background-color: #f8d7da'
            elif val == 'Questionable':
                return 'background-color: #fff3cd'
            return ''
        
        styled_df = reputation_df.style.applymap(
            color_reputation, 
            subset=['Reputation']
        )
        
        st.dataframe(styled_df, use_container_width=True)
    else:
        st.info("No IP reputation data available.")


def render_cdn_summary(anomaly_df: pd.DataFrame):
    """
    Render summary of detected CDN IPs.
    
    Args:
        anomaly_df: DataFrame with anomaly detection results
    """
    st.subheader("📡 Detected CDN & Trusted IPs")
    
    if anomaly_df.empty or 'is_cdn' not in anomaly_df.columns:
        st.info("No CDN detection data available.")
        return
    
    cdn_ips = anomaly_df[anomaly_df['is_cdn'] == True]
    
    if cdn_ips.empty:
        st.info("No CDN IPs detected in the log data.")
        return
    
    cdn_summary = []
    for _, row in cdn_ips.iterrows():
        cdn_name = detect_cdn(row['ip'])
        cdn_summary.append({
            'IP': row['ip'],
            'CDN Provider': cdn_name or 'Unknown',
            'Request Count': row.get('request_count', 0),
            'Unique URLs': row.get('unique_urls', 0)
        })
    
    cdn_df = pd.DataFrame(cdn_summary)
    cdn_grouped = cdn_df.groupby('CDN Provider').agg({
        'IP': 'count',
        'Request Count': 'sum'
    }).reset_index()
    cdn_grouped.columns = ['CDN Provider', 'IP Count', 'Total Requests']
    cdn_grouped = cdn_grouped.sort_values('Total Requests', ascending=False)
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("**CDN Summary**")
        st.dataframe(cdn_grouped, use_container_width=True)
    
    with col2:
        st.markdown("**CDN IPs Detail**")
        st.dataframe(
            cdn_df.sort_values('Request Count', ascending=False).head(10),
            use_container_width=True
        )


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
    
    render_anomaly_alerts(anomaly_df, df)
    
    st.divider()
    
    render_cdn_summary(anomaly_df)
    
    st.divider()
    
    render_ip_reputation(anomaly_df, df)
    
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
        
        st.header("🛡️ Whitelist & CDN")
        
        skip_cdn = st.checkbox(
            "Exclude Known CDN IPs", 
            value=True,
            help="Automatically exclude IPs from known CDN providers (Cloudflare, Bunny, AWS, etc.)"
        )
        
        st.markdown("**IP Whitelist**")
        whitelist_text = st.text_area(
            "Enter IPs to exclude (one per line)",
            height=100,
            placeholder="192.168.1.1\n10.0.0.0/8\n172.16.0.0/12",
            help="Enter IP addresses or CIDR ranges to exclude from anomaly detection"
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
        
        st.markdown("**Filter by File Extension**")
        common_extensions = ['.php', '.html', '.htm', '.js', '.css', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.json', '.xml', '.txt', '.pdf', '.zip']
        extension_filter = st.multiselect(
            "Select Extensions",
            options=['All'] + common_extensions,
            default=['All'],
            help="Filter log entries by URL file extension"
        )
        
        url_filter_mode = st.radio(
            "URL Filter Mode",
            options=['All URLs', 'Include', 'Exclude'],
            index=0,
            horizontal=True,
            help="Include: show only matching URLs. Exclude: hide matching URLs."
        )
        url_filter_text = st.text_area(
            "URL Keywords (one per line)",
            height=80,
            placeholder="/admin\n/wp-login.php\n/api/",
            help="Enter URL keywords to filter"
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
    
    if extension_filter and 'All' not in extension_filter:
        def has_extension(url):
            if not url:
                return False
            url_lower = url.lower().split('?')[0].split('#')[0]
            return any(url_lower.endswith(ext) for ext in extension_filter)
        df = df[df['url'].apply(has_extension)]
    
    if url_filter_text and url_filter_mode != 'All URLs':
        url_keywords = [kw.strip() for kw in url_filter_text.strip().split('\n') if kw.strip()]
        if url_keywords:
            def url_matches(url):
                if not url:
                    return False
                return any(kw.lower() in url.lower() for kw in url_keywords)
            
            if url_filter_mode == 'Include':
                df = df[df['url'].apply(url_matches)]
            elif url_filter_mode == 'Exclude':
                df = df[~df['url'].apply(url_matches)]
    
    if date_filter and date_range and len(date_range) == 2:
        start_date = pd.Timestamp(date_range[0])
        end_date = pd.Timestamp(date_range[1]) + pd.Timedelta(days=1)
        df = df[(df['timestamp'] >= start_date) & (df['timestamp'] < end_date)]
    
    whitelist_ips = []
    if whitelist_text:
        whitelist_ips = [ip.strip() for ip in whitelist_text.strip().split('\n') if ip.strip()]
    
    whitelist_networks = tuple(build_whitelist_networks(whitelist_ips)) if whitelist_ips else ()
    
    with st.spinner("Running anomaly detection..."):
        features_df = extract_features(df)
        anomaly_df = detect_anomalies(
            features_df, 
            contamination=contamination,
            whitelist_networks=whitelist_networks,
            skip_cdn_ips=skip_cdn
        )
    
    render_dashboard(df, anomaly_df)
    
    with st.sidebar:
        st.divider()
        st.markdown("### 📥 Export Results")
        
        anomaly_rows = anomaly_df[anomaly_df['is_anomaly']]
        if not anomaly_rows.empty:
            csv = anomaly_rows.to_csv(index=False)
            st.download_button(
                label="Download Anomaly Report (CSV)",
                data=csv,
                file_name="anomaly_report.csv",
                mime="text/csv"
            )
        else:
            st.info("No anomalies to export")


if __name__ == "__main__":
    main()