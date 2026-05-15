import pandas as pd
import plotly.express as px
import streamlit as st
from src.analysis.reputation import get_ip_reputation, detect_cdn


def render_metrics(df: pd.DataFrame):
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(label="Total Requests", value=f"{len(df):,}", delta=None)
    
    with col2:
        unique_ips = df['ip'].nunique() if not df.empty else 0
        st.metric(label="Unique IPs", value=f"{unique_ips:,}", delta=None)
    
    with col3:
        error_404 = (df['status'] == 404).sum() if not df.empty else 0
        st.metric(label="404 Errors", value=f"{error_404:,}", delta=None)
    
    with col4:
        error_5xx = df['status'].apply(lambda x: 500 <= int(x) < 600).sum() if not df.empty else 0
        st.metric(label="5xx Errors", value=f"{error_5xx:,}", delta=None)


def render_traffic_chart(df: pd.DataFrame):
    if df.empty or 'timestamp' not in df.columns:
        st.info("No timestamp data available for traffic chart.")
        return
    
    df_time = df.dropna(subset=['timestamp']).copy()
    
    if df_time.empty:
        st.info("No valid timestamp data for visualization.")
        return
    
    df_time['time_bucket'] = df_time['timestamp'].dt.floor('h')
    time_series = df_time.groupby('time_bucket').size().reset_index(name='requests')
    
    fig = px.line(
        time_series, x='time_bucket', y='requests',
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
        status_counts, values='Count', names='Category',
        title='HTTP Status Code Distribution', hole=0.4
    )
    
    fig.update_layout(height=350)
    st.plotly_chart(fig, use_container_width=True)


def render_top_ips(df: pd.DataFrame, top_n: int = 10):
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
            ip_stats.head(10), x='request_count', y='ip', orientation='h',
            title=f'Top {min(10, len(ip_stats))} IPs by Request Count',
            labels={'request_count': 'Requests', 'ip': 'IP Address'},
            color='request_count', color_continuous_scale='Blues'
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
            use_container_width=True, height=350
        )


def render_method_distribution(df: pd.DataFrame):
    if df.empty:
        return
    
    method_counts = df['method'].value_counts().reset_index()
    method_counts.columns = ['Method', 'Count']
    
    fig = px.bar(
        method_counts, x='Method', y='Count',
        title='HTTP Methods Distribution',
        color='Count', color_continuous_scale='Viridis'
    )
    
    fig.update_layout(height=300)
    st.plotly_chart(fig, use_container_width=True)


def render_anomaly_alerts(anomaly_df: pd.DataFrame, df: pd.DataFrame):
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
    
    anomalies = anomaly_df[anomaly_df['is_anomaly']].copy()
    
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
        anomaly_df, x='anomaly_score', color='is_anomaly',
        title='Distribution of Anomaly Scores',
        labels={'anomaly_score': 'Anomaly Score', 'is_anomaly': 'Is Anomaly'},
        nbins=50
    )
    fig.update_layout(height=350)
    st.plotly_chart(fig, use_container_width=True)


def render_ip_reputation(anomaly_df: pd.DataFrame, df: pd.DataFrame, top_n: int = 20):
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
                return 'background-color: #d1fae5; color: #065f46'
            elif val == 'Suspicious':
                return 'background-color: #fee2e2; color: #991b1b'
            elif val == 'Questionable':
                return 'background-color: #fef3c7; color: #92400e'
            elif val == 'Neutral':
                return 'background-color: #f3f4f6; color: #374151'
            return ''
        
        styled_df = reputation_df.style.map(color_reputation, subset=['Reputation'])
        st.dataframe(styled_df, use_container_width=True)
    else:
        st.info("No IP reputation data available.")


def render_cdn_summary(anomaly_df: pd.DataFrame):
    st.subheader("📡 Detected CDN & Trusted IPs")
    
    if anomaly_df.empty or 'is_cdn' not in anomaly_df.columns:
        st.info("No CDN detection data available.")
        return
    
    cdn_ips = anomaly_df[anomaly_df['is_cdn']]
    
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
