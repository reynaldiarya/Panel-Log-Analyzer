import logging
import pandas as pd
import streamlit as st

from config import get_settings
from src.analysis import build_whitelist_networks, detect_cdn, is_ip_whitelisted
from src import (
    parse_log_file,
    validate_log_format,
    extract_features,
    detect_anomalies,
    render_dashboard,
)

settings = get_settings()


logging.basicConfig(level=settings.log_level.upper())
logger = logging.getLogger(__name__)


def main():
    st.set_page_config(
        page_title="Security Log Analytics",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    with st.sidebar:
        st.header("📁 Log File Upload")
        uploaded_file = st.file_uploader(
            "Upload access.log file",
            type=["log", "txt"],
            help="Upload Apache/Nginx access log file in Combined Log Format",
        )

        st.divider()

        st.header("⚙️ ML Settings")
        contamination = st.slider(
            "Anomaly Sensitivity",
            min_value=0.01,
            max_value=0.20,
            value=settings.anomaly_contamination,
            step=0.01,
            help="Higher values detect more anomalies but may increase false positives",
        )

        st.divider()

        st.header("🛡️ Whitelist & CDN")

        skip_cdn = st.checkbox(
            "Exclude Known CDN IPs",
            value=True,
            help="Automatically exclude IPs from known CDN providers (Cloudflare, Bunny, AWS, etc.)",
        )

        st.markdown("**IP Whitelist**")
        whitelist_text = st.text_area(
            "Enter IPs to exclude (one per line)",
            height=100,
            placeholder="192.168.1.1\n10.0.0.0/8\n172.16.0.0/12",
            help="Enter IP addresses or CIDR ranges to exclude from anomaly detection",
        )

        st.divider()

        st.header("📊 Filters")

        date_filter = st.checkbox("Enable Date Filter", value=False)
        date_range = None
        if date_filter:
            date_range = st.date_input("Select Date Range", [])

        status_filter = st.multiselect(
            "Filter by Status Code",
            options=["2xx", "3xx", "4xx", "5xx"],
            default=["2xx", "3xx", "4xx", "5xx"],
        )

        st.markdown("**Filter by File Extension**")
        common_extensions = [
            ".php",
            ".html",
            ".htm",
            ".js",
            ".css",
            ".jpg",
            ".jpeg",
            ".png",
            ".gif",
            ".svg",
            ".json",
            ".xml",
            ".txt",
            ".pdf",
            ".zip",
        ]
        extension_filter = st.multiselect(
            "Select Extensions",
            options=["All"] + common_extensions,
            default=["All"],
            help="Filter log entries by URL file extension",
        )

        url_filter_mode = st.radio(
            "URL Filter Mode",
            options=["All URLs", "Include", "Exclude"],
            index=0,
            horizontal=True,
            help="Include: show only matching URLs. Exclude: hide matching URLs.",
        )
        url_filter_text = st.text_area(
            "URL Keywords (one per line)",
            height=80,
            placeholder="/admin\n/wp-login.php\n/api/",
            help="Enter URL keywords to filter",
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

        df = df[df["status"].apply(status_in_filter)]

    if extension_filter and "All" not in extension_filter:

        def has_extension(url):
            if not url:
                return False
            url_lower = url.lower().split("?")[0].split("#")[0]
            return any(url_lower.endswith(ext) for ext in extension_filter)

        df = df[df["url"].apply(has_extension)]

    if url_filter_text and url_filter_mode != "All URLs":
        url_keywords = [
            kw.strip() for kw in url_filter_text.strip().split("\n") if kw.strip()
        ]
        if url_keywords:

            def url_matches(url):
                if not url:
                    return False
                return any(kw.lower() in url.lower() for kw in url_keywords)

            if url_filter_mode == "Include":
                df = df[df["url"].apply(url_matches)]
            elif url_filter_mode == "Exclude":
                df = df[~df["url"].apply(url_matches)]

    if date_filter and date_range and len(date_range) == 2:
        start_date = pd.Timestamp(date_range[0])
        end_date = pd.Timestamp(date_range[1]) + pd.Timedelta(days=1)
        df = df[(df["timestamp"] >= start_date) & (df["timestamp"] < end_date)]

    whitelist_ips = []
    if whitelist_text:
        whitelist_ips = [
            ip.strip() for ip in whitelist_text.strip().split("\n") if ip.strip()
        ]

    whitelist_networks = (
        tuple(build_whitelist_networks(whitelist_ips)) if whitelist_ips else ()
    )

    # Filter out CDN IPs from all analysis if enabled
    if skip_cdn:
        df = df[df["ip"].apply(lambda x: detect_cdn(x) is None)]

    # Filter out whitelisted IPs from all analysis if provided
    if whitelist_ips:
        whitelist_set = build_whitelist_networks(whitelist_ips)
        df = df[~df["ip"].apply(lambda x: is_ip_whitelisted(x, whitelist_set))]

    with st.spinner("Running anomaly detection..."):
        features_df = extract_features(df)
        anomaly_df = detect_anomalies(
            features_df,
            contamination=contamination,
            random_state=settings.random_state,
            whitelist_networks=whitelist_networks,
            skip_cdn_ips=skip_cdn,
        )

    render_dashboard(df, anomaly_df)

    with st.sidebar:
        st.divider()
        st.markdown("### 📥 Export Results")

        anomaly_rows = anomaly_df[anomaly_df["is_anomaly"]]
        if not anomaly_rows.empty:
            csv = anomaly_rows.to_csv(index=False)
            st.download_button(
                label="Download Anomaly Report (CSV)",
                data=csv,
                file_name="anomaly_report.csv",
                mime="text/csv",
            )
        else:
            st.info("No anomalies to export")


if __name__ == "__main__":
    main()
