import logging
from datetime import datetime
from typing import Optional, Tuple
import pandas as pd
import streamlit as st
from config.constants import LOG_PATTERN


logger = logging.getLogger(__name__)


def parse_log_line(line: str) -> Optional[dict]:
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None

    data = match.groupdict()

    try:
        timestamp_str = data["timestamp"]
        data["timestamp"] = datetime.strptime(
            timestamp_str.split()[0], "%d/%b/%Y:%H:%M:%S"
        )
    except (ValueError, IndexError):
        data["timestamp"] = None

    data["status"] = int(data["status"]) if data["status"].isdigit() else 0
    data["size"] = int(data["size"]) if data["size"].isdigit() else 0

    return data


@st.cache_data(show_spinner=False)
def parse_log_file(file_content: bytes) -> Tuple[pd.DataFrame, int]:
    try:
        text = file_content.decode("utf-8", errors="replace")
    except Exception:
        text = file_content.decode("latin-1", errors="replace")

    lines = text.strip().split("\n")
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

    if "timestamp" in df.columns and df["timestamp"].notna().any():
        df = df.sort_values("timestamp").reset_index(drop=True)

    logger.info(f"Successfully parsed {len(df)} log records, {failed_count} failed")
    return df, failed_count


def validate_log_format(df: pd.DataFrame) -> bool:
    required_columns = {"ip", "timestamp", "method", "url", "status", "user_agent"}
    return not df.empty and required_columns.issubset(df.columns)
