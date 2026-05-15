import pandas as pd
import streamlit as st
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from typing import Tuple

from config.constants import ANOMALY_CONTAMINATION, RANDOM_STATE
from src.analysis.reputation import detect_cdn, is_ip_whitelisted


@st.cache_data(show_spinner=False)
def detect_anomalies(
    features_df: pd.DataFrame, 
    contamination: float = ANOMALY_CONTAMINATION,
    whitelist_networks: tuple = (),
    skip_cdn_ips: bool = True
) -> pd.DataFrame:
    if features_df.empty or len(features_df) < 2:
        return features_df.assign(
            anomaly_score=0, 
            is_anomaly=False, 
            threat_level='Normal', 
            is_cdn=False, 
            is_whitelisted=False
        )
    
    whitelist_set = set(whitelist_networks) if whitelist_networks else set()
    
    features_df['is_cdn'] = features_df['ip'].apply(lambda x: detect_cdn(x) is not None)
    features_df['is_whitelisted'] = features_df['ip'].apply(
        lambda x: is_ip_whitelisted(x, whitelist_set)
    )
    
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
    
    risk_scores = (
        result_df[result_df['is_anomaly']]['anomaly_score'].quantile([0.75, 0.9]) 
        if result_df['is_anomaly'].any() else [0, 0]
    )
    
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
