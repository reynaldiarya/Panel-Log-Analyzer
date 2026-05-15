import pandas as pd


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
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
