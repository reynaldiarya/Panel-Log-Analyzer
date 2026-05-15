import ipaddress
import pandas as pd
from typing import Dict, List, Optional, Set, Tuple

from config.constants import CDN_IP_RANGES, BOT_USER_AGENTS


def ip_in_network(ip: str, network: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        network_obj = ipaddress.ip_network(network, strict=False)
        return ip_obj in network_obj
    except (ValueError, TypeError):
        return False


def detect_cdn(ip: str) -> Optional[str]:
    for cdn_name, networks in CDN_IP_RANGES.items():
        for network in networks:
            if ip_in_network(ip, network):
                return cdn_name
    return None


def detect_bot(user_agent: str) -> bool:
    if not user_agent or user_agent == '-':
        return False
    ua_lower = user_agent.lower()
    return any(bot in ua_lower for bot in BOT_USER_AGENTS)


def build_whitelist_networks(whitelist_ips: List[str]) -> Set[str]:
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
    for network in whitelist_networks:
        if ip_in_network(ip, network):
            return True
    return False


def get_ip_reputation(ip: str, df: pd.DataFrame) -> Dict:
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
