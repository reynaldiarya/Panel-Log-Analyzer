import os
from typing import Optional
from pathlib import Path

import yaml

from config.constants import ANOMALY_CONTAMINATION, RANDOM_STATE


class Settings:
    def __init__(self, config_path: Optional[str] = None):
        self._config = {}
        
        if config_path and Path(config_path).exists():
            with open(config_path, 'r') as f:
                self._config = yaml.safe_load(f) or {}
        
        # Environment variable overrides
        self.anomaly_contamination = float(
            os.getenv('SLA_ANOMALY_CONTAMINATION') or 
            self._config.get('anomaly', {}).get('contamination') or 
            ANOMALY_CONTAMINATION
        )
        
        self.random_state = int(
            os.getenv('SLA_RANDOM_STATE') or 
            self._config.get('anomaly', {}).get('random_state') or 
            RANDOM_STATE
        )
        
        self.log_level = (
            os.getenv('SLA_LOG_LEVEL') or 
            self._config.get('log', {}).get('level') or 
            'INFO'
        )


def get_settings(config_path: Optional[str] = 'config.yaml') -> Settings:
    return Settings(config_path)
