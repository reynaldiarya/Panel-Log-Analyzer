import os

from dotenv import load_dotenv

from config.constants import ANOMALY_CONTAMINATION, RANDOM_STATE

# Load environment variables from .env file if it exists
load_dotenv()


class Settings:
    def __init__(self):
        # Environment variable configurations
        self.anomaly_contamination = float(
            os.getenv("SLA_ANOMALY_CONTAMINATION", ANOMALY_CONTAMINATION)
        )

        self.random_state = int(os.getenv("SLA_RANDOM_STATE", RANDOM_STATE))

        self.log_level = os.getenv("SLA_LOG_LEVEL", "INFO")


def get_settings() -> Settings:
    return Settings()
