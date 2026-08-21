"""Configuration loading from environment / .env file."""

import logging
import os

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


def _int_env(name: str, default: int, lo: int = 1, hi: int = 65535) -> int:
    raw = os.getenv(name, "")
    if not raw:
        return default
    try:
        val = int(raw)
    except ValueError:
        logger.error("Invalid value for %s=%r, using default %d", name, raw, default)
        return default
    if val < lo or val > hi:
        logger.error(
            "Value %s=%d out of range [%d, %d], using default %d",
            name, val, lo, hi, default,
        )
        return default
    return val


class Config:
    BOT_TOKEN = os.getenv("BOT_TOKEN", "")

    MT_HOST = os.getenv("MT_HOST", "")
    MT_USER = os.getenv("MT_USER", "")
    MT_PASS = os.getenv("MT_PASS", "")
    MT_PUBLIC_IP = os.getenv("MT_PUBLIC_IP", "")
    MT_VERIFY_TLS = os.getenv("MT_VERIFY_TLS", "false").lower() in ("1", "true", "yes")
    MT_USE_SSL = os.getenv("MT_USE_SSL", "false").lower() in ("1", "true", "yes")

    WG_MTU = _int_env("WG_MTU", 1420, 1280, 1420)
    WG_DNS = os.getenv("WG_DNS", "1.1.1.1,8.8.8.8")
    WG_LISTEN_PORT = _int_env("WG_LISTEN_PORT", 51820, 1, 65535)
    WG_CLIENT_LISTEN_PORT = _int_env("WG_CLIENT_LISTEN_PORT", 51820, 1, 65535)
    WG_SUBNET_PREFIX = os.getenv("WG_SUBNET_PREFIX", "10.200")
    WG_PERSISTENT_KEEPALIVE = _int_env("WG_PERSISTENT_KEEPALIVE", 15, 0, 3600)

    DB_PATH = os.getenv("DB_PATH", "bot.db")
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

    @classmethod
    def validate(cls) -> list[str]:
        """Required settings. Router settings are optional at startup."""
        missing = [name for name, val in [("BOT_TOKEN", cls.BOT_TOKEN)] if not val]
        return missing

    @classmethod
    def mt_ready(cls) -> bool:
        return all(
            [cls.MT_HOST, cls.MT_USER, cls.MT_PASS, cls.MT_PUBLIC_IP]
        )
