import os
import configparser
import logging
class ConfigurationManager:
    """
    設定を管理するクラスです。
    設定ファイルが存在しない場合はデフォルト設定で新しいファイルを作成します。
    """
    DEFAULT_CONFIG = {
        "kex": {
            "KEX_ALG": "Kyber1024",
            "EPHEMERAL_KEY_LIFETIME": "3600"
        },
        "signature": {
            "SIG_ALG": "Dilithium3",
            "SIG_VERIFY_TIMEOUT": "5"
        },
        "noise": {
            "NOISE_PROTOCOL": "ChaCha20_Poly1305"
        },
        "security": {
            "KEY_ROTATION_INTERVAL": "10",
            "KEY_ROTATION_TIME": "360",
            "MAX_KEY_CHAIN_LENGTH": "3",
            "MAX_MESSAGE_SIZE": "1024",
            "TIMESTAMP_WINDOW": "30",
            "MAX_FAILED_ATTEMPTS": "5",
            "RATE_LIMIT_WINDOW": "30",
            "REPLAY_WINDOW_SIZE": "64",
            "MESSAGE_MAX_AGE": "360",
            "KEY_SIZE": "32"
        },
        "timeouts": {
            "HANDSHAKE_TIMEOUT": "30",
            "CONNECTION_TIMEOUT": "30",
            "CLEANUP_INTERVAL": "30"
        },
        "keys": {
            "KEY_ROTATION_CHECK_INTERVAL": "60"
        },
        "performance": {
            "NONCE_CACHE_SIZE": "1024"
        }
    }
    
    def __init__(self, config_file: str = "config.ini"):
        self.config_file = config_file
        self.config = configparser.ConfigParser()
        self._load_configuration()

    def _load_configuration(self):
        if os.path.exists(self.config_file):
            self.config.read(self.config_file)
        else:
            logging.warning(f"Configuration file {self.config_file} not found. Using default settings.")
            self._generate_default_config()

        for section, options in self.DEFAULT_CONFIG.items():
            if not self.config.has_section(section):
                self.config.add_section(section)
            for option, value in options.items():
                if not self.config.has_option(section, option):
                    self.config.set(section, option, value)

        self._validate_configuration()
        self._save_configuration()

    def _generate_default_config(self):
        for section, options in self.DEFAULT_CONFIG.items():
            self.config[section] = options
        self._save_configuration()

    def _save_configuration(self):
        with open(self.config_file, "w") as configfile:
            self.config.write(configfile)
        logging.info(f"Configuration saved to {self.config_file}")

    def _validate_configuration(self):
        for section in ["timeouts", "security"]:
            for option in self.config.options(section):
                value = self.config.getint(section, option)
                if value <= 0:
                    raise ValueError(f"Invalid {section}.{option}: must be positive")

    def get(self, section: str, option: str, fallback=None) -> str:
        if fallback is not None:
            return self.config.get(section, option, fallback=fallback)
        return self.config.get(section, option)

    def getint(self, section: str, option: str, fallback=None) -> int:
        if fallback is not None:
            return self.config.getint(section, option, fallback=fallback)
        return self.config.getint(section, option)

    def getfloat(self, section: str, option: str, fallback=None) -> float:
        if fallback is not None:
            return self.config.getfloat(section, option, fallback=fallback)
        return self.config.getfloat(section, option)

    def getboolean(self, section: str, option: str, fallback=None) -> bool:
        if fallback is not None:
            return self.config.getboolean(section, option, fallback=fallback)
        return self.config.getboolean(section, option)
