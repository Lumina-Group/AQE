import os
import configparser
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ConfigurationManager:
    """
    設定を管理するクラスです。
    設定ファイルが存在しない場合はデフォルト設定で新しいファイルを作成します。
    """
    DEFAULT_CONFIG = {
        "kex": {
            "KEX_ALG": "Kyber1024",
            "DERIVED_KEY_SIZE": "32"
        },
        "signature": {
            "SIG_ALG": "Dilithium3"
        },
        "noise": {
            "NOISE_PROTOCOL": "ChaCha20_Poly1305"
        },
        "security": {
            "MAX_MESSAGE_SIZE": "65536",
            "TIMESTAMP_WINDOW": "60",
            "MAX_FAILED_ATTEMPTS": "5",
            "RATE_LIMIT_WINDOW": "300",
            "SEQUENCE_WINDOW_SIZE": "1024",
            "MESSAGE_MAX_AGE": "300",
            "KEY_SIZE": "32",
            "NONCE_CACHE_SIZE": "1000"
        },
        "timeouts": {
            "HANDSHAKE_TIMEOUT": "30",
            "CONNECTION_TIMEOUT": "300",
            "CLEANUP_INTERVAL": "300"
        }
    }

    def __init__(self, config_file: str = "config.ini"):
        """
        ConfigurationManagerを初期化します。

        Args:
            config_file (str): 設定ファイルへのパス。デフォルトは "config.ini"。
        """
        self.config_file = config_file
        self.config = configparser.ConfigParser(interpolation=None)
        self._load_configuration()

    def _load_configuration(self):
        """設定ファイルを読み込み、存在しない場合はデフォルト設定で作成・保存します。"""
        if os.path.exists(self.config_file):
            try:
                self.config.read(self.config_file)
                logging.info(f"Configuration loaded from {self.config_file}")
            except configparser.Error as e:
                 logging.error(f"Error reading configuration file {self.config_file}: {e}. Using defaults.")
                 self.config = configparser.ConfigParser(interpolation=None)
                 self._apply_defaults_and_save()
        else:
            logging.warning(f"Configuration file {self.config_file} not found. Creating with default settings.")
            self._apply_defaults_and_save()

        needs_save = False
        for section, options in self.DEFAULT_CONFIG.items():
            if not self.config.has_section(section):
                self.config.add_section(section)
                needs_save = True
                logging.info(f"Added default section '{section}' to configuration.")
            for option, value in options.items():
                if not self.config.has_option(section, option):
                    self.config.set(section, option, value)
                    needs_save = True
                    logging.info(f"Added default option '{section}.{option}' = '{value}' to configuration.")

        try:
            self._validate_configuration()
        except ValueError as e:
             logging.error(f"Configuration validation failed: {e}. Check your config file: {self.config_file}")
             raise

        if needs_save:
            self._save_configuration()

    def _apply_defaults_and_save(self):
         """デフォルト設定を適用し、ファイルに保存します。"""
         for section, options in self.DEFAULT_CONFIG.items():
             if not self.config.has_section(section):
                 self.config.add_section(section)
             for option, value in options.items():
                 self.config.set(section, option, value)
         self._save_configuration()

    def _save_configuration(self):
        """現在の設定をファイルに書き込みます。"""
        try:
            with open(self.config_file, "w") as configfile:
                self.config.write(configfile)
            logging.info(f"Configuration saved to {self.config_file}")
        except IOError as e:
            logging.error(f"Could not write configuration file {self.config_file}: {e}")

    def _validate_configuration(self):
        """設定値の基本的な検証を行います（例：数値が正であるか）。"""
        for section in self.config.sections():
            if section in ["timeouts", "security", "kex"]:
                 for option in self.config.options(section):
                     try:
                         value = self.config.getint(section, option)
                         if value <= 0:
                              raise ValueError(f"Invalid value for {section}.{option}: '{self.config.get(section,option)}'. Must be a positive integer.")
                     except ValueError:
                         pass
                     except configparser.NoOptionError:
                          logging.warning(f"Option {section}.{option} not found during validation.")
                          pass

        if not self.get("kex", "KEX_ALG"):
             raise ValueError("kex.KEX_ALG must not be empty.")
        if not self.get("signature", "SIG_ALG"):
             raise ValueError("signature.SIG_ALG must not be empty.")
        if not self.get("noise", "NOISE_PROTOCOL"):
             raise ValueError("noise.NOISE_PROTOCOL must not be empty.")

    def get(self, section: str, option: str, fallback: str = None) -> str:
        """
        指定されたセクションとオプションの設定値を取得します（文字列）。

        Args:
            section (str): 設定のセクション名。
            option (str): 設定のオプション名。
            fallback (str, optional): 値が見つからない場合のデフォルト値。

        Returns:
            str: 設定値。見つからない場合は fallback 値または None。

        Raises:
            configparser.NoSectionError: セクションが存在しない場合（fallback指定なし）。
            configparser.NoOptionError: オプションが存在しない場合（fallback指定なし）。
        """
        try:
            if fallback is not None:
                return self.config.get(section, option, fallback=fallback)
            else:
                return self.config.get(section, option)
        except (configparser.NoSectionError, configparser.NoOptionError) as e:
             if fallback is None:
                  logging.error(f"Configuration value not found for [{section}] {option} and no fallback provided.")
                  raise e
             logging.warning(f"Configuration value for [{section}] {option} not found, using provided fallback '{fallback}'.")
             return fallback
        except Exception as e:
             logging.error(f"Error getting configuration for [{section}] {option}: {e}")
             raise

    def getint(self, section: str, option: str, fallback: int = None) -> int:
        """
        指定されたセクションとオプションの設定値を取得します（整数）。

        Args:
            section (str): 設定のセクション名。
            option (str): 設定のオプション名。
            fallback (int, optional): 値が見つからない場合のデフォルト値。

        Returns:
            int: 設定値（整数）。見つからない/変換できない場合は fallback 値または None。

        Raises:
            ValueError: 値を整数に変換できない場合（fallback指定なし）。
            configparser.NoSectionError: セクションが存在しない場合（fallback指定なし）。
            configparser.NoOptionError: オプションが存在しない場合（fallback指定なし）。
        """
        try:
            if fallback is not None:
                value_str = self.config.get(section, option, fallback=str(fallback))
                try:
                    return int(value_str)
                except ValueError:
                     logging.warning(f"Value for [{section}] {option} ('{value_str}') is not a valid integer. Using fallback {fallback}.")
                     return fallback
            else:
                return self.config.getint(section, option)
        except (configparser.NoSectionError, configparser.NoOptionError) as e:
            if fallback is None:
                logging.error(f"Configuration integer value not found for [{section}] {option} and no fallback provided.")
                raise e
            else:
                 logging.warning(f"Configuration integer value for [{section}] {option} not found, using fallback {fallback}.")
                 return fallback
        except ValueError as e:
             if fallback is None:
                  logging.error(f"Configuration value for [{section}] {option} is not a valid integer and no fallback provided.")
                  raise e
             else:
                  logging.warning(f"Configuration value for [{section}] {option} is not a valid integer. Using fallback {fallback}.")
                  return fallback
        except Exception as e:
             logging.error(f"Error getting integer configuration for [{section}] {option}: {e}")
             raise

    def getfloat(self, section: str, option: str, fallback: float = None) -> float:
        """
        指定されたセクションとオプションの設定値を取得します（浮動小数点数）。

        Args:
            section (str): 設定のセクション名。
            option (str): 設定のオプション名。
            fallback (float, optional): 値が見つからない場合のデフォルト値。

        Returns:
            float: 設定値（浮動小数点数）。見つからない/変換できない場合は fallback 値または None。

        Raises:
            ValueError: 値をfloatに変換できない場合（fallback指定なし）。
            configparser.NoSectionError: セクションが存在しない場合（fallback指定なし）。
            configparser.NoOptionError: オプションが存在しない場合（fallback指定なし）。
        """
        try:
            if fallback is not None:
                value_str = self.config.get(section, option, fallback=str(fallback))
                try:
                    return float(value_str)
                except ValueError:
                     logging.warning(f"Value for [{section}] {option} ('{value_str}') is not a valid float. Using fallback {fallback}.")
                     return fallback
            else:
                return self.config.getfloat(section, option)
        except (configparser.NoSectionError, configparser.NoOptionError) as e:
            if fallback is None:
                logging.error(f"Configuration float value not found for [{section}] {option} and no fallback provided.")
                raise e
            else:
                 logging.warning(f"Configuration float value for [{section}] {option} not found, using fallback {fallback}.")
                 return fallback
        except ValueError as e:
             if fallback is None:
                  logging.error(f"Configuration value for [{section}] {option} is not a valid float and no fallback provided.")
                  raise e
             else:
                  logging.warning(f"Configuration value for [{section}] {option} is not a valid float. Using fallback {fallback}.")
                  return fallback
        except Exception as e:
             logging.error(f"Error getting float configuration for [{section}] {option}: {e}")
             raise

    def getboolean(self, section: str, option: str, fallback: bool = None) -> bool:
        """
        指定されたセクションとオプションの設定値を取得します（ブール値）。
        'yes', 'true', 'on', '1' は True、'no', 'false', 'off', '0' は False として解釈されます。

        Args:
            section (str): 設定のセクション名。
            option (str): 設定のオプション名。
            fallback (bool, optional): 値が見つからない場合のデフォルト値。

        Returns:
            bool: 設定値（ブール値）。見つからない/変換できない場合は fallback 値または None。

        Raises:
            ValueError: 値をbooleanに変換できない場合（fallback指定なし）。
            configparser.NoSectionError: セクションが存在しない場合（fallback指定なし）。
            configparser.NoOptionError: オプションが存在しない場合（fallback指定なし）。
        """
        try:
            if fallback is not None:
                 value_str = self.config.get(section, option, fallback=str(fallback))
                 if value_str.lower() in ('true', 'yes', 'on', '1'):
                     return True
                 elif value_str.lower() in ('false', 'no', 'off', '0'):
                     return False
                 else:
                     logging.warning(f"Value for [{section}] {option} ('{value_str}') is not a valid boolean. Using fallback {fallback}.")
                     return fallback
            else:
                return self.config.getboolean(section, option)
        except (configparser.NoSectionError, configparser.NoOptionError) as e:
            if fallback is None:
                logging.error(f"Configuration boolean value not found for [{section}] {option} and no fallback provided.")
                raise e
            else:
                 logging.warning(f"Configuration boolean value for [{section}] {option} not found, using fallback {fallback}.")
                 return fallback
        except ValueError as e:
             if fallback is None:
                  logging.error(f"Configuration value for [{section}] {option} is not a valid boolean and no fallback provided.")
                  raise e
             else:
                  logging.warning(f"Configuration value for [{section}] {option} is not a valid boolean. Using fallback {fallback}.")
                  return fallback
        except Exception as e:
             logging.error(f"Error getting boolean configuration for [{section}] {option}: {e}")
             raise