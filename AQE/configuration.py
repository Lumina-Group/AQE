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
        "security": {
            "MAX_MESSAGE_SIZE": "65536",
            "TIMESTAMP_WINDOW": "60",
            "MAX_FAILED_ATTEMPTS": "5",
            "RATE_LIMIT_WINDOW": "30",
            "SEQUENCE_WINDOW_SIZE": "10",
            "MESSAGE_MAX_AGE": "300",
            "KEY_SIZE": "32",
            "NONCE_CACHE_SIZE": "100"
        },
        "timeouts": {
            "HANDSHAKE_TIMEOUT": "30",
            "CONNECTION_TIMEOUT": "300",
            "CLEANUP_INTERVAL": "300"
        },
        "logging": {
            "LOG_TIMESTAMPS": "true",
            "ENABLE_SECURITY_METRICS_LOG": "true"
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
        self._config_file_existed = os.path.exists(self.config_file)
        self._load_configuration()

    def _load_defaults(self):
        """Populates self.config with DEFAULT_CONFIG."""
        for section, options in self.DEFAULT_CONFIG.items():
            if not self.config.has_section(section):
                self.config.add_section(section)
            for option, value in options.items():
                if not self.config.has_option(section, option) or self.config.get(section, option) != value:
                    self.config.set(section, option, value)

    def _load_configuration(self):
        """設定ファイルを読み込みます。存在しない場合はメモリ内でデフォルトを使用します。"""
        needs_save = False
        if self._config_file_existed:
            try:
                self.config.read(self.config_file)
                # logging.info(f"Configuration loaded from {self.config_file}")
            except configparser.Error as e:
                 logging.error(f"Error reading configuration file {self.config_file}: {e}. Using defaults and attempting to repair.")
                 self.config = configparser.ConfigParser(interpolation=None) # Reset corrupted config
                 self._load_defaults()
                 needs_save = True # Mark for saving after repair
        else:
            logging.warning(f"Configuration file {self.config_file} not found. Using default settings in memory. No file will be created unless configuration is explicitly saved via 'set'.")
            self._load_defaults()
            # Do not set needs_save = True here, as we don't want to create the file

        # Apply defaults for missing sections/options if the file existed
        if self._config_file_existed:
            for section, options in self.DEFAULT_CONFIG.items():
                if not self.config.has_section(section):
                    self.config.add_section(section)
                    needs_save = True
                    logging.info(f"Added default section '{section}' to in-memory configuration.")
                for option, value in options.items():
                    if not self.config.has_option(section, option):
                        self.config.set(section, option, value)
                        needs_save = True
                        logging.info(f"Added default option '{section}.{option}' = '{value}' to in-memory configuration.")
        # If the file did not exist, defaults are already loaded by _load_defaults(),
        # and we don't want to trigger a save that would create the file.

        try:
            self._validate_configuration()
        except ValueError as e:
             logging.error(f"Configuration validation failed: {e}. Check your config file (if it exists): {self.config_file} or the default settings.")
             raise

        if needs_save and self._config_file_existed:
            self._save_configuration()

    # This method is no longer needed as its logic is integrated elsewhere or handled differently.
    # def _apply_defaults_and_save(self):
    #      """デフォルト設定を適用し、ファイルに保存します。"""
    #      for section, options in self.DEFAULT_CONFIG.items():
    #          if not self.config.has_section(section):
    #              self.config.add_section(section)
    #          for option, value in options.items():
    #              self.config.set(section, option, value)
    #      self._save_configuration()

    def _save_configuration(self):
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

        # The save logic is now conditional within _load_configuration
        # if needs_save and self._config_file_existed:
        #     self._save_configuration()

    # This method is no longer needed as its logic is integrated elsewhere or handled differently.
    # def _apply_defaults_and_save(self):
    #      """デフォルト設定を適用し、ファイルに保存します。"""
    #      for section, options in self.DEFAULT_CONFIG.items():
    #          if not self.config.has_section(section):
    #              self.config.add_section(section)
    #          for option, value in options.items():
    #              self.config.set(section, option, value)
    #      self._save_configuration()

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
    def set(self, section: str, option: str, value: str):
        """
        指定されたセクションとオプションに新しい値を設定します。
        Args:
            section (str): 設定のセクション名。
            option (str): 設定のオプション名。
            value (str): 設定する値。
        """
        if not self.config.has_section(section):
            self.config.add_section(section)
        self.config.set(section, option, value)
        if self._config_file_existed:
            self._save_configuration()
            logging.info(f"Configuration updated and saved: [{section}] {option} = '{value}' to {self.config_file}")
        else:
            logging.info(f"In-memory configuration updated: [{section}] {option} = '{value}'. File {self.config_file} was not found initially and will not be created by this 'set' operation.")
    