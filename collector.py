"""
Collecteur de données pour switches Cisco.
Utilise Netmiko pour la connexion SSH et l'exécution des commandes.
"""

import logging
from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)

from models import RawSwitchData


logger = logging.getLogger("nac_audit")


class ConnectionError(Exception):
    """Erreur de connexion au switch."""
    pass


class SwitchCollector:
    """
    Collecte les données brutes d'un switch Cisco.
    
    Supporte IOS et IOS-XE (2960, 4500, 9200, 9300).
    Utilise device_type 'cisco_ios' qui fonctionne pour les deux.
    """
    
    # Commandes à exécuter
    COMMANDS = {
        "interfaces_switchport": "show interfaces switchport",
        "interfaces_status": "show interfaces status",
        "interfaces_description": "show interfaces description",
        "mac_address_table": "show mac address-table",
        "dot1x_all": "show dot1x all",
        "cdp_neighbors": "show cdp neighbors",
        "lldp_neighbors": "show lldp neighbors",
    }
    
    def __init__(
        self,
        hostname: str,
        ip: str,
        username: str,
        password: str,
        timeout: int = 30,
        enable_password: str | None = None,
    ):
        self.hostname = hostname
        self.ip = ip
        self.username = username
        self.password = password
        self.timeout = timeout
        self.enable_password = enable_password or password
        self.connection = None
    
    def connect(self) -> None:
        """Établit la connexion SSH au switch."""
        device = {
            "device_type": "cisco_ios",
            "host": self.ip,
            "username": self.username,
            "password": self.password,
            "secret": self.enable_password,
            "timeout": self.timeout,
            "conn_timeout": self.timeout,
            "banner_timeout": self.timeout,
            "auth_timeout": self.timeout,
        }
        
        try:
            self.connection = ConnectHandler(**device)
            # S'assurer d'être en mode enable
            if not self.connection.check_enable_mode():
                self.connection.enable()
                
        except NetmikoAuthenticationException as e:
            raise ConnectionError(f"Authentification échouée: {e}")
        except NetmikoTimeoutException as e:
            raise ConnectionError(f"Timeout de connexion: {e}")
        except Exception as e:
            raise ConnectionError(f"Erreur de connexion: {e}")
    
    def disconnect(self) -> None:
        """Ferme la connexion SSH."""
        if self.connection:
            try:
                self.connection.disconnect()
            except Exception:
                pass
            self.connection = None
    
    def _send_command(self, command: str) -> str:
        """
        Exécute une commande et retourne la sortie.
        
        Gère les commandes qui peuvent ne pas exister sur certaines plateformes.
        """
        if not self.connection:
            raise ConnectionError("Non connecté")
        
        try:
            output = self.connection.send_command(
                command,
                read_timeout=self.timeout,
                strip_prompt=True,
                strip_command=True,
            )
            
            # Vérifier si la commande a échoué
            error_patterns = [
                "% Invalid input",
                "% Incomplete command",
                "% Ambiguous command",
            ]
            
            for pattern in error_patterns:
                if pattern in output:
                    logger.warning(
                        f"[{self.hostname}] Commande non supportée: {command}"
                    )
                    return ""
            
            return output
            
        except Exception as e:
            logger.warning(
                f"[{self.hostname}] Erreur lors de '{command}': {e}"
            )
            return ""
    
    def collect_all(self) -> RawSwitchData:
        """
        Collecte toutes les données du switch.
        
        Returns:
            RawSwitchData: Données brutes collectées
        """
        if not self.connection:
            self.connect()
        
        data = RawSwitchData()
        
        for attr, command in self.COMMANDS.items():
            logger.debug(f"[{self.hostname}] Exécution: {command}")
            output = self._send_command(command)
            setattr(data, attr, output)
        
        return data
