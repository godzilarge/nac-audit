"""
Modèles de données pour l'audit NAC.
"""

from dataclasses import dataclass, field


@dataclass
class SwitchInventory:
    """Représente un switch dans l'inventaire."""
    hostname: str
    ip: str


@dataclass
class PortReport:
    """Représente les données d'un port pour le rapport."""
    switch: str
    port: str
    oper_status: str = "N/A"
    admin_status: str = "N/A"
    description: str = ""
    mac_address: str = ""
    vlan: str = "N/A"
    voice_vlan: str = ""
    domain: str = ""  # data, voice, ou vide
    nac_enabled: bool = False

    def to_csv_row(self) -> dict:
        """Convertit en dictionnaire pour export CSV."""
        return {
            "switch": self.switch,
            "port": self.port,
            "oper_status": self.oper_status,
            "admin_status": self.admin_status,
            "description": self.description,
            "mac_address": self.mac_address,
            "vlan": self.vlan,
            "voice_vlan": self.voice_vlan,
            "domain": self.domain,
            "nac_enabled": "yes" if self.nac_enabled else "no"
        }


@dataclass
class RawSwitchData:
    """Données brutes collectées d'un switch."""
    interfaces_switchport: str = ""
    interfaces_status: str = ""
    interfaces_description: str = ""
    mac_address_table: str = ""
    dot1x_all: str = ""
