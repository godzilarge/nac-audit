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
    port_mode: str = "N/A"  # access, trunk, etc.
    mac_address: str = ""
    vlan: str = "N/A"
    voice_vlan: str = ""
    domain: str = ""  # data, voice, ou vide
    nac_enabled: bool = False
    nac_version: str = ""  # v1, v2, v3, ou vide
    cdp_neighbor: str = ""
    lldp_neighbor: str = ""

    def to_csv_row(self) -> dict:
        """Convertit en dictionnaire pour export CSV."""
        return {
            "switch": self.switch,
            "port": self.port,
            "oper_status": self.oper_status,
            "admin_status": self.admin_status,
            "description": self.description,
            "port_mode": self.port_mode,
            "mac_address": self.mac_address,
            "vlan": self.vlan,
            "voice_vlan": self.voice_vlan,
            "domain": self.domain,
            "nac_enabled": "yes" if self.nac_enabled else "no",
            "nac_version": self.nac_version,
            "cdp_neighbor": self.cdp_neighbor,
            "lldp_neighbor": self.lldp_neighbor,
        }


@dataclass
class RawSwitchData:
    """Données brutes collectées d'un switch."""
    interfaces_switchport: str = ""
    interfaces_status: str = ""
    interfaces_description: str = ""
    mac_address_table: str = ""
    dot1x_all: str = ""
    cdp_neighbors: str = ""
    lldp_neighbors: str = ""
    auth_config_mode: str = ""
