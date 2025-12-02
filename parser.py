"""
Parser pour les sorties des commandes Cisco.
Extrait et fusionne les données des différentes commandes.
"""

import re
import logging
from typing import Optional

from models import RawSwitchData, PortReport


logger = logging.getLogger("nac_audit")


class SwitchParser:
    """
    Parse les données brutes collectées et génère les rapports par port.
    """
    
    # Regex pour normaliser les noms d'interfaces
    INTERFACE_PATTERNS = [
        (r"^GigabitEthernet", "Gi"),
        (r"^FastEthernet", "Fa"),
        (r"^TenGigabitEthernet", "Te"),
        (r"^TwentyFiveGigE", "Twe"),
        (r"^FortyGigabitEthernet", "Fo"),
        (r"^HundredGigE", "Hu"),
        (r"^Ethernet", "Et"),
    ]
    
    def __init__(self, hostname: str, raw_data: RawSwitchData):
        self.hostname = hostname
        self.raw_data = raw_data
        
        # Données parsées (clé = nom interface normalisé)
        self._switchport_data: dict[str, dict] = {}
        self._status_data: dict[str, dict] = {}
        self._description_data: dict[str, dict] = {}
        self._mac_data: dict[str, list[str]] = {}
        self._dot1x_ports: set[str] = set()
    
    def _normalize_interface(self, interface: str) -> str:
        """
        Normalise le nom d'interface vers la forme courte.
        Ex: GigabitEthernet1/0/1 -> Gi1/0/1
        """
        interface = interface.strip()
        for pattern, replacement in self.INTERFACE_PATTERNS:
            interface = re.sub(pattern, replacement, interface)
        return interface
    
    def _parse_interfaces_switchport(self) -> None:
        """
        Parse 'show interfaces switchport'.
        
        Extrait pour chaque port :
        - VLAN access
        - VLAN voice
        - Mode (access, trunk, etc.)
        """
        output = self.raw_data.interfaces_switchport
        if not output:
            return
        
        # Le format est un bloc par interface
        # Name: Gi1/0/1
        # Switchport: Enabled
        # Administrative Mode: static access
        # Access Mode VLAN: 100 (vlan100)
        # Voice VLAN: 200 (vlan200)
        
        current_interface = None
        current_data = {}
        
        for line in output.splitlines():
            line = line.strip()
            
            # Nouvelle interface
            if line.startswith("Name:"):
                # Sauvegarder l'interface précédente
                if current_interface and current_data.get("switchport_enabled"):
                    self._switchport_data[current_interface] = current_data
                
                # Nouvelle interface
                iface_name = line.split(":", 1)[1].strip()
                current_interface = self._normalize_interface(iface_name)
                current_data = {"switchport_enabled": False}
            
            elif "Switchport: Enabled" in line:
                current_data["switchport_enabled"] = True
            
            elif "Switchport: Disabled" in line:
                current_data["switchport_enabled"] = False
            
            elif line.startswith("Administrative Mode:"):
                mode = line.split(":", 1)[1].strip()
                current_data["admin_mode"] = mode
            
            elif line.startswith("Operational Mode:"):
                mode = line.split(":", 1)[1].strip()
                current_data["oper_mode"] = mode
            
            elif line.startswith("Access Mode VLAN:"):
                # Format: "100 (vlan100)" ou juste "100"
                vlan_part = line.split(":", 1)[1].strip()
                match = re.match(r"(\d+)", vlan_part)
                if match:
                    current_data["access_vlan"] = match.group(1)
            
            elif line.startswith("Voice VLAN:"):
                vlan_part = line.split(":", 1)[1].strip()
                # "none" ou "200 (vlan200)"
                if vlan_part.lower() != "none":
                    match = re.match(r"(\d+)", vlan_part)
                    if match:
                        current_data["voice_vlan"] = match.group(1)
        
        # Ne pas oublier la dernière interface
        if current_interface and current_data.get("switchport_enabled"):
            self._switchport_data[current_interface] = current_data
    
    def _parse_interfaces_status(self) -> None:
        """
        Parse 'show interfaces status'.
        
        Format typique:
        Port      Name               Status       Vlan       Duplex  Speed Type
        Gi1/0/1   Workstation        connected    100        a-full  a-1000 10/100/1000BaseTX
        Gi1/0/2                      notconnect   100        auto    auto   10/100/1000BaseTX
        """
        output = self.raw_data.interfaces_status
        if not output:
            return
        
        for line in output.splitlines():
            line = line.strip()
            
            # Ignorer les lignes d'en-tête et vides
            if not line or line.startswith("Port") or line.startswith("-"):
                continue
            
            # Matcher les interfaces physiques
            match = re.match(
                r"^(Gi|Fa|Te|Twe|Fo|Hu|Et)[\d/]+",
                line
            )
            if not match:
                continue
            
            parts = line.split()
            if len(parts) < 4:
                continue
            
            interface = self._normalize_interface(parts[0])
            
            # Le status peut être à différentes positions selon la description
            # On cherche les mots-clés de status
            status = "unknown"
            for part in parts[1:]:
                if part in ("connected", "notconnect", "disabled", "err-disabled", 
                           "inactive", "suspended", "faulty"):
                    status = part
                    break
            
            self._status_data[interface] = {"oper_status": status}
    
    def _parse_interfaces_description(self) -> None:
        """
        Parse 'show interfaces description'.
        
        Format typique:
        Interface                      Status         Protocol Description
        Gi1/0/1                        up             up       Workstation PC-001
        Gi1/0/2                        admin down     down
        """
        output = self.raw_data.interfaces_description
        if not output:
            return
        
        for line in output.splitlines():
            line = line.strip()
            
            # Ignorer les lignes d'en-tête et vides
            if not line or line.startswith("Interface") or line.startswith("-"):
                continue
            
            # Matcher les interfaces physiques
            match = re.match(
                r"^(Gi|Fa|Te|Twe|Fo|Hu|Et)[\d/]+",
                line
            )
            if not match:
                continue
            
            parts = line.split()
            if len(parts) < 3:
                continue
            
            interface = self._normalize_interface(parts[0])
            
            # Déterminer admin status
            # "up", "down", "admin down"
            admin_status = "up"
            if "admin" in line.lower() and "down" in line.lower():
                admin_status = "admin down"
            elif parts[1].lower() == "down":
                admin_status = "down"
            elif parts[1].lower() == "up":
                admin_status = "up"
            
            # La description est tout ce qui reste après les status
            # Format: Interface Status Protocol Description
            description = ""
            try:
                # Trouver la position après le protocol status
                # Le protocol est généralement up/down après le status admin
                desc_match = re.search(
                    r"^[\S]+\s+(?:admin\s+)?(?:up|down)\s+(?:up|down)\s+(.*)",
                    line,
                    re.IGNORECASE
                )
                if desc_match:
                    description = desc_match.group(1).strip()
            except Exception:
                pass
            
            self._description_data[interface] = {
                "admin_status": admin_status,
                "description": description
            }
    
    def _parse_mac_address_table(self) -> None:
        """
        Parse 'show mac address-table'.
        
        Formats variés selon la plateforme:
        
        IOS classique:
        Mac Address Table
        -------------------------------------------
        Vlan    Mac Address       Type        Ports
        ----    -----------       --------    -----
        100     0011.2233.4455    DYNAMIC     Gi1/0/1
        
        IOS-XE:
                  Mac Address Table
        -------------------------------------------
        Vlan    Mac Address       Type        Ports
        ----    -----------       --------    -----
         100    0011.2233.4455    DYNAMIC     Gi1/0/1
        """
        output = self.raw_data.mac_address_table
        if not output:
            return
        
        # Regex pour matcher une ligne MAC
        # VLAN peut être avec ou sans espaces, MAC en format xxxx.xxxx.xxxx
        mac_pattern = re.compile(
            r"^\s*(\d+)\s+"                    # VLAN
            r"([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+"  # MAC
            r"(\S+)\s+"                        # Type (DYNAMIC, STATIC, etc.)
            r"(\S+)",                          # Port
            re.MULTILINE
        )
        
        for match in mac_pattern.finditer(output):
            vlan, mac, mac_type, port = match.groups()
            
            # Normaliser le port
            port = self._normalize_interface(port)
            
            # Ignorer les ports non physiques (Po, Vl, etc.)
            if not re.match(r"^(Gi|Fa|Te|Twe|Fo|Hu|Et)", port):
                continue
            
            # Ajouter la MAC au port
            if port not in self._mac_data:
                self._mac_data[port] = []
            
            # Stocker MAC avec son VLAN pour déterminer le domaine
            self._mac_data[port].append({
                "mac": mac,
                "vlan": vlan,
                "type": mac_type
            })
    
    def _parse_dot1x_all(self) -> None:
        """
        Parse 'show dot1x all'.
        
        Extrait la liste des interfaces où dot1x est actif.
        
        Format typique:
        Dot1x Info for GigabitEthernet1/0/1
        -----------------------------------
        PAE                       = AUTHENTICATOR
        ...
        
        Ou format summary:
        Interface    PAE    Client    Status
        Gi1/0/1      Auth   ...       ...
        """
        output = self.raw_data.dot1x_all
        if not output:
            return
        
        # Pattern 1: "Dot1x Info for <interface>"
        pattern1 = re.compile(r"Dot1x Info for (\S+)", re.IGNORECASE)
        
        # Pattern 2: Ligne avec interface au début (format tabulaire)
        pattern2 = re.compile(r"^(Gi|Fa|Te|Twe|Fo|Hu|Et)[\d/]+", re.MULTILINE)
        
        # Pattern 1
        for match in pattern1.finditer(output):
            interface = self._normalize_interface(match.group(1))
            self._dot1x_ports.add(interface)
        
        # Pattern 2 (si format tabulaire)
        for line in output.splitlines():
            line = line.strip()
            match = pattern2.match(line)
            if match:
                # Vérifier que c'est pas juste un header ou autre
                parts = line.split()
                if len(parts) >= 2:
                    interface = self._normalize_interface(parts[0])
                    self._dot1x_ports.add(interface)
    
    def parse_all(self) -> list[PortReport]:
        """
        Parse toutes les données et génère la liste des rapports par port.
        
        Returns:
            list[PortReport]: Liste des rapports de ports
        """
        # Parser chaque type de données
        self._parse_interfaces_switchport()
        self._parse_interfaces_status()
        self._parse_interfaces_description()
        self._parse_mac_address_table()
        self._parse_dot1x_all()
        
        logger.debug(
            f"[{self.hostname}] Ports switchport: {len(self._switchport_data)}, "
            f"Ports dot1x: {len(self._dot1x_ports)}"
        )
        
        # Fusionner les données
        # La source de vérité pour la liste des ports est show interfaces switchport
        reports = []
        
        for interface, sw_data in self._switchport_data.items():
            report = PortReport(
                switch=self.hostname,
                port=interface,
            )
            
            # Données switchport
            report.vlan = sw_data.get("access_vlan", "N/A")
            report.voice_vlan = sw_data.get("voice_vlan", "")
            
            # Status opérationnel (show interfaces status)
            if interface in self._status_data:
                status = self._status_data[interface].get("oper_status", "N/A")
                # Normaliser les status
                if status == "connected":
                    report.oper_status = "up"
                elif status == "notconnect":
                    report.oper_status = "down"
                else:
                    report.oper_status = status
            
            # Status admin et description (show interfaces description)
            if interface in self._description_data:
                report.admin_status = self._description_data[interface].get(
                    "admin_status", "N/A"
                )
                report.description = self._description_data[interface].get(
                    "description", ""
                )
            
            # MAC address (première MAC trouvée)
            if interface in self._mac_data and self._mac_data[interface]:
                mac_entry = self._mac_data[interface][0]
                report.mac_address = mac_entry["mac"]
                
                # Déterminer le domaine (data ou voice)
                mac_vlan = mac_entry["vlan"]
                if report.voice_vlan and mac_vlan == report.voice_vlan:
                    report.domain = "voice"
                elif mac_vlan == report.vlan:
                    report.domain = "data"
                else:
                    report.domain = "data"  # Par défaut
            
            # NAC activé ?
            report.nac_enabled = interface in self._dot1x_ports
            
            reports.append(report)
        
        # Trier par nom de port
        reports.sort(key=lambda r: self._interface_sort_key(r.port))
        
        return reports
    
    @staticmethod
    def _interface_sort_key(interface: str) -> tuple:
        """
        Génère une clé de tri pour les interfaces.
        Ex: Gi1/0/1 -> ('Gi', 1, 0, 1)
        """
        match = re.match(r"([A-Za-z]+)([\d/]+)", interface)
        if not match:
            return (interface, 0, 0, 0)
        
        prefix = match.group(1)
        numbers = match.group(2)
        
        # Extraire les numéros
        num_parts = [int(n) for n in numbers.split("/") if n.isdigit()]
        
        # Padding pour avoir toujours 3 éléments
        while len(num_parts) < 3:
            num_parts.append(0)
        
        return (prefix, *num_parts[:3])
