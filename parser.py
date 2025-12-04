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
    
    # Regex pour normaliser les noms d'interfaces (forme longue -> forme courte)
    # Couvre IOS, IOS-XE, NX-OS et les formes CDP/LLDP
    INTERFACE_PATTERNS = [
        # Ethernet standards (formes longues et CDP)
        (r"^GigabitEthernet", "Gi"),
        (r"^Gig(?=\d)", "Gi"),           # CDP: Gig 1/0/1
        (r"^FastEthernet", "Fa"),
        (r"^Fas(?=\d)", "Fa"),           # CDP: Fas 0/1
        (r"^Ethernet", "Eth"),
        (r"^Eth(?=\d)", "Eth"),          # CDP: Eth 1/1
        
        # Multi-Gigabit (mGig) - Catalyst 9000
        (r"^TwoGigabitEthernet", "Tw"),
        (r"^Two(?=\d)", "Tw"),           # CDP: Two 1/0/1
        (r"^FiveGigabitEthernet", "Fi"),
        (r"^Fiv(?=\d)", "Fi"),           # CDP: Fiv 1/0/1
        
        # 10G+
        (r"^TenGigabitEthernet", "Te"),
        (r"^Ten(?=\d)", "Te"),           # CDP: Ten 1/0/1
        (r"^TwentyFiveGigE", "Twe"),
        (r"^TwentyFiveGigabitEthernet", "Twe"),
        (r"^Twe(?=\d)", "Twe"),          # CDP: Twe 1/0/1
        (r"^FortyGigabitEthernet", "Fo"),
        (r"^For(?=\d)", "Fo"),           # CDP: For 1/0/1
        (r"^FiftyGigE", "Fif"),
        (r"^Fif(?=\d)", "Fif"),          # CDP: Fif 1/0/1
        (r"^HundredGigE", "Hu"),
        (r"^HundredGigabitEthernet", "Hu"),
        (r"^Hun(?=\d)", "Hu"),           # CDP: Hun 1/0/1
        (r"^TwoHundredGigE", "TH"),
        (r"^FourHundredGigE", "FH"),
        
        # Application hosting - Catalyst 9300/9400
        (r"^AppGigabitEthernet", "Ap"),
        (r"^App(?=\d)", "Ap"),           # CDP: App 1/0/1
        
        # Port-channel / LAG
        (r"^Port-channel", "Po"),
        
        # NX-OS
        (r"^Eth(?:ernet)?(?=/)", "Eth"),  # Eth1/1 format NX-OS
        
        # Management
        (r"^mgmt", "mgmt"),
        (r"^Management", "Ma"),
    ]
    
    # Préfixes d'interfaces valides pour le matching (forme courte)
    # Exclut: Vlan, Loopback, Tunnel, etc.
    INTERFACE_PREFIXES = (
        r"^("
        r"Gi|Fa|Eth|"                    # Base Ethernet
        r"Tw|Fi|"                         # mGig
        r"Te|Twe|Fo|Fif|Hu|TH|FH|"       # High-speed
        r"Ap|"                            # App hosting
        r"Po|"                            # Port-channel
        r"mgmt|Ma"                        # Management
        r")"
    )
    
    def __init__(self, hostname: str, raw_data: RawSwitchData):
        self.hostname = hostname
        self.raw_data = raw_data
        
        # Données parsées (clé = nom interface normalisé)
        self._switchport_data: dict[str, dict] = {}
        self._status_data: dict[str, dict] = {}
        self._description_data: dict[str, dict] = {}
        self._mac_data: dict[str, list[str]] = {}
        self._dot1x_ports: set[str] = set()
        self._cdp_neighbors: dict[str, str] = {}
        self._lldp_neighbors: dict[str, str] = {}
        self._nac_version: str = ""  # Version NAC du switch (v1, v2, v3)
    
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
            match = re.match(self.INTERFACE_PREFIXES + r"[\d/]+", line)
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
        Tw1/0/10                       up             up       ||-- Description --||
        """
        output = self.raw_data.interfaces_description
        if not output:
            return
        
        # Regex robuste pour capturer: interface, status, protocol, description
        # Status peut être "up", "down", ou "admin down"
        pattern = re.compile(
            r"^(\S+)\s+"                           # Interface
            r"(up|down|admin down)\s+"             # Status (admin status)
            r"(up|down)\s*"                        # Protocol (oper status)
            r"(.*)$",                              # Description (peut être vide)
            re.IGNORECASE
        )
        
        for line in output.splitlines():
            # Ignorer les lignes d'en-tête et vides
            if not line.strip() or line.strip().startswith("Interface") or line.startswith("-"):
                continue
            
            match = pattern.match(line)
            if not match:
                continue
            
            interface_raw, admin_status, protocol, description = match.groups()
            
            # Vérifier que c'est une interface physique
            if not re.match(self.INTERFACE_PREFIXES, interface_raw):
                continue
            
            interface = self._normalize_interface(interface_raw)
            
            self._description_data[interface] = {
                "admin_status": admin_status.lower(),
                "oper_status": protocol.lower(),
                "description": description.strip()
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
            if not re.match(self.INTERFACE_PREFIXES, port):
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
        pattern2 = re.compile(self.INTERFACE_PREFIXES + r"[\d/]+", re.MULTILINE)
        
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
    
    def _parse_cdp_neighbors(self) -> None:
        """
        Parse 'show cdp neighbors'.
        
        Format typique:
        Device ID        Local Intrfce     Holdtme    Capability  Platform  Port ID
        Switch-Core      Gi 1/0/1          180              R S   WS-C3850  Gi 1/0/24
        AP-Floor3        Ten 1/0/10        140              T     AIR-AP    Gi 0
        
        Note: L'interface locale peut être formatée avec espace et préfixes variés:
        - Gi, Gig (GigabitEthernet)
        - Te, Ten (TenGigabitEthernet)
        - Fa, Fas (FastEthernet)
        - Tw, Two (TwoGigabitEthernet)
        - etc.
        """
        output = self.raw_data.cdp_neighbors
        if not output:
            return
        
        # Préfixes CDP possibles (formes courtes et moyennes)
        cdp_prefixes = (
            r"(?:"
            r"Gig?|Gi|"           # GigabitEthernet
            r"Ten?|Te|"           # TenGigabitEthernet
            r"Fas?|Fa|"           # FastEthernet
            r"Two?|Tw|"           # TwoGigabitEthernet
            r"Fiv?|Fi|"           # FiveGigabitEthernet
            r"For?|Fo|"           # FortyGigabitEthernet
            r"Hun?|Hu|"           # HundredGigE
            r"Twe?|"              # TwentyFiveGigE
            r"Eth?|"              # Ethernet
            r"App?|Ap|"           # AppGigabitEthernet
            r"Po"                 # Port-channel
            r")"
        )
        
        for line in output.splitlines():
            line = line.strip()
            
            # Ignorer les headers et lignes vides
            if not line or line.startswith("Device") or line.startswith("-") or line.startswith("Capability"):
                continue
            
            # Pattern pour capturer: device_id + interface locale
            # L'interface peut être "Gi 1/0/1", "Gig 1/0/1", "Ten 2/0/48" (avec espace après préfixe)
            match = re.match(
                r"^(\S+)\s+"                         # Device ID
                r"(" + cdp_prefixes + r")\s*"        # Préfixe interface
                r"([\d/]+)\s+"                       # Numéro interface
                r"(\d+)\s+",                         # Holdtime
                line,
                re.IGNORECASE
            )
            
            if match:
                device_id = match.group(1)
                iface_prefix = match.group(2)
                iface_num = match.group(3)
                
                # Reconstruire et normaliser l'interface
                local_interface = f"{iface_prefix}{iface_num}"
                local_interface = self._normalize_interface(local_interface)
                
                # Stocker le neighbor (on garde le premier trouvé s'il y en a plusieurs)
                if local_interface not in self._cdp_neighbors:
                    self._cdp_neighbors[local_interface] = device_id
    
    def _parse_lldp_neighbors(self) -> None:
        """
        Parse 'show lldp neighbors'.
        
        Format typique:
        Device ID           Local Intf     Hold-time  Capability      Port ID
        switch-core.domain  Gi1/0/1        120        B,R             Gi1/0/24
        phone-001           Gi1/0/10       180        T               port1
        
        Note: Format généralement sans espace dans l'interface
        """
        output = self.raw_data.lldp_neighbors
        if not output:
            return
        
        for line in output.splitlines():
            line = line.strip()
            
            # Ignorer les headers et lignes vides
            if not line or line.startswith("Device") or line.startswith("-") or line.startswith("Capability") or "Total entries" in line:
                continue
            
            # Pattern pour LLDP - interface généralement collée
            match = re.match(
                r"^(\S+)\s+"                                    # Device ID
                r"([A-Za-z]+[\d/]+)\s+"                         # Interface locale
                r"(\d+)\s+",                                    # Hold-time
                line
            )
            
            if match:
                device_id = match.group(1)
                local_interface = match.group(2)
                
                # Normaliser l'interface
                local_interface = self._normalize_interface(local_interface)
                
                # Stocker le neighbor
                if local_interface not in self._lldp_neighbors:
                    self._lldp_neighbors[local_interface] = device_id

    def _parse_auth_config_mode(self) -> None:
        """
        Parse 'authentication display config-mode'.
        
        Output typique:
        - "Current configuration mode is legacy" -> v1/v2 (IBNS 1.0)
        - "Current configuration mode is new-style" -> v3 (IBNS 2.0/C3PL)
        
        Cette commande retourne la version de configuration NAC du switch.
        """
        output = self.raw_data.auth_config_mode
        if not output:
            return
        
        output_lower = output.lower()
        
        if "new-style" in output_lower or "new style" in output_lower:
            self._nac_version = "v3"
        elif "legacy" in output_lower:
            self._nac_version = "v1/v2"

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
        self._parse_cdp_neighbors()
        self._parse_lldp_neighbors()
        self._parse_auth_config_mode()
        
        logger.debug(
            f"[{self.hostname}] Ports switchport: {len(self._switchport_data)}, "
            f"Ports dot1x: {len(self._dot1x_ports)}, "
            f"CDP neighbors: {len(self._cdp_neighbors)}, "
            f"LLDP neighbors: {len(self._lldp_neighbors)}, "
            f"NAC version: {self._nac_version or 'N/A'}"
        )
        
        # Fusionner les données
        # La source de vérité pour la liste des ports est show interfaces switchport
        reports = []
        
        for interface, sw_data in self._switchport_data.items():
            report = PortReport(
                switch=self.hostname,
                port=interface,
            )
            
            # Mode du port (operational mode: trunk, access, etc.)
            oper_mode = sw_data.get("oper_mode", "").lower()
            if "trunk" in oper_mode:
                report.port_mode = "trunk"
                report.vlan = ""  # Pas de VLAN pour les trunks
                report.voice_vlan = ""
            elif "access" in oper_mode:
                report.port_mode = "access"
                report.vlan = sw_data.get("access_vlan", "N/A")
                report.voice_vlan = sw_data.get("voice_vlan", "")
            else:
                # Autres modes: dynamic, down, etc.
                report.port_mode = oper_mode if oper_mode else "N/A"
                report.vlan = sw_data.get("access_vlan", "N/A")
                report.voice_vlan = sw_data.get("voice_vlan", "")
            
            # Status admin, oper et description (show interfaces description)
            # C'est la source la plus fiable pour admin_status et oper_status
            if interface in self._description_data:
                desc_data = self._description_data[interface]
                report.admin_status = desc_data.get("admin_status", "N/A")
                report.oper_status = desc_data.get("oper_status", "N/A")
                report.description = desc_data.get("description", "")
            
            # Fallback sur show interfaces status si pas de données de description
            if report.oper_status == "N/A" and interface in self._status_data:
                status = self._status_data[interface].get("oper_status", "N/A")
                # Normaliser les status
                if status == "connected":
                    report.oper_status = "up"
                elif status == "notconnect":
                    report.oper_status = "down"
                else:
                    report.oper_status = status
            
            # MAC address (première MAC trouvée)
            if interface in self._mac_data and self._mac_data[interface]:
                mac_entry = self._mac_data[interface][0]
                report.mac_address = mac_entry["mac"]
                
                # Déterminer le domaine (data ou voice) - seulement si pas trunk
                if report.port_mode != "trunk":
                    mac_vlan = mac_entry["vlan"]
                    if report.voice_vlan and mac_vlan == report.voice_vlan:
                        report.domain = "voice"
                    elif mac_vlan == report.vlan:
                        report.domain = "data"
                    else:
                        report.domain = "data"  # Par défaut
            
            # NAC activé ?
            report.nac_enabled = interface in self._dot1x_ports
            
            # NAC version (niveau switch, même valeur pour tous les ports)
            report.nac_version = self._nac_version
            
            # CDP neighbor
            if interface in self._cdp_neighbors:
                report.cdp_neighbor = self._cdp_neighbors[interface]
            
            # LLDP neighbor
            if interface in self._lldp_neighbors:
                report.lldp_neighbor = self._lldp_neighbors[interface]
            
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
