#!/usr/bin/env python3
"""
Tests unitaires pour le NAC Audit Tool.
Utilise des outputs Cisco simulés pour valider le parsing.
"""

import sys
from pathlib import Path

# Ajouter le répertoire parent au path
sys.path.insert(0, str(Path(__file__).parent))

from models import SwitchInventory, PortReport, RawSwitchData
from parser import SwitchParser


# ============================================================
# DONNÉES DE TEST - Outputs Cisco simulés
# ============================================================

SAMPLE_INTERFACES_SWITCHPORT = """
Name: Gi1/0/1
Switchport: Enabled
Administrative Mode: static access
Operational Mode: static access
Administrative Trunking Encapsulation: dot1q
Operational Trunking Encapsulation: native
Negotiation of Trunking: Off
Access Mode VLAN: 100 (data_vlan)
Trunking Native Mode VLAN: 1 (default)
Administrative Native VLAN tagging: enabled
Voice VLAN: 200 (voice_vlan)
Administrative private-vlan host-association: none
Administrative private-vlan mapping: none
Administrative private-vlan trunk native VLAN: none
Administrative private-vlan trunk Native VLAN tagging: enabled
Administrative private-vlan trunk encapsulation: dot1q
Administrative private-vlan trunk normal VLANs: none
Administrative private-vlan trunk associations: none
Administrative private-vlan trunk mappings: none
Operational private-vlan: none
Trunking VLANs Enabled: ALL
Pruning VLANs Enabled: 2-1001
Capture Mode Disabled
Capture VLANs Allowed: ALL

Name: Gi1/0/2
Switchport: Enabled
Administrative Mode: static access
Operational Mode: static access
Administrative Trunking Encapsulation: dot1q
Operational Trunking Encapsulation: native
Negotiation of Trunking: Off
Access Mode VLAN: 100 (data_vlan)
Trunking Native Mode VLAN: 1 (default)
Administrative Native VLAN tagging: enabled
Voice VLAN: none
Administrative private-vlan host-association: none
Administrative private-vlan mapping: none
Administrative private-vlan trunk native VLAN: none
Administrative private-vlan trunk Native VLAN tagging: enabled
Administrative private-vlan trunk encapsulation: dot1q
Administrative private-vlan trunk normal VLANs: none
Administrative private-vlan trunk associations: none
Administrative private-vlan trunk mappings: none
Operational private-vlan: none
Trunking VLANs Enabled: ALL
Pruning VLANs Enabled: 2-1001
Capture Mode Disabled
Capture VLANs Allowed: ALL

Name: Gi1/0/3
Switchport: Enabled
Administrative Mode: static access
Operational Mode: static access
Administrative Trunking Encapsulation: dot1q
Operational Trunking Encapsulation: native
Negotiation of Trunking: Off
Access Mode VLAN: 150 (guest_vlan)
Trunking Native Mode VLAN: 1 (default)
Administrative Native VLAN tagging: enabled
Voice VLAN: none
Administrative private-vlan host-association: none
Administrative private-vlan mapping: none
Administrative private-vlan trunk native VLAN: none
Administrative private-vlan trunk Native VLAN tagging: enabled
Administrative private-vlan trunk encapsulation: dot1q
Administrative private-vlan trunk normal VLANs: none
Administrative private-vlan trunk associations: none
Administrative private-vlan trunk mappings: none
Operational private-vlan: none
Trunking VLANs Enabled: ALL
Pruning VLANs Enabled: 2-1001
Capture Mode Disabled
Capture VLANs Allowed: ALL

Name: Gi1/0/4
Switchport: Disabled

Name: Tw1/0/10
Switchport: Enabled
Administrative Mode: static access
Operational Mode: static access
Administrative Trunking Encapsulation: dot1q
Operational Trunking Encapsulation: native
Negotiation of Trunking: Off
Access Mode VLAN: 1098 (mgmt_vlan)
Trunking Native Mode VLAN: 1 (default)
Administrative Native VLAN tagging: enabled
Voice VLAN: none
Administrative private-vlan host-association: none
Administrative private-vlan mapping: none
Administrative private-vlan trunk native VLAN: none
Administrative private-vlan trunk Native VLAN tagging: enabled
Administrative private-vlan trunk encapsulation: dot1q
Administrative private-vlan trunk normal VLANs: none
Administrative private-vlan trunk associations: none
Administrative private-vlan trunk mappings: none
Operational private-vlan: none
Trunking VLANs Enabled: ALL
Pruning VLANs Enabled: 2-1001
Capture Mode Disabled
Capture VLANs Allowed: ALL

Name: Vlan100
Switchport: Disabled
"""

SAMPLE_INTERFACES_STATUS = """
Port      Name               Status       Vlan       Duplex  Speed Type
Gi1/0/1   PC-User-001        connected    100        a-full  a-1000 10/100/1000BaseTX
Gi1/0/2   Printer-Floor1     notconnect   100        auto    auto   10/100/1000BaseTX
Gi1/0/3   Guest-Port         connected    150        a-full  a-100  10/100/1000BaseTX
Gi1/0/4                      disabled     1          auto    auto   10/100/1000BaseTX
Gi1/0/5   Uplink-Core        connected    trunk      a-full  a-1000 10/100/1000BaseTX
"""

SAMPLE_INTERFACES_DESCRIPTION = """
Interface                      Status         Protocol Description
Gi1/0/1                        up             up       PC-User-001
Gi1/0/2                        down           down     Printer-Floor1
Gi1/0/3                        up             up       Guest-Port
Gi1/0/4                        admin down     down     
Gi1/0/5                        up             up       Uplink-Core
Tw1/0/10                       up             up       ||-- Management Center 02//Management0 --||
Vl100                          up             up       Data VLAN
"""

SAMPLE_MAC_ADDRESS_TABLE = """
          Mac Address Table
-------------------------------------------

Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
 100    0011.2233.4455    DYNAMIC     Gi1/0/1
 200    aabb.ccdd.eeff    DYNAMIC     Gi1/0/1
 150    1122.3344.5566    DYNAMIC     Gi1/0/3
All    0100.0ccc.cccc    STATIC      CPU
All    0100.0ccc.cccd    STATIC      CPU
Total Mac Addresses for this criterion: 5
"""

# Format "show dot1x all" - seuls Gi1/0/1 et Gi1/0/3 ont dot1x actif
SAMPLE_DOT1X_ALL = """
Dot1x Info for GigabitEthernet1/0/1
-----------------------------------
PAE                       = AUTHENTICATOR
PortControl               = AUTO
ControlDirection          = Both 
HostMode                  = MULTI_DOMAIN
QuietPeriod               = 60
ServerTimeout             = 0
SuppTimeout               = 30
ReAuthMax                 = 2
MaxReq                    = 2
TxPeriod                  = 30

Dot1x Info for GigabitEthernet1/0/3
-----------------------------------
PAE                       = AUTHENTICATOR
PortControl               = AUTO
ControlDirection          = Both 
HostMode                  = SINGLE_HOST
QuietPeriod               = 60
ServerTimeout             = 0
SuppTimeout               = 30
ReAuthMax                 = 2
MaxReq                    = 2
TxPeriod                  = 30
"""


def test_parser():
    """Test le parsing complet."""
    print("=" * 60)
    print("TEST: Parsing des outputs Cisco")
    print("=" * 60)
    
    # Créer les données brutes
    raw_data = RawSwitchData(
        interfaces_switchport=SAMPLE_INTERFACES_SWITCHPORT,
        interfaces_status=SAMPLE_INTERFACES_STATUS,
        interfaces_description=SAMPLE_INTERFACES_DESCRIPTION,
        mac_address_table=SAMPLE_MAC_ADDRESS_TABLE,
        dot1x_all=SAMPLE_DOT1X_ALL
    )
    
    # Parser
    parser = SwitchParser("test-switch-01", raw_data)
    ports = parser.parse_all()
    
    print(f"\nPorts trouvés: {len(ports)}")
    
    # Afficher les résultats
    print("\n{:<12} {:<10} {:<12} {:<18} {:<8} {:<8} {:<6}".format(
        "Port", "Oper", "Admin", "MAC", "VLAN", "Voice", "NAC"
    ))
    print("-" * 80)
    
    for port in ports:
        print("{:<12} {:<10} {:<12} {:<18} {:<8} {:<8} {:<6}".format(
            port.port,
            port.oper_status,
            port.admin_status,
            port.mac_address or "-",
            port.vlan,
            port.voice_vlan or "-",
            "YES" if port.nac_enabled else "NO"
        ))
    
    # Validations
    print("\n" + "=" * 60)
    print("VALIDATIONS")
    print("=" * 60)
    
    errors = []
    
    # Doit trouver 4 ports (Gi1/0/1, Gi1/0/2, Gi1/0/3, Tw1/0/10 - switchport enabled)
    # Gi1/0/4 a switchport disabled, donc exclu
    if len(ports) != 4:
        errors.append(f"ERREUR: Attendu 4 ports, trouvé {len(ports)}")
    else:
        print("✓ Nombre de ports correct (4)")
    
    # Vérifier Gi1/0/1
    gi1_0_1 = next((p for p in ports if p.port == "Gi1/0/1"), None)
    if gi1_0_1:
        if gi1_0_1.nac_enabled:
            print("✓ Gi1/0/1 NAC enabled = True")
        else:
            errors.append("ERREUR: Gi1/0/1 devrait avoir NAC enabled")
        
        if gi1_0_1.vlan == "100":
            print("✓ Gi1/0/1 VLAN = 100")
        else:
            errors.append(f"ERREUR: Gi1/0/1 VLAN attendu 100, trouvé {gi1_0_1.vlan}")
        
        if gi1_0_1.voice_vlan == "200":
            print("✓ Gi1/0/1 Voice VLAN = 200")
        else:
            errors.append(f"ERREUR: Gi1/0/1 Voice VLAN attendu 200, trouvé {gi1_0_1.voice_vlan}")
        
        if gi1_0_1.mac_address == "0011.2233.4455":
            print("✓ Gi1/0/1 MAC = 0011.2233.4455")
        else:
            errors.append(f"ERREUR: Gi1/0/1 MAC attendue 0011.2233.4455, trouvée {gi1_0_1.mac_address}")
        
        if gi1_0_1.oper_status == "up":
            print("✓ Gi1/0/1 oper_status = up")
        else:
            errors.append(f"ERREUR: Gi1/0/1 oper_status attendu up, trouvé {gi1_0_1.oper_status}")
    else:
        errors.append("ERREUR: Gi1/0/1 non trouvé")
    
    # Vérifier Gi1/0/2 - PAS de NAC
    gi1_0_2 = next((p for p in ports if p.port == "Gi1/0/2"), None)
    if gi1_0_2:
        if not gi1_0_2.nac_enabled:
            print("✓ Gi1/0/2 NAC enabled = False (correct, pas dans show dot1x all)")
        else:
            errors.append("ERREUR: Gi1/0/2 ne devrait PAS avoir NAC enabled")
        
        if gi1_0_2.oper_status == "down":
            print("✓ Gi1/0/2 oper_status = down")
        else:
            errors.append(f"ERREUR: Gi1/0/2 oper_status attendu down, trouvé {gi1_0_2.oper_status}")
    else:
        errors.append("ERREUR: Gi1/0/2 non trouvé")
    
    # Vérifier Gi1/0/3
    gi1_0_3 = next((p for p in ports if p.port == "Gi1/0/3"), None)
    if gi1_0_3:
        if gi1_0_3.nac_enabled:
            print("✓ Gi1/0/3 NAC enabled = True")
        else:
            errors.append("ERREUR: Gi1/0/3 devrait avoir NAC enabled")
        
        if gi1_0_3.vlan == "150":
            print("✓ Gi1/0/3 VLAN = 150")
        else:
            errors.append(f"ERREUR: Gi1/0/3 VLAN attendu 150, trouvé {gi1_0_3.vlan}")
    else:
        errors.append("ERREUR: Gi1/0/3 non trouvé")
    
    # Vérifier Tw1/0/10 - Test du préfixe Tw et description avec espaces
    tw1_0_10 = next((p for p in ports if p.port == "Tw1/0/10"), None)
    if tw1_0_10:
        print("✓ Tw1/0/10 trouvé (préfixe Tw reconnu)")
        
        if tw1_0_10.vlan == "1098":
            print("✓ Tw1/0/10 VLAN = 1098")
        else:
            errors.append(f"ERREUR: Tw1/0/10 VLAN attendu 1098, trouvé {tw1_0_10.vlan}")
        
        if tw1_0_10.oper_status == "up":
            print("✓ Tw1/0/10 oper_status = up")
        else:
            errors.append(f"ERREUR: Tw1/0/10 oper_status attendu up, trouvé {tw1_0_10.oper_status}")
        
        if tw1_0_10.admin_status == "up":
            print("✓ Tw1/0/10 admin_status = up")
        else:
            errors.append(f"ERREUR: Tw1/0/10 admin_status attendu up, trouvé {tw1_0_10.admin_status}")
        
        expected_desc = "||-- Management Center 02//Management0 --||"
        if tw1_0_10.description == expected_desc:
            print("✓ Tw1/0/10 description avec espaces correctement parsée")
        else:
            errors.append(f"ERREUR: Tw1/0/10 description attendue '{expected_desc}', trouvée '{tw1_0_10.description}'")
    else:
        errors.append("ERREUR: Tw1/0/10 non trouvé")
    
    # Résultat final
    print("\n" + "=" * 60)
    if errors:
        print("ÉCHEC - Erreurs trouvées:")
        for err in errors:
            print(f"  - {err}")
        return False
    else:
        print("SUCCÈS - Tous les tests passent!")
        return True


def test_csv_export():
    """Test l'export CSV."""
    print("\n" + "=" * 60)
    print("TEST: Export CSV")
    print("=" * 60)
    
    port = PortReport(
        switch="test-switch",
        port="Gi1/0/1",
        oper_status="up",
        admin_status="up",
        description="Test port",
        mac_address="0011.2233.4455",
        vlan="100",
        voice_vlan="200",
        domain="data",
        nac_enabled=True
    )
    
    row = port.to_csv_row()
    
    expected_keys = [
        "switch", "port", "oper_status", "admin_status", "description",
        "mac_address", "vlan", "voice_vlan", "domain", "nac_enabled"
    ]
    
    errors = []
    
    for key in expected_keys:
        if key not in row:
            errors.append(f"Clé manquante: {key}")
    
    if row.get("nac_enabled") != "yes":
        errors.append(f"nac_enabled devrait être 'yes', trouvé: {row.get('nac_enabled')}")
    
    if errors:
        print("ÉCHEC:")
        for err in errors:
            print(f"  - {err}")
        return False
    else:
        print("✓ Export CSV correct")
        print(f"  Row: {row}")
        return True


def test_interface_normalization():
    """Test la normalisation des noms d'interface."""
    print("\n" + "=" * 60)
    print("TEST: Normalisation des interfaces")
    print("=" * 60)
    
    # Créer un parser vide pour accéder à la méthode
    raw_data = RawSwitchData()
    parser = SwitchParser("test", raw_data)
    
    test_cases = [
        # Ethernet standards
        ("GigabitEthernet1/0/1", "Gi1/0/1"),
        ("FastEthernet0/1", "Fa0/1"),
        ("Ethernet1/1", "Eth1/1"),
        
        # Châssis modulaires (4500, 6500, 6800) - format 2 segments
        ("GigabitEthernet0/1", "Gi0/1"),
        ("GigabitEthernet3/25", "Gi3/25"),
        ("TenGigabitEthernet1/1", "Te1/1"),
        ("Gi0/1", "Gi0/1"),  # Déjà court
        ("Gi3/48", "Gi3/48"),
        
        # Multi-Gigabit (mGig)
        ("TwoGigabitEthernet1/0/10", "Tw1/0/10"),
        ("FiveGigabitEthernet1/0/5", "Fi1/0/5"),
        
        # High-speed
        ("TenGigabitEthernet1/1/1", "Te1/1/1"),
        ("TwentyFiveGigE1/0/1", "Twe1/0/1"),
        ("FortyGigabitEthernet1/1/1", "Fo1/1/1"),
        ("HundredGigE1/0/49", "Hu1/0/49"),
        
        # App hosting
        ("AppGigabitEthernet1/0/1", "Ap1/0/1"),
        
        # Port-channel
        ("Port-channel1", "Po1"),
        ("Port-channel10", "Po10"),
        ("Po1", "Po1"),
        
        # Déjà normalisés
        ("Gi1/0/1", "Gi1/0/1"),
        ("Tw1/0/10", "Tw1/0/10"),
        ("Te1/1/1", "Te1/1/1"),
        
        # Avec espaces
        ("  Gi1/0/1  ", "Gi1/0/1"),
    ]
    
    errors = []
    
    for input_val, expected in test_cases:
        result = parser._normalize_interface(input_val)
        if result == expected:
            print(f"✓ {input_val} -> {result}")
        else:
            errors.append(f"{input_val}: attendu {expected}, obtenu {result}")
    
    if errors:
        print("ÉCHEC:")
        for err in errors:
            print(f"  - {err}")
        return False
    else:
        print("✓ Normalisation OK")
        return True


def test_cli():
    """Test que la CLI fonctionne."""
    print("\n" + "=" * 60)
    print("TEST: CLI --help")
    print("=" * 60)
    
    import subprocess
    result = subprocess.run(
        ["python3", "nac_audit.py", "--help"],
        capture_output=True,
        text=True
    )
    
    if result.returncode == 0 and "NAC" in result.stdout:
        print("✓ CLI fonctionne")
        print(f"  (première ligne: {result.stdout.splitlines()[0]})")
        return True
    else:
        print(f"ÉCHEC: returncode={result.returncode}")
        print(f"  stdout: {result.stdout[:200]}")
        print(f"  stderr: {result.stderr[:200]}")
        return False


def test_env_credentials():
    """Test la gestion des credentials via variables d'environnement."""
    print("\n" + "=" * 60)
    print("TEST: Credentials via environnement")
    print("=" * 60)
    
    import os
    
    # Simuler les variables d'environnement
    os.environ["NAC_AUDIT_USERNAME"] = "test_user"
    os.environ["NAC_AUDIT_PASSWORD"] = "test_pass"
    
    # Vérifier qu'elles sont accessibles
    username = os.getenv("NAC_AUDIT_USERNAME")
    password = os.getenv("NAC_AUDIT_PASSWORD")
    
    # Nettoyer
    del os.environ["NAC_AUDIT_USERNAME"]
    del os.environ["NAC_AUDIT_PASSWORD"]
    
    if username == "test_user" and password == "test_pass":
        print("✓ Variables d'environnement fonctionnent")
        return True
    else:
        print(f"ÉCHEC: username={username}, password={'***' if password else None}")
        return False


def test_dotenv_loading():
    """Test le chargement du fichier .env."""
    print("\n" + "=" * 60)
    print("TEST: Chargement .env")
    print("=" * 60)
    
    import os
    from pathlib import Path
    from dotenv import load_dotenv
    
    # Créer un fichier .env temporaire
    env_content = """NAC_AUDIT_USERNAME=dotenv_user
NAC_AUDIT_PASSWORD=dotenv_pass
"""
    test_env_file = Path("test_temp.env")
    test_env_file.write_text(env_content)
    
    try:
        # Charger le fichier
        load_dotenv(test_env_file, override=True)
        
        username = os.getenv("NAC_AUDIT_USERNAME")
        password = os.getenv("NAC_AUDIT_PASSWORD")
        
        if username == "dotenv_user" and password == "dotenv_pass":
            print("✓ Chargement .env fonctionne")
            result = True
        else:
            print(f"ÉCHEC: username={username}, password={'***' if password else None}")
            result = False
    finally:
        # Nettoyer
        test_env_file.unlink()
        if "NAC_AUDIT_USERNAME" in os.environ:
            del os.environ["NAC_AUDIT_USERNAME"]
        if "NAC_AUDIT_PASSWORD" in os.environ:
            del os.environ["NAC_AUDIT_PASSWORD"]
    
    return result


def main():
    """Exécute tous les tests."""
    print("\n" + "=" * 60)
    print("NAC AUDIT TOOL - TESTS")
    print("=" * 60)
    
    results = []
    
    results.append(("Normalisation interfaces", test_interface_normalization()))
    results.append(("Parser", test_parser()))
    results.append(("Export CSV", test_csv_export()))
    results.append(("CLI", test_cli()))
    results.append(("Variables environnement", test_env_credentials()))
    results.append(("Chargement .env", test_dotenv_loading()))
    
    # Résumé
    print("\n" + "=" * 60)
    print("RÉSUMÉ DES TESTS")
    print("=" * 60)
    
    passed = 0
    failed = 0
    
    for name, success in results:
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"  {status} - {name}")
        if success:
            passed += 1
        else:
            failed += 1
    
    print(f"\nTotal: {passed} passés, {failed} échoués")
    
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
