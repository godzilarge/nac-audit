#!/usr/bin/env python3
"""
NAC/802.1x Audit Tool for Cisco Switches

Audite les configurations NAC sur des switches Cisco IOS/IOS-XE.
Compare tous les ports switchport avec les ports dot1x pour identifier
les ports sans NAC.

Usage:
    python nac_audit.py -i switches.csv -o report.csv
    python nac_audit.py -i switches.csv -o report.csv -w 20 -t 60

Arguments:
    -i, --input     Fichier CSV d'inventaire (hostname,ip)
    -o, --output    Fichier CSV de sortie
    -w, --workers   Nombre de workers parallèles (défaut: 10)
    -t, --timeout   Timeout connexion en secondes (défaut: 30)
"""

import argparse
import csv
import getpass
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

from models import SwitchInventory, PortReport
from collector import SwitchCollector, ConnectionError
from parser import SwitchParser


# Charger le fichier .env s'il existe
load_dotenv()


def setup_logging(log_dir: Path) -> tuple[logging.Logger, Path]:
    """
    Configure le logging vers console et fichier.
    
    Returns:
        tuple: (logger, chemin du fichier log)
    """
    log_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"nac_audit_{timestamp}.log"
    
    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    
    # File handler - tout
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    
    # Console handler - INFO et plus
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    
    logger = logging.getLogger("nac_audit")
    logger.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger, log_file


def load_inventory(csv_path: Path, logger: logging.Logger) -> list[SwitchInventory]:
    """
    Charge l'inventaire depuis un fichier CSV.
    
    Formats supportés:
        hostname,ip
        switch-01,192.168.1.10
    
    Les noms de colonnes flexibles: hostname/name/switch, ip/ip_address/host
    """
    switches = []
    
    try:
        with open(csv_path, newline="", encoding="utf-8") as f:
            # Détecter le header
            sample = f.read(2048)
            f.seek(0)
            
            try:
                has_header = csv.Sniffer().has_header(sample)
            except csv.Error:
                has_header = True  # Assumer qu'il y a un header
            
            if has_header:
                reader = csv.DictReader(f)
                for row in reader:
                    # Colonnes flexibles
                    hostname = (
                        row.get("hostname") or 
                        row.get("name") or 
                        row.get("switch") or 
                        ""
                    ).strip()
                    
                    ip = (
                        row.get("ip") or 
                        row.get("ip_address") or 
                        row.get("host") or
                        row.get("address") or
                        ""
                    ).strip()
                    
                    if hostname and ip:
                        switches.append(SwitchInventory(hostname=hostname, ip=ip))
                    else:
                        logger.warning(f"Ligne ignorée (données manquantes): {row}")
            else:
                reader = csv.reader(f)
                for row in reader:
                    if len(row) >= 2:
                        switches.append(
                            SwitchInventory(hostname=row[0].strip(), ip=row[1].strip())
                        )
    
    except FileNotFoundError:
        logger.error(f"Fichier non trouvé: {csv_path}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Erreur lecture CSV: {e}")
        sys.exit(1)
    
    return switches


def audit_switch(
    switch: SwitchInventory,
    username: str,
    password: str,
    timeout: int,
    logger: logging.Logger
) -> tuple[SwitchInventory, list[PortReport] | None, str | None]:
    """
    Audite un switch.
    
    Returns:
        tuple: (switch, liste des ports ou None, message d'erreur ou None)
    """
    logger.info(f"[{switch.hostname}] Connexion à {switch.ip}...")
    
    collector = None
    try:
        collector = SwitchCollector(
            hostname=switch.hostname,
            ip=switch.ip,
            username=username,
            password=password,
            timeout=timeout
        )
        
        raw_data = collector.collect_all()
        collector.disconnect()
        
        parser = SwitchParser(switch.hostname, raw_data)
        ports = parser.parse_all()
        
        logger.info(f"[{switch.hostname}] OK - {len(ports)} ports collectés")
        return (switch, ports, None)
        
    except ConnectionError as e:
        error_msg = str(e)
        logger.error(f"[{switch.hostname}] Connexion échouée: {error_msg}")
        return (switch, None, error_msg)
        
    except Exception as e:
        error_msg = str(e)
        logger.exception(f"[{switch.hostname}] Erreur: {error_msg}")
        return (switch, None, error_msg)
        
    finally:
        if collector:
            collector.disconnect()


def write_csv_report(ports: list[PortReport], output_path: Path) -> None:
    """Écrit le rapport CSV."""
    fieldnames = [
        "switch",
        "port",
        "oper_status",
        "admin_status",
        "description",
        "port_mode",
        "mac_address",
        "vlan",
        "voice_vlan",
        "domain",
        "nac_enabled",
        "nac_version",
        "cdp_neighbor",
        "lldp_neighbor",
    ]
    
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for port in ports:
            writer.writerow(port.to_csv_row())


def write_failed_switches(
    failed: list[tuple[SwitchInventory, str]], 
    output_dir: Path,
    timestamp: str
) -> Path:
    """Écrit le fichier des switches non joignables."""
    output_path = output_dir / f"failed_switches_{timestamp}.csv"
    
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["hostname", "ip", "error"])
        
        for switch, error in failed:
            writer.writerow([switch.hostname, switch.ip, error])
    
    return output_path


def main():
    """Point d'entrée principal."""
    arg_parser = argparse.ArgumentParser(
        description="Audit NAC/802.1x sur switches Cisco",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemple:
    python nac_audit.py -i switches.csv -o rapport.csv
    python nac_audit.py -i switches.csv -o rapport.csv -w 20 -t 60

Format du fichier d'entrée (CSV avec header):
    hostname,ip
    switch-core-01,192.168.1.10
    switch-access-01,192.168.1.11
        """
    )
    
    arg_parser.add_argument(
        "-i", "--input",
        required=True,
        type=Path,
        help="Fichier CSV d'inventaire des switches"
    )
    
    arg_parser.add_argument(
        "-o", "--output",
        required=True,
        type=Path,
        help="Fichier CSV de sortie pour le rapport"
    )
    
    arg_parser.add_argument(
        "-w", "--workers",
        type=int,
        default=10,
        help="Nombre de workers parallèles (défaut: 10)"
    )
    
    arg_parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=30,
        help="Timeout de connexion en secondes (défaut: 30)"
    )
    
    arg_parser.add_argument(
        "-u", "--username",
        type=str,
        help="Username SSH (ou variable NAC_AUDIT_USERNAME)"
    )
    
    arg_parser.add_argument(
        "-p", "--password",
        type=str,
        help="Password SSH (non recommandé, préférer NAC_AUDIT_PASSWORD ou .env)"
    )
    
    arg_parser.add_argument(
        "-e", "--env-file",
        type=Path,
        default=None,
        help="Fichier .env alternatif (défaut: .env dans le répertoire courant)"
    )
    
    arg_parser.add_argument(
        "-l", "--log-dir",
        type=Path,
        default=Path("./logs"),
        help="Répertoire pour les fichiers de log (défaut: ./logs)"
    )
    
    args = arg_parser.parse_args()
    
    # Charger le fichier .env alternatif si spécifié
    if args.env_file:
        if args.env_file.exists():
            load_dotenv(args.env_file, override=True)
        else:
            print(f"Erreur: Fichier .env non trouvé: {args.env_file}", file=sys.stderr)
            sys.exit(1)
    
    # Setup logging
    logger, log_file = setup_logging(args.log_dir)
    logger.info("=" * 60)
    logger.info("NAC Audit Tool - Démarrage")
    logger.info("=" * 60)
    
    # Charger l'inventaire
    switches = load_inventory(args.input, logger)
    if not switches:
        logger.error("Aucun switch dans l'inventaire")
        sys.exit(1)
    
    logger.info(f"Inventaire chargé: {len(switches)} switches")
    
    # Credentials (priorité: CLI > env > prompt)
    username = (
        args.username 
        or os.getenv("NAC_AUDIT_USERNAME") 
        or input("Username: ")
    )
    
    password = (
        args.password 
        or os.getenv("NAC_AUDIT_PASSWORD") 
        or getpass.getpass("Password: ")
    )
    
    # Log source des credentials (sans révéler les valeurs)
    if args.username:
        logger.debug("Username: fourni via CLI")
    elif os.getenv("NAC_AUDIT_USERNAME"):
        logger.debug("Username: fourni via variable d'environnement")
    else:
        logger.debug("Username: fourni via prompt")
    
    if args.password:
        logger.warning("Password fourni via CLI - non recommandé pour la sécurité")
    elif os.getenv("NAC_AUDIT_PASSWORD"):
        logger.debug("Password: fourni via variable d'environnement")
    else:
        logger.debug("Password: fourni via prompt")
    
    # Audit parallèle
    all_ports: list[PortReport] = []
    failed_switches: list[tuple[SwitchInventory, str]] = []
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    logger.info(f"Démarrage de l'audit avec {args.workers} workers...")
    
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(
                audit_switch, 
                switch, 
                username, 
                password, 
                args.timeout,
                logger
            ): switch
            for switch in switches
        }
        
        completed = 0
        total = len(switches)
        
        for future in as_completed(futures):
            completed += 1
            switch, ports, error = future.result()
            
            if error:
                failed_switches.append((switch, error))
            elif ports:
                all_ports.extend(ports)
            
            # Progress
            logger.info(f"Progression: {completed}/{total} switches traités")
    
    # Écrire le rapport principal
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_csv_report(all_ports, args.output)
    logger.info(f"Rapport généré: {args.output} ({len(all_ports)} ports)")
    
    # Écrire les switches en échec
    if failed_switches:
        failed_file = write_failed_switches(
            failed_switches, 
            args.output.parent,
            timestamp
        )
        logger.warning(
            f"Switches non joignables: {len(failed_switches)} "
            f"(voir {failed_file})"
        )
    
    # Résumé
    logger.info("=" * 60)
    logger.info("Résumé:")
    logger.info(f"  - Switches traités: {len(switches) - len(failed_switches)}/{len(switches)}")
    logger.info(f"  - Ports audités: {len(all_ports)}")
    
    nac_enabled = sum(1 for p in all_ports if p.nac_enabled)
    nac_disabled = len(all_ports) - nac_enabled
    logger.info(f"  - Ports avec NAC: {nac_enabled}")
    logger.info(f"  - Ports sans NAC: {nac_disabled}")
    
    logger.info(f"  - Rapport: {args.output}")
    logger.info(f"  - Log: {log_file}")
    logger.info("=" * 60)
    
    # Code de sortie
    if failed_switches:
        sys.exit(2)  # Succès partiel
    sys.exit(0)


if __name__ == "__main__":
    main()
