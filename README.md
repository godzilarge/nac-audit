# NAC Audit Tool

Outil d'audit NAC/802.1x pour switches Cisco IOS et IOS-XE.

Identifie les ports où le NAC (dot1x) n'est pas activé en comparant tous les ports switchport avec les ports dot1x actifs.

## Plateformes supportées

- Cisco Catalyst 2960-X
- Cisco Catalyst 4500
- Cisco Catalyst 9200
- Cisco Catalyst 9300
- Tout switch IOS/IOS-XE supportant les commandes standard

## Installation

```bash
# Créer un environnement virtuel (recommandé)
python3 -m venv venv
source venv/bin/activate

# Installer les dépendances
pip install -r requirements.txt
```

## Utilisation

### Format du fichier d'inventaire

Fichier CSV avec header `hostname,ip` :

```csv
hostname,ip
switch-core-01,192.168.1.10
switch-access-01,192.168.1.11
switch-access-02,192.168.1.12
```

### Exécution

```bash
# Usage basique
python nac_audit.py -i switches.csv -o rapport.csv

# Avec plus de workers pour aller plus vite
python nac_audit.py -i switches.csv -o rapport.csv -w 20

# Avec timeout plus long (switches lents)
python nac_audit.py -i switches.csv -o rapport.csv -t 60

# Avec username en paramètre
python nac_audit.py -i switches.csv -o rapport.csv -u admin
```

### Options

| Option | Description | Défaut |
|--------|-------------|--------|
| `-i, --input` | Fichier CSV d'inventaire | (requis) |
| `-o, --output` | Fichier CSV de sortie | (requis) |
| `-w, --workers` | Nombre de workers parallèles | 10 |
| `-t, --timeout` | Timeout connexion (secondes) | 30 |
| `-u, --username` | Username SSH | (interactif) |
| `-l, --log-dir` | Répertoire des logs | ./logs |

## Sortie

### Rapport principal (CSV)

| Colonne | Description |
|---------|-------------|
| switch | Nom du switch |
| port | Nom du port (ex: Gi1/0/1) |
| oper_status | Status opérationnel (up/down) |
| admin_status | Status administratif (up/down/admin down) |
| description | Description configurée sur le port |
| mac_address | Adresse MAC connectée (si présente) |
| vlan | VLAN data |
| voice_vlan | VLAN voix (si configuré) |
| domain | Domaine de la MAC (data/voice) |
| nac_enabled | NAC activé (yes/no) |

### Fichier des échecs

Si des switches sont injoignables, un fichier `failed_switches_<timestamp>.csv` est généré avec :
- hostname
- ip  
- error (message d'erreur)

### Logs

Les logs détaillés sont dans `./logs/nac_audit_<timestamp>.log`

## Commandes Cisco utilisées

L'outil exécute ces commandes sur chaque switch :

1. `show interfaces switchport` - Liste tous les ports switchport, VLANs
2. `show interfaces status` - Status opérationnel des ports
3. `show interfaces description` - Descriptions et status admin
4. `show mac address-table` - Table MAC pour trouver les devices connectés
5. `show dot1x all` - Liste des ports avec dot1x actif

## Logique de détection NAC

Un port est considéré **sans NAC** si :
- Il apparaît dans `show interfaces switchport` (c'est un port switchport)
- Il n'apparaît **pas** dans `show dot1x all` (pas de dot1x actif)

Cette approche fonctionne que la config NAC vienne de commandes directes ou de templates (IBNS 1.0 et 2.0).

## Codes de sortie

| Code | Signification |
|------|---------------|
| 0 | Succès complet |
| 1 | Erreur fatale (fichier non trouvé, etc.) |
| 2 | Succès partiel (certains switches injoignables) |

## Structure du projet

```
nac-audit/
├── nac_audit.py      # Script principal (CLI, orchestration)
├── collector.py      # Connexion SSH et collecte des données
├── parser.py         # Parsing des outputs Cisco
├── models.py         # Modèles de données
├── requirements.txt  # Dépendances Python
└── README.md
```
