# 🛡️ AV-Shield — Antivirus Multi-Couches

> Antivirus développé en **langage C** avec une **interface web Flask**, combinant 4 couches de détection indépendantes pour une analyse complète des fichiers malveillants.

---

##  Présentation

AV-Shield est un antivirus complet développé from scratch en C, intégrant une interface web moderne pour faciliter l'utilisation. Il repose sur **4 couches de détection complémentaires** qui permettent d'identifier aussi bien les menaces connues que les menaces inconnues (zero-day).

---

## Architecture du Projet

```
av-shield/
├── src/                        # Code source C
│   ├── main.c                  # Point d'entrée principal
│   ├── scanner.c               # Orchestrateur du scan multi-couches
│   ├── clamav_engine.c         # Couche 1 : intégration ClamAV
│   ├── hash.c                  # Couche 2 : calcul SHA256
│   ├── heuristic.c             # Couche 3 : analyse heuristique
│   ├── entropy.c               # Couche 4 : calcul d'entropie
│   ├── quarantine.c            # Gestion de la quarantaine
│   ├── report.c                # Génération des rapports JSON/HTML
│   ├── database.c              # Base de données SQLite
│   ├── logger.c                # Journalisation des événements
│   └── correlation.c           # Corrélation des résultats multi-couches
├── include/                    # Fichiers d'en-tête (.h)
├── web/
│   ├── app.py                  # Serveur Flask — API REST + routes
│   ├── templates/              # Pages HTML (Jinja2)
│   │   ├── index.html          # Dashboard principal
│   │   ├── scan.html           # Page de scan
│   │   ├── quarantine.html     # Gestion quarantaine
│   │   └── reports.html        # Consultation des rapports
│   └── static/
│       ├── css/style.css       # Styles de l'interface
│       └── js/main.js          # JavaScript frontend
├── database/
│   └── avshield.db             # Base SQLite (historique, menaces, quarantaine)
├── quarantine/                 # Fichiers isolés (.quar)
├── reports/                    # Rapports générés (JSON + HTML)
├── logs/                       # Journaux d'événements
├── avshield                    # Binaire compilé
└── Makefile                    # Compilation du projet
```

---

##  Les 4 Couches de Détection

### 🔴 Couche 1 — ClamAV (Détection par Signatures)
ClamAV est un moteur antivirus open-source intégré via sa bibliothèque `libclamav`. Il compare chaque fichier à une base de **plus de 3,6 millions de signatures virales** connues.

- **Type** : Détection par signatures
- **Avantage** : Très efficace contre les malwares connus (virus, trojans, ransomwares référencés)
- **Résultat possible** : `MALWARE` si une signature correspond
- **Exemple** : détecte `Eicar-Signature` (fichier de test antivirus standard)

---

### 🔵 Couche 2 — SHA256 (Détection par Hash)
Chaque fichier scanné est haché avec l'algorithme **SHA-256**, qui produit une empreinte unique de 256 bits. Ce hash est comparé à une base de hashes malveillants connus.

- **Type** : Détection par empreinte cryptographique
- **Avantage** : Détection exacte et infalsifiable — même si le nom du fichier change, le hash reste identique
- **Résultat possible** : `MALWARE` si le hash est dans la base de menaces connues
- **Utilité** : Complémentaire à ClamAV pour les malwares non couverts par les signatures textuelles

---

### 🟡 Couche 3 — Heuristique (Détection Comportementale)
L'analyse heuristique examine le **contenu et la structure** du fichier à la recherche de **43 indicateurs IoC** (Indicators of Compromise) suspects : appels système dangereux, patterns de code malveillant, instructions réseau suspectes, etc.

- **Type** : Analyse statique comportementale
- **Avantage** : Peut détecter des **menaces inconnues (zero-day)** non présentes dans les bases de signatures
- **Score** : Un score heuristique est calculé — plus il est élevé, plus le fichier est suspect
- **Résultat possible** : `SUSPICIOUS` si le score dépasse un seuil défini
- **Exemple** : détecte un script Python contenant des appels à `subprocess`, `os.system`, chiffrement de fichiers, etc.

---

### 🟠 Couche 4 — Entropie (Détection de Chiffrement/Packing)
L'entropie de Shannon mesure le **niveau de désordre** dans les données d'un fichier. Un fichier très chiffré ou compressé (packé) aura une entropie proche de **8.0 bits/octet**.

- **Type** : Analyse statistique du contenu binaire
- **Avantage** : Détecte les ransomwares, les malwares packés et les fichiers obfusqués que les autres couches ne voient pas
- **Formule** : `H = -Σ p(x) * log2(p(x))`
- **Résultat possible** : `SUSPICIOUS` si l'entropie dépasse le seuil (généralement > 7.0)
- **Exemple** : un ransomware qui chiffre ses données aura une entropie très élevée

---

##  Corrélation des Couches

Les résultats des 4 couches sont **corrélés** pour produire un verdict final :

| ClamAV | SHA256 | Heuristique | Entropie | Verdict Final |
|--------|--------|-------------|----------|---------------|
|  CLEAN |  CLEAN | Score faible | Normale |  **CLEAN** |
|  CLEAN |  CLEAN | Score élevé | Élevée | **SUSPICIOUS** |
|  DÉTECTÉ | — | — | — | **MALWARE** |
|  CLEAN |  DÉTECTÉ | — | — | **MALWARE** |

---

##  Interface Web

L'interface web est développée avec **Flask (Python)** et expose une API REST consommée par le frontend.

### Pages disponibles :
| Page | URL | Description |
|------|-----|-------------|
| Dashboard | `/` | Statistiques globales, derniers scans et menaces |
| Scanner | `/scan` | Lancer un scan sur un fichier ou dossier |
| Quarantaine | `/quarantine` | Gérer les fichiers isolés (restaurer/supprimer) |
| Rapports | `/reports-page` | Consulter et télécharger les rapports JSON/HTML |

### API REST :
| Méthode | Endpoint | Description |
|---------|----------|-------------|
| POST | `/api/scan` | Lancer un scan |
| GET | `/api/stats` | Statistiques globales |
| GET | `/api/quarantine` | Liste des fichiers en quarantaine |
| POST | `/api/quarantine/restore` | Restaurer un fichier |
| POST | `/api/quarantine/delete` | Supprimer un fichier |
| GET | `/api/reports` | Liste des rapports |
| GET | `/api/history` | Historique des scans |

---

## Prérequis

```bash
# Dépendances système
sudo apt install gcc make libclamav-dev python3 python3-pip sqlite3

# Dépendances Python
pip3 install flask flask-cors
```

---

##  Installation et Lancement

**1. Cloner le projet :**
```bash
git clone https://github.com/fatima-hub03/av-shield.git
cd av-shield
```

**2. Compiler le binaire C :**
```bash
make
```

**3. Lancer l'interface web :**
```bash
python3 web/app.py
```

**4. Ouvrir dans le navigateur :**
```
http://localhost:5000 ou bien http://127.0.0.1:5000/
---

##  Format des Rapports JSON

```json
{
  "av_shield": "AV-Shield v1.0.0",
  "report_id": "SCAN_20260305_091553",
  "scan_target": "/chemin/fichier",
  "statistics": {
    "total_files": 1,
    "clean_files": 0,
    "suspicious_files": 0,
    "malware_files": 1
  },
  "files": [
    {
      "filename": "test.com",
      "result": "MALWARE",
      "threat": "Eicar-Signature",
      "heuristic_score": 0,
      "entropy": 0.0,
      "sha256": "131f95c51cc819...",
      "quarantined": true
    }
  ]
}
```

---

##  Technologies Utilisées

| Composant | Technologie |
|-----------|-------------|
| Moteur antivirus | C (GCC) |
| Détection signatures | libclamav |
| Hachage | SHA-256 (implémentation C) |
| Base de données | SQLite3 |
| Interface web | Python Flask |
| Frontend | HTML5, CSS3, JavaScript |

---

## Auteur

**Fatima** — [@fatima-hub03](https://github.com/fatima-hub03)
