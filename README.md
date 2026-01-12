# 🔐 iAnonymiser

Application web pour anonymiser vos logs, fichiers de configuration et autres données sensibles avant de les partager avec une IA.

![Version](https://img.shields.io/badge/version-3.2.0-blue)
![Python](https://img.shields.io/badge/python-3.12+-green)
![Docker](https://img.shields.io/badge/docker-ready-blue)

> 📋 Voir le [CHANGELOG](CHANGELOG.md) pour l'historique des versions

---

## ✨ Fonctionnalités

### 🔍 Détection automatique

| Catégorie | Types détectés |
|-----------|----------------|
| **Réseau** | IPv4, IPv6 (toutes formes), adresses MAC |
| **Identité** | Emails, usernames, numéros de téléphone (FR/US/intl) |
| **Infrastructure** | Hostnames, URLs, chemins Windows/Unix, noms de serveurs |
| **Identifiants** | UUIDs, clés API, JWT, clés privées, connection strings |
| **Finance** | Cartes bancaires (Luhn), IBAN, SSN (FR/US) |
| **Données** | Dates, patterns personnalisés |

### 🚀 Enhancers - Détection avancée (v3.2.0)

Intégration de bibliothèques Python spécialisées pour une détection encore plus précise :

| Enhancer | Description | Cas d'usage |
|----------|-------------|-------------|
| **Presidio** | NER via spaCy (Microsoft) | Noms de personnes, organisations, lieux |
| **tldextract** | Public Suffix List officielle | Tous les TLDs (co.uk, com.fr, nouveaux gTLDs) |
| **LLM Guard** | Scanners sécurité LLM | Secrets, PII dans les prompts |

### ⚡ Fonctionnalités avancées

- 🎨 **Interface unifiée** avec toggle Édition/Détection/Anonymisé
- 📦 **8 Presets prédéfinis** (Ansible, Apache, K8s, AWS, etc.)
- 🔍 **Preview en temps réel** avec highlighting coloré
- 💾 **Sauvegarde de session** persistante
- 🔄 **Anonymisation cohérente** (même valeur = même placeholder)
- ⚙️ **Patterns personnalisés** (regex)
- 🛡️ **Liste de préservation**
- 📥 **Export JSON/TXT** des mappings
- ⚡ **Regex précompilées** pour des performances optimales

---

## 🐳 Déploiement Docker (Recommandé)

### Méthode rapide avec Docker Compose

```bash
# Cloner le repo
git clone https://github.com/Vanti7/iAnonymiser
cd ianonymiser

# Lancer l'application
docker-compose up -d

# Vérifier que ça tourne
docker-compose ps
docker-compose logs -f
```

L'application sera disponible sur **http://votre-serveur:5000**

### Méthode manuelle avec Docker

```bash
# Construire l'image
docker build -t ianonymiser:latest .

# Lancer le container
docker run -d \
  --name ianonymiser \
  --restart unless-stopped \
  -p 5000:5000 \
  ianonymiser:latest

# Vérifier les logs
docker logs -f ianonymiser
```

### Avec un reverse proxy (Traefik)

Décommentez les labels dans `docker-compose.yml` et adaptez le domaine :

```yaml
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.ianonymiser.rule=Host(`anonymiser.votredomaine.com`)"
  - "traefik.http.routers.ianonymiser.entrypoints=websecure"
  - "traefik.http.routers.ianonymiser.tls.certresolver=letsencrypt"
```

---

## 💻 Installation locale

### Installation minimale

```bash
# Créer un environnement virtuel
python -m venv venv

# Activer l'environnement
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Installer les dépendances de base
pip install flask gunicorn

# Lancer en mode développement
python app.py
```

### Installation complète (avec Enhancers)

```bash
# Installer toutes les dépendances
pip install -r requirements.txt

# Installer les modèles spaCy pour Presidio
python -m spacy download fr_core_news_sm
python -m spacy download en_core_web_sm
```

Ouvrez [http://localhost:5000](http://localhost:5000)

---

## 🔌 API Enhancers

### Endpoints

```bash
# Lister les enhancers et leur statut
GET /enhancers

# Activer/désactiver un enhancer
POST /enhancers/<name>
{
  "enabled": true,
  "config": {
    "confidence_threshold": 0.7,
    "languages": ["fr", "en"]
  }
}

# Activer tous les enhancers disponibles
POST /enhancers/enable-all

# Désactiver tous les enhancers
POST /enhancers/disable-all
```

### Utilisation en Python

```python
from core import Anonymizer

anon = Anonymizer()

# Activer Presidio pour la détection NER
anon.set_enhancer_enabled('presidio', True, {
    'confidence_threshold': 0.7,
    'languages': ['fr', 'en']
})

# Activer tldextract pour les domaines
anon.set_enhancer_enabled('tldextract', True)

# Vérifier le statut des enhancers
print(anon.get_enhancers_status())

result = anon.anonymize(mon_texte)
```

---

## 📦 Presets disponibles

| Preset | Description | Patterns activés |
|--------|-------------|------------------|
| **Par défaut** | Configuration standard | IPs, emails, URLs, UUIDs, tokens, usernames, serveurs |
| **Ansible** | Logs Ansible/SSH/Infrastructure | IPs, hostnames, chemins, usernames, serveurs |
| **Apache/Nginx** | Logs serveurs web | IPs, URLs, hostnames, usernames |
| **Kubernetes** | Logs K8s et Docker | IPs, pods, namespaces, hostnames, serveurs |
| **AWS CloudWatch** | Logs AWS | ARN, EC2, SG, VPC, access keys |
| **Base de données** | Logs SQL | IPs, connection strings, hostnames |
| **Audit Sécurité** | Mode paranoïaque | TOUS les patterns |
| **Minimal** | Essentiel uniquement | IPs et emails |

---

## ⌨️ Raccourcis clavier

| Raccourci | Action |
|-----------|--------|
| `Ctrl + Enter` | Anonymiser |
| `Ctrl + Shift + C` | Copier le résultat |

---

## 🔧 Utilisation CLI

```python
from core import Anonymizer, PatternType
from core.anonymizer import anonymize_text

# Utilisation simple
result = anonymize_text("""
Connection from 192.168.1.100
User: john.doe@company.com
Server: havas-esx-08.havas.esx
Path: C:\\Users\\admin\\config.json
""")
print(result.anonymized_text)
# Connection from [IP_001]
# User: [EMAIL_001]
# Server: [HOST_001]
# Path: [PATH_001]

# Avec un preset
result = anonymize_text(log_text, preset="kubernetes")

# Utilisation avancée
anon = Anonymizer()
anon.load_preset("aws")
anon.add_preserve_value("localhost")
anon.add_custom_pattern(r'SRV-[A-Z0-9]+', 'SERVER')

result = anon.anonymize(mon_texte)
original = anon.deanonymize(result.anonymized_text)
```

---

## 🏗️ Architecture

```
ianonymiser/
├── app.py                      # Point d'entrée Flask
│
├── core/                       # 🧠 Moteur d'anonymisation
│   ├── models.py               # Enums (PatternType) et Dataclasses
│   └── anonymizer.py           # Classe Anonymizer principale
│
├── enhancers/                  # 🚀 Enhancers de détection (v3.2.0)
│   ├── __init__.py             # Registry et factory
│   ├── base.py                 # Classe de base abstraite
│   ├── presidio_enhancer.py    # Microsoft Presidio (NER)
│   ├── tldextract_enhancer.py  # Extraction domaines/TLD
│   └── llm_guard_enhancer.py   # LLM Guard (secrets/PII)
│
├── patterns/                   # 🔍 Patterns de détection
│   ├── base.py                 # Regex par défaut et préfixes
│   └── colors.py               # Couleurs pour le highlighting
│
├── presets/                    # ⚙️ Presets en JSON
│   ├── loader.py               # Chargeur dynamique de presets
│   ├── default.json            # Preset par défaut
│   ├── ansible.json            # Preset Ansible/Infrastructure
│   ├── apache.json             # Preset Apache/Nginx
│   ├── aws.json                # Preset AWS CloudWatch
│   ├── database.json           # Preset Base de données
│   ├── kubernetes.json         # Preset Kubernetes
│   ├── minimal.json            # Preset minimal
│   ├── security.json           # Preset Audit Sécurité
│   └── preset.json.example     # Template pour créer un preset
│
├── api/                        # 🌐 Routes API Flask
│   └── routes.py
│
├── config/                     # 📝 Configuration
│   └── settings.py             # VERSION, Config classes, Enhancers
│
├── templates/
│   └── index.html              # Interface web
│
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── CHANGELOG.md
└── README.md
```

### Créer un preset personnalisé

Créez un fichier JSON dans `presets/` en suivant ce template :

```json
{
    "id": "mon_preset",
    "name": "Mon Preset",
    "description": "Description du preset",
    "patterns": ["ipv4", "email", "hostname"],
    "preserve": ["localhost"],
    "custom_patterns": [
        {"regex": "MON-PATTERN-[0-9]+", "prefix": "CUSTOM"}
    ]
}
```

Le preset sera automatiquement chargé au prochain démarrage.

---

## 🔒 Sécurité

- ✅ Toutes les données sont traitées **localement**
- ✅ Aucune donnée n'est envoyée à un serveur externe
- ✅ Container Docker avec utilisateur non-root
- ✅ Health checks intégrés
- ✅ Limites de ressources configurables
- ✅ Enhancers optionnels (fonctionnement dégradé si non installés)

---

## 📊 Dépendances

### Requises
- `flask>=3.0.0`
- `gunicorn>=21.0.0`

### Optionnelles (Enhancers)
- `presidio-analyzer>=2.2.0` + `presidio-anonymizer>=2.2.0`
- `tldextract>=5.1.0`
- `llm-guard>=0.3.0`
- Modèles spaCy : `fr_core_news_sm`, `en_core_web_sm`

---

## 🤝 Contribution

Les contributions sont les bienvenues ! N'hésitez pas à ouvrir une issue ou une PR.

---

## 📝 Licence

MIT License - Utilisez librement !
