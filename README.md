# 🔐 iAnonymiser

Application web pour anonymiser vos logs, fichiers de configuration et autres données sensibles avant de les partager avec une IA.

![Version](https://img.shields.io/badge/version-2.1.0-blue)
![Python](https://img.shields.io/badge/python-3.12+-green)
![Docker](https://img.shields.io/badge/docker-ready-blue)

> 📋 Voir le [CHANGELOG](CHANGELOG.md) pour l'historique des versions

## ✨ Fonctionnalités

### Détection automatique
- **Adresses IP** (IPv4 et IPv6 - toutes formes compressées)
- **Adresses email**
- **Noms de domaine / hostnames** (TLDs étendus)
- **URLs**
- **Chemins de fichiers** (Windows et Unix)
- **UUIDs**
- **Adresses MAC**
- **Numéros de téléphone** (internationaux - FR, US, et plus)
- **Clés API / Tokens / JWT** (OpenAI, GitHub, Slack, Google...)
- **Numéros de carte bancaire** (avec validation Luhn)
- **IBAN**
- **Numéros de sécurité sociale** (FR et US)
- **Clés privées**
- **Connection strings**
- **Dates**
- **Noms d'utilisateurs** (u=xxx, user@ip, etc.) 🆕
- **Noms de serveurs** (patterns Ansible, K8s, etc.) 🆕

### Fonctionnalités avancées
- 🔍 **Preview en temps réel** avec highlighting coloré
- 📦 **8 Presets prédéfinis** (Ansible, Apache, K8s, AWS, etc.)
- 👁️ **Vue côte-à-côte** ou empilée
- 💾 **Sauvegarde de session** persistante
- 🔄 **Anonymisation cohérente** (même valeur = même placeholder)
- ⚙️ **Patterns personnalisés** (regex)
- 🛡️ **Liste de préservation**
- 📥 **Export JSON/TXT** des mappings
- ⚡ **Regex précompilées** pour des performances optimales
- 🎯 **Système de priorité** intelligent pour éviter les faux positifs

---

## 🐳 Déploiement Docker (Recommandé)

### Méthode rapide avec Docker Compose

```bash
# Cloner le repo
git clone <votre-repo>
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

### Commandes Docker utiles

```bash
# Voir les logs
docker-compose logs -f

# Redémarrer
docker-compose restart

# Mettre à jour (après un git pull)
docker-compose up -d --build

# Arrêter
docker-compose down

# Nettoyer les anciennes images
docker image prune -f
```

---

## 💻 Installation locale (Développement)

```bash
# Créer un environnement virtuel
python -m venv venv

# Activer l'environnement
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Installer les dépendances
pip install -r requirements.txt

# Lancer en mode développement
python app.py
```

Ouvrez [http://localhost:5000](http://localhost:5000)

---

## 📦 Presets disponibles

| Preset | Description | Patterns activés |
|--------|-------------|------------------|
| **Par défaut** | Configuration standard | IPs, emails, URLs, UUIDs, tokens, usernames, serveurs... |
| **Ansible** 🆕 | Logs Ansible/SSH/Infrastructure | IPs, hostnames, chemins, usernames, serveurs |
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
from anonymizer import anonymize_text, Anonymizer

# Utilisation simple
result = anonymize_text("""
Connection from 192.168.1.100
User: john.doe@company.com
""")
print(result.anonymized_text)

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
├── app.py              # Application Flask
├── anonymizer.py       # Moteur d'anonymisation
├── templates/
│   └── index.html      # Interface web
├── Dockerfile          # Image Docker
├── docker-compose.yml  # Orchestration
├── requirements.txt    # Dépendances Python
├── CHANGELOG.md        # Historique des versions
└── README.md
```

---

## 🔒 Sécurité

- ✅ Toutes les données sont traitées **localement**
- ✅ Aucune donnée n'est envoyée à un serveur externe
- ✅ Container Docker avec utilisateur non-root
- ✅ Health checks intégrés
- ✅ Limites de ressources configurables

---

## 🤝 Contribution

Les contributions sont les bienvenues ! N'hésitez pas à ouvrir une issue ou une PR.

---

## 📝 Licence

MIT License - Utilisez librement !
