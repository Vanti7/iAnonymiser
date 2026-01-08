# Changelog

Toutes les modifications notables de ce projet sont documentées dans ce fichier.

Le format est basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/),
et ce projet adhère au [Semantic Versioning](https://semver.org/lang/fr/).

---

## [3.0.0] - 2025-01-08

### 🏗️ Refactorisation majeure - Architecture modulaire

Le code a été entièrement réorganisé pour une meilleure maintenabilité et extensibilité.

#### Nouvelle structure
```
ianonymiser/
├── app.py                      # Point d'entrée Flask
├── core/                       # Moteur d'anonymisation
│   ├── models.py               # Enums et Dataclasses
│   └── anonymizer.py           # Classe Anonymizer
├── patterns/                   # Patterns de détection
│   ├── base.py                 # Regex et préfixes
│   └── colors.py               # Couleurs highlighting
├── presets/                    # Presets en JSON
│   ├── loader.py               # Chargeur dynamique
│   ├── default.json
│   ├── ansible.json
│   ├── apache.json
│   ├── aws.json
│   ├── database.json
│   ├── kubernetes.json
│   ├── minimal.json
│   ├── security.json
│   └── preset.json.example     # Template pour créer un preset
├── api/                        # Routes API Flask
│   └── routes.py
└── config/                     # Configuration
    └── settings.py
```

### ✨ Nouveautés

#### Presets externalisés en JSON
- Tous les presets sont maintenant des fichiers JSON indépendants dans `presets/`
- Ajout de `preset.json.example` comme template pour créer ses propres presets
- Chargement dynamique des presets au démarrage
- Possibilité d'ajouter des presets personnalisés sans modifier le code

#### Architecture améliorée
- **Séparation des responsabilités** : core, patterns, presets, api, config
- **Factory pattern** pour l'application Flask (`create_app()`)
- **Blueprint Flask** pour les routes API
- **Lazy loading** des presets pour de meilleures performances

### 🔄 Compatibilité

- L'API REST reste inchangée
- Les imports doivent utiliser la nouvelle structure modulaire

### 📝 Documentation

- Mise à jour du README avec la nouvelle architecture
- Ajout de `preset.json.example` comme référence

---

## [2.1.0] - 2025-01-08

### ✨ Nouveautés

#### Affichage de la version dans l'interface
- Ajout d'un badge de version dans le header de l'application
- Permet de vérifier facilement que l'application est à jour


### 🔧 Technique

- Ajout de la constante `VERSION` dans `app.py` pour centraliser la gestion de version

---

## [2.0.0] - 2025-01-08

### ✨ Nouveautés

#### Nouveaux patterns de détection
- **USERNAME** : Détection des noms d'utilisateurs dans les logs
  - Format `u=xxx`, `user=xxx`
  - Format `username@X.X.X.X` (username avant IP)
  - Format `login=xxx`, `usr=xxx`
- **SERVER_NAME** : Détection des noms de serveurs/machines
  - Noms Ansible : `fatal: [SERVER-NAME]`
  - PLAY RECAP : `SERVER-NAME : ok=0 changed=0`
  - Formats infrastructure : `PREFIX-TYPE-NN`

#### Nouveau preset
- **Ansible / Infrastructure** : Configuration optimisée pour les logs Ansible, SSH et outils DevOps

### 🚀 Améliorations

#### Performance
- **Précompilation des regex** : Toutes les expressions régulières sont maintenant précompilées au démarrage pour des performances optimales
- **Système de priorité** : Les patterns sont testés dans un ordre intelligent pour éviter les faux positifs (URL avant hostname, email avant hostname, etc.)

#### Patterns améliorés
- **IPv6** : Support complet de toutes les formes compressées (`::`, `::1`, forme compressée avec `::`)
- **Email** : Meilleure gestion des sous-domaines et TLDs jusqu'à 63 caractères
- **Hostname** : Liste étendue de TLDs incluant les cloud providers (amazonaws, azure, gcp, cloudflare, vercel, netlify...)
- **Téléphone** : Support international amélioré (FR, US, et format général avec +XX)
- **API Keys** : Détection des tokens populaires :
  - OpenAI (`sk-proj-*`, `sk-*`)
  - GitHub (`ghp_*`, `gho_*`, `ghs_*`)
  - Slack (`xoxb-*`, `xoxp-*`)
  - Google (`AIza*`)
- **Carte de crédit** : Support des formats avec espaces/tirets + validation Luhn
- **IBAN** : Support avec ou sans espaces

#### Gestion des chevauchements
- Nouvelle logique intelligente : le pattern le plus englobant (complet) est conservé en cas de chevauchement
- Meilleure gestion des groupes de capture multiples dans les regex

### 🐛 Corrections

- Correction du bug où le `@` disparaissait entre username et IP (`user@X.X.X.X`)
- Correction de la gestion des séquences `\r\n` échappées dans les logs JSON
- Correction de la détection des groupes de capture (utilisation du premier groupe non-None)

### 📝 Documentation

- Mise à jour du README avec les nouveaux patterns
- Ajout de ce fichier CHANGELOG

---

## [1.0.0] - 2025-01-08

### 🎉 Version initiale

#### Fonctionnalités
- Interface web avec preview en temps réel
- Détection automatique de 15+ types de données sensibles :
  - Adresses IP (IPv4, IPv6)
  - Emails
  - Hostnames
  - URLs
  - Chemins de fichiers (Windows/Unix)
  - UUIDs
  - Adresses MAC
  - Numéros de téléphone
  - API Keys / Tokens / JWT
  - Numéros de carte bancaire
  - IBAN
  - Numéros de sécurité sociale
  - Clés privées
  - Connection strings
  - Dates

#### Presets
- Par défaut
- Apache/Nginx
- Kubernetes
- AWS CloudWatch
- Base de données
- Audit Sécurité
- Minimal

#### Fonctionnalités avancées
- Anonymisation cohérente (même valeur = même placeholder)
- Patterns personnalisés (regex)
- Liste de préservation
- Export JSON/TXT des mappings
- Sauvegarde de session
- Vue côte-à-côte ou empilée
- Raccourcis clavier

#### Déploiement
- Support Docker avec docker-compose
- Configuration Traefik ready
- Health checks intégrés

