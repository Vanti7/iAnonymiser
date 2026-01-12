# Changelog

Toutes les modifications notables de ce projet sont documentées dans ce fichier.

Le format est basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/),
et ce projet adhère au [Semantic Versioning](https://semver.org/lang/fr/).

---

## [3.2.0] - 2025-01-12

### 🚀 Enhancers - Détection PII avancée avec libs externes

Intégration de bibliothèques Python spécialisées pour améliorer significativement la détection des données sensibles.

#### Nouveaux Enhancers

##### Microsoft Presidio (`presidio`)
- **Détection NER** : Utilise spaCy pour la reconnaissance d'entités nommées (noms, organisations, lieux)
- **Patterns avancés** : Emails, téléphones, numéros de sécurité sociale (FR/US)
- **Support multilingue** : Français et anglais
- **Seuil de confiance** configurable
- Installation : `pip install presidio-analyzer presidio-anonymizer`
- Modèles spaCy requis : `python -m spacy download fr_core_news_sm en_core_web_sm`

##### TLDExtract (`tldextract`)
- **Extraction précise des domaines** : Utilise la Public Suffix List officielle
- **Gestion des TLDs composés** : `co.uk`, `com.fr`, `github.io`, etc.
- **Détection automatique** : Tous les nouveaux gTLDs supportés
- **Cache intelligent** : Performance optimisée
- Installation : `pip install tldextract`

##### LLM Guard (`llm_guard`)
- **Scanner PII** : Détection optimisée pour les prompts LLM
- **Scanner Secrets** : Clés API, tokens, credentials
- **Orienté sécurité** : Conçu pour protéger les entrées/sorties LLM
- Installation : `pip install llm-guard`

#### Architecture

```
enhancers/
├── __init__.py          # Registry et factory
├── base.py              # Classe de base abstraite
├── presidio_enhancer.py # Microsoft Presidio
├── tldextract_enhancer.py # Extraction domaines
└── llm_guard_enhancer.py  # LLM Guard
```

#### API

Nouveaux endpoints pour gérer les enhancers :
- `GET /enhancers` : Liste tous les enhancers et leur statut
- `POST /enhancers/<name>` : Configure et active/désactive un enhancer
- `POST /enhancers/enable-all` : Active tous les enhancers disponibles
- `POST /enhancers/disable-all` : Désactive tous les enhancers

#### Configuration

Dans `config/settings.py` :
```python
ENHANCERS = {
    'presidio': {'enabled': False, 'confidence_threshold': 0.7},
    'tldextract': {'enabled': True, 'confidence_threshold': 0.6},
    'llm_guard': {'enabled': False, 'confidence_threshold': 0.7},
}
```

#### Notes d'installation

Installation minimale (sans enhancers) :
```bash
pip install flask gunicorn
```

Installation complète (avec tous les enhancers) :
```bash
pip install -r requirements.txt
python -m spacy download fr_core_news_sm
python -m spacy download en_core_web_sm
```

---

## [3.1.1] - 2025-01-12

### 🔍 Amélioration de la détection des hostnames

- **Ajout de TLDs virtualisés** : support des domaines VMware et hyperviseurs
  - VMware : `.esx`, `.esxi`, `.vmware`, `.vcenter`, `.vsphere`, `.vsan`
  - Microsoft : `.hyperv`
  - Autres : `.proxmox`, `.nutanix`, `.citrix`, `.xen`
- Correction de la détection des hostnames comme `havas-esx-08.havas.esx`

---

## [3.1.0] - 2025-01-12

### 🎨 Refonte de l'interface - Zone unifiée

L'interface a été simplifiée pour une meilleure ergonomie.

#### Zone d'édition unifiée
- **Fusion des zones** : "Texte original", "Preview détections" et "Texte anonymisé" sont maintenant dans une seule zone
- **Toggle à 3 onglets** :
  - ✏️ **Édition** : pour entrer/modifier le texte
  - 👁️ **Détection** : pour visualiser les données sensibles surlignées
  - 🔒 **Anonymisé** : pour voir le résultat après anonymisation

#### Améliorations UX
- **Basculement automatique** : passage à l'onglet approprié après chaque action
  - Après "Anonymiser" → onglet "Anonymisé"
  - Après "Restaurer" → onglet "Édition"
  - Après upload de fichier → onglet "Anonymisé"
- **Indicateur visuel dynamique** : le dot de couleur et le label changent selon le mode actif
- **Bouton "Télécharger"** déplacé dans les boutons d'action principaux

#### Suppressions
- Suppression de l'option "Vue empilée/côte à côte" (devenue obsolète avec la nouvelle interface)
- Suppression de la zone output séparée en bas de page

### 🔧 Technique
- Transitions CSS fluides entre les modes
- Meilleure gestion de la hauteur minimale des zones

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

