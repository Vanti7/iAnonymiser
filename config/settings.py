"""
Configuration globale de l'application.
"""

import os

# Version de l'application
VERSION = "3.2.0"

# Mode démo publique : payload limité, pas de persistance disque,
# mapping isolé par session (voir api/routes.py) et aucun logging de contenu.
DEMO_MODE = os.environ.get('DEMO_MODE', 'false').strip().lower() in ('1', 'true', 'yes')


class Config:
    """Configuration Flask et application."""

    DEMO_MODE = DEMO_MODE

    # Limite de taille des fichiers uploadés (50 MB, 100 Ko en mode démo)
    MAX_CONTENT_LENGTH = (100 * 1024) if DEMO_MODE else (50 * 1024 * 1024)

    # Nombre max de sessions démo conservées en mémoire (éviction LRU au-delà)
    DEMO_MAX_SESSIONS = 200

    # Mode debug (désactivé par défaut en production)
    DEBUG = False

    # Hôte et port par défaut
    HOST = '0.0.0.0'
    PORT = 5000
    
    # Encodages supportés pour les fichiers
    SUPPORTED_ENCODINGS = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
    
    # ==========================================
    # Configuration des Enhancers
    # ==========================================
    
    # Enhancers disponibles et leur activation par défaut
    ENHANCERS = {
        'presidio': {
            'enabled': False,  # Désactivé par défaut (nécessite spaCy)
            'confidence_threshold': 0.7,
            'languages': ['fr', 'en'],
        },
        'tldextract': {
            'enabled': True,  # Activé par défaut (léger)
            'confidence_threshold': 0.6,
        },
        'llm_guard': {
            'enabled': False,  # Désactivé par défaut (dépendances lourdes)
            'confidence_threshold': 0.7,
        },
    }
    
    # Auto-activer les enhancers disponibles au démarrage
    AUTO_ENABLE_ENHANCERS = False


class DevelopmentConfig(Config):
    """Configuration pour le développement."""
    DEBUG = True
    AUTO_ENABLE_ENHANCERS = True  # Activer en dev pour tester


class ProductionConfig(Config):
    """Configuration pour la production."""
    DEBUG = False

