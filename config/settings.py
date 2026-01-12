"""
Configuration globale de l'application.
"""

# Version de l'application
VERSION = "3.2.0"


class Config:
    """Configuration Flask et application."""
    
    # Limite de taille des fichiers uploadés (50 MB)
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024
    
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

