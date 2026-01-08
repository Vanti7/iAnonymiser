"""
Configuration globale de l'application.
"""

# Version de l'application
VERSION = "3.0.0"


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


class DevelopmentConfig(Config):
    """Configuration pour le développement."""
    DEBUG = True


class ProductionConfig(Config):
    """Configuration pour la production."""
    DEBUG = False

