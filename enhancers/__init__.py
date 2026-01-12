"""
Enhancers de détection - Extensions du moteur d'anonymisation.
Chaque enhancer ajoute des capacités de détection supplémentaires.
"""

from .base import BaseEnhancer, EnhancerResult, EnhancerConfig
from .presidio_enhancer import PresidioEnhancer
from .tldextract_enhancer import TLDExtractEnhancer
from .llm_guard_enhancer import LLMGuardEnhancer

__all__ = [
    'BaseEnhancer',
    'EnhancerResult', 
    'EnhancerConfig',
    'PresidioEnhancer',
    'TLDExtractEnhancer',
    'LLMGuardEnhancer',
]

# Registry des enhancers disponibles
AVAILABLE_ENHANCERS = {
    'presidio': PresidioEnhancer,
    'tldextract': TLDExtractEnhancer,
    'llm_guard': LLMGuardEnhancer,
}


def get_enhancer(name: str, config: dict = None) -> BaseEnhancer | None:
    """
    Factory pour obtenir un enhancer par son nom.
    
    Args:
        name: Nom de l'enhancer ('presidio', 'tldextract', 'llm_guard')
        config: Configuration optionnelle
        
    Returns:
        Instance de l'enhancer ou None si non disponible
    """
    enhancer_class = AVAILABLE_ENHANCERS.get(name)
    if enhancer_class is None:
        return None
    
    try:
        return enhancer_class(config or {})
    except Exception as e:
        print(f"Warning: Failed to initialize enhancer '{name}': {e}")
        return None


def get_available_enhancers() -> list[str]:
    """Retourne la liste des enhancers disponibles et fonctionnels."""
    available = []
    for name, cls in AVAILABLE_ENHANCERS.items():
        try:
            enhancer = cls({})
            if enhancer.is_available():
                available.append(name)
        except Exception:
            pass
    return available

