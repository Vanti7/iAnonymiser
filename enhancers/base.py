"""
Classe de base pour les enhancers de détection.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum


class EnhancerType(Enum):
    """Types d'enhancers disponibles."""
    PRESIDIO = "presidio"
    TLDEXTRACT = "tldextract"
    LLM_GUARD = "llm_guard"


@dataclass
class EnhancerConfig:
    """Configuration d'un enhancer."""
    enabled: bool = True
    confidence_threshold: float = 0.7
    languages: List[str] = field(default_factory=lambda: ["fr", "en"])
    extra_settings: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EnhancerResult:
    """Résultat d'une détection par un enhancer."""
    value: str
    entity_type: str
    start: int
    end: int
    confidence: float = 1.0
    source: str = "unknown"
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_pattern_type_str(self) -> str:
        """Convertit le type d'entité en PatternType string."""
        # Mapping des types Presidio vers nos PatternType
        mapping = {
            # Presidio standard
            "EMAIL_ADDRESS": "email",
            "PHONE_NUMBER": "phone",
            "IP_ADDRESS": "ipv4",
            "URL": "url",
            "DOMAIN_NAME": "hostname",
            "PERSON": "username",  # Noms de personnes -> username
            "LOCATION": "hostname",  # Localisations peuvent être des serveurs
            "CREDIT_CARD": "credit_card",
            "IBAN_CODE": "iban",
            "US_SSN": "ssn",
            "FR_SSN": "ssn",
            "DATE_TIME": "date",
            "NRP": "username",  # National Registration Number
            "MEDICAL_LICENSE": "api_key",
            "US_PASSPORT": "ssn",
            "US_DRIVER_LICENSE": "ssn",
            "CRYPTO": "api_key",
            "UK_NHS": "ssn",
            # LLM Guard
            "PII": "username",
            "SECRET": "api_key",
            "API_KEY": "api_key",
            "PASSWORD": "api_key",
            # TLDExtract
            "FQDN": "hostname",
            "SUBDOMAIN": "hostname",
            "DOMAIN": "hostname",
            "TLD": "hostname",
        }
        return mapping.get(self.entity_type.upper(), "custom")


class BaseEnhancer(ABC):
    """
    Classe de base abstraite pour tous les enhancers.
    Chaque enhancer doit implémenter les méthodes detect() et is_available().
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialise l'enhancer.
        
        Args:
            config: Configuration optionnelle
        """
        self.config = EnhancerConfig(**config) if config else EnhancerConfig()
        self._initialized = False
        self._available = None
    
    @property
    def name(self) -> str:
        """Nom de l'enhancer."""
        return self.__class__.__name__.replace("Enhancer", "").lower()
    
    @abstractmethod
    def is_available(self) -> bool:
        """
        Vérifie si les dépendances de l'enhancer sont disponibles.
        
        Returns:
            True si l'enhancer peut être utilisé
        """
        pass
    
    @abstractmethod
    def detect(self, text: str) -> List[EnhancerResult]:
        """
        Détecte les entités dans le texte.
        
        Args:
            text: Texte à analyser
            
        Returns:
            Liste des détections
        """
        pass
    
    def initialize(self) -> bool:
        """
        Initialise l'enhancer (chargement des modèles, etc.).
        Appelé une seule fois au premier usage.
        
        Returns:
            True si l'initialisation a réussi
        """
        if self._initialized:
            return True
        
        if not self.is_available():
            return False
        
        try:
            self._do_initialize()
            self._initialized = True
            return True
        except Exception as e:
            print(f"Warning: Failed to initialize {self.name}: {e}")
            return False
    
    def _do_initialize(self):
        """
        Méthode à surcharger pour l'initialisation spécifique.
        """
        pass
    
    def filter_by_confidence(self, results: List[EnhancerResult]) -> List[EnhancerResult]:
        """
        Filtre les résultats par seuil de confiance.
        
        Args:
            results: Liste des résultats à filtrer
            
        Returns:
            Résultats au-dessus du seuil de confiance
        """
        return [r for r in results if r.confidence >= self.config.confidence_threshold]
    
    def get_status(self) -> Dict[str, Any]:
        """
        Retourne le statut de l'enhancer.
        
        Returns:
            Dictionnaire avec le statut
        """
        return {
            "name": self.name,
            "available": self.is_available(),
            "initialized": self._initialized,
            "enabled": self.config.enabled,
            "confidence_threshold": self.config.confidence_threshold,
        }

