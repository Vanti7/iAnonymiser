"""
Modèles de données pour le moteur d'anonymisation.
Contient les enums, dataclasses et types utilisés dans l'application.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class PatternType(Enum):
    """Types de données sensibles détectables."""
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    EMAIL = "email"
    HOSTNAME = "hostname"
    URL = "url"
    PATH_WINDOWS = "path_windows"
    PATH_UNIX = "path_unix"
    UUID = "uuid"
    MAC_ADDRESS = "mac"
    PHONE = "phone"
    API_KEY = "api_key"
    JWT = "jwt"
    CREDIT_CARD = "credit_card"
    DATE = "date"
    USERNAME = "username"
    SERVER_NAME = "server_name"
    IBAN = "iban"
    SSN = "ssn"
    PRIVATE_KEY = "private_key"
    CONNECTION_STRING = "connection_string"
    CUSTOM = "custom"


@dataclass
class Detection:
    """Une détection de donnée sensible."""
    value: str
    pattern_type: PatternType
    start: int
    end: int
    placeholder: Optional[str] = None


@dataclass
class AnonymizationResult:
    """Résultat de l'anonymisation."""
    anonymized_text: str
    mappings: Dict[str, str]
    stats: Dict[str, int]
    detections: List[Detection] = field(default_factory=list)


@dataclass
class PreviewResult:
    """Résultat du preview avec les détections."""
    detections: List[Detection]
    highlighted_html: str
    stats: Dict[str, int]


@dataclass
class PatternConfig:
    """Configuration d'un pattern de détection."""
    pattern_type: PatternType
    regex: str
    enabled: bool = True
    prefix: str = ""

