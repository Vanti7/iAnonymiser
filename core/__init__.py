"""
Core module - Moteur d'anonymisation.
"""

from .models import PatternType, Detection, AnonymizationResult, PreviewResult, PatternConfig
from .anonymizer import Anonymizer

__all__ = [
    'PatternType',
    'Detection', 
    'AnonymizationResult',
    'PreviewResult',
    'PatternConfig',
    'Anonymizer',
]

