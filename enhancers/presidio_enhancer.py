"""
Enhancer basé sur Microsoft Presidio pour la détection NER avancée.
Presidio utilise des modèles NER (spaCy) + regex pour détecter les PII.
"""

from typing import List, Dict, Any, Optional
from .base import BaseEnhancer, EnhancerResult, EnhancerConfig


class PresidioEnhancer(BaseEnhancer):
    """
    Enhancer utilisant Microsoft Presidio pour la détection de PII.
    
    Fonctionnalités:
    - Détection NER via spaCy (noms, organisations, lieux)
    - Patterns regex avancés pour emails, téléphones, etc.
    - Support multilingue (fr, en)
    - Seuil de confiance configurable
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self._analyzer = None
        self._nlp_engine = None
        
    def is_available(self) -> bool:
        """Vérifie si presidio-analyzer est installé."""
        if self._available is not None:
            return self._available
        
        try:
            from presidio_analyzer import AnalyzerEngine
            self._available = True
        except ImportError:
            self._available = False
        
        return self._available
    
    def _do_initialize(self):
        """Initialise le moteur Presidio avec les recognizers."""
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider
        
        # Configuration du moteur NLP
        # On utilise spacy avec un modèle léger par défaut
        nlp_config = {
            "nlp_engine_name": "spacy",
            "models": [
                {"lang_code": "fr", "model_name": "fr_core_news_sm"},
                {"lang_code": "en", "model_name": "en_core_web_sm"},
            ]
        }
        
        try:
            # Essayer de charger avec les modèles spaCy
            provider = NlpEngineProvider(nlp_configuration=nlp_config)
            self._nlp_engine = provider.create_engine()
            self._analyzer = AnalyzerEngine(nlp_engine=self._nlp_engine)
        except Exception:
            # Fallback: utiliser le moteur par défaut
            self._analyzer = AnalyzerEngine()
        
        # Ajouter des recognizers personnalisés pour le français
        self._add_custom_recognizers()
    
    def _add_custom_recognizers(self):
        """Ajoute des recognizers personnalisés."""
        try:
            from presidio_analyzer import Pattern, PatternRecognizer
            
            # Recognizer pour les numéros de sécu français
            fr_ssn_patterns = [
                Pattern(
                    "FR_SSN",
                    r"\b[12][0-9]{2}(0[1-9]|1[0-2]|[2-9][0-9])(0[1-9]|[1-8][0-9]|9[0-8]|2[AB])[0-9]{3}[0-9]{3}[0-9]{2}\b",
                    0.85
                )
            ]
            fr_ssn_recognizer = PatternRecognizer(
                supported_entity="FR_SSN",
                patterns=fr_ssn_patterns,
                supported_language="fr"
            )
            self._analyzer.registry.add_recognizer(fr_ssn_recognizer)
            
            # Recognizer pour les téléphones français
            fr_phone_patterns = [
                Pattern(
                    "FR_PHONE",
                    r"(?:(?:\+|00)33[\s.-]?|0)[1-9](?:[\s.-]?[0-9]{2}){4}",
                    0.75
                )
            ]
            fr_phone_recognizer = PatternRecognizer(
                supported_entity="PHONE_NUMBER",
                patterns=fr_phone_patterns,
                supported_language="fr"
            )
            self._analyzer.registry.add_recognizer(fr_phone_recognizer)
            
            # Recognizer pour les hostnames/FQDN
            hostname_patterns = [
                Pattern(
                    "HOSTNAME",
                    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.){1,}[a-zA-Z]{2,}\b",
                    0.6
                )
            ]
            hostname_recognizer = PatternRecognizer(
                supported_entity="DOMAIN_NAME",
                patterns=hostname_patterns,
            )
            self._analyzer.registry.add_recognizer(hostname_recognizer)
            
        except Exception as e:
            print(f"Warning: Could not add custom recognizers: {e}")
    
    def detect(self, text: str) -> List[EnhancerResult]:
        """
        Détecte les PII dans le texte via Presidio.
        
        Args:
            text: Texte à analyser
            
        Returns:
            Liste des détections
        """
        if not self.initialize():
            return []
        
        results = []
        
        # Analyser pour chaque langue configurée
        for lang in self.config.languages:
            try:
                analyzer_results = self._analyzer.analyze(
                    text=text,
                    language=lang,
                    score_threshold=self.config.confidence_threshold
                )
                
                for r in analyzer_results:
                    results.append(EnhancerResult(
                        value=text[r.start:r.end],
                        entity_type=r.entity_type,
                        start=r.start,
                        end=r.end,
                        confidence=r.score,
                        source="presidio",
                        metadata={
                            "language": lang,
                            "recognition_metadata": r.recognition_metadata if hasattr(r, 'recognition_metadata') else {}
                        }
                    ))
            except Exception as e:
                # Continuer avec les autres langues en cas d'erreur
                continue
        
        # Dédupliquer les résultats (mêmes positions)
        results = self._deduplicate_results(results)
        
        return results
    
    def _deduplicate_results(self, results: List[EnhancerResult]) -> List[EnhancerResult]:
        """Supprime les doublons en gardant celui avec la meilleure confiance."""
        seen = {}
        for r in results:
            key = (r.start, r.end)
            if key not in seen or r.confidence > seen[key].confidence:
                seen[key] = r
        return list(seen.values())
    
    def get_supported_entities(self) -> List[str]:
        """Retourne la liste des types d'entités supportés."""
        if not self.initialize():
            return []
        
        return self._analyzer.get_supported_entities()
    
    def get_status(self) -> Dict[str, Any]:
        """Retourne le statut détaillé de l'enhancer."""
        status = super().get_status()
        status["supported_entities"] = self.get_supported_entities() if self._initialized else []
        status["languages"] = self.config.languages
        return status

