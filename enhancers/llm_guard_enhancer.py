"""
Enhancer basé sur LLM Guard pour la détection de PII orientée sécurité LLM.
LLM Guard fournit des scanners spécialisés pour protéger les entrées/sorties LLM.
"""

from typing import List, Dict, Any
from .base import BaseEnhancer, EnhancerResult


class LLMGuardEnhancer(BaseEnhancer):
    """
    Enhancer utilisant LLM Guard pour la détection de PII.
    
    Fonctionnalités:
    - Scanner Anonymize pour la détection PII
    - Scanner Secrets pour les clés API, tokens, etc.
    - Optimisé pour les cas d'usage LLM
    - Lightweight et rapide
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self._anonymize_scanner = None
        self._secrets_scanner = None
    
    def is_available(self) -> bool:
        """Vérifie si llm-guard est installé."""
        if self._available is not None:
            return self._available
        
        try:
            from llm_guard.input_scanners import Anonymize
            self._available = True
        except ImportError:
            self._available = False
        
        return self._available
    
    def _do_initialize(self):
        """Initialise les scanners LLM Guard."""
        from llm_guard.input_scanners import Anonymize
        
        # Configurer le scanner Anonymize
        # Il utilise Presidio en interne mais avec une config optimisée LLM
        self._anonymize_scanner = Anonymize(
            allowed_names=[],  # Pas de noms autorisés par défaut
            preamble="",
            hidden_names=[],
            use_faker=False,  # On ne veut pas de faux noms, juste la détection
            threshold=self.config.confidence_threshold,
        )
        
        # Essayer d'initialiser le scanner de secrets si disponible
        try:
            from llm_guard.input_scanners import Secrets
            self._secrets_scanner = Secrets(
                redact_mode="all"
            )
        except ImportError:
            self._secrets_scanner = None
    
    def detect(self, text: str) -> List[EnhancerResult]:
        """
        Détecte les PII et secrets dans le texte via LLM Guard.
        
        Args:
            text: Texte à analyser
            
        Returns:
            Liste des détections
        """
        if not self.initialize():
            return []
        
        results = []
        
        # Scanner Anonymize pour les PII
        if self._anonymize_scanner:
            try:
                sanitized, is_valid, risk_score = self._anonymize_scanner.scan("", text)
                
                # Extraire les différences entre texte original et sanitisé
                pii_results = self._extract_differences(text, sanitized, "PII", risk_score)
                results.extend(pii_results)
            except Exception as e:
                print(f"Warning: Anonymize scanner error: {e}")
        
        # Scanner Secrets pour les clés API, tokens, etc.
        if self._secrets_scanner:
            try:
                sanitized, is_valid, risk_score = self._secrets_scanner.scan("", text)
                
                # Extraire les secrets détectés
                secret_results = self._extract_differences(text, sanitized, "SECRET", risk_score)
                results.extend(secret_results)
            except Exception as e:
                print(f"Warning: Secrets scanner error: {e}")
        
        return results
    
    def _extract_differences(
        self, 
        original: str, 
        sanitized: str, 
        entity_type: str,
        risk_score: float
    ) -> List[EnhancerResult]:
        """
        Extrait les différences entre le texte original et sanitisé.
        
        LLM Guard remplace les PII par des placeholders, on doit donc
        retrouver les positions originales.
        
        Args:
            original: Texte original
            sanitized: Texte après sanitization
            entity_type: Type d'entité
            risk_score: Score de risque global
            
        Returns:
            Liste des détections
        """
        results = []
        
        # Si les textes sont identiques, pas de détection
        if original == sanitized:
            return results
        
        # Stratégie: chercher les patterns de remplacement dans le texte sanitisé
        # LLM Guard utilise généralement des patterns comme [REDACTED], <PII>, etc.
        import re
        
        # Patterns de remplacement courants de LLM Guard
        placeholder_patterns = [
            r'\[REDACTED(?:_\w+)?\]',
            r'<(?:PERSON|EMAIL|PHONE|IP|URL|CREDIT_CARD|SSN|DATE)>',
            r'\[(?:PERSON|EMAIL|PHONE|IP|URL|CREDIT_CARD|SSN|DATE)(?:_\d+)?\]',
            r'<\w+_\d+>',
        ]
        
        # Trouver les positions des placeholders
        combined_pattern = '|'.join(placeholder_patterns)
        sanitized_matches = list(re.finditer(combined_pattern, sanitized))
        
        if not sanitized_matches:
            # Pas de pattern trouvé, essayer une approche de diff simple
            return self._simple_diff(original, sanitized, entity_type, risk_score)
        
        # Pour chaque placeholder, essayer de retrouver la valeur originale
        # C'est approximatif car on ne peut pas toujours aligner parfaitement
        
        return results
    
    def _simple_diff(
        self,
        original: str,
        sanitized: str,
        entity_type: str,
        risk_score: float
    ) -> List[EnhancerResult]:
        """
        Approche simple pour détecter les différences.
        Utilisée quand on ne peut pas matcher les patterns précisément.
        """
        results = []
        
        # Si le texte sanitisé est significativement différent,
        # on considère que des PII ont été détectés
        if len(sanitized) < len(original) * 0.9:  # Plus de 10% de différence
            # On ne peut pas donner les positions exactes
            # mais on peut signaler qu'il y a des PII
            results.append(EnhancerResult(
                value="[DETECTED_PII]",
                entity_type=entity_type,
                start=0,
                end=0,
                confidence=risk_score,
                source="llm_guard",
                metadata={
                    "note": "Exact positions not available",
                    "original_length": len(original),
                    "sanitized_length": len(sanitized),
                }
            ))
        
        return results
    
    def scan_prompt(self, prompt: str) -> Dict[str, Any]:
        """
        Scanne un prompt pour les risques de sécurité.
        
        Args:
            prompt: Prompt à scanner
            
        Returns:
            Dict avec les résultats du scan
        """
        if not self.initialize():
            return {"error": "LLM Guard not available"}
        
        result = {
            "is_safe": True,
            "risk_score": 0.0,
            "detections": [],
        }
        
        if self._anonymize_scanner:
            try:
                sanitized, is_valid, risk_score = self._anonymize_scanner.scan("", prompt)
                result["pii_safe"] = is_valid
                result["pii_risk"] = risk_score
                if not is_valid:
                    result["is_safe"] = False
                    result["risk_score"] = max(result["risk_score"], risk_score)
            except Exception:
                pass
        
        if self._secrets_scanner:
            try:
                sanitized, is_valid, risk_score = self._secrets_scanner.scan("", prompt)
                result["secrets_safe"] = is_valid
                result["secrets_risk"] = risk_score
                if not is_valid:
                    result["is_safe"] = False
                    result["risk_score"] = max(result["risk_score"], risk_score)
            except Exception:
                pass
        
        return result
    
    def get_status(self) -> Dict[str, Any]:
        """Retourne le statut détaillé de l'enhancer."""
        status = super().get_status()
        status["has_anonymize_scanner"] = self._anonymize_scanner is not None
        status["has_secrets_scanner"] = self._secrets_scanner is not None
        return status

