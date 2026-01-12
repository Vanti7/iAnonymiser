"""
Enhancer basé sur tldextract pour une meilleure détection des domaines.
Gère correctement les TLDs composés (co.uk, com.fr, etc.) et les sous-domaines.
"""

import re
from typing import List, Dict, Any, Set
from .base import BaseEnhancer, EnhancerResult


class TLDExtractEnhancer(BaseEnhancer):
    """
    Enhancer utilisant tldextract pour la détection précise des domaines.
    
    Avantages par rapport aux regex:
    - Utilise la Public Suffix List officielle
    - Gère tous les TLDs valides (y compris les nouveaux gTLDs)
    - Gère correctement co.uk, com.fr, etc.
    - Cache local mis à jour automatiquement
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self._extractor = None
        # Pattern pour trouver les candidats de domaines
        self._domain_pattern = re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        )
        # Cache des domaines déjà extraits
        self._cache: Dict[str, Any] = {}
    
    def is_available(self) -> bool:
        """Vérifie si tldextract est installé."""
        if self._available is not None:
            return self._available
        
        try:
            import tldextract
            self._available = True
        except ImportError:
            self._available = False
        
        return self._available
    
    def _do_initialize(self):
        """Initialise l'extracteur tldextract."""
        import tldextract
        
        # Créer un extracteur avec cache
        # include_psl_private_domains=True pour inclure les domaines privés
        # comme *.github.io, *.herokuapp.com, etc.
        self._extractor = tldextract.TLDExtract(
            include_psl_private_domains=True,
            cache_dir=None,  # Utiliser le cache par défaut
        )
    
    def detect(self, text: str) -> List[EnhancerResult]:
        """
        Détecte les domaines/FQDN dans le texte.
        
        Args:
            text: Texte à analyser
            
        Returns:
            Liste des détections de domaines
        """
        if not self.initialize():
            return []
        
        results = []
        seen_positions: Set[tuple] = set()
        
        # Trouver tous les candidats de domaines
        for match in self._domain_pattern.finditer(text):
            candidate = match.group(0)
            start, end = match.start(), match.end()
            
            # Éviter les doublons sur la même position
            if (start, end) in seen_positions:
                continue
            
            # Extraire les composants du domaine
            extracted = self._extract_domain(candidate)
            
            if not extracted:
                continue
            
            # Vérifier si c'est un domaine valide
            if not extracted.get('is_valid', False):
                continue
            
            # Déterminer le type d'entité
            entity_type = self._determine_entity_type(extracted)
            
            # Calculer le score de confiance
            confidence = self._calculate_confidence(extracted, candidate)
            
            if confidence >= self.config.confidence_threshold:
                results.append(EnhancerResult(
                    value=candidate,
                    entity_type=entity_type,
                    start=start,
                    end=end,
                    confidence=confidence,
                    source="tldextract",
                    metadata={
                        "subdomain": extracted.get('subdomain', ''),
                        "domain": extracted.get('domain', ''),
                        "suffix": extracted.get('suffix', ''),
                        "fqdn": extracted.get('fqdn', ''),
                        "is_private": extracted.get('is_private', False),
                    }
                ))
                seen_positions.add((start, end))
        
        return results
    
    def _extract_domain(self, candidate: str) -> Dict[str, Any]:
        """
        Extrait les composants d'un domaine.
        
        Args:
            candidate: Chaîne candidate (potentiel domaine)
            
        Returns:
            Dict avec les composants ou None
        """
        # Vérifier le cache
        if candidate in self._cache:
            return self._cache[candidate]
        
        try:
            ext = self._extractor(candidate)
            
            result = {
                'subdomain': ext.subdomain,
                'domain': ext.domain,
                'suffix': ext.suffix,
                'fqdn': ext.fqdn,
                'is_valid': bool(ext.domain and ext.suffix),
                'is_private': ext.is_private if hasattr(ext, 'is_private') else False,
            }
            
            # Limiter la taille du cache
            if len(self._cache) > 10000:
                self._cache.clear()
            
            self._cache[candidate] = result
            return result
            
        except Exception:
            return {'is_valid': False}
    
    def _determine_entity_type(self, extracted: Dict[str, Any]) -> str:
        """
        Détermine le type d'entité basé sur les composants.
        
        Args:
            extracted: Composants extraits
            
        Returns:
            Type d'entité
        """
        if extracted.get('subdomain'):
            return "FQDN"  # Fully Qualified Domain Name
        elif extracted.get('domain') and extracted.get('suffix'):
            return "DOMAIN"
        else:
            return "TLD"
    
    def _calculate_confidence(self, extracted: Dict[str, Any], original: str) -> float:
        """
        Calcule un score de confiance pour la détection.
        
        Args:
            extracted: Composants extraits
            original: Chaîne originale
            
        Returns:
            Score de confiance (0-1)
        """
        confidence = 0.5  # Base
        
        # Bonus si domaine et suffix valides
        if extracted.get('domain') and extracted.get('suffix'):
            confidence += 0.3
        
        # Bonus pour les sous-domaines (plus spécifique)
        if extracted.get('subdomain'):
            confidence += 0.1
        
        # Bonus si le TLD est courant
        common_tlds = {'com', 'org', 'net', 'fr', 'eu', 'io', 'co', 'uk', 'de'}
        if extracted.get('suffix', '').split('.')[-1] in common_tlds:
            confidence += 0.1
        
        # Malus pour les domaines très courts (potentiel faux positif)
        if len(extracted.get('domain', '')) < 3:
            confidence -= 0.2
        
        return min(max(confidence, 0.0), 1.0)
    
    def extract_components(self, domain: str) -> Dict[str, str]:
        """
        Méthode utilitaire pour extraire les composants d'un domaine.
        
        Args:
            domain: Domaine à analyser
            
        Returns:
            Dict avec subdomain, domain, suffix, fqdn
        """
        if not self.initialize():
            return {}
        
        extracted = self._extract_domain(domain)
        return {
            'subdomain': extracted.get('subdomain', ''),
            'domain': extracted.get('domain', ''),
            'suffix': extracted.get('suffix', ''),
            'fqdn': extracted.get('fqdn', ''),
        }
    
    def is_valid_domain(self, candidate: str) -> bool:
        """
        Vérifie si une chaîne est un domaine valide.
        
        Args:
            candidate: Chaîne à vérifier
            
        Returns:
            True si c'est un domaine valide
        """
        if not self.initialize():
            return False
        
        extracted = self._extract_domain(candidate)
        return extracted.get('is_valid', False)
    
    def get_status(self) -> Dict[str, Any]:
        """Retourne le statut détaillé de l'enhancer."""
        status = super().get_status()
        status["cache_size"] = len(self._cache)
        return status

