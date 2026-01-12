"""
Moteur principal d'anonymisation.
Détecte et remplace les données sensibles de manière cohérente.
Supporte des enhancers externes (Presidio, tldextract, LLM Guard).
"""

import re
import json
from typing import Dict, List, Tuple, Optional, Any

from .models import PatternType, Detection, AnonymizationResult, PreviewResult
from patterns import DEFAULT_PATTERNS, PREFIXES, PATTERN_COLORS
from presets import PresetLoader

# Import conditionnel des enhancers
try:
    from enhancers import (
        BaseEnhancer, 
        EnhancerResult,
        get_enhancer,
        get_available_enhancers,
        AVAILABLE_ENHANCERS
    )
    ENHANCERS_AVAILABLE = True
except ImportError:
    ENHANCERS_AVAILABLE = False
    BaseEnhancer = None
    EnhancerResult = None


class Anonymizer:
    """
    Moteur principal d'anonymisation.
    Maintient la cohérence des remplacements (même valeur = même placeholder).
    Supporte des enhancers pour améliorer la détection (Presidio, tldextract, etc.).
    """
    
    # Patterns précompilés (initialisé au premier accès)
    _compiled_patterns: Dict[PatternType, 're.Pattern'] = {}
    _patterns_compiled: bool = False
    
    def __init__(self):
        self.mappings: Dict[str, str] = {}
        self.reverse_mappings: Dict[str, str] = {}
        self.counters: Dict[str, int] = {}
        self.stats: Dict[str, int] = {}
        self.enabled_patterns: Dict[PatternType, bool] = {pt: True for pt in PatternType}
        self.custom_patterns: List[Tuple[str, str]] = []  # (regex, prefix)
        self.preserve_list: List[str] = []  # Valeurs à ne pas anonymiser
        self._compiled_custom: List[Tuple['re.Pattern', str]] = []  # Patterns custom compilés
        
        # Enhancers pour détection avancée
        self._enhancers: Dict[str, Any] = {}
        self._enhancers_enabled: Dict[str, bool] = {}
        self._enhancers_config: Dict[str, Dict] = {}
        
        # Précompiler les patterns au premier usage
        self._ensure_patterns_compiled()
        
        # Initialiser les enhancers disponibles
        self._init_enhancers()
    
    @classmethod
    def _ensure_patterns_compiled(cls):
        """Précompile tous les patterns regex pour de meilleures performances."""
        if cls._patterns_compiled:
            return
        
        for pattern_type, regex in DEFAULT_PATTERNS.items():
            try:
                cls._compiled_patterns[pattern_type] = re.compile(regex, re.IGNORECASE)
            except re.error as e:
                print(f"Warning: Failed to compile pattern {pattern_type}: {e}")
        
        cls._patterns_compiled = True
    
    def _init_enhancers(self):
        """Initialise les enhancers disponibles."""
        if not ENHANCERS_AVAILABLE:
            return
        
        # Charger les enhancers disponibles
        for name in get_available_enhancers():
            self._enhancers_enabled[name] = False  # Désactivés par défaut
            self._enhancers_config[name] = {}
    
    def set_enhancer_enabled(self, name: str, enabled: bool, config: Dict = None):
        """
        Active ou désactive un enhancer.
        
        Args:
            name: Nom de l'enhancer ('presidio', 'tldextract', 'llm_guard')
            enabled: True pour activer
            config: Configuration optionnelle
        """
        if not ENHANCERS_AVAILABLE:
            return False
        
        if name not in AVAILABLE_ENHANCERS:
            return False
        
        self._enhancers_enabled[name] = enabled
        
        if config:
            self._enhancers_config[name] = config
        
        # Créer l'instance si activé et pas encore créée
        if enabled and name not in self._enhancers:
            enhancer = get_enhancer(name, self._enhancers_config.get(name, {}))
            if enhancer and enhancer.is_available():
                self._enhancers[name] = enhancer
                return True
            else:
                self._enhancers_enabled[name] = False
                return False
        
        return True
    
    def get_enhancers_status(self) -> Dict[str, Any]:
        """
        Retourne le statut de tous les enhancers.
        
        Returns:
            Dict avec le statut de chaque enhancer
        """
        if not ENHANCERS_AVAILABLE:
            return {"available": False, "enhancers": {}}
        
        status = {
            "available": True,
            "enhancers": {}
        }
        
        for name in AVAILABLE_ENHANCERS.keys():
            if name in self._enhancers:
                status["enhancers"][name] = self._enhancers[name].get_status()
            else:
                status["enhancers"][name] = {
                    "name": name,
                    "available": name in get_available_enhancers(),
                    "enabled": self._enhancers_enabled.get(name, False),
                    "initialized": False
                }
        
        return status
    
    def _detect_with_enhancers(self, text: str) -> List[Detection]:
        """
        Exécute la détection via les enhancers activés.
        
        Args:
            text: Texte à analyser
            
        Returns:
            Liste des détections des enhancers
        """
        if not ENHANCERS_AVAILABLE:
            return []
        
        detections = []
        
        for name, enhancer in self._enhancers.items():
            if not self._enhancers_enabled.get(name, False):
                continue
            
            try:
                results = enhancer.detect(text)
                
                for r in results:
                    # Convertir EnhancerResult en Detection
                    pattern_type_str = r.to_pattern_type_str()
                    try:
                        pattern_type = PatternType(pattern_type_str)
                    except ValueError:
                        pattern_type = PatternType.CUSTOM
                    
                    # Vérifier si ce type de pattern est activé
                    if not self.enabled_patterns.get(pattern_type, True):
                        continue
                    
                    # Vérifier la liste de préservation
                    if self._should_preserve(r.value):
                        continue
                    
                    det = Detection(
                        value=r.value,
                        pattern_type=pattern_type,
                        start=r.start,
                        end=r.end
                    )
                    detections.append(det)
                    
            except Exception as e:
                print(f"Warning: Enhancer '{name}' error: {e}")
                continue
        
        return detections
        
    def reset(self):
        """Réinitialise les mappings et compteurs."""
        self.mappings.clear()
        self.reverse_mappings.clear()
        self.counters.clear()
        self.stats.clear()
        
    def set_pattern_enabled(self, pattern_type: PatternType, enabled: bool):
        """Active ou désactive un type de pattern."""
        self.enabled_patterns[pattern_type] = enabled
        
    def add_custom_pattern(self, regex: str, prefix: str = "CUSTOM"):
        """Ajoute un pattern personnalisé."""
        self.custom_patterns.append((regex, prefix))
        # Invalider le cache des patterns custom compilés
        self._compiled_custom.clear()
        
    def add_preserve_value(self, value: str):
        """Ajoute une valeur à préserver (ne pas anonymiser)."""
        self.preserve_list.append(value)
        
    def load_preset(self, preset_name: str) -> bool:
        """Charge un preset de configuration depuis les fichiers JSON."""
        preset = PresetLoader.get(preset_name)
        if not preset:
            return False
            
        # Désactiver tous les patterns
        for pt in PatternType:
            self.enabled_patterns[pt] = False
            
        # Activer ceux du preset
        for pattern_name in preset.get("patterns", []):
            try:
                pt = PatternType(pattern_name.lower())
                self.enabled_patterns[pt] = True
            except (ValueError, KeyError):
                pass
                
        # Ajouter les valeurs à préserver
        self.preserve_list = preset.get("preserve", []).copy()
        
        # Ajouter les patterns personnalisés
        self.custom_patterns.clear()
        self._compiled_custom.clear()
        for cp in preset.get("custom_patterns", []):
            if cp.get("regex") and cp.get("prefix"):
                self.custom_patterns.append((cp["regex"], cp["prefix"]))
                
        return True
        
    def _get_placeholder(self, value: str, prefix: str) -> str:
        """
        Génère un placeholder unique pour une valeur.
        Garantit la cohérence : même valeur = même placeholder.
        """
        if value in self.mappings:
            return self.mappings[value]
            
        if prefix not in self.counters:
            self.counters[prefix] = 0
        self.counters[prefix] += 1
        
        placeholder = f"[{prefix}_{self.counters[prefix]:03d}]"
        self.mappings[value] = placeholder
        self.reverse_mappings[placeholder] = value
        
        return placeholder
    
    def _should_preserve(self, value: str) -> bool:
        """Vérifie si une valeur doit être préservée."""
        return any(p.lower() in value.lower() for p in self.preserve_list)
    
    def detect(self, text: str) -> List[Detection]:
        """
        Détecte toutes les données sensibles sans les remplacer.
        Utilise des patterns précompilés avec système de priorité.
        Intègre les détections des enhancers si activés.
        """
        detections: List[Detection] = []
        
        # Structure pour gérer les chevauchements de façon plus intelligente
        occupied_ranges: List[Tuple[int, int, Detection]] = []
        
        def _check_overlap_and_add(start: int, end: int, det: Detection) -> bool:
            """
            Vérifie les chevauchements et ajoute la détection si valide.
            Stratégie : le pattern le plus englobant gagne.
            """
            to_remove = []
            
            for i, (s, e, existing) in enumerate(occupied_ranges):
                # Pas de chevauchement
                if end <= s or start >= e:
                    continue
                
                # Chevauchement détecté
                new_len = end - start
                existing_len = e - s
                
                # Si la nouvelle englobe complètement l'existante
                if start <= s and end >= e:
                    to_remove.append(i)
                    continue
                    
                # Si l'existante englobe complètement la nouvelle
                if s <= start and e >= end:
                    return False
                
                # Chevauchement partiel : garder le plus englobant
                if new_len > existing_len:
                    to_remove.append(i)
                else:
                    return False
            
            # Supprimer les détections qui doivent être remplacées
            for i in sorted(to_remove, reverse=True):
                _, _, existing = occupied_ranges.pop(i)
                if existing in detections:
                    detections.remove(existing)
            
            # Ajouter la nouvelle détection
            occupied_ranges.append((start, end, det))
            detections.append(det)
            return True
        
        # S'assurer que les patterns sont compilés
        self._ensure_patterns_compiled()
        
        # 1. D'abord, détecter avec les enhancers (haute priorité)
        enhancer_detections = self._detect_with_enhancers(text)
        for det in enhancer_detections:
            if det.start >= 0 and det.end > det.start:  # Ignorer les détections sans position
                _check_overlap_and_add(det.start, det.end, det)
        
        # 2. Ensuite, détecter avec les patterns par défaut (précompilés)
        for pattern_type in DEFAULT_PATTERNS.keys():
            if not self.enabled_patterns.get(pattern_type, True):
                continue
            
            compiled = self._compiled_patterns.get(pattern_type)
            if compiled is None:
                continue
                
            try:
                for match in compiled.finditer(text):
                    value = match.group(0)
                    start, end = match.start(), match.end()
                    
                    # Gestion des groupes de capture
                    if match.groups():
                        for i, grp in enumerate(match.groups(), 1):
                            if grp is not None:
                                value = grp
                                start = match.start(i)
                                end = match.end(i)
                                break
                    
                    # Validation supplémentaire selon le type
                    if not self._validate_detection(value, pattern_type):
                        continue
                        
                    if self._should_preserve(value):
                        continue
                    
                    det = Detection(
                        value=value,
                        pattern_type=pattern_type,
                        start=start,
                        end=end
                    )
                    _check_overlap_and_add(start, end, det)
                    
            except re.error:
                continue
                
        # Détecter avec les patterns personnalisés
        for i, (regex, prefix) in enumerate(self.custom_patterns):
            try:
                # Compiler et mettre en cache si pas déjà fait
                if i >= len(self._compiled_custom):
                    self._compiled_custom.append((re.compile(regex, re.IGNORECASE), prefix))
                
                compiled, _ = self._compiled_custom[i]
                
                for match in compiled.finditer(text):
                    value = match.group(0)
                    start, end = match.start(), match.end()
                    
                    if match.groups():
                        for j, grp in enumerate(match.groups(), 1):
                            if grp is not None:
                                value = grp
                                start = match.start(j)
                                end = match.end(j)
                                break
                        
                    if self._should_preserve(value):
                        continue
                    
                    det = Detection(
                        value=value,
                        pattern_type=PatternType.CUSTOM,
                        start=start,
                        end=end
                    )
                    _check_overlap_and_add(start, end, det)
                    
            except re.error:
                continue
                
        # Trier par position
        detections.sort(key=lambda d: d.start)
        return detections
    
    def _validate_detection(self, value: str, pattern_type: PatternType) -> bool:
        """
        Validation supplémentaire pour réduire les faux positifs.
        """
        if pattern_type == PatternType.IPV4:
            parts = value.split('.')
            if len(parts) != 4:
                return False
            if all(0 <= int(p) <= 31 for p in parts[:2]):
                return True
                
        elif pattern_type == PatternType.HOSTNAME:
            if value.count('.') < 1:
                return False
            if all(c.isdigit() or c == '.' for c in value):
                return False
                
        elif pattern_type == PatternType.EMAIL:
            if '@' not in value or '.' not in value.split('@')[-1]:
                return False
                
        elif pattern_type == PatternType.PHONE:
            digits = sum(1 for c in value if c.isdigit())
            if digits < 8:
                return False
                
        elif pattern_type == PatternType.CREDIT_CARD:
            digits = [int(c) for c in value if c.isdigit()]
            if len(digits) < 13:
                return False
            # Algorithme de Luhn
            checksum = 0
            for i, d in enumerate(reversed(digits)):
                if i % 2 == 1:
                    d *= 2
                    if d > 9:
                        d -= 9
                checksum += d
            if checksum % 10 != 0:
                return False
                
        elif pattern_type == PatternType.PATH_UNIX:
            if value.startswith('http'):
                return False
            if value.count('/') < 2:
                return False
                
        return True
    
    def preview(self, text: str) -> PreviewResult:
        """
        Génère un preview HTML avec highlighting des détections.
        """
        detections = self.detect(text)
        
        # Construire le HTML avec highlighting
        html_parts = []
        last_end = 0
        
        for det in detections:
            if det.start > last_end:
                html_parts.append(self._escape_html(text[last_end:det.start]))
            
            color = PATTERN_COLORS.get(det.pattern_type, "#868e96")
            html_parts.append(
                f'<span class="detection" data-type="{det.pattern_type.value}" '
                f'style="background-color: {color}20; border-bottom: 2px solid {color}; '
                f'padding: 1px 2px; border-radius: 2px;" '
                f'title="{det.pattern_type.name}">{self._escape_html(det.value)}</span>'
            )
            last_end = det.end
            
        if last_end < len(text):
            html_parts.append(self._escape_html(text[last_end:]))
            
        # Calculer les stats
        stats: Dict[str, int] = {}
        for det in detections:
            key = det.pattern_type.value
            stats[key] = stats.get(key, 0) + 1
            
        return PreviewResult(
            detections=detections,
            highlighted_html="".join(html_parts),
            stats=stats
        )
    
    def _escape_html(self, text: str) -> str:
        """Échappe les caractères HTML."""
        return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
            .replace("\n", "<br>")
            .replace(" ", "&nbsp;")
        )
    
    def anonymize(self, text: str) -> AnonymizationResult:
        """
        Anonymise le texte en remplaçant les données sensibles.
        """
        detections = self.detect(text)
        result = text
        self.stats.clear()
        
        # Remplacer de la fin vers le début pour préserver les indices
        for det in reversed(detections):
            prefix = PREFIXES.get(det.pattern_type, "UNKNOWN")
            placeholder = self._get_placeholder(det.value, prefix)
            det.placeholder = placeholder
            result = result[:det.start] + placeholder + result[det.end:]
            
            stat_key = det.pattern_type.value
            self.stats[stat_key] = self.stats.get(stat_key, 0) + 1
        
        return AnonymizationResult(
            anonymized_text=result,
            mappings=dict(self.mappings),
            stats=dict(self.stats),
            detections=detections
        )
    
    def deanonymize(self, text: str) -> str:
        """Restaure le texte original."""
        result = text
        for placeholder, original in self.reverse_mappings.items():
            result = result.replace(placeholder, original)
        return result
    
    def get_mapping_table(self) -> List[Tuple[str, str]]:
        """Retourne la table des mappings pour affichage."""
        return [(v, k) for k, v in self.mappings.items()]
    
    def export_mappings(self, format: str = "text") -> str:
        """Exporte les mappings dans différents formats."""
        if format == "json":
            return json.dumps({
                "mappings": self.mappings,
                "reverse_mappings": self.reverse_mappings,
                "counters": self.counters
            }, indent=2)
        else:
            lines = ["# Mapping Table (Placeholder -> Original)"]
            lines.append("=" * 60)
            for original, placeholder in sorted(self.mappings.items(), key=lambda x: x[1]):
                lines.append(f"{placeholder} -> {original}")
            return "\n".join(lines)
    
    def import_mappings(self, data: str, format: str = "json") -> bool:
        """Importe des mappings depuis un fichier."""
        try:
            if format == "json":
                parsed = json.loads(data)
                self.mappings = parsed.get("mappings", {})
                self.reverse_mappings = parsed.get("reverse_mappings", {})
                self.counters = parsed.get("counters", {})
                return True
        except (json.JSONDecodeError, KeyError):
            return False
        return False
    
    def get_session_state(self) -> Dict:
        """Retourne l'état complet de la session pour sauvegarde."""
        return {
            "mappings": self.mappings,
            "reverse_mappings": self.reverse_mappings,
            "counters": self.counters,
            "enabled_patterns": {k.value: v for k, v in self.enabled_patterns.items()},
            "custom_patterns": self.custom_patterns,
            "preserve_list": self.preserve_list,
            "enhancers_enabled": self._enhancers_enabled,
            "enhancers_config": self._enhancers_config,
        }
    
    def load_session_state(self, state: Dict) -> bool:
        """Charge un état de session sauvegardé."""
        try:
            self.mappings = state.get("mappings", {})
            self.reverse_mappings = state.get("reverse_mappings", {})
            self.counters = state.get("counters", {})
            
            enabled = state.get("enabled_patterns", {})
            for pt in PatternType:
                self.enabled_patterns[pt] = enabled.get(pt.value, True)
                
            self.custom_patterns = state.get("custom_patterns", [])
            self.preserve_list = state.get("preserve_list", [])
            
            # Restaurer l'état des enhancers
            self._enhancers_enabled = state.get("enhancers_enabled", {})
            self._enhancers_config = state.get("enhancers_config", {})
            
            # Réactiver les enhancers qui étaient activés
            for name, enabled in self._enhancers_enabled.items():
                if enabled:
                    self.set_enhancer_enabled(name, True, self._enhancers_config.get(name))
            
            return True
        except Exception:
            return False


# Fonction utilitaire pour utilisation simple
def anonymize_text(text: str, 
                   enabled_patterns: Optional[List[str]] = None,
                   custom_patterns: Optional[List[Tuple[str, str]]] = None,
                   preserve_values: Optional[List[str]] = None,
                   preset: Optional[str] = None) -> AnonymizationResult:
    """
    Fonction utilitaire pour anonymiser du texte rapidement.
    """
    anonymizer = Anonymizer()
    
    if preset:
        anonymizer.load_preset(preset)
    elif enabled_patterns is not None:
        for pt in PatternType:
            anonymizer.set_pattern_enabled(pt, False)
        for pattern_name in enabled_patterns:
            try:
                pt = PatternType(pattern_name)
                anonymizer.set_pattern_enabled(pt, True)
            except ValueError:
                pass
                
    if custom_patterns:
        for regex, prefix in custom_patterns:
            anonymizer.add_custom_pattern(regex, prefix)
            
    if preserve_values:
        for value in preserve_values:
            anonymizer.add_preserve_value(value)
            
    return anonymizer.anonymize(text)
