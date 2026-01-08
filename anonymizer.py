"""
Moteur d'anonymisation pour logs et fichiers texte.
Détecte et remplace les données sensibles de manière cohérente.
"""

import re
import hashlib
import json
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


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


# Couleurs pour le highlighting (CSS classes)
PATTERN_COLORS: Dict[PatternType, str] = {
    PatternType.IPV4: "#ff6b6b",
    PatternType.IPV6: "#ff8787",
    PatternType.EMAIL: "#4dabf7",
    PatternType.HOSTNAME: "#69db7c",
    PatternType.URL: "#38d9a9",
    PatternType.PATH_WINDOWS: "#ffd43b",
    PatternType.PATH_UNIX: "#ffe066",
    PatternType.UUID: "#da77f2",
    PatternType.MAC_ADDRESS: "#e599f7",
    PatternType.PHONE: "#74c0fc",
    PatternType.API_KEY: "#ff922b",
    PatternType.JWT: "#ffa94d",
    PatternType.CREDIT_CARD: "#f06595",
    PatternType.DATE: "#a9e34b",
    PatternType.USERNAME: "#63e6be",
    PatternType.SERVER_NAME: "#20c997",
    PatternType.IBAN: "#f783ac",
    PatternType.SSN: "#ff8787",
    PatternType.PRIVATE_KEY: "#e64980",
    PatternType.CONNECTION_STRING: "#fd7e14",
    PatternType.CUSTOM: "#868e96",
}


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


# Profils de configuration prédéfinis
PRESETS: Dict[str, Dict] = {
    "default": {
        "name": "Par défaut",
        "description": "Configuration standard pour la plupart des logs",
        "patterns": ["ipv4", "ipv6", "email", "hostname", "url", "uuid", "mac", "phone", "api_key", "jwt", "username", "server_name", "path_unix", "path_windows"],
        "preserve": ["localhost", "127.0.0.1", "::1"]
    },
    "ansible": {
        "name": "Ansible / Infrastructure",
        "description": "Logs Ansible, SSH et outils d'infrastructure",
        "patterns": ["ipv4", "ipv6", "hostname", "path_unix", "username", "server_name", "api_key", "email"],
        "preserve": ["localhost", "127.0.0.1"],
        "custom_patterns": [
            {"regex": r'(?:PLAY|TASK)\s+\[([^\]]+)\]', "prefix": "TASK"},
        ]
    },
    "apache": {
        "name": "Apache / Nginx",
        "description": "Logs de serveurs web Apache et Nginx",
        "patterns": ["ipv4", "ipv6", "url", "hostname", "email", "username"],
        "preserve": ["localhost", "127.0.0.1"],
        "custom_patterns": [
            {"regex": r'"[A-Z]+ ([^"]+) HTTP/[0-9.]+"', "prefix": "REQUEST"},
        ]
    },
    "kubernetes": {
        "name": "Kubernetes",
        "description": "Logs Kubernetes et Docker",
        "patterns": ["ipv4", "hostname", "uuid", "path_unix", "email", "server_name"],
        "preserve": ["localhost", "kubernetes.default"],
        "custom_patterns": [
            {"regex": r'pod/[a-z0-9-]+', "prefix": "POD"},
            {"regex": r'namespace/[a-z0-9-]+', "prefix": "NS"},
            {"regex": r'[a-z0-9]+-[a-z0-9]+-[a-z0-9]+-[a-z0-9]+-[a-z0-9]+', "prefix": "KUID"},
        ]
    },
    "aws": {
        "name": "AWS CloudWatch",
        "description": "Logs AWS et CloudWatch",
        "patterns": ["ipv4", "email", "url", "api_key", "hostname"],
        "preserve": ["amazonaws.com"],
        "custom_patterns": [
            {"regex": r'arn:aws:[a-z0-9-]+:[a-z0-9-]*:[0-9]*:[a-zA-Z0-9-_/]+', "prefix": "ARN"},
            {"regex": r'i-[0-9a-f]{8,17}', "prefix": "EC2"},
            {"regex": r'sg-[0-9a-f]+', "prefix": "SG"},
            {"regex": r'vpc-[0-9a-f]+', "prefix": "VPC"},
            {"regex": r'subnet-[0-9a-f]+', "prefix": "SUBNET"},
            {"regex": r'AKIA[0-9A-Z]{16}', "prefix": "AKID"},
        ]
    },
    "database": {
        "name": "Base de données",
        "description": "Logs SQL et bases de données",
        "patterns": ["ipv4", "email", "hostname", "uuid", "connection_string", "api_key"],
        "preserve": ["localhost"],
        "custom_patterns": [
            {"regex": r'(?:mysql|postgresql|mongodb|redis)://[^\s]+', "prefix": "DBURL"},
        ]
    },
    "security": {
        "name": "Audit Sécurité",
        "description": "Mode paranoïaque - détecte tout",
        "patterns": list(PatternType.__members__.keys()),
        "preserve": [],
    },
    "minimal": {
        "name": "Minimal",
        "description": "Seulement IPs et emails",
        "patterns": ["ipv4", "ipv6", "email"],
        "preserve": ["localhost", "127.0.0.1"],
    },
}


@dataclass
class PatternConfig:
    """Configuration d'un pattern de détection."""
    pattern_type: PatternType
    regex: str
    enabled: bool = True
    prefix: str = ""
    
    
class Anonymizer:
    """
    Moteur principal d'anonymisation.
    Maintient la cohérence des remplacements (même valeur = même placeholder).
    """
    
    # Patterns de détection par défaut (améliorés)
    # L'ordre définit la priorité : les patterns en premier sont testés d'abord
    DEFAULT_PATTERNS: Dict[PatternType, str] = {
        # Priorité haute : patterns spécifiques qui pourraient être capturés par d'autres
        PatternType.PRIVATE_KEY: r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----',
        PatternType.JWT: r'\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b',
        PatternType.CONNECTION_STRING: r'(?:Server|Data Source|Host|jdbc:[a-z]+:)=[^;\s]+(?:;[^;\s]+)*(?:;(?:Password|Pwd|PWD)=[^;\s]+)',
        
        # URLs avant hostnames pour éviter les faux positifs
        PatternType.URL: r'https?://[^\s<>"\'{}|\\^`\[\]]+(?:\?[^\s<>"\'{}|\\^`\[\]]*)?',
        
        # Email avec meilleur support des sous-domaines et TLDs
        PatternType.EMAIL: r'\b[A-Za-z0-9](?:[A-Za-z0-9._%+-]{0,62}[A-Za-z0-9])?@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b',
        
        # UUID (inchangé, déjà bon)
        PatternType.UUID: r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b',
        
        # IPv4 (légèrement amélioré)
        PatternType.IPV4: r'\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?:/[0-9]{1,2})?\b',
        
        # IPv6 amélioré - supporte toutes les formes compressées
        # IMPORTANT: patterns ordonnés du plus spécifique au plus général
        PatternType.IPV6: r'(?:' \
            r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|' \
            r'(?:[0-9a-fA-F]{1,4}:){6}:[0-9a-fA-F]{1,4}|' \
            r'(?:[0-9a-fA-F]{1,4}:){5}(?::[0-9a-fA-F]{1,4}){1,2}|' \
            r'(?:[0-9a-fA-F]{1,4}:){4}(?::[0-9a-fA-F]{1,4}){1,3}|' \
            r'(?:[0-9a-fA-F]{1,4}:){3}(?::[0-9a-fA-F]{1,4}){1,4}|' \
            r'(?:[0-9a-fA-F]{1,4}:){2}(?::[0-9a-fA-F]{1,4}){1,5}|' \
            r'(?:[0-9a-fA-F]{1,4}:){1}(?::[0-9a-fA-F]{1,4}){1,6}|' \
            r'::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}|' \
            r'(?:[0-9a-fA-F]{1,4}:){1,7}:|' \
            r'::' \
            r')(?:/[0-9]{1,3})?',
        
        # Hostname amélioré avec plus de TLDs
        PatternType.HOSTNAME: r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|org|net|edu|gov|mil|int|io|fr|de|uk|eu|es|it|nl|be|ch|at|ca|au|nz|jp|cn|kr|br|ru|in|mx|za|local|internal|corp|lan|intra|cloud|app|dev|test|staging|prod|localhost|example|invalid|onion|i2p|bit|eth|crypto|web3|xyz|online|site|tech|info|biz|co|me|tv|cc|ws|mobi|name|pro|aero|coop|museum|travel|jobs|asia|tel|post|arpa|amazonaws|azure|gcp|cloudflare|digitalocean|heroku|vercel|netlify)\b',
        
        # MAC Address (inchangé)
        PatternType.MAC_ADDRESS: r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b|\b[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\b',
        
        # Téléphone international amélioré
        PatternType.PHONE: r'(?:' \
            r'(?:\+|00)[1-9][0-9]{0,3}[\s.-]?[0-9]{1,2}(?:[\s.-]?[0-9]{2}){4}|' \
            r'\b0[1-9](?:[\s.-]?[0-9]{2}){4}\b|' \
            r'\([0-9]{3}\)[\s.-]?[0-9]{3}[\s.-]?[0-9]{4}|' \
            r'\b[0-9]{3}[\s.-][0-9]{3}[\s.-][0-9]{4}\b|' \
            r'(?:\+|00)[1-9][0-9]{0,2}[\s.-]?\(?[0-9]{2,4}\)?(?:[\s.-]?[0-9]{2,4}){2,4}' \
            r')',
        
        # API Key / Secrets amélioré
        PatternType.API_KEY: r'(?:' \
            r'(?:api[_-]?key|apikey|api_secret|secret[_-]?key|auth[_-]?token|access[_-]?token|password|passwd|pwd|credentials?|private[_-]?key)[=:\s]+["\']?([A-Za-z0-9_\-\.=+/]{16,})["\']?|' \
            r'\b(?:sk|pk|rk|ak)[-_](?:[a-zA-Z]+-)?[a-zA-Z0-9]{16,}\b|' \
            r'\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|' \
            r'\bxox[baprs]-[A-Za-z0-9-]{10,}\b|' \
            r'\bAIza[A-Za-z0-9_-]{35}\b' \
            r')',
        
        # Chemins Windows et Unix
        PatternType.PATH_WINDOWS: r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n\s]+\\)*[^\\/:*?"<>|\r\n\s]+',
        PatternType.PATH_UNIX: r'(?<![A-Za-z0-9])(?:/(?:home|var|etc|usr|opt|tmp|root|mnt|srv|data|app|apps?)/[a-zA-Z0-9._/-]+)',
        
        # Carte de crédit avec espaces/tirets
        PatternType.CREDIT_CARD: r'\b(?:4[0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}|5[1-5][0-9]{2}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}|3[47][0-9]{2}[\s-]?[0-9]{6}[\s-]?[0-9]{5}|6(?:011|5[0-9]{2})[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4})\b',
        
        # Date (inchangé)
        PatternType.DATE: r'\b(?:0?[1-9]|[12][0-9]|3[01])[/-](?:0?[1-9]|1[012])[/-](?:19|20)?\d{2}\b|\b(?:19|20)\d{2}[/-](?:0?[1-9]|1[012])[/-](?:0?[1-9]|[12][0-9]|3[01])\b',
        
        # IBAN amélioré
        PatternType.IBAN: r'\b[A-Z]{2}[0-9]{2}[\s]?(?:[A-Z0-9]{4}[\s]?){2,7}[A-Z0-9]{1,4}\b',
        
        # SSN (US et France)
        PatternType.SSN: r'\b(?:[0-9]{3}-[0-9]{2}-[0-9]{4}|[12][0-9]{2}(?:0[1-9]|1[0-2]|[2-9][0-9])(?:0[1-9]|[1-8][0-9]|9[0-8]|2[AB])[0-9]{3}[0-9]{3}[0-9]{2})\b',
        
        # Username dans les logs (u=xxx, user=xxx, username@, etc.)
        PatternType.USERNAME: r'(?:' \
            r'(?:^|[\s|])u=([a-zA-Z][a-zA-Z0-9_-]{1,31})(?=[\s|,;]|$)|' \
            r'(?:user|username|usr|login)[=:\s]+["\']?([a-zA-Z][a-zA-Z0-9_.-]{1,63})["\']?|' \
            r'(?:^|[\s]|\\r\\n|\\n)([a-zA-Z][a-zA-Z0-9_-]{1,31})@(?=\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' \
            r')',
        
        # Noms de serveurs/machines (patterns infrastructure)
        PatternType.SERVER_NAME: r'(?:' \
            r'(?:fatal|ok|changed|unreachable|failed|skipped|rescued|ignored):\s*\[([A-Za-z][A-Za-z0-9_-]{2,})\]|' \
            r'\[([A-Z][A-Z0-9_-]*(?:-[A-Za-z0-9_]+)+)\]|' \
            r'(?:^|\|)\s*([A-Z][A-Z0-9]*(?:-[A-Za-z0-9_]+)+)\s*(?=[|:]|\s+ok=)' \
            r')',
    }
    
    # Patterns précompilés (initialisé au premier accès)
    _compiled_patterns: Dict[PatternType, 're.Pattern'] = {}
    _patterns_compiled: bool = False
    
    # Préfixes pour les placeholders
    PREFIXES: Dict[PatternType, str] = {
        PatternType.IPV4: "IP",
        PatternType.IPV6: "IPV6",
        PatternType.EMAIL: "EMAIL",
        PatternType.HOSTNAME: "HOST",
        PatternType.URL: "URL",
        PatternType.PATH_WINDOWS: "PATH",
        PatternType.PATH_UNIX: "PATH",
        PatternType.UUID: "UUID",
        PatternType.MAC_ADDRESS: "MAC",
        PatternType.PHONE: "PHONE",
        PatternType.API_KEY: "KEY",
        PatternType.JWT: "TOKEN",
        PatternType.CREDIT_CARD: "CC",
        PatternType.DATE: "DATE",
        PatternType.USERNAME: "USER",
        PatternType.SERVER_NAME: "SERVER",
        PatternType.IBAN: "IBAN",
        PatternType.SSN: "SSN",
        PatternType.PRIVATE_KEY: "PRIVKEY",
        PatternType.CONNECTION_STRING: "CONNSTR",
        PatternType.CUSTOM: "VAL",
    }
    
    def __init__(self):
        self.mappings: Dict[str, str] = {}
        self.reverse_mappings: Dict[str, str] = {}
        self.counters: Dict[str, int] = {}
        self.stats: Dict[str, int] = {}
        self.enabled_patterns: Dict[PatternType, bool] = {pt: True for pt in PatternType}
        self.custom_patterns: List[Tuple[str, str]] = []  # (regex, prefix)
        self.preserve_list: List[str] = []  # Valeurs à ne pas anonymiser
        self._compiled_custom: List[Tuple['re.Pattern', str]] = []  # Patterns custom compilés
        
        # Précompiler les patterns au premier usage
        self._ensure_patterns_compiled()
    
    @classmethod
    def _ensure_patterns_compiled(cls):
        """Précompile tous les patterns regex pour de meilleures performances."""
        if cls._patterns_compiled:
            return
        
        for pattern_type, regex in cls.DEFAULT_PATTERNS.items():
            try:
                cls._compiled_patterns[pattern_type] = re.compile(regex, re.IGNORECASE)
            except re.error as e:
                print(f"Warning: Failed to compile pattern {pattern_type}: {e}")
        
        cls._patterns_compiled = True
        
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
        
    def load_preset(self, preset_name: str):
        """Charge un preset de configuration."""
        if preset_name not in PRESETS:
            return False
            
        preset = PRESETS[preset_name]
        
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
        """
        detections: List[Detection] = []
        
        # Structure pour gérer les chevauchements de façon plus intelligente
        # On utilise un interval tree simplifié (liste triée de (start, end, detection))
        occupied_ranges: List[Tuple[int, int, Detection]] = []
        
        def _check_overlap_and_add(start: int, end: int, det: Detection) -> bool:
            """
            Vérifie les chevauchements et ajoute la détection si valide.
            Stratégie : le pattern le plus englobant gagne (préférer les détections complètes).
            En cas d'égalité de taille, le premier pattern (priorité plus haute) gagne.
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
                    return False  # Garder l'existante
                
                # Chevauchement partiel : garder le plus englobant (le plus long)
                if new_len > existing_len:
                    to_remove.append(i)
                else:
                    # Garder l'existante (même taille ou plus grande + priorité)
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
        
        # Détecter avec les patterns par défaut (précompilés)
        # L'ordre dans DEFAULT_PATTERNS définit la priorité
        for pattern_type in self.DEFAULT_PATTERNS.keys():
            if not self.enabled_patterns.get(pattern_type, True):
                continue
            
            compiled = self._compiled_patterns.get(pattern_type)
            if compiled is None:
                continue
                
            try:
                for match in compiled.finditer(text):
                    value = match.group(0)
                    start, end = match.start(), match.end()
                    
                    # Gestion des groupes de capture (trouver le premier groupe non-None)
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
                
        # Détecter avec les patterns personnalisés (compilés à la volée ou mis en cache)
        for i, (regex, prefix) in enumerate(self.custom_patterns):
            try:
                # Compiler et mettre en cache si pas déjà fait
                if i >= len(self._compiled_custom):
                    self._compiled_custom.append((re.compile(regex, re.IGNORECASE), prefix))
                
                compiled, _ = self._compiled_custom[i]
                
                for match in compiled.finditer(text):
                    value = match.group(0)
                    start, end = match.start(), match.end()
                    
                    # Trouver le premier groupe non-None
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
            # Éviter les numéros de version (1.2.3.4 mais pas 1.2.3)
            parts = value.split('.')
            if len(parts) != 4:
                return False
            # Éviter les dates mal formatées
            if all(0 <= int(p) <= 31 for p in parts[:2]):
                return True
                
        elif pattern_type == PatternType.HOSTNAME:
            # Minimum 2 segments
            if value.count('.') < 1:
                return False
            # Éviter les nombres seuls
            if all(c.isdigit() or c == '.' for c in value):
                return False
                
        elif pattern_type == PatternType.EMAIL:
            # Vérification basique de structure
            if '@' not in value or '.' not in value.split('@')[-1]:
                return False
                
        elif pattern_type == PatternType.PHONE:
            # Au moins 8 chiffres
            digits = sum(1 for c in value if c.isdigit())
            if digits < 8:
                return False
                
        elif pattern_type == PatternType.CREDIT_CARD:
            # Validation Luhn basique
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
            # Éviter les URLs mal parsées
            if value.startswith('http'):
                return False
            # Au moins 2 segments
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
            # Ajouter le texte avant la détection
            if det.start > last_end:
                html_parts.append(self._escape_html(text[last_end:det.start]))
            
            # Ajouter la détection avec highlighting
            color = PATTERN_COLORS.get(det.pattern_type, "#868e96")
            html_parts.append(
                f'<span class="detection" data-type="{det.pattern_type.value}" '
                f'style="background-color: {color}20; border-bottom: 2px solid {color}; '
                f'padding: 1px 2px; border-radius: 2px;" '
                f'title="{det.pattern_type.name}">{self._escape_html(det.value)}</span>'
            )
            last_end = det.end
            
        # Ajouter le reste du texte
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
            prefix = self.PREFIXES.get(det.pattern_type, "UNKNOWN")
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


def get_presets() -> Dict[str, Dict]:
    """Retourne la liste des presets disponibles."""
    return PRESETS


if __name__ == "__main__":
    # Exemple d'utilisation
    sample_log = """
    2024-01-15 10:23:45 ERROR - Connection failed to server prod-db-01.company.internal
    User john.doe@company.com attempted login from 192.168.1.100
    API call to https://api.company.com/v1/users failed
    Token: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U
    Request ID: 550e8400-e29b-41d4-a716-446655440000
    File: C:\\Users\\jdoe\\Documents\\config.yaml
    MAC: 00:1A:2B:3C:4D:5E
    Phone: +33 6 12 34 56 78
    AWS Instance: i-0123456789abcdef0
    ARN: arn:aws:ec2:eu-west-1:123456789012:instance/i-0123456789abcdef0
    """
    
    result = anonymize_text(sample_log)
    print("=== TEXTE ANONYMISÉ ===")
    print(result.anonymized_text)
    print("\n=== STATISTIQUES ===")
    print(result.stats)
    print("\n=== MAPPINGS ===")
    for original, placeholder in result.mappings.items():
        print(f"  {placeholder}: {original}")
