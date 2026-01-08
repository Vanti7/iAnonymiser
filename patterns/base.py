"""
Patterns de détection par défaut pour les données sensibles.
L'ordre définit la priorité : les patterns en premier sont testés d'abord.
"""

from core.models import PatternType

# Patterns de détection par défaut (regex)
DEFAULT_PATTERNS: dict[PatternType, str] = {
    # Priorité haute : patterns spécifiques qui pourraient être capturés par d'autres
    PatternType.PRIVATE_KEY: r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----',
    PatternType.JWT: r'\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b',
    PatternType.CONNECTION_STRING: r'(?:Server|Data Source|Host|jdbc:[a-z]+:)=[^;\s]+(?:;[^;\s]+)*(?:;(?:Password|Pwd|PWD)=[^;\s]+)',
    
    # URLs avant hostnames pour éviter les faux positifs
    PatternType.URL: r'https?://[^\s<>"\'{}|\\^`\[\]]+(?:\?[^\s<>"\'{}|\\^`\[\]]*)?',
    
    # Email avec meilleur support des sous-domaines et TLDs
    PatternType.EMAIL: r'\b[A-Za-z0-9](?:[A-Za-z0-9._%+-]{0,62}[A-Za-z0-9])?@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b',
    
    # UUID
    PatternType.UUID: r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b',
    
    # IPv4
    PatternType.IPV4: r'\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?:/[0-9]{1,2})?\b',
    
    # IPv6 amélioré - supporte toutes les formes compressées
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
    
    # MAC Address
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
    
    # Date
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

# Préfixes pour les placeholders
PREFIXES: dict[PatternType, str] = {
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

