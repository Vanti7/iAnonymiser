"""
Couleurs associées à chaque type de pattern pour le highlighting.
"""

from core.models import PatternType

# Couleurs pour le highlighting (valeurs CSS)
PATTERN_COLORS: dict[PatternType, str] = {
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

