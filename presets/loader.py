"""
Chargeur de presets depuis les fichiers JSON.
Permet de charger dynamiquement les configurations de presets.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Any

# Répertoire contenant les fichiers JSON de presets
PRESETS_DIR = Path(__file__).parent


class PresetLoader:
    """
    Gestionnaire de chargement des presets.
    Charge les presets depuis les fichiers JSON et les met en cache.
    """
    
    _cache: Dict[str, Dict] = {}
    _loaded: bool = False
    
    @classmethod
    def _load_all(cls) -> None:
        """Charge tous les presets depuis les fichiers JSON."""
        if cls._loaded:
            return
        
        cls._cache.clear()
        
        for json_file in PRESETS_DIR.glob("*.json"):
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    preset = json.load(f)
                    preset_id = preset.get('id', json_file.stem)
                    cls._cache[preset_id] = preset
            except (json.JSONDecodeError, IOError) as e:
                print(f"Warning: Could not load preset {json_file}: {e}")
        
        cls._loaded = True
    
    @classmethod
    def reload(cls) -> None:
        """Force le rechargement de tous les presets."""
        cls._loaded = False
        cls._load_all()
    
    @classmethod
    def get_all(cls) -> Dict[str, Dict]:
        """Retourne tous les presets disponibles."""
        cls._load_all()
        return cls._cache.copy()
    
    @classmethod
    def get(cls, preset_id: str) -> Optional[Dict]:
        """Retourne un preset par son ID."""
        cls._load_all()
        return cls._cache.get(preset_id)
    
    @classmethod
    def list_ids(cls) -> List[str]:
        """Retourne la liste des IDs de presets disponibles."""
        cls._load_all()
        return list(cls._cache.keys())
    
    @classmethod
    def add_custom_preset(cls, preset: Dict) -> bool:
        """
        Ajoute un preset personnalisé (en mémoire uniquement).
        Pour persister, utilisez save_preset().
        """
        cls._load_all()
        preset_id = preset.get('id')
        if not preset_id:
            return False
        cls._cache[preset_id] = preset
        return True
    
    @classmethod
    def save_preset(cls, preset: Dict) -> bool:
        """
        Sauvegarde un preset dans un fichier JSON.
        """
        preset_id = preset.get('id')
        if not preset_id:
            return False
        
        # Valider les champs requis
        required_fields = ['id', 'name', 'description', 'patterns']
        if not all(field in preset for field in required_fields):
            return False
        
        # S'assurer que les champs optionnels existent
        preset.setdefault('preserve', [])
        preset.setdefault('custom_patterns', [])
        
        filepath = PRESETS_DIR / f"{preset_id}.json"
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(preset, f, indent=4, ensure_ascii=False)
            
            # Mettre à jour le cache
            cls._cache[preset_id] = preset
            return True
        except IOError as e:
            print(f"Error saving preset {preset_id}: {e}")
            return False
    
    @classmethod
    def delete_preset(cls, preset_id: str) -> bool:
        """
        Supprime un preset (fichier et cache).
        Ne permet pas de supprimer les presets par défaut.
        """
        default_presets = ['default', 'ansible', 'apache', 'kubernetes', 'aws', 'database', 'security', 'minimal']
        
        if preset_id in default_presets:
            return False
        
        filepath = PRESETS_DIR / f"{preset_id}.json"
        try:
            if filepath.exists():
                filepath.unlink()
            cls._cache.pop(preset_id, None)
            return True
        except IOError:
            return False


# Variable globale pour compatibilité avec l'ancien code
def _build_presets_dict() -> Dict[str, Dict]:
    """Construit le dictionnaire PRESETS au format attendu par l'ancien code."""
    return PresetLoader.get_all()


# Initialiser PRESETS comme un dictionnaire qui se charge paresseusement
class _LazyPresets(dict):
    """Dictionnaire qui charge les presets à la première utilisation."""
    
    _initialized: bool = False
    
    def _ensure_loaded(self) -> None:
        if not self._initialized:
            self.update(PresetLoader.get_all())
            self._initialized = True
    
    def __getitem__(self, key: str) -> Dict:
        self._ensure_loaded()
        return super().__getitem__(key)
    
    def __contains__(self, key: object) -> bool:
        self._ensure_loaded()
        return super().__contains__(key)
    
    def __iter__(self):
        self._ensure_loaded()
        return super().__iter__()
    
    def keys(self):
        self._ensure_loaded()
        return super().keys()
    
    def values(self):
        self._ensure_loaded()
        return super().values()
    
    def items(self):
        self._ensure_loaded()
        return super().items()
    
    def get(self, key: str, default: Any = None) -> Any:
        self._ensure_loaded()
        return super().get(key, default)


PRESETS = _LazyPresets()


def get_presets() -> Dict[str, Dict]:
    """Retourne tous les presets disponibles (compatibilité)."""
    return PresetLoader.get_all()


def get_preset(preset_id: str) -> Optional[Dict]:
    """Retourne un preset par son ID (compatibilité)."""
    return PresetLoader.get(preset_id)

