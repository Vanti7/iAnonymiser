"""
Application web Flask pour l'anonymisation de logs et fichiers.
Interface moderne et intuitive avec preview en temps réel.

Point d'entrée principal de l'application.
"""

import sys
from pathlib import Path

# Ajouter le répertoire racine au path pour les imports
sys.path.insert(0, str(Path(__file__).parent))

from flask import Flask, render_template

from config import Config, VERSION
from core import PatternType
from patterns import PATTERN_COLORS
from presets import PRESETS
from api import api_bp


def create_app(config_class=Config):
    """Factory function pour créer l'application Flask."""
    app = Flask(__name__)
    app.config.from_object(config_class)
    app.config['MAX_CONTENT_LENGTH'] = config_class.MAX_CONTENT_LENGTH
    
    # Enregistrer le blueprint API
    app.register_blueprint(api_bp)
    
    # Route principale
    @app.route('/')
    def index():
        """Page principale."""
        pattern_types = [
            {
                "id": pt.value, 
                "name": pt.name.replace("_", " ").title(), 
                "enabled": True,
                "color": PATTERN_COLORS.get(pt, "#868e96")
            }
            for pt in PatternType if pt != PatternType.CUSTOM
        ]
        presets = [
            {"id": k, "name": v["name"], "description": v["description"]}
            for k, v in PRESETS.items()
        ]
        return render_template('index.html', pattern_types=pattern_types, presets=presets, version=VERSION)
    
    return app


# Créer l'application
app = create_app()


if __name__ == '__main__':
    app.run(debug=True, host=Config.HOST, port=Config.PORT)
