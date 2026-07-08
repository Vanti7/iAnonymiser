"""
Application web Flask pour l'anonymisation de logs et fichiers.
Interface moderne et intuitive avec preview en temps réel.

Point d'entrée principal de l'application.
"""

import os
import secrets
import sys
import json
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

    # Requis pour les cookies de session (isolation des mappings en DEMO_MODE).
    # Sans persistance : une valeur aléatoire régénérée à chaque démarrage suffit,
    # les sessions démo n'ont pas vocation à survivre à un redémarrage.
    app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)

    # Enregistrer le blueprint API
    app.register_blueprint(api_bp)

    if config_class.DEMO_MODE:
        @app.after_request
        def _tag_demo_response(response):
            """Ajoute un champ "demo": true aux réponses JSON en mode démo public."""
            if response.mimetype == 'application/json':
                try:
                    payload = json.loads(response.get_data(as_text=True))
                except ValueError:
                    return response
                if isinstance(payload, dict):
                    payload['demo'] = True
                    response.set_data(json.dumps(payload))
            return response

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
        return render_template(
            'index.html',
            pattern_types=pattern_types,
            presets=presets,
            version=VERSION,
            demo_mode=config_class.DEMO_MODE,
        )

    return app


# Créer l'application
app = create_app()


if __name__ == '__main__':
    app.run(debug=True, host=Config.HOST, port=Config.PORT)
