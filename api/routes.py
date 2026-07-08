"""
Routes API Flask pour l'anonymisation de logs et fichiers.
"""

from flask import Blueprint, request, jsonify, send_file, session, current_app
import io
import json
import secrets
from collections import OrderedDict

from core import Anonymizer, PatternType
from presets import PRESETS, get_presets

# Blueprint pour les routes API
api_bp = Blueprint('api', __name__)

# Instance globale pour maintenir les mappings entre requêtes (mode standard mono-utilisateur).
current_anonymizer = Anonymizer()

# En DEMO_MODE, chaque visiteur obtient son propre Anonymizer (clé = cookie de session signé)
# pour ne jamais mélanger les mappings de deux utilisateurs simultanés. Stockage en mémoire
# uniquement, avec éviction LRU pour borner la consommation mémoire (pas de persistance disque).
_demo_sessions: "OrderedDict[str, Anonymizer]" = OrderedDict()


def _is_demo_mode() -> bool:
    return bool(current_app.config.get('DEMO_MODE', False))


def get_current_anonymizer() -> Anonymizer:
    """
    Retourne l'instance courante de l'anonymizer.
    Mode standard : instance globale unique (comportement historique inchangé).
    Mode démo : instance isolée par session pour éviter toute fuite entre visiteurs.
    """
    global current_anonymizer

    if not _is_demo_mode():
        return current_anonymizer

    sid = session.get('sid')
    if not sid or sid not in _demo_sessions:
        sid = secrets.token_urlsafe(16)
        session['sid'] = sid
        _demo_sessions[sid] = Anonymizer()

    _demo_sessions.move_to_end(sid)
    max_sessions = current_app.config.get('DEMO_MAX_SESSIONS', 200)
    while len(_demo_sessions) > max_sessions:
        _demo_sessions.popitem(last=False)

    return _demo_sessions[sid]


def set_current_anonymizer(anonymizer: Anonymizer) -> None:
    """Remplace l'instance courante (global ou de session en mode démo)."""
    global current_anonymizer

    if _is_demo_mode():
        sid = session.get('sid')
        if not sid:
            sid = secrets.token_urlsafe(16)
            session['sid'] = sid
        _demo_sessions[sid] = anonymizer
        _demo_sessions.move_to_end(sid)
        return

    current_anonymizer = anonymizer


def reset_anonymizer() -> None:
    """Réinitialise l'anonymizer courant (global ou de session en mode démo)."""
    set_current_anonymizer(Anonymizer())


@api_bp.route('/preview', methods=['POST'])
def preview():
    """Endpoint pour le preview avec highlighting."""
    data = request.get_json()
    text = data.get('text', '')
    enabled_patterns = data.get('enabled_patterns', [])
    custom_patterns = data.get('custom_patterns', [])
    preserve_values = data.get('preserve_values', [])

    # Créer un anonymizer temporaire pour le preview
    preview_anon = Anonymizer()

    for pt in PatternType:
        preview_anon.set_pattern_enabled(pt, pt.value in enabled_patterns)

    for cp in custom_patterns:
        if cp.get('regex') and cp.get('prefix'):
            preview_anon.add_custom_pattern(cp['regex'], cp['prefix'])

    for val in preserve_values:
        if val.strip():
            preview_anon.add_preserve_value(val.strip())

    result = preview_anon.preview(text)

    return jsonify({
        'highlighted_html': result.highlighted_html,
        'stats': result.stats,
        'detection_count': len(result.detections),
        'detections': [
            {
                'value': d.value,
                'type': d.pattern_type.value,
                'start': d.start,
                'end': d.end
            }
            for d in result.detections
        ]
    })


@api_bp.route('/anonymize', methods=['POST'])
def anonymize():
    """Endpoint pour anonymiser du texte."""
    data = request.get_json()
    text = data.get('text', '')
    reset_mappings = data.get('reset_mappings', False)
    enabled_patterns = data.get('enabled_patterns', [])
    custom_patterns = data.get('custom_patterns', [])
    preserve_values = data.get('preserve_values', [])

    if reset_mappings:
        set_current_anonymizer(Anonymizer())

    anon = get_current_anonymizer()

    for pt in PatternType:
        anon.set_pattern_enabled(pt, pt.value in enabled_patterns)

    anon.custom_patterns.clear()
    for cp in custom_patterns:
        if cp.get('regex') and cp.get('prefix'):
            anon.add_custom_pattern(cp['regex'], cp['prefix'])

    anon.preserve_list.clear()
    for val in preserve_values:
        if val.strip():
            anon.add_preserve_value(val.strip())

    result = anon.anonymize(text)

    return jsonify({
        'anonymized_text': result.anonymized_text,
        'stats': result.stats,
        'mappings': anon.get_mapping_table(),
        'total_replacements': sum(result.stats.values()),
        'session_state': anon.get_session_state()
    })


@api_bp.route('/deanonymize', methods=['POST'])
def deanonymize():
    """Endpoint pour restaurer le texte original."""
    data = request.get_json()
    text = data.get('text', '')

    anon = get_current_anonymizer()
    result = anon.deanonymize(text)

    return jsonify({
        'original_text': result
    })


@api_bp.route('/reset', methods=['POST'])
def reset():
    """Réinitialise les mappings."""
    reset_anonymizer()
    return jsonify({'status': 'ok'})


@api_bp.route('/load-preset', methods=['POST'])
def load_preset():
    """Charge un preset de configuration."""
    data = request.get_json()
    preset_name = data.get('preset', 'default')

    anon = get_current_anonymizer()
    anon.load_preset(preset_name)
    preset = PRESETS.get(preset_name, {})

    return jsonify({
        'status': 'ok',
        'preset': preset_name,
        'enabled_patterns': preset.get('patterns', []),
        'preserve_values': preset.get('preserve', []),
        'custom_patterns': preset.get('custom_patterns', [])
    })


@api_bp.route('/save-session', methods=['POST'])
def save_session():
    """Sauvegarde l'état de la session."""
    anon = get_current_anonymizer()
    state = anon.get_session_state()

    return jsonify({
        'status': 'ok',
        'session_state': state
    })


@api_bp.route('/load-session', methods=['POST'])
def load_session():
    """Charge un état de session sauvegardé."""
    data = request.get_json()
    state = data.get('session_state', {})

    anon = get_current_anonymizer()
    success = anon.load_session_state(state)

    return jsonify({
        'status': 'ok' if success else 'error',
        'mappings': anon.get_mapping_table()
    })


@api_bp.route('/export-mappings', methods=['GET'])
def export_mappings():
    """Exporte les mappings en fichier texte."""
    format = request.args.get('format', 'text')
    anon = get_current_anonymizer()
    content = anon.export_mappings(format=format)

    buffer = io.BytesIO()
    buffer.write(content.encode('utf-8'))
    buffer.seek(0)

    filename = f'anonymization_mappings.{"json" if format == "json" else "txt"}'
    mimetype = 'application/json' if format == 'json' else 'text/plain'

    return send_file(
        buffer,
        mimetype=mimetype,
        as_attachment=True,
        download_name=filename
    )


@api_bp.route('/import-mappings', methods=['POST'])
def import_mappings():
    """Importe des mappings depuis un fichier JSON."""
    data = request.get_json()
    mappings_data = data.get('data', '')

    anon = get_current_anonymizer()
    success = anon.import_mappings(mappings_data, format='json')

    return jsonify({
        'status': 'ok' if success else 'error',
        'mappings': anon.get_mapping_table()
    })


@api_bp.route('/upload', methods=['POST'])
def upload_file():
    """Upload et anonymise un fichier."""
    if 'file' not in request.files:
        return jsonify({'error': 'Aucun fichier fourni'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Aucun fichier sélectionné'}), 400

    try:
        content = file.read().decode('utf-8')
    except UnicodeDecodeError:
        try:
            file.seek(0)
            content = file.read().decode('latin-1')
        except Exception:
            return jsonify({'error': 'Impossible de lire le fichier (encodage non supporté)'}), 400

    reset_mappings = request.form.get('reset_mappings', 'false') == 'true'
    enabled_patterns = json.loads(request.form.get('enabled_patterns', '[]'))

    if reset_mappings:
        set_current_anonymizer(Anonymizer())

    anon = get_current_anonymizer()

    for pt in PatternType:
        anon.set_pattern_enabled(pt, pt.value in enabled_patterns)

    result = anon.anonymize(content)

    return jsonify({
        'original_text': content,
        'anonymized_text': result.anonymized_text,
        'stats': result.stats,
        'mappings': anon.get_mapping_table(),
        'total_replacements': sum(result.stats.values()),
        'filename': file.filename
    })


@api_bp.route('/presets', methods=['GET'])
def list_presets():
    """Liste tous les presets disponibles."""
    presets = [
        {"id": k, "name": v["name"], "description": v["description"]}
        for k, v in get_presets().items()
    ]
    return jsonify({'presets': presets})


# ==========================================
# Routes pour les Enhancers
# ==========================================

@api_bp.route('/enhancers', methods=['GET'])
def list_enhancers():
    """Liste tous les enhancers et leur statut."""
    anon = get_current_anonymizer()
    status = anon.get_enhancers_status()

    return jsonify(status)


@api_bp.route('/enhancers/<name>', methods=['POST'])
def configure_enhancer(name: str):
    """Configure et active/désactive un enhancer."""
    data = request.get_json()
    enabled = data.get('enabled', False)
    config = data.get('config', {})

    anon = get_current_anonymizer()
    success = anon.set_enhancer_enabled(name, enabled, config)

    return jsonify({
        'status': 'ok' if success else 'error',
        'enhancer': name,
        'enabled': enabled,
        'message': f"Enhancer '{name}' {'activé' if enabled else 'désactivé'}" if success else f"Enhancer '{name}' non disponible"
    })


@api_bp.route('/enhancers/enable-all', methods=['POST'])
def enable_all_enhancers():
    """Active tous les enhancers disponibles."""
    data = request.get_json() or {}
    config = data.get('config', {})

    anon = get_current_anonymizer()
    status = anon.get_enhancers_status()
    enabled_list = []

    for name, info in status.get('enhancers', {}).items():
        if info.get('available', False):
            enhancer_config = config.get(name, {})
            if anon.set_enhancer_enabled(name, True, enhancer_config):
                enabled_list.append(name)

    return jsonify({
        'status': 'ok',
        'enabled': enabled_list,
        'message': f"{len(enabled_list)} enhancer(s) activé(s)"
    })


@api_bp.route('/enhancers/disable-all', methods=['POST'])
def disable_all_enhancers():
    """Désactive tous les enhancers."""
    anon = get_current_anonymizer()
    status = anon.get_enhancers_status()

    for name in status.get('enhancers', {}).keys():
        anon.set_enhancer_enabled(name, False)

    return jsonify({
        'status': 'ok',
        'message': 'Tous les enhancers désactivés'
    })
