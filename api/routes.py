"""
Routes API Flask pour l'anonymisation de logs et fichiers.
"""

from flask import Blueprint, request, jsonify, send_file
import io
import json

from core import Anonymizer, PatternType
from patterns import PATTERN_COLORS
from presets import PRESETS, get_presets

# Blueprint pour les routes API
api_bp = Blueprint('api', __name__)

# Instance globale pour maintenir les mappings entre requêtes
current_anonymizer = Anonymizer()


def get_current_anonymizer() -> Anonymizer:
    """Retourne l'instance courante de l'anonymizer."""
    global current_anonymizer
    return current_anonymizer


def reset_anonymizer() -> None:
    """Réinitialise l'anonymizer global."""
    global current_anonymizer
    current_anonymizer = Anonymizer()


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
    global current_anonymizer
    
    data = request.get_json()
    text = data.get('text', '')
    reset_mappings = data.get('reset_mappings', False)
    enabled_patterns = data.get('enabled_patterns', [])
    custom_patterns = data.get('custom_patterns', [])
    preserve_values = data.get('preserve_values', [])
    
    if reset_mappings:
        current_anonymizer = Anonymizer()
    
    for pt in PatternType:
        current_anonymizer.set_pattern_enabled(pt, pt.value in enabled_patterns)
    
    current_anonymizer.custom_patterns.clear()
    for cp in custom_patterns:
        if cp.get('regex') and cp.get('prefix'):
            current_anonymizer.add_custom_pattern(cp['regex'], cp['prefix'])
    
    current_anonymizer.preserve_list.clear()
    for val in preserve_values:
        if val.strip():
            current_anonymizer.add_preserve_value(val.strip())
    
    result = current_anonymizer.anonymize(text)
    
    return jsonify({
        'anonymized_text': result.anonymized_text,
        'stats': result.stats,
        'mappings': current_anonymizer.get_mapping_table(),
        'total_replacements': sum(result.stats.values()),
        'session_state': current_anonymizer.get_session_state()
    })


@api_bp.route('/deanonymize', methods=['POST'])
def deanonymize():
    """Endpoint pour restaurer le texte original."""
    global current_anonymizer
    
    data = request.get_json()
    text = data.get('text', '')
    
    result = current_anonymizer.deanonymize(text)
    
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
    global current_anonymizer
    
    data = request.get_json()
    preset_name = data.get('preset', 'default')
    
    current_anonymizer.load_preset(preset_name)
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
    global current_anonymizer
    
    state = current_anonymizer.get_session_state()
    
    return jsonify({
        'status': 'ok',
        'session_state': state
    })


@api_bp.route('/load-session', methods=['POST'])
def load_session():
    """Charge un état de session sauvegardé."""
    global current_anonymizer
    
    data = request.get_json()
    state = data.get('session_state', {})
    
    success = current_anonymizer.load_session_state(state)
    
    return jsonify({
        'status': 'ok' if success else 'error',
        'mappings': current_anonymizer.get_mapping_table()
    })


@api_bp.route('/export-mappings', methods=['GET'])
def export_mappings():
    """Exporte les mappings en fichier texte."""
    global current_anonymizer
    
    format = request.args.get('format', 'text')
    content = current_anonymizer.export_mappings(format=format)
    
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
    global current_anonymizer
    
    data = request.get_json()
    mappings_data = data.get('data', '')
    
    success = current_anonymizer.import_mappings(mappings_data, format='json')
    
    return jsonify({
        'status': 'ok' if success else 'error',
        'mappings': current_anonymizer.get_mapping_table()
    })


@api_bp.route('/upload', methods=['POST'])
def upload_file():
    """Upload et anonymise un fichier."""
    global current_anonymizer
    
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
        except:
            return jsonify({'error': 'Impossible de lire le fichier (encodage non supporté)'}), 400
    
    reset_mappings = request.form.get('reset_mappings', 'false') == 'true'
    enabled_patterns = json.loads(request.form.get('enabled_patterns', '[]'))
    
    if reset_mappings:
        current_anonymizer = Anonymizer()
    
    for pt in PatternType:
        current_anonymizer.set_pattern_enabled(pt, pt.value in enabled_patterns)
    
    result = current_anonymizer.anonymize(content)
    
    return jsonify({
        'original_text': content,
        'anonymized_text': result.anonymized_text,
        'stats': result.stats,
        'mappings': current_anonymizer.get_mapping_table(),
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

