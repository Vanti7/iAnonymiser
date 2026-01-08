"""
Application web Flask pour l'anonymisation de logs et fichiers.
Interface moderne et intuitive avec preview en temps réel.
"""

from flask import Flask, render_template, request, jsonify, send_file
from anonymizer import Anonymizer, PatternType, anonymize_text, get_presets, PATTERN_COLORS, PRESETS
import io
import json

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50 MB max

# Instance globale pour maintenir les mappings entre requêtes
current_anonymizer = Anonymizer()


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
    return render_template('index.html', pattern_types=pattern_types, presets=presets)


@app.route('/preview', methods=['POST'])
def preview():
    """Endpoint pour le preview avec highlighting."""
    global current_anonymizer
    
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


@app.route('/anonymize', methods=['POST'])
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


@app.route('/deanonymize', methods=['POST'])
def deanonymize():
    """Endpoint pour restaurer le texte original."""
    global current_anonymizer
    
    data = request.get_json()
    text = data.get('text', '')
    
    result = current_anonymizer.deanonymize(text)
    
    return jsonify({
        'original_text': result
    })


@app.route('/reset', methods=['POST'])
def reset():
    """Réinitialise les mappings."""
    global current_anonymizer
    current_anonymizer = Anonymizer()
    return jsonify({'status': 'ok'})


@app.route('/load-preset', methods=['POST'])
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


@app.route('/save-session', methods=['POST'])
def save_session():
    """Sauvegarde l'état de la session."""
    global current_anonymizer
    
    state = current_anonymizer.get_session_state()
    
    return jsonify({
        'status': 'ok',
        'session_state': state
    })


@app.route('/load-session', methods=['POST'])
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


@app.route('/export-mappings', methods=['GET'])
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


@app.route('/import-mappings', methods=['POST'])
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


@app.route('/upload', methods=['POST'])
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


@app.route('/presets', methods=['GET'])
def list_presets():
    """Liste tous les presets disponibles."""
    presets = [
        {"id": k, "name": v["name"], "description": v["description"]}
        for k, v in PRESETS.items()
    ]
    return jsonify({'presets': presets})


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
