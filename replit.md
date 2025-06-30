# XSS Playground - Educational Security Laboratory

## Overview

The XSS Playground is an educational web application built with Flask that demonstrates Cross-Site Scripting (XSS) vulnerabilities in a controlled environment. The application provides hands-on learning experiences for understanding different types of XSS attacks and their mitigation techniques.

## System Architecture

### Frontend Architecture
- **Template Engine**: Jinja2 templates with Bootstrap 5 dark theme
- **Static Assets**: CSS and JavaScript files for styling and client-side functionality
- **UI Framework**: Bootstrap with Font Awesome icons for a modern, responsive interface
- **Client-side Logic**: Custom JavaScript for payload logging, statistics tracking, and educational demonstrations

### Backend Architecture
- **Framework**: Flask (Python web framework)
- **Application Structure**: Single-file Flask application (`app.py`) with modular route handling
- **Session Management**: Flask sessions with configurable secret key
- **Security Modes**: Toggle between "secure" and "insecure" modes to demonstrate vulnerability mitigation

### Data Storage
- **In-Memory Storage**: Uses Python lists for educational purposes (no persistent database)
- **Comment Storage**: `stored_comments` list for stored XSS demonstrations
- **Logging System**: `xss_logs` list for tracking payload executions and security events

## Key Components

### 1. XSS Demonstration Modules
- **Reflected XSS**: Demonstrates how URL parameters can be exploited when reflected without sanitization
- **Stored XSS**: Shows persistent XSS attacks through comment systems
- **Custom Payload Testing**: Allows users to test their own XSS payloads
- **Payload Generator**: Pre-built XSS payloads for different attack scenarios

### 2. Security Toggle System
- **Dual Mode Operation**: Switches between vulnerable and secure implementations
- **HTML Escaping**: Uses Python's `html.escape()` function for input sanitization in secure mode
- **Real-time Switching**: Allows dynamic toggling to compare secure vs. insecure behavior

### 3. Logging and Monitoring
- **Payload Tracking**: Comprehensive logging of XSS payload executions
- **Statistics Dashboard**: Real-time statistics on different types of XSS attempts
- **Error Handling**: JavaScript error monitoring for educational purposes

### 4. Educational Interface
- **Interactive Tutorials**: Step-by-step demonstrations of XSS concepts
- **Code Examples**: Shows both vulnerable and secure code implementations
- **Visual Feedback**: Color-coded alerts and indicators for security status

## Data Flow

1. **User Input**: Users submit data through various forms (search, comments, custom payloads)
2. **Security Check**: Application checks current security mode setting
3. **Processing**: 
   - Secure mode: Input is sanitized using `html.escape()`
   - Insecure mode: Raw input is processed without sanitization
4. **Storage**: Data stored in in-memory lists for demonstration purposes
5. **Display**: Processed data rendered in templates with appropriate security measures
6. **Logging**: All activities logged for educational analysis

## External Dependencies

### Frontend Dependencies
- **Bootstrap 5**: UI framework via CDN (Replit dark theme variant)
- **Font Awesome 6.4.0**: Icon library via CDN
- **Custom CSS/JS**: Local static files for playground-specific functionality

### Backend Dependencies
- **Flask**: Core web framework
- **Python Standard Library**: 
  - `html` module for input sanitization
  - `logging` for debugging and educational logging
  - `datetime` for timestamp tracking
  - `os` for environment variable management

## Deployment Strategy

### Development Environment
- **Entry Point**: `main.py` imports and runs the Flask application
- **Debug Mode**: Enabled for educational purposes with detailed error messages
- **Host Configuration**: Configured for `0.0.0.0:5000` to work in container environments
- **Environment Variables**: `SESSION_SECRET` for session security

### Security Considerations
- **Educational Purpose Only**: Intentionally vulnerable in "insecure" mode for learning
- **Controlled Environment**: No persistent storage to limit security risks
- **Session Management**: Configurable secret key for session security
- **Input Validation**: Demonstrates both presence and absence of proper validation

## Changelog

- June 30, 2025. Initial setup

## User Preferences

Preferred communication style: Simple, everyday language.