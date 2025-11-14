#!/usr/bin/env python3
"""
Flask API with SQLite Database and JWT Authentication

This API provides endpoints to:
1. POST /api/register - Register a new user
2. POST /api/login - Login and get JWT token
3. POST /api/data - Accept JSON data and store it in SQLite (requires JWT)
4. GET /api/data - Retrieve all records from the database (requires JWT)
5. GET /api/data/<id> - Get a specific record (requires JWT)
6. DELETE /api/data/<id> - Delete a specific record (requires JWT)

Requirements:
- flask package: pip install flask
- PyJWT package: pip install PyJWT

To run:
    python voice_built_api.py

Environment Variables:
    JWT_SECRET_KEY - Secret key for JWT token signing (optional, auto-generated if not set)
"""

from flask import Flask, request, jsonify
import sqlite3
import os
import json
import logging
import jwt
import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database file path
DATABASE = 'data.db'

# JWT Configuration
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', secrets.token_urlsafe(32))  # Generate random key if not set
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_HOURS = 24  # Token expires in 24 hours

# Configuration constants
MAX_JSON_SIZE = 1024 * 1024  # 1MB max JSON size
MAX_RECORDS_LIMIT = 1000  # Maximum records to return at once
MIN_PASSWORD_LENGTH = 8  # Minimum password length

def get_db_connection():
    """Create and return a database connection with error handling."""
    try:
        conn = sqlite3.connect(DATABASE, timeout=10.0)
        conn.row_factory = sqlite3.Row  # This enables column access by name
        return conn
    except sqlite3.Error as e:
        logger.error(f"Database connection error: {str(e)}")
        raise

def init_db():
    """Initialize the database with tables if they don't exist."""
    try:
        conn = get_db_connection()
        
        # Create users table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create records table with user_id foreign key
        conn.execute('''
            CREATE TABLE IF NOT EXISTS records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                data TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')
        
        # Create index on user_id for faster queries
        conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_records_user_id ON records(user_id)
        ''')
        
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")
    except sqlite3.Error as e:
        logger.error(f"Database initialization error: {str(e)}")
        raise

def hash_password(password):
    """Hash a password using SHA-256 (for simplicity; use bcrypt in production)."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def verify_password(password, password_hash):
    """Verify a password against its hash."""
    return hash_password(password) == password_hash

def generate_jwt_token(user_id, username):
    """Generate a JWT token for a user."""
    expiration = datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': expiration,
        'iat': datetime.utcnow()
    }
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token

def verify_jwt_token(token):
    """Verify and decode a JWT token."""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def token_required(f):
    """Decorator to require JWT authentication for a route."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Check for token in Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                # Format: "Bearer <token>"
                token = auth_header.split(' ')[1] if auth_header.startswith('Bearer ') else None
            except IndexError:
                return jsonify({
                    'error': 'Invalid authorization header',
                    'message': 'Authorization header must be in format: Bearer <token>'
                }), 401
        
        if not token:
            return jsonify({
                'error': 'Authentication required',
                'message': 'Token is missing. Please provide a valid JWT token.'
            }), 401
        
        # Verify token
        payload = verify_jwt_token(token)
        if payload is None:
            return jsonify({
                'error': 'Invalid or expired token',
                'message': 'The provided token is invalid or has expired'
            }), 401
        
        # Add user info to request context
        request.current_user = {
            'user_id': payload['user_id'],
            'username': payload['username']
        }
        
        return f(*args, **kwargs)
    
    return decorated

def validate_json_data(data):
    """
    Validate JSON data input.
    Returns: (is_valid, error_message)
    """
    if not isinstance(data, dict):
        return False, "Data must be a JSON object"
    
    if len(data) == 0:
        return False, "Data cannot be empty"
    
    # Check JSON size
    json_string = json.dumps(data)
    if len(json_string) > MAX_JSON_SIZE:
        return False, f"JSON data exceeds maximum size of {MAX_JSON_SIZE} bytes"
    
    # Check for nested depth (prevent extremely nested structures)
    def check_depth(obj, depth=0, max_depth=10):
        if depth > max_depth:
            return False
        if isinstance(obj, dict):
            return all(check_depth(v, depth + 1, max_depth) for v in obj.values())
        elif isinstance(obj, list):
            return all(check_depth(item, depth + 1, max_depth) for item in obj)
        return True
    
    if not check_depth(data):
        return False, "JSON data structure is too deeply nested"
    
    return True, None

def validate_record_id(record_id):
    """Validate record ID is a positive integer."""
    if not isinstance(record_id, int):
        return False, "Record ID must be an integer"
    if record_id <= 0:
        return False, "Record ID must be a positive integer"
    return True, None

def handle_db_error(func):
    """Decorator to handle database errors."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except sqlite3.OperationalError as e:
            logger.error(f"Database operational error in {func.__name__}: {str(e)}")
            return jsonify({
                'error': 'Database operation failed',
                'message': 'An error occurred while accessing the database'
            }), 500
        except sqlite3.IntegrityError as e:
            logger.error(f"Database integrity error in {func.__name__}: {str(e)}")
            return jsonify({
                'error': 'Database integrity error',
                'message': 'The operation violated database constraints'
            }), 400
        except sqlite3.Error as e:
            logger.error(f"Database error in {func.__name__}: {str(e)}")
            return jsonify({
                'error': 'Database error',
                'message': 'An unexpected database error occurred'
            }), 500
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error in {func.__name__}: {str(e)}")
            return jsonify({
                'error': 'Invalid JSON data',
                'message': 'The stored data could not be parsed as JSON'
            }), 500
        except Exception as e:
            logger.error(f"Unexpected error in {func.__name__}: {str(e)}", exc_info=True)
            return jsonify({
                'error': 'Internal server error',
                'message': 'An unexpected error occurred'
            }), 500
    return wrapper

@app.route('/api/register', methods=['POST'])
@handle_db_error
def register():
    """Register a new user."""
    if not request.is_json:
        return jsonify({
            'error': 'Invalid content type',
            'message': 'Content-Type must be application/json'
        }), 400
    
    try:
        data = request.get_json()
    except Exception as e:
        logger.error(f"JSON parsing error: {str(e)}")
        return jsonify({
            'error': 'Invalid JSON',
            'message': 'The request body contains invalid JSON'
        }), 400
    
    if not data:
        return jsonify({
            'error': 'Missing data',
            'message': 'No data provided in request body'
        }), 400
    
    # Validate input
    username = data.get('username')
    password = data.get('password')
    
    if not username:
        return jsonify({
            'error': 'Validation failed',
            'message': 'Username is required'
        }), 400
    
    if not password:
        return jsonify({
            'error': 'Validation failed',
            'message': 'Password is required'
        }), 400
    
    # Validate username format
    if not isinstance(username, str) or len(username) < 3:
        return jsonify({
            'error': 'Validation failed',
            'message': 'Username must be at least 3 characters long'
        }), 400
    
    if not username.isalnum():
        return jsonify({
            'error': 'Validation failed',
            'message': 'Username must contain only alphanumeric characters'
        }), 400
    
    # Validate password
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
        return jsonify({
            'error': 'Validation failed',
            'message': f'Password must be at least {MIN_PASSWORD_LENGTH} characters long'
        }), 400
    
    # Check if user already exists
    conn = None
    try:
        conn = get_db_connection()
        existing_user = conn.execute(
            'SELECT id FROM users WHERE username = ?',
            (username,)
        ).fetchone()
        
        if existing_user:
            return jsonify({
                'error': 'User already exists',
                'message': 'A user with this username already exists'
            }), 409
        
        # Create new user
        password_hash = hash_password(password)
        cursor = conn.execute(
            'INSERT INTO users (username, password_hash) VALUES (?, ?)',
            (username, password_hash)
        )
        user_id = cursor.lastrowid
        conn.commit()
        
        logger.info(f"User registered: {username} (ID: {user_id})")
        
        # Generate JWT token
        token = generate_jwt_token(user_id, username)
        
        return jsonify({
            'message': 'User registered successfully',
            'user_id': user_id,
            'username': username,
            'token': token
        }), 201
    finally:
        if conn:
            conn.close()

@app.route('/api/login', methods=['POST'])
@handle_db_error
def login():
    """Login and get JWT token."""
    if not request.is_json:
        return jsonify({
            'error': 'Invalid content type',
            'message': 'Content-Type must be application/json'
        }), 400
    
    try:
        data = request.get_json()
    except Exception as e:
        logger.error(f"JSON parsing error: {str(e)}")
        return jsonify({
            'error': 'Invalid JSON',
            'message': 'The request body contains invalid JSON'
        }), 400
    
    if not data:
        return jsonify({
            'error': 'Missing data',
            'message': 'No data provided in request body'
        }), 400
    
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({
            'error': 'Validation failed',
            'message': 'Username and password are required'
        }), 400
    
    conn = None
    try:
        conn = get_db_connection()
        user = conn.execute(
            'SELECT id, username, password_hash FROM users WHERE username = ?',
            (username,)
        ).fetchone()
        
        if not user:
            logger.warning(f"Login attempt with non-existent username: {username}")
            return jsonify({
                'error': 'Invalid credentials',
                'message': 'Invalid username or password'
            }), 401
        
        # Verify password
        if not verify_password(password, user['password_hash']):
            logger.warning(f"Failed login attempt for user: {username}")
            return jsonify({
                'error': 'Invalid credentials',
                'message': 'Invalid username or password'
            }), 401
        
        # Generate JWT token
        token = generate_jwt_token(user['id'], user['username'])
        
        logger.info(f"User logged in: {username} (ID: {user['id']})")
        
        return jsonify({
            'message': 'Login successful',
            'user_id': user['id'],
            'username': user['username'],
            'token': token
        }), 200
    finally:
        if conn:
            conn.close()

@app.route('/api/data', methods=['POST'])
@token_required
@handle_db_error
def create_record():
    """Accept JSON data and store it in SQLite."""
    # Check if request contains JSON
    if not request.is_json:
        return jsonify({
            'error': 'Invalid content type',
            'message': 'Content-Type must be application/json'
        }), 400
    
    # Check content length
    if request.content_length and request.content_length > MAX_JSON_SIZE:
        return jsonify({
            'error': 'Payload too large',
            'message': f'Request body exceeds maximum size of {MAX_JSON_SIZE} bytes'
        }), 413
    
    # Get JSON data from request with error handling
    try:
        json_data = request.get_json(force=False)
    except Exception as e:
        logger.error(f"JSON parsing error: {str(e)}")
        return jsonify({
            'error': 'Invalid JSON',
            'message': 'The request body contains invalid JSON'
        }), 400
    
    if json_data is None:
        return jsonify({
            'error': 'Missing data',
            'message': 'No JSON data provided in request body'
        }), 400
    
    # Validate JSON data
    is_valid, error_message = validate_json_data(json_data)
    if not is_valid:
        return jsonify({
            'error': 'Validation failed',
            'message': error_message
        }), 400
    
    # Convert JSON to string for storage
    try:
        data_string = json.dumps(json_data, ensure_ascii=False)
    except (TypeError, ValueError) as e:
        logger.error(f"JSON serialization error: {str(e)}")
        return jsonify({
            'error': 'Serialization error',
            'message': 'Data could not be serialized to JSON'
        }), 400
    
    # Insert into database with user_id
    conn = None
    try:
        user_id = request.current_user['user_id']
        conn = get_db_connection()
        cursor = conn.execute(
            'INSERT INTO records (user_id, data) VALUES (?, ?)',
            (user_id, data_string)
        )
        record_id = cursor.lastrowid
        conn.commit()
        logger.info(f"Record created with ID: {record_id} by user {user_id}")
        return jsonify({
            'message': 'Record created successfully',
            'id': record_id,
            'data': json_data
        }), 201
    finally:
        if conn:
            conn.close()

@app.route('/api/data', methods=['GET'])
@token_required
@handle_db_error
def get_all_records():
    """Retrieve all records from the database for the authenticated user."""
    # Validate query parameters
    limit = request.args.get('limit', type=int)
    if limit is not None:
        if limit <= 0:
            return jsonify({
                'error': 'Invalid parameter',
                'message': 'Limit must be a positive integer'
            }), 400
        if limit > MAX_RECORDS_LIMIT:
            return jsonify({
                'error': 'Invalid parameter',
                'message': f'Limit cannot exceed {MAX_RECORDS_LIMIT}'
            }), 400
    
    conn = None
    try:
        user_id = request.current_user['user_id']
        conn = get_db_connection()
        if limit:
            rows = conn.execute(
                'SELECT * FROM records WHERE user_id = ? ORDER BY created_at DESC LIMIT ?',
                (user_id, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                'SELECT * FROM records WHERE user_id = ? ORDER BY created_at DESC',
                (user_id,)
            ).fetchall()
        
        # Convert rows to list of dictionaries
        records = []
        for row in rows:
            try:
                records.append({
                    'id': row['id'],
                    'data': json.loads(row['data']),  # Parse JSON string back to dict
                    'created_at': row['created_at']
                })
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse JSON for record ID {row['id']}: {str(e)}")
                # Include record with error indicator instead of failing completely
                records.append({
                    'id': row['id'],
                    'data': None,
                    'error': 'Failed to parse stored JSON data',
                    'created_at': row['created_at']
                })
        
        return jsonify({
            'count': len(records),
            'records': records
        }), 200
    finally:
        if conn:
            conn.close()

@app.route('/api/data/<int:record_id>', methods=['GET'])
@token_required
@handle_db_error
def get_record(record_id):
    """Retrieve a specific record by ID for the authenticated user."""
    # Validate record ID
    is_valid, error_message = validate_record_id(record_id)
    if not is_valid:
        return jsonify({
            'error': 'Invalid record ID',
            'message': error_message
        }), 400
    
    conn = None
    try:
        user_id = request.current_user['user_id']
        conn = get_db_connection()
        row = conn.execute(
            'SELECT * FROM records WHERE id = ? AND user_id = ?',
            (record_id, user_id)
        ).fetchone()
        
        if row is None:
            return jsonify({
                'error': 'Record not found',
                'message': f'No record found with ID {record_id}'
            }), 404
        
        # Parse JSON data with error handling
        try:
            data = json.loads(row['data'])
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON for record ID {record_id}: {str(e)}")
            return jsonify({
                'error': 'Data corruption',
                'message': 'The stored data for this record is corrupted and cannot be parsed'
            }), 500
        
        return jsonify({
            'id': row['id'],
            'data': data,
            'created_at': row['created_at']
        }), 200
    finally:
        if conn:
            conn.close()

@app.route('/api/data/<int:record_id>', methods=['DELETE'])
@token_required
@handle_db_error
def delete_record(record_id):
    """Delete a specific record by ID for the authenticated user."""
    # Validate record ID
    is_valid, error_message = validate_record_id(record_id)
    if not is_valid:
        return jsonify({
            'error': 'Invalid record ID',
            'message': error_message
        }), 400
    
    conn = None
    try:
        user_id = request.current_user['user_id']
        conn = get_db_connection()
        cursor = conn.execute(
            'DELETE FROM records WHERE id = ? AND user_id = ?',
            (record_id, user_id)
        )
        conn.commit()
        
        if cursor.rowcount == 0:
            return jsonify({
                'error': 'Record not found',
                'message': f'No record found with ID {record_id}'
            }), 404
        
        logger.info(f"Record {record_id} deleted successfully by user {user_id}")
        return jsonify({
            'message': 'Record deleted successfully',
            'id': record_id
        }), 200
    finally:
        if conn:
            conn.close()

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint with database connectivity test."""
    try:
        # Test database connection
        conn = get_db_connection()
        conn.execute('SELECT 1').fetchone()
        conn.close()
        
        return jsonify({
            'status': 'healthy',
            'database': 'connected'
        }), 200
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            'status': 'unhealthy',
            'database': 'disconnected',
            'error': str(e)
        }), 503

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return jsonify({
        'error': 'Not found',
        'message': 'The requested endpoint does not exist'
    }), 404

@app.errorhandler(405)
def method_not_allowed(error):
    """Handle 405 errors."""
    return jsonify({
        'error': 'Method not allowed',
        'message': 'The HTTP method is not allowed for this endpoint'
    }), 405

@app.errorhandler(413)
def payload_too_large(error):
    """Handle 413 errors."""
    return jsonify({
        'error': 'Payload too large',
        'message': f'Request body exceeds maximum size of {MAX_JSON_SIZE} bytes'
    }), 413

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    logger.error(f"Internal server error: {str(error)}")
    return jsonify({
        'error': 'Internal server error',
        'message': 'An unexpected error occurred on the server'
    }), 500

if __name__ == '__main__':
    # Initialize database on startup
    init_db()
    print(f"Database initialized: {DATABASE}")
    print("Starting Flask API server...")
    print("\nAPI endpoints:")
    print("  Authentication (no token required):")
    print("    POST   /api/register  - Register a new user")
    print("    POST   /api/login     - Login and get JWT token")
    print("  Data endpoints (JWT token required):")
    print("    POST   /api/data      - Create a new record")
    print("    GET    /api/data      - Get all records for authenticated user")
    print("    GET    /api/data/<id> - Get a specific record")
    print("    DELETE /api/data/<id> - Delete a specific record")
    print("  Utility:")
    print("    GET    /health        - Health check")
    print("\nNote: Use 'Authorization: Bearer <token>' header for protected endpoints")
    print("Server running on http://127.0.0.1:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)

