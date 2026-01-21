#!/usr/bin/env python3
"""
Pokemon Card Database and Valuation Tool

This Flask API provides endpoints to:
1. POST /api/cards - Add a new Pokemon card to the database
2. GET /api/cards - Get all cards (with optional filters)
3. GET /api/cards/<id> - Get a specific card by ID
4. PUT /api/cards/<id> - Update a card
5. DELETE /api/cards/<id> - Delete a card
6. POST /api/cards/<id>/value - Get valuation for a specific card
7. GET /api/valuation/bulk - Get valuations for multiple cards
8. GET /api/stats - Get statistics about the collection

Requirements:
- flask package: pip install flask

To run:
    python pokemon_card_db.py
"""

from flask import Flask, request, jsonify
import sqlite3
import os
import json
import logging
from datetime import datetime
from functools import wraps
from typing import Dict, Any, Optional, List

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database file path
DATABASE = 'pokemon_cards.db'

# Card conditions and their multipliers
CONDITION_MULTIPLIERS = {
    'Mint': 1.0,
    'Near Mint': 0.9,
    'Excellent': 0.75,
    'Very Good': 0.6,
    'Good': 0.4,
    'Fair': 0.25,
    'Poor': 0.1
}

# Rarity base values (in USD)
RARITY_BASE_VALUES = {
    'Common': 0.50,
    'Uncommon': 1.00,
    'Rare': 5.00,
    'Ultra Rare': 25.00,
    'Secret Rare': 100.00,
    'Promo': 2.00,
    'Holo': 10.00,
    'Reverse Holo': 8.00,
    'Full Art': 50.00,
    'Rainbow Rare': 75.00,
    'Gold Rare': 100.00,
    'VMAX': 30.00,
    'V': 15.00,
    'EX': 20.00,
    'GX': 25.00
}

# Popular sets multiplier (some sets are more valuable)
POPULAR_SETS = {
    'Base Set': 1.5,
    'Jungle': 1.3,
    'Fossil': 1.3,
    'Base Set 2': 1.2,
    'Team Rocket': 1.2,
    'Gym Heroes': 1.2,
    'Gym Challenge': 1.2,
    'Neo Genesis': 1.4,
    'Neo Discovery': 1.3,
    'Neo Revelation': 1.3,
    'Neo Destiny': 1.4,
    'Legendary Collection': 1.5,
    'Expedition': 1.2,
    'Aquapolis': 1.2,
    'Skyridge': 1.2,
    'Charizard': 2.0,  # Special multiplier for Charizard cards
    'Pikachu': 1.3,    # Special multiplier for Pikachu cards
}

def get_db_connection():
    """Create and return a database connection with error handling."""
    try:
        conn = sqlite3.connect(DATABASE, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        logger.error(f"Database connection error: {str(e)}")
        raise

def init_db():
    """Initialize the database with tables if they don't exist."""
    try:
        conn = get_db_connection()
        
        # Create cards table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS cards (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                set_name TEXT,
                set_number TEXT,
                rarity TEXT,
                condition TEXT DEFAULT 'Near Mint',
                card_type TEXT,
                pokemon_type TEXT,
                hp INTEGER,
                artist TEXT,
                year INTEGER,
                language TEXT DEFAULT 'English',
                first_edition INTEGER DEFAULT 0,
                notes TEXT,
                purchase_price REAL,
                purchase_date TEXT,
                estimated_value REAL,
                last_valuation_date TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create indexes for faster queries
        conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_cards_name ON cards(name)
        ''')
        conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_cards_set ON cards(set_name)
        ''')
        conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_cards_rarity ON cards(rarity)
        ''')
        conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_cards_condition ON cards(condition)
        ''')
        
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")
    except sqlite3.Error as e:
        logger.error(f"Database initialization error: {str(e)}")
        raise

def calculate_card_value(card: Dict[str, Any]) -> float:
    """
    Calculate the estimated value of a Pokemon card based on various factors.
    
    Factors considered:
    - Base rarity value
    - Condition multiplier
    - Set popularity
    - First edition bonus
    - Special Pokemon (Charizard, Pikachu, etc.)
    - Year (older cards generally more valuable)
    
    Args:
        card: Dictionary containing card information
        
    Returns:
        Estimated value in USD
    """
    # Start with rarity base value
    rarity = card.get('rarity', 'Common')
    base_value = RARITY_BASE_VALUES.get(rarity, RARITY_BASE_VALUES['Common'])
    
    # Apply condition multiplier
    condition = card.get('condition', 'Near Mint')
    condition_mult = CONDITION_MULTIPLIERS.get(condition, 0.5)
    value = base_value * condition_mult
    
    # Apply set multiplier
    # Note: Exclude 'Charizard' and 'Pikachu' from set matching as they are
    # Pokemon-specific multipliers, not set multipliers
    set_name = card.get('set_name', '')
    if set_name:
        for popular_set, multiplier in POPULAR_SETS.items():
            # Skip Pokemon-specific multipliers in set matching
            if popular_set in ('Charizard', 'Pikachu'):
                continue
            if popular_set.lower() in set_name.lower():
                value *= multiplier
                break
    
    # First edition bonus (50% increase)
    if card.get('first_edition', 0) == 1:
        value *= 1.5
    
    # Special Pokemon multiplier
    card_name = card.get('name', '').lower()
    if 'charizard' in card_name:
        value *= POPULAR_SETS['Charizard']
    elif 'pikachu' in card_name:
        value *= POPULAR_SETS['Pikachu']
    
    # Year multiplier (older = more valuable, up to 2x for pre-2000)
    year = card.get('year')
    if year:
        current_year = datetime.now().year
        age = current_year - year
        if age > 25:  # Cards older than 25 years
            value *= 1.5
        elif age > 20:  # Cards older than 20 years
            value *= 1.3
        elif age > 15:  # Cards older than 15 years
            value *= 1.1
    
    # Round to 2 decimal places
    return round(value, 2)

def validate_card_data(data: Dict[str, Any], is_update: bool = False) -> tuple[bool, Optional[str]]:
    """
    Validate card data.
    
    Returns:
        (is_valid, error_message)
    """
    if not isinstance(data, dict):
        return False, "Data must be a JSON object"
    
    # Required fields for new cards
    if not is_update:
        if not data.get('name'):
            return False, "Card name is required"
    
    # Validate condition if provided
    if 'condition' in data:
        condition = data['condition']
        if condition not in CONDITION_MULTIPLIERS:
            return False, f"Invalid condition. Must be one of: {', '.join(CONDITION_MULTIPLIERS.keys())}"
    
    # Validate rarity if provided
    if 'rarity' in data:
        rarity = data['rarity']
        if rarity not in RARITY_BASE_VALUES:
            logger.warning(f"Unknown rarity: {rarity}. Using default base value.")
    
    # Validate year if provided
    if 'year' in data:
        year = data['year']
        # Check if year is provided (not None) and validate it
        # Distinguish between "not provided" (None) and "provided but invalid" (0, invalid range, etc.)
        if year is not None and (not isinstance(year, int) or year < 1996 or year > datetime.now().year + 1):
            return False, f"Invalid year. Must be between 1996 and {datetime.now().year + 1}"
    
    # Validate first_edition if provided
    if 'first_edition' in data:
        first_ed = data['first_edition']
        if first_ed not in [0, 1]:
            return False, "first_edition must be 0 or 1"
    
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
        except Exception as e:
            logger.error(f"Unexpected error in {func.__name__}: {str(e)}", exc_info=True)
            return jsonify({
                'error': 'Internal server error',
                'message': 'An unexpected error occurred'
            }), 500
    return wrapper

def card_row_to_dict(row) -> Dict[str, Any]:
    """Convert a database row to a dictionary."""
    return {
        'id': row['id'],
        'name': row['name'],
        'set_name': row['set_name'],
        'set_number': row['set_number'],
        'rarity': row['rarity'],
        'condition': row['condition'],
        'card_type': row['card_type'],
        'pokemon_type': row['pokemon_type'],
        'hp': row['hp'],
        'artist': row['artist'],
        'year': row['year'],
        'language': row['language'],
        'first_edition': bool(row['first_edition']),
        'notes': row['notes'],
        'purchase_price': row['purchase_price'],
        'purchase_date': row['purchase_date'],
        'estimated_value': row['estimated_value'],
        'last_valuation_date': row['last_valuation_date'],
        'created_at': row['created_at'],
        'updated_at': row['updated_at']
    }

@app.route('/api/cards', methods=['POST'])
@handle_db_error
def create_card():
    """Add a new Pokemon card to the database."""
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
    
    # Validate data
    is_valid, error_message = validate_card_data(data, is_update=False)
    if not is_valid:
        return jsonify({
            'error': 'Validation failed',
            'message': error_message
        }), 400
    
    # Calculate estimated value
    estimated_value = calculate_card_value(data)
    
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.execute('''
            INSERT INTO cards (
                name, set_name, set_number, rarity, condition, card_type,
                pokemon_type, hp, artist, year, language, first_edition,
                notes, purchase_price, purchase_date, estimated_value, last_valuation_date
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data.get('name'),
            data.get('set_name'),
            data.get('set_number'),
            data.get('rarity', 'Common'),
            data.get('condition', 'Near Mint'),
            data.get('card_type'),
            data.get('pokemon_type'),
            data.get('hp'),
            data.get('artist'),
            data.get('year'),
            data.get('language', 'English'),
            1 if data.get('first_edition', False) else 0,
            data.get('notes'),
            data.get('purchase_price'),
            data.get('purchase_date'),
            estimated_value,
            datetime.now().isoformat()
        ))
        card_id = cursor.lastrowid
        conn.commit()
        
        # Fetch the created card
        row = conn.execute('SELECT * FROM cards WHERE id = ?', (card_id,)).fetchone()
        card = card_row_to_dict(row)
        
        logger.info(f"Card created: {card['name']} (ID: {card_id})")
        return jsonify({
            'message': 'Card created successfully',
            'card': card
        }), 201
    finally:
        if conn:
            conn.close()

@app.route('/api/cards', methods=['GET'])
@handle_db_error
def get_cards():
    """Get all cards with optional filters."""
    # Get query parameters
    name_filter = request.args.get('name')
    set_filter = request.args.get('set')
    rarity_filter = request.args.get('rarity')
    condition_filter = request.args.get('condition')
    min_value = request.args.get('min_value', type=float)
    max_value = request.args.get('max_value', type=float)
    limit = request.args.get('limit', type=int, default=100)
    
    conn = None
    try:
        conn = get_db_connection()
        
        # Build query
        query = 'SELECT * FROM cards WHERE 1=1'
        params = []
        
        if name_filter:
            query += ' AND name LIKE ?'
            params.append(f'%{name_filter}%')
        
        if set_filter:
            query += ' AND set_name LIKE ?'
            params.append(f'%{set_filter}%')
        
        if rarity_filter:
            query += ' AND rarity = ?'
            params.append(rarity_filter)
        
        if condition_filter:
            query += ' AND condition = ?'
            params.append(condition_filter)
        
        if min_value is not None:
            query += ' AND estimated_value >= ?'
            params.append(min_value)
        
        if max_value is not None:
            query += ' AND estimated_value <= ?'
            params.append(max_value)
        
        query += ' ORDER BY estimated_value DESC, name ASC LIMIT ?'
        params.append(limit)
        
        rows = conn.execute(query, params).fetchall()
        
        cards = [card_row_to_dict(row) for row in rows]
        
        return jsonify({
            'count': len(cards),
            'cards': cards
        }), 200
    finally:
        if conn:
            conn.close()

@app.route('/api/cards/<int:card_id>', methods=['GET'])
@handle_db_error
def get_card(card_id):
    """Get a specific card by ID."""
    conn = None
    try:
        conn = get_db_connection()
        row = conn.execute('SELECT * FROM cards WHERE id = ?', (card_id,)).fetchone()
        
        if row is None:
            return jsonify({
                'error': 'Card not found',
                'message': f'No card found with ID {card_id}'
            }), 404
        
        card = card_row_to_dict(row)
        return jsonify({'card': card}), 200
    finally:
        if conn:
            conn.close()

@app.route('/api/cards/<int:card_id>', methods=['PUT'])
@handle_db_error
def update_card(card_id):
    """Update a card."""
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
    
    # Validate data
    is_valid, error_message = validate_card_data(data, is_update=True)
    if not is_valid:
        return jsonify({
            'error': 'Validation failed',
            'message': error_message
        }), 400
    
    conn = None
    try:
        conn = get_db_connection()
        
        # Check if card exists
        existing = conn.execute('SELECT * FROM cards WHERE id = ?', (card_id,)).fetchone()
        if existing is None:
            return jsonify({
                'error': 'Card not found',
                'message': f'No card found with ID {card_id}'
            }), 404
        
        # Get existing card data for recalculation
        existing_dict = card_row_to_dict(existing)
        
        # Create a merged dict for value calculation (only if needed)
        merged_dict = existing_dict.copy()
        merged_dict.update(data)
        
        # Recalculate value if relevant fields changed
        value_changed = any(key in data for key in ['rarity', 'condition', 'set_name', 'first_edition', 'year', 'name'])
        if value_changed:
            merged_dict['estimated_value'] = calculate_card_value(merged_dict)
            merged_dict['last_valuation_date'] = datetime.now().isoformat()
            # Add calculated fields to data so they're included in update
            data['estimated_value'] = merged_dict['estimated_value']
            data['last_valuation_date'] = merged_dict['last_valuation_date']
        
        # Build update query dynamically - only update fields explicitly provided in the request
        update_fields = []
        update_values = []
        
        updatable_fields = [
            'name', 'set_name', 'set_number', 'rarity', 'condition', 'card_type',
            'pokemon_type', 'hp', 'artist', 'year', 'language', 'first_edition',
            'notes', 'purchase_price', 'purchase_date', 'estimated_value', 'last_valuation_date'
        ]
        
        # Only include fields that were explicitly provided in the request (data dict)
        for field in updatable_fields:
            if field in data:  # Only update fields explicitly in the request
                update_fields.append(f'{field} = ?')
                if field == 'first_edition':
                    update_values.append(1 if data[field] else 0)
                else:
                    update_values.append(data[field])
        
        update_fields.append('updated_at = ?')
        update_values.append(datetime.now().isoformat())
        update_values.append(card_id)
        
        query = f'UPDATE cards SET {", ".join(update_fields)} WHERE id = ?'
        conn.execute(query, update_values)
        conn.commit()
        
        # Fetch updated card
        row = conn.execute('SELECT * FROM cards WHERE id = ?', (card_id,)).fetchone()
        card = card_row_to_dict(row)
        
        logger.info(f"Card updated: {card['name']} (ID: {card_id})")
        return jsonify({
            'message': 'Card updated successfully',
            'card': card
        }), 200
    finally:
        if conn:
            conn.close()

@app.route('/api/cards/<int:card_id>', methods=['DELETE'])
@handle_db_error
def delete_card(card_id):
    """Delete a card."""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.execute('DELETE FROM cards WHERE id = ?', (card_id,))
        conn.commit()
        
        if cursor.rowcount == 0:
            return jsonify({
                'error': 'Card not found',
                'message': f'No card found with ID {card_id}'
            }), 404
        
        logger.info(f"Card deleted (ID: {card_id})")
        return jsonify({
            'message': 'Card deleted successfully',
            'id': card_id
        }), 200
    finally:
        if conn:
            conn.close()

@app.route('/api/cards/<int:card_id>/value', methods=['POST'])
@handle_db_error
def get_card_value(card_id):
    """Get valuation for a specific card."""
    conn = None
    try:
        conn = get_db_connection()
        row = conn.execute('SELECT * FROM cards WHERE id = ?', (card_id,)).fetchone()
        
        if row is None:
            return jsonify({
                'error': 'Card not found',
                'message': f'No card found with ID {card_id}'
            }), 404
        
        card = card_row_to_dict(row)
        estimated_value = calculate_card_value(card)
        
        # Update the card's estimated value in database
        conn.execute('''
            UPDATE cards 
            SET estimated_value = ?, last_valuation_date = ?
            WHERE id = ?
        ''', (estimated_value, datetime.now().isoformat(), card_id))
        conn.commit()
        
        return jsonify({
            'card_id': card_id,
            'card_name': card['name'],
            'estimated_value': estimated_value,
            'currency': 'USD',
            'valuation_date': datetime.now().isoformat(),
            'factors': {
                'rarity': card.get('rarity'),
                'condition': card.get('condition'),
                'set': card.get('set_name'),
                'first_edition': card.get('first_edition'),
                'year': card.get('year')
            }
        }), 200
    finally:
        if conn:
            conn.close()

@app.route('/api/valuation/bulk', methods=['POST'])
@handle_db_error
def bulk_valuation():
    """Get valuations for multiple cards."""
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
    
    card_ids = data.get('card_ids', [])
    if not isinstance(card_ids, list) or len(card_ids) == 0:
        return jsonify({
            'error': 'Validation failed',
            'message': 'card_ids must be a non-empty array'
        }), 400
    
    conn = None
    try:
        conn = get_db_connection()
        valuations = []
        total_value = 0.0
        
        for card_id in card_ids:
            row = conn.execute('SELECT * FROM cards WHERE id = ?', (card_id,)).fetchone()
            if row:
                card = card_row_to_dict(row)
                value = calculate_card_value(card)
                
                # Update the card's estimated value in database (consistent with single-card endpoint)
                conn.execute('''
                    UPDATE cards 
                    SET estimated_value = ?, last_valuation_date = ?
                    WHERE id = ?
                ''', (value, datetime.now().isoformat(), card_id))
                
                valuations.append({
                    'card_id': card_id,
                    'card_name': card['name'],
                    'estimated_value': value
                })
                total_value += value
        
        # Commit all updates at once for better performance
        conn.commit()
        
        return jsonify({
            'total_cards': len(valuations),
            'total_value': round(total_value, 2),
            'currency': 'USD',
            'valuations': valuations
        }), 200
    finally:
        if conn:
            conn.close()

@app.route('/api/stats', methods=['GET'])
@handle_db_error
def get_stats():
    """Get statistics about the collection."""
    conn = None
    try:
        conn = get_db_connection()
        
        # Total cards
        total_cards = conn.execute('SELECT COUNT(*) as count FROM cards').fetchone()['count']
        
        # Total value
        total_value_result = conn.execute('SELECT SUM(estimated_value) as total FROM cards').fetchone()
        total_value = total_value_result['total'] or 0.0
        
        # Cards by rarity
        rarity_stats = {}
        rarity_rows = conn.execute('''
            SELECT rarity, COUNT(*) as count, SUM(estimated_value) as total_value
            FROM cards
            GROUP BY rarity
        ''').fetchall()
        for row in rarity_rows:
            rarity_stats[row['rarity']] = {
                'count': row['count'],
                'total_value': round(row['total_value'] or 0.0, 2)
            }
        
        # Cards by condition
        condition_stats = {}
        condition_rows = conn.execute('''
            SELECT condition, COUNT(*) as count
            FROM cards
            GROUP BY condition
        ''').fetchall()
        for row in condition_rows:
            condition_stats[row['condition']] = row['count']
        
        # Most valuable cards (top 5)
        top_cards = conn.execute('''
            SELECT id, name, estimated_value
            FROM cards
            ORDER BY estimated_value DESC
            LIMIT 5
        ''').fetchall()
        top_cards_list = [
            {'id': row['id'], 'name': row['name'], 'value': row['estimated_value']}
            for row in top_cards
        ]
        
        return jsonify({
            'total_cards': total_cards,
            'total_value': round(total_value, 2),
            'average_value': round(total_value / total_cards if total_cards > 0 else 0, 2),
            'currency': 'USD',
            'by_rarity': rarity_stats,
            'by_condition': condition_stats,
            'top_cards': top_cards_list
        }), 200
    finally:
        if conn:
            conn.close()

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    conn = None
    try:
        conn = get_db_connection()
        conn.execute('SELECT 1').fetchone()
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
    finally:
        if conn:
            conn.close()

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

if __name__ == '__main__':
    # Initialize database on startup
    init_db()
    print(f"Database initialized: {DATABASE}")
    print("Starting Pokemon Card Database API server...")
    print("\nAPI endpoints:")
    print("  Card Management:")
    print("    POST   /api/cards           - Add a new card")
    print("    GET    /api/cards           - Get all cards (with filters)")
    print("    GET    /api/cards/<id>      - Get a specific card")
    print("    PUT    /api/cards/<id>      - Update a card")
    print("    DELETE /api/cards/<id>      - Delete a card")
    print("  Valuation:")
    print("    POST   /api/cards/<id>/value - Get valuation for a card")
    print("    POST   /api/valuation/bulk   - Get valuations for multiple cards")
    print("  Statistics:")
    print("    GET    /api/stats            - Get collection statistics")
    print("  Utility:")
    print("    GET    /health               - Health check")
    print("\nServer running on http://127.0.0.1:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
