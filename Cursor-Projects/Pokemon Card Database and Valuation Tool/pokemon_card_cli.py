#!/usr/bin/env python3
"""
Pokemon Card Database CLI Tool

A command-line interface for managing your Pokemon card collection and valuations.

Usage:
    python pokemon_card_cli.py add --name "Charizard" --set "Base Set" --rarity "Rare"
    python pokemon_card_cli.py list
    python pokemon_card_cli.py value <card_id>
    python pokemon_card_cli.py stats
"""

import argparse
import requests
import json
import sys
from typing import Dict, Any, Optional

BASE_URL = "http://127.0.0.1:5000"

def make_request(method: str, endpoint: str, data: Optional[Dict] = None) -> Dict[str, Any]:
    """Make an HTTP request to the API."""
    url = f"{BASE_URL}{endpoint}"
    try:
        if method == 'GET':
            response = requests.get(url, params=data, timeout=10)
        elif method == 'POST':
            response = requests.post(url, json=data, timeout=10)
        elif method == 'PUT':
            response = requests.put(url, json=data, timeout=10)
        elif method == 'DELETE':
            response = requests.delete(url, timeout=10)
        else:
            raise ValueError(f"Unsupported method: {method}")
        
        response.raise_for_status()
        return response.json()
    except requests.exceptions.ConnectionError:
        print("Error: Could not connect to the API server.", file=sys.stderr)
        print("Make sure the server is running: python pokemon_card_db.py", file=sys.stderr)
        sys.exit(1)
    except requests.exceptions.HTTPError as e:
        error_data = {}
        try:
            error_data = response.json()
        except:
            pass
        print(f"Error: {error_data.get('message', str(e))}", file=sys.stderr)
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

def add_card(args):
    """Add a new card to the database."""
    card_data = {
        'name': args.name,
        'set_name': args.set,
        'set_number': args.set_number,
        'rarity': args.rarity,
        'condition': args.condition,
        'card_type': args.card_type,
        'pokemon_type': args.pokemon_type,
        'hp': args.hp,
        'artist': args.artist,
        'year': args.year,
        'language': args.language,
        'notes': args.notes,
        'purchase_price': args.purchase_price,
        'purchase_date': args.purchase_date
    }
    
    # Only include first_edition if explicitly set to True (flag was provided)
    # Since --first-edition uses action='store_true', False means "not provided"
    if args.first_edition:
        card_data['first_edition'] = True
    
    # Remove None values
    card_data = {k: v for k, v in card_data.items() if v is not None}
    
    result = make_request('POST', '/api/cards', card_data)
    card = result['card']
    
    print(f"\n✓ Card added successfully!")
    print(f"  ID: {card['id']}")
    print(f"  Name: {card['name']}")
    print(f"  Set: {card['set_name'] or 'N/A'}")
    print(f"  Rarity: {card['rarity'] or 'N/A'}")
    print(f"  Condition: {card['condition']}")
    print(f"  Estimated Value: ${card['estimated_value']:.2f}")

def list_cards(args):
    """List cards with optional filters."""
    filters = {}
    if args.name:
        filters['name'] = args.name
    if args.set:
        filters['set'] = args.set
    if args.rarity:
        filters['rarity'] = args.rarity
    if args.condition:
        filters['condition'] = args.condition
    if args.min_value:
        filters['min_value'] = args.min_value
    if args.max_value:
        filters['max_value'] = args.max_value
    if args.limit:
        filters['limit'] = args.limit
    
    result = make_request('GET', '/api/cards', filters)
    cards = result['cards']
    
    if len(cards) == 0:
        print("No cards found.")
        return
    
    print(f"\nFound {result['count']} card(s):\n")
    print(f"{'ID':<6} {'Name':<25} {'Set':<20} {'Rarity':<15} {'Condition':<12} {'Value':<10}")
    print("-" * 100)
    
    for card in cards:
        print(f"{card['id']:<6} {card['name']:<25} {str(card['set_name'] or 'N/A'):<20} "
              f"{str(card['rarity'] or 'N/A'):<15} {card['condition']:<12} ${card['estimated_value']:.2f}")

def get_card(args):
    """Get details of a specific card."""
    result = make_request('GET', f'/api/cards/{args.card_id}')
    card = result['card']
    
    print(f"\n{'='*60}")
    print(f"Card Details (ID: {card['id']})")
    print(f"{'='*60}")
    print(f"Name:           {card['name']}")
    print(f"Set:            {card['set_name'] or 'N/A'}")
    print(f"Set Number:     {card['set_number'] or 'N/A'}")
    print(f"Rarity:         {card['rarity'] or 'N/A'}")
    print(f"Condition:      {card['condition']}")
    print(f"Card Type:      {card['card_type'] or 'N/A'}")
    print(f"Pokemon Type:   {card['pokemon_type'] or 'N/A'}")
    print(f"HP:             {card['hp'] or 'N/A'}")
    print(f"Artist:         {card['artist'] or 'N/A'}")
    print(f"Year:           {card['year'] or 'N/A'}")
    print(f"Language:       {card['language']}")
    print(f"First Edition:  {'Yes' if card['first_edition'] else 'No'}")
    purchase_price_str = f"${card['purchase_price']:.2f}" if card['purchase_price'] is not None else "N/A"
    print(f"Purchase Price: {purchase_price_str}")
    print(f"Purchase Date:  {card['purchase_date'] or 'N/A'}")
    print(f"Estimated Value: ${card['estimated_value']:.2f}")
    print(f"Last Valued:    {card['last_valuation_date'] or 'N/A'}")
    if card['notes']:
        print(f"Notes:          {card['notes']}")
    print(f"{'='*60}")

def update_card(args):
    """Update a card."""
    card_data = {}
    
    if args.name:
        card_data['name'] = args.name
    if args.set:
        card_data['set_name'] = args.set
    if args.set_number:
        card_data['set_number'] = args.set_number
    if args.rarity:
        card_data['rarity'] = args.rarity
    if args.condition:
        card_data['condition'] = args.condition
    if args.card_type:
        card_data['card_type'] = args.card_type
    if args.pokemon_type:
        card_data['pokemon_type'] = args.pokemon_type
    if args.hp:
        card_data['hp'] = args.hp
    if args.artist:
        card_data['artist'] = args.artist
    if args.year:
        card_data['year'] = args.year
    if args.language:
        card_data['language'] = args.language
    if args.first_edition is not None:
        card_data['first_edition'] = args.first_edition
    if args.notes:
        card_data['notes'] = args.notes
    if args.purchase_price is not None:
        card_data['purchase_price'] = args.purchase_price
    if args.purchase_date:
        card_data['purchase_date'] = args.purchase_date
    
    if not card_data:
        print("Error: No fields to update. Provide at least one field to update.", file=sys.stderr)
        sys.exit(1)
    
    result = make_request('PUT', f'/api/cards/{args.card_id}', card_data)
    card = result['card']
    
    print(f"\n✓ Card updated successfully!")
    print(f"  ID: {card['id']}")
    print(f"  Name: {card['name']}")
    print(f"  Estimated Value: ${card['estimated_value']:.2f}")

def delete_card(args):
    """Delete a card."""
    result = make_request('DELETE', f'/api/cards/{args.card_id}')
    print(f"\n✓ Card {args.card_id} deleted successfully!")

def get_value(args):
    """Get valuation for a card."""
    result = make_request('POST', f'/api/cards/{args.card_id}/value')
    
    print(f"\n{'='*60}")
    print(f"Card Valuation")
    print(f"{'='*60}")
    print(f"Card ID:        {result['card_id']}")
    print(f"Card Name:      {result['card_name']}")
    print(f"Estimated Value: ${result['estimated_value']:.2f} {result['currency']}")
    print(f"Valuation Date: {result['valuation_date']}")
    print(f"\nFactors:")
    factors = result['factors']
    print(f"  Rarity:        {factors.get('rarity', 'N/A')}")
    print(f"  Condition:     {factors.get('condition', 'N/A')}")
    print(f"  Set:           {factors.get('set', 'N/A')}")
    print(f"  First Edition: {'Yes' if factors.get('first_edition') else 'No'}")
    print(f"  Year:          {factors.get('year', 'N/A')}")
    print(f"{'='*60}")

def bulk_valuation(args):
    """Get valuations for multiple cards."""
    card_ids = args.card_ids
    result = make_request('POST', '/api/valuation/bulk', {'card_ids': card_ids})
    
    print(f"\n{'='*60}")
    print(f"Bulk Valuation")
    print(f"{'='*60}")
    print(f"Total Cards:    {result['total_cards']}")
    print(f"Total Value:    ${result['total_value']:.2f} {result['currency']}")
    print(f"\nIndividual Valuations:")
    print(f"{'ID':<6} {'Name':<30} {'Value':<10}")
    print("-" * 50)
    for val in result['valuations']:
        print(f"{val['card_id']:<6} {val['card_name']:<30} ${val['estimated_value']:.2f}")
    print(f"{'='*60}")

def get_stats(args):
    """Get collection statistics."""
    result = make_request('GET', '/api/stats')
    
    print(f"\n{'='*60}")
    print(f"Collection Statistics")
    print(f"{'='*60}")
    print(f"Total Cards:     {result['total_cards']}")
    print(f"Total Value:     ${result['total_value']:.2f} {result['currency']}")
    print(f"Average Value:   ${result['average_value']:.2f} {result['currency']}")
    
    if result['by_rarity']:
        print(f"\nBy Rarity:")
        for rarity, stats in result['by_rarity'].items():
            print(f"  {rarity:<20} {stats['count']:>3} cards  ${stats['total_value']:>10.2f}")
    
    if result['by_condition']:
        print(f"\nBy Condition:")
        for condition, count in result['by_condition'].items():
            print(f"  {condition:<20} {count:>3} cards")
    
    if result['top_cards']:
        print(f"\nTop 5 Most Valuable Cards:")
        for i, card in enumerate(result['top_cards'], 1):
            print(f"  {i}. {card['name']:<30} ${card['value']:.2f} (ID: {card['id']})")
    
    print(f"{'='*60}")

def main():
    parser = argparse.ArgumentParser(
        description='Pokemon Card Database CLI Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Add command
    add_parser = subparsers.add_parser('add', help='Add a new card')
    add_parser.add_argument('--name', required=True, help='Card name (e.g., "Charizard")')
    add_parser.add_argument('--set', help='Set name (e.g., "Base Set")')
    add_parser.add_argument('--set-number', help='Set number')
    add_parser.add_argument('--rarity', help='Rarity (e.g., "Rare", "Holo", "Secret Rare")')
    add_parser.add_argument('--condition', default='Near Mint', 
                           choices=['Mint', 'Near Mint', 'Excellent', 'Very Good', 'Good', 'Fair', 'Poor'],
                           help='Card condition')
    add_parser.add_argument('--card-type', help='Card type')
    add_parser.add_argument('--pokemon-type', help='Pokemon type (e.g., "Fire", "Water")')
    add_parser.add_argument('--hp', type=int, help='HP value')
    add_parser.add_argument('--artist', help='Artist name')
    add_parser.add_argument('--year', type=int, help='Year printed')
    add_parser.add_argument('--language', default='English', help='Language')
    add_parser.add_argument('--first-edition', action='store_true', help='First edition card')
    add_parser.add_argument('--notes', help='Additional notes')
    add_parser.add_argument('--purchase-price', type=float, help='Purchase price')
    add_parser.add_argument('--purchase-date', help='Purchase date')
    add_parser.set_defaults(func=add_card)
    
    # List command
    list_parser = subparsers.add_parser('list', help='List cards')
    list_parser.add_argument('--name', help='Filter by name')
    list_parser.add_argument('--set', help='Filter by set')
    list_parser.add_argument('--rarity', help='Filter by rarity')
    list_parser.add_argument('--condition', help='Filter by condition')
    list_parser.add_argument('--min-value', type=float, help='Minimum value filter')
    list_parser.add_argument('--max-value', type=float, help='Maximum value filter')
    list_parser.add_argument('--limit', type=int, default=100, help='Limit results')
    list_parser.set_defaults(func=list_cards)
    
    # Get command
    get_parser = subparsers.add_parser('get', help='Get card details')
    get_parser.add_argument('card_id', type=int, help='Card ID')
    get_parser.set_defaults(func=get_card)
    
    # Update command
    update_parser = subparsers.add_parser('update', help='Update a card')
    update_parser.add_argument('card_id', type=int, help='Card ID')
    update_parser.add_argument('--name', help='Card name')
    update_parser.add_argument('--set', help='Set name')
    update_parser.add_argument('--set-number', help='Set number')
    update_parser.add_argument('--rarity', help='Rarity')
    update_parser.add_argument('--condition', 
                              choices=['Mint', 'Near Mint', 'Excellent', 'Very Good', 'Good', 'Fair', 'Poor'],
                              help='Card condition')
    update_parser.add_argument('--card-type', help='Card type')
    update_parser.add_argument('--pokemon-type', help='Pokemon type')
    update_parser.add_argument('--hp', type=int, help='HP value')
    update_parser.add_argument('--artist', help='Artist name')
    update_parser.add_argument('--year', type=int, help='Year printed')
    update_parser.add_argument('--language', help='Language')
    update_parser.add_argument('--first-edition', type=int, choices=[0, 1], help='First edition (0 or 1)')
    update_parser.add_argument('--notes', help='Additional notes')
    update_parser.add_argument('--purchase-price', type=float, help='Purchase price')
    update_parser.add_argument('--purchase-date', help='Purchase date')
    update_parser.set_defaults(func=update_card)
    
    # Delete command
    delete_parser = subparsers.add_parser('delete', help='Delete a card')
    delete_parser.add_argument('card_id', type=int, help='Card ID')
    delete_parser.set_defaults(func=delete_card)
    
    # Value command
    value_parser = subparsers.add_parser('value', help='Get card valuation')
    value_parser.add_argument('card_id', type=int, help='Card ID')
    value_parser.set_defaults(func=get_value)
    
    # Bulk valuation command
    bulk_parser = subparsers.add_parser('bulk-value', help='Get valuations for multiple cards')
    bulk_parser.add_argument('card_ids', type=int, nargs='+', help='Card IDs')
    bulk_parser.set_defaults(func=bulk_valuation)
    
    # Stats command
    stats_parser = subparsers.add_parser('stats', help='Get collection statistics')
    stats_parser.set_defaults(func=get_stats)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    args.func(args)

if __name__ == '__main__':
    main()
