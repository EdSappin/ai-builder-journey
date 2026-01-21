# Pokemon Card Database and Valuation Tool

A comprehensive database and valuation system for managing your Pokemon card collection. This tool provides both a REST API and a command-line interface for tracking cards and estimating their values.

## Features

- **Card Management**: Add, view, update, and delete Pokemon cards
- **Valuation System**: Automatic value estimation based on:
  - Rarity (Common, Rare, Holo, Secret Rare, etc.)
  - Condition (Mint, Near Mint, Excellent, etc.)
  - Set popularity (Base Set, Jungle, Fossil, etc.)
  - First edition status
  - Card age (vintage cards are more valuable)
  - Special Pokemon (Charizard, Pikachu multipliers)
- **Collection Statistics**: Track total value, cards by rarity/condition, top valuable cards
- **Bulk Operations**: Get valuations for multiple cards at once
- **Flexible Filtering**: Search and filter cards by name, set, rarity, condition, value range

## Installation

1. Install dependencies:
```bash
pip install flask requests
```

Or use the existing requirements.txt:
```bash
pip install -r requirements.txt
```

## Usage

### Starting the API Server

Start the Flask API server:
```bash
python pokemon_card_db.py
```

The server will run on `http://127.0.0.1:5000`

### Using the CLI Tool

The CLI tool provides an easy way to interact with your collection:

#### Add a Card
```bash
python pokemon_card_cli.py add --name "Charizard" --set "Base Set" --rarity "Rare" --condition "Near Mint" --year 1999 --first-edition
```

#### List Cards
```bash
# List all cards
python pokemon_card_cli.py list

# Filter by name
python pokemon_card_cli.py list --name "Charizard"

# Filter by set
python pokemon_card_cli.py list --set "Base Set"

# Filter by value range
python pokemon_card_cli.py list --min-value 50 --max-value 200
```

#### Get Card Details
```bash
python pokemon_card_cli.py get <card_id>
```

#### Update a Card
```bash
python pokemon_card_cli.py update <card_id> --condition "Mint" --purchase-price 150.00
```

#### Get Card Valuation
```bash
python pokemon_card_cli.py value <card_id>
```

#### Bulk Valuation
```bash
python pokemon_card_cli.py bulk-value 1 2 3 4 5
```

#### Collection Statistics
```bash
python pokemon_card_cli.py stats
```

### Using the API Directly

#### Add a Card
```bash
curl -X POST http://127.0.0.1:5000/api/cards \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Charizard",
    "set_name": "Base Set",
    "rarity": "Rare",
    "condition": "Near Mint",
    "year": 1999,
    "first_edition": true
  }'
```

#### Get All Cards
```bash
curl http://127.0.0.1:5000/api/cards
```

#### Get Card Valuation
```bash
curl -X POST http://127.0.0.1:5000/api/cards/1/value
```

#### Get Statistics
```bash
curl http://127.0.0.1:5000/api/stats
```

## API Endpoints

### Card Management
- `POST /api/cards` - Add a new card
- `GET /api/cards` - Get all cards (with optional filters: name, set, rarity, condition, min_value, max_value, limit)
- `GET /api/cards/<id>` - Get a specific card
- `PUT /api/cards/<id>` - Update a card
- `DELETE /api/cards/<id>` - Delete a card

### Valuation
- `POST /api/cards/<id>/value` - Get valuation for a specific card
- `POST /api/valuation/bulk` - Get valuations for multiple cards (requires `card_ids` array in body)

### Statistics
- `GET /api/stats` - Get collection statistics

### Utility
- `GET /health` - Health check endpoint

## Card Fields

- **name** (required): Card name (e.g., "Charizard")
- **set_name**: Set name (e.g., "Base Set", "Jungle")
- **set_number**: Set number
- **rarity**: Rarity level (Common, Uncommon, Rare, Ultra Rare, Secret Rare, Promo, Holo, Reverse Holo, Full Art, Rainbow Rare, Gold Rare, VMAX, V, EX, GX)
- **condition**: Card condition (Mint, Near Mint, Excellent, Very Good, Good, Fair, Poor)
- **card_type**: Type of card
- **pokemon_type**: Pokemon type (Fire, Water, Grass, etc.)
- **hp**: HP value
- **artist**: Artist name
- **year**: Year the card was printed
- **language**: Language (default: English)
- **first_edition**: Boolean (0 or 1)
- **notes**: Additional notes
- **purchase_price**: Purchase price
- **purchase_date**: Purchase date

## Valuation Algorithm

The valuation system considers multiple factors:

1. **Base Rarity Value**: Each rarity has a base value
2. **Condition Multiplier**: Condition affects the value (Mint = 100%, Poor = 10%)
3. **Set Popularity**: Popular sets (Base Set, Jungle, etc.) get multipliers
4. **First Edition Bonus**: First edition cards get a 50% increase
5. **Special Pokemon**: Charizard and Pikachu cards get special multipliers
6. **Age Factor**: Older cards (pre-2000) get value increases

## Database

The tool uses SQLite and automatically creates a database file (`pokemon_cards.db`) in the current directory. The database includes indexes for fast queries on name, set, rarity, and condition.

## Examples

### Example: Adding a First Edition Charizard
```bash
python pokemon_card_cli.py add \
  --name "Charizard" \
  --set "Base Set" \
  --set-number "4/102" \
  --rarity "Rare" \
  --condition "Near Mint" \
  --year 1999 \
  --first-edition \
  --pokemon-type "Fire" \
  --hp 120 \
  --purchase-price 500.00 \
  --purchase-date "2024-01-15"
```

### Example: Getting Collection Statistics
```bash
python pokemon_card_cli.py stats
```

Output:
```
============================================================
Collection Statistics
============================================================
Total Cards:     25
Total Value:     $1,234.56 USD
Average Value:   $49.38 USD

By Rarity:
  Rare                10 cards    $  500.00
  Holo                8 cards     $  400.00
  Secret Rare         2 cards     $  200.00

By Condition:
  Near Mint           15 cards
  Excellent           8 cards
  Very Good           2 cards

Top 5 Most Valuable Cards:
  1. Charizard                    $150.00 (ID: 1)
  2. Pikachu                      $75.00 (ID: 2)
  3. Blastoise                     $60.00 (ID: 3)
============================================================
```

## Notes

- The valuation system provides estimates based on general market trends. Actual card values may vary.
- For accurate valuations, consider using this tool in combination with actual market data from sites like TCGPlayer or eBay.
- The database is stored locally in SQLite format.
- All values are in USD.

## License

This tool is provided as-is for personal use.
