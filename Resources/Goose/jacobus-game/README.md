# 🥋 JACOBUS: WILLIAMSBURG WARRIOR

![Game Logo](https://img.shields.io/badge/JACOBUS-WILLIAMSBURG_WARRIOR-ff006e?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.8+-00f5ff?style=for-the-badge&logo=python)
![Pygame](https://img.shields.io/badge/Pygame-2.0+-8b00ff?style=for-the-badge)

> *"Not in my neighborhood!" - Jacobus*

An 80s-style, manga-influenced beat 'em up game featuring Jacobus, the legendary protector of Williamsburg and New York City!

## 🎮 About

**The Year:** 198X  
**The Place:** Williamsburg, Brooklyn & New York City

Jacobus, a martial arts master and community guardian, must defend Williamsburg from the evil MAXCORP syndicate trying to gentrify and destroy the neighborhood's soul. With his signature red bandana and street-fighting skills, Jacobus takes to the neon-lit streets to restore peace.

## ✨ Features

- **🎨 Authentic 80s Aesthetic**: Neon colors, synthwave palette, retro pixel art
- **📚 Manga Influence**: Dynamic action with speed lines and dramatic poses
- **👊 Fast-Paced Combat**: Combo system with light attacks, heavy attacks, and special moves
- **🌊 Wave-Based Gameplay**: Increasingly challenging enemy waves
- **🏆 Score System**: Compete for high scores with combo multipliers
- **🎯 Multiple Enemy Types**: Street punks, corporate guards, and cyber ninjas
- **⚡ Special Move**: "BROOKLYN FURY" - Devastating area attack
- **🎵 Retro Vibes**: 80s-inspired visuals and game feel

## 🕹️ Controls

### Keyboard Layout 1 (Arrows)
- **Arrow Keys**: Move left/right
- **SPACE**: Jump
- **Z**: Light Attack (fast combo)
- **X**: Heavy Attack (powerful strike)
- **C**: Special Move (Brooklyn Fury - costs energy)

### Keyboard Layout 2 (WASD)
- **A/D**: Move left/right
- **W/SPACE**: Jump
- **J**: Light Attack
- **K**: Heavy Attack
- **L**: Special Move

### System
- **ENTER**: Start game / Continue
- **ESC**: Pause game
- **Q**: Quit to title (from pause menu)

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Quick Start

1. **Clone or download this repository**
```bash
cd jacobus-game
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Run the game**
```bash
cd src
python game.py
```

Or from the root directory:
```bash
python src/game.py
```

## 🎯 How to Play

### Objective
Survive waves of enemies and protect Williamsburg! Defeat all enemies in each wave to progress. The game gets progressively harder with each wave.

### Combat Tips
1. **Combo System**: Chain attacks together to build combo multipliers
2. **Special Energy**: Regenerates slowly - use BROOKLYN FURY wisely!
3. **Invincibility Frames**: After taking damage, you briefly flicker - use this time to reposition
4. **Enemy Patterns**: Different enemy types have different behaviors
   - **Punks**: Basic thugs, moderate speed
   - **Guards**: Tougher, corporate security
   - **Ninjas**: Fast and dangerous

### Victory Conditions
- **Win**: Survive 10 waves of enemies
- **Game Over**: Health reaches 0

## 🎨 Visual Style

### Color Palette
- **Hot Pink** (`#FF006E`): Primary accent, player character
- **Electric Cyan** (`#00F5FF`): Secondary accent, special effects
- **Purple** (`#8B00FF`): Enemy characters, grid effects
- **Dark Navy** (`#0A0E27`): Background
- **Gold** (`#FFD700`): UI elements, scoring

### Aesthetic Influences
- 80s arcade beat 'em ups (Double Dragon, Streets of Rage)
- Manga action panels (speed lines, impact effects)
- Synthwave/Vaporwave visuals
- Classic NYC urban graffiti culture

## 📖 Game Mechanics

### Health System
- Player starts with 100 HP
- Invincibility frames after taking damage
- No health pickups (yet) - survival is key!

### Scoring System
- Base score per enemy: **100 points**
- Combo multiplier: **100 × combo count**
- Special move bonus: **50 points**

### Special Energy
- Starts at 100%
- Regenerates slowly over time
- Brooklyn Fury costs **30 energy**

## 🗺️ Future Features (Planned)

- [ ] Multiple stages (Brooklyn Bridge, Times Square, MAXCORP Tower)
- [ ] Boss battles with unique mechanics
- [ ] Power-ups and health pickups
- [ ] Additional playable characters
- [ ] Story mode with cutscenes
- [ ] Local co-op multiplayer
- [ ] Chiptune soundtrack
- [ ] More enemy variety
- [ ] Unlockable moves and upgrades

## 🛠️ Technical Details

- **Engine**: Pygame
- **Language**: Python 3.8+
- **Resolution**: 800x600 (4:3 aspect ratio)
- **Frame Rate**: 60 FPS
- **Architecture**: Object-oriented with state management

## 📁 Project Structure

```
jacobus-game/
├── src/
│   └── game.py          # Main game code
├── assets/
│   ├── sprites/         # (Future: sprite assets)
│   ├── fonts/           # (Future: custom fonts)
│   └── sounds/          # (Future: sound effects)
├── GAME_DESIGN.md       # Complete game design document
├── README.md            # This file
└── requirements.txt     # Python dependencies
```

## 🐛 Known Issues

- Background buildings randomize each frame (intentional for now - adds dynamic feel)
- No sound effects or music yet (coming soon!)

## 🤝 Contributing

This is a game jam / prototype project, but feel free to:
- Report bugs
- Suggest features
- Create fan art
- Fork and modify for your own use

## 📜 License

This project is open source and available for educational and entertainment purposes.

## 🎮 Credits

**Created by**: Goose AI Assistant  
**Concept**: Jacobus the Williamsburg Warrior  
**Genre**: Beat 'em up / Brawler  
**Inspired by**: 80s arcade culture, manga action, and NYC street life

---

## 🌟 Tips for High Scores

1. **Master the Combo System**: Keep attacking without getting hit to maintain combo multiplier
2. **Strategic Special Usage**: Save Brooklyn Fury for when surrounded by multiple enemies
3. **Positioning is Key**: Don't let enemies surround you
4. **Know Your Range**: Learn the hitbox distances for each attack type
5. **Invincibility Management**: Use damage invincibility frames to escape dangerous situations

---

**DEFEND WILLIAMSBURG. PROTECT THE STREETS. BE THE WARRIOR.**

*"Brooklyn Power!" - Jacobus*
