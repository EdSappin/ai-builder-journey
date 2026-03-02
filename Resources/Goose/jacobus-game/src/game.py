"""
JACOBUS: WILLIAMSBURG WARRIOR
Main Game Module
"""

import pygame
import sys
from enum import Enum
import random
import math

# Initialize Pygame
pygame.init()

# Constants
SCREEN_WIDTH = 800
SCREEN_HEIGHT = 600
FPS = 60

# Colors (80s Neon Palette)
HOT_PINK = (255, 0, 110)
ELECTRIC_CYAN = (0, 245, 255)
PURPLE = (139, 0, 255)
DARK_NAVY = (10, 14, 39)
GOLD = (255, 215, 0)
WHITE = (255, 255, 255)
RED = (255, 0, 0)
GREEN = (0, 255, 0)
BLACK = (0, 0, 0)

class GameState(Enum):
    TITLE = 1
    PLAYING = 2
    PAUSED = 3
    GAME_OVER = 4
    VICTORY = 5

class Direction(Enum):
    LEFT = -1
    RIGHT = 1

class Entity:
    """Base class for all game entities"""
    def __init__(self, x, y, width, height, color):
        self.x = x
        self.y = y
        self.width = width
        self.height = height
        self.color = color
        self.vel_x = 0
        self.vel_y = 0
        self.on_ground = True
        
    def get_rect(self):
        return pygame.Rect(self.x, self.y, self.width, self.height)
    
    def draw(self, screen):
        pygame.draw.rect(screen, self.color, self.get_rect())

class Player(Entity):
    """Jacobus - The Williamsburg Warrior"""
    def __init__(self, x, y):
        super().__init__(x, y, 50, 80, HOT_PINK)
        self.max_health = 100
        self.health = self.max_health
        self.speed = 5
        self.jump_power = -15
        self.facing = Direction.RIGHT
        self.attacking = False
        self.attack_timer = 0
        self.attack_cooldown = 20
        self.combo_count = 0
        self.special_energy = 100
        self.max_special = 100
        self.invincible_timer = 0
        
    def update(self, keys, enemies):
        # Movement
        self.vel_x = 0
        
        if keys[pygame.K_LEFT] or keys[pygame.K_a]:
            self.vel_x = -self.speed
            self.facing = Direction.LEFT
        elif keys[pygame.K_RIGHT] or keys[pygame.K_d]:
            self.vel_x = self.speed
            self.facing = Direction.RIGHT
            
        # Jump
        if (keys[pygame.K_SPACE] or keys[pygame.K_w]) and self.on_ground:
            self.vel_y = self.jump_power
            self.on_ground = False
            
        # Gravity
        self.vel_y += 0.8
        if self.vel_y > 10:
            self.vel_y = 10
            
        # Update position
        self.x += self.vel_x
        self.y += self.vel_y
        
        # Ground collision
        ground_level = 450
        if self.y >= ground_level:
            self.y = ground_level
            self.vel_y = 0
            self.on_ground = True
            
        # Screen bounds
        if self.x < 0:
            self.x = 0
        elif self.x > SCREEN_WIDTH - self.width:
            self.x = SCREEN_WIDTH - self.width
            
        # Attack cooldown
        if self.attack_timer > 0:
            self.attack_timer -= 1
            
        if self.invincible_timer > 0:
            self.invincible_timer -= 1
            
        # Regenerate special energy slowly
        if self.special_energy < self.max_special:
            self.special_energy += 0.1
            
    def attack(self, enemies, attack_type="light"):
        """Perform attack"""
        if self.attack_timer > 0:
            return False
            
        self.attacking = True
        self.attack_timer = self.attack_cooldown
        
        # Create attack hitbox
        attack_range = 60
        attack_x = self.x + self.width if self.facing == Direction.RIGHT else self.x - attack_range
        attack_rect = pygame.Rect(attack_x, self.y, attack_range, self.height)
        
        damage = 10 if attack_type == "light" else 20
        hit_enemy = False
        
        for enemy in enemies:
            if not enemy.alive:
                continue
            if attack_rect.colliderect(enemy.get_rect()):
                enemy.take_damage(damage)
                hit_enemy = True
                self.combo_count += 1
                
        return hit_enemy
    
    def special_attack(self, enemies):
        """BROOKLYN FURY - Special move"""
        if self.special_energy < 30:
            return False
            
        self.special_energy -= 30
        
        # Large area attack
        attack_range = 120
        for enemy in enemies:
            if not enemy.alive:
                continue
            distance = abs(self.x - enemy.x)
            if distance < attack_range:
                enemy.take_damage(30)
                enemy.vel_x = 10 if enemy.x > self.x else -10
                
        return True
    
    def take_damage(self, damage):
        """Take damage with invincibility frames"""
        if self.invincible_timer > 0:
            return
            
        self.health -= damage
        self.invincible_timer = 60  # 1 second of invincibility
        self.combo_count = 0
        
        if self.health < 0:
            self.health = 0
            
    def draw(self, screen):
        # Flicker when invincible
        if self.invincible_timer > 0 and self.invincible_timer % 6 < 3:
            return
            
        # Body
        pygame.draw.rect(screen, self.color, self.get_rect())
        
        # Bandana (signature red bandana)
        bandana_rect = pygame.Rect(self.x + 10, self.y + 5, 30, 10)
        pygame.draw.rect(screen, RED, bandana_rect)
        
        # Face outline (manga style)
        face_rect = pygame.Rect(self.x + 10, self.y + 15, 30, 25)
        pygame.draw.rect(screen, ELECTRIC_CYAN, face_rect, 2)
        
        # Attack indicator
        if self.attacking and self.attack_timer > self.attack_cooldown - 5:
            attack_range = 60
            attack_x = self.x + self.width if self.facing == Direction.RIGHT else self.x - attack_range
            attack_rect = pygame.Rect(attack_x, self.y + 20, attack_range, 40)
            pygame.draw.rect(screen, GOLD, attack_rect, 2)
            
            # Speed lines (manga influence)
            for i in range(3):
                offset = i * 15
                start_x = attack_x + offset
                pygame.draw.line(screen, WHITE, 
                               (start_x, self.y + 20), 
                               (start_x + 20, self.y + 20), 2)

class Enemy(Entity):
    """Base enemy class"""
    def __init__(self, x, y, enemy_type="punk"):
        colors = {
            "punk": PURPLE,
            "guard": (100, 100, 100),
            "ninja": (50, 0, 100)
        }
        super().__init__(x, y, 45, 70, colors.get(enemy_type, PURPLE))
        self.enemy_type = enemy_type
        self.health = 30
        self.max_health = 30
        self.speed = 2
        self.alive = True
        self.attack_timer = 0
        self.ai_timer = 0
        
    def update(self, player):
        if not self.alive:
            return
            
        self.ai_timer += 1
        
        # Simple AI - move toward player
        if abs(self.x - player.x) > 50:
            if self.x < player.x:
                self.vel_x = self.speed
            else:
                self.vel_x = -self.speed
        else:
            self.vel_x = 0
            # Attack player
            if self.ai_timer % 60 == 0:
                if abs(self.x - player.x) < 60 and abs(self.y - player.y) < 50:
                    player.take_damage(5)
                    
        # Apply gravity
        self.vel_y += 0.8
        if self.vel_y > 10:
            self.vel_y = 10
            
        # Update position
        self.x += self.vel_x
        self.y += self.vel_y
        
        # Ground collision
        ground_level = 450
        if self.y >= ground_level:
            self.y = ground_level
            self.vel_y = 0
            
        # Decay horizontal velocity
        self.vel_x *= 0.8
        
    def take_damage(self, damage):
        self.health -= damage
        if self.health <= 0:
            self.alive = False
            
    def draw(self, screen):
        if not self.alive:
            return
            
        # Body
        pygame.draw.rect(screen, self.color, self.get_rect())
        
        # Health bar
        health_width = int((self.health / self.max_health) * self.width)
        health_rect = pygame.Rect(self.x, self.y - 10, health_width, 5)
        pygame.draw.rect(screen, RED, health_rect)
        pygame.draw.rect(screen, WHITE, pygame.Rect(self.x, self.y - 10, self.width, 5), 1)

class Game:
    """Main game class"""
    def __init__(self):
        self.screen = pygame.display.set_mode((SCREEN_WIDTH, SCREEN_HEIGHT))
        pygame.display.set_caption("JACOBUS: WILLIAMSBURG WARRIOR")
        self.clock = pygame.time.Clock()
        self.state = GameState.TITLE
        self.font_large = pygame.font.Font(None, 72)
        self.font_medium = pygame.font.Font(None, 36)
        self.font_small = pygame.font.Font(None, 24)
        
        self.player = None
        self.enemies = []
        self.wave = 0
        self.score = 0
        self.high_score = 0
        
    def new_game(self):
        """Start a new game"""
        self.player = Player(100, 450)
        self.enemies = []
        self.wave = 0
        self.score = 0
        self.spawn_wave()
        self.state = GameState.PLAYING
        
    def spawn_wave(self):
        """Spawn a wave of enemies"""
        self.wave += 1
        num_enemies = 2 + self.wave
        
        for i in range(num_enemies):
            x = SCREEN_WIDTH + i * 100
            enemy_types = ["punk", "guard", "ninja"]
            enemy_type = random.choice(enemy_types[:min(self.wave, 3)])
            self.enemies.append(Enemy(x, 450, enemy_type))
            
    def handle_events(self):
        """Handle input events"""
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                return False
                
            if event.type == pygame.KEYDOWN:
                if self.state == GameState.TITLE:
                    if event.key == pygame.K_RETURN:
                        self.new_game()
                        
                elif self.state == GameState.PLAYING:
                    if event.key == pygame.K_ESCAPE:
                        self.state = GameState.PAUSED
                    elif event.key == pygame.K_z or event.key == pygame.K_j:
                        self.player.attack(self.enemies, "light")
                    elif event.key == pygame.K_x or event.key == pygame.K_k:
                        self.player.attack(self.enemies, "heavy")
                    elif event.key == pygame.K_c or event.key == pygame.K_l:
                        if self.player.special_attack(self.enemies):
                            self.score += 50
                            
                elif self.state == GameState.PAUSED:
                    if event.key == pygame.K_ESCAPE:
                        self.state = GameState.PLAYING
                    elif event.key == pygame.K_q:
                        self.state = GameState.TITLE
                        
                elif self.state in [GameState.GAME_OVER, GameState.VICTORY]:
                    if event.key == pygame.K_RETURN:
                        self.state = GameState.TITLE
                        
        return True
    
    def update(self):
        """Update game logic"""
        if self.state != GameState.PLAYING:
            return
            
        keys = pygame.key.get_pressed()
        self.player.update(keys, self.enemies)
        
        # Update enemies
        for enemy in self.enemies:
            enemy.update(self.player)
            
        # Remove dead enemies and update score
        alive_enemies = []
        for enemy in self.enemies:
            if enemy.alive:
                alive_enemies.append(enemy)
            else:
                self.score += 100 * self.player.combo_count if self.player.combo_count > 0 else 100
                
        self.enemies = alive_enemies
        
        # Check if wave is complete
        if len(self.enemies) == 0:
            self.spawn_wave()
            
        # Check game over
        if self.player.health <= 0:
            self.state = GameState.GAME_OVER
            if self.score > self.high_score:
                self.high_score = self.score
                
        # Victory condition (survive 10 waves)
        if self.wave > 10:
            self.state = GameState.VICTORY
            if self.score > self.high_score:
                self.high_score = self.score
    
    def draw(self):
        """Draw everything"""
        self.screen.fill(DARK_NAVY)
        
        if self.state == GameState.TITLE:
            self.draw_title_screen()
        elif self.state == GameState.PLAYING:
            self.draw_game()
        elif self.state == GameState.PAUSED:
            self.draw_game()
            self.draw_pause_screen()
        elif self.state == GameState.GAME_OVER:
            self.draw_game_over()
        elif self.state == GameState.VICTORY:
            self.draw_victory()
            
        pygame.display.flip()
        
    def draw_title_screen(self):
        """Draw title screen"""
        # Title
        title = self.font_large.render("JACOBUS", True, HOT_PINK)
        title_rect = title.get_rect(center=(SCREEN_WIDTH // 2, 150))
        self.screen.blit(title, title_rect)
        
        subtitle = self.font_medium.render("WILLIAMSBURG WARRIOR", True, ELECTRIC_CYAN)
        subtitle_rect = subtitle.get_rect(center=(SCREEN_WIDTH // 2, 220))
        self.screen.blit(subtitle, subtitle_rect)
        
        # Neon grid effect (80s style)
        for i in range(10):
            y = 300 + i * 30
            alpha = 255 - (i * 20)
            color = (139, 0, 255, alpha)
            start_y = y + math.sin(pygame.time.get_ticks() / 100 + i) * 5
            pygame.draw.line(self.screen, PURPLE, (100, start_y), (700, start_y), 2)
            
        # Instructions
        instructions = [
            "PRESS ENTER TO START",
            "",
            "CONTROLS:",
            "ARROW KEYS - MOVE",
            "SPACE - JUMP",
            "Z - LIGHT ATTACK",
            "X - HEAVY ATTACK",
            "C - SPECIAL (BROOKLYN FURY)",
            "ESC - PAUSE"
        ]
        
        y_offset = 350
        for line in instructions:
            if line == "PRESS ENTER TO START":
                # Blinking effect
                if pygame.time.get_ticks() % 1000 < 500:
                    text = self.font_small.render(line, True, GOLD)
                    text_rect = text.get_rect(center=(SCREEN_WIDTH // 2, y_offset))
                    self.screen.blit(text, text_rect)
            else:
                text = self.font_small.render(line, True, WHITE)
                text_rect = text.get_rect(center=(SCREEN_WIDTH // 2, y_offset))
                self.screen.blit(text, text_rect)
            y_offset += 25
            
    def draw_game(self):
        """Draw game screen"""
        # Background (simple cityscape silhouette)
        # Building silhouettes
        for i in range(5):
            height = random.randint(100, 200)
            width = 120
            x = i * 160
            pygame.draw.rect(self.screen, (20, 24, 59), 
                           pygame.Rect(x, 450 - height, width, height))
            # Windows
            for row in range(height // 20):
                for col in range(3):
                    wx = x + 20 + col * 30
                    wy = 450 - height + row * 20
                    color = GOLD if random.random() > 0.7 else (40, 44, 79)
                    pygame.draw.rect(self.screen, color, 
                                   pygame.Rect(wx, wy, 15, 12))
        
        # Ground
        pygame.draw.rect(self.screen, (30, 34, 69), 
                        pygame.Rect(0, 520, SCREEN_WIDTH, 80))
        
        # Grid lines on ground (80s style)
        for i in range(20):
            x = i * 40
            pygame.draw.line(self.screen, PURPLE, (x, 520), (x, SCREEN_HEIGHT), 1)
            
        # Draw entities
        self.player.draw(self.screen)
        for enemy in self.enemies:
            enemy.draw(self.screen)
            
        # HUD
        self.draw_hud()
        
    def draw_hud(self):
        """Draw heads-up display"""
        # Health bar
        pygame.draw.rect(self.screen, BLACK, pygame.Rect(18, 18, 204, 24))
        health_width = int((self.player.health / self.player.max_health) * 200)
        pygame.draw.rect(self.screen, RED, pygame.Rect(20, 20, health_width, 20))
        pygame.draw.rect(self.screen, HOT_PINK, pygame.Rect(20, 20, 200, 20), 3)
        
        health_text = self.font_small.render(f"HP: {self.player.health}", True, WHITE)
        self.screen.blit(health_text, (230, 20))
        
        # Special energy bar
        pygame.draw.rect(self.screen, BLACK, pygame.Rect(18, 48, 204, 14))
        energy_width = int((self.player.special_energy / self.player.max_special) * 200)
        pygame.draw.rect(self.screen, ELECTRIC_CYAN, pygame.Rect(20, 50, energy_width, 10))
        pygame.draw.rect(self.screen, PURPLE, pygame.Rect(20, 50, 200, 10), 2)
        
        # Score
        score_text = self.font_medium.render(f"SCORE: {self.score}", True, GOLD)
        self.screen.blit(score_text, (SCREEN_WIDTH - 250, 20))
        
        # Wave
        wave_text = self.font_small.render(f"WAVE: {self.wave}", True, WHITE)
        self.screen.blit(wave_text, (SCREEN_WIDTH - 150, 60))
        
        # Combo
        if self.player.combo_count > 1:
            combo_text = self.font_medium.render(f"COMBO x{self.player.combo_count}!", True, GOLD)
            combo_rect = combo_text.get_rect(center=(SCREEN_WIDTH // 2, 100))
            self.screen.blit(combo_text, combo_rect)
            
    def draw_pause_screen(self):
        """Draw pause overlay"""
        # Semi-transparent overlay
        overlay = pygame.Surface((SCREEN_WIDTH, SCREEN_HEIGHT))
        overlay.set_alpha(128)
        overlay.fill(BLACK)
        self.screen.blit(overlay, (0, 0))
        
        # Pause text
        pause_text = self.font_large.render("PAUSED", True, HOT_PINK)
        pause_rect = pause_text.get_rect(center=(SCREEN_WIDTH // 2, SCREEN_HEIGHT // 2 - 50))
        self.screen.blit(pause_text, pause_rect)
        
        resume_text = self.font_small.render("ESC - RESUME", True, WHITE)
        resume_rect = resume_text.get_rect(center=(SCREEN_WIDTH // 2, SCREEN_HEIGHT // 2 + 20))
        self.screen.blit(resume_text, resume_rect)
        
        quit_text = self.font_small.render("Q - QUIT TO TITLE", True, WHITE)
        quit_rect = quit_text.get_rect(center=(SCREEN_WIDTH // 2, SCREEN_HEIGHT // 2 + 50))
        self.screen.blit(quit_text, quit_rect)
        
    def draw_game_over(self):
        """Draw game over screen"""
        self.screen.fill(DARK_NAVY)
        
        # Game over text
        game_over_text = self.font_large.render("GAME OVER", True, RED)
        game_over_rect = game_over_text.get_rect(center=(SCREEN_WIDTH // 2, 200))
        self.screen.blit(game_over_text, game_over_rect)
        
        # Score
        score_text = self.font_medium.render(f"FINAL SCORE: {self.score}", True, GOLD)
        score_rect = score_text.get_rect(center=(SCREEN_WIDTH // 2, 300))
        self.screen.blit(score_text, score_rect)
        
        high_score_text = self.font_medium.render(f"HIGH SCORE: {self.high_score}", True, ELECTRIC_CYAN)
        high_score_rect = high_score_text.get_rect(center=(SCREEN_WIDTH // 2, 350))
        self.screen.blit(high_score_text, high_score_rect)
        
        # Continue prompt
        if pygame.time.get_ticks() % 1000 < 500:
            continue_text = self.font_small.render("PRESS ENTER TO CONTINUE", True, WHITE)
            continue_rect = continue_text.get_rect(center=(SCREEN_WIDTH // 2, 450))
            self.screen.blit(continue_text, continue_rect)
            
    def draw_victory(self):
        """Draw victory screen"""
        self.screen.fill(DARK_NAVY)
        
        # Victory text
        victory_text = self.font_large.render("VICTORY!", True, GOLD)
        victory_rect = victory_text.get_rect(center=(SCREEN_WIDTH // 2, 150))
        self.screen.blit(victory_text, victory_rect)
        
        message = self.font_medium.render("WILLIAMSBURG IS SAFE!", True, HOT_PINK)
        message_rect = message.get_rect(center=(SCREEN_WIDTH // 2, 250))
        self.screen.blit(message, message_rect)
        
        # Score
        score_text = self.font_medium.render(f"FINAL SCORE: {self.score}", True, GOLD)
        score_rect = score_text.get_rect(center=(SCREEN_WIDTH // 2, 350))
        self.screen.blit(score_text, score_rect)
        
        high_score_text = self.font_medium.render(f"HIGH SCORE: {self.high_score}", True, ELECTRIC_CYAN)
        high_score_rect = high_score_text.get_rect(center=(SCREEN_WIDTH // 2, 400))
        self.screen.blit(high_score_text, high_score_rect)
        
        # Continue prompt
        if pygame.time.get_ticks() % 1000 < 500:
            continue_text = self.font_small.render("PRESS ENTER TO CONTINUE", True, WHITE)
            continue_rect = continue_text.get_rect(center=(SCREEN_WIDTH // 2, 500))
            self.screen.blit(continue_text, continue_rect)
        
    def run(self):
        """Main game loop"""
        running = True
        
        while running:
            running = self.handle_events()
            self.update()
            self.draw()
            self.clock.tick(FPS)
            
        pygame.quit()
        sys.exit()

def main():
    """Entry point"""
    game = Game()
    game.run()

if __name__ == "__main__":
    main()
