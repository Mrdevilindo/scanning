import pygame
import sys

# Inisialisasi pygame
pygame.init()

# Warna RGB
WHITE = (255, 255, 255)
BLACK = (0, 0, 0)

# Lebar dan tinggi layar animasi
SCREEN_WIDTH = 800
SCREEN_HEIGHT = 600

# Membuat layar animasi
screen = pygame.display.set_mode((SCREEN_WIDTH, SCREEN_HEIGHT))
pygame.display.set_caption("XSS Scanner Animation")

# Fungsi untuk menghentikan program ketika pengguna menutup jendela animasi
def quit_game():
    pygame.quit()
    sys.exit()

# Fungsi untuk menggambar animasi
def draw_animation():
    # Clear layar
    screen.fill(WHITE)

    # Gambar animasi di sini (contoh: garis bergerak dari kiri ke kanan)
    animation_speed = 1  # Kecepatan animasi
    animation_position = 0

    while animation_position < SCREEN_WIDTH:
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                quit_game()

        pygame.draw.line(screen, BLACK, (animation_position, 0), (animation_position, SCREEN_HEIGHT))
        animation_position += animation_speed

        # Update layar animasi
        pygame.display.update()

        # Atur kecepatan animasi
        pygame.time.delay(10)

# Panggil fungsi animasi sebelum menjalankan XSS scanner
draw_animation()
