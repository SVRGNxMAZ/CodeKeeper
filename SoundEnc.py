from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from PIL import Image, ImageDraw, ImageFont
import binascii

def pad_message(message):
    # AES requires the length of the message to be a multiple of 16
    # Pad the message with spaces if necessary
    while len(message) % 16 != 0:
        message += ' '
    return message

def encrypt_message(key, message):
    message = pad_message(message)
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(message.encode('utf-8'))
    return ciphertext

def text_to_bmp(ciphertext, output_filename):
    # Convert ciphertext to hexadecimal
    hex_data = binascii.hexlify(ciphertext).decode()

    # Set image size and font
    image_width = 300
    image_height = 100
    background_color = "black"
    text_color = "white"
    font_path = "arial.ttf"  # Path to a font file
    font_size = 15

    # Create a blank image
    image = Image.new("RGB", (image_width, image_height), color=background_color)
    draw = ImageDraw.Draw(image)

    # Load a font
    try:
        font = ImageFont.truetype(font_path, font_size)
    except IOError:
        font = ImageFont.load_default()

    # Calculate text position
    text_x = 10
    text_y = 10

    # Draw ciphertext (hexadecimal) on the image
    draw.text((text_x, text_y), hex_data, fill=text_color, font=font)

    # Save the image as BMP
    image.save(output_filename, "BMP")
    print(f"Ciphertext converted to BMP. Saved as '{output_filename}'")

# Get user input for the message
message = input("Enter the message to encrypt: ")
key = get_random_bytes(16)  # Generate a random 16-byte key

# Encrypt the message
encrypted_message = encrypt_message(key, message)
print(f"Encrypted Message: {encrypted_message}")

# Convert ciphertext to BMP image
output_filename = "output.bmp"
text_to_bmp(encrypted_message, output_filename)