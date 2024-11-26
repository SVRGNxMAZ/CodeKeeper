import os
from flask import Flask, render_template, request, send_file, url_for
from stepic import encode, decode
from eyed3 import load
from PIL import Image
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64decode, urlsafe_b64encode
from cryptography.hazmat.primitives.ciphers import Cipher
from os import system
from werkzeug.utils import secure_filename

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

RESULT_FOLDER ='results'
app.config['RESULT_FOLDER'] = RESULT_FOLDER
STATIC_IMAGE_PATH = 'static/image.png'  # Replace 'image.png' with the actual path to your static image

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'mp3', 'wav'}  # Allow only mp3 and wav files

def derive_key(password, salt=b'salt', length=32):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,  # Adjust the number of iterations based on your security requirements
        salt=salt,
        length=length
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_message(message, key):
    key = derive_key(key)
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(message.encode('utf-8')) + padder.finalize()

    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    return urlsafe_b64encode(encrypted_message).decode('utf-8')

def decrypt_message(encrypted_message, key):
    key = derive_key(key)
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()

    encrypted_message = urlsafe_b64decode(encrypted_message.encode('utf-8'))
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    unpadded_message = unpadder.update(decrypted_message) + unpadder.finalize()

    return unpadded_message.decode('utf-8')

@app.route('/')
@app.route('/home')
def home():
    return render_template('index.html')

@app.route('/process_data_input', methods=['POST'])
def process_data_input():
    try:
        # Get the message, key, and audio file from the form
        message = request.form.get('message')
        key = request.form.get('key')
        audio_file = request.files['audio_file']

        # Check if the audio file is allowed
        if audio_file and allowed_file(audio_file.filename):
            # Save the audio file to the uploads directory
            audio_filename = os.path.join(app.config['UPLOAD_FOLDER'], audio_file.filename)
            audio_file.save(audio_filename)

            # Load the audio file
            audio = load(audio_filename)

            # Encrypt the message using derived key from the provided key
            encrypted_message = encrypt_message(message, key)

            # Open the static image file and encode the encrypted message
            img = Image.open(STATIC_IMAGE_PATH)
            img_stegano = encode(img, encrypted_message.encode('utf-8'))
            img_stegano.save(STATIC_IMAGE_PATH)

            # Initialize the audio tag, set the image, and save the tag
            audio.initTag()
            audio.tag.images.set(3, open(STATIC_IMAGE_PATH, 'rb').read(), 'image/png')
            audio.tag.save()

            # Decode the message from the audio file using the provided key
            decoded_message = decode(img_stegano)

            # Provide download links for both the decrypted message and the uploaded audio file
            download_audio_link = url_for('download_uploaded_audio', filename=audio_file.filename)

            return render_template('succes.html', form_message_success=True,  download_audio_link=download_audio_link)
        else:
            return 'Error: Invalid audio file format'
    except Exception as e:
        print("Error:", str(e))
        return 'Something went wrong. Please try again.'

@app.route('/download_uploaded_audio/<filename>')
def download_uploaded_audio(filename):
    # Provide the path to the uploaded audio file
    uploaded_audio_filename = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # Serve the file for download
    return send_file(uploaded_audio_filename, as_attachment=True)

@app.route('/download_decrypted/<filename>',  methods=['GET', 'POST'])
def download_decrypted(filename):
    # Provide the path to the decrypted file
    decrypted_filename = os.path.join(app.config['RESULT_FOLDER'], 'decrypted_message.txt')

    # Serve the file for download
    return send_file(decrypted_filename, as_attachment=True)


@app.route('/decode')
def decode_home():
    return render_template('decode.html')

@app.route('/process_data_input2', methods=['POST'])
def process_data_input2():
    try:
        # Get the audio file for decoding
        audio_file = request.files['audio_file']
        key = request.form.get('key')

        # Save the audio file to the uploads directory
        audio_filename = os.path.join(app.config['RESULT_FOLDER'], secure_filename(audio_file.filename))
        audio_file.save(audio_filename)

        # Load the audio file
        audio = load(audio_filename)

        # Extract image data from the audio file
        img_data = audio.tag.images[0].image_data

        # Save the image data to a temporary file
        img_filename = os.path.join(app.config['RESULT_FOLDER'], 'temp_img.png')
        with open(img_filename, 'wb') as img_file:
            img_file.write(img_data)


        # Open the static image file and decode the message
        img = Image.open(img_filename)
        text = decode(img)

        # Decrypt the message using the provided key
        decrypted_message = decrypt_message(text, key)

        # Create a file to store the decrypted message
        decrypted_filename = os.path.join(app.config['RESULT_FOLDER'], 'decrypted_message.txt')
        with open(decrypted_filename, 'w') as decrypted_file:
                decrypted_file.write(decrypted_message)

        # Provide download links for both the decrypted message and the uploaded audio file
        download_message_link = url_for('download_decrypted', filename='decrypted_message.txt')

        return render_template('result.html', decoded_message=text, decrypted_message=decrypted_message)
    except Exception as e:
        print("Error:", str(e))
        return 'Error decoding the message.'
    

    

if __name__ == '__main__':
    app.run(debug=True)
