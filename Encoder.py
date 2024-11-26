from stepic import encode
from eyed3 import load
from PIL import Image

print("#######################")

data =str(input("Enter the message to encrypt: "))

audio = input("Enter the name of the audio file: ")
img_name = input("Enter the name of the image file: ")
audio = load(audio)

img = Image.open(img_name)
img_stegano = encode(img, data.encode('utf-8'))
img_stegano.save(img_name)

audio.initTag()
audio.tag.images.set(3, open(img_name, 'rb').read(), 'image/png')
audio.tag.save()


print("#######################")

input("Press Enter to exit...")