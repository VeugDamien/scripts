#!/usr/bin/python3.6
# -*- Coding: utf-8 -*-

from PIL import Image
import base64

offset = 2 # Step entre chaque colonnes contenant l'information cachée
split = False #True pour séparation des canaux
res = ""
sol = ""
name = "anssi"
ext = ".png"

# 1- Ouverture de l'image
img = Image.open(name + ext)
width, height = img.size

# 2- Création de l'image avec affichage du LSB
lsb = Image.new('RGB',(width, height))

# 3- Création des images de séparations des canaux
if split:
    red = Image.new('RGB',(width, height))
    green = Image.new('RGB',(width, height))
    blue = Image.new('RGB',(width, height))

# 4- Récupération des pixels
for x in range(0,height):
    for y in range(0, width):
        r, g, b = img.getpixel((y,x))

        # Récupération des derniers bits
        r = (r&1)
        g = (g&1)
        b = (b&1)

        # Création du pixel de l'image LSB
        lsb.putpixel((y,x),(r*255,g*255,b*255))
        if split:
            # Ajout des pixels selon les canaux
            red.putpixel((y,x),(r*255,0,0))
            green.putpixel((y,x),(0,g*255,0))
            blue.putpixel((y,x),(0,0,b*255))

        # Récupération des valeurs LSB en fonction d'un offset définit
        if y % offset == 0:
            res += str(r) + str(g) + str(b)

# 5- Sauvegarde de l'image LSB
lsb.save(name + '_lsb' + ext)

# 6- Sauvegarde des images avec séparations des canaux
if split:
    red.save(name + '_red' + ext)
    green.save(name + '_green' + ext)
    blue.save(name + '_blue' + ext)


# 7- Réduction de la taille de la chaine d'extraction du LSB
col_start = 0
ligne_start = 0
start = ligne_start*width+col_start

col_end = 0
ligne_end = 54
end = ligne_end*width+col_end

res = res[start:end]

# 8- Transformation du binaire en ASCII
for i in range(int(len(res)/8)):
    sol += chr(int(res[i*8:i*8+8],2))

print(sol)