#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually decrypt a wep message given the WEP key"""

#
# Autheurs: Julien Quartier et Nathan Séville
# Date: 23.03.2020
#

from scapy.all import *
import zlib
import binascii
from rc4 import RC4

##
## Configuration du script
##

# La clé WEP
key = b'\xaa\xaa\xaa\xaa\xaa'

# L'iv en décimal
iv = 123

# Message contenu par le paquet. 
# Ici la valeur utilisé par le prmier paquet afin de tester le script
#message_plain=b'\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x90\x27\xe4\xea\x61\xf2\xc0\xa8\x01\x64\x00\x00\x00\x00\x00\x00\xc0\xa8\x01\xc8'
#message_plain = b'ceci est un test de notre script de chiffrement WEP pour SWI    '
message_plain = b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
print(f"message en clair(hex): {message_plain.hex()}")

##
## Chiffrement
##


# On converti l'IV en hexadécimal bigendian
iv = iv.to_bytes(3, 'big')

# Seed rc4 composée de la clé et de l'iv
seed = iv + key

# Le paquet fourni est utilisé comme framework
arp = rdpcap('arp.cap')[0]

# Calcule le ICV (basé sur crc32), il est important d'utiliser la bonne endianesse
icv_plain = zlib.crc32(message_plain, 0).to_bytes(4, 'little')



# Création du stream RC4 utilisé pour chiffrer
cipher = RC4(seed, streaming=False)
message_cipher = cipher.crypt(message_plain + icv_plain)


print(arp.len)
print(len(arp.wepdata))

# IV utilisé pour le chiffrement
arp.iv = iv

# Conversion de l'ICV chiffré en int
arp.icv = struct.unpack('!I', message_cipher[-4:])[0]

# Message chiffré au quel on a retiré l'ICV
arp.wepdata = message_cipher[:-4]

# La taille doit être recalculée
arp[RadioTap].len = None


print(arp.len)



print(f"message en chiffré(hex): {arp.wepdata.hex()}")


# On créé une nouvelle capture contenant notre paquet forgé
wrpcap('arp_manual_enc.pcap', arp)

