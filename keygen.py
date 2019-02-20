#!/usr/bin/env python3
import os, binascii, hashlib, base58, ecdsa
import random

def shex(val):
    return binascii.hexlify(val).decode()

def b58wchecksum(val):
    checksum = hashlib.sha256(hashlib.sha256(val).digest()).digest()[:4]
    return base58.b58encode(val+checksum)

def ripemd160(val):
    d = hashlib.new("ripemd160")
    d.update(val)
    return d

#generate private key
random.seed(666) # generate a key with random.seed
priv_key = bytes([random.randint(0, 255) for x in range(32)])

# priv_key => wallet_import_format
full_key = b'\x80' + priv_key
wallet_import_format = b58wchecksum(full_key)

# priv_key to public_key
sk = ecdsa.SigningKey.from_string(priv_key, curve=ecdsa.SECP256k1)
vk = sk.get_verifying_key()
publ_key = b'\x04' + vk.to_string()
hash160 = ripemd160(hashlib.sha256(publ_key).digest()).digest()
publ_addr_a = b'\x00' + hash160
publ_addr_b = b58wchecksum(publ_addr_a)
# printing info
# can be verified over https://coinb.in/#verify
print("Private Key: {}".format(str(shex(priv_key))))
print("Wallet Import Format (WIF_Priv_key): {}".format(str(wallet_import_format)))
print("Wallet Address: {}".format(str(publ_addr_b)))
