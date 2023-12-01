from tinyec.ec import SubGroup, Curve
from Crypto.Random.random import randint
from web3 import Web3
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import json


h = 1

p = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
n = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

x = int("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
y = int("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
g = (x,y)

print(y**2 % p == (x**3 + 7) % p)

field = SubGroup(p, g, n, h)
curve = Curve(a = 0, b = 7, field = field, name = 'secp256k1')

private_key = randint(1, n)

public_key = private_key * curve.g

public_key_hex = Web3.toHex(public_key.x)[2:] + Web3.toHex(public_key.y)[2:]

address = Web3.keccak(hexstr = public_key_hex).hex()
address = "0x" + address[-40:]

private_key = int("f8f8a2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f315", 16)
print(private_key)
print(" ----------------------------------------------------------------------------------- ")
address = Web3.toChecksumAddress(address)
print(address)


print(" --------------------------------------------------------------------------------- ")
password = b"password"
salt = get_random_bytes(16)

key = scrypt(password, salt, 32, N = 2**20, r = 8, p = 1)

private_key = Web3.toHex(private_key)[2:]
data = str(private_key).encode('utf-8')

cipher = AES.new(key, AES.MODE_CBC)
ct_bytes = cipher.encrypt(pad(data, AES.block_size))

salt = salt.hex()
iv = cipher.iv.hex()
ct = ct_bytes.hex()

output = {"salt" : salt, "initialization vector" : iv, "encrypted private key" : ct}

with open(address + '.txt', 'w') as json_file:
	json.dump(output, json_file)


with open(address + '.txt') as f:
	data = json.load(f)

salt = data['salt']
iv = data['initialization vector']
ct = data['encrypted private key']

salt = bytes.fromhex(salt)
iv = bytes.fromhex(iv)
ct = bytes.fromhex(ct)

key = scrypt(password, salt, 32, N = 2**20, r = 8, p = 1)

cipher = AES.new(key, AES.MODE_CBC, iv)
pt = unpad(cipher.decrypt(ct), AES.block_size)


print(pt.decode('utf-8'))