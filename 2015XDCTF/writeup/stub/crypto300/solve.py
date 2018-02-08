from pwn import *
import struct
import gmpy2
from gmpy2 import mpz
from hashlib import sha512

def hash2int(*params):
    sha=sha512()
    for el in params:
        sha.update("%r"%el)
    return int(sha.hexdigest(), 16)

#URL = 'localhost'
URL = '133.130.52.128'
N = mpz(1501763523645191865825715850305314918471290802252408144539280540647301821)
r = remote(URL, 5000)

index = pow(2, (N-1)/4, N)
root = hex(index)[2:]
print r.recv()
r.send(struct.pack("<H", len(root)))
r.send(root)
print r.recv()
r.send(struct.pack("<H", 1))
r.send("1")
salt = int(r.recv().strip(),16)
skey = int(r.recv().strip(),16)

temp_key = hash2int(1L)
ckey = 1
index = int(index)
N = int(N)

final_key = hash2int(hash2int(N) ^ hash2int(index), hash2int(index), salt, ckey, skey, temp_key)
final_key = hex(final_key)[2:]
r.send(struct.pack("<H",len(final_key)))
r.send(final_key)
print r.recv()
