from pwn import *

def xor_str(s1, s2):
    assert(len(s1) == len(s2))
    return "".join(chr(ord(s1[i]) ^ ord(s2[i])) for i in range(len(s1)))

prefix = "comment1=wowsuch%20CBC;userdata="
suffix = ";coment2=%20suchsafe%20very%20encryptwowww"
goal = ";admin=true"
goal = goal + "a" * (16 - len(goal))

payload = "mkprof:" + "a" * 16
plain = prefix + payload[7:] + suffix
plain = [plain[i:i+16] for i in range(0,len(plain),16)]

r = remote('133.130.52.128', 6666)
r.send(payload)
cipher = r.recv().strip()
cipher = [cipher[i:i+32] for i in range(0,len(cipher),32)]
manipulate = cipher[2].decode("hex")
s1 = xor_str(goal, suffix[:16])
s2 = xor_str(manipulate, s1)
cipher[2] = s2.encode("hex")

data = "parse:" + "".join(i for i in cipher)

r.send(data)
print r.recv()
