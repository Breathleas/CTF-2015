# REVERSE100

变态题，属于强行挖坑型。

执行 `file rev100` 发现是 Linux x64 的程序，传到 x64 Kali 上运行后接受输入，目测是 read 12 Bytes，因为输入 11 个字符加回车就会退出。

丢进 IDA 逆向，发现字符串输入后在 sub_4008E1 函数中 encode 并与另一个硬编码字符串比较。这里总共有三个过程，具体记不太清了，直接逆就好了。

比较坑的是用于异或的 key 并不是最原始在 IDA 中看到的 key，而是在后面被修改过的，所以前面一直出错，知道我用 gdb 去单步调试才发现问题。程序最开始有反调试，不过用 gdb 的 jump 直接跳过那一段判断就好了。

坑点还有很多，在三轮加密的过程中有一步是判断字符的 ASCII 值是否小于 0x20，如果是的话就要加上 0x20，所以逆向回去的时候遇到 0x30 这种值你就不知道它是 0x30 还是 0x10，只能通过主办方‘全是小写’的提示来判断。

最后的压轴坑点是如果逆向成功过了整个流程，它会显示 **Congratulations? Key is XDCTF{Input}**， 请注意那个问号，这特么不是正确的函数，真正的函数是这个隔壁的 sub_400787，这个函数在程序原逻辑中没有被调用到，唯一的区别是前一个函数在第一轮加密的时候多异或了一个 **7**。而它的结束后会将 **Congratulations? Key is XDCTF{Input}** 的问号改成感叹号，我是服了 \_(:зゝ∠)\_

```python
enc  = "1b25033814384e21105a3f17"
enc += "270512335d2f350311025958"
enc = enc.decode('hex')
print enc
key = "ZzAwZF9DcjRrM3JfZzBfb24="
tmp1 = ""
tmp2 = list(enc)
for i in range(6):
    tmp = tmp2[i]
    tmp2[i] = tmp2[17-i]
    tmp2[17-i] = tmp
enc = ''.join(tmp2)
# print enc.encode('hex')
for i in range(len(key)):
    tmp1 += chr(ord(enc[i]) ^ ord(key[i]))
print tmp1[:12]
print tmp1[:12].encode('hex')
print tmp1[12:].encode('hex')
```

# REVERSE200

写 writeup 的时候一看这题发现啥都没有，既没有逆向破解脚本也没有 IDA 分析文件，用 Ollydbg 打开看了一下才回忆起来。

这道题就是根据你输入的字符串进行若干次的判断，要通过每一个判断点才能拿到 flag。我反正就是在各个 `test`, `jz`, `jnz` 等指令处下了断点，单步进去根据汇编分析判断的逻辑，然后就过了。

就这样吧，这题没法写，反正难度也不太大。


# REVERSE300

试图修复源文件然而太麻烦，弃疗。于是把整道题当黑盒 Crypto 做。对源码的直接分析只发现了两点有用信息：

* 从 `flag.txt` 读取输入，输出到 `flag.enc`。
* 输入范围限定在 `string.printable.strip()` 中。

通过观察加密程序的输出可以发现它是 4 bytes 一组的 block cipher，各 block 之间互相独立。很神奇的一点是对于每个 block 输出都只有 3 bytes，肯定有丢失数据。

实际上 plaintext 和 ciphertext 之间的关系是完全线性的可以直接解出来。然而懒成了狗于是选择强行穷举 4 bytes 的可见字符。

```python
from StringIO import StringIO

my_table = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
targets = 'a2d378 d01660 cf6209 18e164 f48848 019609 5d4685 4f175c cf4010 1d0000'.split(' ')
result = {_: [] for _ in targets}

for s1 in my_table:
    print s1
    for lga in my_table:
        for hacfun in my_table:
            for bgm in my_table:
                str = ''.join([s1, lga, hacfun, bgm])
                out = StringIO()
                (lambda __g, __y: [[[[[[[(fin.close(), [[(lambda __items, __after, __sentinel: __y(lambda __this: lambda: (lambda __i: [(ss.append(c), (sss.append(0), __this())[1])[1] for __g['c'] in [(__i)]][0] if __i is not __sentinel else __after())(next(__items, __sentinel)))())(iter(s), lambda: [[(lambda __items, __after, __sentinel: __y(lambda __this: lambda: (lambda __i: [(lambda __value: [__this() for __g['sssss'] in [((lambda __ret: __g['sssss'] + __value if __ret is NotImplemented else __ret)(getattr(__g['sssss'], '__iadd__', lambda other: NotImplemented)(__value)))]][0])(chr(c)) for __g['c'] in [(__i)]][0] if __i is not __sentinel else __after())(next(__items, __sentinel)))())(iter(ssss), lambda: [(fout.write(sssss), (lambda : None, None)[1])[1] for __g['fout'] in [(out)]][0], []) for __g['sssss'] in [('')]][0] for __g['ssss'] in [(encode(ss, sss))]][0], []) for __g['sss'] in [([])]][0] for __g['ss'] in [([])]][0])[1] for __g['s'] in [(fin.read().strip())]][0] for __g['fin'] in [(StringIO(str))]][0] for __g['encode'], encode.__name__ in [(lambda data, buf: (lambda __l: [[(lambda __items, __after, __sentinel: __y(lambda __this: lambda: (lambda __i: [[__this() for __l['data'][__l['i']] in [((table.index(__l['data'][__l['i']]) + 1))]][0] for __l['i'] in [(__i)]][0] if __i is not __sentinel else __after())(next(__items, __sentinel)))())(iter(xrange(__l['_len'])), lambda: (lambda __items, __after, __sentinel: __y(lambda __this: lambda: (lambda __i: [[[__this() for __l['buf'] in [(setbit(__l['buf'], __l['i'], getbit(__l['data'], __l['j'])))]][0] for __l['j'] in [((((__l['i'] / 6) * 8) + (__l['i'] % 6)))]][0] for __l['i'] in [(__i)]][0] if __i is not __sentinel else __after())(next(__items, __sentinel)))())(iter(xrange((__l['_len'] * 6))), lambda: __l['buf'], []), []) for __l['_len'] in [(len(__l['data']))]][0] for __l['data'], __l['buf'] in [(data, buf)]][0])({}), 'encode')]][0] for __g['getbit'], getbit.__name__ in [(lambda p, pos: (lambda __l: [[[((__l['p'][__l['cpos']] >> __l['bpos']) & 1) for __l['bpos'] in [((__l['pos'] % 8))]][0] for __l['cpos'] in [((__l['pos'] / 8))]][0] for __l['p'], __l['pos'] in [(p, pos)]][0])({}), 'getbit')]][0] for __g['setbit'], setbit.__name__ in [(lambda p, pos, value: (lambda __l: [[[(lambda __target, __slice, __value: [(lambda __target, __slice, __value: [__l['p'] for __target[__slice] in [((lambda __old: (lambda __ret: __old | __value if __ret is NotImplemented else __ret)(getattr(__old, '__ior__', lambda other: NotImplemented)(__value)))(__target[__slice]))]][0])(__l['p'], __l['cpos'], (__l['value'] << __l['bpos'])) for __target[__slice] in [((lambda __old: (lambda __ret: __old & __value if __ret is NotImplemented else __ret)(getattr(__old, '__iand__', lambda other: NotImplemented)(__value)))(__target[__slice]))]][0])(__l['p'], __l['cpos'], (~(1 << __l['bpos']))) for __l['bpos'] in [((__l['pos'] % 8))]][0] for __l['cpos'] in [((__l['pos'] / 8))]][0] for __l['p'], __l['pos'], __l['value'] in [(p, pos, value)]][0])({}), 'setbit')]][0] for __g['table'] in [(string.printable.strip())]][0] for __g['string'] in [(__import__('string', __g, __g))]][0])(globals(), (lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))))
                enc = out.getvalue().encode('hex')
                out.close()
                if enc[:-2] in targets:
                    result[enc[:-2]].append(str)
                    print str, '->', enc

print(result)
```

中间那行 one-liner 有三处修改：

* 输入的 `open('flag.txt', 'r')` 改成了 `StringIO(str)`
* 输出的 `open('flag.enc', 'wb+')` 改成了 `out`
* 把关闭输出文件的 `fout.close()` 删了

之后不久意识到对于每一个 block 的每一个 byte 都是各自独立的有 2 种可能，不需要搜索那么多。于是人工操作了一下，获取了每一位的两种选择。

```
a2d378 d01660 cf6209 18e164 f48848 019609 5d4685 4f175c cf4010 1d
xdct   f{0n   e-l1   n3d_   Py7h   0n_1   s_@w   es0m   e233   }
         #^   ;a\$   ^&:o     *>   #^o$    oj    ;s#]   ;%&&
```

然后要做的就是人工拼出有意义的句子来。若干次尝试后拼出了 `xdctf{0ne-l1n3d_Py7h0n_1s_@wes0me233}` 简直不能更有道理。

# REVERSE400 （比赛时未完成）

先交作业，待补

但是该说的话还是要说。**<font color='brown'>出题人坑爹啊！</font>**

就差这题不然就 AK 所有 bin 了，然而搞了两三个小时还是没能运行起来，我服。

# REVERSE500

小白的杰作，不愧 Win 逆向/破解大神。

逆了半天，用了 OpenSSL 库，出现了一些类似 `_mm_storeu_si128` 的函数，其实就是处理大数用的，看习惯了就好。

主要是一个 DES 加密， key 没找到，但是可以直接拿到 key_schedule 那里的 16 轮 key ，所以其实没有太大的关系。 set 后的 key 如下

```cpp
unsigned char myks[8*16] =
{
   0xC4, 0x24, 0xFC, 0x00, 0x82, 0x48, 0x41, 0xCE, 0x00, 0xE0, 
   0x44, 0x04, 0xCE, 0x01, 0xC5, 0xC3, 0x70, 0x40, 0x88, 0x7C, 
   0x00, 0x82, 0xCE, 0x86, 0xB0, 0x24, 0x74, 0xA0, 0x8B, 0x00, 
   0x81, 0x80, 0x00, 0x40, 0x0C, 0x50, 0x46, 0xC4, 0xCA, 0x0B, 
   0xE4, 0x0C, 0xA8, 0x78, 0x8B, 0x80, 0x02, 0x44, 0x88, 0x50, 
   0x74, 0xC4, 0x4B, 0x44, 0x41, 0x08, 0x64, 0x08, 0x08, 0x70, 
   0x4C, 0x49, 0x42, 0xCF, 0x24, 0x0C, 0xD4, 0x64, 0x8D, 0x01, 
   0x0C, 0x07, 0x18, 0x50, 0x90, 0x98, 0x8E, 0xC4, 0x44, 0x8A, 
   0xB4, 0x48, 0xEC, 0xE0, 0x04, 0x09, 0xC2, 0x41, 0x28, 0x90, 
   0x84, 0xBC, 0x49, 0x80, 0x04, 0x03, 0xD0, 0x00, 0x68, 0x98, 
   0x02, 0xCB, 0x42, 0x8D, 0x84, 0xA0, 0x7C, 0x68, 0x41, 0x00, 
   0x87, 0x43, 0x50, 0x10, 0x40, 0x1C, 0x4D, 0xC2, 0x08, 0x0E, 
   0xF8, 0x00, 0x70, 0xEC, 0x88, 0x0B, 0x08, 0xC8
};
```

接着就是找一个 DES 加密的代码，把这部分 memcpy 过去就可以解密了。后面还有 16 字节循环左移 2 次以及与 E4 异或就不说了。