# CRYPT200

CBC Cipher，如果修改中间某一个 block 的 ciphertext 并不影响之后的 block 的解密，只会影响之前的 block。

由于 server 不接受带有 `;` 的签名请求，可以利用和 `;` 只有最后一 bit 不同的 `:`。签名完之后 bit reverse 对应的那一位就可以。

然而我懒得算是哪一位，所以实际上是让服务器签了「:admin=true」之后直接尝试了每个 byte 都最后一位取反。

```python
d = '684299166a05383e6eaa9139f8d8f5ff8cda560698b1987eb2092534397496b788cd54f160f52f8a156708257820468219100257fbdc09aacc4e606dbb20b449debf9da47199147dbf2ea70665fc32b083a18197bc033fec666b094bee33a79515a50c70af587fde032e4ed89c6d575b'
	
table = {i: chr(ord(i) ^ 1) for i in '0123456789'}
table['a'] = 'b'
table['b'] = 'a'
table['c'] = 'd'
table['d'] = 'c'
table['e'] = 'f'
table['f'] = 'e'
	
import telnetlib
tn = telnetlib.Telnet("133.130.52.128", 6666)
for i in range(len(d)):
    d2 = d[:i] + table[d[i]] + d[i+1:]
    tn.write(('parse:'+d2+'\n').encode('ascii'))
    print(tn.read_until(b"\n").decode('ascii'))
```

# CRYPT300

我们缺失 tempAgreedKey 的值，而观察发现我们没有 password，算不出storedKey。

可是 N 是一个质数，而且 N-1 % 4 == 0，可以构造一个 index，满足 index ^ 4k mod N == 1，即 4k == N-1，利用费马小定理，使得 storedKey = 1

再同时令 ckey = 1，于是 tempAgreedKey 失效， 从而可以轻松求出 finalKey。


# CRYPT500

记 X(P) 为取 P 点的 x 坐标值。

加密过程如下  

```
i0 = random_seed
i1 = X(i0*P)
out0 = X(i1*Q)

i2 = X(i1*P)
out1 = X(i2*Q)
```


存在 e，使得 ed % r == 1

```
设 X(i1*Q) = X(A)
因为 Q == d*P
i1*Q*e == e*d*i1*P
所以 Ae == i1*P
```

-

第一次生成生成的随机数是x轴方向的值，利用公式  

    y^2 = x^3 + ax + b (mod m) 

a, b, r, m 在 seccure 中使用的椭圆里是固定的，解出y的值，从而得到A点。  

好吧，到了本题最难的部分。。。  
解 `x^2 = a (mod p)` 是要用到奇怪的定理的，**直接开平方会跪(哭**，搜索`modular square root`，搞到计算的代码。

之后可以方便的得到 i2 从而预测下一个输出的值了
