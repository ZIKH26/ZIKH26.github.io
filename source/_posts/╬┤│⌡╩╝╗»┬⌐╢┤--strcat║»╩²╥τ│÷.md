---
title: 未初始化漏洞--strcat函数溢出
tags:
  - 未初始化漏洞
  - lab
categories: 私房菜
password: he13716649461
abbrlink: 5bd42122
---

### 总结：

通过这道题的学习与总结有:

1. 想让fgets函数读出eof可以采用io.shutdown()
2. fgets函数最大读取的size是第二个参数-1，当数据大小超过了第二个参数指定的大小时，fgets函数只会读取第二个参数-1的字节数，而在末尾补上‘\0’。如果没超过第二个参数指定的大小，在遇见回车后依然会在字符串的末尾添加一个0。这就意味着fgets函数读入的字符串末尾正常情况下一定是有‘\0’。**但是fgets函数读出了eof的话，可以让fgets函数直接结束并且不添加\x00**
3. 如果程序只有一次输入，并且此时你不想再写脚本的直接打的话，可以这么写`python -c "print('\xe6\x86\x04\x08')" | ./target` 因为如果要写地址的话，肯定需要脚本里的p32打包一下，上述这样写就不必打包也可以发送地址了。
4. 在往栈里输入大量的数据后，随着函数结束时栈帧销毁，但是栈里的数据依然存在，这就意味着下次开辟新的栈帧，并且不给一些变量初始化，变量的初始值就可能是上次所输入的数据，这就造成了未初始化漏洞。

### README：

> Why is it vulnerable?
> Read man page carefully!

### 保护策略：

![image-20221120094729865](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211200947984.png)

### 程序分析：

存在后门函数

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211200948076.png" alt="image-20221120094802020" style="zoom:50%;" />

首先第一个函数里可以进行大量字节的输入，并且不存在溢出(如下)

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211200948365.png" alt="image-20221120094857320" style="zoom:50%;" />

第二个函数里可以往两个变量里分别输入两次数据(不存在溢出)，然后进行一次复制(strcpy)和追加(strcat)。而dest距离返回地址还有0x209字节的距离，正常fgets函数把字符串末尾添加‘\0’之后，即使在dest之后再追加0x100的字节也无法溢出。

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211200951927.png" alt="image-20221120095122872" style="zoom:50%;" />



### 利用思路：

上面提到了正常的话fgets函数会把字符串末尾添加‘\0’，让复制和追加的操作时去声明字符串的截断。但是如果fgets函数读到了eof就会直接结束fgets函数，并且不会添加‘\0’。因此我们能让fgets函数读到eof的话就有溢出的机会了。

**值得一提的是，我们需要在hello这个函数让fgets去读满垃圾数据a，这样我们到concat函数刚刚开辟栈帧的时候s和src以及dest的初始值都是a。**

在concat函数里栈帧情况如下:

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211201003525.png" alt="image-20221120100300464" style="zoom:50%;" />

第一步操作是往src里输入数据，然后第二次往s里读数据时，我们直接让其读一个eof，从而什么也不写，也不会添加出来一个‘\0’。

第二步操作是src里的数据会复制给dest

第三步操作是将s里的数据追加到dest后面。

因为我们最后要让src里的数据(因为这里的内存可控)落在return address上，于是可以列一个方程，我们设往src里输入x个字节，那么则有`x+0x100+x=0x209+4+4`

图解如下：

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211201017082.png" alt="image-20221120101710995" style="zoom:50%;" />

但是考虑到这里是没有对齐的(ida上显示是0x409)，用gdb调试的时候发现s又或是src dest的地址都是0xf结尾。因此为了让最后的return address上落一个完整的地址，我们需要去垫一个字节，而垫的这个字节也是有讲究的，如果我们放到src里的第一个字符去垫的话，虽然可以在0x209之后的位置对齐，但是s追加过来后里面也有一段src里的数据，此时会再垫一个字符的数据从而到了return address又是没齐的。因此我们只能让这一个字节放到src的末尾，这样追加过来垫的字符就会落到return address的下一个内存单元(而真正对齐是在dest里垫的那个字符起的作用)。

![image-20221120102553495](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211201025257.png)



综上所述，考虑到垫的那一个字节，最后的方程应该这样`x+1+0x100+x=0x209+4+4`

解得x为0x88，而我们只需要让最后四字节为后门函数的地址即可，前面也填充成垃圾数据就行。

用shutdown关闭流，给最后一次的fgets函数一个eof(倒数第二次的fgets函数依然会给字符串src末尾添加‘\0’),避免出现‘\0’在追加的时候造成截断。

### EXP:

```py
from tools import *
context.log_level='debug'
p,e,libc=load("a")

debug(p,0x80488ef)
p.sendafter("What's your name?\n","a"*4095)
p.sendlineafter("Give me 1st input\n",b's'*0x84+p32(0x080486E6)+b'u')
p.shutdown()
p.interactive()
```

![image-20221120105438271](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211201054119.png)

### 题目附件：

链接: https://pan.baidu.com/s/1qjbHpDoskHvzqeR_0w4niQ?pwd=tsw6 提取码: tsw6 