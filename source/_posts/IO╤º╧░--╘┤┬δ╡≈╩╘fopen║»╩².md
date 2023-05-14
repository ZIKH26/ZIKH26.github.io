---
title: IO学习--源码调试fopen函数
tags: 源码调试&&分析
categories: 源码调试&&分析
abbrlink: ce09b1a
---

## 写在前面：

这篇文章是学习IO，进行源码分析四部曲中的第一篇，本篇主要就是**源码调试fopen函数**，并**没有单独对fopen函数的源码专门阅读分析**(之后的三篇基本上是源码分析)。如果要看fopen函数源码分析的话可以去看下文末的参考文章(师傅们写的都非常好诶)

这里我写了一篇关于初学者应该如何去读glibc源码的文章(希望可以帮助到刚刚入门的师傅们) [here](https://www.cnblogs.com/ZIKH26/articles/16582817.html)

## 前置知识

### _IO_FILE_plus结构体

```c
struct _IO_FILE_plus
{
  _IO_FILE file;
  const struct _IO_jump_t *vtable;
};
```

_IO_FILE_plus结构包含了\_IO_FILE结构体和 _IO_jump_t 结构体。

### _IO_FILE结构体

先说_IO_FILE结构体，该结构体就是标准IO库中用来描述文件的结构，在程序执行fopen函数时会创建该结构，并分配在堆中。

```c
struct _IO_FILE {
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */
#define _IO_file_flags _flags

  /* The following pointers correspond to the C++ streambuf protocol. */
  /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
  char* _IO_read_ptr;	/* Current read pointer */ 
  char* _IO_read_end;	/* End of get area. */
  char* _IO_read_base;	/* Start of putback+get area. */
  char* _IO_write_base;	/* Start of put area. */
  char* _IO_write_ptr;	/* Current put pointer. */
  char* _IO_write_end;	/* End of put area. */
  char* _IO_buf_base;	/* Start of reserve area. */
  char* _IO_buf_end;	/* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
#if 0
  int _blksize;
#else
  int _flags2;
#endif
  _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */

#define __HAVE_COLUMN /* temporary */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  /*  char* _save_gptr;  char* _save_egptr; */

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
```



## 调试fopen函数

调试之前的话，可以先看一下整体调用的流程，这样在调试的时候有个参考。另外就是调试的时候，要附加一下源码，关于gdb源码调试环境搭建可以参考我的[这篇文章](https://www.cnblogs.com/ZIKH26/articles/16150232.html)。

源代码

```c
#include<stdio.h>
int main(){
    FILE*fp=fopen("/home/hacker/Desktop/flag","r");
    fclose(fp);
    return 0;
}
```
**本文的源代码以及调试的程序所依赖的libc都为2.23版本的**
### 整体调用流程图

![image-20221007215412769](../img/image-20221007215412769.png)



### 调试

刚进入fopen函数的时候，就发现要调用__fopen_internal 函数了（如下图）。然后这里要注意的就是为啥执行的是fopen函数，但一进去就在\_IO_new_fopen函数中呢? 

原因是这里的宏定义 

```c
# define _IO_new_fopen fopen
```

![image-20221007220100510](../img/image-20221007220100510.png)

#### 给新创建的结构体申请一片内存空间

然后进入\_\_fopen_internal函数后，第一个调用的函数就是malloc来分配了一块locked\_FILE结构体大小的内存(如下图)，这个结构体包含了\_IO_FILE_plus、\_IO\_lock_t、_IO_wide_data这三个结构体。由于我们并不调试malloc函数，因此这里我们n过去

![image-20221007215434310](../img/image-20221007215434310.png)

#### 对FILE结构体初始化

malloc函数执行后，再往下就是_IO_no_init函数(如下图)，我们si进去看看这个函数做了什么

![image-20221007215454681](../img/image-20221007215454681.png)



可以发现调用了这个_IO_old_init函数，我们再次si进去

![image-20221007215520022](../img/image-20221007215520022.png)



发现是在对_IO_FILE_plus结构体进行初始化(如下)

![image-20221007215534954](../img/image-20221007215534954.png)



此时的_IO_FILE_plus结构体中的成员变量如下

![image-20221007215548563](../img/image-20221007215548563.png)



等到_IO_old_init函数执行后，出来继续执行\_IO_no_init函数，发现在对\_IO_wide_data结构体中的成员变量进行初始化，因此得出结论\_IO_no_init函数就是在进行着结构体的初始化工作

![image-20221007215605749](../img/image-20221007215605749.png)

#### 将\_IO_FILE_plus结构体链入_IO_list_all链表

等到\_IO_no_init函数出来后，就调用了_IO_file_init函数

![image-20221007215627273](../img/image-20221007215627273.png)



可以发现其实_IO_file_init函数主要是对\_IO_link_in函数的一个封装，而\_IO_link_in函数听名字就感觉是进行的链入操作,si进去看看

![image-20221007215640763](../img/image-20221007215640763.png)



这部分主要的代码如下

```c
fp->file._chain = (_IO_FILE *) _IO_list_all;
_IO_list_all = fp;
```

很明显这里就把fp(也就是结构体_IO_FILE_plus)给链入了链表中

![image-20221007215652819](../img/image-20221007215652819.png)



下面两个图片分别是将fp链入前后的情况

![image-20221007215705984](../img/image-20221007215705984.png)

![image-20221007215718666](../img/image-20221007215718666.png)



链入前后整个链表对应的情况如下：

![image-20221007215732445](../img/image-20221007215732445.png)



#### 执行open系统调用来打开文件

当_IO_file_init 函数执行完后，就来到了fopen函数的核心部分，将要调用\_IO_file_fopen函数(如下)

![image-20221007215749092](../img/image-20221007215749092.png)



进入\_IO_file_fopen函数后，发现先fopen函数的mode参数(文件的打开方式)进行了处理

![image-20221007215801237](../img/image-20221007215801237.png)



而后调用了_IO_file_open函数(这里就不再放图片说明了)，然后si进去，该函数又调用了open64函数，再次si进去执行了open系统调用

![image-20221007215812651](../img/image-20221007215812651.png)



然后这里将sys_open执行后的文件描述符赋值给fp->fileno(如下图)

![image-20221007215826367](../img/image-20221007215826367.png)



至此fopen函数的整个流程可以说是接近尾声了，最后再次调用了\_IO_link_in函数，确保fp已经链入了链表中(如果发现链入后，那么_IO_link_in函数将直接退出)。(如下图)

![image-20221007215838094](../img/image-20221007215838094.png)

![image-20221007215850109](../img/image-20221007215850109.png)

至此fopen函数结束，此时的FILE结构体如下

![image-20221007215905013](../img/image-20221007215905013.png)

### 总结fopen调用流程

将整个fopen函数的调用流程概括一下为:

> 1、给新创建的结构体申请一片内存空间
>
> 2、对FILE结构体初始化
>
> 3、将\_IO_FILE_plus结构体链入_IO_list_all链表
>
> 4、执行open系统调用来打开文件

## 参考文章：

[IO_FILE相关利用 | Alex's blog~ (la13x.github.io)](https://la13x.github.io/2021/07/27/IO-FILE/#基础知识)

[_IO_FILE结构体利用 - 知世の小屋 (nightrainy.github.io)](https://nightrainy.github.io/2019/08/03/IO-FILE结构体利用/)

[IO FILE之fopen详解 - 安全客，安全资讯平台 (anquanke.com)](https://www.anquanke.com/post/id/177910)

[(41条消息) 好好说话之IO_FILE利用（1）：利用_IO_2_1_stdout泄露libc_hollk的博客-CSDN博客_stdout泄露libc](https://blog.csdn.net/qq_41202237/article/details/113845320)

[pwn——IO_FILE学习（一） - hawkJW - 博客园 (cnblogs.com)](https://www.cnblogs.com/hawkJW/p/13546416.html)