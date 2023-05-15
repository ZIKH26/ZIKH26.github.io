---
title: IO学习--源码分析fclose函数
top: 22
tags: 源码调试&&分析
categories: 源码调试&&分析
abbrlink: b5738aac
---

之前分析的三个函数文章链接:

[IO学习--源码调试fopen函数](https://www.cnblogs.com/ZIKH26/articles/16567446.html)

[IO学习--源码分析fread函数](https://www.cnblogs.com/ZIKH26/articles/16575066.html)

[IO学习--源码分析fwrite函数](https://www.cnblogs.com/ZIKH26/articles/16578093.html)

这篇是IO函数源码分析四部曲中的最后一个fclose函数(并不是以后不分析了，说实话我感觉分析源码去看看我们平常使用的函数到底是怎么实现的，这个过程很有意思，因此以后有机会的话会再调试一些其他函数，花了四天分析了这四个函数，从最开始分析fopen函数源码的时候懵懵逼逼(那篇文章我基本是纯配合着动态调试才搞懂的整体逻辑)，到分析fread函数时对reserve area以及输入和输出缓冲区有了认识，再到基本是对着源码分析的fwrite函数(也是配合着动态调试，不过此时就是静态分析源码为主了)，最后到分析fclose函数源码时感觉的异常顺利和自然。真的是分析每个函数时都有不同的感受。


emmm，感慨有些多了，下面进入正文。



## 整体流程：

下面是fclose函数的整体流程，其他师傅如果分析的时候，可以参考下图。

<img src="https://s2.loli.net/2022/08/12/QDBqLfxORoUMbH8.png" alt="image-20220812201040809" style="zoom:50%;" />

## 源代码:

```c
#include<stdio.h>
int main(){
    char value[20];
    char new[30]="nice-day";
    FILE* fp=fopen("flag","wt+");
    fwrite(new,1,10,fp);
    fclose(fp);
    return 0;
}
```

**本文的源代码以及调试的程序所依赖的libc都为2.23版本的**

## 源码分析:

先看第一部分，经过一些寻常检查后，去调用了_IO_un_link 函数。在fopen函数中新创建了\_IO_FILE结构体，将其链入了\_IO\_list_all链表，而这个\_IO_un_link 函数则是将fopen函数中创建的\_IO_FILE结构体脱链（代码如下）

```c
int
_IO_new_fclose (_IO_FILE *fp)
{
  int status;

  CHECK_FILE(fp, EOF);

#if SHLIB_COMPAT (libc, GLIBC_2_0, GLIBC_2_1)
  /* We desperately try to help programs which are using streams in a
     strange way and mix old and new functions.  Detect old streams
     here.  */
  if (_IO_vtable_offset (fp) != 0)
    return _IO_old_fclose (fp);
#endif

  /* First unlink the stream.  */
  if (fp->_IO_file_flags & _IO_IS_FILEBUF)
    _IO_un_link ((struct _IO_FILE_plus *) fp);
	······
}
```

### 脱链部分

下面是_IO_un_link函数的源码，整体也很好分析。就是先去判断我们要脱链的这个\_IO_FILE结构体是否为链表的头指针。如果是的话执行`_IO_list_all = (struct _IO_FILE_plus *) _IO_list_all->file._chain`来脱链（代码如下）

```c
void
_IO_un_link (struct _IO_FILE_plus *fp)
{
  if (fp->file._flags & _IO_LINKED)
    {
      struct _IO_FILE **f;
	......
      if (_IO_list_all == NULL)
	;
      else if (fp == _IO_list_all)
	{
	  _IO_list_all = (struct _IO_FILE_plus *) _IO_list_all->file._chain;
	  ++_IO_list_all_stamp;
	}
	......
#endif
    }
}
```



如果要脱链的结构体不是链表头指针的话，就去遍历整个链表，去找到需要脱链的那个结构体，然后再脱链(代码如下)

```c
  else
for (f = &_IO_list_all->file._chain; *f; f = &(*f)->_chain)
  if (*f == (_IO_FILE *) fp)
    {
      *f = fp->file._chain;
      ++_IO_list_all_stamp;
      break;
    }
......
```



### 刷新输出缓冲区

脱链之后，调用了_IO_file_close_it函数

```c
  _IO_acquire_lock (fp);
  if (fp->_IO_file_flags & _IO_IS_FILEBUF)
    status = _IO_file_close_it (fp);
```



_IO_new_file_close_it函数中显示判断了一下文件是否有写的权限，如果有的话就调用\_IO_do_flush函数来刷新输出缓冲区。

```c
int
_IO_new_file_close_it (_IO_FILE *fp)
{
  int write_status;
  if (!_IO_file_is_open (fp))
    return EOF;

  if ((fp->_flags & _IO_NO_WRITES) == 0
      && (fp->_flags & _IO_CURRENTLY_PUTTING) != 0)
    write_status = _IO_do_flush (fp);
	·······
}
```



_IO_do_flush是宏定义，调用了\_IO_do_write函数

```c
# define _IO_do_flush(_f) \
  _IO_do_write(_f, (_f)->_IO_write_base,				      \
	       (_f)->_IO_write_ptr-(_f)->_IO_write_base)
```

\_IO_do_write函数对输出缓冲区的剩余部分（也就是宏定义中的(_f)->_IO_write_ptr-(_f)->_IO_write_base）进行了判断，如果输出缓冲区为0的话就直接返回，如果输出缓冲区中有数据的话就调用new_do_write函数。

```c
# define _IO_new_do_write _IO_do_write
_IO_new_do_write (_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
  return (to_do == 0
	  || (_IO_size_t) new_do_write (fp, data, to_do) == to_do) ? 0 : EOF;
}
```



new_do_write函数主要做了两件事，第一执行了系统调用write将输出缓冲区中的数据都读到了文件中。第二就是重置了_IO_write_ptr指针(这两个操作就意味着刷新了输出缓冲区)

```c
new_do_write (_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
	......
  count = _IO_SYSWRITE (fp, data, to_do);
  if (fp->_cur_column && count)
    fp->_cur_column = _IO_adjust_column (fp->_cur_column - 1, data, count) + 1;
  _IO_setg (fp, fp->_IO_buf_base, fp->_IO_buf_base, fp->_IO_buf_base);
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_buf_base;
  fp->_IO_write_end = (fp->_mode <= 0
		       && (fp->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
		       ? fp->_IO_buf_base : fp->_IO_buf_end);
  return count;
}
```

### 系统调用close

而后随着new_do_write函数的返回，程序再次返回到_IO_new_file_close_it中，此时调用了vtable中的\_IO_file_close函数(这个函数就不再说了，就是系统调用了一下close)，然后至此的话主要就剩申请的reserve area区域以及申请出来存放\_IO\_FILE结构体的内存还没有释放。

```c
  int close_status = ((fp->_flags2 & _IO_FLAGS2_NOCLOSE) == 0
		      ? _IO_SYSCLOSE (fp) : 0);
```

### 将reserve area释放掉

最后_IO_new_file_close_it函数还剩下面这部分代码，先删除reserve area然后将read和write相关指针全部置空，最后调用\_IO_un_link确保fopen函数申请的\_IO_FILE结构体已经从\_IO_list_all链表中脱链。

```c
  _IO_setb (fp, NULL, NULL, 0);//删除reserve area
  _IO_setg (fp, NULL, NULL, NULL);//这个宏是将read相关指针全部置空
  _IO_setp (fp, NULL, NULL);//这个宏是将write相关指针全部置空

  _IO_un_link ((struct _IO_FILE_plus *) fp);
  fp->_flags = _IO_MAGIC|CLOSED_FILEBUF_FLAGS;
  fp->_fileno = -1;
  fp->_offset = _IO_pos_BAD;

  return close_status ? close_status : write_status;
```



这个_IO_setb函数代码如下，发现是先将reserve area这片内存给释放掉，然后清空\_IO_buf_base和\_IO_buf_end两个指针，这也就意味着将reserve area删除掉了。

```c
void
_IO_setb (_IO_FILE *f, char *b, char *eb, int a)
{
  if (f->_IO_buf_base && !(f->_flags & _IO_USER_BUF))
    free (f->_IO_buf_base);
  f->_IO_buf_base = b;
  f->_IO_buf_end = eb;
  if (a)
    f->_flags &= ~_IO_USER_BUF;
  else
    f->_flags |= _IO_USER_BUF;
}
```

### 将结构体fp的内存释放掉

最后返回到_IO_new_fclose函数，先是调用了vtable中的\_IO_default_finish函数(这个函数中做的操作，之前已经做过了，其实就相当于啥都没干)，然后最后将结构体fp释放掉。至此fclose函数结束。

```c
  _IO_release_lock (fp);
  _IO_FINISH (fp);
	······
  if (fp != _IO_stdin && fp != _IO_stdout && fp != _IO_stderr)
    {
      fp->_IO_file_flags = 0;
      free(fp);
    }

  return status;
```



## 总结fclose函数调用流程：

先将\_IO_FILE结构体脱链，然后去看输出缓冲区中是否还有内容，如果有的话就系统调用write将输出缓冲区中的内容写入文件然后刷新输出缓冲区。接着系统调用close关闭文件，最后将申请的reserve area和装有\_IO\_FILE结构体的堆块给释放掉。

## 参考文章：

[FILE结构体及漏洞利用方法 | Hacked By Fish_o0O (fish-o0o.github.io)](https://fish-o0o.github.io/2019/12/29/FILE结构体及漏洞利用方法/#fclose)

[IO FILE之fclose详解 « 平凡路上 (ray-cp.github.io)](https://ray-cp.github.io/archivers/IO_FILE_fclose_analysis)