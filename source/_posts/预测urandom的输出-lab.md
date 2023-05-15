---
title: 预测urandom的输出
top: 29
tags:
  - urandom
  - lab
categories: 私房菜
password: he13716649461
abbrlink: 81a94eee
---

### README:

> urandom is used as random source for many cryptographic library.
> However, you can guess the output of urandom.
>
>    Anything looks interesting?
>
>    $ ulimit -a
>    -t: cpu time (seconds)              unlimited
>    -f: file size (blocks)              unlimited
>    -d: data seg size (kbytes)          unlimited
>    -s: stack size (kbytes)             8192
>    -c: core file size (blocks)         0
>    -m: resident set size (kbytes)      unlimited
>    -u: processes                       46924
>    -n: file descriptors                1024
>    -l: locked-in-memory size (kbytes)  unlimited
>    -v: address space (kbytes)          unlimited
>    -x: file locks                      unlimited
>    -i: pending signals                 46924
>    -q: bytes in POSIX msg queues       819200
>    -e: max nice                        30
>    -r: max rt priority                 99
>    -N 15:                              unlimited
>
> 
>
> 本题考虑的是在拿到shell的情况下（也就是只在本地里搞），如何利用该程序来打印出来/flag(需要猜测到urandom的随机数)





### 保护策略：

![image-20221119112459785](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211191124911.png)

### 程序分析：

#### 主函数如下:

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211191129947.png" alt="image-20221119112937884" style="zoom:50%;" />

结合上图，光看函数名也能大概知道程序的逻辑，首先load_flag函数将flag读出来，然后fgets函数读入一些数据到内存里，接着获取随机数。如果输入的数据和随机数一样则打印出来flag。



#### load_flag函数如下：

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211191137894.png" alt="image-20221119113748849" style="zoom:50%;" />

这里就是从/flag里读出flag到内存



#### get_random函数如下：

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211191144184.png" alt="image-20221119114440129" style="zoom:50%;" />

程序打开了/dev/urandom这个文件，想从该文件中获取0x10字节的随机数。

这里需要注意的点是`sprintf((char *)(2 * i + a1), "%02X", (unsigned __int8)s[i]);` 这部分将数组s里的内容(原本是int类型的)，转成了char类型。



### 利用思路：

通过readme给的提示，可以发现ulimit -n 这个命令。该命令可以限制每个进程能打开的最大文件个数，例如ulimit -n 4限制了每个进程最多只能打开四个文件。

对于本题而言除去标准输入、标准输出、标准错误这三个文件，还有程序打开的一个/flag文件。当程序去打开第五个文件/dev/urandom的时候open函数会返回-1(打开失败)，这样read就什么都没读出来。而memset给了这片内存一个初始值0，接着用sprintf函数将本来的Int 0给转成了char类型的”00”存入了内存里。(注意，这里是将一个0变成了两个00，如下)

![image-20221119135240666](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211191352727.png)

因此这样最后与所谓的随机数做比较的时候，其实随机数就全部都是0了，我们在遇到了fgets函数的时候输入0x20个字符0，即可完成了检测的绕过。



**<u>注意：</u>**

我们需要新开一个shell，不然执行ulimit -n 4的时候会发生错误。

![image-20221119135656462](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211191356571.png)

### 题目附件

链接: https://pan.baidu.com/s/1w2zWtGcQMI4ULSNsoDQK-Q?pwd=dafx 提取码: dafx 