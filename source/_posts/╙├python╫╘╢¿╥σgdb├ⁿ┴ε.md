---
title: 用python来自定义gdb命令
categories: 尝试开发小工具
abbrlink: 26ba4673
---

`gdb` 是一款 `linux` 下常用的程序调试器，有时可能我们会根据自己的需求来尝试写一些自定义的 `gdb` 命令，而通过 `python` 语言来编写的话，是再好不过了，下面记录一下如何用 `python` 语言编写自己的 `gdb` 命令



有两种方法，第一种是直接在 `.gdbinit` 文件中来编写，如果只是自定义一个或很少的命令采用这种方法是可以的。（ `gdb` 启动时，会在当前用户的主目录寻找一个 `.gdbinit` 的文件，如果该文件存在的话将执行该文件的所有命令）

假设现在编写一个获取 `libc` 基地址的命令,代码如下

```py
python
def libc_cmd():
    recv_data = gdb.execute("vmmap",to_string=True)
    line = recv_data.split("\n")
    for i in line:
        if "libc" in i:
            list=i.split("    ")
            break
    print("\033[0;31;47mlibc base\033[0m    ",list[1])
end 

define libc
    python libc_cmd()
end
```

这个格式是先在一行写下 `python` ，接下来正常编写函数即可（ `gdb.execute` 函数可以在 `gdb` 内部执行命令，并且将命令的执行结果返回给调用者 ），最后以 `end` 结尾。然后再用 `define` 来定义这个命令的名称，然后下一行用 `python` 调用上面的函数，最后以 `end` 结尾即可。

把上面的代码复制到 `.gdbinit` 文件中，启动 `gdb` 即可正常使用 `libc` 命令



但如果想自定义的命令很多的话，全部把命令都写到 `.gdbinit` 会显得很臃肿，所以可以把自定义的命令单独都存放到一个 `py` 文件中。比如创建一个叫做 `command.py` 的文件，然后在 `.gdbinit` 的开始写入 `source /home/zikh/Desktop/command.py` 即可，然后开始在 `command.py` 文件中编写命令。

比如我这里编写一个获取 `libc` 基地址、堆地址和程序基地址的命令,代码如下

```py
def base_cmd():
    recv_data = gdb.execute("vmmap",to_string=True)
    lines = recv_data.split("\n")
    flag=0
    flag1=0
    flag2=0
    for line in lines:
        match=[]
        if "home" in line and flag1==0:
            flag1=1
            line=line.split()
            for element in line:
                match=re.findall("(0x\w+)",element)
                if match:
                    base_addr=match[0]
                    break
        if "heap" in line and flag==0:
            flag=1
            line=line.split()
            for element in line:
                match=re.findall("(0x\w+)",element)
                if match:
                    heap_addr=match[0]
                    break
        if "libc" in line and flag2==0:
            flag2=1
            line=line.split()     
            for element in line:
                match=re.findall("(0x\w+)",element)
                if match:
                    libc_addr=match[0]
                    break
            
    print("\033[0;31;47mbase address\033[0m\t\t\t",base_addr)
    if flag==0:
         print("\033[0;32;47mno heap\033[0m")
    else:
        print("\033[0;31;47mheap base\033[0m\t\t\t",heap_addr)
    print("\033[0;31;47mlibc base\033[0m\t\t\t",libc_addr)
```

这个格式比较简单，首先在 `py` 文件的开头导入 `gdb` 模块，然后正常定义函数即可，最后写上 `gdb.execute("define base\n\tpython base_cmd()\nend")` ，这句一定要有，这个可以理解为你输入一个命令，然后 `gdb` 要查找是否存在这个命令的定义，只有加上最后一句，才能够识别出来这个命令。（每写一个命令，都需要加上 `gdb.execute` 的命令声明）

实际运行情况如下：

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302041312961.png" alt="image-20230204131253466" style="zoom:50%;" />



如果要写带参数命令的话，可以参考以下格式

```py
def hex_cmd(arg0):
    print("decimal :\t",arg0)
    print("Hexadecimal\t",hex(arg0))
gdb.execute("define hex\n\tpython hex_cmd(int($arg0))\nend")
```

![image-20230204131502126](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302041315210.png)



本文只是简单记录一下如何用 `python` 来编写 `gdb` 命令，至于编写什么命令，还是要根据自己的实际需求来考虑。