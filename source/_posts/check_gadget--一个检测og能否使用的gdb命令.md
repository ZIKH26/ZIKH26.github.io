---
title: check_gadget--检测one_gadget能否使用的gdb命令
top: 36
tags:
  - python
  - 编程
  - 小工具
categories: 尝试开发小工具
abbrlink: bd34f701
---

## 前言

作为一个 `pwner` ，对 `one_gadget` 肯定不会陌生，如果在能劫持执行流的前提下， `one_gadget` 在劫持执行流的位置也恰巧能用，那就可以在一定程度上简化获取 `shell` 的操作，因为执行 `system("/bin/sh\x00")` 是需要控制参数的，有些情况下劫持执行流容易但可能控制参数还得再废些力气，此时成功打一发 `one_gadget` 可以说是方便又迅速。

但因为 `one_gadget` 条件的限制， `one_gadget` 成功的概率并不高，通常是一个一个试，或者调试到劫持执行流的位置观察一下寄存器和内存的情况进行判断。很早之前我就有这样一个想法，如果能用 `gdb` 调试到劫持的地址处，输入一个命令直接判断所有的 `one_gadget` 能否生效该有多方便。终于在几天前进行了动手实践，并将其写出来。

`check_gadget` 是一个 `gdb` 命令，该命令我是用 `python` 进行编写的 这篇 [文章](https://zikh26.github.io/posts/26ba4673.html) 记录了如何用 `python` 来自定义命令。

## 使用效果

此处控制了 `__free_hook` 

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302081628082.png" alt="image-20230208162838925" style="zoom:50%;" />

然后我们 `si` 进去，使用 `check_gadget` 命令，发现了一个可用的 `one_gadget`

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302081627797.png" alt="image-20230208162716225" style="zoom: 50%;" />



该命令是判断当前位置的 `one_gadget` 能否生效,所以这个命令在哪里都可以使用，但真正用到 `one_gadget` 的地方应该是我们控制执行流的地址。

即使在对 `32` 位的程序的判断中，该命令依然发挥出色

![image-20230208163319420](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302081633584.png)



## 缺点

这个命令本身是依赖 `one_gadget` 的返回条件进行判断的，但有时候 `one_gadget` 给出的条件虽然不满足但也能获取 `shell` （如下），而 `check_gadget` 命令无法检测出来这种情况。

下图是跳转到了一个 `one_gadget` 中，并没有满足 `one_gadget` 的条件，但依然可以获取 `shell`

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302081609202.png" alt="image-20230208160957660" style="zoom:50%;" />

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302081611903.png" alt="image-20230208161106805" style="zoom:50%;" />



## 设计思路

判断 `one_gadget` 的大致想法无非就两个，第一个是直接改变 `rip` 跑一遍 `one_gadget` （ **winmt** 师傅给我的提示是在当前要测试 `one_gadget` 的位置直接开多个子进程然后分别改变 `rip` 为不同的 `one_gadget` 以便测试所有的 `one_gadget` ），第二个思路就是我的这种，去将 `one_gadget` 的条件提取出来，访问寄存器和内存的值，来检查条件是否成立。

其实第一种思路我认为才是最优解，主要是 **winmt** 师傅给我说这种思路的时候我已经把命令写完了 QAQ ,因为第二种思路有上面所提到的缺陷。

下面说一下我这个命令的整体实现思路

1. 首先去获取 `one_gadget` 的所有信息，并进行逐一分组
2. 逐一判断每个 `one_gadget` 中的条件，利用正则表达式和 `if` 判断识别其特征，并调用相应的处理函数
3. 获取其关键信息，比如 `[rsp+0x40] == NULL` 这个条件,就需要先识别出来外面有一组 `[]` ，然后还需要提取出来 `rsp` `+` `0x40` 这三个关键信息，利用 `gdb` 模块中的一些函数来访问寄存器和内存的值，进行处理后来判断等式是否成立
4. 最后将一组命令的返回值都存储到一个列表中，只需要遍历返回值列表就知道哪组 `one_gadget` 可以使用或者不能使用



## 如何使用

首先需要确定你的 `gdb` 版本要比较新，至少我在老掉牙的 `ubuntu18.04` 中，`gdb` 版本为 `8.1.1` 是没法用的。我使用这个命令的环境是 `ubuntu 22.04` `gdb` 版本为 `12.0.90` 

然后创建一个 `command.py` 文件（名字随意，位置也随意），将下面的源代码复制进去

然后在 `.gdbinit` 文件中引入这个 `command.py` 文件即可（如下）

![image-20230208164134100](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202302081641185.png)

然后启动 `gdb` 调试，就可以使用该命令了

## 源代码

```py
import gdb
import subprocess
import sys
import re
def debug(a,b=""):
    print(a,b)

def get_libc_path():
    recv_data = gdb.execute("vmmap",to_string=True)
    lines = recv_data.split("\n")
    for line in lines:
      if 'libc' in line:  
        string=line.split()[-1]
        string = string[:-4]
        return string

def get_gadget_info(library):
    """
    该函数作用是获取当前 libc 的 one_gadget信息 -l2除外
    将每一组的 one_gadget 信息（地址和条件）放到一个元组里面，作为返回列表的一个元素

    参数：
    library(str): 当前程序所依赖的 libc 库路径

    返回值：
    gadgets_info(list): 列表中的元素是元组（装有一组 one_gadget 信息），后续进行条件判断时只需要对该列表进行遍历

    """
    result = subprocess.run(["one_gadget", library], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if (result.returncode != 0):
        print("Error: ", result.stderr.decode().strip())
        sys.exit(result.returncode)
    gadgets = result.stdout.decode().strip().split("\n\n")  # 将每个gadget的条件和信息都作为一个元素存储到列表中
    gadgets_info = []
    for gadget in gadgets:
        # 依次对每组元素进行单独的处理
        address_line, constraints_line = gadget.strip().split("\nconstraints:")
        address = address_line.strip().split()[0]
        constraints = constraints_line.strip().split('\n')
        gadgets_info.append((address, constraints))
    return gadgets_info

def get_register_value(register):
    return gdb.parse_and_eval('$'+register)

def get_address_permissions(address):
    recv_data = gdb.execute("vmmap "+str(address),to_string=True)
    if "There are no mappings for specified address or module" in recv_data:
        return False
    recv_data=recv_data.split('\n')[1]
    recv_data=recv_data.strip().split()
    permissions=recv_data[3]
    if 'w' in permissions:
        return True
    else:
        return False

def is_got_address_of_libc(string):
    """
    该函数用来判断目标地址是否为 got_address_of_libc(这个地址是 libc 中具有 rw 权限的首地址)

    参数：
    string(str):传入的为 one_gadget 需要判断是否为 got_address_of_libc的字符串
    例如：
    "ebx is the GOT address of libc"

    返回值:
    (bool):如果目标地址为 got_address_of_libc 那么返回 True ，反之返回 False
    """
    match=re.findall('(\w+) is the GOT address of libc',string)
    register_value=get_register_value(match[0])
    if int(register_value) < 0:
        register_value=register_value+(1<<32)
    recv_data = gdb.execute("vmmap",to_string=True)
    lines = recv_data.split("\n")
    for line in lines:
        if "rw" in line and "libc" in line:
            got_address_of_libc=line.split()[0][5:]
            if register_value == int(got_address_of_libc,16):
                return True
            else:
                return False

def is_writeable_check(string):
    '''
    这个函数的作用是来判断one_gadget中某个地址是否具有可写的权限

    0xebcf5 execve("/bin/sh", r10, rdx)
    constraints:
        address rbp-0x78 is writable
        [r10] == NULL || r10 == NULL
        [rdx] == NULL || rdx == NULL
    例如上面one_gadget的第一个条件  address rbp-0x78 is writable
    该函数将自己获取rbp-0x78 (如果是单个寄存器也可以进行判断 比如判断rsi当前地址是否具有写的权限) 的地址判断其是否为一个具有写权限的地址


    参数：
    string(str):该参数是one_gadget关于某个地址是否为可写的条件字符串  例如“address rbp-0x78 is writable”
 
    
    返回值：
    (bool): 判断目标地址是否具有可写权限  如果具有写权限则返回True  反之返回False
    '''
    result = re.findall(r'(\w+)\s*([+-])\s*(\w+)', string)
    if not result:
        result = re.findall(r'\b\w+\b', string)
        result = result[1]
    
    if len(result)==1:

        result=result[0]
        register=result[0]
        operator=result[1]
        operand=result[2]
        if operator == '-':
            calc_value=int(get_register_value(register))-int(operand,16)
            
        if operator == '+':
            calc_value=int(get_register_value(register))+int(operand,16)
        
        if calc_value == 0:
            return False
        return get_address_permissions(calc_value)
    if len(result)==3:
        register_value=get_register_value(result)
        if register_value==0:
            return False
        return get_address_permissions(register_value)


def get_register_value_ptr(register):
    """
    该函数作用获取寄存器所指向的值

    参数：
    register(str):被访问的寄存器名称

    返回值：
    (int):如果寄存器值为0或者寄存器的值为非法地址则返回-1  否则返回寄存器所指向的值
    """
    address = gdb.parse_and_eval("$" + register)
    if address == 0:
        return -1
    try:
        if register[0] == 'r':
            value = gdb.selected_inferior().read_memory(address, 8)
        if register[0] == 'e':
            value = gdb.selected_inferior().read_memory(address, 4)
    except gdb.MemoryError:
        return -1
    return  int.from_bytes(value, byteorder='little')

def condition_equal_A(condition_list):
    """rsp & 0xf == 0"""
    condition_list=condition_list[0]
    register,operator,operand=condition_list[0],condition_list[1],condition_list[2]
    if operator == '&':
        calc_value=int(get_register_value(register)) & int(operand,16)
        if calc_value == 0:
            return True
        else:
            return False

def condition_equal_B(condition_list):
    """rcx == NULL"""
    register=condition_list[0]
    calc_value=int(get_register_value(register))
    if calc_value == 0:
        return True
    else:
        return False

def condition_equal_C(condition_list):
    """(u16)[rbp] == NULL"""
    condition_list=condition_list[0]
    condition=condition_list[0]
    register=condition_list[1]
    if condition == "u16":
        calc_value=int(get_register_value_ptr(register))
        if calc_value == -1:
            return False
        calc_value=calc_value & 0xffff
        if calc_value == 0:
            return True
        else:
            return False



def condition_equal_D(condition_list):
    """[[rbp-0x70]] == NULL"""
    condition_list=re.findall(r"\[(\w+)([+-])(\w+)", condition_list[0])
    condition_list=condition_list[0]
    register,operator,operand=condition_list[0],condition_list[1],condition_list[2]
    if operator == '-':
        calc_value = int(get_register_value(register)) - int(operand,16)
        if calc_value == 0 - int(operand,16):
            return False
    if operator == '+':
        calc_value = int(get_register_value(register)) + int(operand,16)
        if calc_value == 0 + int(operand,16):
            return False
    if calc_value == 0:
        return False
    try:
        if register[0] == 'r':
            calc_value = gdb.selected_inferior().read_memory(calc_value, 8)
            calc_value = int.from_bytes(calc_value, byteorder='little')
        if register[1] == 'e':
            calc_value = gdb.selected_inferior().read_memory(calc_value, 4)
            calc_value = int.from_bytes(calc_value, byteorder='little')
    except gdb.MemoryError:
        return False
    if calc_value ==0:
        return False
    try:
        if register[0] == 'r':
            calc_value = gdb.selected_inferior().read_memory(calc_value, 8)
            calc_value=int.from_bytes(calc_value, byteorder='little')
        if register[1] == 'e':
            calc_value = gdb.selected_inferior().read_memory(calc_value, 4)
            calc_value=int.from_bytes(calc_value, byteorder='little')

    except gdb.MemoryError:
        return False
    if calc_value ==0:
        return True


def condition_equal_E(condition_list):
    """[r10] == NULL"""
    register=condition_list[0]
    calc_value =get_register_value_ptr(register)
    if calc_value == -1:
        return False
    if calc_value == 0:
        return True
    else:
        return False

def condition_equal_F(condition_list):
    """[esp+0x3c] == NULL"""
    condition_list=condition_list[0]
    register,operator,operand=condition_list[0],condition_list[1],condition_list[2]
    if operator == "+":
        calc_value=int(get_register_value(register) + int(operand,16))
    if operator == "-":
        calc_value=int(get_register_value(register) - int(operand,16))
    if calc_value == 0:
        return False
    try:
        if register[0] == 'r':
            calc_value = gdb.selected_inferior().read_memory(calc_value,8)
            calc_value = int.from_bytes(calc_value, byteorder='little')
        if register[0] == 'e':
            calc_value = gdb.selected_inferior().read_memory(calc_value,4)
            calc_value = int.from_bytes(calc_value, byteorder='little')
    except gdb.MemoryError:
        return False
    if calc_value == 0:
        return True
    else:
        return False

def equal_judgement(string):
    """
    该函数来处理 one_gadget 中的等式判断，我目前发现 one_gadget中的等式一共有六种类型（如下）

    "rsp & 0xf == 0",
    "rcx == NULL",
    "(u16)[rbp] == NULL",
    "[[rbp-0x70]] == NULL",
    "[r10] == NULL",
    "[esp+0x3c] == NULL"

    我通过正则表达式来识别出这六种情况，并将他们的关键信息匹配出来，再调用其对应的处理函数

    参数：
    string(str): 等式判断条件的字符串，例如 "[esp+0x34] == NULL"

    返回值：
    (bool): 如果等式成立则返回 True 不成立则返回 False

    """
    judgement=[]
    match=[]
    judgement = re.findall(r"(\w+)\s*(\&)\s*(\w+)", string)
    if judgement:
        return condition_equal_A(judgement)

    judgement = re.findall(r'\((\w+)\)\[(\w+)\]', string)
    if judgement:
        return condition_equal_C(judgement)



    judgement = re.findall(r'\[(.*?)\]', string)
    if judgement:
        if len(judgement[0].split('[')) > 1:
            return condition_equal_D(judgement)
        else:
            match = re.findall(r'(\w+)\s*([+-])\s*(.*)', judgement[0])
            if match:
                return condition_equal_F(match)


    judgement = re.findall(r"(\w+) == NULL", string)
    if judgement:
        return condition_equal_B(judgement)

    judgement = re.findall(r"\[(\w+)\] == NULL",string)
    if judgement:
        return condition_equal_E(judgement)



def check(constraints):
    """
    该函数作用是将传入的每一组 one_gadget 按照条件进行分类，然后调用更具体的函数进行处理
    目前我考虑了 one_gadget 的三种情况，分别是 is writeable 和 is got address of libc 以及对等式的判断
    如果使用 l2 参数的话，会有更多的情况，我认为它们概率极小并且条件过于繁多，所以目前没有对它们进行判断
    如果之后有条件没有考虑到需要添加的，或者想处理 l2 的 one_gadget 则在这里添加新的函数

    参数：
    constraints(list):存储的是一组的 one_gadget 所有信息

    返回值：
    (bool)如果当前这组 one_gadget 的所有条件都成立返回 True 反之有一个条件没有满足就返回 False

    """
    result = []
    result1 = []
    for constraint in constraints:
        if "is writable" in constraint:
            result.append(is_writeable_check(constraint))
            continue
        if "is the GOT address of libc" in constraint:
            result.append(is_got_address_of_libc(constraint))
            continue

        if "||" in constraint:
            for i in constraint.split('||'):
                if "== 0" in i or "== NULL" in i:
                    result1.append(equal_judgement(i))
            result.append(any(result1))
            result1 = []
            continue

        if "== 0" in constraint or "== NULL" in constraint:
            result.append(equal_judgement(constraint))
            continue

    print('one_gadget--->', result, constraints)
    return all(result)

def check_gadget_cmd():
    """
    该函数为 check_gadget 命令的主函数
    该命令实现了对当前位置概率略高的 one_gadget 能否生效做了判断

    命令使用方法：
    如果你想判断劫持执行流的这个位置是否有 one_gadget 能够生效，那么使用 gdb 调试到劫持执行流的地址处
    使用该命令就可以看到是否有 one_gadget 能用了
    目前只能判断概率较高的 one_gadget 能否使用，无法对 -l2 显示出来的 one_gadget 进行判断

    check_gadget_cmd() 函数无参且无返回值
    """

    libc_path=get_libc_path()    
    all_gadget_info=get_gadget_info(libc_path)
    for i in range(len(all_gadget_info)):
        gadget_address,gadget_constraints=all_gadget_info[i][0],all_gadget_info[i][1]
        result=check(gadget_constraints)
        if result:
            print("\n\033[1;31m"+"="*120+"\033[0m")
            print("\033[1;31m"+"Successful one_gadget"+"\033[0m","\033[1;31m")
            print("\033[1;31m"+"gadget_address------->"+"\033[0m\t\t","\033[1;32m"+gadget_address+"\033[0m","\033[1;31m")
            print("\033[1;31m"+"gadget_info---------->"+"\033[0m\t\t","\033[1;32m"+str(gadget_constraints)+"\033[0m")
            print("\033[1;31m"+"="*120+"\033[0m\n")

gdb.execute("define check_gadget\n\tpython check_gadget_cmd()\nend")
```

