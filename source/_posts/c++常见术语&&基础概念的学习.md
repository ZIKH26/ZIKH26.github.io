---
title: C++ 常见术语&&基础概念的学习总结
top: 34
tags: C++
categories: 学习总结
abbrlink: 4320fd7a
---



简单入门了一下 C++ ，学习了几天，大概清楚了这些常用的术语和基础概念，虽然这对 `PWN` 中的 C++ 题目逆向帮助实在不大，但好奇心总是驱使着我尝试弄懂它们。感谢 `winmt` 师傅在我这部分的学习中，解惑我的一些奇奇怪怪的问题

### 从输出hello world开始

在 C++ 中可以用如下代码来输出`hello world`

```c++
#include<iostream>
int main()
{
    std::cout << "hello world" << std::endl;
    return 0;
}
```

`iostream` 这个头文件定义了输入输出流的相关类型和函数，这里为什么不是`#include<iostream.h>` 呢，因为在 C++ 11 标准后，**标准库的头文件**就不再使用 `.h` 作为后缀了，这样的好处是能够更好的区分标准库的头文件和用户自定义的头文件，比如我们自己写了一个名为 `iostream.h` 的头文件，就可以使用 `#include<iostream.h>` 来包含这个头文件，而不会和标准库的 `<iostream>` 头文件冲突。

此处输出 `hello world\n` 是 ` std::cout << "hello world"`这部分来实现的，而后面 `\n` 则是 `<< std ::endl`来实现的。 `std`是标准命名空间，用于区分不同符号名称的机制，在 C++ 标准库中，所有类型和函数都被定义到了标准命名空间（也就是 `std` ） 补充： 如果在 main函数之前写入 `using namespace std` 那么之后出现属于 `std` 中的对象就不必在前面加入 `std::`了，但通常我们不这么做，尽管这样看起来可能很简洁。

举个例子，全国有很多个张三，为了区分这些张三我们可以给每个张三都加一个前缀，比如河南的张三，北京的张三，这个前缀也就是不同的命名空间了。

<u>我们可以使用这个 `std::cout` **输出流对象**来输出内容</u>，这个输出流对象就是定义在 `std` 中的。而 `<<` 是一个流插入运算符，将数据输出到流中。 `std::cout << "hello world" ` 可以理解为将字符串 `”hello world"` 流向`std::cout` 这个输出流，从而进行了输出。 `<<` 明明是左移运算符，但这里为什么是流插入运算符呢？这是因为运算符重载，姑且可以理解这个重载就是分身，即同一个符号可以在不同情况下有不同的意思

从简单来说，可以把 `std::endl`看成一个 `\n` 添加到字符串的末尾，但实际上它的本质是一个函数指针，具体功能是在字符串中增加了一个 `\n` 并且还调用了flush来刷新缓冲区。那既然是函数指针，怎么调用的时候没有加 `()` 呢？这是因为这个函数指针被重载运算符 `<<` 所包装，成为了函数对象，在调用函数对象时不需要再加上圆括号了，因为调用运算符已经被重载了。



下面先来介绍 C++ 中的函数重载，这需要先从一个问题开始思考

### std::cout如何识别参数类型

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202301042011540.png" alt="image-20230104201132267" style="zoom:50%;" />

我这里输出了三种类型的数据，分别是 `char *` `int` `double`类型，并且都成功的进行了输出，如果是C语言的话，这里肯定是用 `printf` 函数中的不同格式化字符来匹配对应的数据，奇怪的是在 C++ 中，看起来一样的输出语句怎么可以匹配不同的参数类型呢？

这就要提到函数重载这个知识点了。

#### 函数重载

在 C++ 中，**函数重载允许在同一个作用域中定义多个同名函数，不过它们的参数列表需要不同(**参数类型，数量，或者顺序至少有一项不同)

代码示例如下：

```c++
#include<iostream>
void type(int data)
{
	std::cout << "This is data of type int" << std::endl; 
	return;
}

void type(const char *data)
{
	std::cout << "This is data of type const char *" << std::endl;
	return;

}

void type(double data)
{
	std::cout << "This is data of type double" << std::endl;
	return;
}
int main()
{
	type("hello world");
    type(123);
	type(0.06);
	return 0;
}

```

运行结果：

![image-20230104205318468](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202301042053567.png)

可以发现我定义了三个 `type` 函数，他们的函数名一样，但是参数的类型不一样，而在main函数中调用了三次 `type` 函数，根据传入的参数不同调用相匹配的那个函数来执行。**实现原理是编译器在编译代码时把所有函数的签名都记录下来，然后在运行时根据函数提供的参数来选择某个函数**。

#### 运算符重载

但实际上对于 `<<` 还涉及到了一个重载运算符，简单来说重载运算符指的是我们可以赋予原本运算符新的意义，**重载运算符本质上是**带有特殊名称的**函数**，重载运算符函数(也就是函数名)由关键字 `operator` 和要重载的运算符构成。

举个例子，我现在创建了一个Box类，然后实例化对象是一个 `box` ，具有长，宽，高的属性，我现在希望将+重载，使其可以让两个Box对象的每个属性相加。

代码如下：

```c++
#include<iostream>
class Box
{
	public:
		int length;
		int width;
		int height;
		Box operator+(const Box& box2)
		{
			Box box3;
			box3.length=this->length + box2.length;
			box3.width=this->width + box2.width;
			box3.height=this->height + box2.height;
			return box3;
		}
};
int main()
{
	Box box1,box2,box3;
	box1.length=1;
	box1.width=2;
	box1.height=3;

	box2.length=10;
	box2.width=20;
	box2.height=30;

	box3=box1+box2;
	std::cout << "The length of the box3 is " <<box3.length << std::endl;
	std::cout << "The width of the box3 is " << box3.width <<std::endl;
	std::cout << "The height of the box3 is " << box3.height << std::endl;
	return 0;
}
```

运行结果

![image-20230104222911178](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202301042229281.png)

在 `Box` 这个类中，我们用 `operator` 指定了重载的运算符为 `+` ，这二者合成了重载运算符函数，函数名前的依然是函数类型，而后面的括号里装的依然是参数，看起来和正常的函数定义一样。

但需要注意的以下几点

1. 重载运算符函数的参数，在上面的例子中， `+` 两侧的 `box1` 和`box2` 是两个参数传入给`operator+` 这个重载运算符函数，但是实际上定义的地方，你可以看见我写代码中只有一个参数 `box2` ，实际上第一个对象已经被当做参数进行了传递，该对象的属性需要用 `this` 运算符进行访问(关于 `this` 指针，后面会提到)。
2. 观察上面的代码，发现在重载运算符函数的参数中，出现了 `const` 和 `&` ，这是因为程序为了保证正确性和效率采取的措施。关于 `const` ,它是**用来保护函数内部不被意外修改的对象**，例如你重载了加法运算符，那么两个参数都应该是常量，因为它们在函数内部不应该被修改，所以加上 `const` 也就是说你的函数不会修改类内的任何成员变量，那么就可以将函数声明为 `const` 类型。关于**`&` ,它是用来避免拷贝对象的开销的**，提到这里就不得不说**在 C++ 中如果函数的参数是一个对象，那么调用函数时会进行对象的拷贝**，而如果加上 `&`引用的话，就可以避免拷贝对象造成的开销，提升了程序的效率。但是不加 `&` 的话，也有一些优点，比如拷贝对象的话，函数内部对对象的修改不会影响原来的对象
3. **重载运算符函数必须是类的成员函数**，也就是你想重载一个运算符，就必须要定义一个类，然后在类的内部定义重载运算符函数。

因此根据上面的内容，就可以分析出来std::cout <<实际上是调用了运算符重载函数 `cout.operator << ()` ，根据传入的不同参数类型，调用相匹配的重载函数。



### 类与对象

笔记本电脑和台式电脑都属于计算机，计算机有的基本属性，笔记本和台式肯定都有。假设现在有一个任务是要记录计算机的基础配置，并且在之后一段时间还需要记录台式电脑的配置和笔记本电脑的配置，我们可以怎么做，写一个结构体，来记录计算机的配置？然后等到台式就再写一个结构体？如果需要写某个牌子的笔记本电脑的信息就再写N个？(实际上这是个很糟糕的例子,hhh)

不不不，你可能已经猜到我想用什么了，没错，就是用类与对象的概念来实现上述这个问题。

现在抛开之后的任务，只记录计算机的基本信息，并且将其实例化成一个个的对象(你可以将这个实例化的过程理解为将一个抽象的计算机配置突然实例成某个具体品牌的计算机)

举个例子，计算机都具有硬盘，内存，CPU，显卡，IO设备等等。

那么我们可以这么定义一个计算机类，代码如下

此处的各个属性都是我随便写的，理解意思就好，不是真的要介绍各个硬件的信息。

```c++
#include<iostream>
class Computer
{
	public:
		int Hard_disk;
		int Memory;
		const char *CPU;
		const char *Video_card;
		const char *IO;
};
int main()
{
	Computer Lenovo;
	Lenovo.Hard_disk=128;
	Lenovo.Memory=8;
	Lenovo.CPU="xxx-1";
	Lenovo.Video_card="ttt-1";
	Lenovo.IO="uuu-1";
	std::cout << "The Hard disk is " << Lenovo.Hard_disk << "G" << std::endl;
	std::cout << "The Memory is " << Lenovo.Memory << "G" << std::endl;
	std::cout << "The CPU is " << Lenovo.CPU << std::endl;
	std::cout << "The Video_card is " << Lenovo.Video_card << std::endl;
	std::cout << "The IO is " << Lenovo.IO << std::endl;
	return 0;
}

```

运行结果

![image-20230105001321846](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202301050013916.png)

上述代码定义了一个 `Computer` 类，然后实例化的对象为 `Lenovo` ，对其所有属性都进行了初始化。语法很简单，此处代码主要讲两个点。第一就是实例化后的对象在哪里？第二个就是类中有一个 `public` ，这个是干啥的？



#### 类实例化后的对象存放到哪里？

实例化后的对象有两种存储位置，分别是栈和堆。

上面的代码中，因为函数内的局部变量是位于栈上，而 `Lenovo` 是main函数的局部变量，所以 `Lenovo` 这个对象位于栈上。

如果主动使用了 `new` 函数来分配内存给实例化后的对象，那么该对象的内存就会位于堆上，将上面的代码做如下修改，即可让其位于堆上，不再使用该对象的时候需要手动调用 `delete` 进行销毁，避免内存泄露的问题

```c++
Computer *Lenovo = new Computer;
Lenovo->Hard_disk = 128;
Lenovo->Memory = 8;
Lenovo->CPU = "xxx-1";
Lenovo->Video_card = "ttt-1";
Lenovo->IO = "uuu-1";
```



#### 类访问修饰符&&数据封装

关键字  `public` ` private` `protected` 成为访问修饰符，它们标记的区域内可以设置成员变量的访问属性，比如上面的例子里，在main函数中我对 `Lenovo` 对象中的 `Memory` 成员进行了赋值为 `8` 的操作，之所以能够这样直接赋值是因为我将其定义为了公有（` public` ）成员，这就意味这我用 `.` 可以直接访问公有成员，但如果我将成员设置为私有（ `private` ）成员就无法这样直接访问了，正如同下面的代码一样

```c++
#include<iostream>
class Box
{
	private:
		int length;
};
int main()
{
	Box box;
	box.length=1;
	return 0;
}
```

![image-20230105161601838](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202301051616143.png)

可以看到编译是给了一个 `error` 提示说 `Box::length` 这个成员是私有的，所以这里无法赋值。



因此我们可以将代码改成下面这样,通过公有的成员函数来访问私有的成员（**所谓的私有成员指的是只能在类的内部被访问，而无法在外部进行访问**），而公有的成员函数（在类内声明或定义的函数）自然是能够被外部访问。

```c++
#include<iostream>
class Box
{
	private:
		int length;
	public:
		void set_length(int len)
		{
			length=len;
			std::cout << length << std::endl;
		}
};
int main()
{
	Box box;
	box.set_length(60);
	return 0;
}
```

关于 `protected` 修饰符与 `private` 非常类似，不同之处在于 `protected` 成员在派生类中是可以访问的。

你可能会问这个类访问修饰符出现的意义是什么？其实这就体现了 C++ 中的**数据封装**，我们可以将数据成员定义为私有，然后通过公有的成员函数作为接口来访问和操作私有成员，而无需知道具体实现的细节，这样就可以将实现细节与使用者隔离开，提高代码的可读性和可维护性。



### 类构造函数&&析构函数

假设我现在想创建一个对象，就输出一个 `created successly` 或者是进行初始化的一些操作，总之就是在创建一个对象的时候自动调用一个函数来实现一些功能。那就需要用到构造函数了，它会在每次创建新对象的时候就被调用。

构造函数的名称要与类名一致，并且没有类型（也就是没有返回值类型）

代码如下：

```c++
#include<iostream>
class Box
{
	private:
		int length;
	public:
		Box(void)
		{
			std::cout << "created successly!" << std::endl;
		}
		void set_length(int len)
		{
			length=len;
		}
		void add_length(int len)
		{
			length+=len;
		}
		void output_length(void)
		{
			std::cout << length << std:: endl;
		}

};
int main()
{
	Box *p = new Box();
	p->set_length(20);
	p->add_length(4);
	p->output_length();
	return 0;
}
```

输出结果

![image-20230105170056041](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202301051700123.png)

当然了在上面的例子中也可以进行初始化的工作，比如想将每次创建的对象中的 `length` 都设置为100，那只需要对构造函数进行传参对 `length` 进行赋值即可。



假设我创建了一个对象，在释放前进行了一些打开文件和申请内存的操作，那么我希望在删除这个对象的时候，可以关闭之前打开的文件或者释放申请之前的内存，那这就要用到析构函数了，它会在删除对象的时候自动被触发，名字是在类名前面加了一个 `~` ，跟构造函数的利用类似，下面举例在每次删除对象的时候打印 `destruction succeeded!` 

代码如下

```c++
#include<iostream>
class Box
{
	private:
		int length;
	public:
		Box(void)
		{
			std::cout << "created successly!" << std::endl;
		}
		~Box(void)
		{
			std::cout << "destruction succeeded!" << std::endl;
		}
		void set_length(int len)
		{
			length=len;
		}
		void add_length(int len)
		{
			length+=len;
		}
		void output_length(void)
		{
			std::cout << length << std:: endl;
		}

};
int main()
{
	Box *p = new Box();
	p->set_length(20);
	p->add_length(4);
	p->output_length();
	delete p;
	return 0;
}
```

运行结果

![image-20230105175301371](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202301051753557.png)



### 继承

继承指的是类与类之间的一种关系，假设有一个类 `A` ，然后它具有 `100` 个属性，但是我现在希望去定义一个类 `B` ，它在原本 `A` 有的 `100` 个属性前提下再创建 `20` 个属性，怎么做呢？确实可以选择之间将类 `A` 的代码 `copy` 到  `B` 中，但这样显的代码过于臃肿。所以我们可以用继承， `B` 继承 `A` 所有的属性，在此基础上再增加自己新的属性。

下面的代码展示了继承

```c++
#include<iostream>
class Box
{
	public:
		int length;
		int width;
		void set_length(int len)
		{
			length=len;
		}
		void add_length(int len)
		{
			length+=len;
		}
		void output_length(void)
		{
			std::cout << "length is " <<length << std::endl;
		}

};
class BBox : public Box
{
	public:
		int hight;
		void set_hight(int hei)
		{
			hight=hei;
		}
		void output_hight()
		{
			std::cout << "hight is " << hight << std::endl;
		}
};
int main()
{
	BBox box;
	box.set_length(20);
	box.set_hight(30);
	box.output_length();
	box.output_hight();
	return 0;
}

```

运行结果

![image-20230105193512645](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202301051935782.png)

由此可以看出来， `BBox` 这个类（派生类）继承了 `BOX` 类（基类），然后实例化出来的 `box` 对象既拥有原本基类的属性和方法，又拥有新增加的属性和方法。

需要补充的是在定义这个继承类的时候执行了 `class BBox : public Box` 再次使用了 `public`  这个访问修饰符，标明了继承类型。我们通常使用 `public` 继承，很少使用 `protected` 和 `private` 继承。使用不同类型继承，遵循以下几个规则：

1. **公有继承（public）：**当一个类派生自**公有**基类时，基类的**公有**成员也是派生类的**公有**成员，基类的**保护**成员也是派生类的**保护**成员，基类的**私有**成员不能直接被派生类访问，但是可以通过调用基类的**公有**和**保护**成员来访问。
2. **保护继承（protected）：** 当一个类派生自**保护**基类时，基类的**公有**和**保护**成员将成为派生类的**保护**成员。
3. **私有继承（private）：**当一个类派生自**私有**基类时，基类的**公有**和**保护**成员将成为派生类的**私有**成员。

上述规则转自：[C++ 继承 | 菜鸟教程 (runoob.com)](https://www.runoob.com/cplusplus/cpp-inheritance.html)



#### 多继承

就是类 `A` 可以同时继承 `B` 和 `C` 中的所有属性和方法，被称之为多继承。字面意思就是其作用，指一个类可以同时继承多个类的特征。

代码如下

```c++
#include<iostream>
class Box
{
	public:
		int length;
		int width;
		void set_length(int len)
		{
			length=len;
		}
		void add_length(int len)
		{
			length+=len;
		}
		void output_length(void)
		{
			std::cout << "length is " <<length << std::endl;
		}

};
class obj
{
	public:
		const char *color;
		void set_color(const char *col)
		{
			color=col;
		}
		void output_color()
		{
			std::cout << "color is " << color << std::endl;
		}
};
class BBox : public Box,public obj
{
	public:
		int hight;
		void set_hight(int hei)
		{
			hight=hei;
		}
		void output_hight()
		{
			std::cout << "hight is " << hight << std::endl;
		}
};
int main()
{
	BBox box;
	box.set_length(20);
	box.set_hight(30);
	box.output_length();
	box.output_hight();
	box.set_color("blue");
	box.output_color();
	return 0;
}
```

运行结果

![image-20230105200054215](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202301052000403.png)

可以看到 `BBox` 同时继承了 `Box` 和 `obj` 两个类的属性和方法，并且成功调用。这个多继承理解起来应该蛮简单的，**值得一提的是构造函数和析构函数不可以被继承**。



### 多态

多态是针对具体某个函数而言的，称之为多态性。在 C++ 中，一个函数要想具有多态性，必须同时满足以下两个条件：

1. 函数是从基类继承而来的，即基类中定义了这个函数，而派生类中又重新定义了这个函数。
2. 函数为动态绑定，这意味着函数的调用版本是在运行时确定的。在 C++ 中，可以使用虚函数来实现动态绑定。

第一个条件很好理解，就是我在基类 `A` 中定义了函数 `print` ，在它的派生类 `B` 中我对继承来的函数 `print` 进行了重写。

#### 静态绑定

将第二个条件就要提到 C++ 里的静态绑定和动态绑定的概念，静态绑定指的是在编译时就已经可以确定调用的函数版本（也就是确定调用的这个函数属于哪个类中的），这样即使派生类重写了函数，也不会体现出多态的效果，静态绑定可以使程序执行的更快，因为编译器可以在编译时确定函数的调用版本，而不需要在运行时调用。

如下代码， `print` 函数就为静态绑定

```c++
#include<iostream>
class B {
public:
    void print() { std::cout << "B::print" << std::endl; }
};

class A : public B {
public:
    void print() { std::cout << "A::print" << std::endl; }
};

int main() {
    B b;
    b.print();  // 静态绑定：B::print
    return 0;
}

```

#### 动态绑定

动态绑定是函数在调用时确定的具体版本（也就是哪个类中的函数），而非在编译时就确定了。

这是通过指针来调用函数实现的，比如我定义了一个基类 `A` 的指针为 `a` ，然后申请了它的派生类 `B` 大小的空间，将指针 `a` 指向了申请 `B` 类的对象地址。这个写成代码应该为 `A* a = new B() ` 。这里其实是我实例化了一个 `B` 类的对象，然后让指针 `a` 指向了这个对象的地址，这里之所以 `B` 后面带 `()`，是表示调用了 `B` 类的构造函数来创建 `B` 类对象。

而上述的情况就会导致，我可以给 `a` 指针任意赋值其他对象，因为 `a` 的指针类型为基类,所以我可以随意指向它的派生类，这就导致了我在编译的时候不能确定这个指针到底调用的哪个类中的方法。因此只能等到运行时确定，这就是所谓的动态绑定。

动态绑定的代码如下：

```c++
#include <iostream>

class A {
public:
    virtual void print() { std::cout << "A::print" << std::endl; }
};

class B : public A {
public:
    void print() { std::cout << "B::print" << std::endl; }
};

class C : public A {
public:
    void print() { std::cout << "C::print" << std::endl; }
};

int main() {
    A* a = new B();
    a->print();  // 调用的是 B::print()
    a = new C();
    a->print();  // 调用的是 C::print()
    return 0;
}
```

运行结果

![](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202301052225623.png)

**注意**：动态绑定的前提是基类中的函数被 `virtual` 关键词声明为虚函数才行，如果上述代码将基类中的 `virtual` 关键词去掉，那么输出结果就为两个 `A::print` 。因为编译器在处理的时候发现没有 `virtual` 就不会认为这是虚函数，**从而你使用基类的指针即使调用派生类中的函数依然调用的是基类中的函数，依然不会去考虑指针所指向的对象的实际类型**。



#### 虚函数&&虚函数表&&虚表指针

上面的那段文字中出现了虚函数这个陌生的概念，这里来讲一下动态绑定是如何被实现的。

接下来将提到三个概念，分别是虚函数，虚函数表和虚表指针。

简单解释一下，虚函数表其实就是一个**函数指针数组**（就是存放虚函数指针的一个数组），虚表指针则是指向虚函数表的一个**指针**，虚函数则是被 `virtual` 关键字声明的函数。

我们考虑一下这个动态绑定，它是一个基类的指针，可以去指向派生类实例后的对象，从而去调用派生类中的函数，并且指向不同的派生类的对象，可以调用同一个函数名但作用不同的函数（这个就是函数的多态性）。具体实现过程如下：

首先在基类A中定义了虚函数，那么这个类A就会拥有一个虚函数表，这个表中会存放基类A中所有的虚函数地址（不是虚函数的话，就不会将地址放到这个虚函数表中）

方便理解，画了个示意图

<img src="https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202301052306391.png" alt="image-20230105230622294" style="zoom:50%;" />

然后基类A实例化了一个对象，名为 `a` ，那么这个对象内部将包含一个虚表指针 `*__vptr`（这是编译器进行添加的），这个虚表指针就指向了自己这个类的虚函数表。

下面两个图分别是有虚函数和没有虚函数的类，可以看见他们的大小差了八个字节，刚好是64位程序里一个指针的大小，而这个指针就是编译器自动添加的虚表指针。

![image-20230105231306685](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202301052313274.png)



**基类中如果存在虚函数表的话，那么派生类则会将虚函数表也继承下来**，如果<u>派生类中没有对基类中的函数进行重新定义，那么虚函数中的函数指针不变，如果派生类对某个基类中的函数进行了重新定义，那么虚函数表中的函数指针将被更新为新的虚函数地址。同样的，派生类实例化后的对象也具有一个虚表指针，来指向派生类自己的虚函数表</u>。

以下面的代码为例，具体说明一下动态绑定的实现过程

```c++
#include <iostream>

class A {
public:
    virtual void print() { std::cout << "A::print" << std::endl; }
};

class B : public A {
public:
    void print() { std::cout << "B::print" << std::endl; }
};

class C : public A {
public:
    void print() { std::cout << "C::print" << std::endl; }
};

int main() {
    A* a = new B();
    a->print();  // 调用的是 B::print()
    return 0;
}
```

首先， `A* a = new B()` 定义了一个类A的指针a（事实上接下来要说的和指针类型没有关系，即使这里是类B指针也完全可以），然后将B类实例化为对象的地址赋值给了 `a`，所以当前 `a` 可以通过对象中自己存储的一个 `vptr` 指针来访问到类B的虚函数表，从而去类B的虚函数中找到 `print`的函数指针并调用，最终输出 `B::print` 。

**注意：虽然上述操作和 `a` 指针的类型无关，但是不可以定义为类C的指针（也就是说这个指针的类型要么是基类，要么是当前这个派生类），因为这样会得到一个编译错误。**



### 纯虚函数&&抽象类

纯虚函数是一种**虚函数**，它没有实际实现，**只有对函数的声明**。纯虚函数是通过在**函数声明的末尾添加一个 `=0` 来定义的**，**纯虚函数的目的就是要让基类的派生类去实现它**。

纯虚函数的定义如下

```c++
class Animal {
public:
    virtual void makeSound() = 0;
};
```

如果单纯的看纯虚函数，感觉这样做似乎没有什么意义。但事实上纯虚函数是为抽象类来服务的，如果一个类中包含了纯虚函数，那么这个类就是抽象类，**抽象类无法被创建对象，它的作用是为其他类提供一个基类**，假如有一个抽象类 `Animal` ，它定义了一个纯虚函数 `makeSound` ，之后我们可以创建比如 `cat` `dog` 这样的派生类，这样我去每个具体的派生类里面来实现 `makeSound`。你可以将抽象类理解为某些事物必有的一些特性，而具体的特性又会根据事物的不同而要重新定义，就比如刚刚提到的 `makeSound` ，在动物中一定都可以发出声音，但是每个动物发出的声音都不一样，因此我们先定义一个抽象类，至于每个动物发出的声音在具体的派生类中再去实现。

下面写一个抽象类与纯虚函数的代码

```c++
#include<iostream>
class Animal{
	public:
		virtual void makeSound() = 0;
};
class dog:public Animal
{
	public:
		void makeSound()
		{
			std::cout << "Wang" << std::endl;
		}
};
class cat:public Animal
{
	public:
		void makeSound()
		{
			std::cout << "miao" << std::endl;
		}
};
int main()
{
	Animal *p=new dog();
	p->makeSound();
	p=new cat();
	p->makeSound();
	return 0;
}
```

运行结果

![image-20230106162845748](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202301061628111.png)



### this指针

`this` 指针是类中成员函数的一个隐含参数，每个对象都可以通过 `this` 指针来访问自己的地址。

这个主要一个用处是可以区分类中的成员和函数局部变量，假如有如下代码

```c++
#include<iostream>
class A{
	public:
		int x;
		void set_x(int x)
		{
			x=x;
		}

		void output_x()
		{
			std::cout << "x is " << x << std::endl;
		}	
};
int main()
{
	A a;
	a.set_x(60);
	a.output_x();
	return 0;
}
```

正常来说，我们的本意是希望赋值给类中的成员 `x` ，但是在 `set_x` 函数中x进行赋值的时候，程序认为是赋值给函数中的局部变量 `x` 。所以去输出成员变量 `x` 的时候就发生了错误，如下运行结果

![image-20230106174845468](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202301061748632.png)

因此这里我们想强调赋值的是给类中的成员变量 `x`，就可以写成 `this->x`，此时的运行结果就会正常（如下）

![image-20230106175223292](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202301061752361.png)

**注意：只有在类的成员函数内部才能使用 `this` ，在其他函数中使用 `this` 是无效的**



### 友元函数

上面提到，如果某个成员变量用 `private` 进行了修饰，那么就得通过类中定义的公有函数来进行访问，但是有这样一种特殊的函数，**它在类中声明**，具体的定义在类的外面，最关键的是它拥有访问私有（ `pritvate` ）成员和受保护（`protected`）成员的特性。这样的函数就叫做**友元函数**

代码如下

```c++
#include<iostream>
class A{
	private:
		int price;
	public:
		void output_price()
		{
			std::cout << "price is " << price << std::endl;
		}
		friend void set_price(A& a,int n);
};
void set_price(A& a,int n)
{
	a.price=n;
}
int main()
{
	A a;
	set_price(a,30);//不需要声明a对象调用了set_price函数
	a.output_price();
	return 0;
}
```

运行结果

![image-20230106193519661](https://blog-1311372141.cos.ap-nanjing.myqcloud.com/images/202301061935757.png)

可以看见上面的代码中，我并没有在定义的部分写成 `A::set_price(A& a,int n)`，但依然可以访问到类 `A` 中的属性。但要注意的是， `set_price` 函数传参的时候，要提供对象 `a` 的引用，如果这里仅仅是传递进去了对象 `a` 那么修改的只是 `a` 的副本，并没有对原本的实例造成任何改变（函数的参数如果直接传递的是对象，那么仅仅是拷贝一个副本进去）。

关于友元函数有几点需要注意：

1. 友元函数不是类的成员函数，因此不能使用类的示例成员访问符 `.` 或成员指针运算符 `->` 来调用友元函数，同样因为这个原因，友元函数也没有 `this` 指针。
2. 友元函数的声明只能出现在类的定义中，而不能出现在类的实现中。
3. 友元函数可以访问类的所有成员，包括私有成员和公有成员以及受保护成员，因此友元函数不受类的访问控制的限制。





### 参考文章

https://blog.csdn.net/hengyunabc/article/details/7773449

[(44条消息) C++学习笔记一：cout如何判断输入数据类型_marvie_xie的博客-CSDN博客_c++判断输入数据类型](https://blog.csdn.net/marvie_xie/article/details/79042654)

[C++ 重载运算符和重载函数 | 菜鸟教程 (runoob.com)](https://www.runoob.com/cplusplus/cpp-overloading.html)
