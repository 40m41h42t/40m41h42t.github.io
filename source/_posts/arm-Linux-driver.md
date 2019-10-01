---
title: Linix驱动开发-萌新入门
date: 2019-02-20 15:41:34
tags: 
---

上学期选了一门神奇的电工电子实习基础课，其实验要求做一些有趣的项目。我看他的选题里面有一个 Linux 驱动开发，询问老师后我将用树莓派做实验。在完成任务之前，我们应该首先了解一下怎样搭建起基础的环境并写一个最简单的驱动程序。

<!--more-->

首先看一下树莓派操作系统的版本：

```bash
pi@raspberrypi:~ $ uname -a
Linux raspberrypi 4.14.79-v7+ #1159 SMP Sun Nov 4 17:50:20 GMT 2018 armv7l GNU/Linux
```

接下来下载交叉编译工具链（610.86 MB）

```bash
git clone git://github.com/raspberrypi/tools.git RpiTools
```

加入到 zshrc 中：

```bash
export PATH=~/Linux-Driver/RpiTools/arm-bcm2708/gcc-linaro-arm-linux-gnueabihf-raspbian-x64/bin
```

下载内核代码（1.98 GB）

```bash
git clone git://github.com/raspberrypi/linux.git RpiLinux
```

由于我的内核版本号是 4.14，因此切换 branch 到 4.14。

```bash
git checkout -t origin/rpi-4.14.y
```

按照[官网的教程](https://github.com/raspberrypi/documentation/blob/master/linux/kernel/building.md)进行编译：

```bash
cd linux
KERNEL=kernel7
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- bcm2709_defconfig
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- zImage modules dtbs
```

按照教程，一个简单的 hello world 版本的驱动可以写成下面的形式：

```c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>

MODULE_LICENSE("Dual BSD/GPL");
 
static int hello_init(void)
{
    printk(KERN_ALERT"Hello, world\n");
    return 0;
}
 
static void hello_exit(void)
{
    printk(KERN_ALERT"Goodbye, cruel world\n");
}
 
module_init(hello_init);
module_exit(hello_exit);
```

有关驱动程序代码的细节待补充。

仿写的 Makefile 文件：

```makefile
ifneq ($(KERNELRELEASE),)

obj-m := hello.o

else
	
KDIR := ~/Linux-Driver/RpiLinux
CROSS_COMPILE := arm-linux-gnueabihf-
all:
	make -C $(KDIR) M=$(PWD) modules ARCH=arm CROSS_COMPILE=$(CROSS_COMPILE)

clean:
	rm -f *.ko *.o *.mod.o *.mod.c *.symvers  modul*

endif
```

然后 make 编译之。将得到的 hello.ko 文件通过 scp 的方式传入树莓派中：

```bash
scp hello.ko pi@IP:~/dr
```

安装驱动：

```bash
sudo insmod hello.ko
```

通过 `dmesg` 命令查看内核输出：

```
[12126.457870] hello: loading out-of-tree module taints kernel.
[12126.458318] Hello, world
```

通过 `lsmod` 命令查看已有的内核模块。

通过 `rmmod hello` 卸载模块。可以看到输出：

```
[12569.394852] Goodbye, cruel world
```

这样我们就搭好了一个简单的交叉编译环境并写了一个简单的驱动。相关的操作我们也了解了一点。

# 参考资料

[树莓派linux驱动学习之hello world](https://blog.csdn.net/hcx25909/article/details/16860055)

[简单内核模块编写](https://www.dreamxu.com/books/c/linux/kernel-modules.html)

[树莓派3b内核和驱动的交叉编译](https://blog.csdn.net/u014695839/article/details/83720145)

[linux下编写hello驱动](https://blog.csdn.net/u014695839/article/details/83513710)

