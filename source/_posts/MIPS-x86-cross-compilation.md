---
title: 基础MIPS交叉编译和运行环境搭建
date: 2019-02-16 23:21:40
tags: basic
---

嗯。。随便水一篇博客吧

<!--more-->

# Install

MIPS 交叉编译环境安装：

```bash
sudo apt-get install linux-libc-dev-mips-cross 
sudo apt-get install libc6-mips-cross libc6-dev-mips-cross 
sudo apt-get install binutils-mips-linux-gnu gcc-mips-linux-gnu 
sudo apt-get install g++-mips-linux-gnu
```

# Compile

编译程序的例子：

```bash
mips-linux-gnu-gcc hello.c -o hello-mips
```

如果要运行的话可以考虑用 qemu-mips，我直接通过 apt 安装的 qemu，可以考虑编译一个新版本的 qemu。

# Execute by user

运行例子：

```bash
qemu-mips -L /usr/mips-linux-gnu/ hello-mips
```

`-L` 意味着

```
-L path       QEMU_LD_PREFIX    set the elf interpreter prefix to 'path'
```

指向相应的库，如果不指的话默认会从 `/lib/` 里面找，自然是无法找到的。我们之前安装交叉编译环境的时候安装了相应的库。

我们可以用下面的命令安装 MIPSEL 和 ARMEL 的库：

```bash
sudo apt install libc6-mipsel-cross
sudo apt install libc6-armel-cross
```

想要查询相关的库情况，可以输入这个命令：

```bash
apt search libc6-ARCH
```

# Execute by Qemu-System

(TODO)

# Debug

(TODO)

# About

[qemu缺ld.so的解决方法](https://veritas501.space/2018/07/26/qemu%E7%BC%BAld.so%E7%9A%84%E8%A7%A3%E5%86%B3%E6%96%B9%E6%B3%95/)

[[原创]IoT安全：调试环境搭建教程(MIPS篇)](https://bbs.pediy.com/thread-229583.htm)