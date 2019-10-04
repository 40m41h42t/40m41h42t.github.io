---
title: angr 入门（二）
date: 2019-09-30 16:58:25
tags: [angr, re]
---

这里更进一步地学习了 angr 的一些知识点。

<!--more-->

## ais3_crackme

这道题为了讲解 angr 如何获取命令行输入。

模仿 <https://xz.aliyun.com/t/4039#toc-1> 分析。

载入这道题

``` c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax

  if ( argc == 2 )
  {
    if ( (unsigned int)verify((__int64)argv[1]) )
      puts("Correct! that is the secret key!");
    else
      puts("I'm sorry, that's the wrong secret key!");
    result = 0;
  }
  else
  {
    puts("You need to enter the secret key!");
    result = -1;
  }
  return result;
}
```

我们需要用到 `claripy` 模块构造输入。`claripy` 是一个和 `z3` 类似的符号求解引擎。

`claripy` 关于变量的定义在 `claripy.ast.bv.BV` 中。

通常使用 `claripy.BVS()` 创建位向量符号，使用 `claripy.BVV()` 创建位向量值。

我们按照它提供的 solve.py 跑一跑。

``` ipython
In [5]: argv1 = claripy.BVS("argv1", 100*8)

In [6]: argv1
Out[6]: <BV800 argv1_40_800>

```

这里 `argv1` 是符号名称，`100*8` 是长度以 bit 为单位，由于我们不能确定输入长度，因此我们先输入entry 100 个字节。

然后它开始初始化状态：

``` ipython
In [6]: initial_state = project.factory.entry_state(args=["./crackme1", argv1])

In [7]: initial_state
Out[7]: <SimState @ 0x400410>
```

根据文档，`args=["./crackme1", argv1]` 会用作程序的 `argv` 列表。

接下来它用已经创建的初始状态创建路径组，也就是初始化 `simulation_manager`：

``` ipython
In [8]: sm = project.factory.simulation_manager(initial_state)

In [9]: sm
Out[9]: <SimulationManager with 1 active>
```

设置 `find`。实际上，在输入 `sm.explore(find=0x400602)` 这条指令后，程序就会象征性地（symbolically）执行程序，直到达到我们设置的期望值。而在这条指令下，程序会打印出正确的信息。

``` ipython
In [10]: sm.explore(find=0x400602)
WARNING | 2019-09-16 17:58:17,094 | angr.state_plugins.symbolic_memory | The program is accessing memory or registers with an unspecified value. This could indicate unwanted behavior.
WARNING | 2019-09-16 17:58:17,094 | angr.state_plugins.symbolic_memory | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING | 2019-09-16 17:58:17,094 | angr.state_plugins.symbolic_memory | 1) setting a value to the initial state
WARNING | 2019-09-16 17:58:17,094 | angr.state_plugins.symbolic_memory | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING | 2019-09-16 17:58:17,094 | angr.state_plugins.symbolic_memory | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY_REGISTERS}, to suppress these messages.
WARNING | 2019-09-16 17:58:17,095 | angr.state_plugins.symbolic_memory | Filling register r12 with 8 unconstrained bytes referenced from 0x400625 (__libc_csu_init+0x5 in ais3_crackme (0x400625))
WARNING | 2019-09-16 17:58:17,096 | angr.state_plugins.symbolic_memory | Filling register r13 with 8 unconstrained bytes referenced from 0x400638 (__libc_csu_init+0x18 in ais3_crackme (0x400638))
WARNING | 2019-09-16 17:58:17,098 | angr.state_plugins.symbolic_memory | Filling register r14 with 8 unconstrained bytes referenced from 0x40063d (__libc_csu_init+0x1d in ais3_crackme (0x40063d))
WARNING | 2019-09-16 17:58:17,099 | angr.state_plugins.symbolic_memory | Filling register r15 with 8 unconstrained bytes referenced from 0x400642 (__libc_csu_init+0x22 in ais3_crackme (0x400642))
WARNING | 2019-09-16 17:58:17,100 | angr.state_plugins.symbolic_memory | Filling register rbx with 8 unconstrained bytes referenced from 0x400647 (__libc_csu_init+0x27 in ais3_crackme (0x400647))
WARNING | 2019-09-16 17:58:17,160 | angr.state_plugins.symbolic_memory | Filling register cc_ndep with 8 unconstrained bytes referenced from 0x4004b0 (register_tm_clones+0x20 in ais3_crackme (0x4004b0))
Out[10]: <SimulationManager with 9 active, 41 deadended, 1 found>
```

其实也可以设置 `avoid`：（待补充）

不过现在我们不能像之前那样通过 `posix.dump(0)` 来打印出结果，因为我们是通过命令行传参。

我们来看看 `SimState` 的属性：

``` code
- 参数
  - project (angr.Project) -
  - arch (archinfo.Arch) -
- 变量
  - regs - 为了方便查看状态寄存器，其中每个寄存器都是一个属性。
  - mem - 为了查看状态的内存，是一个 `angr.state_plugins.view.SimMemView`。
  - registers - 状态的寄存器文件为平坦的内存区域。
  - memory - 状态的内存为平坦的内存区域。
  - solver - 此状态的符号求解器（symbolic solver）和变量管理器（variable manager）。
  - inspect - 断点管理器，是一个 `angr.state_plugins.inspect.SimInspector`。
  - log - 有关该状态的历史信息。
  - scratch - 有关当前执行步骤的信息。
  - posix - MISNOMER：有关操作系统或环境模型的信息。
  - fs - 模拟文件系统的当前状态。
  - libc - 有关我们正在模拟的标准库的信息。
  - cgc - 有关 cgc 环境的信息。
  - uc_manager - 控制不受约束的符号执行(under-constrained symbolic execution)。
  - unicorn(str) - unicorn 引擎控制。
```

`claripy` 是一个类似 `z3` 的符号引擎，说实话 `z3` 我也不是很了解，但是看样子它们都有共同的 `solver` 属性。

> 同样的我们查看 `found.solver` 都有哪些属性和方法。 （这里为什么要看这个不是很懂 FIXME:）

为了将 `found` 中保存的符号执行的结果打印出来，我们可以使用 `eval` 方法：

``` code
### `eval(e, **kwargs)`

计算一个表达式以获得任何可能的结果。可以使用 `cast_to` 参数指定所需的输出类型。`extra_constraints` 可用于指定返回值必须满足的其他约束。

- 参数
  - `e` - 用来获得结果的表达式。
  - `kwargs` - 任何附加的参数都会被向下传递给 `eval_upto`
- 异常处理
  - `SimUnsatError` - 如果找不到满足给定约束的结果会抛出这个异常。
- 返回值
  - 貌似是 `eval_upto` 的返回值。
```

我们也可以用 `cast_to` 对所需要的值进行转换。

``` ipython
In [14]: solution = found.solver.eval(argv1, cast_to=bytes)

In [15]: solution

Out[15]: b'ais3{I_tak3_g00d_n0t3s}\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
```

这里就是要求符号求解器（symbolic solver）以字符串形式获取到达状态下的 `argv1` 的值。

## csaw_wyvern

这道题的目的是学会使用 angr 正常输入并设置约束条件。

模仿 <https://xz.aliyun.com/t/4039#toc-2> 分析。

实际上它最多可以输入 256 位，但是实际上 flag 没有那么长。输入的字符串会被转换为 string 类型，传入函数 `start_quest(std::string *a1)` 中。在该函数中我们发现它会向一个 vector 中 push 28 次 `secret_xxx`，因此猜测 flag 的长度为 28,。我们构造长度为 28 的 BVS 变量，并在结尾加上 `\n`。

他的构造方法如下：

``` python
flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(28)]
```

解释是：”我们构造几个**符号**的值，一旦有状态就可以添加约束。“

接下来添加换行符：

``` python
flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])
```

构造后的 flag 长度是 232bit - 29 字节。

``` ipython
In [20]: flag.size()
Out[20]: 232
```

接下来的模块会构造初始程序状态以进行分析。

这是一个 C++ 程序，而 `angr` 只实现了 C 的库。

> 为了深入 C++ 标准库中，在设置 `state` 时需要使用 `full_init_state` 方法，并且设置 `unicorn` 引擎。

``` python
st = p.factory.full_init_state(
    args=['./wyvern'],
    add_options=angr.options.unicorn,
    stdin=flag,
)
```

接下来我们添加一些约束条件：

``` python
for k in flag_chars:
    st.solver.add(k != 0)
    st.solver.add(k != 10)
```

它的目的是使前 28 个字符（flag）既不是 `null` 也不是换行符。

接下来它构建了一个 `SimulationManager` 进行符号执行：

``` python
sm = p.factory.simulation_manager(st)
sm.run()
```

它会一直运行，直到没有可以运行的结果为止。

结果会得到 29 个 `deadend` 分支：

``` text
WARNING | 2019-09-27 15:39:15,369 | angr.state_plugins.symbolic_memory | The program is accessing memory or registers with an unspecified value. This could indicate unwanted behavior.
WARNING | 2019-09-27 15:39:15,369 | angr.state_plugins.symbolic_memory | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING | 2019-09-27 15:39:15,369 | angr.state_plugins.symbolic_memory | 1) setting a value to the initial state
WARNING | 2019-09-27 15:39:15,369 | angr.state_plugins.symbolic_memory | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING | 2019-09-27 15:39:15,369 | angr.state_plugins.symbolic_memory | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY_REGISTERS}, to suppress these messages.
WARNING | 2019-09-27 15:39:15,370 | angr.state_plugins.symbolic_memory | Filling memory at 0x7fffffffffeff00 with 8 unconstrained bytes referenced from 0x408b610 (strlen+0x0 in libc.so.6 (0x8b610))
WARNING | 2019-09-27 15:39:15,813 | angr.state_plugins.symbolic_memory | Filling memory at 0xc0012b38 with 29 unconstrained bytes referenced from 0x7000000 (memcpy+0x0 in extern-address space (0x0))
WARNING | 2019-09-27 15:39:18,836 | angr.state_plugins.symbolic_memory | Filling memory at 0xc0012c6a with 29 unconstrained bytes referenced from 0x7000000 (memcpy+0x0 in extern-address space (0x0))
WARNING | 2019-09-27 15:42:14,049 | angr.state_plugins.symbolic_memory | Filling memory at 0xc00133f4 with 28 unconstrained bytes referenced from 0x7000000 (memcpy+0x0 in extern-address space (0x0))
WARNING | 2019-09-27 15:42:14,327 | angr.state_plugins.heap.heap_base | Allocation request of 155 bytes exceeded maximum of 128 bytes; allocating 155 bytes
WARNING | 2019-09-27 15:42:14,565 | angr.state_plugins.symbolic_memory | Filling memory at 0xc001344f with 27 unconstrained bytes referenced from 0x7000000 (memcpy+0x0 in extern-address space (0x0))
WARNING | 2019-09-27 15:42:14,994 | angr.state_plugins.symbolic_memory | Filling memory at 0xc00134a9 with 65 unconstrained bytes referenced from 0x7000000 (memcpy+0x0 in extern-address space (0x0))
Out[8]: <SimulationManager with 29 deadended>
```

实际上 angr 有三种运行方法：`explore`、`run`、`step`。阅读文档我们可以发现 `explore`、`run` 是比较常用的。`run` 最后会返回 `deadend` 的状态，一般我们需要的状态在最后一个；`explore` 根据 `find` 和 `avoid` 进行基本块的执行，最后会返回 `found` 和 `avoid` 状态。

我们可以访问最后一块获取数据：

``` python
sm.deadended[28].posix.dumps(1)
```

也可以遍历以输出：

``` python
out = b''
for pp in sm.deadended:
    out = pp.posix.dumps(1)
    if b'flag{' in out:
        return next(filter(lambda s: b'flag{' in s, out.split()))
```

## ASIS CTF Finals 2015 - fake

通过这道题学习对结果进行条件约束的技巧。

这道题目会将输入的字符串转换为数字：

``` c
  v3 = 0LL;
  if ( argc > 1 )
    v3 = strtol(argv[1], 0LL, 10);
```

经过一系列的处理计算后，输出由 `v5`、`v6`、`v7`、`v8`、`v9` 所组成的字符串，也就是 flag。

``` c
  v3 = 0LL;
  if ( argc > 1 )
    v3 = strtol(argv[1], 0LL, 10);
  v5 = 0x3CC6C7B7 * v3;
  v6 = 0x981DDEC9AB2D9LL
     * ((v3 >> 19)
      - 2837
      * (((signed __int64)((unsigned __int128)(6658253765061184651LL * (signed __int128)(v3 >> 19)) >> 64) >> 10)
       - (v3 >> 63)))
     * ((v3 >> 19)
      - 35
      * (((signed __int64)((unsigned __int128)(1054099661354831521LL * (signed __int128)(v3 >> 19)) >> 64) >> 1)
       - (v3 >> 63)))
     * ((v3 >> 19)
      - 33
      * (((signed __int64)((unsigned __int128)(1117984489315730401LL * (signed __int128)(v3 >> 19)) >> 64) >> 1)
       - (v3 >> 63)));
  v7 = ((v3 >> 19)
      - 9643
      * (((signed __int64)((unsigned __int128)(1958878557656183849LL * (signed __int128)(v3 >> 19)) >> 64) >> 10)
       - (v3 >> 63)))
     * 5785690976857702LL
     * ((v3 >> 19)
      - 167
      * (((signed __int64)((unsigned __int128)(7069410902499468883LL * (signed __int128)(v3 >> 19)) >> 64) >> 6)
       - (v3 >> 63)));
  v8 = ((v3 >> 19)
      - 257
      * (((signed __int64)((unsigned __int128)(9187483429707480961LL * (signed __int128)(v3 >> 19)) >> 64) >> 7)
       - (v3 >> 63)))
     * 668176625215826LL
     * ((v3 >> 19)
      - 55
      * (((signed __int64)((unsigned __int128)(5366325548715505925LL * (signed __int128)(v3 >> 19)) >> 64) >> 4)
       - (v3 >> 63)));
  v9 = ((v3 >> 19)
      - 48271
      * (((signed __int64)((unsigned __int128)(1565284823722614477LL * (signed __int128)(v3 >> 19)) >> 64) >> 12)
       - (v3 >> 63)))
     * 2503371776094LL
     * ((v3 >> 19)
      - 23
      * (((signed __int64)((v3 >> 19) + ((unsigned __int128)(-5614226457215950491LL * (signed __int128)(v3 >> 19)) >> 64)) >> 4)
       - (v3 >> 63)));
  puts((const char *)&v5);
```

> 我们跳过前面的命令行输入部分，直接从 `0x4004AC` 开始，因为 `strtol` 用于将字符串转化为整数，而我们通过 `claripy.BVS` 构造的符号变量是一个 bit 向量，无法使用 `strtol` 转换。当然如果你不闲麻烦，可以将 `strtol` nop 掉，然后使用之前所说的命令行传参的方法。

初始化状态设置：

``` python
state = p.factory.blank_state(addr=0x4004AC)
inp = state.solver.BVS('inp', 8*8)
state.regs.rax = inp

simgr= p.factory.simulation_manager(state)
simgr.explore(find=0x400684)
found = simgr.found[0]
```

在这里，初始化设置是在 `strtol` 之后进行的，接下来创建了一个名称为 `inp`，长度为 8*8bit = 8bytes 的位向量符号，并将其值赋值给 `rax`，因为我们函数调用后的返回值是依赖 `rax` 返回的。

在我们设置好 explore 和 found 之后，它会停在 0x400684。它要打印的值是 `puts` 要打印的 `rdi` 寄存器的值。

``` assembly
.text:0000000000400681                 mov     rdi, rsp        ; s
.text:0000000000400684                 call    _puts
.text:0000000000400689                 xor     eax, eax
```

``` ipython
In [19]: simgr.explore(find=0x400684)
Out[19]: <SimulationManager with 1 found>

In [20]: found=simgr.found[0]
```

接下来是设置条件约束。我们知道它的 flag 格式为：`ASIS{*****}`，而这里输出的是 4 个数字，也就是 5+4*8+1=38 个字节，且前 5 个字节和最后一个字节都可以确定。

``` python
flag_addr = found.regs.rdi
found.add_constraints(found.memory.load(flag_addr, 5) == int(binascii.hexlify(b"ASIS{"), 16))
```

这里添加的约束是从 `flag_addr` 载入的 5bytes 大小的地址是否和 `ASIS{` 一致。

当然，仅仅有这一个条件也不一定够，我们还可以再添加一个约束条件：所有的字符都是可见字符：

``` python
flag = found.memory.load(flag_addr, 40)
for i in range(5, 5+32):
    cond_0 = flag.get_byte(i) >= ord('0')
    cond_1 = flag.get_byte(i) <= ord('9')
    cond_2 = flag.get_byte(i) >= ord('a')
    cond_3 = flag.get_byte(i) <= ord('f')
    cond_4 = found.solver.And(cond_0, cond_1)
    cond_5 = found.solver.And(cond_2, cond_3)
    found.add_constraints(found.solver.Or(cond_4, cond_5))
```

这里就是添加约束了，看起来还蛮好理解的 XDD。分别是限制为数字和字母。接下来我们再添加最后一个限制，以 `}` 结尾：

``` python
found.add_constraints(flag.get_byte(32+5) == ord('}'))
```

同时作者指出：

> 实际上，放置较少的约束（例如，仅约束前几个字符）足以获取最终标志，并且如果约束较少，则 z3 的运行速度更快。我添加了所有约束，只是为了安全起见。

接下来我们用 `eval` 方法找到 flag 并输出：

``` python
flag_str = found.solver.eval(flag, cast_to=bytes)
print(flag_str.rstrip(b'\0'))
```

即可得到输出值：

``` ipython
In [26]: print(flag_str.rstrip(b'\0'))
b'ASIS{f5f7af556bd6973bd6f2687280a243d9}'
```
