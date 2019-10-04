---
title: angr 入门（三）
date: 2019-10-04 23:03:59
tags: [angr, re]
---

本篇主要记录了新手使用 angr 对内存和寄存器操作的记录。题目分析顺序参考了这篇文章：[深入浅出angr（三）](https://xz.aliyun.com/t/4052)

<!--more-->

## 通过直接地址写入

对于 `.bss` 段等固定地址的变量我们可以利用 `claripy` 直接地址写入，进行初始化 `state`。

### sym-write

这道题的关键点是一个存在 `.bss` 段的 `u`。它在程序中是未初始化的变量。

``` assembly
.bss:0804A021                 public u
.bss:0804A021 u               db ?                    ; DATA XREF: main:loc_804849E↑r
.bss:0804A022                 db    ? ;
.bss:0804A023 unk_804A023     db    ? ;               ; DATA XREF: deregister_tm_clones↑o
.bss:0804A023 _bss            ends
```

在默认情况下，所有符号写索引都是具体的。为了写入符号地址，我们在初始化 `simulation_manager` 的 `state` 时需要添加参数 `add_options={"SYMBOLIC_WRITE_ADDRESSES"}`。

``` python
state = p.factory.entry_state(add_options={angr.options.SYMBOLIC_WRITE_ADDRESSES})
```

接下来创建 `u` 的位向量符号并写入内存：

``` python
u = claripy.BVS("u", 8)
state.memory.store(0x804a021, u)
```

这里用到了 `store` 方法，向 bss 段中的该地址写入了符号 `u`。接下来就可以正常创建 `simulation manager` 了。

接下来就是设置 `find` 和 `avoid` 了，它在题解中也给了一个有趣的解决方式：

``` python
def correct(state):
    try:
        return b'win' in state.posix.dumps(1)
    except:
        return False

def wrong(state):
    try:
        return b'lose' in state.posix.dumps(1)
    except:
        return False
```

也就是根据输出判断正确性。当然我们也可以硬编码，但是根据输出判断可能会对一些开启地址随机化的题目有所帮助。

接下来输出即可，它的输出可能会有很多解。

## 操纵内存及寄存器数据

### flareon2015_2 - very_success

载入 IDA，通过某些函数特征可以判断出这是 Windows 程序。

为了避免调用 Windows 的 API，我们需要在后面起始，也就是 0x40105F 或者是 0x401084。

``` python
s = b.factory.blank_state(addr=0x401084)
```

根据前面的 `ReadFile` 函数，我们可以判断出 0x402159 处存放的是我们想要的答案。

由于我们是从后面的一个函数开始的，因此我们需要根据参数构造一下栈帧。参照的压栈顺序：

``` assembly
.text:00401051                 push    eax             ; lpNumberOfBytesWritten
.text:00401052                 push    11h             ; nNumberOfBytesToWrite
.text:00401054                 push    dword ptr [ebp-4]
.text:00401057                 push    offset input_str
.text:0040105C                 push    dword ptr [ebp-10h]
.text:0040105F                 call    sub_401084
.text:00401064                 add     esp, 0Ch
```

题解给的构造方法如下：

``` python
s.memory.store(s.regs.esp+12, s.solver.BVV(40, s.arch.bits))
```

对于这一句，它创建了一个值为 40，大小（以 bits 为单位）为 `s.arch.bits` 的位向量值（BVV）。其中 `s.arch.bits` 的值为 32（这是一个 32 位的程序）。接着它将该值载入到 `esp+12` 的位置上。

对于这个地址，我们可以看到它原本是 `push dword ptr [ebp-4]`。往前看并没有找到它的具体的值，这里也就顺便传了一个符号进去。

``` ipython
In [4]: s.arch
Out[4]: <Arch X86 (LE)>

In [5]: s.arch.bits
Out[5]: 32
```

``` python
s.mem[s.regs.esp+8:].dword = 0x402159   # 输入的数据存放的地址
s.mem[s.regs.esp+4:].dword = 0x4010e4   # [ebp-10] 存放的地址，我们逆过去能找到它。
s.mem[s.regs.esp:].dword = 0x401064     # 返回值地址，确切的来说是 call 调用时 push 的 eip
```

有关那个 0x4010e4 的地址，实际上我们看它压入的是 `[ebp-10h]`，我们向前追溯，在 0x401007 有一段 `mov [ebp-10h], eax`，我们再往前看，0x401000 有一段 `pop eax`。接下来再向前找就只能找到 `.text:004010DF call sub_401000` 了。因此这里的值是 0x4010e4。

接下来向内存中的该地址放入一个符号向量。我们看它读入的大小是 0x32 也就是 40，因此我们向相关的位置写一个大小为 40bytes 的符号向量：

``` python
s.memory.store(0x402159, s.solver.BVS("ans", 8*40))
```

接下来就创建 simulation manager，设置 find 和 avoid 即可：

``` python
sm = b.factory.simulation_manager(s)
sm.explore(find = 0x40106b, avoid = 0x401072)
```

最后输出即可。

``` python
found_state = sm.found[0]
found_state.solver.eval(found_state.memory.load(0x402159, 40), cast_to=bytes).strip(b'\0')
```

### codegate 2017 - angrybird

用 IDA 载入，看一下它的 CFG：

![angrybird CFG][angrybird_CFG_by_IDA]

[angrybird_CFG_by_IDA]: https://raw.githubusercontent.com/40m41h42t/Images/master/2019/10/angrybird_CFG_by_IDA.png

看上去有点恐怖。。而且反汇编分析不出啥：

``` c
void __fastcall main(int a1, char **a2, char **a3)
{
  unsigned __int64 v3; // [rsp+78h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  exit(a1);
}
```

第一段就要退出：

``` assembly
.text:0000000000400761                 push    rbp
.text:0000000000400762                 mov     rbp, rsp
.text:0000000000400765                 add     rsp, 0FFFFFFFFFFFFFF80h
.text:0000000000400769                 mov     rax, fs:28h
.text:0000000000400772                 mov     [rbp+var_8], rax
.text:0000000000400776                 xor     eax, eax
.text:0000000000400778                 cmp     eax, 0
.text:000000000040077B                 jz      _exit
```

接下来要进行三个比较，我们命名一下大概是这样子的：

``` assembly
.text:0000000000400781                 mov     [rbp+var_70], offset off_606018
.text:0000000000400789                 mov     [rbp+var_68], offset off_606020
.text:0000000000400791                 mov     [rbp+var_60], offset off_606028
.text:0000000000400799                 mov     [rbp+var_58], offset off_606038
.text:00000000004007A1                 mov     eax, 0
.text:00000000004007A6                 call    ret_21
.text:00000000004007AB                 mov     [rbp+n], eax
.text:00000000004007AE                 mov     eax, 0
.text:00000000004007B3                 call    stack_check
.text:00000000004007B8                 mov     eax, 0
.text:00000000004007BD                 call    cmp_hello
```

第一段要求返回 21，但是函数会返回 1；第二段会尝试引用不存在的地址；第三段会将 `__lib_start_main` 地址上的值与 `hello` 进行比较。

当然，用了 angr 之后我们可以不关心这些（不需要手动 patch），我们可以从 0x4007C2 开始。当然，从这里开始的话我们需要设置一些值。

首先，对于 `_fgets` 函数，它的参数 `esi` 向前可追溯到 `[rbp+n]`。而通过 `.text:00000000004007AB                 mov     [rbp+n], eax`，我猜测它的值为 21。

接下来，从上面的代码中可以看到这些：

``` assembly
.text:0000000000400781                 mov     [rbp+var_70], offset off_606018
.text:0000000000400789                 mov     [rbp+var_68], offset off_606020
.text:0000000000400791                 mov     [rbp+var_60], offset off_606028
.text:0000000000400799                 mov     [rbp+var_58], offset off_606038
```

它们其实是把一部分函数表的值载入到了栈上：

``` assembly
.got.plt:0000000000606018 off_606018      dq offset strncmp       ; DATA XREF: _strncmp↑r
.got.plt:0000000000606018                                         ; main+20↑o
.got.plt:0000000000606020 off_606020      dq offset puts          ; DATA XREF: _puts↑r
.got.plt:0000000000606020                                         ; main+28↑o
.got.plt:0000000000606028 off_606028      dq offset __stack_chk_fail
.got.plt:0000000000606028                                         ; DATA XREF: ___stack_chk_fail↑r
.got.plt:0000000000606028                                         ; main+30↑o
.got.plt:0000000000606030 off_606030      dq offset printf        ; DATA XREF: _printf↑r
.got.plt:0000000000606038 off_606038      dq offset __libc_start_main
.got.plt:0000000000606038                                         ; DATA XREF: ___libc_start_main↑r
```

我们也需要把这一部分填充，不过填充什么值是值得讨论的。它的题解给出的是：

``` python
state.mem[state.regs.rbp - 0x70].long = 0x1000
state.mem[state.regs.rbp - 0x68].long = 0x1008
state.mem[state.regs.rbp - 0x60].long = 0x1010
state.mem[state.regs.rbp - 0x58].long = 0x1018
```

按照它的注释，这是因为：

> 对于这些变量，使用与二进制文件相同的值不起作用，我认为是因为它们指向 GOT，而二进制文件则使用该值来尝试识别它在 angr 中加载的指纹。将它们设置为指向符号存储器的指针可以正常工作。

然而我尝试把它们修改成 0x0, 0x8, 0x10, 0x18，发现它们一样可以工作；我又试着修改成 0x20xx，发现也可以。它们的它们的 Warning 大同小异，很有可能最开始就没设置为正确的值。或许我们初始化为某些值可能就可以输出正确的答案，而注释中的原因可能是站不住脚的。

我们可以在 main 函数最后找到最终要跳转的位置 `loc_404FAB`，设置 find 的位置为这里即可。

``` python
sm = proj.factory.simulation_manager(state)  # Create the SimulationManager.
sm.explore(find=FIND_ADDR)  # This will take a couple minutes. Ignore the warning message(s), it's fine.
found = sm.found[-1]
flag = found.posix.dumps(0)

# This trims off anything that's not printable.
return flag[:20]
```

#### 参考文章

[ctf-writeups/2017/codegate-prequels/angrybird.md](https://github.com/VulnHub/ctf-writeups/blob/master/2017/codegate-prequels/angrybird.md)

### google ctf unbreakable_1

这道题的 `solve.py` 讲的还是蛮细致的，我们分析一下吧。

第一步是加载位向量、添加约束。

``` python
state = p.factory.blank_state(addr=START_ADDR, add_options={angr.options.LAZY_SOLVES})
```

这里跳过了输入数据的过程，直接加载到内存中。于是从 0x4005BD（`START_ADDR`）开始。这里添加了一个 `LAZY_SOLVES` 选项，查看[文档](https://docs.angr.io/appendix/options)可以知道这是一个“除非绝对必要，否则不要检查可满足性”（Don't check satisfiability until absolutely necessary）的选项。这个选项可以加快分析的速度，而且只有在路径分析完之后才会检查可满足性，如果没有加载这个选项的话，很有可能会路径爆炸。

由于我们没有构造输入，因此我们需要直接在内存中构造数据。输入的数据存放在 `dest`（0x6042C0，`INPUT_ADDR`）中。flag 的长度 `n` 为 0x43 也就是 67。

``` python
for i in range(INPUT_LENGTH):
    c, cond = char(state, i)
    # the first command line argument is copied to INPUT_ADDR in memory
    # so we store the BitVectors for angr to manipulate
    state.memory.store(INPUT_ADDR + i, c)
    state.add_constraints(cond)
```

在这里它实现了一个函数 `char()`，它的作用是返回位向量符号并将其约束为可打印字符，它返回一个 BVS 和一个约束：

``` python
def char(state, n):
    """Returns a symbolic BitVector and contrains it to printable chars for a given state."""
    vec = state.solver.BVS('c{}'.format(n), 8, explicit_name=True)
    return vec, state.solver.And(vec >= ord(' '), vec <= ord('~'))
```

在接下来的每个循环中，它将 BVS 载入到内存中，并添加约束。

然后它开始创建 simulation_manager 并运行 explorer。我们也能轻易找到正确的位置 0x400830 和错误的位置 0x400850。

接下来就是运行并从内存中取出答案咯，看上去很简单的样子，而且速度也蛮快的。
