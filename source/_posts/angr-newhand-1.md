---
title: angr 入门（一）
date: 2019-09-15 01:24:34
tags: [angr]
---

让我们从官方文档走起。

<!--more-->

## 安装指南

在 manjaro 上安装 angr 还算简单，我使用了 miniconda 作为 python 的虚拟环境。

- 创建虚拟环境：

``` shell
conda create -n angr
conda activate angr
```

接下来 `pip install angr` 即可

中途会报一个有关 `psutil` 的错误，主要原因是缺少 python 头文件。网上有 Ubuntu/CentOS 中的解决办法，还没有在 Manjaro 中的。最简单的办法是 `conda install psutil`。

接下来就可以很方便的 `import angr` 了。

#### example

安装完成后，我们用一个例子来跑一下：

以 README 中的 Example 为例，

``` python
import angr

project = angr.Project("/home/qrz/GitHub/angr-doc/examples/defcamp_r100/r100", auto_load_libs=False)

@project.hook(0x400844)
def print_flag(state):
    print("FLAG SHOULD BE:", state.posix.dumps(0))
    project.terminate_execution()

project.execute()
```

我的运行结果为：

``` bash
$ python test.py
WARNING | 2019-09-11 22:55:38,077 | angr.state_plugins.symbolic_memory | The program is accessing memory or registers with an unspecified value. This could indicate unwanted behavior.
WARNING | 2019-09-11 22:55:38,077 | angr.state_plugins.symbolic_memory | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING | 2019-09-11 22:55:38,078 | angr.state_plugins.symbolic_memory | 1) setting a value to the initial state
WARNING | 2019-09-11 22:55:38,078 | angr.state_plugins.symbolic_memory | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING | 2019-09-11 22:55:38,078 | angr.state_plugins.symbolic_memory | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY_REGISTERS}, to suppress these messages.
WARNING | 2019-09-11 22:55:38,078 | angr.state_plugins.symbolic_memory | Filling register r15 with 8 unconstrained bytes referenced from 0x400890 (PLT.ptrace+0x290 in r100 (0x400890))
WARNING | 2019-09-11 22:55:38,084 | angr.state_plugins.symbolic_memory | Filling register r14 with 8 unconstrained bytes referenced from 0x400895 (PLT.ptrace+0x295 in r100 (0x400895))
WARNING | 2019-09-11 22:55:38,087 | angr.state_plugins.symbolic_memory | Filling register r13 with 8 unconstrained bytes referenced from 0x40089a (PLT.ptrace+0x29a in r100 (0x40089a))
WARNING | 2019-09-11 22:55:38,089 | angr.state_plugins.symbolic_memory | Filling register r12 with 8 unconstrained bytes referenced from 0x40089f (PLT.ptrace+0x29f in r100 (0x40089f))
WARNING | 2019-09-11 22:55:38,097 | angr.state_plugins.symbolic_memory | Filling register rbx with 8 unconstrained bytes referenced from 0x4008b0 (PLT.ptrace+0x2b0 in r100 (0x4008b0))
WARNING | 2019-09-11 22:55:38,170 | angr.state_plugins.symbolic_memory | Filling register cc_ndep with 8 unconstrained bytes referenced from 0x400690 (PLT.ptrace+0x90 in r100 (0x400690))
FLAG SHOULD BE: b'Code_Talkers\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\x00'
```

我们看到，它 hook 在了 0x400844 处。

这一处地址的指令为：

``` assembly
.text:0000000000400844                 mov     edi, offset s   ; "Nice!"
```

也就是得到正确答案所需要的程序流。

正常做的话，会进入一个处理函数：

``` c
signed __int64 __fastcall sub_4006FD(char *s)
{
  signed int i; // [rsp+14h] [rbp-24h]
  const char *v3; // [rsp+18h] [rbp-20h]
  const char *v4; // [rsp+20h] [rbp-18h]
  const char *v5; // [rsp+28h] [rbp-10h]

  v3 = "Dufhbmf";
  v4 = "pG`imos";
  v5 = "ewUglpt";
  for ( i = 0; i <= 11; ++i )
  {
    if ( (&v3)[i % 3][2 * (i / 3)] - s[i] != 1 )
      return 1LL;
  }
  return 0LL;
}
```

我们的输入需要让这个函数返回 0。详细做法我就不展开了。

接下来，我们看一下 example 中体现的基础用法吧。

## CFG（Control Flow Graph）

在官方提供的[文档](https://docs.angr.io/built-in-analyses/cfg)中，很难直接看控制流程图，想要查看的话可以按照这种[方法](https://github.com/axt/angr-utils)。

### 安装

实际上按照他的方法安装之后可能还会出现下面的问题：

```bash
FileNotFoundError: [Errno 2] No such file or directory: 'dot': 'dot'
```

经检查是缺少相关的包，我们用 conda 来安装就好了

``` bash
conda install pydot
```

之后就可以正常跑他的样例了。

样例脚本：

``` python
import angr
from angrutils import *
proj = angr.Project("./ais3_crackme", load_options={'auto_load_libs':False})
main = proj.loader.main_object.get_symbol("main")
start_state = proj.factory.blank_state(addr=main.rebased_addr)
cfg = proj.analyses.CFGEmulated(fail_fast=True, starts=[main.rebased_addr], initial_state=start_state)
plot_cfg(cfg, "ais3_cfg", asminst=True, remove_imports=True, remove_path_terminator=True)
```

跑出来的结果如下图所示：

![A simple CFG][cfg_example]

如果我们用 IDA 来看 CFG 的话能得到一个类似的结果：

![CFG BY IDA][cfg_example_IDA]

对比的话能看出来 IDA 的内容更加优雅。

不过按照[文档的 FAQ](https://docs.angr.io/introductory-errata/faq)，angr 的 CFG 与 IDA 的 CFG 不同之处在于：

- angr 会拆分 IDA 不会在函数调用时拆分的基本块，因为 angr 认为它们是控制流的一种形式，基本块以控制流指令结束。通过函数属性的 `.supergraph` 可以生成 IDA 风格的 CFG。
- 如果另一个块跳到一个基本块中间，IDA 会拆分这个基本块，IDA 称其为基本块的标准化，而 angr 默认不会这么做，因为大多数静态分析不需要它。想要开启它的话可以将 `normalize = True`
 传递给 CFG。

[cfg_example]: https://raw.githubusercontent.com/40m41h42t/Images/master/2019/09/CFG_example_ais3_cfg.png "CFG Image"

[cfg_example_IDA]: https://raw.githubusercontent.com/40m41h42t/Images/master/2019/09/CFG_BY_IDA_ais3_cfg.png

## Examples

我们根据某些实际的[例子](https://docs.angr.io/examples)来学习 angr。

### DEFCAMP r100

首先还是以 example 中的 defcamp_r100 为例。

它的输入要求为：

``` c
fgets(&s, 255, stdin);
```

因此 solve 脚本中的约束条件并不严格。

官方做测试的约束是：

``` python
import angr

project = angr.Project("/home/qrz/GitHub/angr-doc/examples/defcamp_r100/r100", auto_load_libs=False)

@project.hook(0x400844)
def print_flag(state):
    print("FLAG SHOULD BE:", state.posix.dumps(0))
    project.terminate_execution()

project.execute()
```

其中，这里用到了 `angr.Project()`，这个 Project 是一个类，里面是各项加载参数。

接下来 hook 了 0x400844 这个地址，当符号执行流程进入到这个地址时，输出 stdin 的内容，接下来停止符号执行。

接下来我们分析一下它给的 `solve.py`。

``` python
import angr

def main():
    p = angr.Project("r100")
    simgr = p.factory.simulation_manager(p.factory.full_init_state())
    simgr.explore(find=0x400844, avoid=0x400855)

    return simgr.found[0].posix.dumps(0).strip(b'\0\n')

def test():
    assert main().startswith(b'Code_Talkers')

if __name__ == '__main__':
    print(main())
```

这里用了不同的方法，它构造了一个模拟管理器，以 `full_init_state` 为初始参数。

`find` 参数下的 `0x400844` 和上面的 hook 一样，都是我们想要找的位置，要避免的地址位于 `0x400855`，也就是

``` assembly
.text:0000000000400855                 mov     edi, offset aIncorrectPassw ; "Incorrect password!"
```

这个错误的分支。

可以看出，我们使用 angr 就是要通过约束条件使程序运行到正确的分支，避免错误的分支。如何让约束优雅地进行是比较困难的。angr 使用 claripy 作为 z3 的简单前端，我们也要掌握一部分其用法。