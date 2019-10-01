---
title: python导出依赖
date: 2019-06-17 00:27:23
tags: 水
---



最近在导出 Python 项目依赖的时候遇到了些小问题。

<!--more-->

导出依赖的方法：

第一种，通过

```bash
pip freeze > requirements.txt
```

导出，不过这种方法有个缺点，它会导出环境中的所有库。比如我导出了一个小项目，它包含这么多依赖：

```
certifi==2016.2.28
cycler==0.10.0
kiwisolver==1.1.0
matplotlib==3.1.0
numpy==1.16.4
pyparsing==2.4.0
python-dateutil==2.8.0
six==1.12.0
wincertstore==0.2
```

很多情况我们并不需要，因此推荐下面的方法：

第二种，安装 pipreqs，然后在项目目录下运行

```bash
pipreqs .
```

这种方法只会导出该项目所需要的库。上面的项目通过 pipreqs 导出之后只剩下了这么一点点：

```
matplotlib==3.1.0
numpy==1.16.4
```

比较推荐。

另外，在 cmd 中运行的时候遇到了这样的错误：

```
(test) C:\WINDOWS\system32>conda deactivate
Fatal Python error: init_sys_streams: can't initialize sys standard streams
LookupError: unknown encoding: 65001

Current thread 0x0000360c (most recent call first):
```

这是因为修改了操作系统编码所导致的。在 CMD 中设置环境变量：

```bash
set PYTHONIOENCODING=UTF-8
```

即可。如果是在 Powershell 中运行的话，需要

```bash
$env:PYTHONIOENCODING = "UTF-8"
```

# 参考资料

[Python 2.7 : LookupError: unknown encoding: cp65001 duplicate](https://stackoverflow.com/questions/35176270/python-2-7-lookuperror-unknown-encoding-cp65001)

然而里面的这个方法：

> Also you can try to install [win-unicode-console](https://github.com/Drekin/win-unicode-console) with pip:

 ``` bash
 pip install win-unicode-console
 ```

> Then reload your terminal and try to execute `pip --version`
>
> However you can follow suggestions from [Windows cmd encoding change causes Python crash](https://stackoverflow.com/questions/878972/windows-cmd-encoding-change-causes-python-crash?answertab=active#tab-top) answer because you have **same problem**.

好像并没有用，所以可能要把上面的环境变量写死。另外 VSCode 中好像没有遇到过这个问题。