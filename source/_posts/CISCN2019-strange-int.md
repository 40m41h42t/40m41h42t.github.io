---
title: CISCN2019 strange_int 题解
date: 2019-04-27 19:42:33
tags: [CTF, re]
categories: CTF
---

这道题在做的时候完全不知道如何下手，我参考[[CTF]（原创）第十二届全国大学生信息安全竞赛strange_int题解](<https://www.52pojie.cn/thread-936377-1-1.html>)分析一波。

<!--more-->

如果单纯的按照 32 位程序来载入这个文件的话，前面有很长一段没有分析出来。根据之前学到的[知识](<https://github.com/40m41h42t/OS-Experiment/blob/master/ucore/%E7%AC%AC%E4%B8%89%E8%AE%B2.md>)，主引导扇区大小为 512 字节，最后两位是 `55 AA`。我们看 1FE 处的确是 `55 AA`，可以判断前面是主引导记录的代码。接下来我们用 IDA 的创建段的功能创建一个从 0x0 到 0x52 的按照 16 位分析的段，并 code 出它的汇编代码。

# 第 0 段：MBR

```asm
MBR16:0000 MBR16           segment byte public '' use16
MBR16:0000                 assume cs:MBR16
MBR16:0000                 assume es:nothing, ss:nothing, ds:nothing, fs:nothing, gs:nothing
MBR16:0000                 jmp     far ptr 7C0h:5
MBR16:0005 ; ---------------------------------------------------------------------------
MBR16:0005                 mov     ax, cs
MBR16:0007                 mov     ds, ax
MBR16:0009                 assume ds:MBR16
MBR16:0009                 mov     ss, ax
MBR16:000B                 assume ss:MBR16
MBR16:000B                 mov     sp, 400h
MBR16:000E                 cld
MBR16:000F                 mov     ax, 3
MBR16:0012                 int     10h             ; - VIDEO - SET VIDEO MODE
MBR16:0012                                         ; AL = mode
MBR16:0014                 mov     dx, 0
MBR16:0017                 mov     cx, 2
MBR16:001A                 mov     ax, 1000h
MBR16:001D                 mov     es, ax
MBR16:001F                 assume es:nothing
MBR16:001F                 xor     bx, bx
MBR16:0021
MBR16:0021 loc_21:                                 ; DATA XREF: seg001:00000F48↓o
MBR16:0021                                         ; seg001:00000F84↓o ...
MBR16:0021                 mov     ax, 228h
MBR16:0024                 int     13h             ; DISK - READ SECTORS INTO MEMORY
MBR16:0024                                         ; AL = number of sectors to read, CH = track, CL = sector
MBR16:0024                                         ; DH = head, DL = drive, ES:BX -> buffer to fill
MBR16:0024                                         ; Return: CF set on error, AH = status, AL = number of sectors read
MBR16:0026
MBR16:0026 loc_26:                                 ; DATA XREF: seg001:00001044↓o
MBR16:0026                 jnb     short loc_2A
```

主引导扇区的地址被加载到了 0x7c00，因此第一条代码会跳转到它的下一条代码上。

`int 10` 调整显示模式，`int 13h` 结合[ BIOS 中断](<https://blog.csdn.net/liguodong86/article/details/3973337>)分析出它将软盘（`DL=0H`）上的 0 磁道（`DH=0H`）0 柱面（`CH=0H`）2 扇区（`CL=2H`）开始的 28 个扇区（`AL=28H`）（28 个扇区的话是读取了 28*512=3800H 个字节）读取（`AH=02H`）到内存的 `1000:0000h` 处（`ES:BX=1000:0000`）。接下来跳转到 `loc_2A`。

```assembly
MBR16:002A loc_2A:                                 ; CODE XREF: MBR16:loc_26↑j
MBR16:002A                 cli
MBR16:002B                 mov     ax, 1000h
MBR16:002E                 mov     ds, ax
MBR16:0030                 assume ds:nothing
MBR16:0030
MBR16:0030 loc_30:                                 ; DATA XREF: seg001:00001140↓o
MBR16:0030                 xor     ax, ax
MBR16:0032                 mov     es, ax
MBR16:0034                 assume es:MBR16
MBR16:0034                 mov     cx, 2000h
MBR16:0037                 sub     si, si
MBR16:0039                 sub     di, di
MBR16:003B                 rep movsb
MBR16:003D                 mov     ax, 7C0h
MBR16:0040
```

在这里将 `DS:SI(1000:0000)` 移动到 `ES:DI(0000:0000)` 处（`movsb`），移动了 2000H 个字节（`cx=2000H`）。

```assembly
MBR16:0040 loc_40:                                 ; DATA XREF: MBR16:0012↑r
MBR16:0040                 mov     ds, ax
MBR16:0042                 assume ds:nothing
MBR16:0042                 lidt    fword ptr ds:6Fh
MBR16:0047                 lgdt    fword ptr ds:75h
MBR16:004C
MBR16:004C loc_4C:                                 ; DATA XREF: MBR16:0024↑r
MBR16:004C                 mov     ax, 1
MBR16:004F                 lmsw    ax
MBR16:004F MBR16           ends
MBR16:004F
seg001:00000052 ; ===========================================================================
seg001:00000052
seg001:00000052 ; Segment type: Pure code
seg001:00000052 seg001          segment byte public 'CODE' use32
seg001:00000052                 assume cs:seg001
seg001:00000052                 ;org 52h
seg001:00000052                 assume es:MBR16, ss:MBR16, ds:MBR16, fs:MBR16, gs:MBR16
seg001:00000052                 jmp     far ptr 0:80000h
```

接下初始化 IDT 和 GDT（lidt、lgdt），其初值都是 0x00000000。然后开启保护模式（lmsw）并跳转到 32 位代码段。接下来的代码从 0x200 开始，以 32 位重建。

# 第 1 段：初始化

```assembly
seg001:00000200                 mov     eax, 10h
seg001:00000205                 mov     ds, eax
seg001:00000207                 assume ds:nothing
seg001:00000207                 lss     esp, large ds:0B5Ch
seg001:0000020E                 call    sub_28B
seg001:00000213                 call    sub_283         ; DATA XREF: sub_2BA+A↓r
seg001:00000213                                         ; sub_2BA:loc_2E0↓w
```

在这一段分别初始化了 LIDT 和 LGDT。正好我详细地分析一下其初始化过程。

首先初始化 IDT：

```assembly
seg000:0000028B sub_28B         proc near               ; CODE XREF: seg000:0000020E↑p
seg000:0000028B                 mov     edx, 0FCh
seg000:00000290                 mov     eax, 80000h
seg000:00000295                 mov     ax, dx
seg000:00000298                 mov     dx, 8E00h
seg000:0000029C                 lea     edi, loc_225+3 - unk_100 ; lea edi, ds:128,不知道为什么被翻译成了这个样子
seg000:000002A2                 mov     ecx, 100h
seg000:000002A7
seg000:000002A7 loc_2A7:                                ; CODE XREF: sub_28B+25↓j
seg000:000002A7                 mov     [edi], eax
seg000:000002A9                 mov     [edi+4], edx
seg000:000002AC                 add     edi, 8
seg000:000002AF                 dec     ecx
seg000:000002B0                 jnz     short loc_2A7
seg000:000002B2                 lidt    large fword ptr ds:11Ch
seg000:000002B9                 retn
seg000:000002B9 sub_28B         endp
```

循环了 256 次，`8:0128H` 开始的地址都填充了 `800fcH`，紧随其后的地址填充了 `8e00H`。然后加载中断描述符表寄存器。我发现这一段我不是很熟悉。这一段是：

```assembly
lidt ds:0x0000011c
```

额，看了一下内存是 

```
0x000000000000011c <bogus+0>:    0x012807ff      0x001f0000
```

`IDTR` 为 `000001287ffH`，其格式为：

- 基址：0x00000128

- 长度：0x7FF

初始化的中断门描述符为

```
0x000800fc      0x00008e00
```
也就是

```
0000 8e00 0008 00fc
```

按照格式可得：

- 偏移：0xfc
- 段选择符：0x8
- P：1（段是否在内存的标志）
- DPL：0

接下来初始化 GDT 与之类似，不过没有填充 GDT 表的操作了，先略过不表。


```assembly
seg001:00000218                 mov     eax, 10h        ; DATA XREF: sub_28B+27↓r
seg001:0000021D                 mov     ds, eax
seg001:0000021F                 mov     es, eax
seg001:00000221                 assume es:nothing
seg001:00000221                 mov     fs, eax         ; DATA XREF: sub_283↓r
seg001:00000223                 assume fs:nothing
seg001:00000223                 mov     gs, eax
seg001:00000225                 assume gs:nothing
seg001:00000225
seg001:00000225 loc_225:                                ; DATA XREF: sub_28B+11↓o
seg001:00000225                 lss     esp, large ds:0B5Ch
seg001:0000022C                 xor     ebx, ebx
seg001:0000022E
seg001:0000022E loc_22E:                                ; CODE XREF: seg001:0000025D↓j
seg001:0000022E                 nop
seg001:0000022F                 cmp     ebx, 10h
seg001:00000232                 jge     short loc_25F
seg001:00000234                 mov     eax, 80000h
seg001:00000239                 lea     edx, ds:0D08h[ebx*4]
seg001:00000240                 mov     edx, [edx]
seg001:00000242                 mov     ax, dx
seg001:00000245                 mov     dx, 8E00h
seg001:00000249                 mov     ecx, 21h ; '!'
seg001:0000024E                 add     ecx, ebx
seg001:00000250                 lea     esi, ds:128h[ecx*8]
seg001:00000257                 mov     [esi], eax
seg001:00000259                 mov     [esi+4], edx
seg001:0000025C                 inc     ebx
seg001:0000025D                 jmp     short loc_22E
```

22EH 到 25DH 是一个循环，执行了 16 次。

其主要作用是将内存中 D08H 开始的数据填充到 21 号中断开始的 入口地址处。执行结束后，中断 21h 到 30h 的入口地址改变如下：

0x00000128开始存储，这里列出全部的中断向量：

| 中断编号 | 入口地址   |
| -------- | ---------- |
| 0x21     | 0x00000B7C |
| 0x22     | 0x00000B8A |
| 0x23     | 0x00000BA1 |
| 0x24     | 0x00000BC1 |
| 0x25     | 0x00000BE1 |
| 0x26     | 0x00000BFC |
| 0x27     | 0x00000C17 |
| 0x28     | 0x00000C32 |
| 0x29     | 0x00000C4F |
| 0x2A     | 0x00000C6C |
| 0x2B     | 0x00000C84 |
| 0x2C     | 0x00000C96 |
| 0x2D     | 0x00000CB5 |
| 0x2E     | 0x00000CF7 |
| 0x2F     | 0x00000CE0 |
| 0x30     | 0x00000CD4 |

> 摘自 https://www.52pojie.cn/thread-936377-1-1.html

然后进入下一个环节

# 第 2 段：中断

```assembly
seg000:0000025F loc_25F:                                ; CODE XREF: seg000:00000232↑j
seg000:0000025F                                         ; seg000:00000266↓j
seg000:0000025F                 call    sub_268
seg000:00000264                 int     21h             ; DOS -
seg000:00000266                 jmp     short loc_25F
seg000:00000268
seg000:00000268 ; =============== S U B R O U T I N E =======================================
seg000:00000268
seg000:00000268
seg000:00000268 sub_268         proc near               ; CODE XREF: seg000:loc_25F↑p
seg000:00000268                 mov     edi, large ds:0B78h
seg000:0000026E                 lea     edi, ds:0D48h[edi*4]
seg000:00000275                 mov     eax, [edi]
seg000:00000277                 mov     large ds:65h, al
seg000:0000027C                 mov     ecx, [edi+4]
seg000:0000027F                 mov     eax, [edi+8]
seg000:00000282                 retn
seg000:00000282 sub_268         endp
```

在这里先调用了 `sub_268` 再执行中断服务程序。在函数 `sub_268` 的内部，指令的寄存器（PC/IP）被存在了内存中的 `B78H`（index）处，操作数被设为了 `D48H`（op）开始选择的指令的第一位，`ecx`（参数 a）是第二位，`eax`（参数 b）是第三位。

## 中断功能分析

进入中断后，大部分中断都会跳进 `loc_EF8` 处。在这里，

而且在程序执行过程中，`264H` 处 `int 21h` 的数字也是在不断变化的。`D48H` 存放的内容是操作指令，3 个字节一组。中断描述服务程序从 `0xD7C` 开始。中断中的 `0xB64` 是一个 20 字节的缓冲区。假设 `B64` 段为 `buf`，`D48` 段叫 `code`，参数为 a、b。假设指针指令为 index（`B78`），则 16 个中断的功能可分析如下：

```assembly
seg000:00000D7C                 lea     ecx, ds:0B64h[ecx*4] ; 21h
seg000:00000D83                 mov     [ecx], eax
seg000:00000D85                 jmp     loc_EF8         ; 30h
```

| 中断号 | 功能       |
| ------ | ---------- |
| 21     | `buf[a]=b` |

```assembly
seg000:00000D8A                 lea     eax, ds:0B64h[eax*4] ; 22h
seg000:00000D91                 mov     eax, [eax]
seg000:00000D93                 lea     ecx, ds:0B64h[ecx*4]
seg000:00000D9A                 mov     [ecx], eax
seg000:00000D9C                 jmp     loc_EF8         ; 30h
```

| 中断号 | 功能            |
| ------ | --------------- |
| 22     | `buf[a]=buf[b]` |

```assembly
seg000:00000DA1                 lea     eax, ds:0B64h[eax*4] ; 23h
seg000:00000DA8                 mov     eax, [eax]
seg000:00000DAA                 lea     ecx, ds:0B64h[ecx*4]
seg000:00000DB1                 lea     eax, ds:0D48h[eax*4]
seg000:00000DB8                 mov     eax, [eax]
seg000:00000DBA                 mov     [ecx], eax
seg000:00000DBC                 jmp     loc_EF8         ; 30h
```

| 中断号 | 功能                  |
| ------ | --------------------- |
| 23     | `buf[a]=code[buf[b]]` |

```assembly
seg000:00000DC1                 lea     eax, ds:0B64h[eax*4] ; 24h
seg000:00000DC8                 mov     eax, [eax]
seg000:00000DCA                 lea     ecx, ds:0B64h[ecx*4]
seg000:00000DD1                 mov     ecx, [ecx]
seg000:00000DD3                 lea     ecx, ds:0D48h[ecx*4]
seg000:00000DDA                 mov     [ecx], eax
seg000:00000DDC                 jmp     loc_EF8         ; 30h
```

| 中断号 | 功能                  |
| ------ | --------------------- |
| 24     | `code[buf[a]]=buf[b]` |

```assembly
eg000:00000DE1                 lea     eax, ds:0B64h[eax*4] ; 25h
seg000:00000DE8                 mov     edx, [eax]
seg000:00000DEA                 lea     ecx, ds:0B64h[ecx*4]
seg000:00000DF1                 mov     eax, [ecx]
seg000:00000DF3                 add     eax, edx
seg000:00000DF5                 mov     [ecx], eax
seg000:00000DF7                 jmp     loc_EF8         ; 30h
```

| 中断号 | 功能             |
| ------ | ---------------- |
| 25     | `buf[a]+=buf[b]` |

```assembly
seg000:00000DFC                 lea     eax, ds:0B64h[eax*4] ; 26h
seg000:00000E03                 mov     edx, [eax]
seg000:00000E05                 lea     ecx, ds:0B64h[ecx*4]
seg000:00000E0C                 mov     eax, [ecx]
seg000:00000E0E                 sub     eax, edx
seg000:00000E10                 mov     [ecx], eax
seg000:00000E12                 jmp     loc_EF8         ; 30h
```

| 中断号 | 功能             |
| ------ | ---------------- |
| 26     | `buf[a]-=buf[b]` |

```assembly
seg000:00000E17                 lea     eax, ds:0B64h[eax*4] ; 27h
seg000:00000E1E                 mov     edx, [eax]
seg000:00000E20                 lea     ecx, ds:0B64h[ecx*4]
seg000:00000E27                 mov     eax, [ecx]
seg000:00000E29                 xor     eax, edx
seg000:00000E2B                 mov     [ecx], eax
seg000:00000E2D                 jmp     loc_EF8         ; 30h
```

| 中断号 | 功能             |
| ------ | ---------------- |
| 27     | `buf[a]^=buf[b]` |

```assembly
seg000:00000E32                 lea     eax, ds:0B64h[eax*4] ; 28h
seg000:00000E39                 mov     eax, [eax]
seg000:00000E3B                 lea     edx, ds:0B64h[ecx*4]
seg000:00000E42                 mov     cl, al
seg000:00000E44                 mov     eax, [edx]
seg000:00000E46                 shl     eax, cl
seg000:00000E48
seg000:00000E48 ; =============== S U B R O U T I N E =======================================
seg000:00000E48
seg000:00000E48
seg000:00000E48 sub_E48         proc near
seg000:00000E48                 mov     [edx], eax
seg000:00000E4A
seg000:00000E4A loc_E4A:                                ; 30h
seg000:00000E4A                 jmp     loc_EF8
```

| 中断号 | 功能                     |
| ------ | ------------------------ |
| 28     | `buf[a]<<=(buf[b]&0xFF)` |

```assembly
seg000:00000E4F loc_E4F:                                ; 29h
seg000:00000E4F                 lea     eax, ds:0B64h[eax*4]
seg000:00000E56                 mov     eax, [eax]
seg000:00000E58                 lea     edx, ds:0B64h[ecx*4]
seg000:00000E5F                 mov     cl, al
seg000:00000E61                 mov     eax, [edx]
seg000:00000E63                 shr     eax, cl
seg000:00000E65                 mov     [edx], eax
seg000:00000E67                 jmp     loc_EF8         ; 30h
```

| 中断号 | 功能                     |
| ------ | ------------------------ |
| 29     | `buf[a]>>=(buf[b]&0xFF)` |

```assembly
seg000:00000E6C                 lea     eax, ds:0B64h[eax*4] ; 2ah
seg000:00000E73                 mov     eax, [eax]
seg000:00000E75                 lea     ecx, ds:0B64h[ecx*4]
seg000:00000E7C                 mov     edx, [ecx]
seg000:00000E7E                 and     eax, edx
seg000:00000E80                 mov     [ecx], eax
seg000:00000E82                 jmp     short loc_EF8   ; 30h
```

| 中断号 | 功能             |
| ------ | ---------------- |
| 2A     | `buf[a]&=buf[b]` |

```assembly
seg000:00000E84                 lea     eax, ds:0B64h[ecx*4] ; 2bh
seg000:00000E8B                 mov     eax, [eax]
seg000:00000E8D                 lea     ecx, dword_B34+44h
seg000:00000E93                 mov     [ecx], eax
seg000:00000E95                 iret
```

| 中断号 | 功能           |
| ------ | -------------- |
| 2B     | `index=buf[a]` |

```assembly
seg000:00000E96                 lea     eax, ds:0B64h[eax*4] ; 2ch
seg000:00000E9D                 mov     eax, [eax]
seg000:00000E9F                 test    eax, eax
seg000:00000EA1                 jnz     short loc_EF8   ; 30h
seg000:00000EA3                 lea     eax, ds:0B64h[ecx*4]
seg000:00000EAA                 mov     eax, [eax]
seg000:00000EAC                 lea     ecx, dword_B34+44h
seg000:00000EB2                 mov     [ecx], eax
seg000:00000EB4                 iret
```

| 中断号 | 功能                          |
| ------ | ----------------------------- |
| 2C     | `if(buf[b]==0){index=buf[a]}` |

```assembly
seg000:00000EB5                 lea     eax, ds:0B64h[eax*4] ; 2dh
seg000:00000EBC                 mov     eax, [eax]
seg000:00000EBE                 test    eax, eax
seg000:00000EC0                 jz      short loc_EF8   ; 30h
seg000:00000EC2                 lea     eax, ds:0B64h[ecx*4]
seg000:00000EC9                 mov     eax, [eax]
seg000:00000ECB                 lea     ecx, dword_B34+44h
seg000:00000ED1                 mov     [ecx], eax
seg000:00000ED3                 iret
```

| 中断号 | 功能                          |
| ------ | ----------------------------- |
| 2D     | `if(buf[b]!=0){index=buf[a]}` |

```assembly
seg000:00000EF7                 hlt                     ; 2Eh
```

| 中断号 | 功能   |
| ------ | ------ |
| 2E     | `exit` |

```assembly
seg000:00000EE0                 lea     eax, unk_FA0    ; 2fh
seg000:00000EE6                 call    sub_2EA
seg000:00000EEB                 lea     eax, word_FAE
seg000:00000EF1                 call    sub_2EA
seg000:00000EF6                 hlt
```

| 中断号 | 功能         |
| ------ | ------------ |
| 2F     | `flag_right` |

```assembly
seg000:00000ED4                 lea     eax, unk_F94    ; 30h
seg000:00000EDA                 call    sub_2EA
seg000:00000EDF                 hlt
```

| 中断号 | 功能         |
| ------ | ------------ |
| 30     | `flag_wrong` |

整理可以得到下面的这张表：

| 中断编号 | 功能描述                         |
| -------- | -------------------------------- |
| 0x21     | buf[a]  = b                      |
| 0x22     | buf[a]  = buf[b]                 |
| 0x23     | buf[a]  = code[buf[b]]           |
| 0x24     | code[buf[a]]  = buf[b]           |
| 0x25     | buf[a]  += buf[b]                |
| 0x26     | buf[a]  -= buf[b]                |
| 0x27     | buf[a]  ^= buf[b]                |
| 0x28     | buf[a]  <<= (buf[b] & 0xFF)      |
| 0x29     | buf[a]  >>= (buf[b] & 0xFF)      |
| 0x2A     | buf[a]  &= buf[b]                |
| 0x2B     | index  = buf[a]                  |
| 0x2C     | if(buf[b]  == 0){index = buf[a]} |
| 0x2D     | if(buf[b]  != 0){index = buf[a]} |
| 0x2E     | 终止CPU运行，即hlt指令           |
| 0x2F     | 输出flag正确提示                 |
| 0x30     | 输出flag错误提示                 |

# 第 3 段：编写虚拟机

分析完中断的功能之后，我们就可以写一个功能类似的虚拟机了。

我用 Python 写的脚本大致如下：

```python
opcode = [
    0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x81, 0x00, 0x00, 0x00, 0x27, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x22, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x27, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x28, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x27, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x27, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x27, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x27, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x21, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x81, 0x00, 0x00, 0x00, 0x26, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x09, 0x00, 0x00, 0x00, 0x26, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x21, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x2D, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x81, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x21, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x25, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x26, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x7E, 0x00, 0x00, 0x00, 0x2D, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x25, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x26, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x5A, 0x00, 0x00, 0x00,
    0x2D, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x2F, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x38, 0x62, 0x64, 0x61, 0x65, 0x34, 0x35, 0x36, 0x2D, 0x35, 0x61, 0x63,
    0x38, 0x2D, 0x31, 0x31, 0x65, 0x39, 0x2D, 0x61, 0x31, 0x63, 0x31, 0x2D, 0x38, 0x38, 0x65, 0x39,
    0x66, 0x65, 0x38, 0x30, 0x66, 0x65, 0x61, 0x66, 0x65, 0x55, 0x63, 0x57, 0x01, 0x04, 0x53, 0x06,
    0x49, 0x49, 0x49, 0x1F, 0x1F, 0x07, 0x57, 0x51, 0x57, 0x43, 0x5F, 0x57, 0x57, 0x5E, 0x43, 0x57,
    0x0A, 0x02, 0x57, 0x43, 0x5E, 0x03, 0x5E, 0x57, 0x00, 0x00, 0x59, 0x0F, 0x77, 0x72, 0x6F, 0x6E,
    0x67, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x00, 0x63, 0x6F, 0x72, 0x72, 0x65, 0x63, 0x74, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x00, 0x66, 0x6C, 0x61, 0x67, 0x20, 0x69, 0x73, 0x20, 0x66, 0x6C,
    0x61, 0x67, 0x7B, 0x59, 0x6F, 0x75, 0x72, 0x50, 0x61, 0x74, 0x63, 0x68, 0x7D, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x00
]

buf = [0, 0, 0, 0, 0]
rcode = []
vstr = ''


def generate_code():
    for i in range(int(len(opcode)/4)):
        rcode.append(opcode[i*4] | (opcode[i*4+1] << 8) |
                     (opcode[i*4+2] << 16) | (opcode[i*4+3] << 24))


def op_analyse(op, pc):
    # print("pc: "+str(pc))
    a = rcode[pc+1]
    b = rcode[pc+2]
    print("#pc: %d, op: %x, a: %d, b: %d" % (pc, op, a, b))
    pc = pc + 3
    if op == 0x21:
        buf[a] = b
        # vstr = vstr+'buf['+str(a)+']='+str(b)+'\n'
        print("buf[%d]=%d" % (a, b))

    elif op == 0x22:
        buf[a] = buf[b]
        print("buf[%d]=buf[%d]" % (a, b))

    elif op == 0x23:
        buf[a] = rcode[buf[b]]
        print("buf[%d]=code[buf[%d]]" % (a, b))
        if buf[b] >= (0x204+0x6F)/4:
            print("# read patch")
        elif buf[b] >= 0x204/4:
            print("# read data offset: %d" % (buf[b]))
        else:
            print("# %d" % (buf[b]))

    elif op == 0x24:
        rcode[buf[a]] = buf[b]
        print("code[buf[%d]]=buf[%d]" % (a, b))
        if buf[a] >= (0x204+0x6F)/4:
            print("# write patch")
        elif buf[a] >= 0x204/4:
            print("# write data offset: %d" % (buf[a]))
        else:
            print("# %d" % (buf[a]))

    elif op == 0x25:
        buf[a] = buf[a] + buf[b]
        print("buf[%d]+=buf[%d]" % (a, b))

    elif op == 0x26:
        buf[a] = buf[a] - buf[b]
        print("buf[%d]-=buf[%d]" % (a, b))

    elif op == 0x27:
        buf[a] = buf[a] ^ buf[b]
        print("buf[%d]^=buf[%d]" % (a, b))

    elif op == 0x28:
        print("buf[%d]=buf[%d]<<(buf[%d]&0xFF)" % (a, a, b))
        buf[a] = buf[a] << (buf[b] & 0xFF)

    elif op == 0x29:
        buf[a] = buf[a] >> (buf[b] & 0xFF)
        print("buf[%d]=buf[%d]>>(buf[%d]&0xFF)" % (a, a, b))

    elif op == 0x2A:
        buf[a] = buf[a] & buf[b]
        print("buf[%d]&=buf[%d]" % (a, b))

    elif op == 0x2B:
        pc = buf[a]
        print("# pc = %d" % buf[a])
        print("jmp %d" % buf[a])

    elif op == 0x2C:
        print("if(buf[%d]==0):\n    #pc=buf[%d]\n    jmp: buf[%d]" % (b, a, a))
        if buf[b] == 0:
            pc = buf[a]

    elif op == 0x2D:
        print("if(buf[%d]!=0):\n    #pc=buf[%d]\n    jmp: buf[%d]" % (b, a, a))
        if buf[b] != 0:
            pc = buf[a]

    elif op == 0x2E:
        print("exit(0)")
        exit(0)

    elif op == 0x2F:
        print("#flag is right!")

    elif op == 0x30:
        print("#flag is wrong!")

    else:
        print("unreadable op: %x", op)
        exit(0)
    return pc


if __name__ == '__main__':
    pc = 0
    generate_code()
    while pc < len(rcode):
        op = rcode[pc]
        if op == 0x2F or op == 0x30:
            op_analyse(op, pc)
            print("# exit(0)")
            break
        pc = op_analyse(op, pc)

```

接下来就可以对输出进行分析整理了。

# 第 4 段：数据分析

第一次运行的输出如下：

```python
#pc: 0, op: 21, a: 0, b: 129
buf[0]=129
#pc: 3, op: 27, a: 1, b: 1
buf[1]^=buf[1]
#pc: 6, op: 24, a: 1, b: 1
code[buf[1]]=buf[1]
# 0
#pc: 9, op: 23, a: 2, b: 0
buf[2]=code[buf[0]]
# read data offset: 129
#pc: 12, op: 22, a: 3, b: 2
buf[3]=buf[2]
#pc: 15, op: 21, a: 4, b: 8
buf[4]=8
#pc: 18, op: 28, a: 3, b: 4
buf[3]=buf[3]<<(buf[4]&0xFF)
#pc: 21, op: 27, a: 2, b: 3
buf[2]^=buf[3]
#pc: 24, op: 28, a: 3, b: 4
buf[3]=buf[3]<<(buf[4]&0xFF)
#pc: 27, op: 27, a: 2, b: 3
buf[2]^=buf[3]
#pc: 30, op: 28, a: 3, b: 4
buf[3]=buf[3]<<(buf[4]&0xFF)
#pc: 33, op: 27, a: 2, b: 3
buf[2]^=buf[3]
#pc: 36, op: 27, a: 3, b: 3
buf[3]^=buf[3]
#pc: 39, op: 23, a: 4, b: 3
buf[4]=code[buf[3]]
# 0
#pc: 42, op: 24, a: 3, b: 2
code[buf[3]]=buf[2]
# 0
#pc: 45, op: 27, a: 2, b: 4
buf[2]^=buf[4]
#pc: 48, op: 24, a: 0, b: 2
code[buf[0]]=buf[2]
# write data offset: 129
#pc: 51, op: 21, a: 1, b: 1
buf[1]=1
#pc: 54, op: 25, a: 0, b: 1
buf[0]+=buf[1]
#pc: 57, op: 22, a: 1, b: 0
buf[1]=buf[0]
#pc: 60, op: 21, a: 2, b: 129
buf[2]=129
#pc: 63, op: 26, a: 1, b: 2
buf[1]-=buf[2]
#pc: 66, op: 21, a: 2, b: 9
buf[2]=9
#pc: 69, op: 26, a: 1, b: 2
buf[1]-=buf[2]
#pc: 72, op: 21, a: 2, b: 9
buf[2]=9
#pc: 75, op: 2d, a: 2, b: 1
if(buf[1]!=0):
    #pc=buf[2]
    jmp: buf[2]
#pc: 9, op: 23, a: 2, b: 0
buf[2]=code[buf[0]]
# read data offset: 130
#pc: 12, op: 22, a: 3, b: 2
buf[3]=buf[2]
#pc: 15, op: 21, a: 4, b: 8
buf[4]=8
#pc: 18, op: 28, a: 3, b: 4
buf[3]=buf[3]<<(buf[4]&0xFF)
#pc: 21, op: 27, a: 2, b: 3
buf[2]^=buf[3]
#pc: 24, op: 28, a: 3, b: 4
buf[3]=buf[3]<<(buf[4]&0xFF)
#pc: 27, op: 27, a: 2, b: 3
buf[2]^=buf[3]
#pc: 30, op: 28, a: 3, b: 4
buf[3]=buf[3]<<(buf[4]&0xFF)
#pc: 33, op: 27, a: 2, b: 3
buf[2]^=buf[3]
#pc: 36, op: 27, a: 3, b: 3
buf[3]^=buf[3]
#pc: 39, op: 23, a: 4, b: 3
buf[4]=code[buf[3]]
# 0
#pc: 42, op: 24, a: 3, b: 2
code[buf[3]]=buf[2]
# 0
#pc: 45, op: 27, a: 2, b: 4
buf[2]^=buf[4]
#pc: 48, op: 24, a: 0, b: 2
code[buf[0]]=buf[2]
# write data offset: 130
#pc: 51, op: 21, a: 1, b: 1
buf[1]=1
#pc: 54, op: 25, a: 0, b: 1
buf[0]+=buf[1]
#pc: 57, op: 22, a: 1, b: 0
buf[1]=buf[0]
#pc: 60, op: 21, a: 2, b: 129
buf[2]=129
#pc: 63, op: 26, a: 1, b: 2
buf[1]-=buf[2]
#pc: 66, op: 21, a: 2, b: 9
buf[2]=9
#pc: 69, op: 26, a: 1, b: 2
buf[1]-=buf[2]
#pc: 72, op: 21, a: 2, b: 9
buf[2]=9
#pc: 75, op: 2d, a: 2, b: 1
if(buf[1]!=0):
    #pc=buf[2]
    jmp: buf[2]
#pc: 9, op: 23, a: 2, b: 0
buf[2]=code[buf[0]]
# read data offset: 131
#pc: 12, op: 22, a: 3, b: 2
buf[3]=buf[2]
#pc: 15, op: 21, a: 4, b: 8
buf[4]=8
#pc: 18, op: 28, a: 3, b: 4
buf[3]=buf[3]<<(buf[4]&0xFF)
#pc: 21, op: 27, a: 2, b: 3
buf[2]^=buf[3]
#pc: 24, op: 28, a: 3, b: 4
buf[3]=buf[3]<<(buf[4]&0xFF)
#pc: 27, op: 27, a: 2, b: 3
buf[2]^=buf[3]
#pc: 30, op: 28, a: 3, b: 4
buf[3]=buf[3]<<(buf[4]&0xFF)
#pc: 33, op: 27, a: 2, b: 3
buf[2]^=buf[3]
#pc: 36, op: 27, a: 3, b: 3
buf[3]^=buf[3]
#pc: 39, op: 23, a: 4, b: 3
buf[4]=code[buf[3]]
# 0
#pc: 42, op: 24, a: 3, b: 2
code[buf[3]]=buf[2]
# 0
#pc: 45, op: 27, a: 2, b: 4
buf[2]^=buf[4]
#pc: 48, op: 24, a: 0, b: 2
code[buf[0]]=buf[2]
# write data offset: 131
#pc: 51, op: 21, a: 1, b: 1
buf[1]=1
#pc: 54, op: 25, a: 0, b: 1
buf[0]+=buf[1]
#pc: 57, op: 22, a: 1, b: 0
buf[1]=buf[0]
#pc: 60, op: 21, a: 2, b: 129
buf[2]=129
#pc: 63, op: 26, a: 1, b: 2
buf[1]-=buf[2]
#pc: 66, op: 21, a: 2, b: 9
buf[2]=9
#pc: 69, op: 26, a: 1, b: 2
buf[1]-=buf[2]
#pc: 72, op: 21, a: 2, b: 9
buf[2]=9
#pc: 75, op: 2d, a: 2, b: 1
if(buf[1]!=0):
    #pc=buf[2]
    jmp: buf[2]
#pc: 9, op: 23, a: 2, b: 0
buf[2]=code[buf[0]]
# read data offset: 132
#pc: 12, op: 22, a: 3, b: 2
buf[3]=buf[2]
#pc: 15, op: 21, a: 4, b: 8
buf[4]=8
#pc: 18, op: 28, a: 3, b: 4
buf[3]=buf[3]<<(buf[4]&0xFF)
#pc: 21, op: 27, a: 2, b: 3
buf[2]^=buf[3]
#pc: 24, op: 28, a: 3, b: 4
buf[3]=buf[3]<<(buf[4]&0xFF)
#pc: 27, op: 27, a: 2, b: 3
buf[2]^=buf[3]
#pc: 30, op: 28, a: 3, b: 4
buf[3]=buf[3]<<(buf[4]&0xFF)
#pc: 33, op: 27, a: 2, b: 3
buf[2]^=buf[3]
#pc: 36, op: 27, a: 3, b: 3
buf[3]^=buf[3]
#pc: 39, op: 23, a: 4, b: 3
buf[4]=code[buf[3]]
# 0
#pc: 42, op: 24, a: 3, b: 2
code[buf[3]]=buf[2]
# 0
#pc: 45, op: 27, a: 2, b: 4
buf[2]^=buf[4]
#pc: 48, op: 24, a: 0, b: 2
code[buf[0]]=buf[2]
# write data offset: 132
#pc: 51, op: 21, a: 1, b: 1
buf[1]=1
#pc: 54, op: 25, a: 0, b: 1
buf[0]+=buf[1]
#pc: 57, op: 22, a: 1, b: 0
buf[1]=buf[0]
#pc: 60, op: 21, a: 2, b: 129
buf[2]=129
#pc: 63, op: 26, a: 1, b: 2
buf[1]-=buf[2]
#pc: 66, op: 21, a: 2, b: 9
buf[2]=9
#pc: 69, op: 26, a: 1, b: 2
buf[1]-=buf[2]
#pc: 72, op: 21, a: 2, b: 9
buf[2]=9
#pc: 75, op: 2d, a: 2, b: 1
if(buf[1]!=0):
    #pc=buf[2]
    jmp: buf[2]
#pc: 9, op: 23, a: 2, b: 0
buf[2]=code[buf[0]]
# read data offset: 133
#pc: 12, op: 22, a: 3, b: 2
buf[3]=buf[2]
#pc: 15, op: 21, a: 4, b: 8
buf[4]=8
#pc: 18, op: 28, a: 3, b: 4
buf[3]=buf[3]<<(buf[4]&0xFF)
#pc: 21, op: 27, a: 2, b: 3
buf[2]^=buf[3]
#pc: 24, op: 28, a: 3, b: 4
buf[3]=buf[3]<<(buf[4]&0xFF)
#pc: 27, op: 27, a: 2, b: 3
buf[2]^=buf[3]
#pc: 30, op: 28, a: 3, b: 4
buf[3]=buf[3]<<(buf[4]&0xFF)
#pc: 33, op: 27, a: 2, b: 3
buf[2]^=buf[3]
#pc: 36, op: 27, a: 3, b: 3
buf[3]^=buf[3]
#pc: 39, op: 23, a: 4, b: 3
buf[4]=code[buf[3]]
# 0
#pc: 42, op: 24, a: 3, b: 2
code[buf[3]]=buf[2]
# 0
#pc: 45, op: 27, a: 2, b: 4
buf[2]^=buf[4]
#pc: 48, op: 24, a: 0, b: 2
code[buf[0]]=buf[2]
# write data offset: 133
#pc: 51, op: 21, a: 1, b: 1
buf[1]=1
#pc: 54, op: 25, a: 0, b: 1
buf[0]+=buf[1]
#pc: 57, op: 22, a: 1, b: 0
buf[1]=buf[0]
#pc: 60, op: 21, a: 2, b: 129
buf[2]=129
#pc: 63, op: 26, a: 1, b: 2
buf[1]-=buf[2]
#pc: 66, op: 21, a: 2, b: 9
buf[2]=9
#pc: 69, op: 26, a: 1, b: 2
buf[1]-=buf[2]
#pc: 72, op: 21, a: 2, b: 9
buf[2]=9
#pc: 75, op: 2d, a: 2, b: 1
if(buf[1]!=0):
    #pc=buf[2]
    jmp: buf[2]
#pc: 9, op: 23, a: 2, b: 0
buf[2]=code[buf[0]]
# read data offset: 134
#pc: 12, op: 22, a: 3, b: 2
buf[3]=buf[2]
#pc: 15, op: 21, a: 4, b: 8
buf[4]=8
#pc: 18, op: 28, a: 3, b: 4
buf[3]=buf[3]<<(buf[4]&0xFF)
#pc: 21, op: 27, a: 2, b: 3
buf[2]^=buf[3]
#pc: 24, op: 28, a: 3, b: 4
buf[3]=buf[3]<<(buf[4]&0xFF)
#pc: 27, op: 27, a: 2, b: 3
buf[2]^=buf[3]
#pc: 30, op: 28, a: 3, b: 4
buf[3]=buf[3]<<(buf[4]&0xFF)
#pc: 33, op: 27, a: 2, b: 3
buf[2]^=buf[3]
#pc: 36, op: 27, a: 3, b: 3
buf[3]^=buf[3]
#pc: 39, op: 23, a: 4, b: 3
buf[4]=code[buf[3]]
# 0
#pc: 42, op: 24, a: 3, b: 2
code[buf[3]]=buf[2]
# 0
#pc: 45, op: 27, a: 2, b: 4
buf[2]^=buf[4]
#pc: 48, op: 24, a: 0, b: 2
code[buf[0]]=buf[2]
# write data offset: 134
#pc: 51, op: 21, a: 1, b: 1
buf[1]=1
#pc: 54, op: 25, a: 0, b: 1
buf[0]+=buf[1]
#pc: 57, op: 22, a: 1, b: 0
buf[1]=buf[0]
#pc: 60, op: 21, a: 2, b: 129
buf[2]=129
#pc: 63, op: 26, a: 1, b: 2
buf[1]-=buf[2]
#pc: 66, op: 21, a: 2, b: 9
buf[2]=9
#pc: 69, op: 26, a: 1, b: 2
buf[1]-=buf[2]
#pc: 72, op: 21, a: 2, b: 9
buf[2]=9
#pc: 75, op: 2d, a: 2, b: 1
if(buf[1]!=0):
    #pc=buf[2]
    jmp: buf[2]
#pc: 9, op: 23, a: 2, b: 0
buf[2]=code[buf[0]]
# read data offset: 135
#pc: 12, op: 22, a: 3, b: 2
buf[3]=buf[2]
#pc: 15, op: 21, a: 4, b: 8
buf[4]=8
#pc: 18, op: 28, a: 3, b: 4
buf[3]=buf[3]<<(buf[4]&0xFF)
#pc: 21, op: 27, a: 2, b: 3
buf[2]^=buf[3]
#pc: 24, op: 28, a: 3, b: 4
buf[3]=buf[3]<<(buf[4]&0xFF)
#pc: 27, op: 27, a: 2, b: 3
buf[2]^=buf[3]
#pc: 30, op: 28, a: 3, b: 4
buf[3]=buf[3]<<(buf[4]&0xFF)
#pc: 33, op: 27, a: 2, b: 3
buf[2]^=buf[3]
#pc: 36, op: 27, a: 3, b: 3
buf[3]^=buf[3]
#pc: 39, op: 23, a: 4, b: 3
buf[4]=code[buf[3]]
# 0
#pc: 42, op: 24, a: 3, b: 2
code[buf[3]]=buf[2]
# 0
#pc: 45, op: 27, a: 2, b: 4
buf[2]^=buf[4]
#pc: 48, op: 24, a: 0, b: 2
code[buf[0]]=buf[2]
# write data offset: 135
#pc: 51, op: 21, a: 1, b: 1
buf[1]=1
#pc: 54, op: 25, a: 0, b: 1
buf[0]+=buf[1]
#pc: 57, op: 22, a: 1, b: 0
buf[1]=buf[0]
#pc: 60, op: 21, a: 2, b: 129
buf[2]=129
#pc: 63, op: 26, a: 1, b: 2
buf[1]-=buf[2]
#pc: 66, op: 21, a: 2, b: 9
buf[2]=9
#pc: 69, op: 26, a: 1, b: 2
buf[1]-=buf[2]
#pc: 72, op: 21, a: 2, b: 9
buf[2]=9
#pc: 75, op: 2d, a: 2, b: 1
if(buf[1]!=0):
    #pc=buf[2]
    jmp: buf[2]
#pc: 9, op: 23, a: 2, b: 0
buf[2]=code[buf[0]]
# read data offset: 136
#pc: 12, op: 22, a: 3, b: 2
buf[3]=buf[2]
#pc: 15, op: 21, a: 4, b: 8
buf[4]=8
#pc: 18, op: 28, a: 3, b: 4
buf[3]=buf[3]<<(buf[4]&0xFF)
#pc: 21, op: 27, a: 2, b: 3
buf[2]^=buf[3]
#pc: 24, op: 28, a: 3, b: 4
buf[3]=buf[3]<<(buf[4]&0xFF)
#pc: 27, op: 27, a: 2, b: 3
buf[2]^=buf[3]
#pc: 30, op: 28, a: 3, b: 4
buf[3]=buf[3]<<(buf[4]&0xFF)
#pc: 33, op: 27, a: 2, b: 3
buf[2]^=buf[3]
#pc: 36, op: 27, a: 3, b: 3
buf[3]^=buf[3]
#pc: 39, op: 23, a: 4, b: 3
buf[4]=code[buf[3]]
# 0
#pc: 42, op: 24, a: 3, b: 2
code[buf[3]]=buf[2]
# 0
#pc: 45, op: 27, a: 2, b: 4
buf[2]^=buf[4]
#pc: 48, op: 24, a: 0, b: 2
code[buf[0]]=buf[2]
# write data offset: 136
#pc: 51, op: 21, a: 1, b: 1
buf[1]=1
#pc: 54, op: 25, a: 0, b: 1
buf[0]+=buf[1]
#pc: 57, op: 22, a: 1, b: 0
buf[1]=buf[0]
#pc: 60, op: 21, a: 2, b: 129
buf[2]=129
#pc: 63, op: 26, a: 1, b: 2
buf[1]-=buf[2]
#pc: 66, op: 21, a: 2, b: 9
buf[2]=9
#pc: 69, op: 26, a: 1, b: 2
buf[1]-=buf[2]
#pc: 72, op: 21, a: 2, b: 9
buf[2]=9
#pc: 75, op: 2d, a: 2, b: 1
if(buf[1]!=0):
    #pc=buf[2]
    jmp: buf[2]
#pc: 9, op: 23, a: 2, b: 0
buf[2]=code[buf[0]]
# read data offset: 137
#pc: 12, op: 22, a: 3, b: 2
buf[3]=buf[2]
#pc: 15, op: 21, a: 4, b: 8
buf[4]=8
#pc: 18, op: 28, a: 3, b: 4
buf[3]=buf[3]<<(buf[4]&0xFF)
#pc: 21, op: 27, a: 2, b: 3
buf[2]^=buf[3]
#pc: 24, op: 28, a: 3, b: 4
buf[3]=buf[3]<<(buf[4]&0xFF)
#pc: 27, op: 27, a: 2, b: 3
buf[2]^=buf[3]
#pc: 30, op: 28, a: 3, b: 4
buf[3]=buf[3]<<(buf[4]&0xFF)
#pc: 33, op: 27, a: 2, b: 3
buf[2]^=buf[3]
#pc: 36, op: 27, a: 3, b: 3
buf[3]^=buf[3]
#pc: 39, op: 23, a: 4, b: 3
buf[4]=code[buf[3]]
# 0
#pc: 42, op: 24, a: 3, b: 2
code[buf[3]]=buf[2]
# 0
#pc: 45, op: 27, a: 2, b: 4
buf[2]^=buf[4]
#pc: 48, op: 24, a: 0, b: 2
code[buf[0]]=buf[2]
# write data offset: 137
#pc: 51, op: 21, a: 1, b: 1
buf[1]=1
#pc: 54, op: 25, a: 0, b: 1
buf[0]+=buf[1]
#pc: 57, op: 22, a: 1, b: 0
buf[1]=buf[0]
#pc: 60, op: 21, a: 2, b: 129
buf[2]=129
#pc: 63, op: 26, a: 1, b: 2
buf[1]-=buf[2]
#pc: 66, op: 21, a: 2, b: 9
buf[2]=9
#pc: 69, op: 26, a: 1, b: 2
buf[1]-=buf[2]
#pc: 72, op: 21, a: 2, b: 9
buf[2]=9
#pc: 75, op: 2d, a: 2, b: 1
if(buf[1]!=0):
    #pc=buf[2]
    jmp: buf[2]
#pc: 78, op: 21, a: 0, b: 129
buf[0]=129
#pc: 81, op: 22, a: 1, b: 0
buf[1]=buf[0]
#pc: 84, op: 21, a: 2, b: 9
buf[2]=9
#pc: 87, op: 25, a: 1, b: 2
buf[1]+=buf[2]
#pc: 90, op: 23, a: 3, b: 0
buf[3]=code[buf[0]]
# read data offset: 129
#pc: 93, op: 23, a: 4, b: 1
buf[4]=code[buf[1]]
# read data offset: 138
#pc: 96, op: 26, a: 3, b: 4
buf[3]-=buf[4]
#pc: 99, op: 21, a: 4, b: 126
buf[4]=126
#pc: 102, op: 2d, a: 4, b: 3
if(buf[3]!=0):
    #pc=buf[4]
    jmp: buf[4]
#pc: 126, op: 30, a: 0, b: 0
#flag is wrong!
# exit(0)
```

不过由于有大量的跳转，因此我们可以进行人工整理。第一轮人工整理的伪代码如下：

```c
0:
buf[0]=129
3:
buf[1]=0
6:
code[buf[1]]=0
9:
buf[2]=code[buf[0]]
12:
buf[3]=buf[2]
15:
buf[4]=8
18:
buf[3]=buf[3]<<buf[4]
21:
buf[2]^=buf[3]
24:
buf[3]=buf[3]<<buf[4]
27:
buf[2]^=buf[3]
30:
buf[3]=buf[3]<<buf[4]
33:
buf[2]^=buf[3]
36:
buf[3]=0
39:
buf[4]=code[buf[3]]
42:
code[buf[3]]=buf[2]
45:
buf[2]^=buf[4]
48:
code[buf[0]]=buf[2]
51:
buf[1]=1
54:
buf[0]+=buf[1]
57:
buf[1]=buf[0]
60:
buf[2]=129
63:
buf[1]-=buf[2]
66:
buf[2]=9
69:
buf[1]-=buf[2]
72:
buf[2]=9
75:
if(buf[1]!=0):
    pc=buf[2]
    // goto 9:
78:
buf[0]=129
81:
buf[1]=buf[0]
84:
buf[2]=9
87:
buf[1]+=buf[2]
90:
buf[3]=code[buf[0]]
93:
buf[4]=code[buf[1]]
96:
buf[3]-=buf[4]
99:
buf[4]=126
102:
if(buf[3]!=0):
    jmp: buf[4]
    // goto: 126
126:
print("flag is wrong")
```

第二轮整理的伪代码如下：

```c
// code[0]=t, buf[0]=i, buf[1]=j
0:
i=129
9:
code[i]=code[i]^(code[i]<<8)^(code[i]<<16)^(code[i]<<24)^code[i-1]^(code[i-1]<<8)^(code[i-1]<<16)^(code[i-1]<<24)
54:
i+=1
75:
if(i-138!=0):
    jmp: 9
96:
buf[3]=code[129]-code[138]
102:
if(buf[3]!=0):
    jmp: 126
126:
print("flag is wrong")
```

接下来我们用任意一个二进制文件编辑器看相关的位置，就大概能猜到他的判断过程了，它将偏移处的数字进行一个比较奇葩的异或（如上面的伪代码所示）然后和后面偏移为 9 的数字进行比较。如果错误的话就会输出 `wrong`。这样我们就能写出来解析脚本了。

# 第 5 段：flag 脚本

python 是真的慢。。但是写起来是真的快（电脑性能太差，枯了）

```python
binary = [
    0x38, 0x62, 0x64, 0x61, 0x65, 0x34, 0x35, 0x36, 0x2D, 0x35, 0x61, 0x63, 0x38, 0x2D, 0x31, 0x31,
    0x65, 0x39, 0x2D, 0x61, 0x31, 0x63, 0x31, 0x2D, 0x38, 0x38, 0x65, 0x39, 0x66, 0x65, 0x38, 0x30,
    0x66, 0x65, 0x61, 0x66, 0x65, 0x55, 0x63, 0x57, 0x01, 0x04, 0x53, 0x06, 0x49, 0x49, 0x49, 0x1F,
    0x1F, 0x07, 0x57, 0x51, 0x57, 0x43, 0x5F, 0x57, 0x57, 0x5E, 0x43, 0x57, 0x0A, 0x02, 0x57, 0x43,
    0x5E, 0x03, 0x5E, 0x57, 0x00, 0x00, 0x59, 0x0F
]

num = []

patch = []


def generate_num():
    for i in range(int(len(binary)/4)):
        num.append(binary[i*4] | (binary[i*4+1] << 8) |
                   (binary[i*4+2] << 16) | (binary[i*4+3] << 24))


def get_flag():
    for i in range(9):
        if i == 0:
            pre = 0
        else:
            pre = (patch[i-1] ^ (patch[i-1] << 8) ^
                   (patch[i-1] << 16) ^ (patch[i-1] << 24)) & 0xFFFFFFFF
        for j in range(0x7FFFFFFF+1):
            if ((j ^ (j << 8) ^ (j << 16) ^ (j << 24) ^ pre) & 0xFFFFFFFF) == num[i+9]:
                print(hex(j))
                patch.append(j)
                break


if __name__ == "__main__":
    generate_num()
    get_flag()
    for i in patch:
        print(hex(i))
    # for i in num:
    #     print(hex(i))

```

跑出来的结果大概是这个样子的：

```
(base) D:\CTF\CISCN2019\re\strange_int>python flag.py
0x34363065
0x61613564
0x3761352d
0x31312d32
0x392d3965
0x2d303032
0x39653838
0x30386566
0x66616566
```

然后我们就可以 patch 啦。

patch 之前是这个样子的：

![](https://raw.githubusercontent.com/40m41h42t/BlogPictures/master/201904/origin.png)

运行会输出这个结果：

![](https://raw.githubusercontent.com/40m41h42t/BlogPictures/master/201904/origin_run.png)

patch 改动的位置如下：

![](https://raw.githubusercontent.com/40m41h42t/BlogPictures/master/201904/patched.png)

运行结果如下：

![](https://raw.githubusercontent.com/40m41h42t/BlogPictures/master/201904/patched_run.png)

因此刚才 patch 的内容就是 flag 里面的内容了。

# 总结

真实地感觉到了逆向是一个耐心+细心的活，然后就是经验了。真的感谢[[CTF]（原创）第十二届全国大学生信息安全竞赛strange_int题解](<https://www.52pojie.cn/thread-936377-1-1.html>)这位大佬的题解，顺着走一遍发现没有想象中的那么难。自己的经验还是欠缺啊。。另外像耗子哥哥说的那样，可能得学一手符号执行了。。

# 其他

bochs 调试运行的命令（已添加全局变量）：

```bash
bochsdbg.exe -q -f bochsrc.bxrc
```

bochs 配置文件修改并重命名为 `bochsrc.bxrc`：

```diff
630c630
< floppya: 1_44=Image.bin, status=inserted
---
> floppya: 1_44=/dev/fd0, status=inserted
663,665c663,665
< #ata1: enabled=1, ioaddr1=0x170, ioaddr2=0x370, irq=15
< #ata2: enabled=0, ioaddr1=0x1e8, ioaddr2=0x3e0, irq=11
< #ata3: enabled=0, ioaddr1=0x168, ioaddr2=0x360, irq=9
---
> ata1: enabled=1, ioaddr1=0x170, ioaddr2=0x370, irq=15
> ata2: enabled=0, ioaddr1=0x1e8, ioaddr2=0x3e0, irq=11
> ata3: enabled=0, ioaddr1=0x168, ioaddr2=0x360, irq=9
718c718
< #ata0-master: type=disk, mode=flat, path="30M.sample"
---
> ata0-master: type=disk, mode=flat, path="30M.sample"
738,739c738,739
< boot: floppy
< #boot: disk
---
> #boot: floppy
> boot: disk
```

从 010 里面复制出来的二进制代码转换为数字数组的脚本：

```python
vop = '0x'
f = open('vcode', 'r')
for line in f.readlines():
    for ch in line:
        if ch == ' ':
            vop += ',0x'
        elif ch == '\n':
            vop += ',\n0x'
        else:
            vop += ch
f1 = open('vop', 'w')
f1.write(vop)
```