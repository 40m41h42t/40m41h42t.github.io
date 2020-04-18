---
title: data 段代码注入
date: 2020-04-18 21:29:16
tags:
---

我们可以通过向 data 段劫持代码并将程序的运行流劫持到这里实现我们希望的功能（包括执行恶意代码、软件保护等）。这一过程中可能是最复杂也是最重要的部分就是怎样将新增的代码注入到 data 段中了。

<!--more-->

在运行的过程中 ELF 的内存布局如下图所示：
![Linux内存布局](https://qrzbbs.oss-cn-shanghai.aliyuncs.com/202004/Linux内存布局.png)

二进制文件被映射到了 0x0804800 起始的地方。我们可以在 data 段上追加代码，由于 .bss 节在 data 段后面，我们需要预留出空间，否则 .bss 节在初始化的过程中会将我们插入的代码覆盖。当然我们也可以向 text 段之前插入代码，向 text 段前插入代码的方法叫做逆向 text 感染。

接下来我们开始详细解析 ELF 的格式。

ELF 的链接视图和执行视图如下图所示：
![链接视图和执行视图](https://qrzbbs.oss-cn-shanghai.aliyuncs.com/202004/链接视图和执行视图.png)
ELF 文件头的结构（Ehdr, ELF file header）如下所示：
``` c
typedef struct
{
  unsigned char	e_ident[EI_NIDENT];	/* Magic number and other info */
  Elf64_Half	e_type;			/* Object file type */
  Elf64_Half	e_machine;		/* Architecture */
  Elf64_Word	e_version;		/* Object file version */
  Elf64_Addr	e_entry;		/* Entry point virtual address */
  Elf64_Off	e_phoff;		/* Program header table file offset */
  Elf64_Off	e_shoff;		/* Section header table file offset */
  Elf64_Word	e_flags;		/* Processor-specific flags */
  Elf64_Half	e_ehsize;		/* ELF header size in bytes */
  Elf64_Half	e_phentsize;		/* Program header table entry size */
  Elf64_Half	e_phnum;		/* Program header table entry count */
  Elf64_Half	e_shentsize;		/* Section header table entry size */
  Elf64_Half	e_shnum;		/* Section header table entry count */
  Elf64_Half	e_shstrndx;		/* Section header string table index */
} Elf64_Ehdr;
```
我们可以通过 `e_phoff` 和 `e_shoff` 找到 Phdr 的位置和 Shdr 的位置。一般来说节头表（Shdr）在程序最后的位置，因此我们需要将节头表的偏移（`e_shoff`）扩大 `sizeof(parasite)` 个长度，也就是节头表后移。

ELF 程序头（Phdr, Program segment header）是对二进制中段的描述，其结构如下所示：
``` c
typedef struct
{
  Elf64_Word	p_type;			/* Segment type */
  Elf64_Word	p_flags;		/* Segment flags */
  Elf64_Off	p_offset;		/* Segment file offset */
  Elf64_Addr	p_vaddr;		/* Segment virtual address */
  Elf64_Addr	p_paddr;		/* Segment physical address */
  Elf64_Xword	p_filesz;		/* Segment size in file */
  Elf64_Xword	p_memsz;		/* Segment size in memory */
  Elf64_Xword	p_align;		/* Segment alignment */
} Elf64_Phdr;
```
可执行文件必然至少有一个 `p_type` 为 `PT_LOAD` 类型的段。text 段和 data 段的类型都是 `PT_LOAD`。一般情况下，text 段的偏移（`p_offset`）为 0 ，是可读可执行的（`p_flags = PF_X | PF_R`）而 data 段的不为 0，是可读可写的（`p_flags = PF_W | PF_R`），我们可以通过判断偏移来区分两个段。由于我们要扩展 data 段，这里需要修改其中的 `p_filesz` 和 `p_memsz`，分别是文件中的段大小和映射到内存中的段的大小。除此之外，由于我们需要执行 data 段上的代码，因此还需要设置 data 段的权限为可执行（`p_flags |= PF_X`）。

由于 bss 段的位置位于程序的结尾，我们可以通过 data 段的 `p_offset + p_filesz` 定位到 bss 段的位置。

ELF 的节头（Shdr, section header）是对程序执行过程中节的描述，它不是程序运行时必要的。但是如果没有节头确实会对 data 段注入造成一定的困扰。其结构如下所示：
``` c
typedef struct
{
  Elf64_Word	sh_name;		/* Section name (string tbl index) */
  Elf64_Word	sh_type;		/* Section type */
  Elf64_Xword	sh_flags;		/* Section flags */
  Elf64_Addr	sh_addr;		/* Section virtual addr at execution */
  Elf64_Off	sh_offset;		/* Section file offset */
  Elf64_Xword	sh_size;		/* Section size in bytes */
  Elf64_Word	sh_link;		/* Link to another section */
  Elf64_Word	sh_info;		/* Additional section information */
  Elf64_Xword	sh_addralign;		/* Section alignment */
  Elf64_Xword	sh_entsize;		/* Entry size if section holds table */
} Elf64_Shdr;
```
我们需要对所有大于等于 .bss 地址的节后移，在文件中是 `sh_offset` 参数，在运行时是 `sh_addr` 参数。

综上，注入算法已经很明确了：

1. `ehdr->e_shoff` 移动注入代码的长度
2. 定位到 data 段
  - 扩大 `phdr->p_filesz`
  - 扩大 `phdr->p_memsz`
  - 修改 data 段的权限
3. 修改 .bss 节及其后面的节的位置

详细的代码可以参考[这里](https://github.com/40m41h42t/data-infector)