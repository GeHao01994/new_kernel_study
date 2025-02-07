==============================
Memory Layout on AArch64 Linux
==============================

Author: Catalin Marinas <catalin.marinas@arm.com>

This document describes the virtual memory layout used by the AArch64
Linux kernel. The architecture allows up to 4 levels of translation
tables with a 4KB page size and up to 3 levels with a 64KB page size.

AArch64 Linux uses either 3 levels or 4 levels of translation tables
with the 4KB page configuration, allowing 39-bit (512GB) or 48-bit
(256TB) virtual addresses, respectively, for both user and kernel. With
64KB pages, only 2 levels of translation tables, allowing 42-bit (4TB)
virtual address, are used but the memory layout is the same.

ARMv8.2 adds optional support for Large Virtual Address space. This is
only available when running with a 64KB page size and expands the
number of descriptors in the first level of translation.

TTBRx selection is given by bit 55 of the virtual address. The
swapper_pg_dir contains only kernel (global) mappings while the user pgd
contains only user (non-global) mappings.  The swapper_pg_dir address is
written to TTBR1 and never written to TTBR0.

本文档描述了AArch64 Linux内核所使用的虚拟内存布局.
该架构支持最多4级转换表(使用4KB页面大小)和最多3级转换表(使用64KB页面大小).

在4KB页面配置下,AArch64 Linux使用3级或4级转换表,
分别为用户和内核提供39位(512GB)或48位(256TB)的虚拟地址空间.
在使用64KB页面时,仅使用2级转换表,提供42位(4TB)的虚拟地址空间,但内存布局是相同的.

ARMv8.2增加了对大型虚拟地址空间的可选支持.
这仅在以64KB页面大小运行时可用,并扩展了第一级转换中的描述符数量.

虚拟地址的第55位决定了使用哪个TTBRx(转换表基址寄存器).
swapper_pg_dir仅包含内核(全局)映射,而用户页全局目录(user pgd)仅包含用户(非全局)映射.
swapper_pg_dir的地址被写入TTBR1,并且从不被写入TTBR0.

AArch64 Linux memory layout with 4KB pages + 4 levels (48-bit)::

  Start			End			Size		Use
  -----------------------------------------------------------------------
  0000000000000000	0000ffffffffffff	 256TB		user
  ffff000000000000	ffff7fffffffffff	 128TB		kernel logical memory map
 [ffff600000000000	ffff7fffffffffff]	  32TB		[kasan shadow region]
  ffff800000000000	ffff80007fffffff	   2GB		modules
  ffff800080000000	fffffbffefffffff	 124TB		vmalloc
  fffffbfff0000000	fffffbfffdffffff	 224MB		fixed mappings (top down)
  fffffbfffe000000	fffffbfffe7fffff	   8MB		[guard region]
  fffffbfffe800000	fffffbffff7fffff	  16MB		PCI I/O space
  fffffbffff800000	fffffbffffffffff	   8MB		[guard region]
  fffffc0000000000	fffffdffffffffff	   2TB		vmemmap
  fffffe0000000000	ffffffffffffffff	   2TB		[guard region]


AArch64 Linux memory layout with 64KB pages + 3 levels (52-bit with HW support)::

  Start			End			Size		Use
  -----------------------------------------------------------------------
  0000000000000000	000fffffffffffff	   4PB		user
  fff0000000000000	ffff7fffffffffff	  ~4PB		kernel logical memory map
 [fffd800000000000	ffff7fffffffffff]	 512TB		[kasan shadow region]
  ffff800000000000	ffff80007fffffff	   2GB		modules
  ffff800080000000	fffffbffefffffff	 124TB		vmalloc
  fffffbfff0000000	fffffbfffdffffff	 224MB		fixed mappings (top down)
  fffffbfffe000000	fffffbfffe7fffff	   8MB		[guard region]
  fffffbfffe800000	fffffbffff7fffff	  16MB		PCI I/O space
  fffffbffff800000	fffffbffffffffff	   8MB		[guard region]
  fffffc0000000000	ffffffdfffffffff	  ~4TB		vmemmap
  ffffffe000000000	ffffffffffffffff	 128GB		[guard region]


Translation table lookup with 4KB pages::

  +--------+--------+--------+--------+--------+--------+--------+--------+
  |63    56|55    48|47    40|39    32|31    24|23    16|15     8|7      0|
  +--------+--------+--------+--------+--------+--------+--------+--------+
            |        |         |         |         |         |
            |        |         |         |         |         v
            |        |         |         |         |   [11:0]  in-page offset
            |        |         |         |         +-> [20:12] L3 index
            |        |         |         +-----------> [29:21] L2 index
            |        |         +---------------------> [38:30] L1 index
            |        +-------------------------------> [47:39] L0 index
            +----------------------------------------> [55] TTBR0/1


Translation table lookup with 64KB pages::

  +--------+--------+--------+--------+--------+--------+--------+--------+
  |63    56|55    48|47    40|39    32|31    24|23    16|15     8|7      0|
  +--------+--------+--------+--------+--------+--------+--------+--------+
            |        |    |               |              |
            |        |    |               |              v
            |        |    |               |            [15:0]  in-page offset
            |        |    |               +----------> [28:16] L3 index
            |        |    +--------------------------> [41:29] L2 index
            |        +-------------------------------> [47:42] L1 index (48-bit)
            |                                          [51:42] L1 index (52-bit)
            +----------------------------------------> [55] TTBR0/1

When using KVM without the Virtualization Host Extensions, the
hypervisor maps kernel pages in EL2 at a fixed (and potentially
random) offset from the linear mapping. See the kern_hyp_va macro and
kvm_update_va_mask function for more details. MMIO devices such as
GICv2 gets mapped next to the HYP idmap page, as do vectors when
ARM64_SPECTRE_V3A is enabled for particular CPUs.

When using KVM with the Virtualization Host Extensions, no additional
mappings are created, since the host kernel runs directly in EL2.

当在不使用虚拟化主机扩展（Virtualization Host Extensions）的情况下使用KVM时,
管理程序(hypervisor)会在线性映射的一个固定(且可能是随机的)偏移量处映射内核页
到EL2(异常级别2).
有关更多详细信息,请参阅kern_hyp_va宏和kvm_update_va_mask函数.
当为特定CPU启用ARM64_SPECTRE_V3A时,诸如GICv2之类的内存映射I/O(MMIO)设备
会被映射到HYP(Hypervisor)idmap页的旁边,向量表也是如此.

当使用带有虚拟化主机扩展的KVM时,不会创建额外的映射,因为宿主内核直接在EL2运行.

52-bit VA support in the kernel
-------------------------------
If the ARMv8.2-LVA optional feature is present, and we are running
with a 64KB page size; then it is possible to use 52-bits of address
space for both userspace and kernel addresses. However, any kernel
binary that supports 52-bit must also be able to fall back to 48-bit
at early boot time if the hardware feature is not present.

This fallback mechanism necessitates the kernel .text to be in the
higher addresses such that they are invariant to 48/52-bit VAs. Due
to the kasan shadow being a fraction of the entire kernel VA space,
the end of the kasan shadow must also be in the higher half of the
kernel VA space for both 48/52-bit. (Switching from 48-bit to 52-bit,
the end of the kasan shadow is invariant and dependent on ~0UL,
whilst the start address will "grow" towards the lower addresses).

In order to optimise phys_to_virt and virt_to_phys, the PAGE_OFFSET
is kept constant at 0xFFF0000000000000 (corresponding to 52-bit),
this obviates the need for an extra variable read. The physvirt
offset and vmemmap offsets are computed at early boot to enable
this logic.

As a single binary will need to support both 48-bit and 52-bit VA
spaces, the VMEMMAP must be sized large enough for 52-bit VAs and
also must be sized large enough to accommodate a fixed PAGE_OFFSET.

Most code in the kernel should not need to consider the VA_BITS, for
code that does need to know the VA size the variables are
defined as follows:

VA_BITS		constant	the *maximum* VA space size

VA_BITS_MIN	constant	the *minimum* VA space size

vabits_actual	variable	the *actual* VA space size


Maximum and minimum sizes can be useful to ensure that buffers are
sized large enough or that addresses are positioned close enough for
the "worst" case.

内核中的52位虚拟地址支持
-------------------------------
如果系统具备ARMv8.2-LVA(大型虚拟地址空间)可选功能,
并且我们使用的是64KB页面大小,那么用户空间和内核地址都可以使用52位的地址空间.
然而,任何支持52位的内核二进制文件在硬件不支持该功能时,也必须在系统早期启动时能够回退到48位.

这种回退机制要求内核的.text部分位于较高的地址,以便在48位和52位虚拟地址下都保持不变.
由于kasan(内核地址消毒器)的影子内存是整个内核虚拟地址空间的一小部分,
因此kasan影子内存的末端也必须在48位和52位虚拟地址的较高半部分。
在从48位切换到52位时,kasan影子内存的末端是不变的,依赖于~0UL
(即无符号长整型的最大值取反,代表地址空间的末端),而起始地址会“扩展”到较低的地址.

为了优化phys_to_virt(物理地址到虚拟地址的转换)和virt_to_phys(虚拟地址到物理地址的转换)函数,
PAGE_OFFSET(页面偏移量)保持为常量0xFFF0000000000000(对应52位),
这样就避免了额外的变量读取.
physvirt偏移量和vmemmap偏移量在系统早期启动时计算得出,以实现这一逻辑.

由于单个二进制文件需要同时支持48位和52位虚拟地址空间,因此VMEMMAP(虚拟内存映射)
的大小必须足够大,以适应52位虚拟地址,并且还必须足够大,以适应固定的PAGE_OFFSET.

内核中的大多数代码不需要考虑VA_BITS(虚拟地址位数).
对于确实需要知道虚拟地址大小的代码,相关变量定义如下:

VA_BITS: 常量,表示最大虚拟地址空间大小.
VA_BITS_MIN: 常量,表示最小虚拟地址空间大小.
vabits_actual: 变量,表示实际虚拟地址空间大小.

最大和最小尺寸对于确保缓冲区足够大或地址在"最坏"情况下足够接近是有用的.

52-bit userspace VAs
--------------------
To maintain compatibility with software that relies on the ARMv8.0
VA space maximum size of 48-bits, the kernel will, by default,
return virtual addresses to userspace from a 48-bit range.

Software can "opt-in" to receiving VAs from a 52-bit space by
specifying an mmap hint parameter that is larger than 48-bit.

For example:

.. code-block:: c

   maybe_high_address = mmap(~0UL, size, prot, flags,...);

It is also possible to build a debug kernel that returns addresses
from a 52-bit space by enabling the following kernel config options:

.. code-block:: sh

   CONFIG_EXPERT=y && CONFIG_ARM64_FORCE_52BIT=y

Note that this option is only intended for debugging applications
and should not be used in production.

52位用户空间虚拟地址
--------------------
为了保持与依赖于ARMv8.0架构下48位最大虚拟地址空间的软件的兼容性，
内核默认情况下会从48位范围内向用户空间返回虚拟地址.

软件可以通过指定一个大于48位的mmap提示参数来选择从52位空间中接收虚拟地址.

例如：

.. code-block:: c

maybe_high_address = mmap(~0UL, size, prot, flags,...);
此外,通过启用以下内核配置选项,还可以构建一个从52位空间中返回地址的调试内核:

.. code-block:: sh
CONFIG_EXPERT=y && CONFIG_ARM64_FORCE_52BIT=y
请注意,此选项仅用于调试应用程序,不应在生产环境中使用.
