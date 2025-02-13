// SPDX-License-Identifier: GPL-2.0-only
/*
 * Based on arch/arm/mm/init.c
 *
 * Copyright (C) 1995-2005 Russell King
 * Copyright (C) 2012 ARM Ltd.
 */

#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/errno.h>
#include <linux/swap.h>
#include <linux/init.h>
#include <linux/cache.h>
#include <linux/mman.h>
#include <linux/nodemask.h>
#include <linux/initrd.h>
#include <linux/gfp.h>
#include <linux/math.h>
#include <linux/memblock.h>
#include <linux/sort.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/dma-direct.h>
#include <linux/dma-map-ops.h>
#include <linux/efi.h>
#include <linux/swiotlb.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/kexec.h>
#include <linux/crash_dump.h>
#include <linux/hugetlb.h>
#include <linux/acpi_iort.h>
#include <linux/kmemleak.h>
#include <linux/execmem.h>

#include <asm/boot.h>
#include <asm/fixmap.h>
#include <asm/kasan.h>
#include <asm/kernel-pgtable.h>
#include <asm/kvm_host.h>
#include <asm/memory.h>
#include <asm/numa.h>
#include <asm/rsi.h>
#include <asm/sections.h>
#include <asm/setup.h>
#include <linux/sizes.h>
#include <asm/tlb.h>
#include <asm/alternative.h>
#include <asm/xen/swiotlb-xen.h>

/*
 * We need to be able to catch inadvertent references to memstart_addr
 * that occur (potentially in generic code) before arm64_memblock_init()
 * executes, which assigns it its actual value. So use a default value
 * that cannot be mistaken for a real physical address.
 */
s64 memstart_addr __ro_after_init = -1;
EXPORT_SYMBOL(memstart_addr);

/*
 * If the corresponding config options are enabled, we create both ZONE_DMA
 * and ZONE_DMA32. By default ZONE_DMA covers the 32-bit addressable memory
 * unless restricted on specific platforms (e.g. 30-bit on Raspberry Pi 4).
 * In such case, ZONE_DMA32 covers the rest of the 32-bit addressable memory,
 * otherwise it is empty.
 */
phys_addr_t __ro_after_init arm64_dma_phys_limit;

/*
 * To make optimal use of block mappings when laying out the linear
 * mapping, round down the base of physical memory to a size that can
 * be mapped efficiently, i.e., either PUD_SIZE (4k granule) or PMD_SIZE
 * (64k granule), or a multiple that can be mapped using contiguous bits
 * in the page tables: 32 * PMD_SIZE (16k granule)
 */
#if defined(CONFIG_ARM64_4K_PAGES)
#define ARM64_MEMSTART_SHIFT		PUD_SHIFT
#elif defined(CONFIG_ARM64_16K_PAGES)
#define ARM64_MEMSTART_SHIFT		CONT_PMD_SHIFT
#else
#define ARM64_MEMSTART_SHIFT		PMD_SHIFT
#endif

/*
 * sparsemem vmemmap imposes an additional requirement on the alignment of
 * memstart_addr, due to the fact that the base of the vmemmap region
 * has a direct correspondence, and needs to appear sufficiently aligned
 * in the virtual address space.
 */
#if ARM64_MEMSTART_SHIFT < SECTION_SIZE_BITS
#define ARM64_MEMSTART_ALIGN	(1UL << SECTION_SIZE_BITS)
#else
#define ARM64_MEMSTART_ALIGN	(1UL << ARM64_MEMSTART_SHIFT)
#endif

static void __init arch_reserve_crashkernel(void)
{
	unsigned long long low_size = 0;
	unsigned long long crash_base, crash_size;
	char *cmdline = boot_command_line;
	bool high = false;
	int ret;

	if (!IS_ENABLED(CONFIG_CRASH_RESERVE))
		return;

	ret = parse_crashkernel(cmdline, memblock_phys_mem_size(),
				&crash_size, &crash_base,
				&low_size, &high);
	if (ret)
		return;

	reserve_crashkernel_generic(cmdline, crash_size, crash_base,
				    low_size, high);
}

static phys_addr_t __init max_zone_phys(phys_addr_t zone_limit)
{
	return min(zone_limit, memblock_end_of_DRAM() - 1) + 1;
}

static void __init zone_sizes_init(void)
{
	unsigned long max_zone_pfns[MAX_NR_ZONES]  = {0};
	phys_addr_t __maybe_unused acpi_zone_dma_limit;
	phys_addr_t __maybe_unused dt_zone_dma_limit;
	/*
	 * #define DMA_BIT_MASK(n)	(((n) == 64) ? ~0ULL : ((1ULL<<(n))-1))
	 *
	 * 这里是这是32位
	 * 所以DMA_BIT_MASK = 0xffffffff
	 *
	 * static phys_addr_t __init max_zone_phys(phys_addr_t zone_limit)
	 *{
	 *	return min(zone_limit, memblock_end_of_DRAM() - 1) + 1;
	 *}
	 */
	phys_addr_t __maybe_unused dma32_phys_limit =
		max_zone_phys(DMA_BIT_MASK(32));

#ifdef CONFIG_ZONE_DMA
	/* 拿到dma_zone的limit */
	acpi_zone_dma_limit = acpi_iort_dma_get_max_cpu_address();
	dt_zone_dma_limit = of_dma_get_max_cpu_address(NULL);
	zone_dma_limit = min(dt_zone_dma_limit, acpi_zone_dma_limit);
	/*
	 * Information we get from firmware (e.g. DT dma-ranges) describe DMA
	 * bus constraints. Devices using DMA might have their own limitations.
	 * Some of them rely on DMA zone in low 32-bit memory. Keep low RAM
	 * DMA zone on platforms that have RAM there.
	 *
	 * 我们从固件(例如设备树中的dma-ranges属性)中获取的信息描述了DMA总线的约束条件.
	 * 使用DMA的设备可能有自己的限制.
	 * 其中一些设备依赖于低32位内存中的DMA区域.
	 * 在那些有低内存RAM的平台上,保留低RAM DMA区域.
	 */

	/* 低内存的平台,保留zone_dma_limit的区域 */
	if (memblock_start_of_DRAM() < U32_MAX)
		zone_dma_limit = min(zone_dma_limit, U32_MAX);

	/* 设置ZONE_DMA最大的PFN */
	arm64_dma_phys_limit = max_zone_phys(zone_dma_limit);
	max_zone_pfns[ZONE_DMA] = PFN_DOWN(arm64_dma_phys_limit);
#endif
#ifdef CONFIG_ZONE_DMA32
	/* 设置DMA32的最大PFN */
	max_zone_pfns[ZONE_DMA32] = PFN_DOWN(dma32_phys_limit);
	if (!arm64_dma_phys_limit)
		arm64_dma_phys_limit = dma32_phys_limit;
#endif
	if (!arm64_dma_phys_limit)
		arm64_dma_phys_limit = PHYS_MASK + 1;

	/* 设置ZONE_NORMAL的最大pfn */
	max_zone_pfns[ZONE_NORMAL] = max_pfn;

	/* Initialise all pg_data_t and zone data */
	free_area_init(max_zone_pfns);
}

int pfn_is_map_memory(unsigned long pfn)
{
	phys_addr_t addr = PFN_PHYS(pfn);

	/* avoid false positives for bogus PFNs, see comment in pfn_valid() */
	if (PHYS_PFN(addr) != pfn)
		return 0;

	return memblock_is_map_memory(addr);
}
EXPORT_SYMBOL(pfn_is_map_memory);

static phys_addr_t memory_limit __ro_after_init = PHYS_ADDR_MAX;

/*
 * Limit the memory size that was specified via FDT.
 */
static int __init early_mem(char *p)
{
	if (!p)
		return 1;

	memory_limit = memparse(p, &p) & PAGE_MASK;
	pr_notice("Memory limited to %lldMB\n", memory_limit >> 20);

	return 0;
}
early_param("mem", early_mem);

/*
 * 分析这段代码的时候我们用上面的文档中的例子
 * AArch64 Linux memory layout with 4KB pages + 4 levels (48-bit)
 * Start			End			Size		Use
 * -----------------------------------------------------------------------
 * 0000000000000000	0000ffffffffffff	 256TB		user
 * ffff000000000000	ffff7fffffffffff	 128TB		kernel logical memory map
 * [ffff600000000000	ffff7fffffffffff]	  32TB		[kasan shadow region]
 * ffff800000000000	ffff80007fffffff	   2GB		modules
 * ffff800080000000	fffffbffefffffff	 124TB		vmalloc
 * fffffbfff0000000	fffffbfffdffffff	 224MB		fixed mappings (top down)
 * fffffbfffe000000	fffffbfffe7fffff	   8MB		[guard region]
 * fffffbfffe800000	fffffbffff7fffff	  16MB		PCI I/O space
 * fffffbffff800000	fffffbffffffffff	   8MB		[guard region]
 * fffffc0000000000	fffffdffffffffff	   2TB		vmemmap
 * fffffe0000000000	ffffffffffffffff	   2TB		[guard region]
 *
 *
 * #define VA_BITS_MIN			(VA_BITS) = 0xffff000000000000
 * #define _PAGE_END(va)		(-(UL(1) << ((va) - 1))) = 0xffff800000000000
 */
void __init arm64_memblock_init(void)
{
	/*
	 * 这里说的是线性区域的大小,等于0xffff800000000000 - 0xffff000000000000 = 0x800000000000
	 * 和上面的kernel logical memory map是一样的
	 */
	s64 linear_region_size = PAGE_END - _PAGE_OFFSET(vabits_actual);

	/*
	 * Corner case: 52-bit VA capable systems running KVM in nVHE mode may
	 * be limited in their ability to support a linear map that exceeds 51
	 * bits of VA space, depending on the placement of the ID map. Given
	 * that the placement of the ID map may be randomized, let's simply
	 * limit the kernel's linear map to 51 bits as well if we detect this
	 * configuration.
	 *
	 * 特殊情况: 在 nVHE 模式下运行KVM的52 位虚拟地址(VA)能力系统,
	 * 可能会因为其身份映射(ID map)的放置位置,
	 * 而在支持超过51位虚拟地址空间的线性映射方面受到限制.
	 * 鉴于身份映射的放置位置可能是随机的,
	 * 如果我们检测到这种配置,那么就简单地也将内核的线性映射限制在 51 位
	 */
	if (IS_ENABLED(CONFIG_KVM) && vabits_actual == 52 &&
	    is_hyp_mode_available() && !is_kernel_in_hyp_mode()) {
		pr_info("Capping linear region to 51 bits for KVM in nVHE mode on LVA capable hardware.\n");
		linear_region_size = min_t(u64, linear_region_size, BIT(51));
	}

	/*
	 * Remove memory above our supported physical address size
	 *
	 * 移除超出我们支持的物理地址大小的内存
	 * 看起来是移除1ULL << PHYS_MASK_SHIFT ~ ULLONG_MAX
	 * 很正常,因为这里是物理地址啊,48位的寻址从0到1ULL << 48这么大的空间
	 */
	memblock_remove(1ULL << PHYS_MASK_SHIFT, ULLONG_MAX);

	/*
	 * Select a suitable value for the base of physical memory.
	 * 为物理内存的基址选择一个合适的值
	 */

	 /*
	  * lowest address
	  *
	  * phys_addr_t __init_memblock memblock_start_of_DRAM(void)
	  * {
	  *		return memblock.memory.regions[0].base;
	  * }
	  */
	memstart_addr = round_down(memblock_start_of_DRAM(),
				   ARM64_MEMSTART_ALIGN);

	  /*
	   * phys_addr_t __init_memblock memblock_end_of_DRAM(void)
	   * {
	   *		int idx = memblock.memory.cnt - 1;
	   *
	   *		return (memblock.memory.regions[idx].base + memblock.memory.regions[idx].size);
	   * }
	   */

	/*
	 * 如果memblock_end_of_DRAM - memstart_addr 大于linear_region_size,物理内存比这个线性映射区域还要大
	 * 那么报个警告出来
	 */
	if ((memblock_end_of_DRAM() - memstart_addr) > linear_region_size)
		pr_warn("Memory doesn't fit in the linear mapping, VA_BITS too small\n");

	/*
	 * Remove the memory that we will not be able to cover with the
	 * linear mapping. Take care not to clip the kernel which may be
	 * high in memory.
	 *
	 * 移除我们无法通过线性映射覆盖的内存.
	 * 注意不要裁剪掉可能位于内存高位的内核.
	 */
	/* 这边就是移除不是线性映射的区域 */
	memblock_remove(max_t(u64, memstart_addr + linear_region_size,
			__pa_symbol(_end)), ULLONG_MAX);

	/* 如果memstart_addr + linear_region_size 比 memblock_end_of_DRAM()小 */
	if (memstart_addr + linear_region_size < memblock_end_of_DRAM()) {
		/*
		 * ensure that memstart_addr remains sufficiently aligned
		 * 确保 memstart_addr 保持足够的对齐
		 */

		/* 这是准备拿最后一块来做吗？ */
		memstart_addr = round_up(memblock_end_of_DRAM() - linear_region_size,
					 ARM64_MEMSTART_ALIGN);
		memblock_remove(0, memstart_addr);
	}

	/*
	 * If we are running with a 52-bit kernel VA config on a system that
	 * does not support it, we have to place the available physical
	 * memory in the 48-bit addressable part of the linear region, i.e.,
	 * we have to move it upward. Since memstart_addr represents the
	 * physical address of PAGE_OFFSET, we have to *subtract* from it.
	 *
	 * 如果我们在一个不支持52位内核虚拟地址(VA)配置的系统上运行该配置,
	 * 我们必须将可用的物理内存放置在线性区域的48位可寻址部分,即我们需要将其向上移动.
	 * 由于memstart_addr表示PAGE_OFFSET的物理地址,我们需要从它那里减去一定的值
	 */

	/*
	 * #define _PAGE_OFFSET(va)	(-(UL(1) << (va)))
	 *
	 * _PAGE_OFFSET(vabits_actual) - _PAGE_OFFSET(52)
	 * 假设vabits_actual = 48
	 *  _PAGE_OFFSET(48) - _PAGE_OFFSET（52）
	 * 0x0xffff800000000000 - 0xffff000000000000
	 *
	 * 实际上这里应该是减去超过的部分
	 *
	 * 感觉这里应该是+才对吧？
	 */
	if (IS_ENABLED(CONFIG_ARM64_VA_BITS_52) && (vabits_actual != 52))
		memstart_addr -= _PAGE_OFFSET(vabits_actual) - _PAGE_OFFSET(52);

	/*
	 * Apply the memory limit if it was set. Since the kernel may be loaded
	 * high up in memory, add back the kernel region that must be accessible
	 * via the linear mapping.
	 *
	 * 如果设置了内存限制,则应用该限制.
	 * 由于内核可能被加载到内存的高地址区域,因此需要加上必须通过线性映射访问的内核区域.
	 */

	/*
	 * 这个memory_limit是可以通过启动参数来设置的
	 *  static int __init early_mem(char *p)
	 * {
	 *	if (!p)
	 *		return 1;
	 *
	 *	memory_limit = memparse(p, &p) & PAGE_MASK;
	 *	pr_notice("Memory limited to %lldMB\n", memory_limit >> 20);
	 *
	 *		return 0;
	 * }
	 *
	 * early_param("mem", early_mem);
	 *
	 * #define PHYS_ADDR_MAX	(~(phys_addr_t)0)
	 *
	 * 这里就是根据memory_limit来拔掉不在这范围之内的memblock
	 */
	if (memory_limit != PHYS_ADDR_MAX) {
		memblock_mem_limit_remove_map(memory_limit);
		/* 内核段的地址还是要保留呀 */
		memblock_add(__pa_symbol(_text), (u64)(_end - _text));
	}

	if (IS_ENABLED(CONFIG_BLK_DEV_INITRD) && phys_initrd_size) {
		/*
		 * Add back the memory we just removed if it results in the
		 * initrd to become inaccessible via the linear mapping.
		 * Otherwise, this is a no-op
		 *
		 * 如果移除内存会导致通过线性映射无法访问initrd,则重新添加刚刚移除的内存.
		 * 否则,这是一个不执行任何操作(无操作)的步骤.
		 */

		/* 让base进行页面对齐 */
		u64 base = phys_initrd_start & PAGE_MASK;
		/* 同样,这里是要让phys_initrd_start + phys_initrd_size 页面对齐后 - base */
		u64 size = PAGE_ALIGN(phys_initrd_start + phys_initrd_size) - base;

		/*
		 * We can only add back the initrd memory if we don't end up
		 * with more memory than we can address via the linear mapping.
		 * It is up to the bootloader to position the kernel and the
		 * initrd reasonably close to each other (i.e., within 32 GB of
		 * each other) so that all granule/#levels combinations can
		 * always access both.
		 *
		 * 只有当不会造成我们可通过线性映射访问的内存超出限制时,
		 * 我们才能将 initrd 内存重新加入.
		 * bootloader需要将内核和 initrd 合理地放置在彼此较近的位置
		 * (即,彼此之间的距离在 32 GB 以内)
		 * 以确保所有粒度/#级别组合始终能够访问这两者.这是启动加载器的责任.
		 */

		 /*
		  * 如果在memblock_start_of_DRAM和memblock_start_of_DRAM() +
		  * linear_region_size之外
		  * 那就报个警告吧
		  */
		if (WARN(base < memblock_start_of_DRAM() ||
			 base + size > memblock_start_of_DRAM() +
				       linear_region_size,
			"initrd not fully accessible via the linear mapping -- please check your bootloader ...\n")) {
			phys_initrd_size = 0;
		} else {
			/* 把它加到memblock中去 */
			memblock_add(base, size);
			/*
			 * 清楚nomap的flag
			 */
			memblock_clear_nomap(base, size);
			/* 放到reserve中去 */
			memblock_reserve(base, size);
		}
	}

	/*
	 * config RANDOMIZE_BASE
	 * bool "Randomize the address of the kernel image"
	 * select RELOCATABLE
	 * help
	 * Randomizes the virtual address at which the kernel image is
	 * loaded, as a security feature that deters exploit attempts
	 * relying on knowledge of the location of kernel internals.
	 *
	 * It is the bootloader's job to provide entropy, by passing a
	 * random u64 value in /chosen/kaslr-seed at kernel entry.
	 *
	 * When booting via the UEFI stub, it will invoke the firmware's
	 * EFI_RNG_PROTOCOL implementation (if available) to supply entropy
	 * to the kernel proper. In addition, it will randomise the physical
	 * location of the kernel Image as well.
	 *
	 * 随机化内核映像加载的虚拟地址,这是一种安全功能,可以阻止依赖于对内核内部结构位置的了解的攻击尝试.
	 *
	 * 引导加载程序的任务是提供随机性,通过在内核入口处的/chosen/kaslr-seed传递一个随机的 u64 值来实现.
	 *
	 * 当通过 UEFI 存根启动时,它将调用固件的 EFI_RNG_PROTOCOL 实现(如果可用)来为内核本身提供随机性.此外,它还会随机化内核映像的物理位置.
	 *
	 * If unsure, say N.
	 */
	if (IS_ENABLED(CONFIG_RANDOMIZE_BASE)) {
		extern u16 memstart_offset_seed;

		/*
		 * Use the sanitised version of id_aa64mmfr0_el1 so that linear
		 * map randomization can be enabled by shrinking the IPA space.
		 *
		 * 使用经过清理的id_aa64mmfr0_el1版本,以便通过缩小IPA空间来启用线性映射随机化.
		 */

		 /* 这里是获取PA的range,应该是48bit */
		u64 mmfr0 = read_sanitised_ftr_reg(SYS_ID_AA64MMFR0_EL1);
		int parange = cpuid_feature_extract_unsigned_field(
					mmfr0, ID_AA64MMFR0_EL1_PARANGE_SHIFT);
		 /*
		  * linear_region_size = 0x800000000000 - 0x1000000000000
		  *
		  */
		s64 range = linear_region_size -
			    BIT(id_aa64mmfr0_parange_to_phys_shift(parange));

		/*
		 * If the size of the linear region exceeds, by a sufficient
		 * margin, the size of the region that the physical memory can
		 * span, randomize the linear region as well.
		 *
		 * 如果线性区域的大小超过了物理内存所能覆盖的区域大小的一个足够大的幅度.
		 * 那么也将对线性区域进行随机化处理
		 */
		if (memstart_offset_seed > 0 && range >= (s64)ARM64_MEMSTART_ALIGN) {
			range /= ARM64_MEMSTART_ALIGN;
			memstart_addr -= ARM64_MEMSTART_ALIGN *
					 ((range * memstart_offset_seed) >> 16);
		}
	}

	/*
	 * Register the kernel text, kernel data, initrd, and initial
	 * pagetables with memblock.
	 *
	 * 使用memblock注册kernel text, kernel data, initrd, and initial
	 * pagetables.
	 */
	memblock_reserve(__pa_symbol(_stext), _end - _stext);
	if (IS_ENABLED(CONFIG_BLK_DEV_INITRD) && phys_initrd_size) {
		/* the generic initrd code expects virtual addresses */
		initrd_start = __phys_to_virt(phys_initrd_start);
		initrd_end = initrd_start + phys_initrd_size;
	}

	early_init_fdt_scan_reserved_mem();

	/* 记录high_memory为最高的地址 */
	high_memory = __va(memblock_end_of_DRAM() - 1) + 1;
}

void __init bootmem_init(void)
{
	unsigned long min, max;

	/* 拿到最小的PFN */
	min = PFN_UP(memblock_start_of_DRAM());
	/* 拿到最大的PFN */
	max = PFN_DOWN(memblock_end_of_DRAM());

	/* 做内存测试,看有没有坏块 */
	early_memtest(min << PAGE_SHIFT, max << PAGE_SHIFT);

	/* 把max_pfn和max_low_pfn都设置为max */
	max_pfn = max_low_pfn = max;
	min_low_pfn = min;

	arch_numa_init();

	/*
	 * must be done after arch_numa_init() which calls numa_init() to
	 * initialize node_online_map that gets used in hugetlb_cma_reserve()
	 * while allocating required CMA size across online nodes.
	 *
	 * 必须在调用numa_init()以初始化node_online_map的arch_numa_init()之后完成,
	 * node_online_map在跨在线节点分配所需的CMA(连续内存分配器)大小时,会被hugetlb_cma_reserve()使用
	 */
#if defined(CONFIG_HUGETLB_PAGE) && defined(CONFIG_CMA)
	arm64_hugetlb_cma_reserve();
#endif

	kvm_hyp_reserve();

	/*
	 * sparse_init() tries to allocate memory from memblock, so must be
	 * done after the fixed reservations
	 *
	 * sparse_init()尝试从内存块(memblock)中分配内存,因此必须在固定预留之后进行.
	 */
	sparse_init();
	zone_sizes_init();

	/*
	 * Reserve the CMA area after arm64_dma_phys_limit was initialised.
	 */
	dma_contiguous_reserve(arm64_dma_phys_limit);

	/*
	 * request_standard_resources() depends on crashkernel's memory being
	 * reserved, so do it here.
	 */
	arch_reserve_crashkernel();

	memblock_dump_all();
}

/*
 * mem_init() marks the free areas in the mem_map and tells us how much memory
 * is free.  This is done after various parts of the system have claimed their
 * memory after the kernel image.
 */
void __init mem_init(void)
{
	unsigned int flags = SWIOTLB_VERBOSE;
	bool swiotlb = max_pfn > PFN_DOWN(arm64_dma_phys_limit);

	if (is_realm_world()) {
		swiotlb = true;
		flags |= SWIOTLB_FORCE;
	}

	if (IS_ENABLED(CONFIG_DMA_BOUNCE_UNALIGNED_KMALLOC) && !swiotlb) {
		/*
		 * If no bouncing needed for ZONE_DMA, reduce the swiotlb
		 * buffer for kmalloc() bouncing to 1MB per 1GB of RAM.
		 */
		unsigned long size =
			DIV_ROUND_UP(memblock_phys_mem_size(), 1024);
		swiotlb_adjust_size(min(swiotlb_size_or_default(), size));
		swiotlb = true;
	}

	swiotlb_init(swiotlb, flags);
	swiotlb_update_mem_attributes();

	/* this will put all unused low memory onto the freelists */
	memblock_free_all();

	/*
	 * Check boundaries twice: Some fundamental inconsistencies can be
	 * detected at build time already.
	 */
#ifdef CONFIG_COMPAT
	BUILD_BUG_ON(TASK_SIZE_32 > DEFAULT_MAP_WINDOW_64);
#endif

	/*
	 * Selected page table levels should match when derived from
	 * scratch using the virtual address range and page size.
	 */
	BUILD_BUG_ON(ARM64_HW_PGTABLE_LEVELS(CONFIG_ARM64_VA_BITS) !=
		     CONFIG_PGTABLE_LEVELS);

	if (PAGE_SIZE >= 16384 && get_num_physpages() <= 128) {
		extern int sysctl_overcommit_memory;
		/*
		 * On a machine this small we won't get anywhere without
		 * overcommit, so turn it on by default.
		 */
		sysctl_overcommit_memory = OVERCOMMIT_ALWAYS;
	}
}

void free_initmem(void)
{
	void *lm_init_begin = lm_alias(__init_begin);
	void *lm_init_end = lm_alias(__init_end);

	WARN_ON(!IS_ALIGNED((unsigned long)lm_init_begin, PAGE_SIZE));
	WARN_ON(!IS_ALIGNED((unsigned long)lm_init_end, PAGE_SIZE));

	/* Delete __init region from memblock.reserved. */
	memblock_free(lm_init_begin, lm_init_end - lm_init_begin);

	free_reserved_area(lm_init_begin, lm_init_end,
			   POISON_FREE_INITMEM, "unused kernel");
	/*
	 * Unmap the __init region but leave the VM area in place. This
	 * prevents the region from being reused for kernel modules, which
	 * is not supported by kallsyms.
	 */
	vunmap_range((u64)__init_begin, (u64)__init_end);
}

void dump_mem_limit(void)
{
	if (memory_limit != PHYS_ADDR_MAX) {
		pr_emerg("Memory Limit: %llu MB\n", memory_limit >> 20);
	} else {
		pr_emerg("Memory Limit: none\n");
	}
}

#ifdef CONFIG_EXECMEM
static u64 module_direct_base __ro_after_init = 0;
static u64 module_plt_base __ro_after_init = 0;

/*
 * Choose a random page-aligned base address for a window of 'size' bytes which
 * entirely contains the interval [start, end - 1].
 */
static u64 __init random_bounding_box(u64 size, u64 start, u64 end)
{
	u64 max_pgoff, pgoff;

	if ((end - start) >= size)
		return 0;

	max_pgoff = (size - (end - start)) / PAGE_SIZE;
	pgoff = get_random_u32_inclusive(0, max_pgoff);

	return start - pgoff * PAGE_SIZE;
}

/*
 * Modules may directly reference data and text anywhere within the kernel
 * image and other modules. References using PREL32 relocations have a +/-2G
 * range, and so we need to ensure that the entire kernel image and all modules
 * fall within a 2G window such that these are always within range.
 *
 * Modules may directly branch to functions and code within the kernel text,
 * and to functions and code within other modules. These branches will use
 * CALL26/JUMP26 relocations with a +/-128M range. Without PLTs, we must ensure
 * that the entire kernel text and all module text falls within a 128M window
 * such that these are always within range. With PLTs, we can expand this to a
 * 2G window.
 *
 * We chose the 128M region to surround the entire kernel image (rather than
 * just the text) as using the same bounds for the 128M and 2G regions ensures
 * by construction that we never select a 128M region that is not a subset of
 * the 2G region. For very large and unusual kernel configurations this means
 * we may fall back to PLTs where they could have been avoided, but this keeps
 * the logic significantly simpler.
 */
static int __init module_init_limits(void)
{
	u64 kernel_end = (u64)_end;
	u64 kernel_start = (u64)_text;
	u64 kernel_size = kernel_end - kernel_start;

	/*
	 * The default modules region is placed immediately below the kernel
	 * image, and is large enough to use the full 2G relocation range.
	 */
	BUILD_BUG_ON(KIMAGE_VADDR != MODULES_END);
	BUILD_BUG_ON(MODULES_VSIZE < SZ_2G);

	if (!kaslr_enabled()) {
		if (kernel_size < SZ_128M)
			module_direct_base = kernel_end - SZ_128M;
		if (kernel_size < SZ_2G)
			module_plt_base = kernel_end - SZ_2G;
	} else {
		u64 min = kernel_start;
		u64 max = kernel_end;

		if (IS_ENABLED(CONFIG_RANDOMIZE_MODULE_REGION_FULL)) {
			pr_info("2G module region forced by RANDOMIZE_MODULE_REGION_FULL\n");
		} else {
			module_direct_base = random_bounding_box(SZ_128M, min, max);
			if (module_direct_base) {
				min = module_direct_base;
				max = module_direct_base + SZ_128M;
			}
		}

		module_plt_base = random_bounding_box(SZ_2G, min, max);
	}

	pr_info("%llu pages in range for non-PLT usage",
		module_direct_base ? (SZ_128M - kernel_size) / PAGE_SIZE : 0);
	pr_info("%llu pages in range for PLT usage",
		module_plt_base ? (SZ_2G - kernel_size) / PAGE_SIZE : 0);

	return 0;
}

static struct execmem_info execmem_info __ro_after_init;

struct execmem_info __init *execmem_arch_setup(void)
{
	unsigned long fallback_start = 0, fallback_end = 0;
	unsigned long start = 0, end = 0;

	module_init_limits();

	/*
	 * Where possible, prefer to allocate within direct branch range of the
	 * kernel such that no PLTs are necessary.
	 */
	if (module_direct_base) {
		start = module_direct_base;
		end = module_direct_base + SZ_128M;

		if (module_plt_base) {
			fallback_start = module_plt_base;
			fallback_end = module_plt_base + SZ_2G;
		}
	} else if (module_plt_base) {
		start = module_plt_base;
		end = module_plt_base + SZ_2G;
	}

	execmem_info = (struct execmem_info){
		.ranges = {
			[EXECMEM_DEFAULT] = {
				.start	= start,
				.end	= end,
				.pgprot	= PAGE_KERNEL,
				.alignment = 1,
				.fallback_start	= fallback_start,
				.fallback_end	= fallback_end,
			},
			[EXECMEM_KPROBES] = {
				.start	= VMALLOC_START,
				.end	= VMALLOC_END,
				.pgprot	= PAGE_KERNEL_ROX,
				.alignment = 1,
			},
			[EXECMEM_BPF] = {
				.start	= VMALLOC_START,
				.end	= VMALLOC_END,
				.pgprot	= PAGE_KERNEL,
				.alignment = 1,
			},
		},
	};

	return &execmem_info;
}
#endif /* CONFIG_EXECMEM */
