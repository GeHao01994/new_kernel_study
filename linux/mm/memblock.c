// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Procedures for maintaining information about logical memory blocks.
 *
 * Peter Bergner, IBM Corp.	June 2001.
 * Copyright (C) 2001 Peter Bergner.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/bitops.h>
#include <linux/poison.h>
#include <linux/pfn.h>
#include <linux/debugfs.h>
#include <linux/kmemleak.h>
#include <linux/seq_file.h>
#include <linux/memblock.h>

#include <asm/sections.h>
#include <linux/io.h>

#include "internal.h"

#define INIT_MEMBLOCK_REGIONS			128
#define INIT_PHYSMEM_REGIONS			4

#ifndef INIT_MEMBLOCK_RESERVED_REGIONS
# define INIT_MEMBLOCK_RESERVED_REGIONS		INIT_MEMBLOCK_REGIONS
#endif

#ifndef INIT_MEMBLOCK_MEMORY_REGIONS
#define INIT_MEMBLOCK_MEMORY_REGIONS		INIT_MEMBLOCK_REGIONS
#endif

/**
 * DOC: memblock overview
 *
 * Memblock is a method of managing memory regions during the early
 * boot period when the usual kernel memory allocators are not up and
 * running.
 *
 * Memblock views the system memory as collections of contiguous
 * regions. There are several types of these collections:
 *
 * * ``memory`` - describes the physical memory available to the
 *   kernel; this may differ from the actual physical memory installed
 *   in the system, for instance when the memory is restricted with
 *   ``mem=`` command line parameter
 * * ``reserved`` - describes the regions that were allocated
 * * ``physmem`` - describes the actual physical memory available during
 *   boot regardless of the possible restrictions and memory hot(un)plug;
 *   the ``physmem`` type is only available on some architectures.
 *
 * Each region is represented by struct memblock_region that
 * defines the region extents, its attributes and NUMA node id on NUMA
 * systems. Every memory type is described by the struct memblock_type
 * which contains an array of memory regions along with
 * the allocator metadata. The "memory" and "reserved" types are nicely
 * wrapped with struct memblock. This structure is statically
 * initialized at build time. The region arrays are initially sized to
 * %INIT_MEMBLOCK_MEMORY_REGIONS for "memory" and
 * %INIT_MEMBLOCK_RESERVED_REGIONS for "reserved". The region array
 * for "physmem" is initially sized to %INIT_PHYSMEM_REGIONS.
 * The memblock_allow_resize() enables automatic resizing of the region
 * arrays during addition of new regions. This feature should be used
 * with care so that memory allocated for the region array will not
 * overlap with areas that should be reserved, for example initrd.
 *
 * The early architecture setup should tell memblock what the physical
 * memory layout is by using memblock_add() or memblock_add_node()
 * functions. The first function does not assign the region to a NUMA
 * node and it is appropriate for UMA systems. Yet, it is possible to
 * use it on NUMA systems as well and assign the region to a NUMA node
 * later in the setup process using memblock_set_node(). The
 * memblock_add_node() performs such an assignment directly.
 *
 * Once memblock is setup the memory can be allocated using one of the
 * API variants:
 *
 * * memblock_phys_alloc*() - these functions return the **physical**
 *   address of the allocated memory
 * * memblock_alloc*() - these functions return the **virtual** address
 *   of the allocated memory.
 *
 * Note, that both API variants use implicit assumptions about allowed
 * memory ranges and the fallback methods. Consult the documentation
 * of memblock_alloc_internal() and memblock_alloc_range_nid()
 * functions for more elaborate description.
 *
 * As the system boot progresses, the architecture specific mem_init()
 * function frees all the memory to the buddy page allocator.
 *
 * Unless an architecture enables %CONFIG_ARCH_KEEP_MEMBLOCK, the
 * memblock data structures (except "physmem") will be discarded after the
 * system initialization completes.
 */

#ifndef CONFIG_NUMA
struct pglist_data __refdata contig_page_data;
EXPORT_SYMBOL(contig_page_data);
#endif

unsigned long max_low_pfn;
unsigned long min_low_pfn;
unsigned long max_pfn;
unsigned long long max_possible_pfn;

static struct memblock_region memblock_memory_init_regions[INIT_MEMBLOCK_MEMORY_REGIONS] __initdata_memblock;
static struct memblock_region memblock_reserved_init_regions[INIT_MEMBLOCK_RESERVED_REGIONS] __initdata_memblock;
#ifdef CONFIG_HAVE_MEMBLOCK_PHYS_MAP
static struct memblock_region memblock_physmem_init_regions[INIT_PHYSMEM_REGIONS];
#endif

/*
 * 这边应该说的是,分配出去的内存(也就是说正在用的内存都放到reserved里面)
 * memory是个整体的,也就是系统中的所有内存
 */
struct memblock memblock __initdata_memblock = {
	.memory.regions		= memblock_memory_init_regions,
	.memory.max		= INIT_MEMBLOCK_MEMORY_REGIONS,
	.memory.name		= "memory",

	.reserved.regions	= memblock_reserved_init_regions,
	.reserved.max		= INIT_MEMBLOCK_RESERVED_REGIONS,
	.reserved.name		= "reserved",

	.bottom_up		= false,
	.current_limit		= MEMBLOCK_ALLOC_ANYWHERE,
};

#ifdef CONFIG_HAVE_MEMBLOCK_PHYS_MAP
struct memblock_type physmem = {
	.regions		= memblock_physmem_init_regions,
	.max			= INIT_PHYSMEM_REGIONS,
	.name			= "physmem",
};
#endif

/*
 * keep a pointer to &memblock.memory in the text section to use it in
 * __next_mem_range() and its helpers.
 *  For architectures that do not keep memblock data after init, this
 * pointer will be reset to NULL at memblock_discard()
 */
static __refdata struct memblock_type *memblock_memory = &memblock.memory;

#define for_each_memblock_type(i, memblock_type, rgn)			\
	for (i = 0, rgn = &memblock_type->regions[0];			\
	     i < memblock_type->cnt;					\
	     i++, rgn = &memblock_type->regions[i])

#define memblock_dbg(fmt, ...)						\
	do {								\
		if (memblock_debug)					\
			pr_info(fmt, ##__VA_ARGS__);			\
	} while (0)

static int memblock_debug __initdata_memblock;
static bool system_has_some_mirror __initdata_memblock;
static int memblock_can_resize __initdata_memblock;
static int memblock_memory_in_slab __initdata_memblock;
static int memblock_reserved_in_slab __initdata_memblock;

bool __init_memblock memblock_has_mirror(void)
{
	return system_has_some_mirror;
}

static enum memblock_flags __init_memblock choose_memblock_flags(void)
{
	return system_has_some_mirror ? MEMBLOCK_MIRROR : MEMBLOCK_NONE;
}

/* adjust *@size so that (@base + *@size) doesn't overflow, return new size */
static inline phys_addr_t memblock_cap_size(phys_addr_t base, phys_addr_t *size)
{
	return *size = min(*size, PHYS_ADDR_MAX - base);
}

/*
 * Address comparison utilities
 */
unsigned long __init_memblock
memblock_addrs_overlap(phys_addr_t base1, phys_addr_t size1, phys_addr_t base2,
		       phys_addr_t size2)
{
	return ((base1 < (base2 + size2)) && (base2 < (base1 + size1)));
}

bool __init_memblock memblock_overlaps_region(struct memblock_type *type,
					phys_addr_t base, phys_addr_t size)
{
	unsigned long i;

	memblock_cap_size(base, &size);

	for (i = 0; i < type->cnt; i++)
		if (memblock_addrs_overlap(base, size, type->regions[i].base,
					   type->regions[i].size))
			return true;
	return false;
}

/**
 * __memblock_find_range_bottom_up - find free area utility in bottom-up
 * @start: start of candidate range
 * @end: end of candidate range, can be %MEMBLOCK_ALLOC_ANYWHERE or
 *       %MEMBLOCK_ALLOC_ACCESSIBLE
 * @size: size of free area to find
 * @align: alignment of free area to find
 * @nid: nid of the free area to find, %NUMA_NO_NODE for any node
 * @flags: pick from blocks based on memory attributes
 *
 * Utility called from memblock_find_in_range_node(), find free area bottom-up.
 *
 * Return:
 * Found address on success, 0 on failure.
 *
 * __memblock_find_range_bottom_up - 底部向上查找空闲区域的工具函数
 * @start: 候选范围的起始地址
 * @end: 候选范围的结束地址,可以是 %MEMBLOCK_ALLOC_ANYWHERE（任意位置)
 *       或%MEMBLOCK_ALLOC_ACCESSIBLE(可访问的位置)
 * @size: 需要查找的空闲区域的大小
 * @align: 需要查找的空闲区域的对齐方式
 * @nid: 需要查找的空闲区域所在的节点ID,%NUMA_NO_NODE 表示任意节点
 * @flags: 根据内存属性从块中选择
 *
 * 该工具函数从 memblock_find_in_range_node() 被调用,以底部向上的方式查找空闲区域.
 *
 * 返回值:
 * 成功时返回找到的地址,失败时返回0.
 */
static phys_addr_t __init_memblock
__memblock_find_range_bottom_up(phys_addr_t start, phys_addr_t end,
				phys_addr_t size, phys_addr_t align, int nid,
				enum memblock_flags flags)
{
	phys_addr_t this_start, this_end, cand;
	u64 i;

	/**
	 * clamp - return a value clamped to a given range with strict typechecking
	 * @val: current value
	 * @lo: lowest allowable value
	 * @hi: highest allowable value
	 *
	 * This macro does strict typechecking of @lo/@hi to make sure they are of the
	 * same type as @val.  See the unnecessary pointer comparisons.
	 *
	 * clamp - 对给定范围内的值进行严格类型检查并返回该范围内的值
	 * @val: 当前值
	 * @lo: 允许的最低值
	 * @hi: 允许的最高值
	 * 这个宏对 @lo 和 @hi 进行严格的类型检查，以确保它们与 @val 的类型相同
	 *
	 * #define clamp(val, lo, hi) __careful_clamp(val, lo, hi)
	 */
	for_each_free_mem_range(i, nid, flags, &this_start, &this_end, NULL) {
		this_start = clamp(this_start, start, end);
		this_end = clamp(this_end, start, end);
		/* 让start进行page_align */
		cand = round_up(this_start, align);

		/* 实际上这里的意思就是在start到end之间找到一块size大小的区域分配出去 */
		if (cand < this_end && this_end - cand >= size)
			return cand;
	}

	return 0;
}

/**
 * __memblock_find_range_top_down - find free area utility, in top-down
 * @start: start of candidate range
 * @end: end of candidate range, can be %MEMBLOCK_ALLOC_ANYWHERE or
 *       %MEMBLOCK_ALLOC_ACCESSIBLE
 * @size: size of free area to find
 * @align: alignment of free area to find
 * @nid: nid of the free area to find, %NUMA_NO_NODE for any node
 * @flags: pick from blocks based on memory attributes
 *
 * Utility called from memblock_find_in_range_node(), find free area top-down.
 *
 * Return:
 * Found address on success, 0 on failure.
 */
static phys_addr_t __init_memblock
__memblock_find_range_top_down(phys_addr_t start, phys_addr_t end,
			       phys_addr_t size, phys_addr_t align, int nid,
			       enum memblock_flags flags)
{
	phys_addr_t this_start, this_end, cand;
	u64 i;

	for_each_free_mem_range_reverse(i, nid, flags, &this_start, &this_end,
					NULL) {
		this_start = clamp(this_start, start, end);
		this_end = clamp(this_end, start, end);

		if (this_end < size)
			continue;

		cand = round_down(this_end - size, align);
		if (cand >= this_start)
			return cand;
	}

	return 0;
}

/**
 * memblock_find_in_range_node - find free area in given range and node
 * @size: size of free area to find
 * @align: alignment of free area to find
 * @start: start of candidate range
 * @end: end of candidate range, can be %MEMBLOCK_ALLOC_ANYWHERE or
 *       %MEMBLOCK_ALLOC_ACCESSIBLE
 * @nid: nid of the free area to find, %NUMA_NO_NODE for any node
 * @flags: pick from blocks based on memory attributes
 *
 * Find @size free area aligned to @align in the specified range and node.
 *
 * Return:
 * Found address on success, 0 on failure.
 *
 * memblock_find_in_range_node - 在给定范围和节点内查找空闲区域
 * @size: 要查找的空闲区域的大小
 * @align: 要查找的空闲区域的对齐方式
 * @start: 候选范围的起始地址
 * @end: 候选范围的结束地址,可以是 %MEMBLOCK_ALLOC_ANYWHERE（任意位置）或
 *	 %MEMBLOCK_ALLOC_ACCESSIBLE（可访问位置）
 * @nid: 要查找的空闲区域所在的节点ID,%NUMA_NO_NODE 表示任意节点
 * @flags: 根据内存属性从块中选择
 *
 * 在指定的范围和节点内查找大小为 @size 且对齐方式为 @align 的空闲区域.
 *
 * 返回值:
 * 成功时返回找到的地址,失败时返回0.
 */
static phys_addr_t __init_memblock memblock_find_in_range_node(phys_addr_t size,
					phys_addr_t align, phys_addr_t start,
					phys_addr_t end, int nid,
					enum memblock_flags flags)
{
	/* pump up @end */
	if (end == MEMBLOCK_ALLOC_ACCESSIBLE ||
	    end == MEMBLOCK_ALLOC_NOLEAKTRACE)
		end = memblock.current_limit;

	/* avoid allocating the first page */
	/* 这里的第一页应该是被uboot传递给内核的那些给占用了 */
	start = max_t(phys_addr_t, start, PAGE_SIZE);
	end = max(start, end);

	if (memblock_bottom_up())
		return __memblock_find_range_bottom_up(start, end, size, align,
						       nid, flags);
	else
		return __memblock_find_range_top_down(start, end, size, align,
						      nid, flags);
}

/**
 * memblock_find_in_range - find free area in given range
 * @start: start of candidate range
 * @end: end of candidate range, can be %MEMBLOCK_ALLOC_ANYWHERE or
 *       %MEMBLOCK_ALLOC_ACCESSIBLE
 * @size: size of free area to find
 * @align: alignment of free area to find
 *
 * Find @size free area aligned to @align in the specified range.
 *
 * Return:
 * Found address on success, 0 on failure.
 *
 * memblock_find_in_range - 在给定范围内查找空闲区域
 * @start: 候选范围的起始地址
 * @end: 候选范围的结束地址,可以是 %MEMBLOCK_ALLOC_ANYWHERE
 *       或%MEMBLOCK_ALLOC_ACCESSIBLE
 * @size: 要查找的空闲区域的大小
 * @align: 要查找的空闲区域的对齐方式
 *
 * 在指定的范围内查找大小为 @size 且对齐方式为 @align 的空闲区域.
 *
 * 返回值:
 * 成功时返回找到的地址,失败时返回0.
 */
static phys_addr_t __init_memblock memblock_find_in_range(phys_addr_t start,
					phys_addr_t end, phys_addr_t size,
					phys_addr_t align)
{
	phys_addr_t ret;
	enum memblock_flags flags = choose_memblock_flags();

again:
	ret = memblock_find_in_range_node(size, align, start, end,
					    NUMA_NO_NODE, flags);

	/* MEMBLOCK_MIRROR的意思是有镜像内存 */
	if (!ret && (flags & MEMBLOCK_MIRROR)) {
		pr_warn_ratelimited("Could not allocate %pap bytes of mirrored memory\n",
			&size);
		flags &= ~MEMBLOCK_MIRROR;
		goto again;
	}

	return ret;
}

static void __init_memblock memblock_remove_region(struct memblock_type *type, unsigned long r)
{
	type->total_size -= type->regions[r].size;
	memmove(&type->regions[r], &type->regions[r + 1],
		(type->cnt - (r + 1)) * sizeof(type->regions[r]));
	type->cnt--;

	/* Special case for empty arrays */
	if (type->cnt == 0) {
		WARN_ON(type->total_size != 0);
		type->regions[0].base = 0;
		type->regions[0].size = 0;
		type->regions[0].flags = 0;
		memblock_set_region_node(&type->regions[0], MAX_NUMNODES);
	}
}

#ifndef CONFIG_ARCH_KEEP_MEMBLOCK
/**
 * memblock_discard - discard memory and reserved arrays if they were allocated
 */
void __init memblock_discard(void)
{
	phys_addr_t addr, size;

	if (memblock.reserved.regions != memblock_reserved_init_regions) {
		addr = __pa(memblock.reserved.regions);
		size = PAGE_ALIGN(sizeof(struct memblock_region) *
				  memblock.reserved.max);
		if (memblock_reserved_in_slab)
			kfree(memblock.reserved.regions);
		else
			memblock_free_late(addr, size);
	}

	if (memblock.memory.regions != memblock_memory_init_regions) {
		addr = __pa(memblock.memory.regions);
		size = PAGE_ALIGN(sizeof(struct memblock_region) *
				  memblock.memory.max);
		if (memblock_memory_in_slab)
			kfree(memblock.memory.regions);
		else
			memblock_free_late(addr, size);
	}

	memblock_memory = NULL;
}
#endif

/**
 * memblock_double_array - double the size of the memblock regions array
 * @type: memblock type of the regions array being doubled
 * @new_area_start: starting address of memory range to avoid overlap with
 * @new_area_size: size of memory range to avoid overlap with
 *
 * Double the size of the @type regions array. If memblock is being used to
 * allocate memory for a new reserved regions array and there is a previously
 * allocated memory range [@new_area_start, @new_area_start + @new_area_size]
 * waiting to be reserved, ensure the memory used by the new array does
 * not overlap.
 *
 * Return:
 * 0 on success, -1 on failure.
 *
 * memblock_double_array - 将memblock区域数组的大小加倍
 * @type: 正在加倍的区域数组所属的memblock类型
 * @new_area_start: 需要避免重叠的内存范围的起始地址
 * @new_area_size: 需要避免重叠的内存范围的大小
 *
 * 将@type区域数组的大小加倍。如果memblock正在为新的保留区域数组分配内存，
 * 并且存在一个先前已分配的内存范围[@new_area_start, @new_area_start + @new_area_size]等待被保留，
 * 确保用于新数组的内存不与该范围重叠。
 */
static int __init_memblock memblock_double_array(struct memblock_type *type,
						phys_addr_t new_area_start,
						phys_addr_t new_area_size)
{
	struct memblock_region *new_array, *old_array;
	phys_addr_t old_alloc_size, new_alloc_size;
	phys_addr_t old_size, new_size, addr, new_end;
	/* 看看slab是不是available了 */
	int use_slab = slab_is_available();
	int *in_slab;

	/* We don't allow resizing until we know about the reserved regions
	 * of memory that aren't suitable for allocation
	 *
	 * 在了解哪些内存保留区域不适合分配之前，我们不允许调整大小
	 */
	if (!memblock_can_resize)
		panic("memblock: cannot resize %s array\n", type->name);

	/* Calculate new doubled size */
	/* 这里是乘以2 */
	old_size = type->max * sizeof(struct memblock_region);
	new_size = old_size << 1;
	/*
	 * We need to allocated new one align to PAGE_SIZE,
	 * so we can free them completely later.
	 *
	 * 我们需要分配一个新的,并且要与页面大小（PAGE_SIZE）对齐,
	 * 这样我们之后才能完全释放它们
	 */
	old_alloc_size = PAGE_ALIGN(old_size);
	new_alloc_size = PAGE_ALIGN(new_size);

	/*
	 * Retrieve the slab flag
	 * 检索(或获取)Slab标志
	 */
	if (type == &memblock.memory)
		in_slab = &memblock_memory_in_slab;
	else
		in_slab = &memblock_reserved_in_slab;

	/* Try to find some space for it */
	if (use_slab) {
		/* 通过kmalloc分配new_size */
		new_array = kmalloc(new_size, GFP_KERNEL);
		/* 获得new_array的物理地址 */
		addr = new_array ? __pa(new_array) : 0;
	} else {
		/*
		 * only exclude range when trying to double reserved.regions
		 * 仅在尝试将reserved.regions加倍时才排除该范围
		 */
		if (type != &memblock.reserved)
			new_area_start = new_area_size = 0;

		/* 找到空闲满足条件的地址空间的起始地址 */
		addr = memblock_find_in_range(new_area_start + new_area_size,
						memblock.current_limit,
						new_alloc_size, PAGE_SIZE);
		/*
		 * 如果没找到,那么重新从0到min(new_area_start, memblock.current_limit)开始找
		 * 怕他还有
		 */
		if (!addr && new_area_size)
			addr = memblock_find_in_range(0,
				min(new_area_start, memblock.current_limit),
				new_alloc_size, PAGE_SIZE);
		 /* 拿到它的虚拟地址 */
		new_array = addr ? __va(addr) : NULL;
	}
	if (!addr) {
		pr_err("memblock: Failed to double %s array from %ld to %ld entries !\n",
		       type->name, type->max, type->max * 2);
		return -1;
	}

	/* 这边就是double的new_end */
	new_end = addr + new_size - 1;
	memblock_dbg("memblock: %s is doubled to %ld at [%pa-%pa]",
			type->name, type->max * 2, &addr, &new_end);

	/*
	 * Found space, we now need to move the array over before we add the
	 * reserved region since it may be our reserved array itself that is
	 * full.
	 *
	 * 已找到空间,我们现在需要在添加保留区域之前移动数组,
	 * 因为这可能是我们的保留数组本身已经满了
	 */

	memcpy(new_array, type->regions, old_size);
	memset(new_array + type->max, 0, old_size);
	/* 保留旧的type->regions */
	old_array = type->regions;
	/* 把新的new_array赋值给type->regions */
	type->regions = new_array;
	/* tpye->max乘以2 */
	type->max <<= 1;

	/*
	 * Free old array. We needn't free it if the array is the static one
	 * 如果数组是静态的,则无需释放旧数组;否则,需要释放旧数组.
	 */

	/* 如果是用的slab,那么就调用kfree来释放这段内存 */
	if (*in_slab)
		kfree(old_array);
	/* 如果不是初始化的那段，那么就调用memblock_free来释放这段内存 */
	else if (old_array != memblock_memory_init_regions &&
		 old_array != memblock_reserved_init_regions)
		memblock_free(old_array, old_alloc_size);

	/*
	 * Reserve the new array if that comes from the memblock.  Otherwise, we
	 * needn't do it
	 *
	 * 如果新数组来自memblock,则保留它.
	 * 否则,我们无需这样做
	 */

	/* 把它放到memblock_reserve里面 */
	if (!use_slab)
		BUG_ON(memblock_reserve(addr, new_alloc_size));

	/* Update slab flag */
	*in_slab = use_slab;

	return 0;
}

/**
 * memblock_merge_regions - merge neighboring compatible regions
 * @type: memblock type to scan
 * @start_rgn: start scanning from (@start_rgn - 1)
 * @end_rgn: end scanning at (@end_rgn - 1)
 * Scan @type and merge neighboring compatible regions in [@start_rgn - 1, @end_rgn)
 *
 * memblock_merge_regions - 合并相邻的兼容区域
 * @type: 要扫描的memblock类型
 * @start_rgn: 从(@start_rgn - 1)开始扫描
 * @end_rgn: 在(@end_rgn - 1)结束扫描
 * 扫描@type类型，并合并[@start_rgn - 1, @end_rgn)范围内的相邻兼容区域
 */
static void __init_memblock memblock_merge_regions(struct memblock_type *type,
						   unsigned long start_rgn,
						   unsigned long end_rgn)
{
	int i = 0;
	/* 如果给定了start_rgn,那么我们需要从start_rgn - 1扫描,看看前一个能不能和它合并 */
	if (start_rgn)
		i = start_rgn - 1;
	/* end_rgn肯定是end_rgn和最后那个rgn的最小值啦 */
	end_rgn = min(end_rgn, type->cnt - 1);
	/* 这里就是从start_rgn - 1到end_rgn开始扫描了 */
	while (i < end_rgn) {
		/* 拿到对应的memblock_region */
		struct memblock_region *this = &type->regions[i];
		struct memblock_region *next = &type->regions[i + 1];

		/* 这里先判断是不是连续的,然后在判断node是不是一样的，最后在判断flag是不是一样的 */
		if (this->base + this->size != next->base ||
		    memblock_get_region_node(this) !=
		    memblock_get_region_node(next) ||
		    this->flags != next->flags) {
			/*
			 * 如果this->base + this->size > next->base,那么就出错了啊
			 * 怎么可能比下一个的base还大呢
			 */
			BUG_ON(this->base + this->size > next->base);
			i++;
			continue;
		}

		/*
		 * 如果上面的判断都不成立,那么说明可以合并,那就开始呗
		 * 让this和next合并成一块
		 */
		this->size += next->size;
		/*
		 * move forward from next + 1, index of which is i + 2
		 *
		 * 从下一个元素之后的元素(其索引为i+2)开始向前移动
		 */
		memmove(next, next + 1, (type->cnt - (i + 2)) * sizeof(*next));
		type->cnt--;
		end_rgn--;
	}
}

/**
 * memblock_insert_region - insert new memblock region
 * @type:	memblock type to insert into
 * @idx:	index for the insertion point
 * @base:	base address of the new region
 * @size:	size of the new region
 * @nid:	node id of the new region
 * @flags:	flags of the new region
 *
 * Insert new memblock region [@base, @base + @size) into @type at @idx.
 * @type must already have extra room to accommodate the new region.
 *
 * 在类型 @type 的 @idx 位置插入新的内存块区域[@base, @base + @size).
 * @type 必须已经有额外的空间来容纳这个新区域.
 */
static void __init_memblock memblock_insert_region(struct memblock_type *type,
						   int idx, phys_addr_t base,
						   phys_addr_t size,
						   int nid,
						   enum memblock_flags flags)
{
	struct memblock_region *rgn = &type->regions[idx];

	BUG_ON(type->cnt >= type->max);
	/*
	 * 这里就是把rgn 移动到rgn + 1的位置上
	 * 也就是往后移动一个位置,腾出位置给新来的
	 */
	memmove(rgn + 1, rgn, (type->cnt - idx) * sizeof(*rgn));
	rgn->base = base;
	rgn->size = size;
	rgn->flags = flags;
	memblock_set_region_node(rgn, nid);
	type->cnt++;
	type->total_size += size;
}

/**
 * memblock_add_range - add new memblock region
 * @type: memblock type to add new region into
 * @base: base address of the new region
 * @size: size of the new region
 * @nid: nid of the new region
 * @flags: flags of the new region
 *
 * Add new memblock region [@base, @base + @size) into @type.  The new region
 * is allowed to overlap with existing ones - overlaps don't affect already
 * existing regions.  @type is guaranteed to be minimal (all neighbouring
 * compatible regions are merged) after the addition.
 *
 * Return:
 * 0 on success, -errno on failure.
 *
 * 将新的内存块区域[@base, @base + @size)添加到@type中.
 * 新的区域允许与已存在的区域重叠 —— 重叠不会影响已存在的区域.
 * 在添加之后，@type保证是最小的(所有相邻的兼容区域都将被合并)
 */
static int __init_memblock memblock_add_range(struct memblock_type *type,
				phys_addr_t base, phys_addr_t size,
				int nid, enum memblock_flags flags)
{
	bool insert = false;
	phys_addr_t obase = base;
	phys_addr_t end = base + memblock_cap_size(base, &size);
	int idx, nr_new, start_rgn = -1, end_rgn;
	struct memblock_region *rgn;

	/* 如果size为0,那么直接返回0 */
	if (!size)
		return 0;

	/*
	 * special case for empty array
	 * 空数组的特殊情况
	 */
	/*
	 * 这里就是type->regions[0].size == 0的情况
	 * 就把这一块设置为regions[0]
	 */
	if (type->regions[0].size == 0) {
		WARN_ON(type->cnt != 0 || type->total_size);
		type->regions[0].base = base;
		type->regions[0].size = size;
		type->regions[0].flags = flags;
		memblock_set_region_node(&type->regions[0], nid);
		type->total_size = size;
		type->cnt = 1;
		return 0;
	}

	/*
	 * The worst case is when new range overlaps all existing regions,
	 * then we'll need type->cnt + 1 empty regions in @type. So if
	 * type->cnt * 2 + 1 is less than or equal to type->max, we know
	 * that there is enough empty regions in @type, and we can insert
	 * regions directly.
	 *
	 * 最坏的情况是新的范围与所有已存在的区域都重叠,
	 * 这时我们需要在@type中增加type->cnt + 1个空区域.
	 * 因此，如果type->cnt的两倍再加1小于或等于type->max,我们就知道@type中有足够的空区域,
	 * 可以直接插入新的区域
	 */
	if (type->cnt * 2 + 1 <= type->max)
		insert = true;

repeat:
	/*
	 * The following is executed twice.  Once with %false @insert and
	 * then with %true.  The first counts the number of regions needed
	 * to accommodate the new area.  The second actually inserts them.
	 *
	 * 下面的操作会执行两次. 一次是将@insert设为%false(假),另一次是设为%true(真).
	 * 第一次是为了计算容纳新区域所需的区域数量.第二次则是实际将这些新区域插入.
	 */
	base = obase;
	nr_new = 0;

	for_each_memblock_type(idx, type, rgn) {
		phys_addr_t rbase = rgn->base;
		phys_addr_t rend = rbase + rgn->size;
		/*
		 * 这边就是说看有没有重叠部分
		 *	rbase                      rend
		 * (end)  ↓			    ↓ (base)
		 *	   -------------------------
		 * 	  |                         |
		 *  	   -------------------------
		 *
		 */
		if (rbase >= end)
			break;
		if (rend <= base)
			continue;
		/*
		 * @rgn overlaps.  If it separates the lower part of new
		 * area, insert that portion.
		 *
		 * @rgn重叠. 如果它将新区域的较低部分分隔开，则插入该部分
		 */

		/*
		 * 这种情况就是base确定，但是end不一定，有可能大于rend,有可能小于
		 *	rbase                      rend
		 * base   ↓			    ↓
		 *	   -------------------------
		 * 	  |                         |
		 *  	   -------------------------
		 *
		 *
		 * 对于这种情况，至少要多出一块,也就是向下多出一块
		 * 从base->rbase
		 */
		if (rbase > base) {
#ifdef CONFIG_NUMA
			WARN_ON(nid != memblock_get_region_node(rgn));
#endif
			/* 如果两边的flags不相同,那么这里报个WARN */
			WARN_ON(flags != rgn->flags);
			/* 新块数目+1 */
			nr_new++;
			if (insert) {
				if (start_rgn == -1)
					start_rgn = idx;
				end_rgn = idx + 1;
				memblock_insert_region(type, idx++, base,
						       rbase - base, nid,
						       flags);
			}
		}
		/*
		 * area below @rend is dealt with, forget about it
		 * @rend以下的区域已经处理过了，不用管它
		 */
		base = min(rend, end);
	}

	/*
	 * insert the remaining portion
	 * 插入剩余的部分
	 */
	/*
	 * 这种情况就是end
	 *	 rbase                      rend  end
	 *        ↓			    ↓      ↓
	 *	   -------------------------      -
	 * 	  |                         |	   |
	 *  	   -------------------------	  -
	 *
	 */
	if (base < end) {
		nr_new++;
		if (insert) {
			if (start_rgn == -1)
				start_rgn = idx;
			end_rgn = idx + 1;
			memblock_insert_region(type, idx, base, end - base,
					       nid, flags);
		}
	}

	if (!nr_new)
		return 0;

	/*
	 * If this was the first round, resize array and repeat for actual
	 * insertions; otherwise, merge and return.
	 *
	 * 如果这是第一轮,则调整数组大小并重复进行实际的插入操作；否则，进行合并并返回
	 */
	if (!insert) {
		/*
		 * 这里就是说如果cnt + nr_new > type->max
		 * 那么重新为这个type分配空间,且大小为type->max * 2
		 */
		while (type->cnt + nr_new > type->max)
			if (memblock_double_array(type, obase, size) < 0)
				return -ENOMEM;
		insert = true;
		goto repeat;
	} else {
		memblock_merge_regions(type, start_rgn, end_rgn);
		return 0;
	}
}

/**
 * memblock_add_node - add new memblock region within a NUMA node
 * @base: base address of the new region
 * @size: size of the new region
 * @nid: nid of the new region
 * @flags: flags of the new region
 *
 * Add new memblock region [@base, @base + @size) to the "memory"
 * type. See memblock_add_range() description for mode details
 *
 * Return:
 * 0 on success, -errno on failure.
 */
int __init_memblock memblock_add_node(phys_addr_t base, phys_addr_t size,
				      int nid, enum memblock_flags flags)
{
	phys_addr_t end = base + size - 1;

	memblock_dbg("%s: [%pa-%pa] nid=%d flags=%x %pS\n", __func__,
		     &base, &end, nid, flags, (void *)_RET_IP_);

	return memblock_add_range(&memblock.memory, base, size, nid, flags);
}

/**
 * memblock_add - add new memblock region
 * @base: base address of the new region
 * @size: size of the new region
 *
 * Add new memblock region [@base, @base + @size) to the "memory"
 * type. See memblock_add_range() description for mode details
 *
 * Return:
 * 0 on success, -errno on failure.
 */
int __init_memblock memblock_add(phys_addr_t base, phys_addr_t size)
{
	phys_addr_t end = base + size - 1;

	memblock_dbg("%s: [%pa-%pa] %pS\n", __func__,
		     &base, &end, (void *)_RET_IP_);

	/* 这里就是把这段内存添加到全局变量的memblock.memory中去 */
	return memblock_add_range(&memblock.memory, base, size, MAX_NUMNODES, 0);
}

/**
 * memblock_validate_numa_coverage - check if amount of memory with
 * no node ID assigned is less than a threshold
 * @threshold_bytes: maximal memory size that can have unassigned node
 * ID (in bytes).
 *
 * A buggy firmware may report memory that does not belong to any node.
 * Check if amount of such memory is below @threshold_bytes.
 *
 * Return: true on success, false on failure.
 */
bool __init_memblock memblock_validate_numa_coverage(unsigned long threshold_bytes)
{
	unsigned long nr_pages = 0;
	unsigned long start_pfn, end_pfn, mem_size_mb;
	int nid, i;

	/* calculate lose page */
	for_each_mem_pfn_range(i, MAX_NUMNODES, &start_pfn, &end_pfn, &nid) {
		if (!numa_valid_node(nid))
			nr_pages += end_pfn - start_pfn;
	}

	if ((nr_pages << PAGE_SHIFT) > threshold_bytes) {
		mem_size_mb = memblock_phys_mem_size() >> 20;
		pr_err("NUMA: no nodes coverage for %luMB of %luMB RAM\n",
		       (nr_pages << PAGE_SHIFT) >> 20, mem_size_mb);
		return false;
	}

	return true;
}


/**
 * memblock_isolate_range - isolate given range into disjoint memblocks
 * @type: memblock type to isolate range for
 * @base: base of range to isolate
 * @size: size of range to isolate
 * @start_rgn: out parameter for the start of isolated region
 * @end_rgn: out parameter for the end of isolated region
 *
 * Walk @type and ensure that regions don't cross the boundaries defined by
 * [@base, @base + @size).  Crossing regions are split at the boundaries,
 * which may create at most two more regions.  The index of the first
 * region inside the range is returned in *@start_rgn and the index of the
 * first region after the range is returned in *@end_rgn.
 *
 * Return:
 * 0 on success, -errno on failure.
 *
 * memblock_isolate_range - 将给定范围隔离为不相交的内存块
 * @type: 要隔离范围的内存块类型
 * @base: 要隔离范围的起始地址
 * @size: 要隔离范围的大小
 * @start_rgn: 隔离区域起始位置的输出参数
 * @end_rgn: 隔离区域结束位置的输出参数
 * 遍历 @type 类型的内存块,并确保内存块区域不跨越由 [@base, @base + @size) 定义的边界.
 * 跨越边界的区域将在边界处被拆分，这最多可能会创建两个额外的区域.
 * 范围内第一个区域的索引将通过 *@start_rgn 返回,
 * 而范围后第一个区域的索引将通过 *@end_rgn 返回.
 *
 * 返回值:
 * 成功时返回 0,失败时返回 -errno.
 */
static int __init_memblock memblock_isolate_range(struct memblock_type *type,
					phys_addr_t base, phys_addr_t size,
					int *start_rgn, int *end_rgn)
{
	phys_addr_t end = base + memblock_cap_size(base, &size);
	int idx;
	struct memblock_region *rgn;

	*start_rgn = *end_rgn = 0;

	/* 如果size为0,那么直接返回0 */
	if (!size)
		return 0;

	/*
	 * we'll create at most two more regions
	 * 我们最多会再创建两个区域
	 */
	while (type->cnt + 2 > type->max)
		if (memblock_double_array(type, base, size) < 0)
			return -ENOMEM;

	for_each_memblock_type(idx, type, rgn) {
		phys_addr_t rbase = rgn->base;
		phys_addr_t rend = rbase + rgn->size;

		/* 这都是按地址大小排序的,如果rbase >=end了,那真可以break了 */
		if (rbase >= end)
			break;
		 /* 如果rend <= base,就说明我还比你大,那就下一位呗 */
		if (rend <= base)
			continue;

		/* 如果rbase比base小,那么说明在这里面 */
		if (rbase < base) {
			/*
			 * @rgn intersects from below.  Split and continue
			 * to process the next region - the new top half.
			 *
			 * rgn从下方相交.进行拆分,并继续处理下一个区域 - 即新的上半部分
			 */
			rgn->base = base;
			/*
			 * 那就让rgn->base = base,rgn->size -= base - rbase
			 * type->total_size -= base - rbase
			 */
			rgn->size -= base - rbase;
			type->total_size -= base - rbase;
			/*
			 * 这里就是把rbase以及 base - rbase大小区域的region
			 * 插入到idx，然后其他的整体平移1个单位
			 */
			memblock_insert_region(type, idx, rbase, base - rbase,
					       memblock_get_region_node(rgn),
					       rgn->flags);
		/* 如果说end小于rend */
		} else if (rend > end) {
			/*
			 * @rgn intersects from above.  Split and redo the
			 * current region - the new bottom half.
			 *
			 * 当上方有区域相交时. 拆分并重做当前区域 - 即新的下半部分.
			 */
			rgn->base = end;
			rgn->size -= end - rbase;
			type->total_size -= end - rbase;
			/*
			 * 注意这里有idx--,也就是说执行完毕后idx - 1
			 */
			memblock_insert_region(type, idx--, rbase, end - rbase,
					       memblock_get_region_node(rgn),
					       rgn->flags);
		} else {
			/*
			 * @rgn is fully contained, record it
			 * 实际上最后都会跑到这里,因为你上面有个idx--,那最后肯定是这一块了
			 */
			/* 记录这一块的位置 */
			if (!*end_rgn)
				*start_rgn = idx;
			*end_rgn = idx + 1;
		}
	}

	return 0;
}

static int __init_memblock memblock_remove_range(struct memblock_type *type,
					  phys_addr_t base, phys_addr_t size)
{
	int start_rgn, end_rgn;
	int i, ret;

	ret = memblock_isolate_range(type, base, size, &start_rgn, &end_rgn);
	if (ret)
		return ret;

	for (i = end_rgn - 1; i >= start_rgn; i--)
		memblock_remove_region(type, i);
	return 0;
}

int __init_memblock memblock_remove(phys_addr_t base, phys_addr_t size)
{
	phys_addr_t end = base + size - 1;

	memblock_dbg("%s: [%pa-%pa] %pS\n", __func__,
		     &base, &end, (void *)_RET_IP_);

	return memblock_remove_range(&memblock.memory, base, size);
}

/**
 * memblock_free - free boot memory allocation
 * @ptr: starting address of the  boot memory allocation
 * @size: size of the boot memory block in bytes
 *
 * Free boot memory block previously allocated by memblock_alloc_xx() API.
 * The freeing memory will not be released to the buddy allocator.
 */
void __init_memblock memblock_free(void *ptr, size_t size)
{
	if (ptr)
		memblock_phys_free(__pa(ptr), size);
}

/**
 * memblock_phys_free - free boot memory block
 * @base: phys starting address of the  boot memory block
 * @size: size of the boot memory block in bytes
 *
 * Free boot memory block previously allocated by memblock_phys_alloc_xx() API.
 * The freeing memory will not be released to the buddy allocator.
 */
int __init_memblock memblock_phys_free(phys_addr_t base, phys_addr_t size)
{
	phys_addr_t end = base + size - 1;

	memblock_dbg("%s: [%pa-%pa] %pS\n", __func__,
		     &base, &end, (void *)_RET_IP_);

	kmemleak_free_part_phys(base, size);
	return memblock_remove_range(&memblock.reserved, base, size);
}

int __init_memblock memblock_reserve(phys_addr_t base, phys_addr_t size)
{
	phys_addr_t end = base + size - 1;

	memblock_dbg("%s: [%pa-%pa] %pS\n", __func__,
		     &base, &end, (void *)_RET_IP_);

	return memblock_add_range(&memblock.reserved, base, size, MAX_NUMNODES, 0);
}

#ifdef CONFIG_HAVE_MEMBLOCK_PHYS_MAP
int __init_memblock memblock_physmem_add(phys_addr_t base, phys_addr_t size)
{
	phys_addr_t end = base + size - 1;

	memblock_dbg("%s: [%pa-%pa] %pS\n", __func__,
		     &base, &end, (void *)_RET_IP_);

	return memblock_add_range(&physmem, base, size, MAX_NUMNODES, 0);
}
#endif

/**
 * memblock_setclr_flag - set or clear flag for a memory region
 * @type: memblock type to set/clear flag for
 * @base: base address of the region
 * @size: size of the region
 * @set: set or clear the flag
 * @flag: the flag to update
 *
 * This function isolates region [@base, @base + @size), and sets/clears flag
 *
 * Return: 0 on success, -errno on failure.
 */
static int __init_memblock memblock_setclr_flag(struct memblock_type *type,
				phys_addr_t base, phys_addr_t size, int set, int flag)
{
	int i, ret, start_rgn, end_rgn;

	ret = memblock_isolate_range(type, base, size, &start_rgn, &end_rgn);
	if (ret)
		return ret;

	for (i = start_rgn; i < end_rgn; i++) {
		struct memblock_region *r = &type->regions[i];

		if (set)
			r->flags |= flag;
		else
			r->flags &= ~flag;
	}

	memblock_merge_regions(type, start_rgn, end_rgn);
	return 0;
}

/**
 * memblock_mark_hotplug - Mark hotpluggable memory with flag MEMBLOCK_HOTPLUG.
 * @base: the base phys addr of the region
 * @size: the size of the region
 *
 * Return: 0 on success, -errno on failure.
 */
int __init_memblock memblock_mark_hotplug(phys_addr_t base, phys_addr_t size)
{
	return memblock_setclr_flag(&memblock.memory, base, size, 1, MEMBLOCK_HOTPLUG);
}

/**
 * memblock_clear_hotplug - Clear flag MEMBLOCK_HOTPLUG for a specified region.
 * @base: the base phys addr of the region
 * @size: the size of the region
 *
 * Return: 0 on success, -errno on failure.
 */
int __init_memblock memblock_clear_hotplug(phys_addr_t base, phys_addr_t size)
{
	return memblock_setclr_flag(&memblock.memory, base, size, 0, MEMBLOCK_HOTPLUG);
}

/**
 * memblock_mark_mirror - Mark mirrored memory with flag MEMBLOCK_MIRROR.
 * @base: the base phys addr of the region
 * @size: the size of the region
 *
 * Return: 0 on success, -errno on failure.
 */
int __init_memblock memblock_mark_mirror(phys_addr_t base, phys_addr_t size)
{
	if (!mirrored_kernelcore)
		return 0;

	system_has_some_mirror = true;

	return memblock_setclr_flag(&memblock.memory, base, size, 1, MEMBLOCK_MIRROR);
}

/**
 * memblock_mark_nomap - Mark a memory region with flag MEMBLOCK_NOMAP.
 * @base: the base phys addr of the region
 * @size: the size of the region
 *
 * The memory regions marked with %MEMBLOCK_NOMAP will not be added to the
 * direct mapping of the physical memory. These regions will still be
 * covered by the memory map. The struct page representing NOMAP memory
 * frames in the memory map will be PageReserved()
 *
 * Note: if the memory being marked %MEMBLOCK_NOMAP was allocated from
 * memblock, the caller must inform kmemleak to ignore that memory
 *
 * Return: 0 on success, -errno on failure.
 *
 * memblock_mark_nomap - 使用MEMBLOCK_NOMAP标志标记一个内存区域.
 * @base: 该区域的基物理地址
 * @size: 该区域的大小
 *
 * 使用%MEMBLOCK_NOMAP标记的内存区域不会被添加到物理内存的直接映射中.
 * 这些区域仍然会被内存映射所覆盖.
 * 在内存映射中,代表NOMAP内存帧的struct page将被标记为PageReserved()(保留页).
 *
 * 注意: 如果正在被标记为%MEMBLOCK_NOMAP的内存是从memblock分配的,调用者必须通知kmemleak忽略那块内存.
 *
 * 返回值：成功时返回0，失败时返回-errno。
 */
int __init_memblock memblock_mark_nomap(phys_addr_t base, phys_addr_t size)
{
	return memblock_setclr_flag(&memblock.memory, base, size, 1, MEMBLOCK_NOMAP);
}

/**
 * memblock_clear_nomap - Clear flag MEMBLOCK_NOMAP for a specified region.
 * @base: the base phys addr of the region
 * @size: the size of the region
 *
 * Return: 0 on success, -errno on failure.
 *
 * memblock_clear_nomap - 清除指定区域的 MEMBLOCK_NOMAP 标志.
 * @base: 该区域的基地址(物理地址)
 * @size: 该区域的大小
 */
int __init_memblock memblock_clear_nomap(phys_addr_t base, phys_addr_t size)
{
	return memblock_setclr_flag(&memblock.memory, base, size, 0, MEMBLOCK_NOMAP);
}

/**
 * memblock_reserved_mark_noinit - Mark a reserved memory region with flag
 * MEMBLOCK_RSRV_NOINIT which results in the struct pages not being initialized
 * for this region.
 * @base: the base phys addr of the region
 * @size: the size of the region
 *
 * struct pages will not be initialized for reserved memory regions marked with
 * %MEMBLOCK_RSRV_NOINIT.
 *
 * Return: 0 on success, -errno on failure.
 */
int __init_memblock memblock_reserved_mark_noinit(phys_addr_t base, phys_addr_t size)
{
	return memblock_setclr_flag(&memblock.reserved, base, size, 1,
				    MEMBLOCK_RSRV_NOINIT);
}

static bool should_skip_region(struct memblock_type *type,
			       struct memblock_region *m,
			       int nid, int flags)
{
	int m_nid = memblock_get_region_node(m);

	/*
	 * we never skip regions when iterating memblock.reserved or physmem
	 * 在遍历memblock.reserved或physmem时,我们从不跳过任何区域.
	 */
	if (type != memblock_memory)
		return false;

	/*
	 * only memory regions are associated with nodes, check it
	 *
	 * 只有当内存区域与节点相关联时,才进行检查.
	 */
	if (numa_valid_node(nid) && nid != m_nid)
		return true;

	/*
	 * skip hotpluggable memory regions if needed
	 *
	 * 如果需要,则跳过可热插拔的内存区域.
	 */
	/* static inline bool movable_node_is_enabled(void)
	 *{
	 *	return movable_node_enabled;
	 *}
	 */
	if (movable_node_is_enabled() && memblock_is_hotpluggable(m) &&
	    !(flags & MEMBLOCK_HOTPLUG))
		return true;

	/*
	 * if we want mirror memory skip non-mirror memory regions
	 *
	 * 如果我们想要镜像内存,则跳过非镜像内存区域.
	 */
	if ((flags & MEMBLOCK_MIRROR) && !memblock_is_mirror(m))
		return true;

	/*
	 * skip nomap memory unless we were asked for it explicitly
	 *
	 * 除非明确请求,否则跳过nomap内存区域.
	 */
	if (!(flags & MEMBLOCK_NOMAP) && memblock_is_nomap(m))
		return true;

	/*
	 * skip driver-managed memory unless we were asked for it explicitly
	 *
	 * 除非明确请求,否则跳过由驱动程序管理的内存区域.
	 */
	if (!(flags & MEMBLOCK_DRIVER_MANAGED) && memblock_is_driver_managed(m))
		return true;

	return false;
}

/**
 * __next_mem_range - next function for for_each_free_mem_range() etc.
 * @idx: pointer to u64 loop variable
 * @nid: node selector, %NUMA_NO_NODE for all nodes
 * @flags: pick from blocks based on memory attributes
 * @type_a: pointer to memblock_type from where the range is taken
 * @type_b: pointer to memblock_type which excludes memory from being taken
 * @out_start: ptr to phys_addr_t for start address of the range, can be %NULL
 * @out_end: ptr to phys_addr_t for end address of the range, can be %NULL
 * @out_nid: ptr to int for nid of the range, can be %NULL
 *
 * Find the first area from *@idx which matches @nid, fill the out
 * parameters, and update *@idx for the next iteration.  The lower 32bit of
 * *@idx contains index into type_a and the upper 32bit indexes the
 * areas before each region in type_b.	For example, if type_b regions
 * look like the following,
 *
 *	0:[0-16), 1:[32-48), 2:[128-130)
 *
 * The upper 32bit indexes the following regions.
 *
 *	0:[0-0), 1:[16-32), 2:[48-128), 3:[130-MAX)
 *
 * As both region arrays are sorted, the function advances the two indices
 * in lockstep and returns each intersection.
 *
 * __next_mem_range - 用于for_each_free_mem_range()等函数的下一个遍历函数.
 * @idx: 指向u64类型循环变量的指针
 * @nid: 节点选择器,对于所有节点使用%NUMA_NO_NODE
 * @flags: 根据内存属性从区块中选择
 * @type_a: 从中选取范围的memblock类型的指针
 * @type_b: 指向memblock_type的指针,表示排除(不被占用)的内存块类型
 * @out_start: 指向物理起始地址(phys_addr_t类型)的指针,可以为%NULL
 * @out_end: 指向物理结束地址(phys_addr_t类型)的指针,可以为%NULL
 * @out_nid: 指向范围节点ID(int类型)的指针,可以为%NULL
 *
 * 从*@idx指向的位置开始,找到第一个匹配@nid的区域,填充输出参数,并更新*@idx以便下次迭代.
 * *@idx的低32位包含type_a中的索引,而高32位则索引type_b中每个区域之前的区域.
 *
 * 例如,如果type_b的区域如下所示:
 *
 * 	0:[0-16), 1:[32-48), 2:[128-130)
 *
 * 高32位索引以下的区域:
 *
 *	0:[0-0), 1:[16-32), 2:[48-128), 3:[130-MAX)
 *
 * 由于两个区域数组都是排序的,该函数会同步推进这两个索引,并返回每个交集.
 */
void __next_mem_range(u64 *idx, int nid, enum memblock_flags flags,
		      struct memblock_type *type_a,
		      struct memblock_type *type_b, phys_addr_t *out_start,
		      phys_addr_t *out_end, int *out_nid)
{
	/* 拿到idx的低32位 */
	int idx_a = *idx & 0xffffffff;
	/* 拿到idx的高32位 */
	int idx_b = *idx >> 32;

	/* 从idx_a到cnt的循环 */
	for (; idx_a < type_a->cnt; idx_a++) {
		/* 拿到对应的memblock_region */
		struct memblock_region *m = &type_a->regions[idx_a];

		phys_addr_t m_start = m->base;
		phys_addr_t m_end = m->base + m->size;
		int	    m_nid = memblock_get_region_node(m);

		/* 这里需要跳过某些区域 */
		if (should_skip_region(type_a, m, nid, flags))
			continue;

		/* 如果type_b为NULL,那么返回相应的输出参数 */
		if (!type_b) {
			if (out_start)
				*out_start = m_start;
			if (out_end)
				*out_end = m_end;
			if (out_nid)
				*out_nid = m_nid;
			/*
			 * idx_a计数 + 1
			 * 并且加上高32位(idx_b << 32)
			 */
			idx_a++;
			*idx = (u32)idx_a | (u64)idx_b << 32;
			return;
		}

		/*
		 * scan areas before each reservation
		 *
		 * 在每次预留之前扫描区域
		 */
		for (; idx_b < type_b->cnt + 1; idx_b++) {
			struct memblock_region *r;
			phys_addr_t r_start;
			phys_addr_t r_end;

			/*
			 * 经典之处在于这里
			 * 我们假设idx = 0;
			 *
			 * mstart                                   mend
			 * ↓                                         ↓
			 *   ________________________________________
			 *  |________________________________________|
			 *
			 *        _____________________________
			 *       |_____________________________|
			 *      ↑			       ↑
			 *     r->base                       r->end
			 *
			 * 那么r_start会在下面的赋值中转换成0, r_end会在下面的赋值中转换成r->base
			 * 所以拿到的还是不相交的部分
			 */
			/* 拿到相应的memblock_region */
			r = &type_b->regions[idx_b];
			/*
			 * 如果idx_b为NULL,那么设置为0
			 * 否则,拿到前一个的base
			 */
			r_start = idx_b ? r[-1].base + r[-1].size : 0;
			/*
			 * 如果idx_b < type_b->cnt,那么就是r->base
			 * 否则为PHYS_ADDR_MAX
			 */
			r_end = idx_b < type_b->cnt ?
				r->base : PHYS_ADDR_MAX;

			/*
			 * if idx_b advanced past idx_a,
			 * break out to advance idx_a
			 *
			 * 如果idx_b超过了idx_a,则跳出循环以推进idx_a
			 */
			/* 也就是说m_end比r_start要小,那肯定不会有重叠的了 */
			if (r_start >= m_end)
				break;
			/*
			 * if the two regions intersect, we're done
			 *
			 * 如果两个区域相交,那么我们就完成了
			 */

			/* 如果m_start < r_end */
			if (m_start < r_end) {
				/* 拿到m_start和r_start的最大值 */
				if (out_start)
					*out_start =
						max(m_start, r_start);
				/* 拿到m_end和r_end的最小值 */
				if (out_end)
					*out_end = min(m_end, r_end);
				if (out_nid)
					*out_nid = m_nid;
				/*
				 * The region which ends first is
				 * advanced for the next iteration.
				 *
				 * 先结束的那个区域将在下一次迭代中向前推进.
				 * 这里的意思应该是说他们有重叠部分吧
				 *
				 */
				if (m_end <= r_end)
					idx_a++;
				else
					idx_b++;
				/* 并上idx */
				*idx = (u32)idx_a | (u64)idx_b << 32;
				return;
			}
		}
	}

	/* signal end of iteration */
	*idx = ULLONG_MAX;
}

/**
 * __next_mem_range_rev - generic next function for for_each_*_range_rev()
 *
 * @idx: pointer to u64 loop variable
 * @nid: node selector, %NUMA_NO_NODE for all nodes
 * @flags: pick from blocks based on memory attributes
 * @type_a: pointer to memblock_type from where the range is taken
 * @type_b: pointer to memblock_type which excludes memory from being taken
 * @out_start: ptr to phys_addr_t for start address of the range, can be %NULL
 * @out_end: ptr to phys_addr_t for end address of the range, can be %NULL
 * @out_nid: ptr to int for nid of the range, can be %NULL
 *
 * Finds the next range from type_a which is not marked as unsuitable
 * in type_b.
 *
 * Reverse of __next_mem_range().
 */
void __init_memblock __next_mem_range_rev(u64 *idx, int nid,
					  enum memblock_flags flags,
					  struct memblock_type *type_a,
					  struct memblock_type *type_b,
					  phys_addr_t *out_start,
					  phys_addr_t *out_end, int *out_nid)
{
	int idx_a = *idx & 0xffffffff;
	int idx_b = *idx >> 32;

	if (*idx == (u64)ULLONG_MAX) {
		idx_a = type_a->cnt - 1;
		if (type_b != NULL)
			idx_b = type_b->cnt;
		else
			idx_b = 0;
	}

	for (; idx_a >= 0; idx_a--) {
		struct memblock_region *m = &type_a->regions[idx_a];

		phys_addr_t m_start = m->base;
		phys_addr_t m_end = m->base + m->size;
		int m_nid = memblock_get_region_node(m);

		if (should_skip_region(type_a, m, nid, flags))
			continue;

		if (!type_b) {
			if (out_start)
				*out_start = m_start;
			if (out_end)
				*out_end = m_end;
			if (out_nid)
				*out_nid = m_nid;
			idx_a--;
			*idx = (u32)idx_a | (u64)idx_b << 32;
			return;
		}

		/* scan areas before each reservation */
		for (; idx_b >= 0; idx_b--) {
			struct memblock_region *r;
			phys_addr_t r_start;
			phys_addr_t r_end;

			r = &type_b->regions[idx_b];
			r_start = idx_b ? r[-1].base + r[-1].size : 0;
			r_end = idx_b < type_b->cnt ?
				r->base : PHYS_ADDR_MAX;
			/*
			 * if idx_b advanced past idx_a,
			 * break out to advance idx_a
			 */

			if (r_end <= m_start)
				break;
			/* if the two regions intersect, we're done */
			if (m_end > r_start) {
				if (out_start)
					*out_start = max(m_start, r_start);
				if (out_end)
					*out_end = min(m_end, r_end);
				if (out_nid)
					*out_nid = m_nid;
				if (m_start >= r_start)
					idx_a--;
				else
					idx_b--;
				*idx = (u32)idx_a | (u64)idx_b << 32;
				return;
			}
		}
	}
	/* signal end of iteration */
	*idx = ULLONG_MAX;
}

/*
 * Common iterator interface used to define for_each_mem_pfn_range().
 */
void __init_memblock __next_mem_pfn_range(int *idx, int nid,
				unsigned long *out_start_pfn,
				unsigned long *out_end_pfn, int *out_nid)
{
	struct memblock_type *type = &memblock.memory;
	struct memblock_region *r;
	int r_nid;

	while (++*idx < type->cnt) {
		r = &type->regions[*idx];
		r_nid = memblock_get_region_node(r);

		if (PFN_UP(r->base) >= PFN_DOWN(r->base + r->size))
			continue;
		if (!numa_valid_node(nid) || nid == r_nid)
			break;
	}
	if (*idx >= type->cnt) {
		*idx = -1;
		return;
	}

	if (out_start_pfn)
		*out_start_pfn = PFN_UP(r->base);
	if (out_end_pfn)
		*out_end_pfn = PFN_DOWN(r->base + r->size);
	if (out_nid)
		*out_nid = r_nid;
}

/**
 * memblock_set_node - set node ID on memblock regions
 * @base: base of area to set node ID for
 * @size: size of area to set node ID for
 * @type: memblock type to set node ID for
 * @nid: node ID to set
 *
 * Set the nid of memblock @type regions in [@base, @base + @size) to @nid.
 * Regions which cross the area boundaries are split as necessary.
 *
 * Return:
 * 0 on success, -errno on failure.
 */
int __init_memblock memblock_set_node(phys_addr_t base, phys_addr_t size,
				      struct memblock_type *type, int nid)
{
#ifdef CONFIG_NUMA
	int start_rgn, end_rgn;
	int i, ret;

	ret = memblock_isolate_range(type, base, size, &start_rgn, &end_rgn);
	if (ret)
		return ret;

	for (i = start_rgn; i < end_rgn; i++)
		memblock_set_region_node(&type->regions[i], nid);

	memblock_merge_regions(type, start_rgn, end_rgn);
#endif
	return 0;
}

#ifdef CONFIG_DEFERRED_STRUCT_PAGE_INIT
/**
 * __next_mem_pfn_range_in_zone - iterator for for_each_*_range_in_zone()
 *
 * @idx: pointer to u64 loop variable
 * @zone: zone in which all of the memory blocks reside
 * @out_spfn: ptr to ulong for start pfn of the range, can be %NULL
 * @out_epfn: ptr to ulong for end pfn of the range, can be %NULL
 *
 * This function is meant to be a zone/pfn specific wrapper for the
 * for_each_mem_range type iterators. Specifically they are used in the
 * deferred memory init routines and as such we were duplicating much of
 * this logic throughout the code. So instead of having it in multiple
 * locations it seemed like it would make more sense to centralize this to
 * one new iterator that does everything they need.
 */
void __init_memblock
__next_mem_pfn_range_in_zone(u64 *idx, struct zone *zone,
			     unsigned long *out_spfn, unsigned long *out_epfn)
{
	int zone_nid = zone_to_nid(zone);
	phys_addr_t spa, epa;

	__next_mem_range(idx, zone_nid, MEMBLOCK_NONE,
			 &memblock.memory, &memblock.reserved,
			 &spa, &epa, NULL);

	while (*idx != U64_MAX) {
		unsigned long epfn = PFN_DOWN(epa);
		unsigned long spfn = PFN_UP(spa);

		/*
		 * Verify the end is at least past the start of the zone and
		 * that we have at least one PFN to initialize.
		 */
		if (zone->zone_start_pfn < epfn && spfn < epfn) {
			/* if we went too far just stop searching */
			if (zone_end_pfn(zone) <= spfn) {
				*idx = U64_MAX;
				break;
			}

			if (out_spfn)
				*out_spfn = max(zone->zone_start_pfn, spfn);
			if (out_epfn)
				*out_epfn = min(zone_end_pfn(zone), epfn);

			return;
		}

		__next_mem_range(idx, zone_nid, MEMBLOCK_NONE,
				 &memblock.memory, &memblock.reserved,
				 &spa, &epa, NULL);
	}

	/* signal end of iteration */
	if (out_spfn)
		*out_spfn = ULONG_MAX;
	if (out_epfn)
		*out_epfn = 0;
}

#endif /* CONFIG_DEFERRED_STRUCT_PAGE_INIT */

/**
 * memblock_alloc_range_nid - allocate boot memory block
 * @size: size of memory block to be allocated in bytes
 * @align: alignment of the region and block's size
 * @start: the lower bound of the memory region to allocate (phys address)
 * @end: the upper bound of the memory region to allocate (phys address)
 * @nid: nid of the free area to find, %NUMA_NO_NODE for any node
 * @exact_nid: control the allocation fall back to other nodes
 *
 * The allocation is performed from memory region limited by
 * memblock.current_limit if @end == %MEMBLOCK_ALLOC_ACCESSIBLE.
 *
 * If the specified node can not hold the requested memory and @exact_nid
 * is false, the allocation falls back to any node in the system.
 *
 * For systems with memory mirroring, the allocation is attempted first
 * from the regions with mirroring enabled and then retried from any
 * memory region.
 *
 * In addition, function using kmemleak_alloc_phys for allocated boot
 * memory block, it is never reported as leaks.
 *
 * Return:
 * Physical address of allocated memory block on success, %0 on failure.
 *
 * memblock_alloc_range_nid - 分配启动内存块
 * @size: 要分配的内存块的大小(以字节为单位)
 * @align: 区域和内存块大小的对齐要求
 * @start: 要分配的内存区域的起始边界(物理地址)
 * @end: 要分配的内存区域的结束边界(物理地址)
 * @nid: 要查找的空闲区域的节点ID,%NUMA_NO_NODE表示任何节点
 * @exact_nid: 控制分配是否回退到其他节点
 *
 * 如果@end等于%MEMBLOCK_ALLOC_ACCESSIBLE,则分配将在由memblock.current_limit限制的内存区域内进行.
 * 如果指定的节点无法满足所需的内存大小,并且@exact_nid为假,则分配将回退到系统中的任何节点.
 *
 * 对于具有内存镜像功能的系统,分配将首先尝试从启用了镜像的区域进行,然后再从任何内存区域重试.
 * 此外,该函数使用kmemleak_alloc_phys为分配的启动内存块分配物理内存,这些内存块不会被报告为内存泄漏.
 *
 * 返回值:
 * 成功时返回分配的内存块的物理地址,失败时返回%0(即0).
 */
phys_addr_t __init memblock_alloc_range_nid(phys_addr_t size,
					phys_addr_t align, phys_addr_t start,
					phys_addr_t end, int nid,
					bool exact_nid)
{
	enum memblock_flags flags = choose_memblock_flags();
	phys_addr_t found;

	/*
	 * Detect any accidental use of these APIs after slab is ready, as at
	 * this moment memblock may be deinitialized already and its
	 * internal data may be destroyed (after execution of memblock_free_all)
	 *
	 * 检测在slab准备就绪后对这些API的任何意外使用,因为此时memblock可能已经被反初始化,
	 * 其内部数据可能已被销毁(在执行memblock_free_all之后)
	 */
	if (WARN_ON_ONCE(slab_is_available())) {
		void *vaddr = kzalloc_node(size, GFP_NOWAIT, nid);

		return vaddr ? virt_to_phys(vaddr) : 0;
	}

	if (!align) {
		/* Can't use WARNs this early in boot on powerpc */
		dump_stack();
		align = SMP_CACHE_BYTES;
	}

again:
	/* 这边就是在start和end区域找一块大小为size的内存 */
	found = memblock_find_in_range_node(size, align, start, end, nid,
					    flags);
	/* 如果找到了,把它放到reserve区域里面 */
	if (found && !memblock_reserve(found, size))
		goto done;

	/* 如果带了nid并且没有exact_nid(也就是说可以回退到其他节点),那么就在任意的nid中去找 */
	if (numa_valid_node(nid) && !exact_nid) {
		found = memblock_find_in_range_node(size, align, start,
						    end, NUMA_NO_NODE,
						    flags);
		/* 如果找到了,把它放到reserve区域里面 */
		if (found && !memblock_reserve(found, size))
			goto done;
	}

	/* 如果flags是带了有内存镜像的,那么清除这个flag之后报个警告 */
	if (flags & MEMBLOCK_MIRROR) {
		flags &= ~MEMBLOCK_MIRROR;
		pr_warn_ratelimited("Could not allocate %pap bytes of mirrored memory\n",
			&size);
		goto again;
	}

	return 0;

done:
	/*
	 * Skip kmemleak for those places like kasan_init() and
	 * early_pgtable_alloc() due to high volume.
	 *
	 * 由于数据量大,对于诸如kasan_init()和early_pgtable_alloc()等位置,跳过kmemleak的内存泄漏检测.
	 */
	if (end != MEMBLOCK_ALLOC_NOLEAKTRACE)
		/*
		 * Memblock allocated blocks are never reported as
		 * leaks. This is because many of these blocks are
		 * only referred via the physical address which is
		 * not looked up by kmemleak.
		 *
		 * 通过memblock分配的内存块从不会被报告为内存泄漏.
		 * 这是因为其中许多内存块仅通过物理地址进行引用,而kmemleak不会查找这些物理地址.
		 */
		kmemleak_alloc_phys(found, size, 0);

	/*
	 * Some Virtual Machine platforms, such as Intel TDX or AMD SEV-SNP,
	 * require memory to be accepted before it can be used by the
	 * guest.
	 *
	 * Accept the memory of the allocated buffer.
	 *
	 * 一些虚拟机平台,如Intel的TDX或AMD的SEV-SNP,要求内存必须在被客户机使用之前被接受.
	 * 接受已分配缓冲区的内存.
	 */
	accept_memory(found, size);

	return found;
}

/**
 * memblock_phys_alloc_range - allocate a memory block inside specified range
 * @size: size of memory block to be allocated in bytes
 * @align: alignment of the region and block's size
 * @start: the lower bound of the memory region to allocate (physical address)
 * @end: the upper bound of the memory region to allocate (physical address)
 *
 * Allocate @size bytes in the between @start and @end.
 *
 * Return: physical address of the allocated memory block on success,
 * %0 on failure.
 *
 * memblock_phys_alloc_range - 在指定范围内分配一个内存块
 * @size: 要分配的内存块的大小(以字节为单位)
 * @align: 区域和内存块大小的对齐要求
 * @start: 要分配的内存区域的起始边界(物理地址)
 * @end: 要分配的内存区域的结束边界(物理地址)
 * 在@start和@end之间分配@size字节的内存。
 * 返回值: 成功时返回分配的内存块的物理地址,失败时返回%0(即0).
 */
phys_addr_t __init memblock_phys_alloc_range(phys_addr_t size,
					     phys_addr_t align,
					     phys_addr_t start,
					     phys_addr_t end)
{
	memblock_dbg("%s: %llu bytes align=0x%llx from=%pa max_addr=%pa %pS\n",
		     __func__, (u64)size, (u64)align, &start, &end,
		     (void *)_RET_IP_);
	return memblock_alloc_range_nid(size, align, start, end, NUMA_NO_NODE,
					false);
}

/**
 * memblock_phys_alloc_try_nid - allocate a memory block from specified NUMA node
 * @size: size of memory block to be allocated in bytes
 * @align: alignment of the region and block's size
 * @nid: nid of the free area to find, %NUMA_NO_NODE for any node
 *
 * Allocates memory block from the specified NUMA node. If the node
 * has no available memory, attempts to allocated from any node in the
 * system.
 *
 * Return: physical address of the allocated memory block on success,
 * %0 on failure.
 */
phys_addr_t __init memblock_phys_alloc_try_nid(phys_addr_t size, phys_addr_t align, int nid)
{
	return memblock_alloc_range_nid(size, align, 0,
					MEMBLOCK_ALLOC_ACCESSIBLE, nid, false);
}

/**
 * memblock_alloc_internal - allocate boot memory block
 * @size: size of memory block to be allocated in bytes
 * @align: alignment of the region and block's size
 * @min_addr: the lower bound of the memory region to allocate (phys address)
 * @max_addr: the upper bound of the memory region to allocate (phys address)
 * @nid: nid of the free area to find, %NUMA_NO_NODE for any node
 * @exact_nid: control the allocation fall back to other nodes
 *
 * Allocates memory block using memblock_alloc_range_nid() and
 * converts the returned physical address to virtual.
 *
 * The @min_addr limit is dropped if it can not be satisfied and the allocation
 * will fall back to memory below @min_addr. Other constraints, such
 * as node and mirrored memory will be handled again in
 * memblock_alloc_range_nid().
 *
 * Return:
 * Virtual address of allocated memory block on success, NULL on failure.
 */
static void * __init memblock_alloc_internal(
				phys_addr_t size, phys_addr_t align,
				phys_addr_t min_addr, phys_addr_t max_addr,
				int nid, bool exact_nid)
{
	phys_addr_t alloc;


	if (max_addr > memblock.current_limit)
		max_addr = memblock.current_limit;

	alloc = memblock_alloc_range_nid(size, align, min_addr, max_addr, nid,
					exact_nid);

	/* retry allocation without lower limit */
	if (!alloc && min_addr)
		alloc = memblock_alloc_range_nid(size, align, 0, max_addr, nid,
						exact_nid);

	if (!alloc)
		return NULL;

	return phys_to_virt(alloc);
}

/**
 * memblock_alloc_exact_nid_raw - allocate boot memory block on the exact node
 * without zeroing memory
 * @size: size of memory block to be allocated in bytes
 * @align: alignment of the region and block's size
 * @min_addr: the lower bound of the memory region from where the allocation
 *	  is preferred (phys address)
 * @max_addr: the upper bound of the memory region from where the allocation
 *	      is preferred (phys address), or %MEMBLOCK_ALLOC_ACCESSIBLE to
 *	      allocate only from memory limited by memblock.current_limit value
 * @nid: nid of the free area to find, %NUMA_NO_NODE for any node
 *
 * Public function, provides additional debug information (including caller
 * info), if enabled. Does not zero allocated memory.
 *
 * Return:
 * Virtual address of allocated memory block on success, NULL on failure.
 */
void * __init memblock_alloc_exact_nid_raw(
			phys_addr_t size, phys_addr_t align,
			phys_addr_t min_addr, phys_addr_t max_addr,
			int nid)
{
	memblock_dbg("%s: %llu bytes align=0x%llx nid=%d from=%pa max_addr=%pa %pS\n",
		     __func__, (u64)size, (u64)align, nid, &min_addr,
		     &max_addr, (void *)_RET_IP_);

	return memblock_alloc_internal(size, align, min_addr, max_addr, nid,
				       true);
}

/**
 * memblock_alloc_try_nid_raw - allocate boot memory block without zeroing
 * memory and without panicking
 * @size: size of memory block to be allocated in bytes
 * @align: alignment of the region and block's size
 * @min_addr: the lower bound of the memory region from where the allocation
 *	  is preferred (phys address)
 * @max_addr: the upper bound of the memory region from where the allocation
 *	      is preferred (phys address), or %MEMBLOCK_ALLOC_ACCESSIBLE to
 *	      allocate only from memory limited by memblock.current_limit value
 * @nid: nid of the free area to find, %NUMA_NO_NODE for any node
 *
 * Public function, provides additional debug information (including caller
 * info), if enabled. Does not zero allocated memory, does not panic if request
 * cannot be satisfied.
 *
 * Return:
 * Virtual address of allocated memory block on success, NULL on failure.
 */
void * __init memblock_alloc_try_nid_raw(
			phys_addr_t size, phys_addr_t align,
			phys_addr_t min_addr, phys_addr_t max_addr,
			int nid)
{
	memblock_dbg("%s: %llu bytes align=0x%llx nid=%d from=%pa max_addr=%pa %pS\n",
		     __func__, (u64)size, (u64)align, nid, &min_addr,
		     &max_addr, (void *)_RET_IP_);

	return memblock_alloc_internal(size, align, min_addr, max_addr, nid,
				       false);
}

/**
 * memblock_alloc_try_nid - allocate boot memory block
 * @size: size of memory block to be allocated in bytes
 * @align: alignment of the region and block's size
 * @min_addr: the lower bound of the memory region from where the allocation
 *	  is preferred (phys address)
 * @max_addr: the upper bound of the memory region from where the allocation
 *	      is preferred (phys address), or %MEMBLOCK_ALLOC_ACCESSIBLE to
 *	      allocate only from memory limited by memblock.current_limit value
 * @nid: nid of the free area to find, %NUMA_NO_NODE for any node
 *
 * Public function, provides additional debug information (including caller
 * info), if enabled. This function zeroes the allocated memory.
 *
 * Return:
 * Virtual address of allocated memory block on success, NULL on failure.
 */
void * __init memblock_alloc_try_nid(
			phys_addr_t size, phys_addr_t align,
			phys_addr_t min_addr, phys_addr_t max_addr,
			int nid)
{
	void *ptr;

	memblock_dbg("%s: %llu bytes align=0x%llx nid=%d from=%pa max_addr=%pa %pS\n",
		     __func__, (u64)size, (u64)align, nid, &min_addr,
		     &max_addr, (void *)_RET_IP_);
	ptr = memblock_alloc_internal(size, align,
					   min_addr, max_addr, nid, false);
	if (ptr)
		memset(ptr, 0, size);

	return ptr;
}

/**
 * __memblock_alloc_or_panic - Try to allocate memory and panic on failure
 * @size: size of memory block to be allocated in bytes
 * @align: alignment of the region and block's size
 * @func: caller func name
 *
 * This function attempts to allocate memory using memblock_alloc,
 * and in case of failure, it calls panic with the formatted message.
 * This function should not be used directly, please use the macro memblock_alloc_or_panic.
 */
void *__init __memblock_alloc_or_panic(phys_addr_t size, phys_addr_t align,
				       const char *func)
{
	void *addr = memblock_alloc(size, align);

	if (unlikely(!addr))
		panic("%s: Failed to allocate %pap bytes\n", func, &size);
	return addr;
}

/**
 * memblock_free_late - free pages directly to buddy allocator
 * @base: phys starting address of the  boot memory block
 * @size: size of the boot memory block in bytes
 *
 * This is only useful when the memblock allocator has already been torn
 * down, but we are still initializing the system.  Pages are released directly
 * to the buddy allocator.
 */
void __init memblock_free_late(phys_addr_t base, phys_addr_t size)
{
	phys_addr_t cursor, end;

	end = base + size - 1;
	memblock_dbg("%s: [%pa-%pa] %pS\n",
		     __func__, &base, &end, (void *)_RET_IP_);
	kmemleak_free_part_phys(base, size);
	cursor = PFN_UP(base);
	end = PFN_DOWN(base + size);

	for (; cursor < end; cursor++) {
		memblock_free_pages(pfn_to_page(cursor), cursor, 0);
		totalram_pages_inc();
	}
}

/*
 * Remaining API functions
 */

phys_addr_t __init_memblock memblock_phys_mem_size(void)
{
	return memblock.memory.total_size;
}

phys_addr_t __init_memblock memblock_reserved_size(void)
{
	return memblock.reserved.total_size;
}

/**
 * memblock_estimated_nr_free_pages - return estimated number of free pages
 * from memblock point of view
 *
 * During bootup, subsystems might need a rough estimate of the number of free
 * pages in the whole system, before precise numbers are available from the
 * buddy. Especially with CONFIG_DEFERRED_STRUCT_PAGE_INIT, the numbers
 * obtained from the buddy might be very imprecise during bootup.
 *
 * Return:
 * An estimated number of free pages from memblock point of view.
 */
unsigned long __init memblock_estimated_nr_free_pages(void)
{
	return PHYS_PFN(memblock_phys_mem_size() - memblock_reserved_size());
}

/* lowest address */
phys_addr_t __init_memblock memblock_start_of_DRAM(void)
{
	return memblock.memory.regions[0].base;
}

phys_addr_t __init_memblock memblock_end_of_DRAM(void)
{
	int idx = memblock.memory.cnt - 1;

	return (memblock.memory.regions[idx].base + memblock.memory.regions[idx].size);
}

static phys_addr_t __init_memblock __find_max_addr(phys_addr_t limit)
{
	phys_addr_t max_addr = PHYS_ADDR_MAX;
	struct memblock_region *r;

	/*
	 * translate the memory @limit size into the max address within one of
	 * the memory memblock regions, if the @limit exceeds the total size
	 * of those regions, max_addr will keep original value PHYS_ADDR_MAX
	 *
	 * 将内存@limit大小转换为内存memblock区域中的一个区域的最大地址,
	 * 如果@limit超过了这些区域的总大小,则max_addr将保持其原始值PHYS_ADDR_MAX不变
	 */

	/*
	 * 这里就是找出最大的物理地址
	 * 满足这个限制(limit)
	 */
	for_each_mem_region(r) {
		if (limit <= r->size) {
			max_addr = r->base + limit;
			break;
		}
		limit -= r->size;
	}

	return max_addr;
}

void __init memblock_enforce_memory_limit(phys_addr_t limit)
{
	phys_addr_t max_addr;

	if (!limit)
		return;

	max_addr = __find_max_addr(limit);

	/* @limit exceeds the total size of the memory, do nothing */
	if (max_addr == PHYS_ADDR_MAX)
		return;

	/* truncate both memory and reserved regions */
	memblock_remove_range(&memblock.memory, max_addr,
			      PHYS_ADDR_MAX);
	memblock_remove_range(&memblock.reserved, max_addr,
			      PHYS_ADDR_MAX);
}

void __init memblock_cap_memory_range(phys_addr_t base, phys_addr_t size)
{
	int start_rgn, end_rgn;
	int i, ret;

	/* 如果size为0,直接返回 */
	if (!size)
		return;

	/* 如果memblock_memory的total_size为0,那么也直接返回*/
	if (!memblock_memory->total_size) {
		pr_warn("%s: No memory registered yet\n", __func__);
		return;
	}

	/* 这里就是隔离出base到size区域的内存 */
	ret = memblock_isolate_range(&memblock.memory, base, size,
						&start_rgn, &end_rgn);
	if (ret)
		return;

	/*
	 * remove all the MAP regions
	 *
	 *
	 *
	 * static inline bool memblock_is_nomap(struct memblock_region *m)
	 * {
	 *		return m->flags & MEMBLOCK_NOMAP;
	 * }
	 *
	 * 这里就是把超出这个界限的给remove掉
	 */
	for (i = memblock.memory.cnt - 1; i >= end_rgn; i--)
		if (!memblock_is_nomap(&memblock.memory.regions[i]))
			memblock_remove_region(&memblock.memory, i);

	for (i = start_rgn - 1; i >= 0; i--)
		if (!memblock_is_nomap(&memblock.memory.regions[i]))
			memblock_remove_region(&memblock.memory, i);

	/*
	 * truncate the reserved regions
	 * 截断保留区域
	 */

	/* 同理,reserved块也需要remove掉不在这个范围内的 */
	memblock_remove_range(&memblock.reserved, 0, base);
	memblock_remove_range(&memblock.reserved,
			base + size, PHYS_ADDR_MAX);
}

void __init memblock_mem_limit_remove_map(phys_addr_t limit)
{
	phys_addr_t max_addr;

	if (!limit)
		return;

	/* 找到这个最大的物理地址 */
	max_addr = __find_max_addr(limit);

	/*
	 * @limit exceeds the total size of the memory, do nothing
	 * 如果limit超过了内存的总大小,则不执行任何操作.
	 */
	if (max_addr == PHYS_ADDR_MAX)
		return;

	/* 拔掉多余的,NOMAP的memblock */
	memblock_cap_memory_range(0, max_addr);
}

static int __init_memblock memblock_search(struct memblock_type *type, phys_addr_t addr)
{
	unsigned int left = 0, right = type->cnt;

	do {
		unsigned int mid = (right + left) / 2;

		if (addr < type->regions[mid].base)
			right = mid;
		else if (addr >= (type->regions[mid].base +
				  type->regions[mid].size))
			left = mid + 1;
		else
			return mid;
	} while (left < right);
	return -1;
}

bool __init_memblock memblock_is_reserved(phys_addr_t addr)
{
	return memblock_search(&memblock.reserved, addr) != -1;
}

bool __init_memblock memblock_is_memory(phys_addr_t addr)
{
	return memblock_search(&memblock.memory, addr) != -1;
}

bool __init_memblock memblock_is_map_memory(phys_addr_t addr)
{
	int i = memblock_search(&memblock.memory, addr);

	if (i == -1)
		return false;
	return !memblock_is_nomap(&memblock.memory.regions[i]);
}

int __init_memblock memblock_search_pfn_nid(unsigned long pfn,
			 unsigned long *start_pfn, unsigned long *end_pfn)
{
	struct memblock_type *type = &memblock.memory;
	int mid = memblock_search(type, PFN_PHYS(pfn));

	if (mid == -1)
		return NUMA_NO_NODE;

	*start_pfn = PFN_DOWN(type->regions[mid].base);
	*end_pfn = PFN_DOWN(type->regions[mid].base + type->regions[mid].size);

	return memblock_get_region_node(&type->regions[mid]);
}

/**
 * memblock_is_region_memory - check if a region is a subset of memory
 * @base: base of region to check
 * @size: size of region to check
 *
 * Check if the region [@base, @base + @size) is a subset of a memory block.
 *
 * Return:
 * 0 if false, non-zero if true
 */
bool __init_memblock memblock_is_region_memory(phys_addr_t base, phys_addr_t size)
{
	int idx = memblock_search(&memblock.memory, base);
	phys_addr_t end = base + memblock_cap_size(base, &size);

	if (idx == -1)
		return false;
	return (memblock.memory.regions[idx].base +
		 memblock.memory.regions[idx].size) >= end;
}

/**
 * memblock_is_region_reserved - check if a region intersects reserved memory
 * @base: base of region to check
 * @size: size of region to check
 *
 * Check if the region [@base, @base + @size) intersects a reserved
 * memory block.
 *
 * Return:
 * True if they intersect, false if not.
 */
bool __init_memblock memblock_is_region_reserved(phys_addr_t base, phys_addr_t size)
{
	return memblock_overlaps_region(&memblock.reserved, base, size);
}

void __init_memblock memblock_trim_memory(phys_addr_t align)
{
	phys_addr_t start, end, orig_start, orig_end;
	struct memblock_region *r;

	for_each_mem_region(r) {
		orig_start = r->base;
		orig_end = r->base + r->size;
		start = round_up(orig_start, align);
		end = round_down(orig_end, align);

		if (start == orig_start && end == orig_end)
			continue;

		if (start < end) {
			r->base = start;
			r->size = end - start;
		} else {
			memblock_remove_region(&memblock.memory,
					       r - memblock.memory.regions);
			r--;
		}
	}
}

void __init_memblock memblock_set_current_limit(phys_addr_t limit)
{
	memblock.current_limit = limit;
}

phys_addr_t __init_memblock memblock_get_current_limit(void)
{
	return memblock.current_limit;
}

static void __init_memblock memblock_dump(struct memblock_type *type)
{
	phys_addr_t base, end, size;
	enum memblock_flags flags;
	int idx;
	struct memblock_region *rgn;

	pr_info(" %s.cnt  = 0x%lx\n", type->name, type->cnt);

	for_each_memblock_type(idx, type, rgn) {
		char nid_buf[32] = "";

		base = rgn->base;
		size = rgn->size;
		end = base + size - 1;
		flags = rgn->flags;
#ifdef CONFIG_NUMA
		if (numa_valid_node(memblock_get_region_node(rgn)))
			snprintf(nid_buf, sizeof(nid_buf), " on node %d",
				 memblock_get_region_node(rgn));
#endif
		pr_info(" %s[%#x]\t[%pa-%pa], %pa bytes%s flags: %#x\n",
			type->name, idx, &base, &end, &size, nid_buf, flags);
	}
}

static void __init_memblock __memblock_dump_all(void)
{
	pr_info("MEMBLOCK configuration:\n");
	pr_info(" memory size = %pa reserved size = %pa\n",
		&memblock.memory.total_size,
		&memblock.reserved.total_size);

	memblock_dump(&memblock.memory);
	memblock_dump(&memblock.reserved);
#ifdef CONFIG_HAVE_MEMBLOCK_PHYS_MAP
	memblock_dump(&physmem);
#endif
}

void __init_memblock memblock_dump_all(void)
{
	if (memblock_debug)
		__memblock_dump_all();
}

void __init memblock_allow_resize(void)
{
	memblock_can_resize = 1;
}

static int __init early_memblock(char *p)
{
	if (p && strstr(p, "debug"))
		memblock_debug = 1;
	return 0;
}
early_param("memblock", early_memblock);

static void __init free_memmap(unsigned long start_pfn, unsigned long end_pfn)
{
	struct page *start_pg, *end_pg;
	phys_addr_t pg, pgend;

	/*
	 * Convert start_pfn/end_pfn to a struct page pointer.
	 */
	start_pg = pfn_to_page(start_pfn - 1) + 1;
	end_pg = pfn_to_page(end_pfn - 1) + 1;

	/*
	 * Convert to physical addresses, and round start upwards and end
	 * downwards.
	 */
	pg = PAGE_ALIGN(__pa(start_pg));
	pgend = PAGE_ALIGN_DOWN(__pa(end_pg));

	/*
	 * If there are free pages between these, free the section of the
	 * memmap array.
	 */
	if (pg < pgend)
		memblock_phys_free(pg, pgend - pg);
}

/*
 * The mem_map array can get very big.  Free the unused area of the memory map.
 */
static void __init free_unused_memmap(void)
{
	unsigned long start, end, prev_end = 0;
	int i;

	if (!IS_ENABLED(CONFIG_HAVE_ARCH_PFN_VALID) ||
	    IS_ENABLED(CONFIG_SPARSEMEM_VMEMMAP))
		return;

	/*
	 * This relies on each bank being in address order.
	 * The banks are sorted previously in bootmem_init().
	 */
	for_each_mem_pfn_range(i, MAX_NUMNODES, &start, &end, NULL) {
#ifdef CONFIG_SPARSEMEM
		/*
		 * Take care not to free memmap entries that don't exist
		 * due to SPARSEMEM sections which aren't present.
		 */
		start = min(start, ALIGN(prev_end, PAGES_PER_SECTION));
#endif
		/*
		 * Align down here since many operations in VM subsystem
		 * presume that there are no holes in the memory map inside
		 * a pageblock
		 */
		start = pageblock_start_pfn(start);

		/*
		 * If we had a previous bank, and there is a space
		 * between the current bank and the previous, free it.
		 */
		if (prev_end && prev_end < start)
			free_memmap(prev_end, start);

		/*
		 * Align up here since many operations in VM subsystem
		 * presume that there are no holes in the memory map inside
		 * a pageblock
		 */
		prev_end = pageblock_align(end);
	}

#ifdef CONFIG_SPARSEMEM
	if (!IS_ALIGNED(prev_end, PAGES_PER_SECTION)) {
		prev_end = pageblock_align(end);
		free_memmap(prev_end, ALIGN(prev_end, PAGES_PER_SECTION));
	}
#endif
}

static void __init __free_pages_memory(unsigned long start, unsigned long end)
{
	int order;

	while (start < end) {
		/*
		 * Free the pages in the largest chunks alignment allows.
		 *
		 * __ffs() behaviour is undefined for 0. start == 0 is
		 * MAX_PAGE_ORDER-aligned, set order to MAX_PAGE_ORDER for
		 * the case.
		 */
		if (start)
			order = min_t(int, MAX_PAGE_ORDER, __ffs(start));
		else
			order = MAX_PAGE_ORDER;

		while (start + (1UL << order) > end)
			order--;

		memblock_free_pages(pfn_to_page(start), start, order);

		start += (1UL << order);
	}
}

static unsigned long __init __free_memory_core(phys_addr_t start,
				 phys_addr_t end)
{
	unsigned long start_pfn = PFN_UP(start);
	unsigned long end_pfn = min_t(unsigned long,
				      PFN_DOWN(end), max_low_pfn);

	if (start_pfn >= end_pfn)
		return 0;

	__free_pages_memory(start_pfn, end_pfn);

	return end_pfn - start_pfn;
}

static void __init memmap_init_reserved_pages(void)
{
	struct memblock_region *region;
	phys_addr_t start, end;
	int nid;

	/*
	 * set nid on all reserved pages and also treat struct
	 * pages for the NOMAP regions as PageReserved
	 */
	for_each_mem_region(region) {
		nid = memblock_get_region_node(region);
		start = region->base;
		end = start + region->size;

		if (memblock_is_nomap(region))
			reserve_bootmem_region(start, end, nid);

		memblock_set_node(start, end, &memblock.reserved, nid);
	}

	/*
	 * initialize struct pages for reserved regions that don't have
	 * the MEMBLOCK_RSRV_NOINIT flag set
	 */
	for_each_reserved_mem_region(region) {
		if (!memblock_is_reserved_noinit(region)) {
			nid = memblock_get_region_node(region);
			start = region->base;
			end = start + region->size;

			if (!numa_valid_node(nid))
				nid = early_pfn_to_nid(PFN_DOWN(start));

			reserve_bootmem_region(start, end, nid);
		}
	}
}

static unsigned long __init free_low_memory_core_early(void)
{
	unsigned long count = 0;
	phys_addr_t start, end;
	u64 i;

	memblock_clear_hotplug(0, -1);

	memmap_init_reserved_pages();

	/*
	 * We need to use NUMA_NO_NODE instead of NODE_DATA(0)->node_id
	 *  because in some case like Node0 doesn't have RAM installed
	 *  low ram will be on Node1
	 */
	for_each_free_mem_range(i, NUMA_NO_NODE, MEMBLOCK_NONE, &start, &end,
				NULL)
		count += __free_memory_core(start, end);

	return count;
}

static int reset_managed_pages_done __initdata;

static void __init reset_node_managed_pages(pg_data_t *pgdat)
{
	struct zone *z;

	for (z = pgdat->node_zones; z < pgdat->node_zones + MAX_NR_ZONES; z++)
		atomic_long_set(&z->managed_pages, 0);
}

void __init reset_all_zones_managed_pages(void)
{
	struct pglist_data *pgdat;

	if (reset_managed_pages_done)
		return;

	for_each_online_pgdat(pgdat)
		reset_node_managed_pages(pgdat);

	reset_managed_pages_done = 1;
}

/**
 * memblock_free_all - release free pages to the buddy allocator
 */
void __init memblock_free_all(void)
{
	unsigned long pages;

	free_unused_memmap();
	reset_all_zones_managed_pages();

	pages = free_low_memory_core_early();
	totalram_pages_add(pages);
}

/* Keep a table to reserve named memory */
#define RESERVE_MEM_MAX_ENTRIES		8
#define RESERVE_MEM_NAME_SIZE		16
struct reserve_mem_table {
	char			name[RESERVE_MEM_NAME_SIZE];
	phys_addr_t		start;
	phys_addr_t		size;
};
static struct reserve_mem_table reserved_mem_table[RESERVE_MEM_MAX_ENTRIES];
static int reserved_mem_count;

/* Add wildcard region with a lookup name */
static void __init reserved_mem_add(phys_addr_t start, phys_addr_t size,
				   const char *name)
{
	struct reserve_mem_table *map;

	map = &reserved_mem_table[reserved_mem_count++];
	map->start = start;
	map->size = size;
	strscpy(map->name, name);
}

/**
 * reserve_mem_find_by_name - Find reserved memory region with a given name
 * @name: The name that is attached to a reserved memory region
 * @start: If found, holds the start address
 * @size: If found, holds the size of the address.
 *
 * @start and @size are only updated if @name is found.
 *
 * Returns: 1 if found or 0 if not found.
 */
int reserve_mem_find_by_name(const char *name, phys_addr_t *start, phys_addr_t *size)
{
	struct reserve_mem_table *map;
	int i;

	for (i = 0; i < reserved_mem_count; i++) {
		map = &reserved_mem_table[i];
		if (!map->size)
			continue;
		if (strcmp(name, map->name) == 0) {
			*start = map->start;
			*size = map->size;
			return 1;
		}
	}
	return 0;
}
EXPORT_SYMBOL_GPL(reserve_mem_find_by_name);

/*
 * Parse reserve_mem=nn:align:name
 */
static int __init reserve_mem(char *p)
{
	phys_addr_t start, size, align, tmp;
	char *name;
	char *oldp;
	int len;

	if (!p)
		return -EINVAL;

	/* Check if there's room for more reserved memory */
	if (reserved_mem_count >= RESERVE_MEM_MAX_ENTRIES)
		return -EBUSY;

	oldp = p;
	size = memparse(p, &p);
	if (!size || p == oldp)
		return -EINVAL;

	if (*p != ':')
		return -EINVAL;

	align = memparse(p+1, &p);
	if (*p != ':')
		return -EINVAL;

	/*
	 * memblock_phys_alloc() doesn't like a zero size align,
	 * but it is OK for this command to have it.
	 */
	if (align < SMP_CACHE_BYTES)
		align = SMP_CACHE_BYTES;

	name = p + 1;
	len = strlen(name);

	/* name needs to have length but not too big */
	if (!len || len >= RESERVE_MEM_NAME_SIZE)
		return -EINVAL;

	/* Make sure that name has text */
	for (p = name; *p; p++) {
		if (!isspace(*p))
			break;
	}
	if (!*p)
		return -EINVAL;

	/* Make sure the name is not already used */
	if (reserve_mem_find_by_name(name, &start, &tmp))
		return -EBUSY;

	start = memblock_phys_alloc(size, align);
	if (!start)
		return -ENOMEM;

	reserved_mem_add(start, size, name);

	return 1;
}
__setup("reserve_mem=", reserve_mem);

#if defined(CONFIG_DEBUG_FS) && defined(CONFIG_ARCH_KEEP_MEMBLOCK)
static const char * const flagname[] = {
	[ilog2(MEMBLOCK_HOTPLUG)] = "HOTPLUG",
	[ilog2(MEMBLOCK_MIRROR)] = "MIRROR",
	[ilog2(MEMBLOCK_NOMAP)] = "NOMAP",
	[ilog2(MEMBLOCK_DRIVER_MANAGED)] = "DRV_MNG",
	[ilog2(MEMBLOCK_RSRV_NOINIT)] = "RSV_NIT",
};

static int memblock_debug_show(struct seq_file *m, void *private)
{
	struct memblock_type *type = m->private;
	struct memblock_region *reg;
	int i, j, nid;
	unsigned int count = ARRAY_SIZE(flagname);
	phys_addr_t end;

	for (i = 0; i < type->cnt; i++) {
		reg = &type->regions[i];
		end = reg->base + reg->size - 1;
		nid = memblock_get_region_node(reg);

		seq_printf(m, "%4d: ", i);
		seq_printf(m, "%pa..%pa ", &reg->base, &end);
		if (numa_valid_node(nid))
			seq_printf(m, "%4d ", nid);
		else
			seq_printf(m, "%4c ", 'x');
		if (reg->flags) {
			for (j = 0; j < count; j++) {
				if (reg->flags & (1U << j)) {
					seq_printf(m, "%s\n", flagname[j]);
					break;
				}
			}
			if (j == count)
				seq_printf(m, "%s\n", "UNKNOWN");
		} else {
			seq_printf(m, "%s\n", "NONE");
		}
	}
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(memblock_debug);

static int __init memblock_init_debugfs(void)
{
	struct dentry *root = debugfs_create_dir("memblock", NULL);

	debugfs_create_file("memory", 0444, root,
			    &memblock.memory, &memblock_debug_fops);
	debugfs_create_file("reserved", 0444, root,
			    &memblock.reserved, &memblock_debug_fops);
#ifdef CONFIG_HAVE_MEMBLOCK_PHYS_MAP
	debugfs_create_file("physmem", 0444, root, &physmem,
			    &memblock_debug_fops);
#endif

	return 0;
}
__initcall(memblock_init_debugfs);

#endif /* CONFIG_DEBUG_FS */
