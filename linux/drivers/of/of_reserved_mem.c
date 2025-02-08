// SPDX-License-Identifier: GPL-2.0+
/*
 * Device tree based initialization code for reserved memory.
 *
 * Copyright (c) 2013, 2015 The Linux Foundation. All Rights Reserved.
 * Copyright (c) 2013,2014 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com
 * Author: Marek Szyprowski <m.szyprowski@samsung.com>
 * Author: Josh Cartwright <joshc@codeaurora.org>
 */

#define pr_fmt(fmt)	"OF: reserved mem: " fmt

#include <linux/err.h>
#include <linux/libfdt.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/of_platform.h>
#include <linux/mm.h>
#include <linux/sizes.h>
#include <linux/of_reserved_mem.h>
#include <linux/sort.h>
#include <linux/slab.h>
#include <linux/memblock.h>
#include <linux/kmemleak.h>
#include <linux/cma.h>

#include "of_private.h"

static struct reserved_mem reserved_mem_array[MAX_RESERVED_REGIONS] __initdata;
static struct reserved_mem *reserved_mem __refdata = reserved_mem_array;
static int total_reserved_mem_cnt = MAX_RESERVED_REGIONS;
static int reserved_mem_count;

static int __init early_init_dt_alloc_reserved_memory_arch(phys_addr_t size,
	phys_addr_t align, phys_addr_t start, phys_addr_t end, bool nomap,
	phys_addr_t *res_base)
{
	phys_addr_t base;
	int err = 0;

	/*
	 * 如果end为0,那么我们就选择MEMBLOCK_ALLOC_ANYWHERE,也就是说任何地方都可以
	 * 否则就选择end
	 */
	end = !end ? MEMBLOCK_ALLOC_ANYWHERE : end;
	/* 这边就是选择合适的align */
	align = !align ? SMP_CACHE_BYTES : align;
	/* 分配这段内存 */
	base = memblock_phys_alloc_range(size, align, start, end);
	/* 如果没有分配到,返回-ENOMEN */
	if (!base)
		return -ENOMEM;

	/* 把起始地址给传出去 */
	*res_base = base;
	/* 如果设置nomap */
	if (nomap) {
		/* 标记它的nomap flag */
		err = memblock_mark_nomap(base, size);
		/* 把它释放了 */
		if (err)
			memblock_phys_free(base, size);
	}

	if (!err)
		kmemleak_ignore_phys(base);

	return err;
}

/*
 * alloc_reserved_mem_array() - allocate memory for the reserved_mem
 * array using memblock
 *
 * This function is used to allocate memory for the reserved_mem
 * array according to the total number of reserved memory regions
 * defined in the DT.
 * After the new array is allocated, the information stored in
 * the initial static array is copied over to this new array and
 * the new array is used from this point on.
 */
static void __init alloc_reserved_mem_array(void)
{
	struct reserved_mem *new_array;
	size_t alloc_size, copy_size, memset_size;

	alloc_size = array_size(total_reserved_mem_cnt, sizeof(*new_array));
	if (alloc_size == SIZE_MAX) {
		pr_err("Failed to allocate memory for reserved_mem array with err: %d", -EOVERFLOW);
		return;
	}

	new_array = memblock_alloc(alloc_size, SMP_CACHE_BYTES);
	if (!new_array) {
		pr_err("Failed to allocate memory for reserved_mem array with err: %d", -ENOMEM);
		return;
	}

	copy_size = array_size(reserved_mem_count, sizeof(*new_array));
	if (copy_size == SIZE_MAX) {
		memblock_free(new_array, alloc_size);
		total_reserved_mem_cnt = MAX_RESERVED_REGIONS;
		pr_err("Failed to allocate memory for reserved_mem array with err: %d", -EOVERFLOW);
		return;
	}

	memset_size = alloc_size - copy_size;

	memcpy(new_array, reserved_mem, copy_size);
	memset(new_array + reserved_mem_count, 0, memset_size);

	reserved_mem = new_array;
}

static void __init fdt_init_reserved_mem_node(struct reserved_mem *rmem);
/*
 * fdt_reserved_mem_save_node() - save fdt node for second pass initialization
 *
 * fdt_reserved_mem_save_node() - 在第二阶段初始化时保存设备树(FDT)节点
 */
static void __init fdt_reserved_mem_save_node(unsigned long node, const char *uname,
					      phys_addr_t base, phys_addr_t size)
{
	/* 保存到reserved_mem数组里面 */
	struct reserved_mem *rmem = &reserved_mem[reserved_mem_count];

	if (reserved_mem_count == total_reserved_mem_cnt) {
		pr_err("not enough space for all defined regions.\n");
		return;
	}

	rmem->fdt_node = node;
	rmem->name = uname;
	rmem->base = base;
	rmem->size = size;

	/*
	 * Call the region specific initialization function
	 * 调用特定区域的初始化函数
	 */
	fdt_init_reserved_mem_node(rmem);

	reserved_mem_count++;
	return;
}

static int __init early_init_dt_reserve_memory(phys_addr_t base,
					       phys_addr_t size, bool nomap)
{
	if (nomap) {
		/*
		 * If the memory is already reserved (by another region), we
		 * should not allow it to be marked nomap, but don't worry
		 * if the region isn't memory as it won't be mapped.
		 *
		 * 如果内存已经被预留(被另一个区域占用),我们不应该允许它被标记为不可映射(nomap),
		 * 但如果该区域不是内存,则不用担心,因为它不会被映射
		 */

		/* 如果该区域与memblock.memory一块有重叠并且和reserved区域有重叠,那么返回-EBUSY */
		if (memblock_overlaps_region(&memblock.memory, base, size) &&
		    memblock_is_region_reserved(base, size))
			return -EBUSY;

		/* 这里应该是说这块区域在memblock.memory里面,那么把它设置为MEMBLOCK_NOMAP的 */
		return memblock_mark_nomap(base, size);
	}

	/* 否则,把它设置到reserve里面 */
	return memblock_reserve(base, size);
}

/*
 * __reserved_mem_reserve_reg() - reserve all memory described in 'reg' property
 */
static int __init __reserved_mem_reserve_reg(unsigned long node,
					     const char *uname)
{
	int t_len = (dt_root_addr_cells + dt_root_size_cells) * sizeof(__be32);
	phys_addr_t base, size;
	int len;
	const __be32 *prop;
	bool nomap;

	/* 拿到reg属性 */
	prop = of_get_flat_dt_prop(node, "reg", &len);
	if (!prop)
		return -ENOENT;

	if (len && len % t_len != 0) {
		pr_err("Reserved memory: invalid reg property in '%s', skipping node.\n",
		       uname);
		return -EINVAL;
	}

	/* 拿到no-map属性,根据是否存在来设置nomap变量 */
	nomap = of_get_flat_dt_prop(node, "no-map", NULL) != NULL;

	while (len >= t_len) {
		/* 拿到该节点的base和size */
		base = dt_mem_next_cell(dt_root_addr_cells, &prop);
		size = dt_mem_next_cell(dt_root_size_cells, &prop);

		if (size &&
		    early_init_dt_reserve_memory(base, size, nomap) == 0)
			pr_debug("Reserved memory: reserved region for node '%s': base %pa, size %lu MiB\n",
				uname, &base, (unsigned long)(size / SZ_1M));
		else
			pr_err("Reserved memory: failed to reserve memory for node '%s': base %pa, size %lu MiB\n",
			       uname, &base, (unsigned long)(size / SZ_1M));

		len -= t_len;
	}
	return 0;
}

/*
 * __reserved_mem_check_root() - check if #size-cells, #address-cells provided
 * in /reserved-memory matches the values supported by the current implementation,
 * also check if ranges property has been provided
 *
 * __reserved_mem_check_root() - 检查/reserved-memory中提供的#size-cells和#address-cells是否与当前实现支持的值匹配,
 * 同时检查是否已提供ranges属性
 */
static int __init __reserved_mem_check_root(unsigned long node)
{
	const __be32 *prop;

	prop = of_get_flat_dt_prop(node, "#size-cells", NULL);
	if (!prop || be32_to_cpup(prop) != dt_root_size_cells)
		return -EINVAL;

	prop = of_get_flat_dt_prop(node, "#address-cells", NULL);
	if (!prop || be32_to_cpup(prop) != dt_root_addr_cells)
		return -EINVAL;

	prop = of_get_flat_dt_prop(node, "ranges", NULL);
	if (!prop)
		return -EINVAL;
	return 0;
}

static void __init __rmem_check_for_overlap(void);

/**
 * fdt_scan_reserved_mem_reg_nodes() - Store info for the "reg" defined
 * reserved memory regions.
 *
 * This function is used to scan through the DT and store the
 * information for the reserved memory regions that are defined using
 * the "reg" property. The region node number, name, base address, and
 * size are all stored in the reserved_mem array by calling the
 * fdt_reserved_mem_save_node() function.
 *
 * fdt_scan_reserved_mem_reg_nodes() - 存储使用“reg”属性定义的保留内存区域的信息.
 *
 * 此函数用于扫描设备树(DT),并存储使用“reg”属性定义的保留内存区域的信息.
 * 保留内存区域的节点编号、名称、基地址和大小都通过调用fdt_reserved_mem_save_node()函数存储在reserved_mem数组中
 */
void __init fdt_scan_reserved_mem_reg_nodes(void)
{
	int t_len = (dt_root_addr_cells + dt_root_size_cells) * sizeof(__be32);
	const void *fdt = initial_boot_params;
	phys_addr_t base, size;
	const __be32 *prop;
	int node, child;
	int len;

	if (!fdt)
		return;

	/*
	 * 我们用arch/arm64/boot/dts/mediatek/mt8183-evb.dts为例子来分析一下这个函数
	 * reserved-memory {
	 *	#address-cells = <2>;
	 *	#size-cells = <2>;
	 *	ranges;
	 *	scp_mem_reserved: memory@50000000 {
	 *		compatible = "shared-dma-pool";
	 *		reg = <0 0x50000000 0 0x2900000>;
	 *		no-map;
	 *	};
	 * };
	 */
	/* 找到根目录下的/reserved-memory结点 */
	node = fdt_path_offset(fdt, "/reserved-memory");
	if (node < 0) {
		pr_info("Reserved memory: No reserved-memory node in the DT\n");
		return;
	}

	/* Attempt dynamic allocation of a new reserved_mem array */
	alloc_reserved_mem_array();

	/* 检查reserved-memory node是否合法 */
	if (__reserved_mem_check_root(node)) {
		pr_err("Reserved memory: unsupported node format, ignoring\n");
		return;
	}

	/* 遍历这个下面所有的子节点 */
	fdt_for_each_subnode(child, fdt, node) {
		const char *uname;

		/* 拿到reg属性 */
		prop = of_get_flat_dt_prop(child, "reg", &len);
		if (!prop)
			continue;

		/* 判断这个节点是不是available的 */
		if (!of_fdt_device_is_available(fdt, child))
			continue;

		/* 拿到这个节点的名字 */
		uname = fdt_get_name(fdt, child, NULL);
		if (len && len % t_len != 0) {
			pr_err("Reserved memory: invalid reg property in '%s', skipping node.\n",
			       uname);
			continue;
		}

		if (len > t_len)
			pr_warn("%s() ignores %d regions in node '%s'\n",
				__func__, len / t_len - 1, uname);

		/* 拿到base和size */
		base = dt_mem_next_cell(dt_root_addr_cells, &prop);
		size = dt_mem_next_cell(dt_root_size_cells, &prop);

		if (size)
			fdt_reserved_mem_save_node(child, uname, base, size);
	}

	/* check for overlapping reserved regions */
	__rmem_check_for_overlap();
}

static int __init __reserved_mem_alloc_size(unsigned long node, const char *uname);

/*
 * fdt_scan_reserved_mem() - scan a single FDT node for reserved memory
 */
int __init fdt_scan_reserved_mem(void)
{
	int node, child;
	int dynamic_nodes_cnt = 0, count = 0;
	int dynamic_nodes[MAX_RESERVED_REGIONS];
	const void *fdt = initial_boot_params;

	/*
	 * 我们用arch/arm64/boot/dts/mediatek/mt8183-evb.dts为例子来分析一下这个函数
	 * reserved-memory {
	 *	#address-cells = <2>;
	 *	#size-cells = <2>;
	 *	ranges;
	 *	scp_mem_reserved: memory@50000000 {
	 *		compatible = "shared-dma-pool";
	 *		reg = <0 0x50000000 0 0x2900000>;
	 *		no-map;
	 *	};
	 * };
	 */

	/* 找到根目录下的/reserved-memory结点 */
	node = fdt_path_offset(fdt, "/reserved-memory");
	if (node < 0)
		return -ENODEV;

	/* 检查reserved-memory node是否合法 */
	if (__reserved_mem_check_root(node) != 0) {
		pr_err("Reserved memory: unsupported node format, ignoring\n");
		return -EINVAL;
	}

	/* 遍历这个下面的子节点 */
	fdt_for_each_subnode(child, fdt, node) {
		const char *uname;
		int err;

		/* 判断这个节点是不是available的 */
		if (!of_fdt_device_is_available(fdt, child))
			continue;

		/* 拿到这个节点的名字 */
		uname = fdt_get_name(fdt, child, NULL);

		err = __reserved_mem_reserve_reg(child, uname);
		if (!err)
			count++;
		/*
		 * Save the nodes for the dynamically-placed regions
		 * into an array which will be used for allocation right
		 * after all the statically-placed regions are reserved
		 * or marked as no-map. This is done to avoid dynamically
		 * allocating from one of the statically-placed regions.
		 *
		 * 将动态放置区域的节点保存到一个数组中,该数组将在所有静态放置区域都被预留或标记为不可映射之后用于分配.
		 * 这样做是为了避免从任何一个静态放置区域中进行动态分配.
		 */

		/* 这里是说如果这个设备节点没有reg,但是指定了size,
		 * 这种需求应该是说你给我分配地址,不用我指定
		 */
		if (err == -ENOENT && of_get_flat_dt_prop(child, "size", NULL)) {
			dynamic_nodes[dynamic_nodes_cnt] = child;
			dynamic_nodes_cnt++;
		}
	}
	for (int i = 0; i < dynamic_nodes_cnt; i++) {
		const char *uname;
		int err;

		child = dynamic_nodes[i];
		/* 拿到这个节点的名字 */
		uname = fdt_get_name(fdt, child, NULL);
		err = __reserved_mem_alloc_size(child, uname);
		if (!err)
			count++;
	}
	total_reserved_mem_cnt = count;
	return 0;
}

/*
 * __reserved_mem_alloc_in_range() - allocate reserved memory described with
 *	'alloc-ranges'. Choose bottom-up/top-down depending on nearby existing
 *	reserved regions to keep the reserved memory contiguous if possible.
 *
 * __reserved_mem_alloc_in_range() - 根据“alloc-ranges”描述分配保留内存.
 * 根据附近的现有保留区域选择自下而上或自上而下分配,以尽可能保持保留内存的连续性.
 */
static int __init __reserved_mem_alloc_in_range(phys_addr_t size,
	phys_addr_t align, phys_addr_t start, phys_addr_t end, bool nomap,
	phys_addr_t *res_base)
{
	/* 判断当前的memblock是不是从下而上分配的 */
	bool prev_bottom_up = memblock_bottom_up();
	bool bottom_up = false, top_down = false;
	int ret, i;

	/* 这里就是去找reserved_mem */
	for (i = 0; i < reserved_mem_count; i++) {
		struct reserved_mem *rmem = &reserved_mem[i];

		/*
		 * Skip regions that were not reserved yet
		 * 如果该rmem的size为0,那么continue
		 */
		if (rmem->size == 0)
			continue;

		/*
		 * If range starts next to an existing reservation, use bottom-up:
		 * 如果范围紧邻一个现有的保留区域,则使用自下而上的方式
		 *	|....RRRR................RRRRRRRR..............|
		 *	       --RRRR------
		 *
		 * rmem->base <= start <= rmem->base + rmem->size
		 */
		if (start >= rmem->base && start <= (rmem->base + rmem->size))
			bottom_up = true;

		/*
		 * If range ends next to an existing reservation, use top-down:
		 *	|....RRRR................RRRRRRRR..............|
		 *	              -------RRRR-----
		 *
		 * rmem->base <= end <= rmem->base + rmem->size
		 */
		if (end >= rmem->base && end <= (rmem->base + rmem->size))
			top_down = true;
	}

	/*
	 * Change setting only if either bottom-up or top-down was selected
	 * 仅当选择了自下而上或自上而下时才更改设置
	 */
	if (bottom_up != top_down)
		memblock_set_bottom_up(bottom_up);

	/* 这里就是分配内存 */
	ret = early_init_dt_alloc_reserved_memory_arch(size, align,
			start, end, nomap, res_base);

	/* Restore old setting if needed */
	if (bottom_up != top_down)
		memblock_set_bottom_up(prev_bottom_up);

	return ret;
}

/*
 * __reserved_mem_alloc_size() - allocate reserved memory described by
 *	'size', 'alignment'  and 'alloc-ranges' properties.
 *
 * __reserved_mem_alloc_size() - 根据'size'(大小)、'alignment'(对齐)和'alloc-ranges'(分配范围)属性分配预留内存
 */
static int __init __reserved_mem_alloc_size(unsigned long node, const char *uname)
{
	int t_len = (dt_root_addr_cells + dt_root_size_cells) * sizeof(__be32);
	phys_addr_t start = 0, end = 0;
	phys_addr_t base = 0, align = 0, size;
	int len;
	const __be32 *prop;
	bool nomap;
	int ret;

	/* 拿到size属性 */
	prop = of_get_flat_dt_prop(node, "size", &len);
	if (!prop)
		return -EINVAL;

	if (len != dt_root_size_cells * sizeof(__be32)) {
		pr_err("invalid size property in '%s' node.\n", uname);
		return -EINVAL;
	}

	/* 得到size大小 */
	size = dt_mem_next_cell(dt_root_size_cells, &prop);

	/* 看看有没有alignment */
	prop = of_get_flat_dt_prop(node, "alignment", &len);
	if (prop) {
		if (len != dt_root_size_cells * sizeof(__be32)) {
			pr_err("invalid alignment property in '%s' node.\n",
				uname);
			return -EINVAL;
		}
		/* 拿到align */
		align = dt_mem_next_cell(dt_root_size_cells, &prop);
	}

	/* 看看是不是需要nomap的 */
	nomap = of_get_flat_dt_prop(node, "no-map", NULL) != NULL;

	/*
	 * Need adjust the alignment to satisfy the CMA requirement
	 * 需要调整对齐以满足CMA(连续内存分配器)的要求
	 */

	/*
	 * 这里就是cma的逻辑,又是shared-dma-pool,又是可复用的,并且不是nomap的
	 * 根据这个来调整align
	 */
	if (IS_ENABLED(CONFIG_CMA)
	    && of_flat_dt_is_compatible(node, "shared-dma-pool")
	    && of_get_flat_dt_prop(node, "reusable", NULL)
	    && !nomap)
		align = max_t(phys_addr_t, align, CMA_MIN_ALIGNMENT_BYTES);
	/* 这边是去看它有没有设置alloc-ranges属性 */
	prop = of_get_flat_dt_prop(node, "alloc-ranges", &len);
	/* 如果有 */
	if (prop) {

		if (len % t_len != 0) {
			pr_err("invalid alloc-ranges property in '%s', skipping node.\n",
			       uname);
			return -EINVAL;
		}

		while (len > 0) {
			/* 拿到起始地址 */
			start = dt_mem_next_cell(dt_root_addr_cells, &prop);
			/* 拿到size算出结束地址 */
			end = start + dt_mem_next_cell(dt_root_size_cells,
						       &prop);

			base = 0;
			ret = __reserved_mem_alloc_in_range(size, align,
					start, end, nomap, &base);
			if (ret == 0) {
				pr_debug("allocated memory for '%s' node: base %pa, size %lu MiB\n",
					uname, &base,
					(unsigned long)(size / SZ_1M));
				break;
			}
			len -= t_len;
		}

	/* 如果没有,那么就从任意地址去拿就好了 */
	} else {
		ret = early_init_dt_alloc_reserved_memory_arch(size, align,
							0, 0, nomap, &base);
		if (ret == 0)
			pr_debug("allocated memory for '%s' node: base %pa, size %lu MiB\n",
				uname, &base, (unsigned long)(size / SZ_1M));
	}

	/* base为0,表示没有分配成功 */
	if (base == 0) {
		pr_err("failed to allocate memory for node '%s': size %lu MiB\n",
		       uname, (unsigned long)(size / SZ_1M));
		return -ENOMEM;
	}

	/*
	 * Save region in the reserved_mem array
	 * 在reserved_mem数组中保存区域
	 */
	fdt_reserved_mem_save_node(node, uname, base, size);
	return 0;
}

static const struct of_device_id __rmem_of_table_sentinel
	__used __section("__reservedmem_of_table_end");

/*
 * __reserved_mem_init_node() - call region specific reserved memory init code
 */
static int __init __reserved_mem_init_node(struct reserved_mem *rmem)
{
	extern const struct of_device_id __reservedmem_of_table[];
	const struct of_device_id *i;
	int ret = -ENOENT;

	for (i = __reservedmem_of_table; i < &__rmem_of_table_sentinel; i++) {
		reservedmem_of_init_fn initfn = i->data;
		const char *compat = i->compatible;

		if (!of_flat_dt_is_compatible(rmem->fdt_node, compat))
			continue;

		ret = initfn(rmem);
		if (ret == 0) {
			pr_info("initialized node %s, compatible id %s\n",
				rmem->name, compat);
			break;
		}
	}
	return ret;
}

static int __init __rmem_cmp(const void *a, const void *b)
{
	const struct reserved_mem *ra = a, *rb = b;

	if (ra->base < rb->base)
		return -1;

	if (ra->base > rb->base)
		return 1;

	/*
	 * Put the dynamic allocations (address == 0, size == 0) before static
	 * allocations at address 0x0 so that overlap detection works
	 * correctly.
	 */
	if (ra->size < rb->size)
		return -1;
	if (ra->size > rb->size)
		return 1;

	if (ra->fdt_node < rb->fdt_node)
		return -1;
	if (ra->fdt_node > rb->fdt_node)
		return 1;

	return 0;
}

static void __init __rmem_check_for_overlap(void)
{
	int i;

	if (reserved_mem_count < 2)
		return;

	sort(reserved_mem, reserved_mem_count, sizeof(reserved_mem[0]),
	     __rmem_cmp, NULL);
	for (i = 0; i < reserved_mem_count - 1; i++) {
		struct reserved_mem *this, *next;

		this = &reserved_mem[i];
		next = &reserved_mem[i + 1];

		if (this->base + this->size > next->base) {
			phys_addr_t this_end, next_end;

			this_end = this->base + this->size;
			next_end = next->base + next->size;
			pr_err("OVERLAP DETECTED!\n%s (%pa--%pa) overlaps with %s (%pa--%pa)\n",
			       this->name, &this->base, &this_end,
			       next->name, &next->base, &next_end);
		}
	}
}

/**
 * fdt_init_reserved_mem_node() - Initialize a reserved memory region
 * @rmem: reserved_mem struct of the memory region to be initialized.
 *
 * This function is used to call the region specific initialization
 * function for a reserved memory region.
 *
 * fdt_init_reserved_mem_node() - 初始化预留内存区域
 * @rmem: 要初始化的内存区域的reserved_mem结构体.
 *
 * 此函数用于调用特定预留内存区域的初始化函数.
 */
static void __init fdt_init_reserved_mem_node(struct reserved_mem *rmem)
{
	unsigned long node = rmem->fdt_node;
	int err = 0;
	bool nomap;

	nomap = of_get_flat_dt_prop(node, "no-map", NULL) != NULL;

	/* 这里就是去初始化这块内存 */
	err = __reserved_mem_init_node(rmem);
	if (err != 0 && err != -ENOENT) {
		pr_info("node %s compatible matching fail\n", rmem->name);
		/* NG了,如果设置了nomap,那么就清除这个标志 */
		if (nomap)
			memblock_clear_nomap(rmem->base, rmem->size);
		/* 否则，free掉 */
		else
			memblock_phys_free(rmem->base, rmem->size);
	} else {
		phys_addr_t end = rmem->base + rmem->size - 1;
		bool reusable =
			(of_get_flat_dt_prop(node, "reusable", NULL)) != NULL;

		pr_info("%pa..%pa (%lu KiB) %s %s %s\n",
			&rmem->base, &end, (unsigned long)(rmem->size / SZ_1K),
			nomap ? "nomap" : "map",
			reusable ? "reusable" : "non-reusable",
			rmem->name ? rmem->name : "unknown");
	}
}

struct rmem_assigned_device {
	struct device *dev;
	struct reserved_mem *rmem;
	struct list_head list;
};

static LIST_HEAD(of_rmem_assigned_device_list);
static DEFINE_MUTEX(of_rmem_assigned_device_mutex);

/**
 * of_reserved_mem_device_init_by_idx() - assign reserved memory region to
 *					  given device
 * @dev:	Pointer to the device to configure
 * @np:		Pointer to the device_node with 'reserved-memory' property
 * @idx:	Index of selected region
 *
 * This function assigns respective DMA-mapping operations based on reserved
 * memory region specified by 'memory-region' property in @np node to the @dev
 * device. When driver needs to use more than one reserved memory region, it
 * should allocate child devices and initialize regions by name for each of
 * child device.
 *
 * Returns error code or zero on success.
 */
int of_reserved_mem_device_init_by_idx(struct device *dev,
				       struct device_node *np, int idx)
{
	struct rmem_assigned_device *rd;
	struct device_node *target;
	struct reserved_mem *rmem;
	int ret;

	if (!np || !dev)
		return -EINVAL;

	target = of_parse_phandle(np, "memory-region", idx);
	if (!target)
		return -ENODEV;

	if (!of_device_is_available(target)) {
		of_node_put(target);
		return 0;
	}

	rmem = of_reserved_mem_lookup(target);
	of_node_put(target);

	if (!rmem || !rmem->ops || !rmem->ops->device_init)
		return -EINVAL;

	rd = kmalloc(sizeof(struct rmem_assigned_device), GFP_KERNEL);
	if (!rd)
		return -ENOMEM;

	ret = rmem->ops->device_init(rmem, dev);
	if (ret == 0) {
		rd->dev = dev;
		rd->rmem = rmem;

		mutex_lock(&of_rmem_assigned_device_mutex);
		list_add(&rd->list, &of_rmem_assigned_device_list);
		mutex_unlock(&of_rmem_assigned_device_mutex);

		dev_info(dev, "assigned reserved memory node %s\n", rmem->name);
	} else {
		kfree(rd);
	}

	return ret;
}
EXPORT_SYMBOL_GPL(of_reserved_mem_device_init_by_idx);

/**
 * of_reserved_mem_device_init_by_name() - assign named reserved memory region
 *					   to given device
 * @dev: pointer to the device to configure
 * @np: pointer to the device node with 'memory-region' property
 * @name: name of the selected memory region
 *
 * Returns: 0 on success or a negative error-code on failure.
 */
int of_reserved_mem_device_init_by_name(struct device *dev,
					struct device_node *np,
					const char *name)
{
	int idx = of_property_match_string(np, "memory-region-names", name);

	return of_reserved_mem_device_init_by_idx(dev, np, idx);
}
EXPORT_SYMBOL_GPL(of_reserved_mem_device_init_by_name);

/**
 * of_reserved_mem_device_release() - release reserved memory device structures
 * @dev:	Pointer to the device to deconfigure
 *
 * This function releases structures allocated for memory region handling for
 * the given device.
 */
void of_reserved_mem_device_release(struct device *dev)
{
	struct rmem_assigned_device *rd, *tmp;
	LIST_HEAD(release_list);

	mutex_lock(&of_rmem_assigned_device_mutex);
	list_for_each_entry_safe(rd, tmp, &of_rmem_assigned_device_list, list) {
		if (rd->dev == dev)
			list_move_tail(&rd->list, &release_list);
	}
	mutex_unlock(&of_rmem_assigned_device_mutex);

	list_for_each_entry_safe(rd, tmp, &release_list, list) {
		if (rd->rmem && rd->rmem->ops && rd->rmem->ops->device_release)
			rd->rmem->ops->device_release(rd->rmem, dev);

		kfree(rd);
	}
}
EXPORT_SYMBOL_GPL(of_reserved_mem_device_release);

/**
 * of_reserved_mem_lookup() - acquire reserved_mem from a device node
 * @np:		node pointer of the desired reserved-memory region
 *
 * This function allows drivers to acquire a reference to the reserved_mem
 * struct based on a device node handle.
 *
 * Returns a reserved_mem reference, or NULL on error.
 */
struct reserved_mem *of_reserved_mem_lookup(struct device_node *np)
{
	const char *name;
	int i;

	if (!np->full_name)
		return NULL;

	name = kbasename(np->full_name);
	for (i = 0; i < reserved_mem_count; i++)
		if (!strcmp(reserved_mem[i].name, name))
			return &reserved_mem[i];

	return NULL;
}
EXPORT_SYMBOL_GPL(of_reserved_mem_lookup);
