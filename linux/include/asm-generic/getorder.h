/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_GENERIC_GETORDER_H
#define __ASM_GENERIC_GETORDER_H

#ifndef __ASSEMBLY__

#include <linux/compiler.h>
#include <linux/log2.h>

/**
 * get_order - Determine the allocation order of a memory size
 * @size: The size for which to get the order
 *
 * Determine the allocation order of a particular sized block of memory.  This
 * is on a logarithmic scale, where:
 *
 *	0 -> 2^0 * PAGE_SIZE and below
 *	1 -> 2^1 * PAGE_SIZE to 2^0 * PAGE_SIZE + 1
 *	2 -> 2^2 * PAGE_SIZE to 2^1 * PAGE_SIZE + 1
 *	3 -> 2^3 * PAGE_SIZE to 2^2 * PAGE_SIZE + 1
 *	4 -> 2^4 * PAGE_SIZE to 2^3 * PAGE_SIZE + 1
 *	...
 *
 * The order returned is used to find the smallest allocation granule required
 * to hold an object of the specified size.
 *
 * The result is undefined if the size is 0.
 *
 * get_order - 确定内存大小的分配阶数
 * @size: 需要获取阶数的内存大小
 *
 * 确定特定大小内存块的分配阶数. 这是一个对数尺度,其中:
 *
 * 0 -> 2^0 * PAGE_SIZE 及以下
 * 1 -> 20 * PAGE_SIZE + 1
 * 2 -> 21 * PAGE_SIZE + 1
 * 3 -> 22 * PAGE_SIZE + 1
 * 4 -> 23 * PAGE_SIZE + 1
 * ...
 *
 * 返回的阶数用于找到能够容纳指定大小对象所需的最小分配粒度.
 *
 * 如果大小为0，则结果未定义。
 */
static __always_inline __attribute_const__ int get_order(unsigned long size)
{
	/*
	 * __builtin_constant_p是GCC(GNU Compiler Collection))提供的一个内置函数,
	 * 用于在编译时检测一个表达式是否是常量.
	 * 它返回一个整型值:
	 * 如果表达式 exp 是编译时常量,则返回1
	 * 否则,返回 0.
	 */
	if (__builtin_constant_p(size)) {
		/* 如果size为0,那么就返回BITS_PER_LONG - PAGE_SHIFT */
		if (!size)
			return BITS_PER_LONG - PAGE_SHIFT;

		/* 如果size比一个page小,那么就返回0 */
		if (size < (1UL << PAGE_SHIFT))
			return 0;

		/*
		 * 求以2为底x的对数,且向下取整
		 * ilog2(17) = 4
		 * 到这里就比一个PAGE_SIZE大了,那么取对数之后 - PAGE_SHIFT + 1
		 */
		return ilog2((size) - 1) - PAGE_SHIFT + 1;
	}

	/* 如果是变量,那么先让size -- */
	size--;
	/* 然后除以页面的大小 */
	size >>= PAGE_SHIFT;
#if BITS_PER_LONG == 32
	return fls(size);
#else
	return fls64(size);
#endif
}

#endif	/* __ASSEMBLY__ */

#endif	/* __ASM_GENERIC_GETORDER_H */
