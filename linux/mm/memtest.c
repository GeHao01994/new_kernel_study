// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/memblock.h>
#include <linux/seq_file.h>

static bool early_memtest_done;
static phys_addr_t early_memtest_bad_size;

static u64 patterns[] __initdata = {
	/*
	 * The first entry has to be 0 to leave memtest with zeroed memory
	 *
	 * 第一条entry必须是0,以便以清零的内存状态退出memtest
	 */
	0,
	0xffffffffffffffffULL,
	0x5555555555555555ULL,
	0xaaaaaaaaaaaaaaaaULL,
	0x1111111111111111ULL,
	0x2222222222222222ULL,
	0x4444444444444444ULL,
	0x8888888888888888ULL,
	0x3333333333333333ULL,
	0x6666666666666666ULL,
	0x9999999999999999ULL,
	0xccccccccccccccccULL,
	0x7777777777777777ULL,
	0xbbbbbbbbbbbbbbbbULL,
	0xddddddddddddddddULL,
	0xeeeeeeeeeeeeeeeeULL,
	0x7a6c7258554e494cULL, /* yeah ;-) */
};

static void __init reserve_bad_mem(u64 pattern, phys_addr_t start_bad, phys_addr_t end_bad)
{
	pr_info("  %016llx bad mem addr %pa - %pa reserved\n",
		cpu_to_be64(pattern), &start_bad, &end_bad);
	/* reserve这段内存 */
	memblock_reserve(start_bad, end_bad - start_bad);
	/* 把这个大小记录在early_memtest_bad_size中 */
	early_memtest_bad_size += (end_bad - start_bad);
}

static void __init memtest(u64 pattern, phys_addr_t start_phys, phys_addr_t size)
{
	u64 *p, *start, *end;
	phys_addr_t start_bad, last_bad;
	phys_addr_t start_phys_aligned;
	/*
	 * 计算pattern的size,用以对齐
	 *
	 * incr应该是increase的缩写
	 */
	const size_t incr = sizeof(pattern);

	/* 对齐 */
	start_phys_aligned = ALIGN(start_phys, incr);
	/* 得到虚拟地址 */
	start = __va(start_phys_aligned);
	/* 得到结束地址,但是这里是以incr为单位 */
	end = start + (size - (start_phys_aligned - start_phys)) / incr;
	start_bad = 0;
	last_bad = 0;

	/* 进行写操作 */
	for (p = start; p < end; p++)
		WRITE_ONCE(*p, pattern);

	/* 进行读操作,并且让start_phys_aligned也加上incr进行步进 */
	for (p = start; p < end; p++, start_phys_aligned += incr) {
		/* 如果相等,表示没有写错,那么continue */
		if (READ_ONCE(*p) == pattern)
			continue;
		/*
		 * 这里表示不相等了,那么应该内存有问题了
		 */

		/* 这里实际上就是两个连续的坏块,那么就算到一起 */
		if (start_phys_aligned == last_bad + incr) {
			last_bad += incr;
			continue;
		}

		/* 把它进行reserved */
		if (start_bad)
			reserve_bad_mem(pattern, start_bad, last_bad + incr);
		start_bad = last_bad = start_phys_aligned;
	}

	/* 这里说的是对最后一块进行reserve */
	if (start_bad)
		reserve_bad_mem(pattern, start_bad, last_bad + incr);

	/* 设置early_memtest_done为true */
	early_memtest_done = true;
}

static void __init do_one_pass(u64 pattern, phys_addr_t start, phys_addr_t end)
{
	u64 i;
	phys_addr_t this_start, this_end;

	/* 对每一个free memblock进行测试 */
	for_each_free_mem_range(i, NUMA_NO_NODE, MEMBLOCK_NONE, &this_start,
				&this_end, NULL) {
		this_start = clamp(this_start, start, end);
		this_end = clamp(this_end, start, end);
		/* 开始打pattern */
		if (this_start < this_end) {
			pr_info("  %pa - %pa pattern %016llx\n",
				&this_start, &this_end, cpu_to_be64(pattern));
			memtest(pattern, this_start, this_end - this_start);
		}
	}
}

/* default is disabled */
static unsigned int memtest_pattern __initdata;

static int __init parse_memtest(char *arg)
{
	int ret = 0;

	if (arg)
		ret = kstrtouint(arg, 0, &memtest_pattern);
	else
		memtest_pattern = ARRAY_SIZE(patterns);

	return ret;
}

early_param("memtest", parse_memtest);

void __init early_memtest(phys_addr_t start, phys_addr_t end)
{
	unsigned int i;
	unsigned int idx = 0;

	/* 如果memtest_pattern没有被设置,那么return */
	if (!memtest_pattern)
		return;

	pr_info("early_memtest: # of tests: %u\n", memtest_pattern);

	/* 这里就是从那个patterns开始打 */
	for (i = memtest_pattern-1; i < UINT_MAX; --i) {
		idx = i % ARRAY_SIZE(patterns);
		do_one_pass(patterns[idx], start, end);
	}
}

/* 这函数实际上就是在/proc/meminfo里面打印出来 */
void memtest_report_meminfo(struct seq_file *m)
{
	unsigned long early_memtest_bad_size_kb;

	if (!IS_ENABLED(CONFIG_PROC_FS))
		return;

	if (!early_memtest_done)
		return;

	/* 把它转换成kb,然后打印 */
	early_memtest_bad_size_kb = early_memtest_bad_size >> 10;
	if (early_memtest_bad_size && !early_memtest_bad_size_kb)
		early_memtest_bad_size_kb = 1;
	/* When 0 is reported, it means there actually was a successful test */
	seq_printf(m, "EarlyMemtestBad:   %5lu kB\n", early_memtest_bad_size_kb);
}
