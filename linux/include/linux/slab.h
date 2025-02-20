/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Written by Mark Hemment, 1996 (markhe@nextd.demon.co.uk).
 *
 * (C) SGI 2006, Christoph Lameter
 * 	Cleaned up and restructured to ease the addition of alternative
 * 	implementations of SLAB allocators.
 * (C) Linux Foundation 2008-2013
 *      Unified interface for all slab allocators
 */

#ifndef _LINUX_SLAB_H
#define	_LINUX_SLAB_H

#include <linux/cache.h>
#include <linux/gfp.h>
#include <linux/overflow.h>
#include <linux/types.h>
#include <linux/workqueue.h>
#include <linux/percpu-refcount.h>
#include <linux/cleanup.h>
#include <linux/hash.h>

enum _slab_flag_bits {
	_SLAB_CONSISTENCY_CHECKS,
	_SLAB_RED_ZONE,
	_SLAB_POISON,
	_SLAB_KMALLOC,
	_SLAB_HWCACHE_ALIGN,
	_SLAB_CACHE_DMA,
	_SLAB_CACHE_DMA32,
	_SLAB_STORE_USER,
	_SLAB_PANIC,
	_SLAB_TYPESAFE_BY_RCU,
	_SLAB_TRACE,
#ifdef CONFIG_DEBUG_OBJECTS
	_SLAB_DEBUG_OBJECTS,
#endif
	_SLAB_NOLEAKTRACE,
	_SLAB_NO_MERGE,
#ifdef CONFIG_FAILSLAB
	_SLAB_FAILSLAB,
#endif
#ifdef CONFIG_MEMCG
	_SLAB_ACCOUNT,
#endif
#ifdef CONFIG_KASAN_GENERIC
	_SLAB_KASAN,
#endif
	_SLAB_NO_USER_FLAGS,
#ifdef CONFIG_KFENCE
	_SLAB_SKIP_KFENCE,
#endif
#ifndef CONFIG_SLUB_TINY
	_SLAB_RECLAIM_ACCOUNT,
#endif
	_SLAB_OBJECT_POISON,
	_SLAB_CMPXCHG_DOUBLE,
#ifdef CONFIG_SLAB_OBJ_EXT
	_SLAB_NO_OBJ_EXT,
#endif
	_SLAB_FLAGS_LAST_BIT
};

#define __SLAB_FLAG_BIT(nr)	((slab_flags_t __force)(1U << (nr)))
#define __SLAB_FLAG_UNUSED	((slab_flags_t __force)(0U))

/*
 * Flags to pass to kmem_cache_create().
 * The ones marked DEBUG need CONFIG_SLUB_DEBUG enabled, otherwise are no-op
 *
 * 传递给 kmem_cache_create() 的标志.
 * 其中标记为 DEBUG 的标志需要启用 CONFIG_SLUB_DEBUG 配置,否则它们将不起作用。
 */
/*
 * DEBUG: Perform (expensive) checks on alloc/free
 * 调试: 在执行分配/释放时进行(耗时的)检查
 */
#define SLAB_CONSISTENCY_CHECKS	__SLAB_FLAG_BIT(_SLAB_CONSISTENCY_CHECKS)
/*
 * DEBUG: Red zone objs in a cache
 * 调试：在缓存中为对象设置红区
 */
#define SLAB_RED_ZONE		__SLAB_FLAG_BIT(_SLAB_RED_ZONE)
/*
 * DEBUG: Poison objects
 */
#define SLAB_POISON		__SLAB_FLAG_BIT(_SLAB_POISON)
/*
 * Indicate a kmalloc slab
 *
 * 指示一个 kmalloc slab
 */
#define SLAB_KMALLOC		__SLAB_FLAG_BIT(_SLAB_KMALLOC)
/**
 * define SLAB_HWCACHE_ALIGN - Align objects on cache line boundaries.
 *
 * 定义SLAB_HWCACHE_ALIGN - 在cache line界上对齐对象.
 *
 * Sufficiently large objects are aligned on cache line boundary. For object
 * size smaller than a half of cache line size, the alignment is on the half of
 * cache line size. In general, if object size is smaller than 1/2^n of cache
 * line size, the alignment is adjusted to 1/2^n.
 *
 * If explicit alignment is also requested by the respective
 * &struct kmem_cache_args field, the greater of both is alignments is applied.
 *
 * 对于足够大的对象,它们在缓存行边界上进行对齐.
 * 对于小于缓存行尺寸一半的对象,对齐方式是以缓存行尺寸的一半为准.
 * 通常,如果对象的尺寸小于缓存行尺寸的1/(2的n次方)(n为正整数),则对齐方式会相应调整为1/(2的n次方).
 *
 * 如果通过相应的&struct kmem_cache_args字段也请求了明确的对齐方式,则会采用这两种对齐方式中较大的那个.
 */
#define SLAB_HWCACHE_ALIGN	__SLAB_FLAG_BIT(_SLAB_HWCACHE_ALIGN)
/* Use GFP_DMA memory */
#define SLAB_CACHE_DMA		__SLAB_FLAG_BIT(_SLAB_CACHE_DMA)
/* Use GFP_DMA32 memory */
#define SLAB_CACHE_DMA32	__SLAB_FLAG_BIT(_SLAB_CACHE_DMA32)
/*
 * DEBUG: Store the last owner for bug hunting
 * DEBUG: 存储最后的使用者以进行BUG追踪
 */
#define SLAB_STORE_USER		__SLAB_FLAG_BIT(_SLAB_STORE_USER)
/*
 * Panic if kmem_cache_create() fails
 * 如果kmem_cache_create失败,则panic
 */
#define SLAB_PANIC		__SLAB_FLAG_BIT(_SLAB_PANIC)
/**
 * define SLAB_TYPESAFE_BY_RCU - **WARNING** READ THIS!
 *
 * This delays freeing the SLAB page by a grace period, it does _NOT_
 * delay object freeing. This means that if you do kmem_cache_free()
 * that memory location is free to be reused at any time. Thus it may
 * be possible to see another object there in the same RCU grace period.
 *
 * This feature only ensures the memory location backing the object
 * stays valid, the trick to using this is relying on an independent
 * object validation pass. Something like:
 *
 * 这会延迟释放SLAB页面一个宽限期,但不会延迟释放对象.
 * 这意味着,当你调用kmem_cache_free()函数时,该内存位置可以随时被重用.
 * 因此,在同一个 RCU(Read-Copy Update)宽限期内,你可能会在那里看到另一个对象.
 * 这个特性仅确保对象所依赖的内存位置保持有效.要使用这个特性,关键在于依赖一个独立的对象验证过程.
 * 这个过程可能类似于：
 *
 * ::
 *
 *  begin:
 *   rcu_read_lock();
 *   obj = lockless_lookup(key);
 *   if (obj) {
 *     if (!try_get_ref(obj)) // might fail for free objects
 *       rcu_read_unlock();
 *       goto begin;
 *
 *     if (obj->key != key) { // not the object we expected
 *       put_ref(obj);
 *       rcu_read_unlock();
 *       goto begin;
 *     }
 *   }
 *  rcu_read_unlock();
 *
 * This is useful if we need to approach a kernel structure obliquely,
 * from its address obtained without the usual locking. We can lock
 * the structure to stabilize it and check it's still at the given address,
 * only if we can be sure that the memory has not been meanwhile reused
 * for some other kind of object (which our subsystem's lock might corrupt).
 *
 * 如果我们需要从非正常的锁定途径(即,在没有通常锁定的情况下获得的地址)来间接访问内核结构,
 * 这一方法将非常有用.我们只有在确保内存在此期间没有被重新用于其他类型的对象(这可能会因我们子系统的锁定而损坏)的情况下,
 * 才能对该结构进行锁定以稳定它,并检查它是否仍然位于给定的地址.
 *
 * rcu_read_lock before reading the address, then rcu_read_unlock after
 * taking the spinlock within the structure expected at that address.
 *
 * 在读取地址之前,我们需要先获取rcu_read_lock,然后在预期位于该地址的结构内部获取自旋锁之后
 * 再释放rcu_read_unlock.
 *
 * Note that it is not possible to acquire a lock within a structure
 * allocated with SLAB_TYPESAFE_BY_RCU without first acquiring a reference
 * as described above.  The reason is that SLAB_TYPESAFE_BY_RCU pages
 * are not zeroed before being given to the slab, which means that any
 * locks must be initialized after each and every kmem_struct_alloc().
 * Alternatively, make the ctor passed to kmem_cache_create() initialize
 * the locks at page-allocation time, as is done in __i915_request_ctor(),
 * sighand_ctor(), and anon_vma_ctor().  Such a ctor permits readers
 * to safely acquire those ctor-initialized locks under rcu_read_lock()
 * protection.
 *
 * 需要注意的是,对于使用SLAB_TYPESAFE_BY_RCU分配的结构,我们无法在不先获取上述描述的引用的情况下获取其内部的锁.
 * 原因是,在将 SLAB_TYPESAFE_BY_RCU 页面交给slab之前,这些页面并没有被清零,这意味着任何锁都必须在每次kmem_struct_alloc()调用之后进行初始化.
 * 或者,我们可以让传递给 kmem_cache_create()的构造函数在页面分配时初始化锁,
 * 就像 __i915_request_ctor()、sighand_ctor() 和 anon_vma_ctor() 中所做的那样.
 * 这样的构造函数允许读者在rcu_read_lock()保护下安全地获取这些由构造函数初始化的锁.
 *
 * Note that SLAB_TYPESAFE_BY_RCU was originally named SLAB_DESTROY_BY_RCU.
 */
#define SLAB_TYPESAFE_BY_RCU	__SLAB_FLAG_BIT(_SLAB_TYPESAFE_BY_RCU)
/*
 * Trace allocations and frees
 *
 * Trace分配和释放
 */
#define SLAB_TRACE		__SLAB_FLAG_BIT(_SLAB_TRACE)

/*
 * Flag to prevent checks on free
 * 防止释放时检查
 */
#ifdef CONFIG_DEBUG_OBJECTS
# define SLAB_DEBUG_OBJECTS	__SLAB_FLAG_BIT(_SLAB_DEBUG_OBJECTS)
#else
# define SLAB_DEBUG_OBJECTS	__SLAB_FLAG_UNUSED
#endif

/* Avoid kmemleak tracing */
#define SLAB_NOLEAKTRACE	__SLAB_FLAG_BIT(_SLAB_NOLEAKTRACE)

/*
 * Prevent merging with compatible kmem caches. This flag should be used
 * cautiously. Valid use cases:
 *
 * - caches created for self-tests (e.g. kunit)
 * - general caches created and used by a subsystem, only when a
 *   (subsystem-specific) debug option is enabled
 * - performance critical caches, should be very rare and consulted with slab
 *   maintainers, and not used together with CONFIG_SLUB_TINY
 *
 * 防止与兼容的kmem缓存合并. 此标志应谨慎使用.
 * 有效的用例包括：
 *
 * 为自测(例如 kunit)创建的caches
 * 子系统创建和使用的通用缓存,但仅当启用了(子系统特定的)调试选项时
 *
 * 对性能至关重要的缓存,这种情况应该非常罕见,并且需要与slab维护者协商,同时不能与CONFIG_SLUB_TINY 一起使用.
 */
#define SLAB_NO_MERGE		__SLAB_FLAG_BIT(_SLAB_NO_MERGE)

/*
 * Fault injection mark
 * Fault注入mask
 */
#ifdef CONFIG_FAILSLAB
# define SLAB_FAILSLAB		__SLAB_FLAG_BIT(_SLAB_FAILSLAB)
#else
# define SLAB_FAILSLAB		__SLAB_FLAG_UNUSED
#endif
/**
 * define SLAB_ACCOUNT - Account allocations to memcg.
 *
 * All object allocations from this cache will be memcg accounted, regardless of
 * __GFP_ACCOUNT being or not being passed to individual allocations.
 *
 * 定义 SLAB_ACCOUNT - 对 memcg 进行分配计数
 * 从此缓存进行的所有对象分配都将进行 memcg计数,无论是否向单个分配传递了__GFP_ACCOUNT标志.
 */
#ifdef CONFIG_MEMCG
# define SLAB_ACCOUNT		__SLAB_FLAG_BIT(_SLAB_ACCOUNT)
#else
# define SLAB_ACCOUNT		__SLAB_FLAG_UNUSED
#endif

#ifdef CONFIG_KASAN_GENERIC
#define SLAB_KASAN		__SLAB_FLAG_BIT(_SLAB_KASAN)
#else
#define SLAB_KASAN		__SLAB_FLAG_UNUSED
#endif

/*
 * Ignore user specified debugging flags.
 * Intended for caches created for self-tests so they have only flags
 * specified in the code and other flags are ignored.
 *
 * 忽略用户指定的调试标志.
 * 旨在为自测创建的缓存,因此它们只具有代码中指定的标志,并忽略其他标志.
 */
#define SLAB_NO_USER_FLAGS	__SLAB_FLAG_BIT(_SLAB_NO_USER_FLAGS)

#ifdef CONFIG_KFENCE
#define SLAB_SKIP_KFENCE	__SLAB_FLAG_BIT(_SLAB_SKIP_KFENCE)
#else
#define SLAB_SKIP_KFENCE	__SLAB_FLAG_UNUSED
#endif

/*
 * The following flags affect the page allocator grouping pages by mobility
 * 以下标志影响页面分配器按移动性对页面进行分组
 */
/**
 * define SLAB_RECLAIM_ACCOUNT - Objects are reclaimable.
 *
 * SLAB_RECLAIM_ACCOUNT: 对象是可回收的.
 *
 * Use this flag for caches that have an associated shrinker. As a result, slab
 * pages are allocated with __GFP_RECLAIMABLE, which affects grouping pages by
 * mobility, and are accounted in SReclaimable counter in /proc/meminfo
 *
 * 这个标志用于那些与shrinker（收缩器）相关联的缓存.
 * shrinker是内核中用于在内存压力时回收内存的一种机制.
 * 当为缓存设置了这个标志时,意味着该缓存中的对象在必要时可以被内核回收以释放内存.
 *
 * 此标志用于那些关联有收缩器(shrinker)的缓存.
 *
 * 结果,slab页面会以__GFP_RECLAIMABLE(可回收)的方式分配,这会影响页面按移动性的分组,
 * 并且这些页面会在/proc/meminfo的SReclaimable计数器中进行统计
 *
 */
#ifndef CONFIG_SLUB_TINY
#define SLAB_RECLAIM_ACCOUNT	__SLAB_FLAG_BIT(_SLAB_RECLAIM_ACCOUNT)
#else
#define SLAB_RECLAIM_ACCOUNT	__SLAB_FLAG_UNUSED
#endif
#define SLAB_TEMPORARY		SLAB_RECLAIM_ACCOUNT	/* Objects are short-lived */

/* Slab created using create_boot_cache */
#ifdef CONFIG_SLAB_OBJ_EXT
#define SLAB_NO_OBJ_EXT		__SLAB_FLAG_BIT(_SLAB_NO_OBJ_EXT)
#else
#define SLAB_NO_OBJ_EXT		__SLAB_FLAG_UNUSED
#endif

/*
 * freeptr_t represents a SLUB freelist pointer, which might be encoded
 * and not dereferenceable if CONFIG_SLAB_FREELIST_HARDENED is enabled.
 *
 * freeptr_t代表了一个 SLUB 自由列表(freelist)指针,当启用CONFIG_SLAB_FREELIST_HARDENED配置选项时,
 * 这个指针可能会被编码,并且不能直接解引用.
 */
typedef struct { unsigned long v; } freeptr_t;

/*
 * ZERO_SIZE_PTR will be returned for zero sized kmalloc requests.
 *
 * Dereferencing ZERO_SIZE_PTR will lead to a distinct access fault.
 *
 * ZERO_SIZE_PTR can be passed to kfree though in the same way that NULL can.
 * Both make kfree a no-op.
 */
#define ZERO_SIZE_PTR ((void *)16)

#define ZERO_OR_NULL_PTR(x) ((unsigned long)(x) <= \
				(unsigned long)ZERO_SIZE_PTR)

#include <linux/kasan.h>

struct list_lru;
struct mem_cgroup;
/*
 * struct kmem_cache related prototypes
 */
bool slab_is_available(void);

/**
 * struct kmem_cache_args - Less common arguments for kmem_cache_create()
 *
 * Any uninitialized fields of the structure are interpreted as unused. The
 * exception is @freeptr_offset where %0 is a valid value, so
 * @use_freeptr_offset must be also set to %true in order to interpret the field
 * as used. For @useroffset %0 is also valid, but only with non-%0
 * @usersize.
 *
 * When %NULL args is passed to kmem_cache_create(), it is equivalent to all
 * fields unused.
 *
 * kmem_cache_args 结构体是用于kmem_cache_create()函数的一个参数结构体,它包含了一些不那么常用的参数.
 *
 * 这个结构体中的任何未初始化字段都被解释为未使用.
 * 但是有两个例外情况需要注意：
 * freeptr_offset字段: 当这个字段的值为%0(即0)时,它仍然可以被视为有效值,但前提是需要同时将use_freeptr_offset字段设置为%true(即true),
 * 这样 freeptr_offset 字段才会被解释为已使用.
 *
 * useroffset 字段: 同样地,useroffset字段的值为%0时也是有效的,但仅当usersize字段的值非%0(即非0)时.
 * 这意味着如果usersize为0,那么useroffset的值将被忽略,无论其是否为0.
 *
 * 当向kmem_cache_create(()函数传递 NULL作为args参数时,这等价于所有字段都未被使用.
 */
struct kmem_cache_args {
	/**
	 * @align: The required alignment for the objects.
	 *
	 * %0 means no specific alignment is requested.
	 *
	 * @align 字段表示对象所需的对齐要求.
	 * %0(即0)意味着没有特定的对齐要求.
	 */
	unsigned int align;
	/**
	 * @useroffset: Usercopy region offset.
	 *
	 * %0 is a valid offset, when @usersize is non-%0
	 *
	 * @useroffset 字段代表用户复制区域的偏移量.
	 *
	 * 当@usersize(用户区域的大小)不为0时,偏移量设置为0是有效的
	 */
	unsigned int useroffset;
	/**
	 * @usersize: Usercopy region size.
	 *
	 * %0 means no usercopy region is specified.
	 *
	 * @usersize 字段代表用户复制区域的大小.
	 *
	 * 当@usersize的值为0时,表示没有指定用户复制区域
	 */
	unsigned int usersize;
	/**
	 * @freeptr_offset: Custom offset for the free pointer
	 * in &SLAB_TYPESAFE_BY_RCU caches
	 *
	 * By default &SLAB_TYPESAFE_BY_RCU caches place the free pointer
	 * outside of the object. This might cause the object to grow in size.
	 * Cache creators that have a reason to avoid this can specify a custom
	 * free pointer offset in their struct where the free pointer will be
	 * placed.
	 *
	 * Note that placing the free pointer inside the object requires the
	 * caller to ensure that no fields are invalidated that are required to
	 * guard against object recycling (See &SLAB_TYPESAFE_BY_RCU for
	 * details).
	 *
	 * Using %0 as a value for @freeptr_offset is valid. If @freeptr_offset
	 * is specified, %use_freeptr_offset must be set %true.
	 *
	 * Note that @ctor currently isn't supported with custom free pointers
	 * as a @ctor requires an external free pointer.
	 *
	 * @freeptr_offset字段用于指定在&SLAB_TYPESAFE_BY_RCU类型的缓存中,自由指针(free pointer)的自定义偏移量.
	 *
	 * 默认情况下,&SLAB_TYPESAFE_BY_RCU类型的缓存会将free pointer放置在对象外部. 这可能会导致对象的大小增加.
	 * 如果缓存创建者有理由避免这种情况,他们可以在自己的结构体中指定一个自定义的自由指针偏移量,以确定自由指针的放置位置.
	 *
	 * 需要注意的是,将自由指针放置在对象内部要求调用者确保没有使保护对象不被重复使用的字段失效(有关详细信息,请参阅 &SLAB_TYPESAFE_BY_RCU).
	 *
	 * 使用%0作为@freeptr_offset的值是有效的. 如果指定了@freeptr_offset,则必须将%use_freeptr_offset设置为%true.
	 *
	 * 另外,请注意,当使用自定义自由指针时,目前不支持@ctor(构造函数).因为@ctor需要一个外部的自由指针.
	 */
	unsigned int freeptr_offset;
	/**
	 * @use_freeptr_offset: Whether a @freeptr_offset is used.
	 */
	bool use_freeptr_offset;
	/**
	 * @ctor: A constructor for the objects.
	 *
	 * The constructor is invoked for each object in a newly allocated slab
	 * page. It is the cache user's responsibility to free object in the
	 * same state as after calling the constructor, or deal appropriately
	 * with any differences between a freshly constructed and a reallocated
	 * object.
	 *
	 * %NULL means no constructor.
	 *
	 * @ctor 字段代表对象的构造函数.
	 *
	 * 构造函数会在新分配的slab页面中的每个对象上被调用.缓存的使用者有责任确保在释放对象时,对象的状态与调用构造函数后的状态相同,或者妥善处理新构造的对象和重新分配的对象之间的任何差异.
	 *
	 * 如果@ctor被设置为%NULL,则表示没有构造函数.这意味着在对象被分配时,不会自动调用任何初始化代码.
	 * 缓存的使用者需要自己确保对象在使用前处于正确的状态.
	 */
	void (*ctor)(void *);
};

struct kmem_cache *__kmem_cache_create_args(const char *name,
					    unsigned int object_size,
					    struct kmem_cache_args *args,
					    slab_flags_t flags);
static inline struct kmem_cache *
__kmem_cache_create(const char *name, unsigned int size, unsigned int align,
		    slab_flags_t flags, void (*ctor)(void *))
{
	/* 拿到align和构造函数 */
	struct kmem_cache_args kmem_args = {
		.align	= align,
		.ctor	= ctor,
	};

	return __kmem_cache_create_args(name, size, &kmem_args, flags);
}

/**
 * kmem_cache_create_usercopy - Create a kmem cache with a region suitable
 * for copying to userspace.
 * @name: A string which is used in /proc/slabinfo to identify this cache.
 * @size: The size of objects to be created in this cache.
 * @align: The required alignment for the objects.
 * @flags: SLAB flags
 * @useroffset: Usercopy region offset
 * @usersize: Usercopy region size
 * @ctor: A constructor for the objects, or %NULL.
 *
 * This is a legacy wrapper, new code should use either KMEM_CACHE_USERCOPY()
 * if whitelisting a single field is sufficient, or kmem_cache_create() with
 * the necessary parameters passed via the args parameter (see
 * &struct kmem_cache_args)
 *
 * Return: a pointer to the cache on success, NULL on failure.
 */
static inline struct kmem_cache *
kmem_cache_create_usercopy(const char *name, unsigned int size,
			   unsigned int align, slab_flags_t flags,
			   unsigned int useroffset, unsigned int usersize,
			   void (*ctor)(void *))
{
	struct kmem_cache_args kmem_args = {
		.align		= align,
		.ctor		= ctor,
		.useroffset	= useroffset,
		.usersize	= usersize,
	};

	return __kmem_cache_create_args(name, size, &kmem_args, flags);
}

/* If NULL is passed for @args, use this variant with default arguments. */
static inline struct kmem_cache *
__kmem_cache_default_args(const char *name, unsigned int size,
			  struct kmem_cache_args *args,
			  slab_flags_t flags)
{
	struct kmem_cache_args kmem_default_args = {};

	/* Make sure we don't get passed garbage. */
	if (WARN_ON_ONCE(args))
		return ERR_PTR(-EINVAL);

	return __kmem_cache_create_args(name, size, &kmem_default_args, flags);
}

/**
 * kmem_cache_create - Create a kmem cache.
 *
 * kmem_cache_create 函数(或宏)用于创建一个内核内存缓存(kmem cache)
 *
 * @__name: A string which is used in /proc/slabinfo to identify this cache.
 * @__object_size: The size of objects to be created in this cache.
 * @__args: Optional arguments, see &struct kmem_cache_args. Passing %NULL
 *	    means defaults will be used for all the arguments.
 *
 * @__name: 一个字符串,用于在/proc/slabinfo文件中标识这个缓存. 这个名字应该是唯一的,以便于区分不同的缓存.
 * @__object_size: 要在这个缓存中创建的对象的大小(以字节为单位). 这是每个对象所需内存空间的大小.
 * @__args: 可选参数,指向一个struct kmem_cache_args 结构体的指针,该结构体包含了创建缓存时可以指定的各种选项.
 *	    如果传递NULL,则使用所有参数的默认值.这个参数允许调用者指定诸如对齐要求、构造函数、析构函数等高级选项.
 *
 * This is currently implemented as a macro using ``_Generic()`` to call
 * either the new variant of the function, or a legacy one.
 *
 * The new variant has 4 parameters:
 * ``kmem_cache_create(name, object_size, args, flags)``
 *
 * See __kmem_cache_create_args() which implements this.
 *
 * The legacy variant has 5 parameters:
 * ``kmem_cache_create(name, object_size, align, flags, ctor)``
 *
 * The align and ctor parameters map to the respective fields of
 * &struct kmem_cache_args
 *
 * Context: Cannot be called within a interrupt, but can be interrupted.
 *
 * Return: a pointer to the cache on success, NULL on failure.
 *
 * 在新版本中,kmem_cache_create宏使用_Generic()关键字根据传递的参数类型调用不同的函数变体.
 * 有两种变体：
 *
 * 新变体接受四个参数: name(缓存名称)、object_size(对象大小)、args(指向 struct kmem_cache_args 的指针,包含可选参数)和flags(标志位,用于指定缓存的行为,如是否启用 SLAB 调试等).
 *
 * 旧变体接受五个参数: name(缓存名称)、object_size(对象大小)、align(对齐要求)、flags(标志位)和ctor(构造函数指针,用于在对象分配时初始化对象).
 *
 * 在旧变体中,align和ctor参数分别对应于struct kmem_cache_args结构体中的相应字段.
 *
 * 调用上下文: kmem_cache_create不能在中断上下文中调用,但可以被中断.这意味着在调用此函数时,必须确保当前不在中断处理程序内部,
 * 	       但如果在调用过程中发生中断,函数应该能够正确处理这种情况.
 *
 * 返回值: 如果成功,返回一个指向新创建的缓存的指针;如果失败(例如,由于内存不足),返回 NULL.
 *
 * 在实际使用中,开发者应该根据自己的需求选择合适的变体,并提供必要的参数来创建内存缓存.
 * 创建成功后,可以使用返回的缓存指针来分配和释放对象.
 */
#define kmem_cache_create(__name, __object_size, __args, ...)           \
	_Generic((__args),                                              \
		struct kmem_cache_args *: __kmem_cache_create_args,	\
		void *: __kmem_cache_default_args,			\
		default: __kmem_cache_create)(__name, __object_size, __args, __VA_ARGS__)

void kmem_cache_destroy(struct kmem_cache *s);
int kmem_cache_shrink(struct kmem_cache *s);

/*
 * Please use this macro to create slab caches. Simply specify the
 * name of the structure and maybe some flags that are listed above.
 *
 * The alignment of the struct determines object alignment. If you
 * f.e. add ____cacheline_aligned_in_smp to the struct declaration
 * then the objects will be properly aligned in SMP configurations.
 */
#define KMEM_CACHE(__struct, __flags)                                   \
	__kmem_cache_create_args(#__struct, sizeof(struct __struct),    \
			&(struct kmem_cache_args) {			\
				.align	= __alignof__(struct __struct), \
			}, (__flags))

/*
 * To whitelist a single field for copying to/from usercopy, use this
 * macro instead for KMEM_CACHE() above.
 */
#define KMEM_CACHE_USERCOPY(__struct, __flags, __field)						\
	__kmem_cache_create_args(#__struct, sizeof(struct __struct),				\
			&(struct kmem_cache_args) {						\
				.align		= __alignof__(struct __struct),			\
				.useroffset	= offsetof(struct __struct, __field),		\
				.usersize	= sizeof_field(struct __struct, __field),	\
			}, (__flags))

/*
 * Common kmalloc functions provided by all allocators
 */
void * __must_check krealloc_noprof(const void *objp, size_t new_size,
				    gfp_t flags) __realloc_size(2);
#define krealloc(...)				alloc_hooks(krealloc_noprof(__VA_ARGS__))

void kfree(const void *objp);
void kfree_sensitive(const void *objp);
size_t __ksize(const void *objp);

DEFINE_FREE(kfree, void *, if (!IS_ERR_OR_NULL(_T)) kfree(_T))
DEFINE_FREE(kfree_sensitive, void *, if (_T) kfree_sensitive(_T))

/**
 * ksize - Report actual allocation size of associated object
 *
 * @objp: Pointer returned from a prior kmalloc()-family allocation.
 *
 * This should not be used for writing beyond the originally requested
 * allocation size. Either use krealloc() or round up the allocation size
 * with kmalloc_size_roundup() prior to allocation. If this is used to
 * access beyond the originally requested allocation size, UBSAN_BOUNDS
 * and/or FORTIFY_SOURCE may trip, since they only know about the
 * originally allocated size via the __alloc_size attribute.
 */
size_t ksize(const void *objp);

#ifdef CONFIG_PRINTK
bool kmem_dump_obj(void *object);
#else
static inline bool kmem_dump_obj(void *object) { return false; }
#endif

/*
 * Some archs want to perform DMA into kmalloc caches and need a guaranteed
 * alignment larger than the alignment of a 64-bit integer.
 * Setting ARCH_DMA_MINALIGN in arch headers allows that.
 */
#ifdef ARCH_HAS_DMA_MINALIGN
#if ARCH_DMA_MINALIGN > 8 && !defined(ARCH_KMALLOC_MINALIGN)
#define ARCH_KMALLOC_MINALIGN ARCH_DMA_MINALIGN
#endif
#endif

#ifndef ARCH_KMALLOC_MINALIGN
#define ARCH_KMALLOC_MINALIGN __alignof__(unsigned long long)
#elif ARCH_KMALLOC_MINALIGN > 8
#define KMALLOC_MIN_SIZE ARCH_KMALLOC_MINALIGN
#define KMALLOC_SHIFT_LOW ilog2(KMALLOC_MIN_SIZE)
#endif

/*
 * Setting ARCH_SLAB_MINALIGN in arch headers allows a different alignment.
 * Intended for arches that get misalignment faults even for 64 bit integer
 * aligned buffers.
 */
#ifndef ARCH_SLAB_MINALIGN
#define ARCH_SLAB_MINALIGN __alignof__(unsigned long long)
#endif

/*
 * Arches can define this function if they want to decide the minimum slab
 * alignment at runtime. The value returned by the function must be a power
 * of two and >= ARCH_SLAB_MINALIGN.
 */
#ifndef arch_slab_minalign
static inline unsigned int arch_slab_minalign(void)
{
	return ARCH_SLAB_MINALIGN;
}
#endif

/*
 * kmem_cache_alloc and friends return pointers aligned to ARCH_SLAB_MINALIGN.
 * kmalloc and friends return pointers aligned to both ARCH_KMALLOC_MINALIGN
 * and ARCH_SLAB_MINALIGN, but here we only assume the former alignment.
 */
#define __assume_kmalloc_alignment __assume_aligned(ARCH_KMALLOC_MINALIGN)
#define __assume_slab_alignment __assume_aligned(ARCH_SLAB_MINALIGN)
#define __assume_page_alignment __assume_aligned(PAGE_SIZE)

/*
 * Kmalloc array related definitions
 */

/*
 * SLUB directly allocates requests fitting in to an order-1 page
 * (PAGE_SIZE*2).  Larger requests are passed to the page allocator.
 */
#define KMALLOC_SHIFT_HIGH	(PAGE_SHIFT + 1)
#define KMALLOC_SHIFT_MAX	(MAX_PAGE_ORDER + PAGE_SHIFT)
#ifndef KMALLOC_SHIFT_LOW
#define KMALLOC_SHIFT_LOW	3
#endif

/* Maximum allocatable size */
#define KMALLOC_MAX_SIZE	(1UL << KMALLOC_SHIFT_MAX)
/* Maximum size for which we actually use a slab cache */
#define KMALLOC_MAX_CACHE_SIZE	(1UL << KMALLOC_SHIFT_HIGH)
/* Maximum order allocatable via the slab allocator */
#define KMALLOC_MAX_ORDER	(KMALLOC_SHIFT_MAX - PAGE_SHIFT)

/*
 * Kmalloc subsystem.
 */
#ifndef KMALLOC_MIN_SIZE
#define KMALLOC_MIN_SIZE (1 << KMALLOC_SHIFT_LOW)
#endif

/*
 * This restriction comes from byte sized index implementation.
 * Page size is normally 2^12 bytes and, in this case, if we want to use
 * byte sized index which can represent 2^8 entries, the size of the object
 * should be equal or greater to 2^12 / 2^8 = 2^4 = 16.
 * If minimum size of kmalloc is less than 16, we use it as minimum object
 * size and give up to use byte sized index.
 */
#define SLAB_OBJ_MIN_SIZE      (KMALLOC_MIN_SIZE < 16 ? \
                               (KMALLOC_MIN_SIZE) : 16)

#ifdef CONFIG_RANDOM_KMALLOC_CACHES
#define RANDOM_KMALLOC_CACHES_NR	15 // # of cache copies
#else
#define RANDOM_KMALLOC_CACHES_NR	0
#endif

/*
 * Whenever changing this, take care of that kmalloc_type() and
 * create_kmalloc_caches() still work as intended.
 *
 * KMALLOC_NORMAL can contain only unaccounted objects whereas KMALLOC_CGROUP
 * is for accounted but unreclaimable and non-dma objects. All the other
 * kmem caches can have both accounted and unaccounted objects.
 */
enum kmalloc_cache_type {
	KMALLOC_NORMAL = 0,
#ifndef CONFIG_ZONE_DMA
	KMALLOC_DMA = KMALLOC_NORMAL,
#endif
#ifndef CONFIG_MEMCG
	KMALLOC_CGROUP = KMALLOC_NORMAL,
#endif
	KMALLOC_RANDOM_START = KMALLOC_NORMAL,
	KMALLOC_RANDOM_END = KMALLOC_RANDOM_START + RANDOM_KMALLOC_CACHES_NR,
#ifdef CONFIG_SLUB_TINY
	KMALLOC_RECLAIM = KMALLOC_NORMAL,
#else
	KMALLOC_RECLAIM,
#endif
#ifdef CONFIG_ZONE_DMA
	KMALLOC_DMA,
#endif
#ifdef CONFIG_MEMCG
	KMALLOC_CGROUP,
#endif
	NR_KMALLOC_TYPES
};

typedef struct kmem_cache * kmem_buckets[KMALLOC_SHIFT_HIGH + 1];

extern kmem_buckets kmalloc_caches[NR_KMALLOC_TYPES];

/*
 * Define gfp bits that should not be set for KMALLOC_NORMAL.
 */
#define KMALLOC_NOT_NORMAL_BITS					\
	(__GFP_RECLAIMABLE |					\
	(IS_ENABLED(CONFIG_ZONE_DMA)   ? __GFP_DMA : 0) |	\
	(IS_ENABLED(CONFIG_MEMCG) ? __GFP_ACCOUNT : 0))

extern unsigned long random_kmalloc_seed;

static __always_inline enum kmalloc_cache_type kmalloc_type(gfp_t flags, unsigned long caller)
{
	/*
	 * The most common case is KMALLOC_NORMAL, so test for it
	 * with a single branch for all the relevant flags.
	 */
	if (likely((flags & KMALLOC_NOT_NORMAL_BITS) == 0))
#ifdef CONFIG_RANDOM_KMALLOC_CACHES
		/* RANDOM_KMALLOC_CACHES_NR (=15) copies + the KMALLOC_NORMAL */
		return KMALLOC_RANDOM_START + hash_64(caller ^ random_kmalloc_seed,
						      ilog2(RANDOM_KMALLOC_CACHES_NR + 1));
#else
		return KMALLOC_NORMAL;
#endif

	/*
	 * At least one of the flags has to be set. Their priorities in
	 * decreasing order are:
	 *  1) __GFP_DMA
	 *  2) __GFP_RECLAIMABLE
	 *  3) __GFP_ACCOUNT
	 */
	if (IS_ENABLED(CONFIG_ZONE_DMA) && (flags & __GFP_DMA))
		return KMALLOC_DMA;
	if (!IS_ENABLED(CONFIG_MEMCG) || (flags & __GFP_RECLAIMABLE))
		return KMALLOC_RECLAIM;
	else
		return KMALLOC_CGROUP;
}

/*
 * Figure out which kmalloc slab an allocation of a certain size
 * belongs to.
 * 0 = zero alloc
 * 1 =  65 .. 96 bytes
 * 2 = 129 .. 192 bytes
 * n = 2^(n-1)+1 .. 2^n
 *
 * Note: __kmalloc_index() is compile-time optimized, and not runtime optimized;
 * typical usage is via kmalloc_index() and therefore evaluated at compile-time.
 * Callers where !size_is_constant should only be test modules, where runtime
 * overheads of __kmalloc_index() can be tolerated.  Also see kmalloc_slab().
 */
static __always_inline unsigned int __kmalloc_index(size_t size,
						    bool size_is_constant)
{
	if (!size)
		return 0;

	if (size <= KMALLOC_MIN_SIZE)
		return KMALLOC_SHIFT_LOW;

	if (KMALLOC_MIN_SIZE <= 32 && size > 64 && size <= 96)
		return 1;
	if (KMALLOC_MIN_SIZE <= 64 && size > 128 && size <= 192)
		return 2;
	if (size <=          8) return 3;
	if (size <=         16) return 4;
	if (size <=         32) return 5;
	if (size <=         64) return 6;
	if (size <=        128) return 7;
	if (size <=        256) return 8;
	if (size <=        512) return 9;
	if (size <=       1024) return 10;
	if (size <=   2 * 1024) return 11;
	if (size <=   4 * 1024) return 12;
	if (size <=   8 * 1024) return 13;
	if (size <=  16 * 1024) return 14;
	if (size <=  32 * 1024) return 15;
	if (size <=  64 * 1024) return 16;
	if (size <= 128 * 1024) return 17;
	if (size <= 256 * 1024) return 18;
	if (size <= 512 * 1024) return 19;
	if (size <= 1024 * 1024) return 20;
	if (size <=  2 * 1024 * 1024) return 21;

	if (!IS_ENABLED(CONFIG_PROFILE_ALL_BRANCHES) && size_is_constant)
		BUILD_BUG_ON_MSG(1, "unexpected size in kmalloc_index()");
	else
		BUG();

	/* Will never be reached. Needed because the compiler may complain */
	return -1;
}
static_assert(PAGE_SHIFT <= 20);
#define kmalloc_index(s) __kmalloc_index(s, true)

#include <linux/alloc_tag.h>

/**
 * kmem_cache_alloc - Allocate an object
 * @cachep: The cache to allocate from.
 * @flags: See kmalloc().
 *
 * Allocate an object from this cache.
 * See kmem_cache_zalloc() for a shortcut of adding __GFP_ZERO to flags.
 *
 * Return: pointer to the new object or %NULL in case of error
 */
void *kmem_cache_alloc_noprof(struct kmem_cache *cachep,
			      gfp_t flags) __assume_slab_alignment __malloc;
#define kmem_cache_alloc(...)			alloc_hooks(kmem_cache_alloc_noprof(__VA_ARGS__))

void *kmem_cache_alloc_lru_noprof(struct kmem_cache *s, struct list_lru *lru,
			    gfp_t gfpflags) __assume_slab_alignment __malloc;
#define kmem_cache_alloc_lru(...)	alloc_hooks(kmem_cache_alloc_lru_noprof(__VA_ARGS__))

/**
 * kmem_cache_charge - memcg charge an already allocated slab memory
 * @objp: address of the slab object to memcg charge
 * @gfpflags: describe the allocation context
 *
 * kmem_cache_charge allows charging a slab object to the current memcg,
 * primarily in cases where charging at allocation time might not be possible
 * because the target memcg is not known (i.e. softirq context)
 *
 * The objp should be pointer returned by the slab allocator functions like
 * kmalloc (with __GFP_ACCOUNT in flags) or kmem_cache_alloc. The memcg charge
 * behavior can be controlled through gfpflags parameter, which affects how the
 * necessary internal metadata can be allocated. Including __GFP_NOFAIL denotes
 * that overcharging is requested instead of failure, but is not applied for the
 * internal metadata allocation.
 *
 * There are several cases where it will return true even if the charging was
 * not done:
 * More specifically:
 *
 * 1. For !CONFIG_MEMCG or cgroup_disable=memory systems.
 * 2. Already charged slab objects.
 * 3. For slab objects from KMALLOC_NORMAL caches - allocated by kmalloc()
 *    without __GFP_ACCOUNT
 * 4. Allocating internal metadata has failed
 *
 * Return: true if charge was successful otherwise false.
 */
bool kmem_cache_charge(void *objp, gfp_t gfpflags);
void kmem_cache_free(struct kmem_cache *s, void *objp);

kmem_buckets *kmem_buckets_create(const char *name, slab_flags_t flags,
				  unsigned int useroffset, unsigned int usersize,
				  void (*ctor)(void *));

/*
 * Bulk allocation and freeing operations. These are accelerated in an
 * allocator specific way to avoid taking locks repeatedly or building
 * metadata structures unnecessarily.
 *
 * Note that interrupts must be enabled when calling these functions.
 */
void kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p);

int kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags, size_t size, void **p);
#define kmem_cache_alloc_bulk(...)	alloc_hooks(kmem_cache_alloc_bulk_noprof(__VA_ARGS__))

static __always_inline void kfree_bulk(size_t size, void **p)
{
	kmem_cache_free_bulk(NULL, size, p);
}

void *kmem_cache_alloc_node_noprof(struct kmem_cache *s, gfp_t flags,
				   int node) __assume_slab_alignment __malloc;
#define kmem_cache_alloc_node(...)	alloc_hooks(kmem_cache_alloc_node_noprof(__VA_ARGS__))

/*
 * These macros allow declaring a kmem_buckets * parameter alongside size, which
 * can be compiled out with CONFIG_SLAB_BUCKETS=n so that a large number of call
 * sites don't have to pass NULL.
 */
#ifdef CONFIG_SLAB_BUCKETS
#define DECL_BUCKET_PARAMS(_size, _b)	size_t (_size), kmem_buckets *(_b)
#define PASS_BUCKET_PARAMS(_size, _b)	(_size), (_b)
#define PASS_BUCKET_PARAM(_b)		(_b)
#else
#define DECL_BUCKET_PARAMS(_size, _b)	size_t (_size)
#define PASS_BUCKET_PARAMS(_size, _b)	(_size)
#define PASS_BUCKET_PARAM(_b)		NULL
#endif

/*
 * The following functions are not to be used directly and are intended only
 * for internal use from kmalloc() and kmalloc_node()
 * with the exception of kunit tests
 */

void *__kmalloc_noprof(size_t size, gfp_t flags)
				__assume_kmalloc_alignment __alloc_size(1);

void *__kmalloc_node_noprof(DECL_BUCKET_PARAMS(size, b), gfp_t flags, int node)
				__assume_kmalloc_alignment __alloc_size(1);

void *__kmalloc_cache_noprof(struct kmem_cache *s, gfp_t flags, size_t size)
				__assume_kmalloc_alignment __alloc_size(3);

void *__kmalloc_cache_node_noprof(struct kmem_cache *s, gfp_t gfpflags,
				  int node, size_t size)
				__assume_kmalloc_alignment __alloc_size(4);

void *__kmalloc_large_noprof(size_t size, gfp_t flags)
				__assume_page_alignment __alloc_size(1);

void *__kmalloc_large_node_noprof(size_t size, gfp_t flags, int node)
				__assume_page_alignment __alloc_size(1);

/**
 * kmalloc - allocate kernel memory
 * @size: how many bytes of memory are required.
 * @flags: describe the allocation context
 *
 * kmalloc is the normal method of allocating memory
 * for objects smaller than page size in the kernel.
 *
 * The allocated object address is aligned to at least ARCH_KMALLOC_MINALIGN
 * bytes. For @size of power of two bytes, the alignment is also guaranteed
 * to be at least to the size. For other sizes, the alignment is guaranteed to
 * be at least the largest power-of-two divisor of @size.
 *
 * The @flags argument may be one of the GFP flags defined at
 * include/linux/gfp_types.h and described at
 * :ref:`Documentation/core-api/mm-api.rst <mm-api-gfp-flags>`
 *
 * The recommended usage of the @flags is described at
 * :ref:`Documentation/core-api/memory-allocation.rst <memory_allocation>`
 *
 * Below is a brief outline of the most useful GFP flags
 *
 * %GFP_KERNEL
 *	Allocate normal kernel ram. May sleep.
 *
 * %GFP_NOWAIT
 *	Allocation will not sleep.
 *
 * %GFP_ATOMIC
 *	Allocation will not sleep.  May use emergency pools.
 *
 * Also it is possible to set different flags by OR'ing
 * in one or more of the following additional @flags:
 *
 * %__GFP_ZERO
 *	Zero the allocated memory before returning. Also see kzalloc().
 *
 * %__GFP_HIGH
 *	This allocation has high priority and may use emergency pools.
 *
 * %__GFP_NOFAIL
 *	Indicate that this allocation is in no way allowed to fail
 *	(think twice before using).
 *
 * %__GFP_NORETRY
 *	If memory is not immediately available,
 *	then give up at once.
 *
 * %__GFP_NOWARN
 *	If allocation fails, don't issue any warnings.
 *
 * %__GFP_RETRY_MAYFAIL
 *	Try really hard to succeed the allocation but fail
 *	eventually.
 */
static __always_inline __alloc_size(1) void *kmalloc_noprof(size_t size, gfp_t flags)
{
	if (__builtin_constant_p(size) && size) {
		unsigned int index;

		if (size > KMALLOC_MAX_CACHE_SIZE)
			return __kmalloc_large_noprof(size, flags);

		index = kmalloc_index(size);
		return __kmalloc_cache_noprof(
				kmalloc_caches[kmalloc_type(flags, _RET_IP_)][index],
				flags, size);
	}
	return __kmalloc_noprof(size, flags);
}
#define kmalloc(...)				alloc_hooks(kmalloc_noprof(__VA_ARGS__))

#define kmem_buckets_alloc(_b, _size, _flags)	\
	alloc_hooks(__kmalloc_node_noprof(PASS_BUCKET_PARAMS(_size, _b), _flags, NUMA_NO_NODE))

#define kmem_buckets_alloc_track_caller(_b, _size, _flags)	\
	alloc_hooks(__kmalloc_node_track_caller_noprof(PASS_BUCKET_PARAMS(_size, _b), _flags, NUMA_NO_NODE, _RET_IP_))

static __always_inline __alloc_size(1) void *kmalloc_node_noprof(size_t size, gfp_t flags, int node)
{
	if (__builtin_constant_p(size) && size) {
		unsigned int index;

		if (size > KMALLOC_MAX_CACHE_SIZE)
			return __kmalloc_large_node_noprof(size, flags, node);

		index = kmalloc_index(size);
		return __kmalloc_cache_node_noprof(
				kmalloc_caches[kmalloc_type(flags, _RET_IP_)][index],
				flags, node, size);
	}
	return __kmalloc_node_noprof(PASS_BUCKET_PARAMS(size, NULL), flags, node);
}
#define kmalloc_node(...)			alloc_hooks(kmalloc_node_noprof(__VA_ARGS__))

/**
 * kmalloc_array - allocate memory for an array.
 * @n: number of elements.
 * @size: element size.
 * @flags: the type of memory to allocate (see kmalloc).
 */
static inline __alloc_size(1, 2) void *kmalloc_array_noprof(size_t n, size_t size, gfp_t flags)
{
	size_t bytes;

	if (unlikely(check_mul_overflow(n, size, &bytes)))
		return NULL;
	if (__builtin_constant_p(n) && __builtin_constant_p(size))
		return kmalloc_noprof(bytes, flags);
	return kmalloc_noprof(bytes, flags);
}
#define kmalloc_array(...)			alloc_hooks(kmalloc_array_noprof(__VA_ARGS__))

/**
 * krealloc_array - reallocate memory for an array.
 * @p: pointer to the memory chunk to reallocate
 * @new_n: new number of elements to alloc
 * @new_size: new size of a single member of the array
 * @flags: the type of memory to allocate (see kmalloc)
 *
 * If __GFP_ZERO logic is requested, callers must ensure that, starting with the
 * initial memory allocation, every subsequent call to this API for the same
 * memory allocation is flagged with __GFP_ZERO. Otherwise, it is possible that
 * __GFP_ZERO is not fully honored by this API.
 *
 * See krealloc_noprof() for further details.
 *
 * In any case, the contents of the object pointed to are preserved up to the
 * lesser of the new and old sizes.
 */
static inline __realloc_size(2, 3) void * __must_check krealloc_array_noprof(void *p,
								       size_t new_n,
								       size_t new_size,
								       gfp_t flags)
{
	size_t bytes;

	if (unlikely(check_mul_overflow(new_n, new_size, &bytes)))
		return NULL;

	return krealloc_noprof(p, bytes, flags);
}
#define krealloc_array(...)			alloc_hooks(krealloc_array_noprof(__VA_ARGS__))

/**
 * kcalloc - allocate memory for an array. The memory is set to zero.
 * @n: number of elements.
 * @size: element size.
 * @flags: the type of memory to allocate (see kmalloc).
 */
#define kcalloc(n, size, flags)		kmalloc_array(n, size, (flags) | __GFP_ZERO)

void *__kmalloc_node_track_caller_noprof(DECL_BUCKET_PARAMS(size, b), gfp_t flags, int node,
					 unsigned long caller) __alloc_size(1);
#define kmalloc_node_track_caller_noprof(size, flags, node, caller) \
	__kmalloc_node_track_caller_noprof(PASS_BUCKET_PARAMS(size, NULL), flags, node, caller)
#define kmalloc_node_track_caller(...)		\
	alloc_hooks(kmalloc_node_track_caller_noprof(__VA_ARGS__, _RET_IP_))

/*
 * kmalloc_track_caller is a special version of kmalloc that records the
 * calling function of the routine calling it for slab leak tracking instead
 * of just the calling function (confusing, eh?).
 * It's useful when the call to kmalloc comes from a widely-used standard
 * allocator where we care about the real place the memory allocation
 * request comes from.
 */
#define kmalloc_track_caller(...)		kmalloc_node_track_caller(__VA_ARGS__, NUMA_NO_NODE)

#define kmalloc_track_caller_noprof(...)	\
		kmalloc_node_track_caller_noprof(__VA_ARGS__, NUMA_NO_NODE, _RET_IP_)

static inline __alloc_size(1, 2) void *kmalloc_array_node_noprof(size_t n, size_t size, gfp_t flags,
							  int node)
{
	size_t bytes;

	if (unlikely(check_mul_overflow(n, size, &bytes)))
		return NULL;
	if (__builtin_constant_p(n) && __builtin_constant_p(size))
		return kmalloc_node_noprof(bytes, flags, node);
	return __kmalloc_node_noprof(PASS_BUCKET_PARAMS(bytes, NULL), flags, node);
}
#define kmalloc_array_node(...)			alloc_hooks(kmalloc_array_node_noprof(__VA_ARGS__))

#define kcalloc_node(_n, _size, _flags, _node)	\
	kmalloc_array_node(_n, _size, (_flags) | __GFP_ZERO, _node)

/*
 * Shortcuts
 */
#define kmem_cache_zalloc(_k, _flags)		kmem_cache_alloc(_k, (_flags)|__GFP_ZERO)

/**
 * kzalloc - allocate memory. The memory is set to zero.
 * @size: how many bytes of memory are required.
 * @flags: the type of memory to allocate (see kmalloc).
 */
static inline __alloc_size(1) void *kzalloc_noprof(size_t size, gfp_t flags)
{
	return kmalloc_noprof(size, flags | __GFP_ZERO);
}
#define kzalloc(...)				alloc_hooks(kzalloc_noprof(__VA_ARGS__))
#define kzalloc_node(_size, _flags, _node)	kmalloc_node(_size, (_flags)|__GFP_ZERO, _node)

void *__kvmalloc_node_noprof(DECL_BUCKET_PARAMS(size, b), gfp_t flags, int node) __alloc_size(1);
#define kvmalloc_node_noprof(size, flags, node)	\
	__kvmalloc_node_noprof(PASS_BUCKET_PARAMS(size, NULL), flags, node)
#define kvmalloc_node(...)			alloc_hooks(kvmalloc_node_noprof(__VA_ARGS__))

#define kvmalloc(_size, _flags)			kvmalloc_node(_size, _flags, NUMA_NO_NODE)
#define kvmalloc_noprof(_size, _flags)		kvmalloc_node_noprof(_size, _flags, NUMA_NO_NODE)
#define kvzalloc(_size, _flags)			kvmalloc(_size, (_flags)|__GFP_ZERO)

#define kvzalloc_node(_size, _flags, _node)	kvmalloc_node(_size, (_flags)|__GFP_ZERO, _node)
#define kmem_buckets_valloc(_b, _size, _flags)	\
	alloc_hooks(__kvmalloc_node_noprof(PASS_BUCKET_PARAMS(_size, _b), _flags, NUMA_NO_NODE))

static inline __alloc_size(1, 2) void *
kvmalloc_array_node_noprof(size_t n, size_t size, gfp_t flags, int node)
{
	size_t bytes;

	if (unlikely(check_mul_overflow(n, size, &bytes)))
		return NULL;

	return kvmalloc_node_noprof(bytes, flags, node);
}

#define kvmalloc_array_noprof(...)		kvmalloc_array_node_noprof(__VA_ARGS__, NUMA_NO_NODE)
#define kvcalloc_node_noprof(_n,_s,_f,_node)	kvmalloc_array_node_noprof(_n,_s,(_f)|__GFP_ZERO,_node)
#define kvcalloc_noprof(...)			kvcalloc_node_noprof(__VA_ARGS__, NUMA_NO_NODE)

#define kvmalloc_array(...)			alloc_hooks(kvmalloc_array_noprof(__VA_ARGS__))
#define kvcalloc_node(...)			alloc_hooks(kvcalloc_node_noprof(__VA_ARGS__))
#define kvcalloc(...)				alloc_hooks(kvcalloc_noprof(__VA_ARGS__))

void *kvrealloc_noprof(const void *p, size_t size, gfp_t flags)
		__realloc_size(2);
#define kvrealloc(...)				alloc_hooks(kvrealloc_noprof(__VA_ARGS__))

extern void kvfree(const void *addr);
DEFINE_FREE(kvfree, void *, if (!IS_ERR_OR_NULL(_T)) kvfree(_T))

extern void kvfree_sensitive(const void *addr, size_t len);

unsigned int kmem_cache_size(struct kmem_cache *s);

/**
 * kmalloc_size_roundup - Report allocation bucket size for the given size
 *
 * @size: Number of bytes to round up from.
 *
 * This returns the number of bytes that would be available in a kmalloc()
 * allocation of @size bytes. For example, a 126 byte request would be
 * rounded up to the next sized kmalloc bucket, 128 bytes. (This is strictly
 * for the general-purpose kmalloc()-based allocations, and is not for the
 * pre-sized kmem_cache_alloc()-based allocations.)
 *
 * Use this to kmalloc() the full bucket size ahead of time instead of using
 * ksize() to query the size after an allocation.
 */
size_t kmalloc_size_roundup(size_t size);

void __init kmem_cache_init_late(void);
void __init kvfree_rcu_init(void);

#endif	/* _LINUX_SLAB_H */
