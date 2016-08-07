/*
 * Copyright (C) 2005-2016 Junjiro R. Okajima
 */

/*
 * module initialization and module-global
 */

#ifndef __AUFS_MODULE_H__
#define __AUFS_MODULE_H__

#ifdef __KERNEL__

#include <linux/slab.h>
#include "debug.h"

struct path;
struct seq_file;

/* module parameters */
extern int sysaufs_brs;
extern bool au_userns;

/* ---------------------------------------------------------------------- */

extern int au_dir_roflags;

void *au_kzrealloc(void *p, unsigned int nused, unsigned int new_sz, gfp_t gfp);
int au_seq_path(struct seq_file *seq, struct path *path);

#ifdef CONFIG_PROC_FS
/* procfs.c */
int __init au_procfs_init(void);
void au_procfs_fin(void);
#else
AuStubInt0(au_procfs_init, void);
AuStubVoid(au_procfs_fin, void);
#endif

/* ---------------------------------------------------------------------- */

/* kmem cache and delayed free */
enum {
	AuCache_DINFO,
	AuCache_ICNTNR,
	AuCache_FINFO,
	AuCache_VDIR,
	AuCache_DEHSTR,
	AuCache_HNOTIFY, /* must be last */
	AuCache_Last
};

enum {
	AU_DFREE_KFREE,
	AU_DFREE_FREE_PAGE,
	AU_DFREE_Last
};

struct au_cache {
	struct kmem_cache	*cache;
	struct llist_head	llist;	/* delayed free */
};

/*
 * in order to reduce the cost of the internal timer, consolidate all the
 * delayed free works into a single delayed_work.
 */
struct au_dfree {
	struct au_cache		cache[AuCache_Last];
	struct llist_head	llist[AU_DFREE_Last];
	struct delayed_work	dwork;
};

extern struct au_dfree au_dfree;

#define AuCacheFlags		(SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD)
#define AuCache(type)		KMEM_CACHE(type, AuCacheFlags)
#define AuCacheCtor(type, ctor)	\
	kmem_cache_create(#type, sizeof(struct type), \
			  __alignof__(struct type), AuCacheFlags, ctor)

#define AU_DFREE_DELAY		msecs_to_jiffies(10)
#define AU_DFREE_BODY(lnode, llist) do {				\
		if (llist_add(lnode, llist))				\
			schedule_delayed_work(&au_dfree.dwork,		\
					      AU_DFREE_DELAY);		\
	} while (0)
#define AU_CACHE_DFREE_FUNC(name, idx, lnode)				\
	void au_cache_dfree_##name(struct au_##name *p)			\
	{								\
		struct au_cache *cp = au_dfree.cache + AuCache_##idx;	\
		AU_DFREE_BODY(&p->lnode, &cp->llist);			\
	}

#define AuCacheFuncs(name, index) \
static inline struct au_##name *au_cache_alloc_##name(void) \
{ return kmem_cache_alloc(au_dfree.cache[AuCache_##index].cache, GFP_NOFS); } \
static inline void au_cache_free_##name(struct au_##name *p) \
{ kmem_cache_free(au_dfree.cache[AuCache_##index].cache, p); } \
void au_cache_dfree_##name(struct au_##name *p)

AuCacheFuncs(dinfo, DINFO);
AuCacheFuncs(icntnr, ICNTNR);
AuCacheFuncs(finfo, FINFO);
AuCacheFuncs(vdir, VDIR);
AuCacheFuncs(vdir_dehstr, DEHSTR);
#ifdef CONFIG_AUFS_HNOTIFY
AuCacheFuncs(hnotify, HNOTIFY);
#endif

static inline void au_delayed_kfree(const void *p)
{
	AuDebugOn(!p);
	AuDebugOn(ksize(p) < sizeof(struct llist_node));

	AU_DFREE_BODY((void *)p, au_dfree.llist + AU_DFREE_KFREE);
}

/* cast only */
static inline void au_free_page(void *p)
{
	free_page((unsigned long)p);
}

static inline void au_delayed_free_page(unsigned long addr)
{
	AU_DFREE_BODY((void *)addr, au_dfree.llist + AU_DFREE_FREE_PAGE);
}

#endif /* __KERNEL__ */
#endif /* __AUFS_MODULE_H__ */
