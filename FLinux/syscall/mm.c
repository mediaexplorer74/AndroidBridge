/* Linux mmap() allows mapping into 4kB page boundaries, while Windows only
 * allows 64kB boundaries (called allocation granularity), although both
 * systems use 4kB page size.
 *
 * This difference causes two main issues for mmap() implementation:
 * 1. Map non 64kB aligned starting address of a file
 *     It's impossible to use Windows file mapping functions. We have to
 *     read/write file content manually on mmap()/msync()/munmap() calls.
 *     This may be slow. But we can possibly implement demand paging to
 *     improve performance.
 *
 * 2. Use MAP_FIXED with non 64kB aligned address
 *     We can allocate full 64kB aligned memory blocks and do partial
 *     allocations inside them. Note it seems impossible to implement
 *     MAP_FIXED with MAP_SHARED or MAP_PRIVATE on non 64kB aligned address.
 */

#include <common/errno.h>
//#include <dbt/x86.h>
#include <lib/rbtree.h>
#include <lib/slist.h>
#include <syscall/mm.h>
#include <syscall/syscall.h>
#include <syscall/vfs.h>
#include <flags.h>
#include <log.h>
#include <str.h>

#include <stdbool.h>
#include <stdint.h>
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Psapi.h>
#include <ntdll.h>
#include <onecore_types.h>



/* Hard limits */
/* Maximum number of mmap()-ed areas */
#define MAX_MMAP_COUNT 1024

#define MMAP_ERR(err) (err)

//RnD
#ifdef _WIN32//_WIN64

/* Lower bound of the virtual address space */
#define ADDRESS_SPACE_LOW		0x0000000000000000ULL
/* Higher bound of the virtual address space */
#define ADDRESS_SPACE_HIGH		0x0001000000000000ULL
/* The lowest non fixed allocation address we can make */
#define ADDRESS_ALLOCATION_LOW	0x0000000200000000ULL
/* The highest non fixed allocation address we can make */
#define ADDRESS_ALLOCATION_HIGH	0x0001000000000000ULL

//my! removi it after all
void* mm_address_allocation_low;
void* mm_address_allocation_high;

#else

/* Lower bound of the virtual address space */
#define ADDRESS_SPACE_LOW		0x00000000U
/* Higher bound of the virtual address space */
#define ADDRESS_SPACE_HIGH		0x80000000U
/* The lowest non fixed allocation address we can make */
//#define ADDRESS_ALLOCATION_LOW	0x10000000U
void* mm_address_allocation_low;

//TODO: detect it dynamically, because we sahre memory space with regular DLL loader
/* The highest non fixed allocation address we can make */
//#define ADDRESS_ALLOCATION_HIGH	0x58000000U
void* mm_address_allocation_high;

#endif

#define PAGES_PER_BLOCK (BLOCK_SIZE / PAGE_SIZE)
#define BLOCK_COUNT ((ADDRESS_SPACE_HIGH - ADDRESS_SPACE_LOW) / BLOCK_SIZE)

#define SECTION_HANDLE_PER_TABLE (BLOCK_SIZE / sizeof(HANDLE))
#define SECTION_TABLE_PER_DIRECTORY (BLOCK_SIZE / sizeof(uint16_t))
#define SECTION_TABLE_COUNT (BLOCK_COUNT / SECTION_HANDLE_PER_TABLE)

#define GET_SECTION_TABLE(i) ((i) / SECTION_HANDLE_PER_TABLE)

/* Helper macros */
// RnD: unsigned __int64 exploding !!!
#define IS_ALIGNED(addr, alignment) ((unsigned __int64) (addr) % (unsigned __int64) (alignment) == 0)
#define ALIGN_TO_BLOCK(addr) (((unsigned __int64) addr + BLOCK_SIZE - 1) & ~(BLOCK_SIZE - 1))
#define ALIGN_TO_PAGE(addr) (((unsigned __int64) addr + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))
#define GET_BLOCK(addr) ((unsigned __int64) (addr) / BLOCK_SIZE)
#define GET_PAGE(addr) ((unsigned __int64) (addr) / PAGE_SIZE)
#define GET_PAGE_IN_BLOCK(page) ((page) % PAGES_PER_BLOCK)
#define GET_BLOCK_OF_PAGE(page) ((page) / PAGES_PER_BLOCK)
#define GET_FIRST_PAGE_OF_BLOCK(block)	((block) * PAGES_PER_BLOCK)
#define GET_LAST_PAGE_OF_BLOCK(block) ((block) * PAGES_PER_BLOCK + (PAGES_PER_BLOCK - 1))
#define GET_BLOCK_ADDRESS(block) (void *)((block) * BLOCK_SIZE)
#define GET_PAGE_ADDRESS(page) (void *)((page) * PAGE_SIZE)
/* Page offset in bytes from the start of its block */
#define GET_SIZE_OF_BLOCK_TO_PAGE(page) ((char*)GET_PAGE_ADDRESS(page) - (char*)GET_BLOCK_ADDRESS(GET_BLOCK_OF_PAGE(page)))
/* Bytes from the page's location to its block's next block */
#define GET_SIZE_OF_PAGE_TO_NEXT_BLOCK(page) ((char*)GET_BLOCK_ADDRESS(GET_BLOCK_OF_PAGE(page) + 1) - (char*)GET_PAGE_ADDRESS(page))

struct map_entry
{
	struct rb_node tree;
	union
	{
		struct slist free_list;
		struct
		{
			unsigned __int64 start_page;
			unsigned __int64 end_page;
			int prot, flags;
			struct file *f;
			lx_off_t offset_pages;
		};
	};
};

static int map_entry_cmp(const struct rb_node *l, const struct rb_node *r)
{
	struct map_entry *left = rb_entry(l, struct map_entry, tree);
	struct map_entry *right = rb_entry(r, struct map_entry, tree);
	if (left->start_page == right->start_page)
		return 0;
	else if (left->start_page < right->start_page)
		return -1;
	else
		return 1;
}

struct mm_munmap_list_entry
{
	void *addr;
	unsigned __int64 length;
	struct mm_munmap_list_entry *next;
};

struct mm_data
{
	/* RW lock for multi-threading protection */
	SRWLOCK rw_lock;

	/* Thread ID for recursive munmap */
	DWORD thread_id;

	/* Recursive munmap block list */
	struct mm_munmap_list_entry *munmap_list;

	/* Program break address, brk() will use this */
	void *brk;

	/* Used for mm_static_alloc() */
	void *static_alloc_begin, *static_alloc_end;

	/* Information for all existing mappings */
	struct rb_tree entry_tree;
	struct slist entry_free_list;
	struct map_entry entries[MAX_MMAP_COUNT];

	/* Section handle count for each table */
	uint16_t section_table_handle_count[SECTION_TABLE_COUNT];
} _mm;

static struct mm_data *const mm = &_mm;
static HANDLE *mm_section_handle;

static __forceinline HANDLE get_section_handle(unsigned __int64 i)
{
	unsigned __int64 t = GET_SECTION_TABLE(i);

	if (mm->section_table_handle_count[t])
	{
		return mm_section_handle[i];
	}
	else
	{
		return NULL;
	}
}

// RnD
//static __forceinline void add_section_handle(unsigned __int64 i, HANDLE handle)
static __forceinline void add_section_handle(unsigned __int64 i, HANDLE handle)
{
	unsigned __int64 t = GET_SECTION_TABLE(i);

	if (mm->section_table_handle_count[t]++)
	{
		mm_section_handle[i] = handle;
	}
	else
	{
		//RnD
		VirtualAlloc(&mm_section_handle[t * SECTION_HANDLE_PER_TABLE], BLOCK_SIZE, MEM_COMMIT, PAGE_READWRITE);

		//RnD
		mm_section_handle[i] = handle;
	}
}

//static __forceinline void replace_section_handle(unsigned __int64 i, HANDLE handle)
static __forceinline void replace_section_handle(unsigned __int64 i, HANDLE handle)
{
	mm_section_handle[i] = handle;
}

//static __forceinline void replace_section_handle_ex(HANDLE process, unsigned __int64 i, HANDLE handle)
static __forceinline void replace_section_handle_ex(HANDLE process, unsigned __int64 i, HANDLE handle)
{
	unsigned __int64 written;
	NtWriteVirtualMemory(process, &mm_section_handle[i], &handle, sizeof(HANDLE), &written);
}

//
static __forceinline void remove_section_handle(unsigned __int64 i)
{
	mm_section_handle[i] = NULL;
	unsigned __int64 t = GET_SECTION_TABLE(i);
	if (--mm->section_table_handle_count[t] == 0)
		VirtualFree(&mm_section_handle[t * SECTION_HANDLE_PER_TABLE], BLOCK_SIZE, MEM_DECOMMIT);
}

static void munmap_list_add(void *addr, unsigned __int64 length)
{
	struct mm_munmap_list_entry *e = HeapAlloc(GetProcessHeap(), 0, sizeof(struct mm_munmap_list_entry));
	e->addr = addr;
	e->length = length;
	e->next = mm->munmap_list;
	mm->munmap_list = e;
}

static void *munmap_list_pop(unsigned __int64 *length)
{
	struct mm_munmap_list_entry *e = mm->munmap_list;
	if (e == NULL)
		return NULL;
	void *addr = e->addr;
	*length = e->length;
	mm->munmap_list = e->next;
	HeapFree(GetProcessHeap(), 0, e);
	return addr;
}

static struct map_entry *new_map_entry()
{
	if (slist_empty(&mm->entry_free_list))
	{
		log_error("Map entry exhausted.");
		return NULL;
	}
	struct map_entry *entry = slist_next_entry(&mm->entry_free_list, struct map_entry, free_list);
	slist_remove(&mm->entry_free_list, &entry->free_list);
	return entry;
}

static void free_map_entry(struct map_entry *entry)
{
	slist_add(&mm->entry_free_list, &entry->free_list);
}

// !
static struct rb_node *start_node(unsigned __int64 start_page)
{
	struct map_entry probe;
	probe.start_page = start_page;
	struct rb_node *node = rb_upper_bound(&mm->entry_tree, &probe.tree, map_entry_cmp);
	
	if (node)
	{
		return node;
	}

	return rb_lower_bound(&mm->entry_tree, &probe.tree, map_entry_cmp);
}

static struct map_entry *find_map_entry(void *addr)
{
	struct map_entry probe, *entry;

	unsigned __int64 page = GET_PAGE(addr);
	
	probe.start_page = page;
	
	entry = rb_entry(rb_upper_bound(&mm->entry_tree, &probe.tree, map_entry_cmp), struct map_entry, tree);
	
	/* upper bound condition: block->start_page <= page */
	if (page <= entry->end_page)
	{
		return entry;
	}

	return NULL;
}

static void split_map_entry(struct map_entry *e, unsigned __int64 last_page_of_first_entry)
{
	struct map_entry *ne = new_map_entry();
	ne->start_page = last_page_of_first_entry + 1;
	ne->end_page = e->end_page;
	if ((ne->f = e->f))
	{
		vfs_ref(ne->f);
		ne->offset_pages = e->offset_pages + (ne->start_page - e->start_page);
	}
	ne->prot = e->prot;
	ne->flags = e->flags;
	e->end_page = last_page_of_first_entry;
	rb_add(&mm->entry_tree, &ne->tree, map_entry_cmp);
}

static void free_map_entry_blocks(struct map_entry *e)
{
	if (e->flags & INTERNAL_MAP_VIRTUALALLOC)
	{
		VirtualFree(GET_PAGE_ADDRESS(e->start_page), 0, MEM_RELEASE);
		return;
	}
	if (e->f)
		vfs_release(e->f);
	struct rb_node *prev = rb_prev(&e->tree);
	struct rb_node *next = rb_next(&e->tree);

	unsigned __int64 start_block = GET_BLOCK_OF_PAGE(e->start_page);	
	unsigned __int64 end_block = GET_BLOCK_OF_PAGE(e->end_page);

	/* The first block and last block may be shared with previous/next entry
	 * We should mark corresponding pages in such blocks as PAGE_NOACCESS instead of free them */
	if (prev && GET_BLOCK_OF_PAGE(rb_entry(prev, struct map_entry, tree)->end_page) == start_block)
	{
		/* First block is shared, just make it inaccessible */

		unsigned __int64 last_page = GET_LAST_PAGE_OF_BLOCK(GET_BLOCK_OF_PAGE(e->start_page));
		
		last_page = min(last_page, e->end_page); /* The entry may occupy only a block */
		
		DWORD oldProtect;
		
		VirtualProtect(GET_PAGE_ADDRESS(e->start_page), (last_page - e->start_page + 1) * PAGE_SIZE, PAGE_NOACCESS, &oldProtect);
		start_block++;
	}
	if (end_block >= start_block && next && GET_BLOCK_OF_PAGE(rb_entry(next, struct map_entry, tree)->start_page) == end_block)
	{
		/* Last block is shared, just make it inaccessible */
		DWORD oldProtect;
		if(!VirtualProtect(GET_BLOCK_ADDRESS(end_block), GET_SIZE_OF_BLOCK_TO_PAGE(e->end_page + 1), PAGE_NOACCESS, &oldProtect))
		{
			log_error("VirtualProtect(0x%p, 0x%p) failed, error code: %d.", GET_BLOCK_ADDRESS(end_block),
				GET_SIZE_OF_BLOCK_TO_PAGE(e->end_page + 1), GetLastError());
			//return false;
		}

		end_block--;
	}
	/* Unmap non-shared full blocks */
	for (unsigned __int64 i = start_block; i <= end_block; i++)
	{
		HANDLE handle = get_section_handle(i);
		if (handle)
		{
			/* The section handle may not be currrently mapped, let it silently fail here */
			NtUnmapViewOfSection(NtCurrentProcess(), GET_BLOCK_ADDRESS(i));
			NtClose(handle);
			remove_section_handle(i);
		}
	}
}


/* To prevent collisions with Windows module loader pre-allocate all memory blocks
   and keep some small space for Windows to be able to breathe */
void mm_reserve_blocks()
{
	PVOID heap_start = 0;
	unsigned __int64 heap_size = 0;
	char *addr = 0;

	do
	{
		MEMORY_BASIC_INFORMATION info;
		VirtualQueryEx(GetCurrentProcess(), addr, &info, sizeof(info));
		if (info.State == MEM_FREE)
		{
			log_info("0x%p - 0x%p", info.BaseAddress, (unsigned __int64)info.BaseAddress + info.RegionSize);
			if (info.RegionSize > heap_size)
			{
				heap_size = info.RegionSize;
				heap_start = info.BaseAddress;
			}
		}
		addr += info.RegionSize;
	} while ((unsigned __int64)addr < 0x7FFF0000U);

	unsigned __int64 start_block = GET_BLOCK(heap_start);
	unsigned __int64 end_block = GET_BLOCK((unsigned __int64)heap_start + heap_size) - 1;

	if (!IS_ALIGNED(heap_start, BLOCK_SIZE))
	{
		start_block++;
	}

	heap_start = GET_BLOCK_ADDRESS(start_block);

	addr = heap_start;

	for (unsigned __int64 block = start_block; block <= end_block; block++)
	{
		void* mem = VirtualAlloc(GET_BLOCK_ADDRESS(block), BLOCK_SIZE, MEM_RESERVE, PAGE_NOACCESS);
	}

	mm_address_allocation_low = heap_start;
	mm_address_allocation_high = GET_BLOCK_ADDRESS(end_block);

}


void mm_init()
{
	/* Initialize RW lock */
	InitializeSRWLock(&mm->rw_lock);
	/* Initialize thread ID */
	mm->thread_id = 0;
	/* Initialize munmap_list */
	mm->munmap_list = NULL;
	/* Initialize mapping info freelist */
	rb_init(&mm->entry_tree);
	slist_init(&mm->entry_free_list);

	for (unsigned __int64 i = 0; i + 1 < MAX_MMAP_COUNT; i++)
	{
		slist_add(&mm->entry_free_list, &mm->entries[i].free_list);
	}

	mm->brk = 0;

	/* Initialize section handle table */
	mm_section_handle = VirtualAlloc(NULL, BLOCK_COUNT * sizeof(HANDLE), MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE);

	/* Pre-reserve blocks */
	mm_reserve_blocks();

	/* Initialize static alloc */
	mm->static_alloc_begin = mm_mmap(NULL, MM_STATIC_ALLOC_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS,
		INTERNAL_MAP_TOPDOWN | INTERNAL_MAP_NORESET | INTERNAL_MAP_VIRTUALALLOC, NULL, 0);
	mm->static_alloc_end = (uint8_t*)mm->static_alloc_begin + MM_STATIC_ALLOC_SIZE;

}

void mm_reset()
{
	/* Release all user memory */

	unsigned __int64 last_block = 0;
	
	for (struct rb_node *cur = rb_first(&mm->entry_tree); cur;)
	{
		struct map_entry *e = rb_entry(cur, struct map_entry, tree);

		unsigned __int64 start_block = GET_BLOCK_OF_PAGE(e->start_page);
		unsigned __int64 end_block = GET_BLOCK_OF_PAGE(e->end_page);
		
		if (e->flags & INTERNAL_MAP_NORESET)
		{
			cur = rb_next(cur);
			continue;
		}

		if (start_block == last_block)
		{
			start_block++;
		}

		for (unsigned __int64 i = start_block; i <= end_block; i++)
		{
			HANDLE handle = get_section_handle(i);
			if (handle)
			{
				/* The section handle may not be currrently mapped, let it silently fail here */
				NtUnmapViewOfSection(NtCurrentProcess(), GET_BLOCK_ADDRESS(i));
				NtClose(handle);
				remove_section_handle(i);
			}
		}
		last_block = end_block;

		if (e->f)
			vfs_release(e->f);
		free_map_entry(e);
		struct rb_node *next = rb_next(cur);
		rb_remove(&mm->entry_tree, cur);
		cur = next;
	}
	mm->brk = 0;
}

// 
void mm_shutdown()
{
	for (unsigned __int64 i = 0; i < BLOCK_COUNT; i++)
	{
		HANDLE handle = get_section_handle(i);
		if (handle)
		{
			/* The section handle may not be currrently mapped, let it silently fail here */
			NtUnmapViewOfSection(NtCurrentProcess(), GET_BLOCK_ADDRESS(i));
			NtClose(handle);
			remove_section_handle(i);
		}
	}
	VirtualFree(mm_section_handle, 0, MEM_RELEASE);
}

// 
void *mm_static_alloc(unsigned __int64 size)
{
	if ((uint8_t*)mm->static_alloc_begin + size > mm->static_alloc_end)
	{
		log_error("mm_static_alloc(): Overlarge static block size, remain: %p, requested: %p",
			(uint8_t*)mm->static_alloc_end - (uint8_t*)mm->static_alloc_begin, size);
		log_error("Please enlarge MM_STATIC_ALLOC_SIZE manually.");
		__debugbreak();
	}
	void *ret = mm->static_alloc_begin;
	mm->static_alloc_begin = (void*)ALIGN_TO((uint8_t*)mm->static_alloc_begin + size, 16);
	return ret;
}

void mm_update_brk(void *brk)
{
	/* Seems glibc does not like unaligned initial brk */
#ifdef _WIN64
	mm->brk = MM_BRK_BASE;
#else
	mm->brk = (void*)max((unsigned __int64)mm->brk, ALIGN_TO_PAGE(brk));
#endif
}

/* Find 'count' consecutive free pages near addr, return 0 if not found */
static unsigned __int64 find_nearest_free_pages(void* addr, unsigned __int64 count, bool block_align)
{
	unsigned __int64 last = GET_PAGE(mm_address_allocation_low);
	unsigned __int64 req_start_page = GET_PAGE(addr);
	unsigned __int64 req_end_page = GET_PAGE((char*)addr + count - 1);

	struct rb_node *prev_node = start_node(GET_PAGE(addr) - 1);
	struct rb_node *node = start_node(GET_PAGE(addr) - 1);

	for (struct rb_node *cur = rb_first(&mm->entry_tree); cur; cur = rb_next(cur))
	{
		struct map_entry *e = rb_entry(cur, struct map_entry, tree);
		if (e->start_page >= last && e->start_page - last >= count)
			return last;
		else if (e->end_page >= last)
		{
			last = e->end_page + 1;
			/* Make sure not collide with block aligned entries */
			if (block_align || BLOCK_ALIGNED(e->flags))
				last = (last + PAGES_PER_BLOCK - 1) & ~(PAGES_PER_BLOCK - 1);
		}
		if (last >= GET_PAGE(mm_address_allocation_high))
			return 0;
	}
	if (GET_PAGE(mm_address_allocation_high) > last && GET_PAGE(mm_address_allocation_high) - last >= count)
		return last;
	else
		return 0;
}

/* Find 'count' consecutive free pages, return 0 if not found */
static unsigned __int64 find_free_pages_hint(void* addr, unsigned __int64 count, bool block_align)
{
	unsigned __int64 last = GET_PAGE(addr);

	for (struct rb_node *cur = rb_first(&mm->entry_tree); cur; cur = rb_next(cur))
	{
		struct map_entry *e = rb_entry(cur, struct map_entry, tree);
		if (e->start_page >= last && e->start_page - last >= count)
			return last;
		else if (e->end_page >= last)
		{
			last = e->end_page + 1;
			/* Make sure not collide with block aligned entries */
			if (block_align || BLOCK_ALIGNED(e->flags))
				last = (last + PAGES_PER_BLOCK - 1) & ~(PAGES_PER_BLOCK-1);
		}
		if (last >= GET_PAGE(mm_address_allocation_high))
			return 0;
	}

	if
		(
			GET_PAGE(mm_address_allocation_high) > last
			&&
			GET_PAGE(mm_address_allocation_high) - last >= count
			)
	{
		return last;
	}
	else
	{
		return 0;
	}
}

//
static unsigned __int64 find_free_pages(unsigned __int64 count, bool block_align)
{
	find_free_pages_hint(mm_address_allocation_low, count, block_align);
}

/* Find 'count' consecutive free pages at the highest possible address with, return 0 if not found */
static unsigned __int64 find_free_pages_topdown(unsigned __int64 count, bool block_align)
{
	unsigned __int64 last = GET_PAGE(mm_address_allocation_high);
	for (struct rb_node *cur = rb_last(&mm->entry_tree); cur; cur = rb_prev(cur))
	{
		struct map_entry *e = rb_entry(cur, struct map_entry, tree);
		unsigned __int64 end_page = e->end_page;

		/* MAP_SHARED entries always occupy entire blocks */
		if (e->flags & INTERNAL_MAP_SHARED)
		{
			end_page = (end_page & ~(PAGES_PER_BLOCK - 1)) + (PAGES_PER_BLOCK - 1);
		}

		if (e->end_page < last && e->end_page + count < last)
		{
			return last - count;
		}
		else if (e->start_page < last)
		{
			last = e->start_page;
			if (block_align)
				last &= ~(PAGES_PER_BLOCK - 1);
		}
		if (last <= GET_PAGE(mm_address_allocation_low))
		{
			return 0;
		}
	}

	if (GET_PAGE(mm_address_allocation_low) < last
		&& GET_PAGE(mm_address_allocation_low) + count < last)
	{
		return last - count;
	}
	else
	{
		return 0;
	}
}//


unsigned __int64 mm_find_free_pages(unsigned __int64 count_bytes)
{
	return find_free_pages(GET_PAGE(ALIGN_TO_PAGE(count_bytes)), false);
}

static DWORD prot_linux2win(int prot)
{
	if ((prot & PROT_EXEC) && (prot & PROT_WRITE))
		return PAGE_EXECUTE_READWRITE;
	else if ((prot & PROT_EXEC) && (prot & PROT_READ))
		return PAGE_EXECUTE_READ;
	else if ((prot & PROT_EXEC))
		return PAGE_EXECUTE; /* Unsupported for file mapping */
	else if (prot & PROT_WRITE)
		return PAGE_READWRITE;
	else if (prot & PROT_READ)
		return PAGE_READONLY;
	else
		return PAGE_NOACCESS;
}

void mm_dump_windows_memory_mappings(HANDLE process)
{
	log_info("Windows memory mappings...");
	char *addr = 0;
	do
	{
		MEMORY_BASIC_INFORMATION info;
		VirtualQueryEx(process, addr, &info, sizeof(info));
		if (info.State != MEM_FREE)
		{
			char filename[1024];
			char *access;
			switch (info.Protect & 0xFF)
			{
			case PAGE_NOACCESS: access = "---"; break;
			case PAGE_READONLY: access = "R--"; break;
			case PAGE_READWRITE: access = "RW-"; break;
			case PAGE_WRITECOPY: access = "RC-"; break;
			case PAGE_EXECUTE: access = "--X"; break;
			case PAGE_EXECUTE_READ: access = "R-X"; break;
			case PAGE_EXECUTE_READWRITE: access = "RWX"; break;
			case PAGE_EXECUTE_WRITECOPY: access = "RCX"; break;
			default:
				if (info.State == MEM_RESERVE)
					access = "res";
				else
					access = "???";
			}
			if (GetMappedFileNameA(process, addr, filename, sizeof(filename)))
				log_info("0x%p - 0x%p [%s] <--- %s", info.BaseAddress, (unsigned __int64)info.BaseAddress + info.RegionSize, access, filename);
			else
				log_info("0x%p - 0x%p [%s]", info.BaseAddress, (unsigned __int64)info.BaseAddress + info.RegionSize, access);
		}
		addr += info.RegionSize;
#ifdef _WIN64
	} while ((unsigned __int64)addr < 0x00007FFFFFFF0000ULL);
#else
	} while ((unsigned __int64)addr < 0x7FFF0000U);
#endif
}

void mm_dump_memory_mappings()
{
	AcquireSRWLockShared(&mm->rw_lock);
	log_info("Current memory mappings...");
	for (struct rb_node *cur = rb_first(&mm->entry_tree); cur; cur = rb_next(cur))
	{
		struct map_entry *e = rb_entry(cur, struct map_entry, tree);
		if (e->f != NULL && e->f->op_vtable->getpath != NULL)
		{
			char path[PATH_MAX];
			e->f->op_vtable->getpath(e->f, path);
			log_info("0x%p - 0x%p: PROT: %d (%s)", GET_PAGE_ADDRESS(e->start_page), GET_PAGE_ADDRESS(e->end_page), e->prot, path);
		}
		else
			log_info("0x%p - 0x%p: PROT: %d", GET_PAGE_ADDRESS(e->start_page), GET_PAGE_ADDRESS(e->end_page), e->prot);
	}
	ReleaseSRWLockShared(&mm->rw_lock);
}

int mm_get_maps(char *buf)
{
	int r = 0;
	AcquireSRWLockShared(&mm->rw_lock);
	char path[PATH_MAX];
	for (struct rb_node *cur = rb_first(&mm->entry_tree); cur; cur = rb_next(cur))
	{
		struct map_entry *e = rb_entry(cur, struct map_entry, tree);
		char perm[5] = "----";
		if (e->prot & PROT_READ)
			perm[0] = 'r';
		if (e->prot & PROT_WRITE)
			perm[1] = 'w';
		if (e->prot & PROT_EXEC)
			perm[2] = 'x';
		if (!(e->flags & INTERNAL_MAP_SHARED))
			perm[3] = 'p'; /* Private mapping */
		if (e->f && e->f->op_vtable->getpath != NULL)
		{
			int len = e->f->op_vtable->getpath(e->f, path);
			path[len] = 0;
		}
		else
			path[0] = 0;
		r += ksprintf(buf + r, "%p-%p %s %p %02x:%02x %5d           %s\n",
			GET_PAGE_ADDRESS(e->start_page), GET_PAGE_ADDRESS(e->end_page + 1),
			perm,
			0,
			0, 0,
			0,
			path);
	}

	r += ksprintf(buf + r, "%p-%p %s %p %02x:%02x %5d %s\n",
		(void*)0x80000000, (void*)0xffffffff,
		"---p",
		0,
		0, 0,
		0,
		"          reserved");

	r += ksprintf(buf + r, "%p-%p %s %p %02x:%02x %5d %s\n",
		process_get_stack_limit(), process_get_stack_base(),
		"rw-p",
		0,
		0, 0,
		0,
		"          [stack]");

	

	ReleaseSRWLockShared(&mm->rw_lock);
	return r;
}

static void map_entry_range(struct map_entry *e, unsigned __int64 start_page, unsigned __int64 end_page)
{
	if (e->f)
	{
		unsigned __int64 desired_size = (end_page - start_page + 1) * PAGE_SIZE;
		if (e->f->op_vtable->pread == NULL)
		{
			log_error("pread not implemented");
			return;
		}

		unsigned __int64 r = e->f->op_vtable->pread(e->f, GET_PAGE_ADDRESS(start_page), desired_size,
			(lx_loff_t)(e->offset_pages + start_page - e->start_page) * PAGE_SIZE);
		if (r < desired_size)
		{
			unsigned __int64 remain = desired_size - r;
			RtlZeroMemory((char*)GET_PAGE_ADDRESS(end_page + 1) - remain, remain);
		}
	}
	else
		RtlZeroMemory(GET_PAGE_ADDRESS(start_page), (end_page - start_page + 1) * PAGE_SIZE);
}

static int mm_change_protection(HANDLE process, unsigned __int64 start_page, unsigned __int64 end_page, int prot)
{
	DWORD protection = prot_linux2win(prot);
	unsigned __int64 start_block = GET_BLOCK_OF_PAGE(start_page);
	unsigned __int64 end_block = GET_BLOCK_OF_PAGE(end_page);
	for (unsigned __int64 i = start_block; i <= end_block; i++)
	{
		HANDLE handle = get_section_handle(i);
		if (handle)
		{
			unsigned __int64 range_start = max(GET_FIRST_PAGE_OF_BLOCK(i), start_page);
			unsigned __int64 range_end = min(GET_LAST_PAGE_OF_BLOCK(i), end_page);
			DWORD old_protection;
			PVOID addr = GET_PAGE_ADDRESS(range_start);
			unsigned __int64 size = PAGE_SIZE * (range_end - range_start + 1);
			NTSTATUS status;
			status = NtProtectVirtualMemory(process, &addr, &size, protection, &old_protection);
			if (status == STATUS_CONFLICTING_ADDRESSES) /* The block is not yet mapped */
				log_info("NtProtectVirtualMemory(0x%p, 0x%p) failed: block %p not yet mapped, silently ignore.", addr, size, i);
			else if (!NT_SUCCESS(status))
			{
				log_error("NtProtectVirtualMemory(0x%p, 0x%p) failed, status: %p", addr, size, status);
				mm_dump_windows_memory_mappings(process);
				return 0;
			}
		}
	}
	return 1;
}

void mm_dump_stack_trace(PCONTEXT context)
{
	log_info("Stack trace:");
#ifdef defined(_M_X64)
	unsigned __int64 sp = context->Rsp;
	log_info("RSP: 0x%p", sp);
#elif defined(_M_IX86)
	unsigned __int64 sp = context->Esp;
	log_info("ESP: 0x%p", sp);
#elif defined(_M_ARM)
	unsigned __int64 sp = context->Sp;
	log_info("SP: 0x%p", sp);
#endif
	for (unsigned __int64 i = sp & ~15; i < ((sp + 256) & ~15); i += 16)
	{
		char buf[256];
		int t = ksprintf(buf, "%p ", i);
		for (unsigned __int64 j = i; j < i + 16 && j < ((sp + 256) & ~15); j++)
			t += ksprintf(buf + t, "%02x ", *(unsigned char *)j);
		log_info("%s", buf);
	}
}

static int allocate_block(unsigned __int64 i)
{
	OBJECT_ATTRIBUTES attr;
	attr.Length = sizeof(OBJECT_ATTRIBUTES);
	attr.RootDirectory = NULL;
	attr.ObjectName = NULL;
	attr.Attributes = OBJ_INHERIT;
	attr.SecurityDescriptor = NULL;
	attr.SecurityQualityOfService = NULL;
	LARGE_INTEGER max_size;
	max_size.QuadPart = BLOCK_SIZE;
	NTSTATUS status;
	HANDLE handle;

	/* Allocate section */
	status = NtCreateSection(&handle, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, &attr, &max_size, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	if (!NT_SUCCESS(status))
	{
		log_error("NtCreateSection() failed. Status: %x", status);
		return 0;
	}

	/* Map section */
	PVOID base_addr = GET_BLOCK_ADDRESS(i);
	unsigned __int64 view_size = BLOCK_SIZE;

	if (!VirtualFree(base_addr, 0, MEM_RELEASE))
	{
		log_error("VirtualFree() failed. Address: %p, Status: %x", base_addr, GetLastError());
		NtClose(handle);
		return 0;
	}


	status = NtMapViewOfSection(handle, NtCurrentProcess(), &base_addr, 0, BLOCK_SIZE, NULL, &view_size, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		log_error("NtMapViewOfSection() failed. Address: %p, Status: %x", base_addr, status);
		NtClose(handle);
		return 0;
	}
	add_section_handle(i, handle);
	return 1;
}

/* Duplicate the section at given block. */
static int duplicate_section(unsigned __int64 block)
{
	OBJECT_ATTRIBUTES attr;
	attr.Length = sizeof(OBJECT_ATTRIBUTES);
	attr.RootDirectory = NULL;
	attr.ObjectName = NULL;
	attr.Attributes = OBJ_INHERIT;
	attr.SecurityDescriptor = NULL;
	attr.SecurityQualityOfService = NULL;
	LARGE_INTEGER max_size;
	max_size.QuadPart = BLOCK_SIZE;
	unsigned __int64 view_size = BLOCK_SIZE;
	NTSTATUS status;

	void *base_addr = GET_BLOCK_ADDRESS(block);
	void *remapped_addr = NULL;

	/* Remap the old section out of this block address as read-write.
	 * This not only frees the occupied address space, but also fixes the problem
	 * that the region is mapped as not writable and write protection can not be
	 * promoted afterwards. See mm_fork() for details.
	 */
	status = NtUnmapViewOfSection(NtCurrentProcess(), base_addr);
	/* The section may not be mapped yet */
	if (status == STATUS_NOT_MAPPED_VIEW)
		log_info("NtUnmapViewOfSection() failed: view not yet mapped, silently ignore.");
	else if (!NT_SUCCESS(status))
	{
		log_error("NtUnmapViewOfSection() failed, status: %x", status);
		return 0;
	}

	HANDLE source = get_section_handle(block);
	status = NtMapViewOfSection(source, NtCurrentProcess(), &remapped_addr, 0, BLOCK_SIZE,
		NULL, &view_size, ViewUnmap, 0, PAGE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		log_error("NtMapViewOfSection() failed, status: %x", status);
		return 0;
	}

	/* Allocate new section */
	allocate_block(block);

	/* Copy memory */
	CopyMemory(base_addr, remapped_addr, BLOCK_SIZE);

	/* Delete source section */
	status = NtUnmapViewOfSection(NtCurrentProcess(), remapped_addr);
	if (!NT_SUCCESS(status))
	{
		log_error("NtUnmapViewOfSection() failed, status: %x", status);
		return 0;
	}
	NtClose(source);
	return 1;
}

static int take_block_ownership(unsigned __int64 block)
{
	HANDLE handle = get_section_handle(block);
	if (!handle)
	{
		log_error("Block %p not exist.", block);
		return 0;
	}
	/* Query information about the section object which the page within */
	OBJECT_BASIC_INFORMATION info;
	NTSTATUS status;
	status = NtQueryObject(handle, ObjectBasicInformation, &info, sizeof(OBJECT_BASIC_INFORMATION), NULL);
	if (!NT_SUCCESS(status))
	{
		log_error("NtQueryObject() on block %p failed, status: 0x%x.", block, status);
		return 0;
	}
	if (info.HandleCount == 1)
	{
		log_info("We're the only owner.");
		return 1;
	}

	/* We are not the only one holding the section, duplicate it */
	log_info("Duplicating section %p...", block);
	if (!duplicate_section(block))
	{
		log_error("Duplicating section failed.");
		return 0;
	}
	log_info("Duplicating section succeeded.");
	return 1;
}

/* Load block protection flags, the block must be mapped as PAGE_EXECUTE_READWRITE
 * and has its content loaded.
 * prot_mask is AND-ed to the entry's prot flag
 * initial_prot is the current prot of the block, or INITIAL_PROT_UNKNOWN if multiple
 * prot flags are mixed or the current prot flag is unknown.
 */
#define INITIAL_PROT_UNKNOWN	-1
static bool load_block_protection(unsigned __int64 block, int prot_mask, int initial_prot)
{
	unsigned __int64 start_page = GET_FIRST_PAGE_OF_BLOCK(block);
	unsigned __int64 end_page = GET_LAST_PAGE_OF_BLOCK(block);
	for (struct rb_node *cur = start_node(start_page); cur; cur = rb_next(cur))
	{
		struct map_entry *e = rb_entry(cur, struct map_entry, tree);
		if (end_page < e->start_page)
			break;
		else
		{
			unsigned __int64 range_start = max(start_page, e->start_page);
			unsigned __int64 range_end = min(end_page, e->end_page);
			if (range_start > range_end)
				continue;
			DWORD oldProtect;
			int prot = (e->prot & prot_mask);
			if (initial_prot == INITIAL_PROT_UNKNOWN || prot != initial_prot)
			{
				if (!VirtualProtect(GET_PAGE_ADDRESS(range_start), PAGE_SIZE * (range_end - range_start + 1), prot_linux2win(prot), &oldProtect))
				{
					log_error("VirtualProtect(0x%p, 0x%p) failed, error code: %d.", GET_PAGE_ADDRESS(range_start),
						PAGE_SIZE * (range_end - range_start + 1), GetLastError());
					return false;
				}
			}
		}
	}
	return true;
}

/* Load the detached block if not yet loaded, returns true if a detached block is loaded */
static bool load_detached_block(unsigned __int64 block)
{
	HANDLE section = get_section_handle(block);
	PVOID addr = GET_BLOCK_ADDRESS(block);
	unsigned __int64 size = BLOCK_SIZE;
	NTSTATUS status = NtMapViewOfSection(section, NtCurrentProcess(), &addr, 0, BLOCK_SIZE,
		NULL, &size, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
	if (NT_SUCCESS(status))
	{
		/* Load content of the block and disable write permission */
		if (load_block_protection(block, PROT_READ | PROT_EXEC, PROT_READ | PROT_WRITE | PROT_EXEC))
		{
			log_info("Detached block 0x%p successfully loaded.", block);
			return true;
		}
		log_error("Detached block 0x%p cannot be loaded.", block);
	}
	return false;
}

static int handle_cow_page_fault(void *addr)
{
	struct map_entry *entry = find_map_entry(addr);
	if (entry == NULL)
	{
		log_warning("No corresponding map entry found.");
		return 0;
	}
	if ((entry->prot & PROT_WRITE) == 0)
	{
		log_warning("Address %p (page %p) not writable.", addr, GET_PAGE(addr));
		return 0;
	}
	unsigned __int64 block = GET_BLOCK(addr);

	if (!take_block_ownership(block))
		return 0;

	/* Make sure it is mapped */
	PVOID base_addr = GET_BLOCK_ADDRESS(block);
	HANDLE section = get_section_handle(block);
	unsigned __int64 size = BLOCK_SIZE;
	NTSTATUS status;
	status = NtMapViewOfSection(section, NtCurrentProcess(), &base_addr, 0, size,
		NULL, &size, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
	int initial_prot = INITIAL_PROT_UNKNOWN;
	if (NT_SUCCESS(status))
		initial_prot = PROT_READ | PROT_WRITE | PROT_EXEC;

	/* We're the only owner of the section now, change page protection flags */
	load_block_protection(block, PROT_READ | PROT_WRITE | PROT_EXEC, initial_prot);

	/* TODO: Mark unmapped pages as PAGE_NOACCESS */
	log_info("CoW section %p successfully duplicated.", block);
	return 1;
}

static int handle_on_demand_page_fault(void *addr)
{
	unsigned __int64 page = GET_PAGE(addr);
	unsigned __int64 block = GET_BLOCK(addr);
	/* Map all map entries in the block */
	unsigned __int64 start_page = GET_FIRST_PAGE_OF_BLOCK(block);
	unsigned __int64 end_page = GET_LAST_PAGE_OF_BLOCK(block);
	int found = 0;
	if (!allocate_block(block))
	{
		return found;
	}
	for (struct rb_node *cur = start_node(start_page); cur; cur = rb_next(cur))
	{
		struct map_entry *e = rb_entry(cur, struct map_entry, tree);
		if (end_page < e->start_page)
			break;
		else
		{
			unsigned __int64 range_start = max(start_page, e->start_page);
			unsigned __int64 range_end = min(end_page, e->end_page);
			if (range_start > range_end)
				continue;
			if (page >= range_start && page <= range_end)
				found = 1;
			map_entry_range(e, range_start, range_end);
			if (e->prot != (PROT_READ | PROT_WRITE | PROT_EXEC))
			{
				DWORD oldProtect;
				if(!VirtualProtect(GET_PAGE_ADDRESS(range_start), (range_end - range_start + 1) * PAGE_SIZE, prot_linux2win(e->prot), &oldProtect))
				{
					log_error("VirtualProtect(0x%p, 0x%p, %d) failed, error code: %d.", GET_PAGE_ADDRESS(range_start),
						PAGE_SIZE * (range_end - range_start + 1), prot_linux2win(e->prot), GetLastError());
					return false;
				}
			}
		}
	}
	/* TODO: Mark unmapped pages as PAGE_NOACCESS */
	if (!found)
		log_error("Block 0x%p not mapped.", block);
	else
		log_info("On demand block 0x%p loaded.", block);
	return found;
}

int mm_handle_page_fault(void *addr, bool is_write)
{
	log_info("Handling page fault at address %p (page %p)", addr, GET_PAGE(addr));
	if ((unsigned __int64)addr < mm_address_allocation_low || (unsigned __int64)addr >= mm_address_allocation_high) //Was: if ((unsigned __int64)addr < ADDRESS_SPACE_LOW || (unsigned __int64)addr >= ADDRESS_SPACE_HIGH)
	{
		log_warning("Address %p outside of valid usermode address space.", addr);
		return 0;
	}
	AcquireSRWLockExclusive(&mm->rw_lock);
	int r;
	unsigned __int64 block = GET_BLOCK(addr);
	HANDLE section = get_section_handle(block);
	if (!section)
	{
		/* Page not loaded, load it now */
		r = handle_on_demand_page_fault(addr);
	}
	else
	{
		if (!is_write)
		{
			/* A detached block */
			r = load_detached_block(block);
		}
		else
		{
			/* CoW triggered, this function will automatically map the section if not yet */
			r = handle_cow_page_fault(addr);
		}
	}
	ReleaseSRWLockExclusive(&mm->rw_lock);
	return r;
}


int mm_write_process_memory(HANDLE process, LPVOID lpBaseAddress, LPCVOID lpBuffer, unsigned __int64 nSize)
{
	DWORD oldProtect;
	if (!VirtualProtectEx(process, mm, sizeof(struct mm_data), PAGE_READWRITE, &oldProtect))
	{
		return -1;
	}

	if (!WriteProcessMemory(process, mm, &mm, sizeof(struct mm_data), NULL))
	{
		return -2;
	}


	if (oldProtect != PAGE_READWRITE && !VirtualProtectEx(process, mm, sizeof(struct mm_data), oldProtect, &oldProtect))
	{
		return -3;
	}

	return 0;
}

int mm_fork(HANDLE process)
{
	// mem is already copied
	return 1;
	AcquireSRWLockShared(&mm->rw_lock);
	NTSTATUS status;
	/* Copy mm_data struct */
	if (!mm_write_process_memory(process, mm, &mm, sizeof(struct mm_data)))
	{
		log_error("mm_fork(): Write mm_data structure failed, status: %d", GetLastError());
		return 0;
	}

	/* Copy section handle tables */
	HANDLE *forked_section_handle = VirtualAllocEx(process, NULL, BLOCK_COUNT * sizeof(HANDLE), MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE);
	if(! mm_write_process_memory(process, &mm_section_handle, &forked_section_handle, sizeof(HANDLE *), NULL))
	{
		log_error("mm_fork(): Copy section handle master table failed, status: %x", GetLastError());
		return 0;
	}
	for (unsigned __int64 i = 0; i < SECTION_TABLE_COUNT; i++)
		if (mm->section_table_handle_count[i])
		{
			unsigned __int64 j = i * SECTION_HANDLE_PER_TABLE;
			if (!VirtualAllocEx(process, &forked_section_handle[j], BLOCK_SIZE, MEM_COMMIT, PAGE_READWRITE))
			{
				log_error("mm_fork(): Allocate section table 0x%p failed, error code: %d", i, GetLastError());
				return 0;
			}
			if (!mm_write_process_memory(process, &forked_section_handle[j], &mm_section_handle[j], BLOCK_SIZE, NULL))
			{
				log_error("mm_fork(): Write section table 0x%p failed, status: %x", GetLastError());
				return 0;
			}
		}
	/* Section mapping plus protection change is very time consuming
	 * It takes about 8 msec for 50-60 sections (3-4M) on my machine.
	 * This is too slow that even a NtWriteVirtualMemory() for such amount of
	 * data only takes about 4 msec.
	 *
	 * In most cases when execve() is invoked immediately after fork(),
	 * these regions are quickly discarded and the mapping time is wasted.
	 * To improve performance, we don't map any of the sections at all and leave
	 * the section objects in the child as `detached'. That is, they are present
	 * in the child's section handle table, but not actually mapped.
	 * When they are accessed, page faults will occur and we get the chance to do
	 * the actual mapping.
	 *
	 * So here we only do what is essential: copy VIRTUALALLOC mapped memory,
	 * and mark CoW memory regions in parent as non-writeable.
	 */
	log_info("Copy VirtualAlloc() memory blocks...");
	for (struct rb_node *cur = rb_first(&mm->entry_tree); cur; cur = rb_next(cur))
	{
		struct map_entry *e = rb_entry(cur, struct map_entry, tree);
		/* Map section */
		unsigned __int64 start_block = GET_BLOCK_OF_PAGE(e->start_page);
		unsigned __int64 end_block = GET_BLOCK_OF_PAGE(e->end_page);
		if (e->flags & INTERNAL_MAP_VIRTUALALLOC)
		{
			/* Memory region allocated via VirtualAlloc(), always block aligned */
			if (!VirtualAllocEx(process, GET_BLOCK_ADDRESS(start_block), (end_block - start_block + 1) * BLOCK_SIZE, MEM_RESERVE | MEM_COMMIT, prot_linux2win(e->prot)))
			{
				log_error("VirtualAllocEx() failed, error code: %d", GetLastError());
				mm_dump_windows_memory_mappings(process);
				return 0;
			}
			/* VirtualAlloc()-ed memory blocks are special, they can only be operated as a whole.
			 * They are never splitted and their protection flags are not stored in e->prot.
			 * Instead use VirtualQuery() to find out protection flags for each part of the memory block.
			 */
			/* Copy memory content to child process */
			unsigned __int64 current = e->start_page;
			while (current <= e->end_page)
			{
				MEMORY_BASIC_INFORMATION info;
				if (!VirtualQuery(GET_PAGE_ADDRESS(current), &info, sizeof(info)))
				{
					log_error("VirtualQuery(%p) failed, error code: %d", current, GetLastError());
					mm_dump_memory_mappings();
					mm_dump_windows_memory_mappings(GetCurrentProcess());
					return 0;
				}
				unsigned __int64 start_page = current;
				unsigned __int64 end_page = min(e->end_page, GET_PAGE((unsigned __int64)info.BaseAddress + info.RegionSize));

				log_assert(info.State == MEM_COMMIT && info.Type == MEM_PRIVATE);
				if (info.Protect == PAGE_NOACCESS || info.Protect == 0)
				{
					// FIXME: How to handle this case?
					log_warning("FIXME: PAGE_NOACCESS page ignored for copying. Range: [%p, %p)",
						GET_PAGE_ADDRESS(start_page), GET_PAGE_ADDRESS(end_page + 1));
				}
				else
				{
					/* TODO: Check unhandled/invalid protections */
					unsigned __int64 written;
					status = NtWriteVirtualMemory(process, GET_PAGE_ADDRESS(e->start_page), GET_PAGE_ADDRESS(e->start_page),
						(e->end_page - e->start_page + 1) * PAGE_SIZE, &written);
					if (!NT_SUCCESS(status))
					{
						log_error("NtWriteVirtualMemory() failed, status: %x", status);
						mm_dump_windows_memory_mappings(process);
						return 0;
					}
				}
				/* Change memory protection */
				DWORD old;
				if (!VirtualProtectEx(process, GET_PAGE_ADDRESS(start_page), (end_page - start_page + 1) * PAGE_SIZE,
					info.Protect, &old))
				{
					log_error("VirtualProtectEx() failed, error code: %d", GetLastError());
					mm_dump_windows_memory_mappings(process);
					return 0;
				}
				current = end_page + 1;
			}
		}
		else if (!(e->flags & INTERNAL_MAP_SHARED))
		{
			/* It is a CoW page, disable write permission on parent */
			if ((e->prot & PROT_WRITE))
				mm_change_protection(NtCurrentProcess(), e->start_page, e->end_page, e->prot & ~PROT_WRITE);
		}
	}
	log_info("Memory copying completed.");
	return 1;
}

void mm_afterfork_parent()
{
	ReleaseSRWLockShared(&mm->rw_lock);
}

void mm_afterfork_child()
{
	InitializeSRWLock(&mm->rw_lock);
	mm->static_alloc_begin = (uint8_t *)mm->static_alloc_end - MM_STATIC_ALLOC_SIZE;
}



static void *mmap_internal(void *addr, unsigned __int64 length, int prot, int flags, int internal_flags, struct file *f, lx_off_t offset_pages)
{
	if (length == 0)
		return MMAP_ERR(-L_EINVAL);
	length = ALIGN_TO_PAGE(length);
	if ((unsigned __int64)addr < ADDRESS_SPACE_LOW || (unsigned __int64)addr >= ADDRESS_SPACE_HIGH
		|| (unsigned __int64)addr + length < ADDRESS_SPACE_LOW || (unsigned __int64)addr + length >= ADDRESS_SPACE_HIGH
		|| (unsigned __int64)addr + length < (unsigned __int64)addr)
		return MMAP_ERR(-L_EINVAL);
	if ((flags & MAP_ANONYMOUS) && f != NULL)
	{

		log_error("MAP_ANONYMOUS with file descriptor.");
		//return MMAP_ERR(-L_EINVAL);
		f = NULL;// android bug
	}
	if (!(flags & MAP_ANONYMOUS) && f == NULL)
	{
		log_error("MAP_FILE with bad file descriptor.");
		return MMAP_ERR(-L_EBADF);
	}
	if ((internal_flags & INTERNAL_MAP_VIRTUALALLOC) &&
		(!IS_ALIGNED(addr, BLOCK_SIZE) || !IS_ALIGNED(length, BLOCK_SIZE)))
	{
		log_error("INTERNAL_MAP_VIRTUALALLOC memory regions must be aligned on entire blocks.");
		return MMAP_ERR(-L_EINVAL);
	}
	if ((flags & MAP_SHARED))
	{
		/* Translate to internal flag, which will be recorded in entry->flags */
		internal_flags |= INTERNAL_MAP_SHARED;
		/* Allocate memory immediately */
		flags |= MAP_POPULATE;
	}
	if ((flags & MAP_STACK))
	{
		/* Windows shows strange behaviour when the stack is on a shared section object */
		/* For example, it sometimes crashes when returning from a blocking system call */
		/* To avoid this, we always use VirtualAlloc() for holding stacks */
		internal_flags |= INTERNAL_MAP_VIRTUALALLOC;
	}

	bool block_align = BLOCK_ALIGNED(internal_flags);
	if ((flags & MAP_FIXED))
	{
		if (block_align && !IS_ALIGNED(addr, BLOCK_SIZE))
		{
			log_error("Non-64kB aligned MAP_FIXED address with the suppied flag is unsupported.");
			return MMAP_ERR(-L_ENOMEM);
		}
		if (!IS_ALIGNED(addr, PAGE_SIZE))
		{
			log_warning("Not page-aligned addr with MAP_FIXED.");
			return MMAP_ERR(-L_EINVAL);
		}
		if (!IS_ALIGNED(addr, BLOCK_SIZE))
		{
			/* For block unaligned fixed allocation, ensure it does not collide with block aligned memory regions */
			/* Get the previous node whose start_page should be less than or equal to current page minus one */
			// It seems that this code miss check for overlapping with other map_entry?
			struct rb_node *prev_node = start_node(GET_PAGE(addr) - 1);
			if (prev_node) /* If previous node exists... */
			{
				struct map_entry *prev_entry = rb_entry(prev_node, struct map_entry, tree);
				if (BLOCK_ALIGNED(prev_entry->flags) && GET_BLOCK_OF_PAGE(prev_entry->end_page) == GET_BLOCK(addr))
				{
					log_error("MAP_FIXED addr collides with an existing MAP_SHARED memory region.");
					return MMAP_ERR(-L_ENOMEM);
				}
			}
		}
	}
	else /* MAP_FIXED */
	{
		unsigned __int64 alloc_page;
		if (addr == NULL)
		{
			if (internal_flags & INTERNAL_MAP_TOPDOWN)
				alloc_page = find_free_pages_topdown(GET_PAGE(ALIGN_TO_PAGE(length)), block_align);
			else
				alloc_page = find_free_pages(GET_PAGE(ALIGN_TO_PAGE(length)), block_align);
			if (!alloc_page)
			{
				log_error("Cannot find free pages.");
				return MMAP_ERR(-L_ENOMEM);
			}
		}
		else
		{
			/* For block unaligned fixed allocation, ensure it does not collide with block aligned memory regions */
			/* Get the previous node whose start_page should be less than or equal to current page minus one */
			struct rb_node *prev_node = start_node(GET_PAGE(addr) - 1);
			if (prev_node) /* If previous node exists... */
			{
				unsigned __int64 start_page = GET_PAGE(addr);
				unsigned __int64 end_page = GET_PAGE((unsigned __int64)addr + length - 1);

				struct map_entry *prev_entry = rb_entry(prev_node, struct map_entry, tree);
				if (max(start_page, prev_entry->start_page) < min(end_page, prev_entry->end_page)) // is range intersecting?
				{
					alloc_page = find_free_pages_hint(addr, GET_PAGE(ALIGN_TO_PAGE(length)), block_align); //TODO: topdown
					if (!alloc_page)
					{
						log_error("Cannot find free pages.");
						return MMAP_ERR(-L_ENOMEM);
					}
				}
				else
				{
					alloc_page = GET_PAGE(addr);
				}
			}
		}
		addr = GET_PAGE_ADDRESS(alloc_page);
	}

	unsigned __int64 start_page = GET_PAGE(addr);
	unsigned __int64 end_page = GET_PAGE((unsigned __int64)addr + length - 1);
	unsigned __int64 start_block = GET_BLOCK(addr);
	unsigned __int64 end_block = GET_BLOCK((unsigned __int64)addr + length - 1);

	/*
	 * If address are fixed, unmap conflicting pages,
	 * Otherwise the pages are found by find_free_pages() thus are guaranteed free.
	 */
	if ((flags & MAP_FIXED))
	{
		if (internal_flags & INTERNAL_MAP_NOOVERWRITE)
		{
			/* The caller does not want to overwrite existing pages
			 * Check whether it is possible before doing anything
			 */
			for (struct rb_node *cur = start_node(start_page); cur; cur = rb_next(cur))
			{
				struct map_entry *e = rb_entry(cur, struct map_entry, tree);
				if (end_page < e->start_page)
					break;
				else if (start_page <= e->end_page && e->start_page <= end_page)
					return MMAP_ERR(-L_ENOMEM);
			}
		}
		else
		{
			static int munmap_internal(void *addr, unsigned __int64 length);
			munmap_internal(addr, length);
		}
	}

	/* Create new map_entry */
	struct map_entry *entry = new_map_entry();
	entry->start_page = start_page;
	entry->end_page = end_page;
	entry->f = f;
	entry->offset_pages = offset_pages;
	entry->prot = prot;
	if (f)
		vfs_ref(f);
	entry->flags = 0;
	if (internal_flags & INTERNAL_MAP_NORESET)
		entry->flags |= INTERNAL_MAP_NORESET;
	if (internal_flags & INTERNAL_MAP_VIRTUALALLOC)
		entry->flags |= INTERNAL_MAP_VIRTUALALLOC;

	/* Add the new entry to VAD tree */
	rb_add(&mm->entry_tree, &entry->tree, map_entry_cmp);

	if (internal_flags & INTERNAL_MAP_VIRTUALALLOC)
	{
		/* Ensure block is not reserved */
		for (unsigned __int64 block = start_block; block <= end_block; block++)
		{
			VirtualFree(GET_BLOCK_ADDRESS(block), 0, MEM_RELEASE); //ignore result because it can be called on already unreserved block
		}


		/* Allocate the memory now */
		if (!VirtualAlloc(GET_PAGE_ADDRESS(start_page), (end_page - start_page + 1) * PAGE_SIZE, MEM_RESERVE | MEM_COMMIT, prot_linux2win(prot)))
		{
			log_error("VirtualAlloc(%p, %p) failed, error code: %d", GET_PAGE_ADDRESS(start_page),
				(end_page - start_page + 1) * PAGE_SIZE, GetLastError());
			mm_dump_windows_memory_mappings(GetCurrentProcess());
			return MMAP_ERR(-L_ENOMEM);
		}
	}

	/* If the first or last block is already allocated, we have to set up proper content in it
	   For other blocks we map them on demand */
	HANDLE section;
	NTSTATUS status;
	if ((section = get_section_handle(start_block)) != NULL)
	{
		if (!take_block_ownership(start_block))
		{
			log_error("Taking ownership of block %p failed.", start_block);
			return MMAP_ERR (-L_ENOMEM);
		}
		/* Load it if it is detached block */
		load_detached_block(start_block);
		/* Set up content */
		unsigned __int64 last_page = GET_LAST_PAGE_OF_BLOCK(start_block);
		last_page = min(last_page, end_page);
		DWORD oldProtect;
		if(!VirtualProtect(GET_PAGE_ADDRESS(start_page), (last_page - start_page + 1) * PAGE_SIZE, prot_linux2win(prot | PROT_WRITE), &oldProtect))
		{
			log_error("VirtualProtect(0x%p, 0x%p) failed, error code: %d.", GET_PAGE_ADDRESS(start_page),
				PAGE_SIZE * (last_page - start_page + 1), GetLastError());
			return false;
		}
		map_entry_range(entry, start_page, last_page);
		if ((prot & PROT_WRITE) == 0)
		{
			if(!VirtualProtect(GET_PAGE_ADDRESS(start_page), (last_page - start_page + 1) * PAGE_SIZE, prot_linux2win(prot), &oldProtect))
			{
				log_error("VirtualProtect(0x%p, 0x%p) failed, error code: %d.", GET_PAGE_ADDRESS(start_page),
					PAGE_SIZE * (last_page - start_page + 1), GetLastError());
				return false;
			}
		}
		start_block++;
	}
	if (end_block >= start_block && (section = get_section_handle(end_block)) != NULL)
	{
		if (!take_block_ownership(end_block))
		{
			log_error("Taking ownership of block %p failed.", start_block);
			return MMAP_ERR(-L_ENOMEM);
		}
		/* Load it if it is detached block */
		load_detached_block(end_block);
		/* Set up content */
		unsigned __int64 first_page = GET_FIRST_PAGE_OF_BLOCK(end_block);
		DWORD oldProtect;
		if(!VirtualProtect(GET_PAGE_ADDRESS(first_page), (end_page - first_page + 1) * PAGE_SIZE, prot_linux2win(prot | PROT_WRITE), &oldProtect))
		{
			log_error("VirtualProtect(0x%p, 0x%p) failed, error code: %d.", GET_PAGE_ADDRESS(first_page),
				PAGE_SIZE * (end_page - first_page + 1), GetLastError());
			return false;
		}
		map_entry_range(entry, first_page, end_page);
		if ((prot & PROT_WRITE) == 0)
		{
			if(!VirtualProtect(GET_PAGE_ADDRESS(first_page), (end_page - first_page + 1) * PAGE_SIZE, prot_linux2win(prot), &oldProtect))
			{
				log_error("VirtualProtect(0x%p, 0x%p) failed, error code: %d.", GET_PAGE_ADDRESS(first_page),
					PAGE_SIZE * (end_page - first_page + 1), GetLastError());
				return false;
			}

		}
		end_block--;
	}
	if ((flags & MAP_POPULATE) && start_block < end_block)
	{
		for (unsigned __int64 i = start_block; i <= end_block; i++)
			allocate_block(i);
		map_entry_range(entry, GET_FIRST_PAGE_OF_BLOCK(start_block), GET_LAST_PAGE_OF_BLOCK(end_block));
		mm_change_protection(NtCurrentProcess(), GET_FIRST_PAGE_OF_BLOCK(start_block), GET_LAST_PAGE_OF_BLOCK(end_block), prot);
	}
	else if ((internal_flags & INTERNAL_MAP_VIRTUALALLOC) == 0)
	{
		//reserve?
	}
	log_info("Allocated memory: [%p, %p]", addr, (unsigned __int64)addr + length);
	return addr;
}

static int munmap_internal_check(void *addr, unsigned __int64 *length)
{
	/* TODO: We should mark NOACCESS for munmap()-ed but not VirtualFree()-ed pages */
	if (!IS_ALIGNED(addr, PAGE_SIZE))
		return -L_EINVAL;
	*length = ALIGN_TO_PAGE(*length);
	if ((unsigned __int64)addr < ADDRESS_SPACE_LOW || (unsigned __int64)addr >= ADDRESS_SPACE_HIGH
		|| (unsigned __int64)addr + *length < ADDRESS_SPACE_LOW || (unsigned __int64)addr + *length >= ADDRESS_SPACE_HIGH
		|| (unsigned __int64)addr + *length < (unsigned __int64)addr)
	{
		return -L_EINVAL;
	}
	return 0;
}

static void munmap_internal_unsafe(void *addr, unsigned __int64 length)
{
	mm->thread_id = GetCurrentThreadId();
	do
	{
		unsigned __int64 start_page = GET_PAGE(addr);
		unsigned __int64 end_page = GET_PAGE((unsigned __int64)addr + length - 1);
		for (struct rb_node *cur = start_node(start_page); cur;)
		{
			struct map_entry *e = rb_entry(cur, struct map_entry, tree);
			if (end_page < e->start_page)
				break;
			else
			{
				unsigned __int64 range_start = max(start_page, e->start_page);
				unsigned __int64 range_end = min(end_page, e->end_page);
				if (range_start > range_end)
				{
					cur = rb_next(cur);
					continue;
				}
				if (range_start == e->start_page && range_end == e->end_page)
				{
					/* That's good, the current entry is fully overlapped */
					if (e->prot & PROT_EXEC)
					{
						/* Notify dbt subsystem the executable pages has been lost */
						//dbt_code_changed((unsigned __int64)GET_PAGE_ADDRESS(e->start_page), (e->end_page - e->start_page + 1) * PAGE_SIZE);
					}
					struct rb_node *next = rb_next(cur);
					free_map_entry_blocks(e);
					rb_remove(&mm->entry_tree, cur);
					free_map_entry(e);
					cur = next;
				}
				else
				{
					/* Not so good, part of current entry is overlapped */
					if (range_start == e->start_page)
					{
						split_map_entry(e, range_end);
						struct rb_node *next = rb_next(cur);
						free_map_entry_blocks(e);
						rb_remove(&mm->entry_tree, cur);
						free_map_entry(e);
						cur = next;
					}
					else
					{
						split_map_entry(e, range_start - 1);
						/* The current entry is unrelated, we just skip to next entry (which we just generated) */
						cur = rb_next(cur);
					}
				}
			}
		}
		addr = munmap_list_pop(&length);
	} while (addr != NULL);
	mm->thread_id = 0;
}

static int munmap_internal(void *addr, unsigned __int64 length)
{
	int err = munmap_internal_check(addr, &length);
	if (err)
		return err;

	munmap_internal_unsafe(addr, length);
	return 0;
}

void *mm_mmap(void *addr, unsigned __int64 length, int prot, int flags, int internal_flags, struct file *f, lx_off_t offset_pages)
{
	AcquireSRWLockExclusive(&mm->rw_lock);
	void *r = mmap_internal(addr, length, prot, flags, internal_flags, f, offset_pages);
	ReleaseSRWLockExclusive(&mm->rw_lock);
	return r;
}

void *mm_alloc_thread_stack(unsigned __int64 len, bool guard_page)
{
	return VirtualAlloc(NULL, len, MEM_COMMIT, PAGE_READWRITE);
}

int mm_munmap(void *addr, unsigned __int64 length)
{
	/* Pure function, no need for locking */
	int err = munmap_internal_check(addr, &length);
	if (err)
		return err;

	/* Recursive case */
	if (mm->thread_id == GetCurrentThreadId())
	{
		munmap_list_add(addr, length);
		return 0;
	}

	AcquireSRWLockExclusive(&mm->rw_lock);
	munmap_internal_unsafe(addr, length);
	ReleaseSRWLockExclusive(&mm->rw_lock);
	return 0;
}

DEFINE_SYSCALL(mmap, void *, addr, unsigned __int64, length, int, prot, int, flags, int, fd, lx_off_t, offset)
{
	/* TODO: We should mark NOACCESS for VirtualAlloc()-ed but currently unused pages */
	log_info("mmap(%p, %p, %x, %x, %d, %p)", addr, length, prot, flags, fd, offset);
	/* TODO: Initialize mapped area to zero */
	if (!IS_ALIGNED(offset, PAGE_SIZE))
		return MMAP_ERR(-L_EINVAL);
	struct file *f = vfs_get(fd);
	intptr_t r = (intptr_t)mm_mmap(addr, length, prot, flags, 0, f, offset / PAGE_SIZE);
	if (f)
		vfs_release(f);
	return r;
}

DEFINE_SYSCALL(oldmmap, void *, _args)
{
	log_info("oldmmap(%p)", _args);
	struct oldmmap_args_t
	{
		void *addr;
		unsigned long len;
		unsigned long prot;
		unsigned long flags;
		unsigned long fd;
		unsigned long offset;
	};
	struct oldmmap_args_t *args = _args;
	return sys_mmap(args->addr, args->len, args->prot, args->flags, args->fd, args->offset);
}

DEFINE_SYSCALL(mmap2, void *, addr, unsigned __int64, length, int, prot, int, flags, int, fd, lx_off_t, offset)
{
	log_info("mmap2(%p, %p, %x, %x, %d, %p)", addr, length, prot, flags, fd, offset);
	struct file *f = vfs_get(fd);
	intptr_t r = (intptr_t)mm_mmap(addr, length, prot, flags, 0, f, offset);
	if (f)
		vfs_release(f);
	return r;
}

DEFINE_SYSCALL(munmap, void *, addr, unsigned __int64, length)
{
	log_info("munmap(%p, %p)", addr, length);
	return mm_munmap(addr, length);
}

DEFINE_SYSCALL(mprotect, void *, addr, unsigned __int64, length, int, prot)
{
	log_info("mprotect(%p, %p, %x)", addr, length, prot);
	int r = 0;

	AcquireSRWLockExclusive(&mm->rw_lock);
	if (!IS_ALIGNED(addr, PAGE_SIZE))
	{
		//r = -L_EINVAL;
		//TODO: align some modules (libc.dll) on page
		log_warning("mprotect: addr not aligned, fix it!");
		goto out;
	}
	length = ALIGN_TO_PAGE(length);
	if ((unsigned __int64)addr < ADDRESS_SPACE_LOW || (unsigned __int64)addr >= ADDRESS_SPACE_HIGH
		|| (unsigned __int64)addr + length < ADDRESS_SPACE_LOW || (unsigned __int64)addr + length >= ADDRESS_SPACE_HIGH
		|| (unsigned __int64)addr + length < (unsigned __int64)addr)
	{
		r = -L_EINVAL;
		goto out;
	}
	/* Validate all pages are mapped */
	unsigned __int64 start_page = GET_PAGE(addr);
	unsigned __int64 end_page = GET_PAGE((unsigned __int64)addr + length - 1);
	unsigned __int64 last_page = start_page - 1;
	for (struct rb_node *cur = start_node(start_page); cur; cur = rb_next(cur))
	{
		struct map_entry *e = rb_entry(cur, struct map_entry, tree);
		if (e->start_page > end_page)
			break;
		else if (e->end_page >= start_page)
		{
			if (e->start_page <= last_page + 1)
				last_page = e->end_page;
			else
				break;
		}
	}
	if (last_page < end_page)
	{
		log_error("mprotect - all pages in required block are not fully mapped");
		//r = -L_ENOMEM;
		r = 0;
		goto out;
	}

	/* Change protection flags */
	for (struct rb_node *cur = start_node(start_page); cur; cur = rb_next(cur))
	{
		struct map_entry *e = rb_entry(cur, struct map_entry, tree);
		if (end_page < e->start_page)
			break;
		else
		{
			unsigned __int64 range_start = max(start_page, e->start_page);
			unsigned __int64 range_end = min(end_page, e->end_page);
			if (range_start > range_end)
				continue;
			/* Do not split VirtualAlloc()-ed memory regions, so we can deal with the entire entry at mm_fork() */
			if ((e->flags & INTERNAL_MAP_VIRTUALALLOC))
				continue;
			if ((range_start == e->start_page && range_end == e->end_page))
			{
				/* That's good, the current entry is fully overlapped */
				e->prot = prot;
			}
			else
			{
				/* Not so good, part of current entry is overlapped, we need to split the entry */
				if (range_start == e->start_page)
				{
					split_map_entry(e, range_end);
					e->prot = prot;
				}
				else
				{
					split_map_entry(e, range_start - 1);
					/* The current entry is unrelated, we just skip to next entry (which we just generated) */
				}
			}
		}
	}
	if (!mm_change_protection(GetCurrentProcess(), start_page, end_page, prot & ~PROT_WRITE))
	{
		/* We remove the write protection in case the pages are already shared */
		r = -L_ENOMEM; /* TODO */
		goto out;
	}

out:
	ReleaseSRWLockExclusive(&mm->rw_lock);
	return r;
}

DEFINE_SYSCALL(msync, void *, addr, unsigned __int64, len, int, flags)
{
	log_info("msync(0x%p, 0x%p, %d)", addr, len, flags);
	log_error("msync() not implemented.");
	int r = 0;

	unsigned __int64 start_page = GET_PAGE(addr);
	unsigned __int64 end_page = GET_PAGE((unsigned __int64)addr + len - 1);
	unsigned __int64 last_page = start_page - 1;

	AcquireSRWLockExclusive(&mm->rw_lock);


	for (struct rb_node *cur = start_node(start_page); cur; cur = rb_next(cur))
	{
		struct map_entry *e = rb_entry(cur, struct map_entry, tree);
		if (end_page < e->start_page)
			break;
		else
		{
			unsigned __int64 range_start = max(start_page, e->start_page);
			unsigned __int64 range_end = min(end_page, e->end_page);
			if (range_start > range_end)
				continue;

			unsigned __int64 desired_size = (range_end - range_start + 1) * PAGE_SIZE;

			if (e->f->op_vtable->pwrite == NULL)
			{
				log_error("pwrite not implemented");
				r = -L_ENOSYS;
				goto out;
			}

			unsigned __int64 r = e->f->op_vtable->pwrite(e->f, GET_PAGE_ADDRESS(range_start), desired_size,
				(lx_loff_t)(e->offset_pages + range_start - e->start_page - 1) * PAGE_SIZE);

		}
	}

	out:
		ReleaseSRWLockExclusive(&mm->rw_lock);
		return r;
	}

static int mm_populate_internal(const void *addr, unsigned __int64 len)
{
	unsigned __int64 start_page = GET_PAGE(addr);
	unsigned __int64 end_page = GET_PAGE((unsigned __int64)addr + len);
	unsigned __int64 num_blocks = 0;
	for (struct rb_node *cur = start_node(start_page); cur; cur = rb_next(cur))
	{
		struct map_entry *e = rb_entry(cur, struct map_entry, tree);
		if (e->start_page > end_page)
			break;
		else
		{
			unsigned __int64 range_start = max(start_page, e->start_page);
			unsigned __int64 range_end = min(end_page, e->end_page);
			if (range_start > range_end)
				continue;

			unsigned __int64 start_block = GET_BLOCK_OF_PAGE(range_start);
			unsigned __int64 end_block = GET_BLOCK_OF_PAGE(range_end);
			for (unsigned __int64 i = start_block; i <= end_block; i++)
			{
				HANDLE section = get_section_handle(i);
				if (section != NULL)
				{
					/* Load it if it is detached block */
					load_detached_block(i);
					continue;
				}
				else
				{
					if (!allocate_block(i))
						return -L_ENOMEM;
					num_blocks++;
					unsigned __int64 first_page = max(range_start, GET_FIRST_PAGE_OF_BLOCK(i));
					unsigned __int64 last_page = min(range_end, GET_LAST_PAGE_OF_BLOCK(i));
					map_entry_range(e, first_page, last_page);
					if (e->prot != PROT_READ | PROT_WRITE | PROT_EXEC)
					{
						DWORD oldProtect;
						if(!VirtualProtect(GET_PAGE_ADDRESS(first_page), (last_page - first_page + 1) * PAGE_SIZE, prot_linux2win(e->prot), &oldProtect))
						{
							log_error("VirtualProtect(0x%p, 0x%p) failed, error code: %d.", GET_PAGE_ADDRESS(first_page),
								PAGE_SIZE * (end_page - first_page + 1), GetLastError());
							return false;
						}

					}
				}
			}
		}
	}
	log_info("Populated memory blocks: %d", num_blocks);
	/* TODO: Mark unused pages as NOACCESS */
	return 0;
}

void mm_populate(void *addr)
{
	AcquireSRWLockExclusive(&mm->rw_lock);
	unsigned __int64 page = GET_PAGE(addr);
	struct rb_node *cur = start_node(page);
	struct map_entry *e = rb_entry(cur, struct map_entry, tree);
	if (e->start_page <= page && page <= e->end_page)
		mm_populate_internal(GET_PAGE_ADDRESS(e->start_page), (e->end_page - e->start_page + 1) * PAGE_SIZE);
	ReleaseSRWLockExclusive(&mm->rw_lock);
}

DEFINE_SYSCALL(mlock, const void *, addr, unsigned __int64, len)
{
	log_info("mlock(0x%p, 0x%p)", addr, len);
	int r = 0;
	AcquireSRWLockExclusive(&mm->rw_lock);
	if (!IS_ALIGNED(addr, PAGE_SIZE))
	{
		r = -L_EINVAL;
		goto out;
	}

	/* All on demand page must be properly loaded or the locking operation will fail */
	r = mm_populate_internal(addr, len);
	if (!r)
		goto out;

	/* The actual locking */
	/* TODO: Automatically enlarge working set size for arbitrary sized mlock() call */
	if (!VirtualLock((LPVOID)addr, len))
	{
		log_warning("VirtualLock() failed, error code: %d", GetLastError());
		r = -L_ENOMEM;
		goto out;
	}

out:
	ReleaseSRWLockExclusive(&mm->rw_lock);
	return r;
}

DEFINE_SYSCALL(munlock, const void *, addr, unsigned __int64, len)
{
	log_info("munlock(0x%p, 0x%p)", addr, len);
	if (!IS_ALIGNED(addr, PAGE_SIZE))
		return -L_EINVAL;
	if (!VirtualUnlock((LPVOID)addr, len))
	{
		log_warning("VirtualUnlock() failed, error code: %d", GetLastError());
		return -L_ENOMEM;
	}
	return 0;
}

DEFINE_SYSCALL(mremap, void *, old_address, unsigned __int64, old_size, unsigned __int64, new_size, int, flags, void *, new_address)
{
	log_info("mremap(old_address=%p, old_size=%p, new_size=%p, flags=%x, new_address=%p)", old_address, old_size, new_size, flags, new_address);
	log_error("mremap() not implemented.");
	return -L_ENOSYS;
}

DEFINE_SYSCALL(madvise, void *, addr, unsigned __int64, length, int, advise)
{
	log_info("madvise(%p, %p, %x)", addr, length, advise);
	/* Notes behaviour-changing advices, other non-critical advises are ignored for now */
	if (advise == MADV_DONTFORK)
		log_error("MADV_DONTFORK not supported.");
	return 0;
}

DEFINE_SYSCALL(brk, void *, addr)
{
	log_info("brk(%p)", addr);
	log_info("Last brk: %p", mm->brk);
	AcquireSRWLockExclusive(&mm->rw_lock);
	unsigned __int64 brk = ALIGN_TO_PAGE(mm->brk);
	addr = (void*)ALIGN_TO_PAGE(addr);
	if (addr > 0 && addr < mm->brk)
	{
		if (munmap_internal(addr, (unsigned __int64)brk - (unsigned __int64)addr) < 0)
		{
			log_error("Shrink brk failed.");
			goto out;
		}
		mm->brk = addr;
	}
	else if (addr > mm->brk)
	{
		int r = (int)mmap_internal((void *)brk, (unsigned __int64)addr - (unsigned __int64)brk, PROT_READ | PROT_WRITE /*| PROT_EXEC*/,
			MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, INTERNAL_MAP_NOOVERWRITE, NULL, 0);
		if (r < 0)
		{
			log_error("Enlarge brk failed.");
			goto out;
		}
		mm->brk = addr;
	}
out:
	ReleaseSRWLockExclusive(&mm->rw_lock);
	log_info("New brk: %p", mm->brk);
	return (intptr_t)mm->brk;
}

DEFINE_SYSCALL(mlockall)
{
	log_info("mlockall()");
	log_error("mlockall not supported.");
	return 0;
}

DEFINE_SYSCALL(munlockall)
{
	log_info("munlockall()");
	log_error("munlockall not supported.");
	return 0;
}
