#ifndef _NVME_LIST_H
#define _NVME_LIST_H 

#include <stdio.h>
#include <stdlib.h>

#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

struct list_head {
	struct list_head *next, *prev;
};

static inline void INIT_LIST_HEAD(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}

#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)

static inline __list_add(struct list_head *_new,
			struct list_head *prev,
			struct list_head *next)
{
	next->prev = _new;
	_new->next = next;
	_new->prev = prev;
	prev->next = _new;
}

static inline void list_add_tail(struct list_head *_new, struct list_head *head)
{
	__list_add(_new, head->prev, head);
}

#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type, member) ); })

#define list_entry(ptr, type, member)   \
        container_of(ptr, type, member)

#define list_for_each_entry(pos, head, member)                          \
        for (pos = list_entry((head)->next, typeof(*pos), member);      \
                &pos->member != (head);                                 \
                pos = list_entry(pos->member.next, typeof(*pos), member))

#define list_for_each_entry_safe(pos, n, head, member)                  \
        for (pos = list_entry((head)->next, typeof(*pos), member),      \
                n = list_entry(pos->member.next, typeof(*pos), member); \
                &pos->member != (head);                                 \
                pos = n, n = list_entry(n->member.next, typeof(*n), member))


static inline void __list_del(struct list_head *prev, struct list_head *next)
{
        next->prev = prev;
        prev->next = next;
}

#define LIST_POISON1    ((void *) 0x00100100)
#define LIST_POISON2    ((void *) 0x00200200)

static inline void list_del(struct list_head *entry)
{
        __list_del(entry->prev, entry->next);
        entry->next = (struct list_head *) LIST_POISON1;
        entry->prev = (struct list_head *) LIST_POISON2;
}

#endif
