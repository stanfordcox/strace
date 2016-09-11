/**
 * Some simple implementation of list similar to one used in kernel.
 */

#ifndef STRACE_LIST_H
#define STRACE_LIST_H

/*
 * Macro to test if we're using a specific version of gcc or later.
 */
#if defined(__GNUC__) && !defined(__INTEL_COMPILER)
#define	__GNUC_PREREQ__(ma, mi)	\
	(__GNUC__ > (ma) || __GNUC__ == (ma) && __GNUC_MINOR__ >= (mi))
#else
#define	__GNUC_PREREQ__(ma, mi)	0
#endif

#ifndef	__DEQUALIFY
#define	__DEQUALIFY(type, var)	((type)(uintptr_t)(const volatile void *)(var))
#endif

/*
 * We define this here since <stddef.h>, <sys/queue.h>, and <sys/types.h>
 * require it.
 */
#if __GNUC_PREREQ__(4, 1)
#define	__offsetof(type, field)	 __builtin_offsetof(type, field)
#else
#define	__offsetof(type, field) \
	((__size_t)(uintptr_t)((const volatile void *)&((type *)0)->field))
#endif

#ifndef __containerof
/*
 * Given the pointer x to the member m of the struct s, return
 * a pointer to the containing structure.  When using GCC, we first
 * assign pointer x to a local variable, to check that its type is
 * compatible with member m.
 */
#if __GNUC_PREREQ__(3, 1)
#define	__containerof(x, s, m) ({					\
	const volatile __typeof(((s *)0)->m) *__x = (x);		\
	__DEQUALIFY(s *, (const volatile char *)__x - __offsetof(s, m));\
})
#else
#define	__containerof(x, s, m)						\
	__DEQUALIFY(s *, (const volatile char *)(x) - __offsetof(s, m))
#endif
#endif /* #ifndef __containerof */

struct list_item {
	struct list_item *prev;
	struct list_item *next;
};

#define EMPTY_LIST(_l) { _l, _l }

static inline void
list_init(struct list_item *l)
{
	l->prev = l;
	l->next = l;
}

static inline bool
list_is_empty(struct list_item *l)
{
	return (l->next == l) && (l->prev == l);
}

#define list_elem(var, type, field) \
	__containerof((var), type, field)

#define list_head(head, type, field) \
	(list_is_empty(head) ? NULL : list_elem((head)->next, type, field))
#define list_tail(head, type, field) \
	(list_is_empty(head) ? NULL : list_elem((head)->prev, type, field))

#define list_next(val, field) \
	list_elem((val)->field.next, __typeof(*(val)), field)
#define list_prev(val, field) \
	list_elem((val)->field.prev, __typeof(*(val)), field)

static inline void
list_insert(struct list_item *head, struct list_item *item)
{
	item->next = head->next;
	item->prev = head;
	head->next->prev = item;
	head->next = item;
}

static inline void
list_append(struct list_item *head, struct list_item *item)
{
	item->next = head;
	item->prev = head->prev;
	head->prev->next = item;
	head->prev = item;
}

static inline void
list_remove(struct list_item *item)
{
	item->prev->next = item->next;
	item->next->prev = item->prev;
	item->next = item->prev = NULL;
}

static inline void
list_remove_tail(struct list_item *head)
{
	list_remove(head->prev);
}

static inline void
list_remove_head(struct list_item *head)
{
	list_remove(head->next);
}

static inline void
list_replace(struct list_item *old, struct list_item *new)
{
	new->next = old->next;
	new->prev = old->prev;
	old->prev->next = new;
	old->next->prev = new;
	old->next = old->prev = NULL;
}

#define list_foreach(_var, _head, _field) \
	for (_var = list_elem((_head)->next, __typeof(*_var), _field); \
	    &(_var->_field) != (_head); _var = list_next(_var, _field))

#define list_foreach_safe(_var, _head, _field, _tmp) \
	for (_var = list_elem((_head)->next, __typeof(*_var), _field), \
	    _tmp = list_elem((_var)->_field.next, __typeof(*_var), _field); \
	    &_var->_field != _head; _var = _tmp, _tmp = list_next(_tmp, _field))

#endif /* !STRACE_LIST_H */
