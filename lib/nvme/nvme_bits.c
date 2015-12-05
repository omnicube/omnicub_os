#include "nvme_osdep.h"

/**
 * ffz - find first zero bit in word
 * @word: The word to search
 * 
 * Undefined if no zero exists, so code should check against ~0UL first.
 */
static inline unsigned long ffz(unsigned long word)
{
	asm("rep; bsf %1,%0"
		: "=r" (word)
		: "r" (~word));
	return word;
}

unsigned long
find_next_zero_bit(const unsigned long *addr, unsigned long size,
                                 unsigned long offset)
{
	const unsigned long *p = addr + BITOP_WORD(offset);
	unsigned long result = offset & ~(BITS_PER_LONG-1);
	unsigned long tmp;

	if (offset >= size)
		return size;
	size -= result;
	offset %= BITS_PER_LONG;

	if (offset) {
		tmp = *(p++);
		tmp |= ~0UL >> (BITS_PER_LONG - offset);
		if (size < BITS_PER_LONG)
			goto found_first;
		if (~tmp)
			goto found_middle;
		size -= BITS_PER_LONG;
		result += BITS_PER_LONG;
	}

	while (size & ~(BITS_PER_LONG-1)) {
		if (~(tmp = *(p++)))
			goto found_middle;
		result += BITS_PER_LONG;
		size -= BITS_PER_LONG;
	}
	if (!size)
		return result;
	tmp = *p;

found_first:
	tmp |= ~0UL << size;
	if (tmp == ~0UL)        /* Are any bits zero? */
		return result + size;   /* Nope. */
found_middle:
	return result + ffz(tmp);
}

unsigned long
find_first_zero_bit(const unsigned long *addr, unsigned long size)
{
	const unsigned long *p = addr;
	unsigned long result = 0;
	unsigned long tmp;
       
	while (size & ~(BITS_PER_LONG-1)) {
		if (~(tmp = *(p++)))
			goto found;
		result += BITS_PER_LONG;
		size -= BITS_PER_LONG;
	}
	if (!size)
		return result;

	tmp = (*p) | (~0UL << size);
	if (tmp == ~0UL)        /* Are any bits zero? */
		return result + size;   /* Nope. */
found:
	return result + ffz(tmp);
}

#if __GNUC__ < 4 || (__GNUC__ == 4 && __GNUC_MINOR__ < 1)
	/* Technically wrong, but this avoids compilation errors on some gcc
	   versions. */
	#define BITOP_ADDR(x) "=m" (*(volatile long *) (x))
#else
	#define BITOP_ADDR(x) "+m" (*(volatile long *) (x))
#endif

#define IS_IMMEDIATE(nr)                (__builtin_constant_p(nr))
#define CONST_MASK_ADDR(nr, addr)       BITOP_ADDR((void *)(addr) + ((nr)>>3))
#define CONST_MASK(nr)                  (1 << ((nr) & 7))

inline void
clear_bit(long nr, volatile unsigned long *addr)
{
	if (IS_IMMEDIATE(nr)) {
		asm volatile(LOCK_PREFIX "andb %1,%0"
			: CONST_MASK_ADDR(nr, addr)
			: "iq" ((u8)~CONST_MASK(nr)));
	} else {
		asm volatile(LOCK_PREFIX "btr %1,%0"
			: BITOP_ADDR(addr)
			: "Ir" (nr));
	}
}
