/*-
 * Copyright (c) 1998 Doug Rabson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */
#ifndef _MACHINE_ATOMIC_H_
#define	_MACHINE_ATOMIC_H_

#ifndef _SYS_CDEFS_H_
#error this file needs sys/cdefs.h as a prerequisite
#endif

#define	mb()	__asm __volatile("mfence;" : : : "memory")
#define	wmb()	__asm __volatile("sfence;" : : : "memory")
#define	rmb()	__asm __volatile("lfence;" : : : "memory")

/*
 * Various simple operations on memory, each of which is atomic in the
 * presence of interrupts and multiple processors.
 *
 * atomic_set_char(P, V)	(*(u_char *)(P) |= (V))
 * atomic_clear_char(P, V)	(*(u_char *)(P) &= ~(V))
 * atomic_add_char(P, V)	(*(u_char *)(P) += (V))
 * atomic_subtract_char(P, V)	(*(u_char *)(P) -= (V))
 *
 * atomic_set_short(P, V)	(*(u_short *)(P) |= (V))
 * atomic_clear_short(P, V)	(*(u_short *)(P) &= ~(V))
 * atomic_add_short(P, V)	(*(u_short *)(P) += (V))
 * atomic_subtract_short(P, V)	(*(u_short *)(P) -= (V))
 *
 * atomic_set_int(P, V)		(*(u_int *)(P) |= (V))
 * atomic_clear_int(P, V)	(*(u_int *)(P) &= ~(V))
 * atomic_add_int(P, V)		(*(u_int *)(P) += (V))
 * atomic_subtract_int(P, V)	(*(u_int *)(P) -= (V))
 * atomic_readandclear_int(P)	(return (*(u_int *)(P)); *(u_int *)(P) = 0;)
 *
 * atomic_set_long(P, V)	(*(u_long *)(P) |= (V))
 * atomic_clear_long(P, V)	(*(u_long *)(P) &= ~(V))
 * atomic_add_long(P, V)	(*(u_long *)(P) += (V))
 * atomic_subtract_long(P, V)	(*(u_long *)(P) -= (V))
 * atomic_readandclear_long(P)	(return (*(u_long *)(P)); *(u_long *)(P) = 0;)
 */


int	atomic_cmpset_int(volatile u_int *dst, u_int expect, u_int src);
int	atomic_cmpset_long(volatile u_long *dst, u_long expect, u_long src);
u_int	atomic_fetchadd_int(volatile u_int *p, u_int v);
u_long	atomic_fetchadd_long(volatile u_long *p, u_long v);
u_long atomic_cmpset_acq_ptr(volatile u_long *p, volatile u_long cmpval, volatile u_long newval);
void atomic_add_barr_int(volatile u_int32_t *p, u_int32_t val);
void atomic_store_rel_int(volatile uint32_t *dst, uint32_t src);
void atomic_set_32(volatile uint32_t *address, uint32_t setmask);
#define	atomic_add_acq_int		atomic_add_barr_int
#define atomic_add_int atomic_add_barr_int
#define atomic_cmpset_rel_ptr atomic_cmpset_long
#define atomic_clear_ptr
#define atomic_store_rel_ptr
#define atomic_cmpset_ptr atomic_cmpset_long
#define atomic_set_ptr atomic_set_32

#if 0
#define	ATOMIC_ASM(NAME, TYPE, OP, CONS, V)		\
static __inline void					\
atomic_##NAME##_##TYPE(volatile u_##TYPE *p, u_##TYPE v)\
{							\
	__asm __volatile(MPLOCKED OP			\
	: "=m" (*p)					\
	: CONS (V), "m" (*p)				\
	: "cc");					\
}							\
							\
static __inline void					\
atomic_##NAME##_barr_##TYPE(volatile u_##TYPE *p, u_##TYPE v)\
{							\
	__asm __volatile(MPLOCKED OP			\
	: "=m" (*p)					\
	: CONS (V), "m" (*p)				\
	: "memory", "cc");				\
}							\
struct __hack

#define	ATOMIC_STORE_LOAD(TYPE, LOP, SOP)		\
static __inline u_##TYPE				\
atomic_load_acq_##TYPE(volatile u_##TYPE *p)		\
{							\
	u_##TYPE tmp;					\
							\
	tmp = *p;					\
	return (tmp);					\
}							\
							\
static __inline void					\
atomic_store_rel_##TYPE(volatile u_##TYPE *p, u_##TYPE v)\
{							\
	*p = v;						\
}							\
struct __hack



ATOMIC_ASM(set,	     char,  "orb %b1,%0",  "iq",  v);
ATOMIC_ASM(clear,    char,  "andb %b1,%0", "iq", ~v);
ATOMIC_ASM(add,	     char,  "addb %b1,%0", "iq",  v);
ATOMIC_ASM(subtract, char,  "subb %b1,%0", "iq",  v);

ATOMIC_ASM(set,	     short, "orw %w1,%0",  "ir",  v);
ATOMIC_ASM(clear,    short, "andw %w1,%0", "ir", ~v);
ATOMIC_ASM(add,	     short, "addw %w1,%0", "ir",  v);
ATOMIC_ASM(subtract, short, "subw %w1,%0", "ir",  v);

ATOMIC_ASM(set,	     int,   "orl %1,%0",   "ir",  v);
ATOMIC_ASM(clear,    int,   "andl %1,%0",  "ir", ~v);
ATOMIC_ASM(add,	     int,   "addl %1,%0",  "ir",  v);
ATOMIC_ASM(subtract, int,   "subl %1,%0",  "ir",  v);

ATOMIC_ASM(set,	     long,  "orq %1,%0",   "ir",  v);
ATOMIC_ASM(clear,    long,  "andq %1,%0",  "ir", ~v);
ATOMIC_ASM(add,	     long,  "addq %1,%0",  "ir",  v);
ATOMIC_ASM(subtract, long,  "subq %1,%0",  "ir",  v);

ATOMIC_STORE_LOAD(char,	"cmpxchgb %b0,%1", "xchgb %b1,%0");
ATOMIC_STORE_LOAD(short,"cmpxchgw %w0,%1", "xchgw %w1,%0");
ATOMIC_STORE_LOAD(int,	"cmpxchgl %0,%1",  "xchgl %1,%0");
ATOMIC_STORE_LOAD(long,	"cmpxchgq %0,%1",  "xchgq %1,%0");

#undef ATOMIC_ASM
#undef ATOMIC_STORE_LOAD
#endif


#endif /* !_MACHINE_ATOMIC_H_ */
