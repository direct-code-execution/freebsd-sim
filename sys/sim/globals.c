/*
  Network Simulation Cradle
  Copyright (C) 2003-2005 Sam Jansen

  This program is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by the Free
  Software Foundation; either version 2 of the License, or (at your option)
  any later version.

  This program is distributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
  more details.

  You should have received a copy of the GNU General Public License along
  with this program; if not, write to the Free Software Foundation, Inc., 59
  Temple Place, Suite 330, Boston, MA 02111-1307 USA
*/
/* $Id$ */
/* This nasty file contains lots of globals that were defined elsewhere in the
   kernel that the network code relies on. Quite a few miscellaneous globals
   ended up in this file. Some of the stuff I wasn't very sure about, and
   just chucked in this file and hoped things would work. It is a bit nasty
   and probably requires some amount of maintenance between kernel versions.

   May 11 2004: So far I've found it requires very little maintenance.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mac.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/syslog.h>
#include <sys/sysctl.h>
#include <sys/bus.h>
#include <sys/interrupt.h>
#include <sys/random.h>
#include <sys/event.h>
#include <sys/ucred.h>
#include <sys/vnode.h>
#include <sys/proc.h>
#include <sys/tty.h>
#include <sys/conf.h>
#include <sys/callout.h>

#include <machine/stdarg.h>

#include <net/ethernet.h>

#include <vm/vm.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_param.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_extern.h>
#include <vm/uma.h>
#include <vm/uma_int.h>
#include <vm/uma_dbg.h>

#include <ddb/ddb.h>
#include <ddb/db_command.h>

/* The Giant mutex. Woot. */
#if 0
struct mtx Giant;
#endif
int dumping;				/* system is dumping */

// kern/init_main.c
struct	thread thread0;
struct	proc proc0;
int      bootverbose;

// kern/kern_shutdown.c
/*
 * Variable panicstr contains argument to first call to panic; used as flag
 * to indicate that the kernel has already called panic.
 */
const char *panicstr;

// kern/tty_conf.c
#ifndef MAXLDISC
#define MAXLDISC 9
#endif

/*static l_open_t		l_noopen;
static l_close_t	l_noclose;
static l_rint_t		l_norint;
static l_start_t	l_nostart;*/

/* I think this one is auto-generated somehow/somewhere. */

/* I don't think this is important at all */
long physmem;
long realmem;
int elf32_fallback_brand = -1;
int elf64_fallback_brand = -1;
struct vmmeter cnt;

/*
 * XXX it probably doesn't matter what the entries other than the l_open
 * entry are here.  The l_nullioctl and ttymodem entries still look fishy.
 * Reconsider the removal of nullmodem anyway.  It was too much like
 * ttymodem, but a completely null version might be useful.
 */
/*#define NODISC(n) \
	{ l_noopen,	l_noclose,	l_noread,	l_nowrite, \
	  l_nullioctl,	l_norint,	l_nostart,	ttymodem }*/

struct	linesw *linesw[MAXLDISC];
#if 0
=
{
				/* 0- termios */
	{ ttyopen,	ttylclose,	ttread,		ttwrite,
	  l_nullioctl,	ttyinput,	ttstart,	ttymodem },
	NODISC(1),		/* 1- defunct */
	  			/* 2- NTTYDISC */
#ifdef COMPAT_43
	{ ttyopen,	ttylclose,	ttread,		ttwrite,
	  l_nullioctl,	ttyinput,	ttstart,	ttymodem },
#else
	NODISC(2),
#endif
	NODISC(3),		/* loadable */
	NODISC(4),		/* SLIPDISC */
	NODISC(5),		/* PPPDISC */
	NODISC(6),		/* NETGRAPHDISC */
	NODISC(7),		/* loadable */
	NODISC(8),		/* loadable */
};
#endif

// vm/vm_kern.c
vm_map_t kmem_map = 0;
vm_map_t kernel_map;

// libkern/bcd.c
/* This is actually used with radix [2..36] */
char const hex2ascii_data[] = "0123456789abcdefghijklmnopqrstuvwxyz";

// dev/random/harvest.c
/* Structure holding the desired entropy sources */
struct harvest_select harvest = { 0, 0, 0 };

// kern/tty.c
MALLOC_DEFINE(M_TTYS, "ttys", "tty data structures");

// kern/kern_malloc.c
MALLOC_DEFINE(M_TEMP, "temp", "misc temporary data buffers");
MALLOC_DEFINE(M_IP6OPT, "ip6opt", "IPv6 options");
MALLOC_DEFINE(M_IP6NDP, "ip6ndp", "IPv6 Neighbor Discovery");
MALLOC_DEFINE(M_DEVBUF, "devbuf", "device driver memory");
MALLOC_DEFINE(M_SUBPROC, "subproc", "Proc sub-structures");
MALLOC_DEFINE(M_IOV, "iov", "large iov's");

// externed in kern/kern_conf.c:47. It says "Built at compile time from sys/conf/majors"
unsigned char reserved_majors[256];



struct mtx sched_lock;
struct mtx Giant;


int			cpu_disable_deep_sleep = 0; /* Timer dies in C3. */
u_int cpuid = 1;
int kdb_active = 0;
struct thread *kdb_thread = NULL;	/* Current thread. */

int unmapped_buf_allowed = 1;

struct proclist allproc;
struct sx allproc_lock;
struct sx proctree_lock;

volatile int	db_pager_quit;			/* user requested quit */
struct command_table db_show_table;
struct command_table db_show_all_table;

struct filterops sig_filtops;
struct filterops fs_filtops;
