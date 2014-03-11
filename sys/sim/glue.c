/*
  Network Simulation Cradle
  Copyright (C) 2003-2008 Sam Jansen

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
/* $Id: implemented.c 1018 2006-01-16 05:26:00Z stj2 $ */
/* Functions that have a body, whether empty or fully implemented. Functions
 * move from stub.c into implemented.c when they are required for operation. 
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
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/bio.h>
#include <sys/namei.h>
#include <sys/sx.h>
#include <sys/condvar.h>
#include <sys/rwlock.h>
#include <sys/vnode.h>
#include <sys/proc.h>
#include <sys/file.h>
#include <sys/module.h>

#include <machine/stdarg.h>

#include <vm/vm.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_param.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>
#include <vm/uma.h>
#include <vm/uma_int.h>
#include <vm/uma_dbg.h>

#include <sys/resourcevar.h>
#include <sys/limits.h>
#include <crypto/blowfish/blowfish.h>

#include "sim.h"

struct linesw;
struct ipsecrequest;
struct selinfo;
struct sigio;

#define	atomic_add_rel_int		atomic_add_barr_int
void
bzero(void *buf, size_t len)
{
  char *ptr;
  for (ptr = (char *)buf; len--; )
    *ptr++ = 0;
}

void
bcopy(const void *src0, void *dst0, size_t length)
{
  char *ptr;
  for (ptr = (char *)src0; length--; )
    *(char *)dst0++ = *ptr++;
}

void *
memcpy(void *dst0, const void *src0, size_t length)
{
  bcopy((src0), (dst0), (length));
  return dst0;
}

#define UNIMPLEMENED_NOASSERT() sim_assert (0)/*\ 
	debugf("%s:%d] Function %s unimplemented. Called from: %x %x\n", \
			__FILE__, __LINE__, __FUNCTION__, \
			__builtin_return_address(0), __builtin_return_address(1));*/


// --------------------------------------------------------------------------
// All functions at the top of this file are partially or fully implemented
// --------------------------------------------------------------------------

/**
 * "Return an integer value from an environment variable."
 *
 * @todo: Consider implementing this function.
 * Note that implementing this function would make it possible to set up
 * kernel vars easily. For example, this gets called with kern.hz as a
 * parameter, so we could use it to set up the hz value without having to
 * modify kern/subr_param.c all the time.
 */
int getenv_int(const char *name, int *data)
{
  return 0;
}

int getenv_long(const char *name, long *data)
{
  return 0;
}

int getenv_ulong(const char *name, unsigned long *data)
{
  return 0;
}
int
getenv_string(const char *name, char *data, int size)
{
  return 0;
}
/*
 * Return a quad_t value from an environment variable.
 */
int getenv_quad(const char *name, quad_t *data)
{
  /* XXX */
  return 0;
}

char *
getenv(const char *name)
{
  return NULL;
}

/*
 * Shortcut to hide contents of struct td and struct proc from the
 * caller, promoting binary compatibility.
 */
int suser(struct thread *td)
{
  UNIMPLEMENED_NOASSERT();
  // Returning 0 here means we are the super-user
  return 0;
}

int resource_string_value(const char *name, int unit, const char *resname,
    const char **result)
{
  UNIMPLEMENED_NOASSERT();
  return (int)1;
}

/*
 * err = resource_find_dev(&anchor, name, &unit, res, value);
 * Iterate through a list of devices, returning their unit numbers.
 * res and value are optional restrictions.  eg: "at", "scbus0".
 * *unit is set to the value.
 * set *anchor to zero before starting.
 */
int resource_find_dev(int *anchor, const char *name, int *unit,
    const char *resname, const char *value)
{
  UNIMPLEMENED_NOASSERT();
  return (int)1;
}

/*
 * Change the total socket buffer size a user has used.
 */
int chgsbsize(struct  uidinfo *uip, u_int* hiwat, u_int to, rlim_t  max)
{
  /*	
        rlim_t new;
        int s;

        s = splnet();
        UIDINFO_LOCK(uip);
        new = uip->ui_sbsize + to - *hiwat;
  // don't allow them to exceed max, but allow subtraction
  if (to > *hiwat && new > max) {
  splx(s);
  UIDINFO_UNLOCK(uip);
  return (0);
  }
  uip->ui_sbsize = new;*/
  *hiwat = to;
  /*if (uip->ui_sbsize < 0)
    printf("negative sbsize for uid = %d\n", uip->ui_uid);
    splx(s);
    UIDINFO_UNLOCK(uip);*/
  return (1);
}

u_long random(void) 
{
  return sim_random();
}

int read_random(void *buf, int count)
{
  unsigned int* int_buf = (unsigned int*)buf;
  unsigned char* uc_buf = (unsigned char*)buf;

  int i, j;

  for(i = 0; i < count; i += sizeof(int)) {
    if(count - i < sizeof(int)) {
      for(j = 0; j < count - i; j++)
        uc_buf[i + j] = (unsigned char)(sim_random() % 256);
    } else
      int_buf[i >> 2] = sim_random();
  }
  return count;
}


void nsc_log(int a, const char *b, ...) 
{
  printf("log: '%s'\n", b);
}



/*
 * Claim another reference to a ucred structure.
 */
struct ucred *crhold(struct ucred *cr)
{
  cr->cr_ref++;
  return (cr);
}

/*
 * Allocate a zeroed cred structure.
 */
static MALLOC_DEFINE(M_CRED, "cred", "credentials");

struct ucred *crget(void)
{
  register struct ucred *cr;

  MALLOC(cr, struct ucred *, sizeof(*cr), M_CRED, M_WAITOK | M_ZERO);
  cr->cr_ref = 1;
#ifdef MAC
  mac_init_cred(cr);
#endif
  return (cr);
}

void uma_zfree_arg(uma_zone_t zone, void *item, void *udata)
{
  debugf("Freeing in %s. zone='%s' (%s:%d) ", 
       __FUNCTION__,
      zone->uz_name,
      __FILE__,__LINE__);

  debugf("= %p\n", item);

  if (zone->uz_dtor)
    zone->uz_dtor(item, zone->uz_size, udata);

  if(zone->uz_fini)
    zone->uz_fini(item, zone->uz_size);

  free(((unsigned char *)item - 4), 0);
}

uma_zone_t uma_zcreate(const char *name, size_t size, uma_ctor ctor, uma_dtor dtor,
    uma_init uminit, uma_fini fini, int align, u_int32_t flags)
{
  uma_zone_t zone = (uma_zone_t)malloc(sizeof(struct uma_zone),0,0);

  debugf("Creating uma zone '%s' (size=%d)\n", name, size);

  zone->uz_name = name;
  zone->uz_ctor = ctor;
  zone->uz_dtor = dtor;
  zone->uz_init = uminit;
  zone->uz_fini = fini;

  zone->uz_size = size;
  //  zone->uz_align = align;
  zone->uz_flags = flags;

  return zone;
}

uma_zone_t uma_zsecond_create(char *name, uma_ctor ctor, uma_dtor dtor,
    uma_init zinit, uma_fini zfini, uma_zone_t master)
{
  uma_zone_t zone = (uma_zone_t)malloc(sizeof(struct uma_zone),0,0);
  debugf("Creating uma second zone '%s'(size=%d)\n", name, master->uz_size);

  zone->uz_size = master->uz_size;
  zone->uz_name = name;
  zone->uz_ctor = ctor;
  zone->uz_dtor = dtor;
  zone->uz_init = zinit;
  zone->uz_fini = zfini;

  return zone;
}

void *uma_zalloc_arg(uma_zone_t zone, void *udata, int flags)
{
  unsigned char *m = NULL;
  unsigned int size = zone->uz_size;

  debugf("Allocating %u bytes in %s. zone='%s' (%s:%d) ", 
      size, __FUNCTION__,
      zone->uz_name,
      __FILE__,__LINE__);

  m = (unsigned char *)malloc(size + 4, 0, flags);
  m += 4;
  sim_assert(m);

  debugf("= %p\n", m);

  if(zone->uz_init)
    zone->uz_init(m, size, flags);
  if(zone->uz_ctor)
    zone->uz_ctor(m, size, udata, flags);
  if(flags & M_ZERO)
    bzero(m, size);

  return m;
}

u_int32_t *uma_find_refcnt(uma_zone_t zone, void *item)
{
  unsigned char *m = (unsigned char *)item;
  return (u_int32_t *)(m - 4);
}

void
uma_zone_set_allocf(uma_zone_t zone, uma_alloc allocf)
{
  return;
}

int
uma_zone_set_max(uma_zone_t zone, int nitems)
{
  return nitems;
}

int
uma_zone_exhausted_nolock(uma_zone_t zone)
{
  return 0;
}

void
uma_zone_set_warning(uma_zone_t zone, const char *warning)
{
  zone->uz_warning = warning;
}

/*
 * General routine to allocate a hash table.
 */
void *hashinit(int elements, struct malloc_type *type, u_long *hashmask)
{
  long hashsize;
  LIST_HEAD(generic, generic) *hashtbl;
  int i;

  if (elements <= 0)
    panic("hashinit: bad elements");
  for (hashsize = 1; hashsize <= elements; hashsize <<= 1)
    continue;
  hashsize >>= 1;
  hashtbl = malloc((u_long)hashsize * sizeof(*hashtbl), type, M_WAITOK);
  for (i = 0; i < hashsize; i++)
    LIST_INIT(&hashtbl[i]);
  *hashmask = hashsize - 1;
  return (hashtbl);
}

/*
 * ldisc_register: Register a line discipline.
 *
 * discipline: Index for discipline to load, or LDISC_LOAD for us to choose.
 * linesw_p:   Pointer to linesw_p.
 *
 * Returns: Index used or -1 on failure.
 */
int ldisc_register(int discipline, struct linesw *linesw_p)
{
  UNIMPLEMENED_NOASSERT();
  return (int)-1;
}

/*
 * Compute number of ticks in the specified amount of time.
 */
int tvtohz(struct timeval *tv)
{
  register unsigned long ticks;
  register long sec, usec;

  /*
   * If the number of usecs in the whole seconds part of the time
   * difference fits in a long, then the total number of usecs will
   * fit in an unsigned long.  Compute the total and convert it to
   * ticks, rounding up and adding 1 to allow for the current tick
   * to expire.  Rounding also depends on unsigned long arithmetic
   * to avoid overflow.
   *
   * Otherwise, if the number of ticks in the whole seconds part of
   * the time difference fits in a long, then convert the parts to
   * ticks separately and add, using similar rounding methods and
   * overflow avoidance.  This method would work in the previous
   * case but it is slightly slower and assumes that hz is integral.
   *
   * Otherwise, round the time difference down to the maximum
   * representable value.
   *
   * If ints have 32 bits, then the maximum value for any timeout in
   * 10ms ticks is 248 days.
   */
  sec = tv->tv_sec;
  usec = tv->tv_usec;
  if (usec < 0) {
    sec--;
    usec += 1000000;
  }
  if (sec < 0) {
#ifdef DIAGNOSTIC
    if (usec > 0) {
      sec++;
      usec -= 1000000;
    }
    printf("tvotohz: negative time difference %ld sec %ld usec\n",
        sec, usec);
#endif
    ticks = 1;
  } else if (sec <= LONG_MAX / 1000000)
    ticks = (sec * 1000000 + (unsigned long)usec + (tick - 1))
      / tick + 1;
  else if (sec <= LONG_MAX / hz)
    ticks = sec * hz
      + ((unsigned long)usec + (tick - 1)) / tick + 1;
  else
    ticks = LONG_MAX;
  if (ticks > INT_MAX)
    ticks = INT_MAX;
  return ((int)ticks);
}


extern void sim_softirq_wakeup (void);

/*
 * Make all processes sleeping on the specified identifier runnable.
 */
void wakeup(register void *ident)
{
  sim_softirq_wakeup ();
}

/*
 * Make a process sleeping on the specified identifier runnable.
 * May wake more than one process if a target process is currently
 * swapped out.
 */
void wakeup_one(register void *ident)
{
  sim_softirq_wakeup ();
}

vm_offset_t kmem_malloc(vm_map_t map, vm_size_t size, int flags)
{
  vm_offset_t ptr;
  UNIMPLEMENED_NOASSERT();

  ptr = (vm_offset_t)malloc(size, 0, flags);

  return ptr;
}

void timer_expire(void *cc)
{
  struct callout *c = (struct callout *)cc;

  c->c_flags &= ~CALLOUT_PENDING;

  if(c->c_func) {
    c->c_func(c->c_arg);
  }
}

// --------------------------------------------------------------------------
// All functions below are non-void empty stubs, returning 0
// --------------------------------------------------------------------------

const struct ah_algorithm *ah_algorithm_lookup(int idx)
{
  UNIMPLEMENED_NOASSERT();
  return 0;
}

/*
 * compute AH header size.
 * transport mode only.  for tunnel mode, we should implement
 * virtual interface, and control MTU/MSS by the interface MTU.
 */
size_t ah_hdrsiz(struct ipsecrequest *isr)
{
  UNIMPLEMENED_NOASSERT();
  return 0;
}

/*
 * Fill in the Authentication Header and calculate checksum.
 */
int ah6_output(struct mbuf *m, u_char *nexthdrp, struct mbuf *md,
    struct ipsecrequest *isr)
{
  UNIMPLEMENED_NOASSERT();
  return 0;
}

/*
 * Modify the packet so that it includes the authentication data.
 * The mbuf passed must start with IPv4 header.
 *
 * assumes that the first mbuf contains IPv4 header + option only.
 * the function does not modify m.
 */
int ah4_output(struct mbuf *m, struct ipsecrequest *isr)
{
  UNIMPLEMENED_NOASSERT();
  return 0;
}

/*
 * Create a kernel process/thread/whatever.  It shares its address space
 * with proc0 - ie: kernel only.
 *
 * func is the function to start.
 * arg is the parameter to pass to function on first startup.
 * newpp is the return value pointing to the thread's struct proc.
 * flags are flags to fork1 (in unistd.h)
 * fmt and following will be *printf'd into (*newpp)->p_comm (for ps, etc.).
 */
int kthread_create(void (*func)(void *), void *arg,
    struct proc **newpp, int flags, int pages, const char *fmt, ...)
{
  UNIMPLEMENED_NOASSERT();
  return 0;
}


int ttykqfilter(struct cdev *dev, struct knote *kn)
{
  UNIMPLEMENED_NOASSERT();
  return 0;
}

int ttywrite(struct cdev *dev, struct uio *uio, int flag)
{
  UNIMPLEMENED_NOASSERT();
  return 0;
}

int ttyread(struct cdev *dev, struct uio *uio, int flag)
{
  UNIMPLEMENED_NOASSERT();
  return 0;
}

int ttypoll(struct cdev *dev, int events, struct thread *td)
{
  UNIMPLEMENED_NOASSERT();
  return 0;
}

int ttyioctl(struct cdev *dev, u_long cmd, caddr_t data, int flag, 
    struct thread *td)       
{
  UNIMPLEMENED_NOASSERT();
  return 0;   
}

/*
 * Return the current (soft) limit for a particular system resource.
 * The which parameter which specifies the index into the rlimit array
 */
rlim_t lim_cur(struct proc *p, int which)
{
  return RLIM_INFINITY;
}

int namei(struct nameidata *ndp)
{
  UNIMPLEMENED_NOASSERT();
  return 0;
}


int change_dir(struct vnode *vp, struct thread *td)
{
  UNIMPLEMENED_NOASSERT();
  return 0;
}

int change_root(struct vnode *vp, struct thread *td)
{
  UNIMPLEMENED_NOASSERT();
  return 0;
}

int securelevel_gt(struct ucred *cr, int level)
{
  UNIMPLEMENED_NOASSERT();
  return 0;
}

int useracc(void *a, int b, int c)
{
  UNIMPLEMENED_NOASSERT();
  return 0;
}

int vslock(void *a, size_t b)
{
  UNIMPLEMENED_NOASSERT();
  return 0;
}

/*-
 * Determine if u1 "can see" the subject specified by u2.
 * Returns: 0 for permitted, an errno value otherwise
 * Locks: none
 * References: *u1 and *u2 must not change during the call
 *             u1 may equal u2, in which case only one reference is required
 */
int cr_cansee(struct ucred *u1, struct ucred *u2)
{
  UNIMPLEMENED_NOASSERT();
  return 0;
}

/*
 * The important part of mtx_trylock{,_flags}()
 * Tries to acquire lock `m.' We do NOT handle recursion here.  If this
 * function is called on a recursed mutex, it will return failure and
 * will not recursively acquire the lock.  You are expected to know what
 * you are doing.
 */
int _mtx_trylock(struct mtx *m, int opts, const char *file, int line)
{
  // XXX: What is reasonable to return here?
  // Kinda hard to figure out, it is the result of _obtain_lock which
  // is just a list of some assembler. Lovely.
  return 1;
}
// --------------------------------------------------------------------------
// All functions below are empty stubs, returning void
// --------------------------------------------------------------------------

void
_mtx_lock_spin(struct mtx *m, uintptr_t tid, int opts, const char *file,
    int line)
{
  return;
}

void mtx_sysinit(void *arg)
{
  return;
}

void
_mtx_init(volatile uintptr_t *c, const char *name, const char *type, int opts)
{
  return;
}

void
_mtx_destroy(volatile uintptr_t *c)
{
  return;
}

void
__mtx_lock_flags(volatile uintptr_t *c, int opts, const char *file, int line)
{
  return;
}

void
__mtx_unlock_flags(volatile uintptr_t *c, int opts, const char *file, int line)
{
  return;
}

void
__mtx_assert(const volatile uintptr_t *c, int what, const char *file, int line)
{
  return;
}

/* kern_rwlock.c */
void
_rw_init_flags(volatile uintptr_t *c, const char *name, int opts)
{
  return;
}

void
_rw_destroy(volatile uintptr_t *c)
{
  return;
}

void
rw_sysinit(void *arg)
{
  return;
}

void
__rw_rlock(volatile uintptr_t *c, const char *file, int line)
{
  return;
}

void
_rw_runlock_cookie(volatile uintptr_t *c, const char *file, int line)
{
  return;
}

void
_rw_wlock_cookie(volatile uintptr_t *c, const char *file, int line)
{
  return;
}

void
_rw_wunlock_cookie(volatile uintptr_t *c, const char *file, int line)
{
  return;
}

void
__rw_assert(const volatile uintptr_t *c, int what, const char *file, int line)
{
  return;
}

int
__rw_try_wlock(volatile uintptr_t *c, const char *file, int line)
{
  return 1;
}

/* kern_rmlock */
void
rm_init(struct rmlock *rm, const char *name)
{
  return;
}

void
rm_init_flags(struct rmlock *rm, const char *name, int opts)
{
  return;
}

void
_rm_wlock_debug(struct rmlock *rm, const char *file, int line)
{
  return;
}

void
_rm_wunlock_debug(struct rmlock *rm, const char *file, int line)
{
  return;
}

/* kern_mutex.c */
void
mutex_init(void)
{
  return;
}

int
witness_warn(int flags, struct lock_object *lock, const char *fmt, ...)
{
  return 0;
}

void disk_dev_synth(dev_t dev)
{
  UNIMPLEMENED_NOASSERT();
}

/*
 * Signal a condition variable, wakes up one waiting thread.  Will also wakeup
 * the swapper if the process is not in memory, so that it can bring the
 * sleeping process in.  Note that this may also result in additional threads
 * being made runnable.  Should be called with the same mutex as was passed to
 * cv_wait held.
 */
void cv_signal(struct cv *cvp)
{
  UNIMPLEMENED_NOASSERT();
}

/*
 * Initialize a condition variable.  Must be called before use.
 */
void cv_init(struct cv *cvp, const char *desc)
{
  UNIMPLEMENED_NOASSERT();
}

void critical_exit(void)
{
  return;
}

/* Critical sections that prevent preemption. */
void critical_enter(void)
{
  return;
}

/*
 * Free a cred structure.
 * Throws away space when ref count gets to 0.
 */
void crfree(struct ucred *cr)
{
  return;
}

void biofinish(struct bio *bp, struct devstat *stat, int error)
{
  UNIMPLEMENED_NOASSERT();
}


void revoke_and_destroy_dev(dev_t dev)
{
  UNIMPLEMENED_NOASSERT();
}

void vsunlock(void *a, size_t b)
{
  UNIMPLEMENED_NOASSERT();
}

void tunable_int_init(void *data)
{
}

void tunable_ulong_init(void *data)
{
}

/* kern_sx.c */
void
sx_sysinit(void *arg)
{
  return;
}

void
sx_init_flags(struct sx *sx, const char *description, int opts)
{
  return;
}

void
sx_destroy(struct sx *sx)
{
  return;
}

int
_sx_slock(struct sx *sx, int opts, const char *file, int line)
{
  return 0;
}

int
_sx_xlock(struct sx *sx, int opts, const char *file, int line)
{
  return 0;
}

void _sx_sunlock(struct sx *sx, const char *file, int line)
{
  return;
}

void _sx_xunlock(struct sx *sx, const char *file, int line)
{
  return;
}
void
_sx_assert(const struct sx *sx, int what, const char *file, int line)
{
  return;
}

void
timekeep_push_vdso(void)
{
  return;
}


#if 0
int knlist_empty(struct knlist *knl)
{
  UNIMPLEMENED_NOASSERT();
  return 0;
}
void
knlist_init(struct knlist *knl, void *lock, void (*kl_lock)(void *),
    void (*kl_unlock)(void *),
    void (*kl_assert_locked)(void *), void (*kl_assert_unlocked)(void *))
{
  SLIST_INIT(&knl->kl_list);
}
void
knlist_init_mtx(struct knlist *knl, struct mtx *lock)
{

  knlist_init(knl, lock, NULL, NULL, NULL, NULL);
}

void vrele(struct vnode *vp)
{
  UNIMPLEMENED_NOASSERT();
}

void cv_broadcastpri(struct cv *cvp, int pri)
{
  UNIMPLEMENED_NOASSERT();
}

void knlist_cleardel(struct knlist *knl, struct thread *td,
    int islocked, int killkn)
{
  UNIMPLEMENED_NOASSERT();
}

void knlist_destroy(struct knlist *knl)
{
  UNIMPLEMENED_NOASSERT();
}


/*
 * remove all knotes from a specified klist
 */
void knlist_remove(struct knlist *knl, struct knote *kn, int islocked)
{
  UNIMPLEMENED_NOASSERT();
}

/*
 * remove knote from a specified klist while in f_event handler.
 */
void knlist_remove_inevent(struct knlist *knl, struct knote *kn)
{
  UNIMPLEMENED_NOASSERT();
}
/*
 * add a knote to a knlist
 */
void knlist_add(struct knlist *knl, struct knote *kn, int islocked)
{
  UNIMPLEMENED_NOASSERT();
}
/*
 * walk down a list of knotes, activating them if their event has triggered.
 */
void knote(struct knlist *list, long hint, int islocked)
{
  UNIMPLEMENED_NOASSERT();
}
#endif

void setsugid(struct proc *p)
{
  UNIMPLEMENED_NOASSERT();
}

/*
 * Transform the running time and tick information in proc p into user,
 * system, and interrupt time usage.
 */
void
calcru(struct proc *p, struct timeval *up, struct timeval *sp)
{
  UNIMPLEMENED_NOASSERT();
}

/*
 * Write system time back to RTC
 */
void resettodr()
{
  UNIMPLEMENED_NOASSERT();
}

void NDFREE(struct nameidata *a, const u_int b)
{
  UNIMPLEMENED_NOASSERT();
}

void BF_ecb_encrypt(const unsigned char *in, unsigned char *out,
	     BF_KEY *key, int encrypt)
{
  UNIMPLEMENED_NOASSERT();
}


/* Wake up a selecting thread, and set its priority. */
void selwakeuppri(struct selinfo *sip, int pri)
{
  return;
}

void
seldrain(struct selinfo *sip)
{
  return;
}

void malloc_uninit(void *data)
{
  UNIMPLEMENED_NOASSERT();
}

void malloc_init(void *data)
{
  return;
}

/*
 * If sigio is on the list associated with a process or process group,
 * disable signalling from the device, remove sigio from the list and
 * free sigio.
 */
void funsetown(struct sigio **sigiop)
{
  return;
}

void *
malloc(unsigned long size, struct malloc_type *mtp, int flags)
{
  void *ptr = sim_malloc (size);

  if (flags & M_ZERO)
    {
      bzero(ptr, size);
    }

  return ptr;
}

void 
free(void *buffer, struct malloc_type *type)
{
  if (buffer)
    sim_free (buffer);
}

int
priv_check(struct thread *td, int priv)
{
  /* always granted */
  return 0;
}

int
vop_panic(struct vop_generic_args *ap)
{
  panic("filesystem goof: vop_panic[%s]", ap->a_desc->vdesc_name);
}

#define ADDCARRY(x)  (x > 65535 ? x -= 65535 : x)
#define REDUCE32							  \
    {									  \
	q_util.q = sum;							  \
	sum = q_util.s[0] + q_util.s[1] + q_util.s[2] + q_util.s[3];	  \
    }
#define REDUCE16							  \
    {									  \
	q_util.q = sum;							  \
	l_util.l = q_util.s[0] + q_util.s[1] + q_util.s[2] + q_util.s[3]; \
	sum = l_util.s[0] + l_util.s[1];				  \
	ADDCARRY(sum);							  \
    }
union l_util {
	u_int16_t s[2];
	u_int32_t l;
};
union q_util {
	u_int16_t s[4];
	u_int32_t l[2];
	u_int64_t q;
};
u_short
in_pseudo(u_int32_t a, u_int32_t b, u_int32_t c)
{
	u_int64_t sum;
	union q_util q_util;
	union l_util l_util;
		    
	sum = (u_int64_t) a + b + c;
	REDUCE16;
	return (sum);
}

static const u_int32_t in_masks[] = {
	/*0 bytes*/ /*1 byte*/	/*2 bytes*/ /*3 bytes*/
	0x00000000, 0x000000FF, 0x0000FFFF, 0x00FFFFFF,	/* offset 0 */
	0x00000000, 0x0000FF00, 0x00FFFF00, 0xFFFFFF00,	/* offset 1 */
	0x00000000, 0x00FF0000, 0xFFFF0000, 0xFFFF0000,	/* offset 2 */
	0x00000000, 0xFF000000, 0xFF000000, 0xFF000000,	/* offset 3 */
};
static u_int64_t
in_cksumdata(const u_int32_t *lw, int len)
{
	u_int64_t sum = 0;
	u_int64_t prefilled;
	int offset;
	union q_util q_util;

	if ((3 & (long) lw) == 0 && len == 20) {
	     sum = (u_int64_t) lw[0] + lw[1] + lw[2] + lw[3] + lw[4];
	     REDUCE32;
	     return sum;
	}

	if ((offset = 3 & (long) lw) != 0) {
		const u_int32_t *masks = in_masks + (offset << 2);
		lw = (u_int32_t *) (((long) lw) - offset);
		sum = *lw++ & masks[len >= 3 ? 3 : len];
		len -= 4 - offset;
		if (len <= 0) {
			REDUCE32;
			return sum;
		}
	}
#if 0
	/*
	 * Force to cache line boundary.
	 */
	offset = 32 - (0x1f & (long) lw);
	if (offset < 32 && len > offset) {
		len -= offset;
		if (4 & offset) {
			sum += (u_int64_t) lw[0];
			lw += 1;
		}
		if (8 & offset) {
			sum += (u_int64_t) lw[0] + lw[1];
			lw += 2;
		}
		if (16 & offset) {
			sum += (u_int64_t) lw[0] + lw[1] + lw[2] + lw[3];
			lw += 4;
		}
	}
#endif
	/*
	 * access prefilling to start load of next cache line.
	 * then add current cache line
	 * save result of prefilling for loop iteration.
	 */
	prefilled = lw[0];
	while ((len -= 32) >= 4) {
		u_int64_t prefilling = lw[8];
		sum += prefilled + lw[1] + lw[2] + lw[3]
			+ lw[4] + lw[5] + lw[6] + lw[7];
		lw += 8;
		prefilled = prefilling;
	}
	if (len >= 0) {
		sum += prefilled + lw[1] + lw[2] + lw[3]
			+ lw[4] + lw[5] + lw[6] + lw[7];
		lw += 8;
	} else {
		len += 32;
	}
	while ((len -= 16) >= 0) {
		sum += (u_int64_t) lw[0] + lw[1] + lw[2] + lw[3];
		lw += 4;
	}
	len += 16;
	while ((len -= 4) >= 0) {
		sum += (u_int64_t) *lw++;
	}
	len += 4;
	if (len > 0)
		sum += (u_int64_t) (in_masks[len] & *lw);
	REDUCE32;
	return sum;
}

u_short
in_cksum_skip(struct mbuf *m, int len, int skip)
{
	u_int64_t sum = 0;
	int mlen = 0;
	int clen = 0;
	caddr_t addr;
	union q_util q_util;
	union l_util l_util;

        len -= skip;
        for (; skip && m; m = m->m_next) {
                if (m->m_len > skip) {
                        mlen = m->m_len - skip;
			addr = mtod(m, caddr_t) + skip;
                        goto skip_start;
                } else {
                        skip -= m->m_len;
                }
        }

	for (; m && len; m = m->m_next) {
		if (m->m_len == 0)
			continue;
		mlen = m->m_len;
		addr = mtod(m, caddr_t);
skip_start:
		if (len < mlen)
			mlen = len;
		if ((clen ^ (long) addr) & 1)
		    sum += in_cksumdata((const u_int32_t *)addr, mlen) << 8;
		else
		    sum += in_cksumdata((const u_int32_t *)addr, mlen);

		clen += mlen;
		len -= mlen;
	}
	REDUCE16;
	return (~sum & 0xffff);
}

#if 1
static const u_int32_t uma_junk = 0xdeadc0de;
int
trash_ctor(void *mem, int size, void *arg, int flags)
{
	int cnt;
	u_int32_t *p;

	cnt = size / sizeof(uma_junk);

	for (p = mem; cnt > 0; cnt--, p++)
		if (*p != uma_junk) {
			printf("Memory modified after free %p(%d) val=%x @ %p\n",
			    mem, size, *p, p);
			return (0);
		}
	return (0);
}

/*
 * Fills an item with predictable garbage
 *
 * Complies with standard dtor arg/return
 *
 */
void
trash_dtor(void *mem, int size, void *arg)
{
	int cnt;
	u_int32_t *p;

	cnt = size / sizeof(uma_junk);

	for (p = mem; cnt > 0; cnt--, p++)
		*p = uma_junk;
}
int
trash_init(void *mem, int size, int flags)
{
  trash_dtor(mem, size, NULL);
	return (0);
}

/*
 * Checks an item to make sure it hasn't been overwritten since it was freed.
 *
 * Complies with standard fini arg/return
 *
 */
void
trash_fini(void *mem, int size)
{
  (void)trash_ctor(mem, size, NULL, 0);
  return;
}
#endif

int
priv_check_cred(struct ucred *cred, int priv, int flags)
{
  return 0;
}

int
vn_chmod(struct file *fp, mode_t mode, struct ucred *active_cred,
    struct thread *td)
{
  return 0;
}

void
spinlock_enter(void)
{
  struct thread *td;
  int intr;

  td = curthread;
  if (td->td_md.md_spinlock_count == 0) {
    intr = intr_disable();
    td->td_md.md_spinlock_count = 1;
  } else
    td->td_md.md_spinlock_count++;
  critical_enter();
}

void
spinlock_exit(void)
{
  struct thread *td;

  td = curthread;
  critical_exit();
  td->td_md.md_spinlock_count--;
}

void
stack_save(struct stack *st)
{
  return;
}

void
kdb_backtrace(void)
{
  return;
}

int
db_printf(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  (void)vprintf(fmt, ap);
  va_end(ap);
  return (int)0;
}

void
db_command_register(struct command_table *list, struct command *cmd)
{
}

void
p31b_setcfg(int num, int value)
{
}

int	atomic_cmpset_long(volatile u_long *dst, u_long expect, u_long src)
{
  int ret;
	
  if (*dst == expect) {
    *dst = src;
    ret = 1;
  } else {
    ret = 0;
  }
  return (ret);
}
int	atomic_cmpset_int(volatile u_int *dst, u_int expect, u_int src)
{
  int ret;
	
  if (*dst == expect) {
    *dst = src;
    ret = 1;
  } else {
    ret = 0;
  }
  return (ret);
}


u_int	atomic_fetchadd_int(volatile u_int *p, u_int v)
{
  u_int value;

  value = *p;
  *p += v;
  return (value);
}
u_long	atomic_fetchadd_long(volatile u_long *p, u_long v)
{
  u_long value;

  value = *p;
  *p += v;
  return (value);
}

void
atomic_store_rel_int(volatile uint32_t *dst, uint32_t src)
{
  *dst = src;
}

void
atomic_add_barr_int(volatile u_int32_t *p, u_int32_t val)
{
  *p += val;
}


u_long
atomic_cmpset_acq_ptr(volatile u_long *p, volatile u_long cmpval, volatile u_long newval)
{
  return atomic_cmpset_long (p, cmpval, newval);
}

void
atomic_set_32(volatile uint32_t *address, uint32_t setmask)
{
  *address |= setmask;
}

struct fileops vnops;
struct fileops badfileops;

void
vfs_timestamp(struct timespec *tsp)
{
  return;
  sim_assert (false);
}

int
vfs_modevent(module_t mod, int type, void *data)
{
  return 0;
}

struct vop_vector default_vnodeops;

int
vn_chown(struct file *fp, uid_t uid, gid_t gid, struct ucred *active_cred,
    struct thread *td)
{
  return 0;
}

int
invfo_chmod(struct file *fp, mode_t mode, struct ucred *active_cred,
    struct thread *td)
{
	return (EINVAL);
}

int
invfo_chown(struct file *fp, uid_t uid, gid_t gid, struct ucred *active_cred,
    struct thread *td)
{
	return (EINVAL);
}

void
devctl_notify(const char *system, const char *subsystem, const char *type,
    const char *data)
{
  return;
}
