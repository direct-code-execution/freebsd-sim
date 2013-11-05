//#include <linux/time.h>
#include <sys/errno.h>
//#include <linux/timex.h>
//#include <linux/ktime.h>
#include "sim.h"
#include "sim-assert.h"

// kern/kern_clock.c
long tk_nin;
int ticks;

#define HZ 100

// accessed from wrap_clock from do_sys_settimeofday. We don't call the latter
// so we should never access this variable.
struct timespec wall_to_monotonic;

uint64_t ns_to_ticks (uint64_t ns)
{
  ns /=  (1000000000 / HZ);
  return ns;
}

void sim_update_ticks (void)
{
  ticks = ns_to_ticks (sim_current_ns ());
}


void do_gettimeofday(struct timeval *tv)
{
  u64 ns = sim_current_ns ();
  tv->tv_sec = (ns / 1000000000);
  tv->tv_usec = (ns % 1000000000) / 1000;
}

int do_settimeofday(struct timespec *tv)
{
  sim_assert (false);
  return -EPERM; // quiet compiler
}
unsigned long get_seconds(void)
{
  u64 ns = sim_current_ns ();
  ns /= 1000000000;
  return ns;
}
static unsigned long 
round_ticks_common(unsigned long j,
		     bool force_up)
{
  int rem;
  unsigned long original = j;

  rem = j % HZ;
  if (rem < HZ/4 && !force_up) /* round down */
    j = j - rem;
  else /* round up */
    j = j - rem + HZ;
  if (j <= ticks) /* rounding ate our timeout entirely; */
    return original;
  return j;
}
unsigned long round_ticks(unsigned long j)
{
  return round_ticks_common(j, false);
}
unsigned long round_ticks_relative(unsigned long j)
{
  unsigned long j0 = ticks;
  /* Use j0 because ticks might change while we run */
  return round_ticks_common(j + j0, false) - j0;
}
unsigned long round_ticks_up(unsigned long j)
{
  return round_ticks_common(j, true);
}
void msleep_trampoline (void *context)
{
  struct SimTask *task = context;
  sim_task_wakeup (task);
}
void msleep(unsigned int msecs)
{
  sim_event_schedule_ns (((__u64) msecs) * 1000000, &msleep_trampoline, sim_task_current ());
  sim_task_wait ();
}

int
_sleep(void *ident, struct lock_object *lock, int priority,
    const char *wmesg, int timo)
{
  if (timo)
    {
      sim_event_schedule_ns (((__u64) timo) * 1000000/HZ, &msleep_trampoline, sim_task_current ());
    }
  sim_task_wait ();
}

/* FIXME: XXX!!! _sleep/wakeup should be implemented for sbwait like operation */
#if 0
struct sleep_barrier {
  void *indent;
  struct SimTask      *waiter;
};

static void
sleep_function (void *context)
{
  while (true)
    {
      sim_task_wait ();
      while (!list_empty (&g_work))
       {
         struct work_struct *work = list_first_entry(&g_work,
                                                     struct work_struct, entry);
         work_func_t f = work->func;
         __list_del (work->entry.prev, work->entry.next);
         work_clear_pending (work);
         f(work);
       }
    }
}

static struct SimTask *sleep_task (void)
{
  static struct SimTask *g_task = 0;
  if (g_task == 0)
    {
      g_task = sim_task_start (&sleep_function, 0);
    }
  return g_task;
}

/*
 * Make all processes sleeping on the specified identifier runnable.
 */
void wakeup(register void *ident)
{
  struct sleep_barrier *barr = (struct sleep_barrier *)ident;
  sim_task_wakeup (barr->waiter);
}

/*
 * Make a process sleeping on the specified identifier runnable.
 * May wake more than one process if a target process is currently
 * swapped out.
 */
void wakeup_one(register void *ident)
{
  struct sleep_barrier *barr = (struct sleep_barrier *)ident;
  sim_task_wakeup (barr->waiter);
}
#endif
