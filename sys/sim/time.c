#include <sys/errno.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/sdt.h>
#include <sys/queue.h>
#include <sys/stddef.h>
#include "sim.h"
#include "sim-assert.h"

// kern/kern_clock.c
long tk_nin;

#define HZ hz

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

struct sleep_barrier {
  void *ident;
  void *event;
  struct SimTask      *waiter;
  LIST_ENTRY(sleep_barrier) entries;
};

static LIST_HEAD(sleep_barrier_list, sleep_barrier) g_sleep_events = 
  LIST_HEAD_INITIALIZER(&sleep_barrier_list);

void msleep_trampoline (void *context)
{
  struct sleep_barrier *barr = context;
  struct SimTask *task = barr->waiter;
  sim_task_wakeup (task);
  sim_free (barr);
}

int
_sleep(void *ident, struct lock_object *lock, int priority,
    const char *wmesg, sbintime_t sbt, sbintime_t pr, int flags)
{
  struct sleep_barrier *barr = sim_malloc (sizeof (struct sleep_barrier));
  sim_memset (barr, 0, sizeof (struct sleep_barrier));
  barr->ident = ident;
  barr->waiter = sim_task_current ();

  if (sbt)
    {
      barr->event = sim_event_schedule_ns (((__u64) sbt) * (1000000000/HZ),
                                           &msleep_trampoline, barr);
    }

  LIST_INSERT_HEAD(&g_sleep_events, barr, entries);
  sim_task_wait ();
  return 0;
}

/*
 * Make all processes sleeping on the specified identifier runnable.
 */
void wakeup(register void *ident)
{
  struct sleep_barrier *barr = NULL;

  LIST_FOREACH(barr, &g_sleep_events, entries)
    if (barr->ident == ident)
      {
        break;
      }

  if (!barr)
    return;

  LIST_REMOVE(barr, entries);

  if (barr->event)
    sim_event_cancel (barr->event);

  sim_task_wakeup (barr->waiter);
  //sim_free (barr);
}

/*
 * Make a process sleeping on the specified identifier runnable.
 * May wake more than one process if a target process is currently
 * swapped out.
 */
void wakeup_one(register void *ident)
{
  wakeup (ident);
}
