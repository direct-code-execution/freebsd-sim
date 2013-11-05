#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/callout.h>
#include <sys/condvar.h>
#include <sys/interrupt.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/sdt.h>
#include <sys/sleepqueue.h>
#include <sys/sysctl.h>
#include "sim-assert.h"
#include "sim.h"


struct callout_list g_expired_events;
struct callout_list g_pending_events;

static void run_timer_softirq(void *args)
{
  while (!SLIST_EMPTY(&g_expired_events))
    {
      struct callout *c = SLIST_FIRST(&g_expired_events);
      void (*fn)(void *);
      void *data;
      fn = c->c_func;
      data = c->c_arg;
      sim_assert (c->c_lock == 0);
      SLIST_REMOVE(&g_expired_events, c, callout, c_links.sle);
      fn (data);
    }
  sim_task_wait ();
}

static void ensure_softirq_opened (void)
{
  static bool opened = false;
  if (opened)
    {
      return;
    }
  opened = true;
  swi_add(NULL, "clock", run_timer_softirq, NULL, SWI_CLOCK, 0, NULL);
}
static void timer_trampoline (void *context)
{
  ensure_softirq_opened ();
  struct callout *c = context;
  c->c_lock = 0;
  c->c_flags &= ~CALLOUT_PENDING;
  SLIST_REMOVE(&g_pending_events, c, callout, c_links.sle);
  SLIST_INSERT_HEAD(&g_expired_events, c, c_links.sle);
  sim_softirq_wakeup ();
  //  raise_softirq (TIMER_SOFTIRQ);
}

int
callout_reset_on(struct callout *c, int to_ticks, void (*ftn)(void *),
    void *arg, int cpu)
{
  if (c->c_flags & CALLOUT_PENDING)
    {
      c->c_flags &= ~CALLOUT_PENDING;
      SLIST_REMOVE(&g_pending_events, c, callout, c_links.sle);
      sim_event_cancel (c->c_lock);
      c->c_lock = 0;
    }

  if (to_ticks <= 0)
    to_ticks = 1;
  c->c_arg = arg;
  c->c_flags |= (CALLOUT_ACTIVE | CALLOUT_PENDING);
  c->c_func = ftn;
  c->c_time = ticks + to_ticks;

  __u64 delay_ns = 0;
  delay_ns = (__u64) to_ticks * (1000000000/hz);
  //  delay_ns = ((__u64) c->c_time * (1000000000/hz)) - sim_current_ns ();

  void *event = sim_event_schedule_ns (delay_ns, &timer_trampoline, c);

  // store the external event in the base field
  // to be able to retrieve it from del_timer
  c->c_lock = event;
  // finally, store timer in list of pending events.
  SLIST_INSERT_HEAD(&g_pending_events, c, c_links.sle);

#if 0
  debugf("%sscheduled %p func %p arg %p in %d\n",
         "", c, c->c_func, c->c_arg, to_ticks);
#endif
  return (0);
}

int
_callout_stop_safe(struct callout *c, int safe)
{
  int retval = 1;

  if (c->c_lock != 0)
    {
      sim_event_cancel (c->c_lock);
      retval = 1;
    }
  else
    {
      retval = 0;
    }
  /* XXX */
  if (c->c_flags & CALLOUT_PENDING)
    {
      SLIST_REMOVE(&g_pending_events, c, callout, c_links.sle);
      c->c_flags &= ~CALLOUT_PENDING;
    }

  debugf("cancelled %p func %p arg %p\n",
         c, c->c_func, c->c_arg);

  return (retval);
}


int
callout_schedule(struct callout *c, int to_ticks)
{
  return callout_reset_on(c, to_ticks, c->c_func, c->c_arg, c->c_cpu);
}

void
callout_init(struct callout *c, int mpsafe)
{
  bzero(c, sizeof *c);
}

void
_callout_init_lock(struct callout *c, 
                   struct lock_object *lock,
                   int flags)
{
  callout_init (c, 0);
}
