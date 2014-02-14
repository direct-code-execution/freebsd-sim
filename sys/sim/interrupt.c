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
#include <sys/param.h>
#include <sys/mac.h>
#include <sys/mbuf.h>
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
#include <sys/taskqueue.h>

#include <machine/stdarg.h>

#include "sim.h"

static struct SimTask *g_softirq_task = 0;
static int g_n_raises = 0;
static TAILQ_HEAD(, intr_event) event_list =
    TAILQ_HEAD_INITIALIZER(event_list);
void do_softirq (void);

void sim_softirq_wakeup (void)
{
  g_n_raises++;
  sim_task_wakeup (g_softirq_task);
}

static void softirq_task_function (void *context)
{
  while (true)
    {
      do_softirq ();
      g_n_raises--;
      if (g_n_raises < 0)
        {
          g_n_raises = 0;
          sim_task_wait ();
        }
    }
}

static void ensure_task_created (void)
{
  if (g_softirq_task != 0)
    {
      return;
    }
  g_softirq_task = sim_task_start (&softirq_task_function, 0);
}

/** Used to add a software interrupt. Currently looks for the call that sets
 * up the network software interrupt and sets that one interrupt up. Ignores
 * any other call. */
int
swi_add(struct intr_event **eventp, const char *name, driver_intr_t handler,
            void *arg, int pri, enum intr_type flags, void **cookiep)
{

  if (strncmp (name, "net", 3) &&
      strncmp (name, "clock", 5))
    return 0;

  ensure_task_created ();

  struct intr_event *ie;
  struct intr_handler *ih;

  ie = sim_malloc(sizeof(struct intr_event));
  ie->ie_flags = flags;
  ie->ie_irq = 0;
  TAILQ_INIT(&ie->ie_handlers);

  snprintf(ie->ie_name, sizeof(ie->ie_name), "swi%d", pri);
  strlcpy(ie->ie_fullname, ie->ie_name, sizeof(ie->ie_fullname));
  TAILQ_INSERT_TAIL(&event_list, ie, ie_list);

  if (eventp != NULL)
    *eventp = ie;

  ih = sim_malloc(sizeof(struct intr_handler));
  ih->ih_handler = handler;
  ih->ih_argument = arg;
  strlcpy(ih->ih_name, name, sizeof(ih->ih_name));
  TAILQ_INSERT_TAIL(&ie->ie_handlers, ih, ih_next);

    debugf("swi_add: %0x \"%s\" %0x %0x %i %i %0x\n",
            eventp, name, handler, arg, pri, flags, cookiep);

    return 0;
}

void do_softirq (void)
{
  struct intr_handler *ih, *ihn;
  struct intr_event *ie;

  TAILQ_FOREACH(ie, &event_list, ie_list) {
    TAILQ_FOREACH_SAFE(ih, &ie->ie_handlers, ih_next, ihn) {
      /*
       * If this handler is marked for death, remove it from
       * the list of handlers and wake up the sleeper.
       */
      if (ih->ih_flags & IH_DEAD) {
        TAILQ_REMOVE(&ie->ie_handlers, ih, ih_next);
        ih->ih_flags &= ~IH_DEAD;
        continue;
      }

      /* Skip filter only handlers */
      if (ih->ih_handler == NULL)
        continue;

      /*
       * For software interrupt threads, we only execute
       * handlers that have their need flag set.  Hardware
       * interrupt threads always invoke all of their handlers.
       */
      if (ie->ie_flags & IE_SOFT) {
        if (!ih->ih_need)
          continue;
      }

      /* Execute this handler. */
#if 0
      debugf("%s: exec %p(%p) for %s flg=%x\n",
             __func__, (void *)ih->ih_handler, 
             ih->ih_argument, ih->ih_name, ih->ih_flags);
#endif

      ih->ih_handler(ih->ih_argument);
    }
  }
}
