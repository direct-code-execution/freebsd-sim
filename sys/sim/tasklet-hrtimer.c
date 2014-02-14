#include <linux/interrupt.h>
#include "sim-assert.h"
/**
 * tasklet_hrtimer_init - Init a tasklet/hrtimer combo for softirq callbacks
 * @ttimer:      tasklet_hrtimer which is initialized
 * @function:    hrtimer callback funtion which gets called from softirq context
 * @which_clock: clock id (CLOCK_MONOTONIC/CLOCK_REALTIME)
 * @mode:        hrtimer mode (HRTIMER_MODE_ABS/HRTIMER_MODE_REL)
 */
void tasklet_hrtimer_init(struct tasklet_hrtimer *ttimer,
                          enum hrtimer_restart (*function)(struct hrtimer *),
                          clockid_t which_clock, enum hrtimer_mode mode)
{
  sim_assert (false);
#if 0
  hrtimer_init(&ttimer->timer, which_clock, mode);
  ttimer->timer.function = __hrtimer_tasklet_trampoline;
  tasklet_init(&ttimer->tasklet, __tasklet_hrtimer_trampoline,
	       (unsigned long)ttimer);
  ttimer->function = function;
#endif
}
