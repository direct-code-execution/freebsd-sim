#ifndef SIM_H
#define SIM_H

#include <stdarg.h>
#include <sys/types.h>

#include "sim-types.h"
#include "sim-assert.h"

//typedef __uint64_t __u64;
typedef long long unsigned int __u64;
typedef __uint64_t u64;
typedef __uint32_t u32;


// API called from within linux kernel. Forwards to SimImported.
int sim_vprintf (const char *str, va_list args);
void *sim_malloc (unsigned long size);
void sim_free (void *buffer);
void *sim_memcpy (void *dst, const void *src, unsigned long size);
void *sim_memset (void *dst, char value, unsigned long size);
unsigned long sim_random (void);
void *sim_event_schedule_ns (__u64 ns, void (*fn) (void *context), void *context);
void sim_event_cancel (void *event);
__u64 sim_current_ns (void);

struct SimTask *sim_task_start (void (*callback) (void *), void *context);
void sim_task_wait (void);
void sim_task_yield (void);
struct SimTask *sim_task_current (void);
// returns 1 if task was woken up, 0 if it was already running.
int sim_task_wakeup (struct SimTask *task);

void sim_dev_xmit (struct SimDevice *dev, unsigned char *data, int len);

void sim_signal_raised (struct SimTask *task, int sig);

void sim_poll_event (int flag, void *context);

#endif /* SIM_H */
