#include <machine/stdarg.h>
#include <sys/types.h>
#include "sim.h"
#include "sim-assert.h"


int printf(const char * fmt, ...)
{
  va_list args;
  va_start (args, fmt);
  int value = sim_vprintf (fmt, args);
  va_end (args);
  return value;
}

void panic(const char * fmt, ...)
{
  va_list args;
  va_start (args, fmt);
  sim_vprintf (fmt, args);
  va_end (args);  
  sim_assert (false);
  while (true) {} // quiet compiler
}

void warn_slowpath_fmt(const char *file, int line, const char *fmt, ...)
{
  printf ("%s:%d -- ", file, line);
  va_list args;
  va_start (args, fmt);
  sim_vprintf (fmt, args);
  va_end (args);  
}

void warn_slowpath_null(const char *file, int line)
{
  printf ("%s:%d -- ", file, line);
}

int debugf(const char *fmt, ...)
{
  va_list args;

  va_start(args, fmt);
  int value = sim_vprintf (fmt, args);
  va_end(args);

  return value;
}

void sim_printf(const char *str, ...)
{
  va_list args;
  va_start (args, str);
  sim_vprintf (str, args);
  va_end (args);
}

