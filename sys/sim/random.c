#include "sim.h"

u32 random32(void)
{
  return sim_random ();
}

void get_random_bytes(void *buf, int nbytes)
{
  char *p = (char *)buf;
  int i;
  for (i = 0; i < nbytes; i++)
    {
      p[i] = sim_random ();
    }
}
void srandom32(u32 entropy)
{}

u_int32_t arc4random(void)
{
  return sim_random();
}
