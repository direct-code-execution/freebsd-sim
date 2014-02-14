#include "linux/capability.h"

struct sock;
struct sk_buff;

int capable(int cap)
{
  switch (cap)
  {
    case CAP_NET_RAW: return 1;

    default: break;
  }

  return 0;
}

int cap_netlink_recv(struct sk_buff *skb, int cap)
{
  return 0;
}

int cap_netlink_send(struct sock *sk, struct sk_buff *skb)
{
  return 0;
}
