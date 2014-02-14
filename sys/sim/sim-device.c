#include "opt_atalk.h"
#include "opt_inet.h"

#include <sys/param.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/kernel.h>
#include <sys/mac.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/protosw.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_types.h>
#include <net/netisr.h>
#include <net/route.h>
#include <net/bpf.h>
#include <net/bpfdesc.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/if_ether.h>

/* XXX */
#include <net/if.h>
#include <net/if_types.h>
#include <net/if_var.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <net/netisr.h>
#include <net/ethernet.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>
#include <netinet/ip_icmp.h>
#include <machine/in_cksum.h> // I wonder why this is included

#include "sim-init.h"
#include "sim.h"
#include "sim-assert.h"

struct SimDevice
{
  struct ifnet ifp;
  void *priv;
};

/** Initialisation callback function of our fake interface. This does not
 * seem to ever get called. */
void
fake_ether_init(void *vp)
{
  sim_assert(0);
}


/** Callback function called when our fake interface is supposed to output
 * a packet to the wire. At this point we need to tell the simulator a
 * packet is to be sent. */
int
fake_ether_output(struct ifnet *ifp, struct mbuf *m, struct sockaddr *dst,
                  struct route *rt0)
{
  short type;
  int error, hdrcmplt = 0;
  u_char esrc[ETHER_ADDR_LEN], edst[ETHER_ADDR_LEN];
  struct ether_header *eh;
  int loop_copy = 0;
  int hlen;	/* link layer header length */
  struct llentry *lle;

  hlen = ETHER_HDR_LEN;
  switch (dst->sa_family) {
#ifdef INET
  case AF_INET:
    if (!(ifp->if_flags & IFF_NOARP))
      {
        //error = arpresolve(ifp, rt0->ro_rt, m, dst, edst, &lle);
        error = arpresolve(ifp, rt0, m, dst, edst, &lle);
        if (error)
          return (error == EWOULDBLOCK ? 0 : error);
      }
    type = htons(ETHERTYPE_IP);
    break;
  case AF_ARP:
    {
      struct arphdr *ah;
      ah = (struct arphdr *)mtod(m, struct arphdr *);
      ah->ar_hrd = htons(ARPHRD_ETHER);

      loop_copy = -1; /* if this is for us, don't do it */

      switch(ntohs(ah->ar_op)) {
      case ARPOP_REVREQUEST:
      case ARPOP_REVREPLY:
        type = htons(ETHERTYPE_REVARP);
        break;
      case ARPOP_REQUEST:
      case ARPOP_REPLY:
      default:
        type = htons(ETHERTYPE_ARP);
        break;
      }

      if (m->m_flags & M_BCAST)
        bcopy(ifp->if_broadcastaddr, edst, ETHER_ADDR_LEN);
      else
        bcopy(ar_tha(ah), edst, ETHER_ADDR_LEN);

    }
    break;
#endif
#ifdef INET6
  case AF_INET6:
    error = nd6_storelladdr(ifp, rt0, m, dst, (u_char *)edst);
    if (error)
      return error;
    type = htons(ETHERTYPE_IPV6);
    break;
#endif

  default:
    if_printf(ifp, "can't handle af%d\n", dst->sa_family);
    return EAFNOSUPPORT;
  }

  /*
   * Add local net header.  If no space in first mbuf,
   * allocate another.
   */
  M_PREPEND(m, ETHER_HDR_LEN, M_DONTWAIT);
  if (m == NULL)
    return ENOBUFS;
  eh = mtod(m, struct ether_header *);
  (void)memcpy(&eh->ether_type, &type,
               sizeof(eh->ether_type));
  (void)memcpy(eh->ether_dhost, edst, sizeof (edst));
  if (hdrcmplt)
    (void)memcpy(eh->ether_shost, esrc,
                 sizeof(eh->ether_shost));
  else
    {
#ifdef FIXME
    (void)memcpy(eh->ether_shost, IFP2AC(ifp)->ac_enaddr,
                 sizeof(eh->ether_shost));
#endif
    }

  char packetbuf[65535];
  int size = m->m_pkthdr.len;

  // XXX: @TODO: FIXME: this is a function that does a full data copy. It 
  // shouldn't be needed
  m_copydata(m, 0, size, packetbuf);
  sim_dev_xmit ((struct SimDevice *)ifp, (unsigned char *)packetbuf, size);
  m_freem(m);

  sim_softirq_wakeup ();
  return 0;
}

/** The input callback routine of our fake interface. This is called when
 * a packet is received from the wire or whatever. The routine copies the
 * packet into an mbuf and dispatches it to the network stack, which will
 * either process it straight away (likely, might always happen?) or 
 * queue it (unlikely). This function should be called (indirectly) when
 * the simulator has a packet for us. */
void fake_ether_input(struct ifnet *ifp, const void *packetdata, int packetlen)
{
  struct mbuf *m = NULL;
  int size = packetlen;

  MGETHDR(m, M_DONTWAIT, MT_DATA);
  sim_assert(m);

  m->m_len = sizeof(m->M_dat.MH.MH_dat.MH_databuf);
  m->m_pkthdr.len = m->m_len;

  m->m_flags |= M_PKTHDR;
  /* FIXME */
  m->m_pkthdr.csum_flags |= (CSUM_IP_CHECKED|CSUM_IP_VALID|CSUM_DATA_VALID|CSUM_PSEUDO_HDR);
  m->m_pkthdr.csum_data = 0xffff;
  //bcopy(packetdata, m->m_data, packetlen);
  //m->m_len = packetlen;
  //m->m_pkthdr.len = packetlen;
  m->m_pkthdr.rcvif = ifp;

  /* We don't need the entire packet. But the length of the mbuf needs
     to be correct. Hmm. 
     Lets just copy 100 bytes of data for now and see if it works.

     This works... but checksums will be wrong. I think. Hmm...
  */
  //if(size > 100) size = 100;
  m_copyback(m, 0, size, (void *)packetdata);
  // HACK HACK HACK
  //m->m_pkthdr.len = m->m_len = packetlen;

  //fprintf(stderr, "%d] m: %p m_len: %u m_pkthdr.len: %u\n",
  //		get_stack_id(), m, m->m_len, m->m_pkthdr.len);

  // Dispatch tries to send the packet right away, but may also end
  // up enqueing it. netisr_enqueue always enqueues.
  netisr_dispatch(NETISR_ETHER, m);

}

/** This implements the ioctl callback function of our fake ethernet
 * interface. It doesn't do anything, and I don't believe it needs to
 * do anything. */
int
fake_ether_ioctl(
		struct ifnet *ifp,
		u_long cmd,
		caddr_t data)
{
	debugf("fake_ther_ioctl called cmd:%x data:%x\n", cmd, data);
	return 0;
}

#if 0
static netdev_tx_t 
kernel_dev_xmit(struct sk_buff *skb,
		struct net_device *dev)
{
  netif_stop_queue(dev);
  sim_dev_xmit ((struct SimDevice *)dev, skb->data, skb->len);
  dev_kfree_skb(skb);
  netif_wake_queue(dev);
  return 0;
}

static u32 always_on(struct net_device *dev)
{
  return 1;
}


static const struct ethtool_ops sim_ethtool_ops = {
  .get_link               = always_on,
  .get_sg                 = always_on,
};

static const struct net_device_ops sim_dev_ops = {
  .ndo_start_xmit = kernel_dev_xmit,
  .ndo_set_mac_address = eth_mac_addr,

};

static void sim_dev_setup(struct net_device *dev)
{
  dev->mtu                = (16 * 1024) + 20 + 20 + 12;
  dev->hard_header_len    = ETH_HLEN;     /* 14   */
  dev->addr_len           = ETH_ALEN;     /* 6    */
  dev->tx_queue_len       = 0;
  dev->type               = ARPHRD_ETHER;
  dev->flags              = 0; 
  //dev->priv_flags        &= ~IFF_XMIT_DST_RELEASE;
  dev->features           = 0
    | NETIF_F_NO_CSUM
    | NETIF_F_HIGHDMA
    | NETIF_F_NETNS_LOCAL;
  // disabled  NETIF_F_TSO NETIF_F_SG  NETIF_F_FRAGLIST NETIF_F_LLTX
  dev->ethtool_ops        = &sim_ethtool_ops;
  dev->header_ops         = &eth_header_ops;
  dev->netdev_ops         = &sim_dev_ops;
  dev->destructor         = &free_netdev;
}
#endif

static int
new_ifhwioctl(u_long cmd, struct ifnet *ifp, caddr_t data, struct thread *td)
{
	struct ifreq *ifr;
	struct ifstat *ifs;
	int error = 0;
	int new_flags;

	ifr = (struct ifreq *)data;
	switch (cmd) {
	case SIOCGIFINDEX:
		ifr->ifr_index = ifp->if_index;
		break;

	case SIOCGIFFLAGS:
		ifr->ifr_flags = ifp->if_flags & 0xffff;
		ifr->ifr_flagshigh = ifp->if_flags >> 16;
		break;

	case SIOCGIFCAP:
		ifr->ifr_reqcap = ifp->if_capabilities;
		ifr->ifr_curcap = ifp->if_capenable;
		break;

#ifdef MAC
	case SIOCGIFMAC:
		error = mac_ioctl_ifnet_get(td->td_proc->p_ucred, ifr, ifp);
		break;
#endif

	case SIOCGIFMETRIC:
		ifr->ifr_metric = ifp->if_metric;
		break;

	case SIOCGIFMTU:
		ifr->ifr_mtu = ifp->if_mtu;
		break;

	case SIOCGIFPHYS:
		ifr->ifr_phys = ifp->if_physical;
		break;

	case SIOCSIFFLAGS:
		new_flags = (ifr->ifr_flags & 0xffff) |
		    (ifr->ifr_flagshigh << 16);
		if (ifp->if_flags & IFF_SMART) {
			/* Smart drivers twiddle their own routes */
		} else if (ifp->if_flags & IFF_UP &&
		    (new_flags & IFF_UP) == 0) {
			//int s = splimp();
			if_down(ifp);
			//splx(s);
		} else if (new_flags & IFF_UP &&
		    (ifp->if_flags & IFF_UP) == 0) {
			//int s = splimp();
			if_up(ifp);
			//splx(s);
		}
		ifp->if_flags = (ifp->if_flags & IFF_CANTCHANGE) |
			(new_flags &~ IFF_CANTCHANGE);
		if (new_flags & IFF_PPROMISC) {
			/* Permanently promiscuous mode requested */
			ifp->if_flags |= IFF_PROMISC;
		} else if (ifp->if_pcount == 0) {
			ifp->if_flags &= ~IFF_PROMISC;
		}
		if (ifp->if_ioctl)
			(void) (*ifp->if_ioctl)(ifp, cmd, data);
		getmicrotime(&ifp->if_lastchange);
		break;

	case SIOCSIFCAP:
		if (ifr->ifr_reqcap & ~ifp->if_capabilities)
			return (EINVAL);
		(void) (*ifp->if_ioctl)(ifp, cmd, data);
		break;

#ifdef MAC
	case SIOCSIFMAC:
		error = mac_ioctl_ifnet_set(td->td_proc->p_ucred, ifr, ifp);
		break;
#endif

	case SIOCSIFMETRIC:
		ifp->if_metric = ifr->ifr_metric;
		getmicrotime(&ifp->if_lastchange);
		break;

	case SIOCSIFPHYS:
		if (!ifp->if_ioctl)
		        return EOPNOTSUPP;
		error = (*ifp->if_ioctl)(ifp, cmd, data);
		if (error == 0)
			getmicrotime(&ifp->if_lastchange);
		return(error);

	case SIOCSIFMTU:
	{
		u_long oldmtu = ifp->if_mtu;

		if (ifr->ifr_mtu < IF_MINMTU || ifr->ifr_mtu > IF_MAXMTU)
			return (EINVAL);
		if (ifp->if_ioctl == NULL)
			return (EOPNOTSUPP);
		error = (*ifp->if_ioctl)(ifp, cmd, data);
		if (error == 0) {
			getmicrotime(&ifp->if_lastchange);
			rt_ifmsg(ifp);
		}
		/*
		 * If the link MTU changed, do network layer specific procedure.
		 */
		if (ifp->if_mtu != oldmtu) {
#ifdef INET6
			nd6_setmtu(ifp);
#endif
		}
		break;
	}

	case SIOCADDMULTI:
	case SIOCDELMULTI:
		/* Don't allow group membership on non-multicast interfaces. */
		if ((ifp->if_flags & IFF_MULTICAST) == 0)
			return (EOPNOTSUPP);

		/* Don't let users screw up protocols' entries. */
		if (ifr->ifr_addr.sa_family != AF_LINK)
			return (EINVAL);

		if (cmd == SIOCADDMULTI) {
			struct ifmultiaddr *ifma;
			error = if_addmulti(ifp, &ifr->ifr_addr, &ifma);
		} else {
			error = if_delmulti(ifp, &ifr->ifr_addr);
		}
		if (error == 0)
			getmicrotime(&ifp->if_lastchange);
		break;

	case SIOCSIFPHYADDR:
	case SIOCDIFPHYADDR:
#ifdef INET6
	case SIOCSIFPHYADDR_IN6:
#endif
	case SIOCSLIFPHYADDR:
        case SIOCSIFMEDIA:
	case SIOCSIFGENERIC:
		if (ifp->if_ioctl == NULL)
			return (EOPNOTSUPP);
		error = (*ifp->if_ioctl)(ifp, cmd, data);
		if (error == 0)
			getmicrotime(&ifp->if_lastchange);
		break;

	case SIOCGIFSTATUS:
		ifs = (struct ifstat *)data;
		ifs->ascii[0] = '\0';
		
	case SIOCGIFPSRCADDR:
	case SIOCGIFPDSTADDR:
	case SIOCGLIFPHYADDR:
	case SIOCGIFMEDIA:
	case SIOCGIFGENERIC:
		if (ifp->if_ioctl == 0)
			return (EOPNOTSUPP);
		error = (*ifp->if_ioctl)(ifp, cmd, data);
		break;

	case SIOCSIFLLADDR:
          error = if_setlladdr(ifp, (u_char *)ifr->ifr_addr.sa_data,
                                     ifr->ifr_addr.sa_len);
		break;

	default:
		error = ENOIOCTL;
		break;
	}
	return (error);
}
int new_ifioctl(
		struct socket *so,
		u_long cmd,
		caddr_t data,
		struct thread *td,
		struct ifnet *ifp)
{
	struct ifreq *ifr;
	int error;
	int oif_flags;

	ifr = (struct ifreq *)data;

	error = new_ifhwioctl(cmd, ifp, data, td);
	if (error != ENOIOCTL)
		return (error);

	oif_flags = ifp->if_flags;
	if (so->so_proto == 0)
		return (EOPNOTSUPP);
	error = ((*so->so_proto->pr_usrreqs->pru_control)(so, cmd,
								 data,
								 ifp, td));
	sim_assert(error == 0);

	return error;
}
void
fake_ether_set_addr(struct ifnet *ifp, char *ifname, uint32_t ipn,
                    uint32_t ip_maskn)
{
  /* The below function was originally from Alpine but has been modified
     since. */
  struct socket * so;
  struct in_aliasreq ifr;
  struct sockaddr_in *sin, *sinb;
  int err = 0;

  //  memset (&ifr, 0, sizeof (struct in_aliasreq));
  ifr.ifra_vhid = 0;
  sim_assert(
         socreate( AF_INET, &so, SOCK_DGRAM, IPPROTO_UDP, proc0.p_ucred, 
                   curthread )
         == 0);

  sin = (struct sockaddr_in *)&ifr.ifra_addr;

  /* copy in the name of the device */
  strcpy( ifr.ifra_name, ifname );
  sin->sin_addr.s_addr = ipn;
  sin->sin_len = sizeof( struct sockaddr_in );
  sin->sin_family = AF_INET;

  sinb =  (struct sockaddr_in *)&ifr.ifra_broadaddr;
  sinb->sin_addr.s_addr = ip_maskn;
  sinb->sin_len = sizeof( struct sockaddr_in );
  sinb->sin_family = AF_INET;

  new_ifioctl( so, SIOCAIFADDR, (caddr_t)&ifr, curthread, ifp );
  sim_assert(err == 0); 

  soclose( so );
}

static const u_char etherbroadcastaddr[ETHER_ADDR_LEN] =
			{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
struct SimDevice *sim_dev_create (void *priv, enum SimDevFlags flags)
{
  /* FIXME!! */
  static uint32_t devnum = 0;
  struct SimDevice *ifp = (struct SimDevice *) if_alloc (IFT_ETHER);
  //  ifp = realloc (ifp, sizeof(struct SimDevice));

  ifp->ifp.if_dname = "sim"; /* change from name and unit to dname and dunit for 5.3 */
  ifp->ifp.if_dunit = 0;
  if (flags & SIM_DEV_NOARP)
    {
      ifp->ifp.if_flags |= IFF_NOARP;
    }
  if (flags & SIM_DEV_POINTTOPOINT)
    {
      ifp->ifp.if_flags |= IFF_POINTOPOINT;
    }
  if (flags & SIM_DEV_MULTICAST)
    {
      ifp->ifp.if_flags |= IFF_MULTICAST;
    }
  if (flags & SIM_DEV_BROADCAST)
    {
      ifp->ifp.if_flags |= IFF_BROADCAST;
    }
  ifp->ifp.if_type = IFT_ETHER;
  ifp->ifp.if_flags |= IFF_UP;

  /* Set up function pointers */
  ifp->ifp.if_init = fake_ether_init;
  ifp->ifp.if_output = fake_ether_output;
  ifp->ifp.if_ioctl = fake_ether_ioctl;

  /* Alpine says: "we have to set up a false output queue */
  ifp->ifp.if_snd.ifq_maxlen = 1000;
  ifp->ifp.if_linkmib = ifp;

  /* FIXME should be set by user */
  ifp->ifp.if_mtu = 1500;

  ifp->priv = priv;

  /* Attach the interface */
  if_initname(&ifp->ifp, "sim", devnum);
  if_attach(&ifp->ifp);
  bpfattach(&ifp->ifp, DLT_EN10MB, ETHER_HDR_LEN);

  //printf("Fake interface attached.\n");

  /* FIXME */
  struct in_addr addr, mask;
  inet_aton ("255.0.0.0", &mask);
  if (flags & (1<<4))
    inet_aton ("10.0.0.1", &addr);
  else
    inet_aton ("10.0.0.2", &addr);

  fake_ether_set_addr(&ifp->ifp, ifp->ifp.if_xname,
                      (uint32_t)addr.s_addr, (uint32_t)mask.s_addr);

  /* set ether address */
  ifp->ifp.if_broadcastaddr = etherbroadcastaddr;
  ifp->ifp.if_addrlen = ETHER_ADDR_LEN;
  ifp->ifp.if_hdrlen = ETHER_HDR_LEN;

  return ifp;
}
/* FIXME */
void sim_dev_destroy (struct SimDevice *dev)
{
  sim_assert (0);
#if 0
  unregister_netdev(&dev->dev);
  // XXX
  free_netdev (&dev->dev);
#endif
}

void sim_dev_set_address (struct SimDevice *dev, unsigned char buffer[6])
{
  char *lladdr = IF_LLADDR(&dev->ifp);
  bcopy(buffer, lladdr, 6);
  return;
}
void sim_dev_set_mtu (struct SimDevice *dev, int mtu)
{
  // called by ns-3 to synchronize the kernel mtu with 
  // the simulation mtu
  dev->ifp.if_mtu = mtu;
}

void *sim_dev_get_private (struct SimDevice *dev)
{
  return dev->priv;
}


static int get_hack_size (int size)
{
  // Note: this hack is coming from nsc
  // Bit of a hack...
  // Note that the size allocated here effects the offered window somewhat.
  // I've got this heuristic here to try and match up with what we observe
  // on the emulation network and by looking at the driver code of the
  // eepro100. In both cases we allocate enough space for our packet, which
  // is the important thing. The amount of slack at the end can make linux
  // decide the grow the window differently. This is quite subtle, but the
  // code in question is in the tcp_grow_window function. It checks
  // skb->truesize, which is the size of the skbuff allocated for the 
  // incoming data packet -- what we are allocating right now!
  if (size < 1200)
    {
      return size + 36;
    } 
  else if(size <= 1500)
    {
      return 1536;
    } 
  else
    {
      return size + 36;
    }
}
struct SimDevicePacket sim_dev_create_packet (struct SimDevice *dev, int size)
{
  struct SimDevicePacket packet;
  int len = get_hack_size (size);
  struct mbuf *m = NULL;
  m = m_getm(m, len, M_DONTWAIT, MT_DATA);

  packet.token = len;
  packet.buffer = mtod (m, void *);
  return packet;
}
void sim_dev_rx (struct SimDevice *device, struct SimDevicePacket packet)
{
  int size = (int)packet.token;
  struct ifnet *ifp = &device->ifp;
  void *packetdata = packet.buffer;

  fake_ether_input (ifp, packetdata, size);
  return;
}
