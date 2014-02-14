#include "sim-init.h"
#include "sim.h"
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/uio.h>
#include <net/if.h>

struct SimSocket
{};

static struct iovec *copy_iovec (const struct iovec *input, int len)
{
  int size = sizeof (struct iovec) * len;
  struct iovec *output = sim_malloc (size);
  sim_memcpy (output, input, size);
  return output;
}

int sim_sock_socket (int domain, int type, int protocol, struct SimSocket **socket)
{
  struct socket **kernel_socket = (struct socket **)socket;
  int retval = socreate (domain, kernel_socket, type, protocol,
                         proc0.p_ucred, curthread);
  if (retval != 0)
    {
      return -retval;
    }
  return retval;
}
int sim_sock_close (struct SimSocket *socket)
{
  struct socket *kernel_socket = (struct socket *)socket;
  soclose (kernel_socket);
  return 0;
}
ssize_t sim_sock_recvmsg (struct SimSocket *socket, struct msghdr *msg, int flags)
{
  int len;
  struct socket *kernel_socket = (struct socket *)socket;
  struct iovec *kernel_iov = copy_iovec (msg->msg_iov, msg->msg_iovlen);
  struct iovec *user_iov = msg->msg_iov;
  struct cmsghdr *user_cmsgh = msg->msg_control;
  size_t user_cmsghlen = msg->msg_controllen;
  struct sockaddr *from = NULL;
  struct mbuf *control = 0;
  int i;

  msg->msg_iov = kernel_iov;

  struct uio auio;
  auio.uio_iov = msg->msg_iov;
  auio.uio_iovcnt = msg->msg_iovlen;
  auio.uio_segflg = UIO_USERSPACE;
  auio.uio_rw = UIO_READ; 
  auio.uio_td = curthread;
  auio.uio_offset = 0;      
  auio.uio_resid = 0;
  for (i = 0; i < msg->msg_iovlen; i++, msg->msg_iov++) {
    if ((auio.uio_resid += msg->msg_iov->iov_len) < 0) {
      return (EINVAL);
    }
  }

  len = auio.uio_resid;
  int retval = kernel_socket->so_proto->pr_usrreqs->pru_soreceive(
                kernel_socket, &from, &auio, (struct mbuf **)0, 
                msg->msg_control ? &control : (struct mbuf **)0,
                &msg->msg_flags);

  msg->msg_iov = user_iov;
  msg->msg_control = user_cmsgh;
  msg->msg_controllen = user_cmsghlen - msg->msg_controllen;

  retval = (int)len - auio.uio_resid;
  sim_free (kernel_iov);
  return retval;
}
ssize_t sim_sock_sendmsg (struct SimSocket *socket, const struct msghdr *msg, int flags)
{
  int len;
  struct socket *kernel_socket = (struct socket *)socket;
  struct iovec *kernel_iov = copy_iovec (msg->msg_iov, msg->msg_iovlen);
  struct msghdr kernel_msg = *msg;
  kernel_msg.msg_flags = flags;
  kernel_msg.msg_iov = kernel_iov;


  struct uio auio;
  auio.uio_iov = kernel_msg.msg_iov;
  auio.uio_iovcnt = kernel_msg.msg_iovlen;
  auio.uio_segflg = UIO_USERSPACE;
  auio.uio_rw = UIO_WRITE;
  auio.uio_td = curthread;
  auio.uio_offset = 0;   
  auio.uio_resid = kernel_msg.msg_iov->iov_len;

  // Make sure the socket is non-blocking, so we dont try and msleep()
  //  kernel_socket->so_state |= SS_NBIO;

  len = auio.uio_resid;
  int retval = kernel_socket->so_proto->pr_usrreqs->pru_sosend(
            kernel_socket,        // struct socket *so
            kernel_msg.msg_name,        // struct sockaddr *addr
            &auio,                // struct uio *uio
            (struct mbuf *)0,    // struct mbuf *top
            (struct mbuf *)0,   // struct mbuf *control
            0,                    // int flags 
            curthread);            // struct thread *td
        
  if (retval == 0)
    retval = len - auio.uio_resid;

  sim_free (kernel_iov);
  return retval;
}
int sim_sock_getsockname (struct SimSocket *socket, struct sockaddr *name, int *namelen)
{
  struct sockaddr *sa_kern;
  struct socket *sock = (struct socket *)socket;
  int retval = sock->so_proto->pr_usrreqs->pru_sockaddr(sock, &sa_kern);
  return retval;
}
int sim_sock_getpeername (struct SimSocket *socket, struct sockaddr *name, int *namelen)
{
  struct sockaddr *sa_kern;
  struct socket *sock = (struct socket *)socket;
  int retval = sock->so_proto->pr_usrreqs->pru_peeraddr(sock, &sa_kern);
  return retval;
}
int sim_sock_bind (struct SimSocket *socket, const struct sockaddr *name, int namelen)
{
  struct socket *sock = (struct socket *)socket;
  struct sockaddr_storage address;
  memcpy ((char *)&address, name, namelen);
  /* XXX: FreeBSD has ss_len at offset 0.... */
  address.ss_len = namelen;
  memcpy (&address.ss_family, &name->sa_len, sizeof (unsigned char));
  int retval = sobind(sock, (struct sockaddr *)&address, curthread);
  return retval;
}
void msleep_trampoline (void *context);
int sim_sock_connect (struct SimSocket *socket, const struct sockaddr *name, int namelen, int flags)
{
  struct socket *sock = (struct socket *)socket;
  struct sockaddr_storage address;
  memcpy ((char *)&address, name, namelen);
  /* XXX: FreeBSD has ss_len at offset 0.... */
  address.ss_len = namelen;
  memcpy (&address.ss_family, &name->sa_len, sizeof (unsigned char));
  int retval = soconnect(sock, (struct sockaddr *)&address, curthread);

  /* wait for connected */
  int interrupted = 0;
  int error = 0;
  while ((sock->so_state & SS_ISCONNECTING) && sock->so_error == 0) {
    /* FIXME */
#if 0
    sim_event_schedule_ns ((1) * 1000000, &msleep_trampoline, sim_task_current ());
    sim_task_wait ();
#else
    error = msleep(&sock->so_timeo, SOCK_MTX(sock), PSOCK | PCATCH,
                   "sim_connec", 1 /* FIXME */); 
#endif
    if (error) {
      if (error == EINTR || error == ERESTART)
        interrupted = 1;
      break;
    }
  }
  if (error == 0) {
    error = sock->so_error;
    sock->so_error = 0;
  }
  if (!interrupted)
    sock->so_state &= ~SS_ISCONNECTING;
  if (error == ERESTART)
    error = EINTR;

  return retval;
}
int sim_sock_listen (struct SimSocket *socket, int backlog)
{
  struct socket *sock = (struct socket *)socket;
  int retval = solisten(sock, backlog, curthread);
  return retval;
}
int sim_sock_shutdown (struct SimSocket *socket, int how)
{
  struct socket *sock = (struct socket *)socket;
  int retval = soshutdown(sock, how);
  return retval;
}
int sim_sock_accept (struct SimSocket *socket, struct SimSocket **new_socket, int flags)
{
  struct socket *sock, *newsock;
  int err;
  struct sockaddr *nam = NULL;
  sock = (struct socket *)socket;

  if (TAILQ_EMPTY(&sock->so_comp) && sock->so_error == 0)
    return -EAGAIN;

#if 0
  if(sock->so_error) {
    err = sock->so_error;
    sock->so_error = 0;
    return err;
  }
#endif
  newsock = TAILQ_FIRST(&sock->so_comp);
  TAILQ_REMOVE(&sock->so_comp, newsock, so_list);
  newsock->so_qlen--;

  /* connection has been removed from the listen queue */
  KNOTE_UNLOCKED(&sock->so_rcv.sb_sel.si_note, 0);
  newsock->so_head = NULL;

  err = soaccept(newsock, &nam);
  if (err != 0)
    {
      soclose(newsock);
      return -err;
    }
  *new_socket = (struct SimSocket *)newsock;
  soref(newsock);
  return 0;
}
int sim_sock_ioctl (struct SimSocket *socket, int request, char *argp)
{
  sim_assert (0);
#ifdef FIXME
  struct socket *sock = (struct socket *)socket;
  struct sock *sk;
  struct net *net;
  int err;

  sk = sock->sk;
  net = sock_net(sk);

  err = sock->ops->ioctl(sock, request, (long)argp);

  /*
   * If this ioctl is unknown try to hand it down
   * to the NIC driver.
   */
  if (err == -ENOIOCTLCMD)
    err = dev_ioctl(net, request, argp);
  return err;
#endif
}
int sim_sock_setsockopt (struct SimSocket *socket, int level, int optname,
			 const void *optval, int optlen)
{
  struct socket *sock = (struct socket *)socket;
  struct sockopt sopt;
  int err;

  sopt.sopt_dir = SOPT_SET;
  sopt.sopt_level = level;
  sopt.sopt_name = optname;
  sopt.sopt_val = (void *)optval;
  sopt.sopt_valsize = optlen;
  sopt.sopt_td = NULL;

  err = sosetopt(sock, &sopt);
  return err;
}
int sim_sock_getsockopt (struct SimSocket *socket, int level, int optname,
			 void *optval, int *optlen)
{
  struct socket *sock = (struct socket *)socket;
  struct sockopt sopt;
  int err;
  sopt.sopt_dir = SOPT_SET;
  sopt.sopt_level = level;
  sopt.sopt_name = optname;
  sopt.sopt_val = optval;
  sopt.sopt_valsize = *optlen;
  sopt.sopt_td = NULL;

  err = sogetopt(sock, &sopt);
  *optlen = sopt.sopt_valsize;
  return err;
}

#ifdef FIXME
// Wake Up DCE Waiter
int sim_wake_function(wait_queue_t *wait, unsigned mode, int flags, void *key)
{
  sim_poll_event((int)key, wait->private);

  return 0;
}

// Wait for an event occuring over the socket
void* sim_sock_pollwait (struct SimSocket *socket, void *context)
{
  struct socket *sock = (struct socket *)socket;
  wait_queue_t *wait = ( wait_queue_t * ) sim_malloc (sizeof(wait_queue_t));

  wait->func = sim_wake_function;
  wait->private = context;
  wait->task_list.prev = NULL;
  wait->task_list.next = NULL;

  add_wait_queue ( &sock->sk->sk_wq->wait,  wait);

  return wait;
}

void sim_sock_freepoll (struct SimSocket *socket, void *wait)
{
  struct socket *sock = (struct socket *)socket;
  remove_wait_queue (&sock->sk->sk_wq->wait, wait);
  sim_free (wait);
}

int sim_sock_canrecv (struct SimSocket *socket)
{
  struct socket *sock = (struct socket *)socket;

  switch ( sock->sk->sk_state )
  {
    case TCP_CLOSE:
    if ( SOCK_STREAM == sock->sk->sk_type) return 1;

    case TCP_ESTABLISHED:
      return sock->sk->sk_receive_queue.qlen > 0;

    case TCP_SYN_SENT:
    case TCP_SYN_RECV:
    case TCP_LAST_ACK:
    case TCP_CLOSING:
      return 0;

    case TCP_FIN_WAIT1:
    case TCP_FIN_WAIT2:
    case TCP_TIME_WAIT:
    case TCP_CLOSE_WAIT:
      return 1;

    case TCP_LISTEN:
      {
        struct inet_connection_sock *icsk = inet_csk(sock->sk);

        return !reqsk_queue_empty(&icsk->icsk_accept_queue);
      }

    default: break;
  }

  return 0;
}
int sim_sock_cansend (struct SimSocket *socket)
{
  struct socket *sock = (struct socket *)socket;

  return sock_writeable ( sock->sk );
}

/**
 * Struct used to pass pool table context between DCE and Kernel and back from Kernel to DCE
 *
 * When calling sock_poll we provide in ret field the wanted eventmask, and in the opaque field
 * the DCE poll table
 *
 * if a corresponding event occurs later, the PollEvent will be called by kernel with the DCE
 * poll table in context variable, then we will able to wake up the thread blocked in poll call.
 *
 * Back from sock_poll method the kernel change ret field with the response from poll return of the
 * corresponding kernel socket, and in opaque field there is a reference to the kernel poll table
 * we will use this reference to remove us from the file wait queue when ending the DCE poll call or
 * when ending the DCE process which is curently polling.
 *
 */
struct poll_table_ref {
  int ret;
  void *opaque;
};

// Because the poll main loop code is in NS3/DCE we have only on entry in our kernel poll table
struct sim_ptable_entry
{
  wait_queue_t wait;
  wait_queue_head_t *wait_address;
  int eventMask;  // Poll wanted event mask.
  void *opaque; // Pointeur to DCE poll table
};

static int sim_pollwake(wait_queue_t *wait, unsigned mode, int sync, void *key)
{
  struct sim_ptable_entry *entry = (struct sim_ptable_entry *) wait->private;

  if ( ((int)key) & entry->eventMask)
    { // Filter only wanted events
      sim_poll_event((int)key, entry->opaque);
    }

  return 0;
}

static void sim_pollwait(struct file *filp, wait_queue_head_t *wait_address, poll_table *p)
{
  struct poll_wqueues *pwq = container_of(p, struct poll_wqueues, pt);
  struct sim_ptable_entry *entry =
      ( struct sim_ptable_entry * ) sim_malloc (sizeof(struct sim_ptable_entry));
  struct poll_table_ref *fromDCE =  (struct poll_table_ref *) pwq->table;

  entry->opaque = fromDCE->opaque; // Copy DCE poll table reference
  entry->eventMask = fromDCE->ret; // Copy poll mask of wanted events.

  pwq->table = entry;

  init_waitqueue_func_entry(&entry->wait, sim_pollwake);
  entry->wait.private = entry;
  entry->wait_address = wait_address;
  add_wait_queue(wait_address, &entry->wait);
}

void dce_poll_initwait(struct poll_wqueues *pwq)
{
  init_poll_funcptr(&pwq->pt, sim_pollwait);
  pwq->polling_task = current;
  pwq->triggered = 0;
  pwq->error = 0;
  pwq->table = NULL;
  pwq->inline_index = 0;
}

// call poll on socket ...
void sim_sock_poll (struct SimSocket *socket, struct poll_table_ref *ret)
{
  struct socket *sock = (struct socket *)socket;
  // Provide a fake file structure
  struct file zero;
  poll_table *pwait = 0;
  struct poll_wqueues *ptable = 0;

  sim_memset(&zero,0,sizeof(struct file));

  if ( ret->opaque )
    {
      ptable = (struct poll_wqueues *)sim_malloc (sizeof(struct poll_wqueues));
      dce_poll_initwait(ptable);

      pwait = &(ptable->pt);
      // Pass the DCE pool table to sim_pollwait function
      ptable->table = ret;
    }

  ret->ret = sock->ops->poll(&zero, sock, pwait);
  // Pass back the kernel poll table to DCE in order to DCE to remove from wait queue
  // using sim_sock_pollfreewait method below
  ret->opaque = ptable;
}

void sim_sock_pollfreewait (void *polltable)
{
  struct poll_wqueues* ptable = (struct poll_wqueues*) polltable;

  if (ptable && ptable->table)
    {
      struct sim_ptable_entry *entry = ( struct sim_ptable_entry * )ptable->table;
      remove_wait_queue(entry->wait_address, &entry->wait);
      sim_free (entry);
    }
  sim_free (ptable);
}
#endif
