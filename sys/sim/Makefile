SRCDIR=$(dir $(firstword $(MAKEFILE_LIST)))
SRCDIR=$(dir $(shell pwd)/../../)
ARCHDIR=$(SRCDIR)/sys/sim
INSTALL_DIR=./usr
KCONFIG_CONFIG?=config
VPATH=$(SRCDIR)
KERNEL_VERSION=748cf05a77ebd633e384c1dd4a818cc8b538af55

SIM_SRC=\
sim.c interrupt.c sim-device.c sim-socket.c \
globals.c sam.c sort_sysinit.c stub.c \
print.c time.c sched.c random.c glue.c linker.c timer.c vers.c

#fs.c \
#sysctl.c timer.c \
#hrtimer.c sysfs.c workqueue.c \
# security.c slab.c tasklet.c \
#proc.c seq.c socket.c tasklet-hrtimer.c \
#cred.c pid.c modules.c

OPT?=no
opt_yes=-O3 -fomit-frame-pointer 
opt_no=-O0
PIC?=yes
pic_yes=-fpic -DPIC
pic_no=-mcmodel=large
PIC_CFLAGS=$(pic_$(PIC))
KERNEL_LIB=libsim-freebsd.git.so
SIM_OBJ=$(addprefix ./,$(addsuffix .o,$(basename $(SIM_SRC))))
CFLAGS+= \
 $(opt_$(OPT)) -g3 -D__KERNEL__ -Wall -Wstrict-prototypes -Wno-trigraphs \
 -fno-inline -iwithprefix $(SRCDIR)/include -DKBUILD_BASENAME=\"clnt\" \
 -fno-strict-aliasing -fno-common -fno-delete-null-pointer-checks \
 -fno-stack-protector \
 -I$(SRCDIR)/include \
 $(PIC_CFLAGS) -D_DEBUG -I$(PWD)\
 -I$(SRCDIR)/ \
 -I$(SRCDIR)/sys/sim/ \
 -I$(SRCDIR)/sys/sim/machine \
 -I$(SRCDIR)/sys/sim/include \
 -I$(SRCDIR)/sys/sim/compile/DCE \
 -I$(SRCDIR)/sys \
 -I$(SRCDIR)/sys/contrib/altq/ \
 -I$(SRCDIR)/sys/contrib/pf/ \
 -include $(SRCDIR)/sys/sim/compile/DCE/opt_global.h \
 -nostdinc -D__FreeBSD__=5 -D_KERNEL \
 -ffreestanding -std=c99 \
 -Wunused-but-set-variable  # XXX		



include processor.mk

ifeq ($(PROCESSOR_SIZE),64)
CFLAGS+= -DCONFIG_64BIT
endif

LDFLAGS += -shared -nodefaultlibs -g3 -Wl,-O0 -Wl,-Tlinker.lds 

modules:=
all-obj-for-clean:=

all: library modules

-include objs.mk

# note: the directory order below matters to ensure that we match the kernel order
dirs=kern/ netinet/ netinet/cc/ net/ netinet6/ sim/compile/DCE/ fs/devfs/ crypto/ crypto/siphash/ libkern/
#netipsec/ crypto/ \
#crypto/des/ crypto/cast128/ crypto/blowfish/ crypto/rc4/ \
#crypto/rijndael/ crypto/sha2/ 
empty:=
space:= $(empty) $(empty)
colon:= :
comma= ,
kern/_to_keep=inflate.o subr_taskqueue.o kern_conf.o kern_fail.o \
md4c.o syscalls.o kern_jail.o md5c.o sysv_ipc.o kern_mac.o subr_blist.o \
tty_subr.o kern_mbuf.o subr_disk.o uipc_accf.o kern_mib.o \
uipc_domain.o subr_kobj.o \
uipc_mbuf2.o kern_mtxpool.o subr_module.o uipc_mbuf.o \
kern_ntptime.o subr_param.o uipc_socket2.o kern_sysctl.o \
uipc_socket.o kern_tc.o subr_sbuf.o kern_time.o \
subr_scanf.o subr_clock.o subr_smp.o subr_unit.o uipc_sockbuf.o \
kern_khelp.o kern_hhook.o kern_event.o subr_eventhandler.o kern_module.o \
subr_counter.o
#kern_rwlock.o kern_sx.o \
kern_rmlock.o kern_mutex.o kern_lock.o subr_lock.o subr_witness.o \
 subr_stack.o subr_turnstile.o
net/_to_keep=bpf.o if_fwsubr.o if_vlan.o bpf_filter.o if_gif.o \
netisr.o bridge.o if_gre.o net_osdep.o bsd_comp.o if_iso88025subr.o \
pfil.o if_arcsubr.o if_loop.o ppp_deflate.o if_atmsubr.o if_media.o \
ppp_tty.o if.o if_mib.o radix.o if_clone.o if_ppp.o raw_cb.o \
if_disc.o if_sl.o raw_usrreq.o if_ef.o if_spppsubr.o route.o \
if_ethersubr.o if_stf.o rtsock.o if_faith.o if_tap.o slcompress.o \
if_fddisubr.o if_tun.o zlib.o if_llatbl.o
netinet/_to_keep=accf_data.o accf_http.o in_pcb.o  in_pcbgroup.o \
if_atm.o if_ether.o igmp.o in.o  in_cksum.o in_debug.o in_gif.o  in_mcast.o \
in_proto.o in_rmx.o siftr.o ip_carp.o tcp_debug.o \
ip_divert.o tcp_hostcache.o ip_ecn.o tcp_input.o ip_encap.o \
tcp_lro.o ip_fastfwd.o tcp_offload.o ip_gre.o tcp_output.o \
ip_icmp.o tcp_reass.o ip_id.o tcp_sack.o ip_input.o tcp_subr.o \
tcp_syncache.o ip_mroute.o tcp_timer.o ip_options.o tcp_timewait.o \
ip_output.o tcp_usrreq.o raw_ip.o udp_usrreq.o if_llatbl.o mptcp_subr.o
#sctp_auth.o sctp_bsd_addr.o sctp_cc_functions.o sctp_crc32.o 
#sctp_indata.o sctp_input.o sctp_output.o sctp_pcb.o sctp_peeloff.o
#sctp_ss_functions.o sctp_sysctl.o sctp_timer.o sctp_usrreq.o
#sctputil.o sctp_asconf.o
netinet6/_to_keep=dest6.o frag6.o icmp6.o in6.o in6_cksum.o in6_gif.o \
in6_ifattach.o in6_mcast.o in6_pcb.o in6_pcbgroup.o in6_proto.o \
in6_rmx.o in6_src.o ip6_forward.o ip6_id.o ip6_input.o ip6_mroute.o \
ip6_output.o mld6.o nd6.o nd6_nbr.o nd6_rtr.o raw_ip6.o \
route6.o scope6.o send.o udp6_usrreq.o 
#sctp6_usrreq.o
sim/compile/DCE/_to_keep=vnode_if.o
crypto/_to_keep=sha1.o
crypto/siphash/_to_keep=siphash.o
libkern/_to_keep=strcmp.o strncmp.o strlen.o strcpy.o strncpy.o strlcpy.o strtoq.o \
strtouq.o bcmp.o inet_ntoa.o

objs.mk: Makefile.print Makefile compile/DCE/vnode_if.c
	-for i in 1; do \
	$(foreach d,$(dirs), \
           $(MAKE) -i -s -f $< srcdir=$(SRCDIR)/sys/$(d) \
	    objdir=$(SRCDIR)/sys/$(d) \
	    to_keep=$(subst $(space),$(colon),$($(d)_to_keep)) print;) \
	done > $@
linker.lds: ./generate-linker-script.py
	ld -shared --verbose | ./$^ > $@

vers.c:
	sh $(SRCDIR)/sys/conf/newvers.sh >& /dev/null

KERNEL_BUILTIN=$(addprefix $(SRCDIR)/sys/,$(addsuffix builtin.o,$(dirs)))
OBJS=$(SIM_OBJ) $(foreach builtin,$(KERNEL_BUILTIN),$(if $($(builtin)),$($(builtin))))

%/builtin.o:
	mkdir -p $(dir $@); if test -n "$($@)"; then for f in $($@); do $(AR) Tcru $@ $$f; done; else $(AR) Tcru $@; fi
%.ko:%.o
	$(CC) -shared -o $@ -nostdlib $^
%.o:%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $^ -o $@

# For FreeBSD config build
config: Makefile.config Makefile
	make -f Makefile.config
	rm -rf compile
	mkdir -p compile
	cd $(SRCDIR)/sys/sim/conf; \
	$(ARCHDIR)/config  -C DCE

addheader: config
	@cd $(SRCDIR)/sys/sim/compile/DCE; awk -f ../../../tools/makeobjops.awk ../../../kern/device_if.m -h
	@cd $(SRCDIR)/sys/sim/compile/DCE; awk -f ../../../tools/makeobjops.awk ../../../kern/cpufreq_if.m -h
	@cd $(SRCDIR)/sys/sim/compile/DCE; awk -f ../../../tools/makeobjops.awk ../../../kern/bus_if.m -h
	@cd $(SRCDIR)/sys/sim/compile/DCE; awk -f ../../../tools/makeobjops.awk ../../../kern/linker_if.m -h
	@cd $(SRCDIR)/sys/sim/compile/DCE; awk -f ../../../tools/makeobjops.awk ../../../kern/clock_if.m -h
	cd $(SRCDIR)/sys/sim/compile/DCE; awk -f ../../../tools/vnode_if.awk ../../../kern/vnode_if.src -q -p -h -c

compile/DCE/vnode_if.c: addheader

buildkernel: $(KERNEL_LIB)
modules: $(modules) 

ALL_OBJS=$(OBJS) $(KERNEL_LIB) $(modules) $(all-obj-for-clean)
clean:
	@for f in $(ALL_OBJS); do rm -f $$f; done 2>/dev/null
	@rm -rf  linker.lds objs.mk vers.c 2>/dev/null
	@rm -f $(CONFIG_OBJ) $(CONFIG_DIR)/config.c $(CONFIG_DIR)/y.tab.h ./config

$(KERNEL_LIB): addheader objs.mk $(OBJS) linker.lds vers.c
	$(CC) $(LDFLAGS) -Wl,--whole-archive $(OBJS) -o $@
	mv $(KERNEL_LIB) $(SRCDIR)
	cd $(SRCDIR) ; ln -f -s $(KERNEL_LIB) libfreebsd.so

