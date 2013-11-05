KERN_IDENT=DCE
MACHINE=sim
MACHINE_ARCH=sim
DEBUG=-g
# Makefile.sim -- with config changes.
# Copyright 1990 W. Jolitz
#	from: src/sys/conf/Makefile.alpha,v 1.76
# $FreeBSD$
#
# Makefile for FreeBSD
#
# This makefile is constructed from a machine description:
#	config machineid
# Most changes should be made in the machine description
#	/sys/sim/conf/``machineid''
# after which you should do
#	 config machineid
# Generic makefile changes should be made in
#	/sys/conf/Makefile.sim
# after which config should be rerun for all machines.
#

# Which version of config(8) is required.

MACHINE=sim


STD8X16FONT?=	iso

INCLUDES+=

CFLAGS+=

ASM_CFLAGS= -x assembler-with-cpp -Wa,-x -DLOCORE ${CFLAGS}

BEFORE_DEPEND=pccarddevs.h 

OBJS=rijndael-alg-fst.o rijndael-api-fst.o sha2.o db_access.o \
	db_break.o db_capture.o db_command.o db_examine.o db_expr.o \
	db_input.o db_lex.o db_main.o db_output.o db_print.o db_ps.o \
	db_run.o db_script.o db_sym.o db_thread.o db_textdump.o \
	db_variables.o db_watch.o db_write_cmd.o ichss.o eisa_if.o led.o \
	md.o mmcbr_if.o mmcbus_if.o null.o card_if.o power_if.o pci_if.o \
	pcib_if.o pty.o harvest.o hash.o probe.o randomdev.o \
	randomdev_soft.o yarrow.o watchdog.o dead_vnops.o devfs_devs.o \
	devfs_dir.o devfs_rule.o devfs_vfsops.o devfs_vnops.o \
	fifo_vnops.o msdosfs_conv.o msdosfs_denode.o msdosfs_fat.o \
	msdosfs_fileno.o msdosfs_lookup.o msdosfs_vfsops.o \
	msdosfs_vnops.o nfs_commonkrpc.o nfs_commonsubs.o \
	nfs_commonport.o nfs_commonacl.o nfs_clcomsubs.o nfs_clsubs.o \
	nfs_clstate.o nfs_clkrpc.o nfs_clrpcops.o nfs_clvnops.o \
	nfs_clnode.o nfs_clvfsops.o nfs_clport.o nfs_clbio.o \
	nfs_clnfsiod.o nfs_nfsdsocket.o nfs_nfsdsubs.o nfs_nfsdstate.o \
	nfs_nfsdkrpc.o nfs_nfsdserv.o nfs_nfsdport.o nfs_nfsdcache.o \
	procfs.o procfs_ctl.o procfs_dbregs.o procfs_fpregs.o \
	procfs_ioctl.o procfs_map.o procfs_mem.o procfs_note.o \
	procfs_osrel.o procfs_regs.o procfs_rlimit.o procfs_status.o \
	procfs_type.o pseudofs.o pseudofs_fileno.o pseudofs_vncache.o \
	pseudofs_vnops.o gdb_cons.o gdb_main.o gdb_packet.o geom_ctl.o \
	geom_dev.o geom_disk.o geom_dump.o geom_event.o geom_io.o \
	geom_kern.o geom_slice.o geom_subr.o geom_vfs.o g_label.o \
	g_label_ext2fs.o g_label_iso9660.o g_label_msdosfs.o \
	g_label_ntfs.o g_label_reiserfs.o g_label_ufs.o g_label_gpt.o \
	g_part.o g_part_if.o g_part_gpt.o isa_if.o cd9660_bmap.o \
	cd9660_lookup.o cd9660_node.o cd9660_rrip.o cd9660_util.o \
	cd9660_vfsops.o cd9660_vnops.o bus_if.o clock_if.o cpufreq_if.o \
	device_if.o imgact_elf.o imgact_shell.o init_main.o \
	init_sysent.o ksched.o kern_acct.o kern_clock.o kern_condvar.o \
	kern_conf.o kern_cons.o kern_cpu.o kern_cpuset.o kern_context.o \
	kern_descrip.o kern_environment.o kern_et.o kern_event.o \
	kern_exec.o kern_exit.o kern_fail.o kern_ffclock.o kern_fork.o \
	kern_hhook.o kern_idle.o kern_intr.o kern_jail.o kern_khelp.o \
	kern_kthread.o kern_ktrace.o kern_linker.o kern_lock.o \
	kern_lockf.o kern_loginclass.o kern_malloc.o kern_mbuf.o \
	kern_mib.o kern_module.o kern_mtxpool.o kern_mutex.o \
	kern_ntptime.o kern_osd.o kern_physio.o kern_pmc.o kern_priv.o \
	kern_proc.o kern_prot.o kern_racct.o kern_rctl.o kern_resource.o \
	kern_rmlock.o kern_rwlock.o kern_sema.o kern_shutdown.o \
	kern_sig.o kern_switch.o kern_sx.o kern_synch.o kern_syscalls.o \
	kern_sysctl.o kern_tc.o kern_thr.o kern_thread.o kern_time.o \
	kern_timeout.o kern_umtx.o kern_uuid.o kern_xxx.o link_elf.o \
	linker_if.o md5c.o p1003_1b.o posix4_mib.o sched_ule.o \
	serdev_if.o stack_protector.o subr_acl_nfs4.o subr_acl_posix1e.o \
	subr_autoconf.o subr_blist.o subr_bus.o subr_bufring.o \
	subr_clock.o subr_devstat.o subr_disk.o subr_eventhandler.o \
	subr_fattime.o subr_firmware.o subr_hash.o subr_hints.o \
	subr_kdb.o subr_kobj.o subr_lock.o subr_log.o subr_module.o \
	subr_msgbuf.o subr_param.o subr_pcpu.o subr_power.o subr_prf.o \
	subr_prof.o subr_rman.o subr_rtc.o subr_sbuf.o subr_scanf.o \
	subr_sglist.o subr_sleepqueue.o subr_smp.o subr_stack.o \
	subr_taskqueue.o subr_trap.o subr_turnstile.o subr_uio.o \
	subr_unit.o subr_witness.o sys_capability.o sys_generic.o \
	sys_pipe.o sys_procdesc.o sys_process.o sys_socket.o syscalls.o \
	sysv_ipc.o sysv_msg.o sysv_sem.o sysv_shm.o tty.o tty_info.o \
	tty_inq.o tty_outq.o tty_pts.o tty_tty.o tty_ttydisc.o \
	uipc_accf.o uipc_debug.o uipc_domain.o uipc_mbuf.o uipc_mbuf2.o \
	uipc_shm.o uipc_sockbuf.o uipc_socket.o uipc_syscalls.o \
	uipc_usrreq.o vfs_acl.o vfs_bio.o vfs_cache.o vfs_cluster.o \
	vfs_default.o vfs_export.o vfs_extattr.o vfs_hash.o vfs_init.o \
	vfs_lookup.o vfs_mount.o vfs_mountroot.o vfs_subr.o \
	vfs_syscalls.o vfs_vnops.o arc4random.o bcd.o bsearch.o crc32.o \
	fnmatch.o inet_aton.o inet_ntoa.o inet_ntop.o inet_pton.o \
	memcchr.o memcmp.o qsort.o qsort_r.o random.o scanc.o \
	strcasecmp.o strcat.o strchr.o strcmp.o strcpy.o strcspn.o \
	strdup.o strlcat.o strlcpy.o strlen.o strncmp.o strncpy.o \
	strnlen.o strrchr.o strsep.o strspn.o strstr.o strtol.o strtoq.o \
	strtoul.o strtouq.o strvalid.o bpf.o bpf_buffer.o bpf_filter.o \
	bpf_zerocopy.o if.o if_clone.o if_dead.o if_debug.o \
	if_ethersubr.o if_faith.o if_gif.o if_loop.o if_llatbl.o \
	if_media.o if_mib.o if_tun.o if_vlan.o netisr.o pfil.o radix.o \
	radix_mpath.o raw_cb.o raw_usrreq.o route.o rtsock.o if_ether.o \
	igmp.o in.o in_debug.o in_gif.o ip_id.o in_mcast.o in_pcb.o \
	in_proto.o in_rmx.o ip_ecn.o ip_encap.o ip_fastfwd.o ip_icmp.o \
	ip_input.o ip_options.o ip_output.o raw_ip.o cc.o cc_newreno.o \
	tcp_hostcache.o tcp_input.o tcp_lro.o tcp_output.o tcp_offload.o \
	tcp_reass.o tcp_sack.o tcp_subr.o tcp_syncache.o tcp_timer.o \
	tcp_timewait.o tcp_usrreq.o udp_usrreq.o dest6.o frag6.o icmp6.o \
	in6.o in6_cksum.o in6_gif.o in6_ifattach.o in6_mcast.o in6_pcb.o \
	in6_proto.o in6_rmx.o in6_src.o ip6_forward.o ip6_id.o \
	ip6_input.o ip6_output.o mld6.o nd6.o nd6_nbr.o nd6_rtr.o \
	raw_ip6.o route6.o scope6.o udp6_usrreq.o nfs_diskless.o \
	nfs_lock.o nfs_nfssvc.o nlm_advlock.o nlm_prot_clnt.o \
	nlm_prot_impl.o nlm_prot_server.o nlm_prot_svc.o nlm_prot_xdr.o \
	sm_inter_xdr.o auth_none.o auth_unix.o authunix_prot.o clnt_dg.o \
	clnt_rc.o clnt_vc.o getnetconfig.o replay.o rpc_callmsg.o \
	rpc_generic.o rpc_prot.o rpcb_clnt.o rpcb_prot.o svc.o \
	svc_auth.o svc_auth_unix.o svc_dg.o svc_generic.o svc_vc.o \
	audit.o audit_arg.o audit_bsm.o audit_bsm_domain.o \
	audit_bsm_errno.o audit_bsm_fcntl.o audit_bsm_klib.o \
	audit_bsm_socket_type.o audit_bsm_token.o audit_pipe.o \
	audit_syscalls.o audit_trigger.o audit_worker.o mac_syscalls.o \
	ffs_alloc.o ffs_balloc.o ffs_inode.o ffs_snapshot.o \
	ffs_softdep.o ffs_subr.o ffs_tables.o ffs_vfsops.o ffs_vnops.o \
	ufs_acl.o ufs_bmap.o ufs_dirhash.o ufs_extattr.o ufs_gjournal.o \
	ufs_inode.o ufs_lookup.o ufs_quota.o ufs_vfsops.o ufs_vnops.o \
	default_pager.o device_pager.o phys_pager.o sg_pager.o \
	swap_pager.o uma_core.o uma_dbg.o vm_contig.o vm_fault.o \
	vm_glue.o vm_init.o vm_kern.o vm_map.o vm_meter.o vm_mmap.o \
	vm_object.o vm_page.o vm_pageout.o vm_pager.o vm_phys.o \
	vm_reserv.o vm_unix.o vm_zeroidle.o vnode_pager.o xdr.o \
	xdr_array.o xdr_mbuf.o xdr_mem.o xdr_reference.o xdr_sizeof.o 

CFILES=$S/crypto/rijndael/rijndael-alg-fst.c \
	$S/crypto/rijndael/rijndael-api-fst.c $S/crypto/sha2/sha2.c \
	$S/ddb/db_access.c $S/ddb/db_break.c $S/ddb/db_capture.c \
	$S/ddb/db_command.c $S/ddb/db_examine.c $S/ddb/db_expr.c \
	$S/ddb/db_input.c $S/ddb/db_lex.c $S/ddb/db_main.c \
	$S/ddb/db_output.c $S/ddb/db_print.c $S/ddb/db_ps.c \
	$S/ddb/db_run.c $S/ddb/db_script.c $S/ddb/db_sym.c \
	$S/ddb/db_thread.c $S/ddb/db_textdump.c $S/ddb/db_variables.c \
	$S/ddb/db_watch.c $S/ddb/db_write_cmd.c $S/dev/cpufreq/ichss.c \
	$S/dev/led/led.c $S/dev/md/md.c $S/dev/null/null.c \
	$S/dev/pty/pty.c $S/dev/random/harvest.c $S/dev/random/hash.c \
	$S/dev/random/probe.c $S/dev/random/randomdev.c \
	$S/dev/random/randomdev_soft.c $S/dev/random/yarrow.c \
	$S/dev/watchdog/watchdog.c $S/fs/deadfs/dead_vnops.c \
	$S/fs/devfs/devfs_devs.c $S/fs/devfs/devfs_dir.c \
	$S/fs/devfs/devfs_rule.c $S/fs/devfs/devfs_vfsops.c \
	$S/fs/devfs/devfs_vnops.c $S/fs/fifofs/fifo_vnops.c \
	$S/fs/msdosfs/msdosfs_conv.c $S/fs/msdosfs/msdosfs_denode.c \
	$S/fs/msdosfs/msdosfs_fat.c $S/fs/msdosfs/msdosfs_fileno.c \
	$S/fs/msdosfs/msdosfs_lookup.c $S/fs/msdosfs/msdosfs_vfsops.c \
	$S/fs/msdosfs/msdosfs_vnops.c $S/fs/nfs/nfs_commonkrpc.c \
	$S/fs/nfs/nfs_commonsubs.c $S/fs/nfs/nfs_commonport.c \
	$S/fs/nfs/nfs_commonacl.c $S/fs/nfsclient/nfs_clcomsubs.c \
	$S/fs/nfsclient/nfs_clsubs.c $S/fs/nfsclient/nfs_clstate.c \
	$S/fs/nfsclient/nfs_clkrpc.c $S/fs/nfsclient/nfs_clrpcops.c \
	$S/fs/nfsclient/nfs_clvnops.c $S/fs/nfsclient/nfs_clnode.c \
	$S/fs/nfsclient/nfs_clvfsops.c $S/fs/nfsclient/nfs_clport.c \
	$S/fs/nfsclient/nfs_clbio.c $S/fs/nfsclient/nfs_clnfsiod.c \
	$S/fs/nfsserver/nfs_nfsdsocket.c $S/fs/nfsserver/nfs_nfsdsubs.c \
	$S/fs/nfsserver/nfs_nfsdstate.c $S/fs/nfsserver/nfs_nfsdkrpc.c \
	$S/fs/nfsserver/nfs_nfsdserv.c $S/fs/nfsserver/nfs_nfsdport.c \
	$S/fs/nfsserver/nfs_nfsdcache.c $S/fs/procfs/procfs.c \
	$S/fs/procfs/procfs_ctl.c $S/fs/procfs/procfs_dbregs.c \
	$S/fs/procfs/procfs_fpregs.c $S/fs/procfs/procfs_ioctl.c \
	$S/fs/procfs/procfs_map.c $S/fs/procfs/procfs_mem.c \
	$S/fs/procfs/procfs_note.c $S/fs/procfs/procfs_osrel.c \
	$S/fs/procfs/procfs_regs.c $S/fs/procfs/procfs_rlimit.c \
	$S/fs/procfs/procfs_status.c $S/fs/procfs/procfs_type.c \
	$S/fs/pseudofs/pseudofs.c $S/fs/pseudofs/pseudofs_fileno.c \
	$S/fs/pseudofs/pseudofs_vncache.c \
	$S/fs/pseudofs/pseudofs_vnops.c $S/gdb/gdb_cons.c \
	$S/gdb/gdb_main.c $S/gdb/gdb_packet.c $S/geom/geom_ctl.c \
	$S/geom/geom_dev.c $S/geom/geom_disk.c $S/geom/geom_dump.c \
	$S/geom/geom_event.c $S/geom/geom_io.c $S/geom/geom_kern.c \
	$S/geom/geom_slice.c $S/geom/geom_subr.c $S/geom/geom_vfs.c \
	$S/geom/label/g_label.c $S/geom/label/g_label_ext2fs.c \
	$S/geom/label/g_label_iso9660.c $S/geom/label/g_label_msdosfs.c \
	$S/geom/label/g_label_ntfs.c $S/geom/label/g_label_reiserfs.c \
	$S/geom/label/g_label_ufs.c $S/geom/label/g_label_gpt.c \
	$S/geom/part/g_part.c $S/geom/part/g_part_gpt.c \
	$S/fs/cd9660/cd9660_bmap.c $S/fs/cd9660/cd9660_lookup.c \
	$S/fs/cd9660/cd9660_node.c $S/fs/cd9660/cd9660_rrip.c \
	$S/fs/cd9660/cd9660_util.c $S/fs/cd9660/cd9660_vfsops.c \
	$S/fs/cd9660/cd9660_vnops.c $S/kern/imgact_elf.c \
	$S/kern/imgact_shell.c $S/kern/init_main.c $S/kern/init_sysent.c \
	$S/kern/ksched.c $S/kern/kern_acct.c $S/kern/kern_clock.c \
	$S/kern/kern_condvar.c $S/kern/kern_conf.c $S/kern/kern_cons.c \
	$S/kern/kern_cpu.c $S/kern/kern_cpuset.c $S/kern/kern_context.c \
	$S/kern/kern_descrip.c $S/kern/kern_environment.c \
	$S/kern/kern_et.c $S/kern/kern_event.c $S/kern/kern_exec.c \
	$S/kern/kern_exit.c $S/kern/kern_fail.c $S/kern/kern_ffclock.c \
	$S/kern/kern_fork.c $S/kern/kern_hhook.c $S/kern/kern_idle.c \
	$S/kern/kern_intr.c $S/kern/kern_jail.c $S/kern/kern_khelp.c \
	$S/kern/kern_kthread.c $S/kern/kern_ktrace.c \
	$S/kern/kern_linker.c $S/kern/kern_lock.c $S/kern/kern_lockf.c \
	$S/kern/kern_loginclass.c $S/kern/kern_malloc.c \
	$S/kern/kern_mbuf.c $S/kern/kern_mib.c $S/kern/kern_module.c \
	$S/kern/kern_mtxpool.c $S/kern/kern_mutex.c \
	$S/kern/kern_ntptime.c $S/kern/kern_osd.c $S/kern/kern_physio.c \
	$S/kern/kern_pmc.c $S/kern/kern_priv.c $S/kern/kern_proc.c \
	$S/kern/kern_prot.c $S/kern/kern_racct.c $S/kern/kern_rctl.c \
	$S/kern/kern_resource.c $S/kern/kern_rmlock.c \
	$S/kern/kern_rwlock.c $S/kern/kern_sema.c \
	$S/kern/kern_shutdown.c $S/kern/kern_sig.c $S/kern/kern_switch.c \
	$S/kern/kern_sx.c $S/kern/kern_synch.c $S/kern/kern_syscalls.c \
	$S/kern/kern_sysctl.c $S/kern/kern_tc.c $S/kern/kern_thr.c \
	$S/kern/kern_thread.c $S/kern/kern_time.c $S/kern/kern_timeout.c \
	$S/kern/kern_umtx.c $S/kern/kern_uuid.c $S/kern/kern_xxx.c \
	$S/kern/link_elf.c $S/kern/md5c.c $S/kern/p1003_1b.c \
	$S/kern/posix4_mib.c $S/kern/sched_ule.c \
	$S/kern/stack_protector.c $S/kern/subr_acl_nfs4.c \
	$S/kern/subr_acl_posix1e.c $S/kern/subr_autoconf.c \
	$S/kern/subr_blist.c $S/kern/subr_bus.c $S/kern/subr_bufring.c \
	$S/kern/subr_clock.c $S/kern/subr_devstat.c $S/kern/subr_disk.c \
	$S/kern/subr_eventhandler.c $S/kern/subr_fattime.c \
	$S/kern/subr_firmware.c $S/kern/subr_hash.c $S/kern/subr_hints.c \
	$S/kern/subr_kdb.c $S/kern/subr_kobj.c $S/kern/subr_lock.c \
	$S/kern/subr_log.c $S/kern/subr_module.c $S/kern/subr_msgbuf.c \
	$S/kern/subr_param.c $S/kern/subr_pcpu.c $S/kern/subr_power.c \
	$S/kern/subr_prf.c $S/kern/subr_prof.c $S/kern/subr_rman.c \
	$S/kern/subr_rtc.c $S/kern/subr_sbuf.c $S/kern/subr_scanf.c \
	$S/kern/subr_sglist.c $S/kern/subr_sleepqueue.c \
	$S/kern/subr_smp.c $S/kern/subr_stack.c $S/kern/subr_taskqueue.c \
	$S/kern/subr_trap.c $S/kern/subr_turnstile.c $S/kern/subr_uio.c \
	$S/kern/subr_unit.c $S/kern/subr_witness.c \
	$S/kern/sys_capability.c $S/kern/sys_generic.c \
	$S/kern/sys_pipe.c $S/kern/sys_procdesc.c $S/kern/sys_process.c \
	$S/kern/sys_socket.c $S/kern/syscalls.c $S/kern/sysv_ipc.c \
	$S/kern/sysv_msg.c $S/kern/sysv_sem.c $S/kern/sysv_shm.c \
	$S/kern/tty.c $S/kern/tty_info.c $S/kern/tty_inq.c \
	$S/kern/tty_outq.c $S/kern/tty_pts.c $S/kern/tty_tty.c \
	$S/kern/tty_ttydisc.c $S/kern/uipc_accf.c $S/kern/uipc_debug.c \
	$S/kern/uipc_domain.c $S/kern/uipc_mbuf.c $S/kern/uipc_mbuf2.c \
	$S/kern/uipc_shm.c $S/kern/uipc_sockbuf.c $S/kern/uipc_socket.c \
	$S/kern/uipc_syscalls.c $S/kern/uipc_usrreq.c $S/kern/vfs_acl.c \
	$S/kern/vfs_bio.c $S/kern/vfs_cache.c $S/kern/vfs_cluster.c \
	$S/kern/vfs_default.c $S/kern/vfs_export.c $S/kern/vfs_extattr.c \
	$S/kern/vfs_hash.c $S/kern/vfs_init.c $S/kern/vfs_lookup.c \
	$S/kern/vfs_mount.c $S/kern/vfs_mountroot.c $S/kern/vfs_subr.c \
	$S/kern/vfs_syscalls.c $S/kern/vfs_vnops.c \
	$S/libkern/arc4random.c $S/libkern/bcd.c $S/libkern/bsearch.c \
	$S/libkern/crc32.c $S/libkern/fnmatch.c $S/libkern/inet_aton.c \
	$S/libkern/inet_ntoa.c $S/libkern/inet_ntop.c \
	$S/libkern/inet_pton.c $S/libkern/memcchr.c $S/libkern/memcmp.c \
	$S/libkern/qsort.c $S/libkern/qsort_r.c $S/libkern/random.c \
	$S/libkern/scanc.c $S/libkern/strcasecmp.c $S/libkern/strcat.c \
	$S/libkern/strchr.c $S/libkern/strcmp.c $S/libkern/strcpy.c \
	$S/libkern/strcspn.c $S/libkern/strdup.c $S/libkern/strlcat.c \
	$S/libkern/strlcpy.c $S/libkern/strlen.c $S/libkern/strncmp.c \
	$S/libkern/strncpy.c $S/libkern/strnlen.c $S/libkern/strrchr.c \
	$S/libkern/strsep.c $S/libkern/strspn.c $S/libkern/strstr.c \
	$S/libkern/strtol.c $S/libkern/strtoq.c $S/libkern/strtoul.c \
	$S/libkern/strtouq.c $S/libkern/strvalid.c $S/net/bpf.c \
	$S/net/bpf_buffer.c $S/net/bpf_filter.c $S/net/bpf_zerocopy.c \
	$S/net/if.c $S/net/if_clone.c $S/net/if_dead.c $S/net/if_debug.c \
	$S/net/if_ethersubr.c $S/net/if_faith.c $S/net/if_gif.c \
	$S/net/if_loop.c $S/net/if_llatbl.c $S/net/if_media.c \
	$S/net/if_mib.c $S/net/if_tun.c $S/net/if_vlan.c $S/net/netisr.c \
	$S/net/pfil.c $S/net/radix.c $S/net/radix_mpath.c \
	$S/net/raw_cb.c $S/net/raw_usrreq.c $S/net/route.c \
	$S/net/rtsock.c $S/netinet/if_ether.c $S/netinet/igmp.c \
	$S/netinet/in.c $S/netinet/in_debug.c $S/netinet/in_gif.c \
	$S/netinet/ip_id.c $S/netinet/in_mcast.c $S/netinet/in_pcb.c \
	$S/netinet/in_proto.c $S/netinet/in_rmx.c $S/netinet/ip_ecn.c \
	$S/netinet/ip_encap.c $S/netinet/ip_fastfwd.c \
	$S/netinet/ip_icmp.c $S/netinet/ip_input.c \
	$S/netinet/ip_options.c $S/netinet/ip_output.c \
	$S/netinet/raw_ip.c $S/netinet/cc/cc.c \
	$S/netinet/cc/cc_newreno.c $S/netinet/tcp_hostcache.c \
	$S/netinet/tcp_input.c $S/netinet/tcp_lro.c \
	$S/netinet/tcp_output.c $S/netinet/tcp_offload.c \
	$S/netinet/tcp_reass.c $S/netinet/tcp_sack.c \
	$S/netinet/tcp_subr.c $S/netinet/tcp_syncache.c \
	$S/netinet/tcp_timer.c $S/netinet/tcp_timewait.c \
	$S/netinet/tcp_usrreq.c $S/netinet/udp_usrreq.c \
	$S/netinet6/dest6.c $S/netinet6/frag6.c $S/netinet6/icmp6.c \
	$S/netinet6/in6.c $S/netinet6/in6_cksum.c $S/netinet6/in6_gif.c \
	$S/netinet6/in6_ifattach.c $S/netinet6/in6_mcast.c \
	$S/netinet6/in6_pcb.c $S/netinet6/in6_proto.c \
	$S/netinet6/in6_rmx.c $S/netinet6/in6_src.c \
	$S/netinet6/ip6_forward.c $S/netinet6/ip6_id.c \
	$S/netinet6/ip6_input.c $S/netinet6/ip6_output.c \
	$S/netinet6/mld6.c $S/netinet6/nd6.c $S/netinet6/nd6_nbr.c \
	$S/netinet6/nd6_rtr.c $S/netinet6/raw_ip6.c $S/netinet6/route6.c \
	$S/netinet6/scope6.c $S/netinet6/udp6_usrreq.c \
	$S/nfs/nfs_diskless.c $S/nfs/nfs_lock.c $S/nfs/nfs_nfssvc.c \
	$S/nlm/nlm_advlock.c $S/nlm/nlm_prot_clnt.c \
	$S/nlm/nlm_prot_impl.c $S/nlm/nlm_prot_server.c \
	$S/nlm/nlm_prot_svc.c $S/nlm/nlm_prot_xdr.c \
	$S/nlm/sm_inter_xdr.c $S/rpc/auth_none.c $S/rpc/auth_unix.c \
	$S/rpc/authunix_prot.c $S/rpc/clnt_dg.c $S/rpc/clnt_rc.c \
	$S/rpc/clnt_vc.c $S/rpc/getnetconfig.c $S/rpc/replay.c \
	$S/rpc/rpc_callmsg.c $S/rpc/rpc_generic.c $S/rpc/rpc_prot.c \
	$S/rpc/rpcb_clnt.c $S/rpc/rpcb_prot.c $S/rpc/svc.c \
	$S/rpc/svc_auth.c $S/rpc/svc_auth_unix.c $S/rpc/svc_dg.c \
	$S/rpc/svc_generic.c $S/rpc/svc_vc.c $S/security/audit/audit.c \
	$S/security/audit/audit_arg.c $S/security/audit/audit_bsm.c \
	$S/security/audit/audit_bsm_domain.c \
	$S/security/audit/audit_bsm_errno.c \
	$S/security/audit/audit_bsm_fcntl.c \
	$S/security/audit/audit_bsm_klib.c \
	$S/security/audit/audit_bsm_socket_type.c \
	$S/security/audit/audit_bsm_token.c \
	$S/security/audit/audit_pipe.c \
	$S/security/audit/audit_syscalls.c \
	$S/security/audit/audit_trigger.c \
	$S/security/audit/audit_worker.c $S/security/mac/mac_syscalls.c \
	$S/ufs/ffs/ffs_alloc.c $S/ufs/ffs/ffs_balloc.c \
	$S/ufs/ffs/ffs_inode.c $S/ufs/ffs/ffs_snapshot.c \
	$S/ufs/ffs/ffs_softdep.c $S/ufs/ffs/ffs_subr.c \
	$S/ufs/ffs/ffs_tables.c $S/ufs/ffs/ffs_vfsops.c \
	$S/ufs/ffs/ffs_vnops.c $S/ufs/ufs/ufs_acl.c \
	$S/ufs/ufs/ufs_bmap.c $S/ufs/ufs/ufs_dirhash.c \
	$S/ufs/ufs/ufs_extattr.c $S/ufs/ufs/ufs_gjournal.c \
	$S/ufs/ufs/ufs_inode.c $S/ufs/ufs/ufs_lookup.c \
	$S/ufs/ufs/ufs_quota.c $S/ufs/ufs/ufs_vfsops.c \
	$S/ufs/ufs/ufs_vnops.c $S/vm/default_pager.c \
	$S/vm/device_pager.c $S/vm/phys_pager.c $S/vm/sg_pager.c \
	$S/vm/swap_pager.c $S/vm/uma_core.c $S/vm/uma_dbg.c \
	$S/vm/vm_contig.c $S/vm/vm_fault.c $S/vm/vm_glue.c \
	$S/vm/vm_init.c $S/vm/vm_kern.c $S/vm/vm_map.c $S/vm/vm_meter.c \
	$S/vm/vm_mmap.c $S/vm/vm_object.c $S/vm/vm_page.c \
	$S/vm/vm_pageout.c $S/vm/vm_pager.c $S/vm/vm_phys.c \
	$S/vm/vm_reserv.c $S/vm/vm_unix.c $S/vm/vm_zeroidle.c \
	$S/vm/vnode_pager.c $S/xdr/xdr.c $S/xdr/xdr_array.c \
	$S/xdr/xdr_mbuf.c $S/xdr/xdr_mem.c $S/xdr/xdr_reference.c \
	$S/xdr/xdr_sizeof.c 

SFILES=
MFILES=$S/dev/eisa/eisa_if.m $S/dev/mmc/mmcbr_if.m \
	$S/dev/mmc/mmcbus_if.m $S/dev/pccard/card_if.m \
	$S/dev/pccard/power_if.m $S/dev/pci/pci_if.m \
	$S/dev/pci/pcib_if.m $S/geom/part/g_part_if.m $S/isa/isa_if.m \
	$S/kern/bus_if.m $S/kern/clock_if.m $S/kern/cpufreq_if.m \
	$S/kern/device_if.m $S/kern/linker_if.m $S/kern/serdev_if.m 

CLEAN=pccarddevs.h 

pccarddevs.h: $S/tools/pccarddevs2h.awk $S/dev/pccard/pccarddevs
	${AWK} -f $S/tools/pccarddevs2h.awk $S/dev/pccard/pccarddevs

rijndael-alg-fst.ln: $S/crypto/rijndael/rijndael-alg-fst.c
	${NORMAL_LINT}

rijndael-alg-fst.o: $S/crypto/rijndael/rijndael-alg-fst.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

rijndael-api-fst.ln: $S/crypto/rijndael/rijndael-api-fst.c
	${NORMAL_LINT}

rijndael-api-fst.o: $S/crypto/rijndael/rijndael-api-fst.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

sha2.ln: $S/crypto/sha2/sha2.c
	${NORMAL_LINT}

sha2.o: $S/crypto/sha2/sha2.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

db_access.ln: $S/ddb/db_access.c
	${NORMAL_LINT}

db_access.o: $S/ddb/db_access.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

db_break.ln: $S/ddb/db_break.c
	${NORMAL_LINT}

db_break.o: $S/ddb/db_break.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

db_capture.ln: $S/ddb/db_capture.c
	${NORMAL_LINT}

db_capture.o: $S/ddb/db_capture.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

db_command.ln: $S/ddb/db_command.c
	${NORMAL_LINT}

db_command.o: $S/ddb/db_command.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

db_examine.ln: $S/ddb/db_examine.c
	${NORMAL_LINT}

db_examine.o: $S/ddb/db_examine.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

db_expr.ln: $S/ddb/db_expr.c
	${NORMAL_LINT}

db_expr.o: $S/ddb/db_expr.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

db_input.ln: $S/ddb/db_input.c
	${NORMAL_LINT}

db_input.o: $S/ddb/db_input.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

db_lex.ln: $S/ddb/db_lex.c
	${NORMAL_LINT}

db_lex.o: $S/ddb/db_lex.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

db_main.ln: $S/ddb/db_main.c
	${NORMAL_LINT}

db_main.o: $S/ddb/db_main.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

db_output.ln: $S/ddb/db_output.c
	${NORMAL_LINT}

db_output.o: $S/ddb/db_output.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

db_print.ln: $S/ddb/db_print.c
	${NORMAL_LINT}

db_print.o: $S/ddb/db_print.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

db_ps.ln: $S/ddb/db_ps.c
	${NORMAL_LINT}

db_ps.o: $S/ddb/db_ps.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

db_run.ln: $S/ddb/db_run.c
	${NORMAL_LINT}

db_run.o: $S/ddb/db_run.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

db_script.ln: $S/ddb/db_script.c
	${NORMAL_LINT}

db_script.o: $S/ddb/db_script.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

db_sym.ln: $S/ddb/db_sym.c
	${NORMAL_LINT}

db_sym.o: $S/ddb/db_sym.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

db_thread.ln: $S/ddb/db_thread.c
	${NORMAL_LINT}

db_thread.o: $S/ddb/db_thread.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

db_textdump.ln: $S/ddb/db_textdump.c
	${NORMAL_LINT}

db_textdump.o: $S/ddb/db_textdump.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

db_variables.ln: $S/ddb/db_variables.c
	${NORMAL_LINT}

db_variables.o: $S/ddb/db_variables.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

db_watch.ln: $S/ddb/db_watch.c
	${NORMAL_LINT}

db_watch.o: $S/ddb/db_watch.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

db_write_cmd.ln: $S/ddb/db_write_cmd.c
	${NORMAL_LINT}

db_write_cmd.o: $S/ddb/db_write_cmd.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

ichss.ln: $S/dev/cpufreq/ichss.c
	${NORMAL_LINT}

ichss.o: $S/dev/cpufreq/ichss.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

eisa_if.ln: $S/dev/eisa/eisa_if.m
	${NORMAL_LINT}

eisa_if.o: $S/dev/eisa/eisa_if.m
	${NORMAL_M}

	${NORMAL_CTFCONVERT}

led.ln: $S/dev/led/led.c
	${NORMAL_LINT}

led.o: $S/dev/led/led.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

md.ln: $S/dev/md/md.c
	${NORMAL_LINT}

md.o: $S/dev/md/md.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

mmcbr_if.ln: $S/dev/mmc/mmcbr_if.m
	${NORMAL_LINT}

mmcbr_if.o: $S/dev/mmc/mmcbr_if.m
	${NORMAL_M}

	${NORMAL_CTFCONVERT}

mmcbus_if.ln: $S/dev/mmc/mmcbus_if.m
	${NORMAL_LINT}

mmcbus_if.o: $S/dev/mmc/mmcbus_if.m
	${NORMAL_M}

	${NORMAL_CTFCONVERT}

null.ln: $S/dev/null/null.c
	${NORMAL_LINT}

null.o: $S/dev/null/null.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

card_if.ln: $S/dev/pccard/card_if.m
	${NORMAL_LINT}

card_if.o: $S/dev/pccard/card_if.m
	${NORMAL_M}

	${NORMAL_CTFCONVERT}

power_if.ln: $S/dev/pccard/power_if.m
	${NORMAL_LINT}

power_if.o: $S/dev/pccard/power_if.m
	${NORMAL_M}

	${NORMAL_CTFCONVERT}

pci_if.ln: $S/dev/pci/pci_if.m
	${NORMAL_LINT}

pci_if.o: $S/dev/pci/pci_if.m
	${NORMAL_M}

	${NORMAL_CTFCONVERT}

pcib_if.ln: $S/dev/pci/pcib_if.m
	${NORMAL_LINT}

pcib_if.o: $S/dev/pci/pcib_if.m
	${NORMAL_M}

	${NORMAL_CTFCONVERT}

pty.ln: $S/dev/pty/pty.c
	${NORMAL_LINT}

pty.o: $S/dev/pty/pty.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

harvest.ln: $S/dev/random/harvest.c
	${NORMAL_LINT}

harvest.o: $S/dev/random/harvest.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

hash.ln: $S/dev/random/hash.c
	${NORMAL_LINT}

hash.o: $S/dev/random/hash.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

probe.ln: $S/dev/random/probe.c
	${NORMAL_LINT}

probe.o: $S/dev/random/probe.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

randomdev.ln: $S/dev/random/randomdev.c
	${NORMAL_LINT}

randomdev.o: $S/dev/random/randomdev.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

randomdev_soft.ln: $S/dev/random/randomdev_soft.c
	${NORMAL_LINT}

randomdev_soft.o: $S/dev/random/randomdev_soft.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

yarrow.ln: $S/dev/random/yarrow.c
	${NORMAL_LINT}

yarrow.o: $S/dev/random/yarrow.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

watchdog.ln: $S/dev/watchdog/watchdog.c
	${NORMAL_LINT}

watchdog.o: $S/dev/watchdog/watchdog.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

dead_vnops.ln: $S/fs/deadfs/dead_vnops.c
	${NORMAL_LINT}

dead_vnops.o: $S/fs/deadfs/dead_vnops.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

devfs_devs.ln: $S/fs/devfs/devfs_devs.c
	${NORMAL_LINT}

devfs_devs.o: $S/fs/devfs/devfs_devs.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

devfs_dir.ln: $S/fs/devfs/devfs_dir.c
	${NORMAL_LINT}

devfs_dir.o: $S/fs/devfs/devfs_dir.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

devfs_rule.ln: $S/fs/devfs/devfs_rule.c
	${NORMAL_LINT}

devfs_rule.o: $S/fs/devfs/devfs_rule.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

devfs_vfsops.ln: $S/fs/devfs/devfs_vfsops.c
	${NORMAL_LINT}

devfs_vfsops.o: $S/fs/devfs/devfs_vfsops.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

devfs_vnops.ln: $S/fs/devfs/devfs_vnops.c
	${NORMAL_LINT}

devfs_vnops.o: $S/fs/devfs/devfs_vnops.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

fifo_vnops.ln: $S/fs/fifofs/fifo_vnops.c
	${NORMAL_LINT}

fifo_vnops.o: $S/fs/fifofs/fifo_vnops.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

msdosfs_conv.ln: $S/fs/msdosfs/msdosfs_conv.c
	${NORMAL_LINT}

msdosfs_conv.o: $S/fs/msdosfs/msdosfs_conv.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

msdosfs_denode.ln: $S/fs/msdosfs/msdosfs_denode.c
	${NORMAL_LINT}

msdosfs_denode.o: $S/fs/msdosfs/msdosfs_denode.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

msdosfs_fat.ln: $S/fs/msdosfs/msdosfs_fat.c
	${NORMAL_LINT}

msdosfs_fat.o: $S/fs/msdosfs/msdosfs_fat.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

msdosfs_fileno.ln: $S/fs/msdosfs/msdosfs_fileno.c
	${NORMAL_LINT}

msdosfs_fileno.o: $S/fs/msdosfs/msdosfs_fileno.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

msdosfs_lookup.ln: $S/fs/msdosfs/msdosfs_lookup.c
	${NORMAL_LINT}

msdosfs_lookup.o: $S/fs/msdosfs/msdosfs_lookup.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

msdosfs_vfsops.ln: $S/fs/msdosfs/msdosfs_vfsops.c
	${NORMAL_LINT}

msdosfs_vfsops.o: $S/fs/msdosfs/msdosfs_vfsops.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

msdosfs_vnops.ln: $S/fs/msdosfs/msdosfs_vnops.c
	${NORMAL_LINT}

msdosfs_vnops.o: $S/fs/msdosfs/msdosfs_vnops.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

nfs_commonkrpc.ln: $S/fs/nfs/nfs_commonkrpc.c
	${NORMAL_LINT}

nfs_commonkrpc.o: $S/fs/nfs/nfs_commonkrpc.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

nfs_commonsubs.ln: $S/fs/nfs/nfs_commonsubs.c
	${NORMAL_LINT}

nfs_commonsubs.o: $S/fs/nfs/nfs_commonsubs.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

nfs_commonport.ln: $S/fs/nfs/nfs_commonport.c
	${NORMAL_LINT}

nfs_commonport.o: $S/fs/nfs/nfs_commonport.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

nfs_commonacl.ln: $S/fs/nfs/nfs_commonacl.c
	${NORMAL_LINT}

nfs_commonacl.o: $S/fs/nfs/nfs_commonacl.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

nfs_clcomsubs.ln: $S/fs/nfsclient/nfs_clcomsubs.c
	${NORMAL_LINT}

nfs_clcomsubs.o: $S/fs/nfsclient/nfs_clcomsubs.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

nfs_clsubs.ln: $S/fs/nfsclient/nfs_clsubs.c
	${NORMAL_LINT}

nfs_clsubs.o: $S/fs/nfsclient/nfs_clsubs.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

nfs_clstate.ln: $S/fs/nfsclient/nfs_clstate.c
	${NORMAL_LINT}

nfs_clstate.o: $S/fs/nfsclient/nfs_clstate.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

nfs_clkrpc.ln: $S/fs/nfsclient/nfs_clkrpc.c
	${NORMAL_LINT}

nfs_clkrpc.o: $S/fs/nfsclient/nfs_clkrpc.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

nfs_clrpcops.ln: $S/fs/nfsclient/nfs_clrpcops.c
	${NORMAL_LINT}

nfs_clrpcops.o: $S/fs/nfsclient/nfs_clrpcops.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

nfs_clvnops.ln: $S/fs/nfsclient/nfs_clvnops.c
	${NORMAL_LINT}

nfs_clvnops.o: $S/fs/nfsclient/nfs_clvnops.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

nfs_clnode.ln: $S/fs/nfsclient/nfs_clnode.c
	${NORMAL_LINT}

nfs_clnode.o: $S/fs/nfsclient/nfs_clnode.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

nfs_clvfsops.ln: $S/fs/nfsclient/nfs_clvfsops.c
	${NORMAL_LINT}

nfs_clvfsops.o: $S/fs/nfsclient/nfs_clvfsops.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

nfs_clport.ln: $S/fs/nfsclient/nfs_clport.c
	${NORMAL_LINT}

nfs_clport.o: $S/fs/nfsclient/nfs_clport.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

nfs_clbio.ln: $S/fs/nfsclient/nfs_clbio.c
	${NORMAL_LINT}

nfs_clbio.o: $S/fs/nfsclient/nfs_clbio.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

nfs_clnfsiod.ln: $S/fs/nfsclient/nfs_clnfsiod.c
	${NORMAL_LINT}

nfs_clnfsiod.o: $S/fs/nfsclient/nfs_clnfsiod.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

nfs_nfsdsocket.ln: $S/fs/nfsserver/nfs_nfsdsocket.c
	${NORMAL_LINT}

nfs_nfsdsocket.o: $S/fs/nfsserver/nfs_nfsdsocket.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

nfs_nfsdsubs.ln: $S/fs/nfsserver/nfs_nfsdsubs.c
	${NORMAL_LINT}

nfs_nfsdsubs.o: $S/fs/nfsserver/nfs_nfsdsubs.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

nfs_nfsdstate.ln: $S/fs/nfsserver/nfs_nfsdstate.c
	${NORMAL_LINT}

nfs_nfsdstate.o: $S/fs/nfsserver/nfs_nfsdstate.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

nfs_nfsdkrpc.ln: $S/fs/nfsserver/nfs_nfsdkrpc.c
	${NORMAL_LINT}

nfs_nfsdkrpc.o: $S/fs/nfsserver/nfs_nfsdkrpc.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

nfs_nfsdserv.ln: $S/fs/nfsserver/nfs_nfsdserv.c
	${NORMAL_LINT}

nfs_nfsdserv.o: $S/fs/nfsserver/nfs_nfsdserv.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

nfs_nfsdport.ln: $S/fs/nfsserver/nfs_nfsdport.c
	${NORMAL_LINT}

nfs_nfsdport.o: $S/fs/nfsserver/nfs_nfsdport.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

nfs_nfsdcache.ln: $S/fs/nfsserver/nfs_nfsdcache.c
	${NORMAL_LINT}

nfs_nfsdcache.o: $S/fs/nfsserver/nfs_nfsdcache.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

procfs.ln: $S/fs/procfs/procfs.c
	${NORMAL_LINT}

procfs.o: $S/fs/procfs/procfs.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

procfs_ctl.ln: $S/fs/procfs/procfs_ctl.c
	${NORMAL_LINT}

procfs_ctl.o: $S/fs/procfs/procfs_ctl.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

procfs_dbregs.ln: $S/fs/procfs/procfs_dbregs.c
	${NORMAL_LINT}

procfs_dbregs.o: $S/fs/procfs/procfs_dbregs.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

procfs_fpregs.ln: $S/fs/procfs/procfs_fpregs.c
	${NORMAL_LINT}

procfs_fpregs.o: $S/fs/procfs/procfs_fpregs.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

procfs_ioctl.ln: $S/fs/procfs/procfs_ioctl.c
	${NORMAL_LINT}

procfs_ioctl.o: $S/fs/procfs/procfs_ioctl.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

procfs_map.ln: $S/fs/procfs/procfs_map.c
	${NORMAL_LINT}

procfs_map.o: $S/fs/procfs/procfs_map.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

procfs_mem.ln: $S/fs/procfs/procfs_mem.c
	${NORMAL_LINT}

procfs_mem.o: $S/fs/procfs/procfs_mem.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

procfs_note.ln: $S/fs/procfs/procfs_note.c
	${NORMAL_LINT}

procfs_note.o: $S/fs/procfs/procfs_note.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

procfs_osrel.ln: $S/fs/procfs/procfs_osrel.c
	${NORMAL_LINT}

procfs_osrel.o: $S/fs/procfs/procfs_osrel.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

procfs_regs.ln: $S/fs/procfs/procfs_regs.c
	${NORMAL_LINT}

procfs_regs.o: $S/fs/procfs/procfs_regs.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

procfs_rlimit.ln: $S/fs/procfs/procfs_rlimit.c
	${NORMAL_LINT}

procfs_rlimit.o: $S/fs/procfs/procfs_rlimit.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

procfs_status.ln: $S/fs/procfs/procfs_status.c
	${NORMAL_LINT}

procfs_status.o: $S/fs/procfs/procfs_status.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

procfs_type.ln: $S/fs/procfs/procfs_type.c
	${NORMAL_LINT}

procfs_type.o: $S/fs/procfs/procfs_type.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

pseudofs.ln: $S/fs/pseudofs/pseudofs.c
	${NORMAL_LINT}

pseudofs.o: $S/fs/pseudofs/pseudofs.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

pseudofs_fileno.ln: $S/fs/pseudofs/pseudofs_fileno.c
	${NORMAL_LINT}

pseudofs_fileno.o: $S/fs/pseudofs/pseudofs_fileno.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

pseudofs_vncache.ln: $S/fs/pseudofs/pseudofs_vncache.c
	${NORMAL_LINT}

pseudofs_vncache.o: $S/fs/pseudofs/pseudofs_vncache.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

pseudofs_vnops.ln: $S/fs/pseudofs/pseudofs_vnops.c
	${NORMAL_LINT}

pseudofs_vnops.o: $S/fs/pseudofs/pseudofs_vnops.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

gdb_cons.ln: $S/gdb/gdb_cons.c
	${NORMAL_LINT}

gdb_cons.o: $S/gdb/gdb_cons.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

gdb_main.ln: $S/gdb/gdb_main.c
	${NORMAL_LINT}

gdb_main.o: $S/gdb/gdb_main.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

gdb_packet.ln: $S/gdb/gdb_packet.c
	${NORMAL_LINT}

gdb_packet.o: $S/gdb/gdb_packet.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

geom_ctl.ln: $S/geom/geom_ctl.c
	${NORMAL_LINT}

geom_ctl.o: $S/geom/geom_ctl.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

geom_dev.ln: $S/geom/geom_dev.c
	${NORMAL_LINT}

geom_dev.o: $S/geom/geom_dev.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

geom_disk.ln: $S/geom/geom_disk.c
	${NORMAL_LINT}

geom_disk.o: $S/geom/geom_disk.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

geom_dump.ln: $S/geom/geom_dump.c
	${NORMAL_LINT}

geom_dump.o: $S/geom/geom_dump.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

geom_event.ln: $S/geom/geom_event.c
	${NORMAL_LINT}

geom_event.o: $S/geom/geom_event.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

geom_io.ln: $S/geom/geom_io.c
	${NORMAL_LINT}

geom_io.o: $S/geom/geom_io.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

geom_kern.ln: $S/geom/geom_kern.c
	${NORMAL_LINT}

geom_kern.o: $S/geom/geom_kern.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

geom_slice.ln: $S/geom/geom_slice.c
	${NORMAL_LINT}

geom_slice.o: $S/geom/geom_slice.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

geom_subr.ln: $S/geom/geom_subr.c
	${NORMAL_LINT}

geom_subr.o: $S/geom/geom_subr.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

geom_vfs.ln: $S/geom/geom_vfs.c
	${NORMAL_LINT}

geom_vfs.o: $S/geom/geom_vfs.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

g_label.ln: $S/geom/label/g_label.c
	${NORMAL_LINT}

g_label.o: $S/geom/label/g_label.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

g_label_ext2fs.ln: $S/geom/label/g_label_ext2fs.c
	${NORMAL_LINT}

g_label_ext2fs.o: $S/geom/label/g_label_ext2fs.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

g_label_iso9660.ln: $S/geom/label/g_label_iso9660.c
	${NORMAL_LINT}

g_label_iso9660.o: $S/geom/label/g_label_iso9660.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

g_label_msdosfs.ln: $S/geom/label/g_label_msdosfs.c
	${NORMAL_LINT}

g_label_msdosfs.o: $S/geom/label/g_label_msdosfs.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

g_label_ntfs.ln: $S/geom/label/g_label_ntfs.c
	${NORMAL_LINT}

g_label_ntfs.o: $S/geom/label/g_label_ntfs.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

g_label_reiserfs.ln: $S/geom/label/g_label_reiserfs.c
	${NORMAL_LINT}

g_label_reiserfs.o: $S/geom/label/g_label_reiserfs.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

g_label_ufs.ln: $S/geom/label/g_label_ufs.c
	${NORMAL_LINT}

g_label_ufs.o: $S/geom/label/g_label_ufs.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

g_label_gpt.ln: $S/geom/label/g_label_gpt.c
	${NORMAL_LINT}

g_label_gpt.o: $S/geom/label/g_label_gpt.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

g_part.ln: $S/geom/part/g_part.c
	${NORMAL_LINT}

g_part.o: $S/geom/part/g_part.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

g_part_if.ln: $S/geom/part/g_part_if.m
	${NORMAL_LINT}

g_part_if.o: $S/geom/part/g_part_if.m
	${NORMAL_M}

	${NORMAL_CTFCONVERT}

g_part_gpt.ln: $S/geom/part/g_part_gpt.c
	${NORMAL_LINT}

g_part_gpt.o: $S/geom/part/g_part_gpt.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

isa_if.ln: $S/isa/isa_if.m
	${NORMAL_LINT}

isa_if.o: $S/isa/isa_if.m
	${NORMAL_M}

	${NORMAL_CTFCONVERT}

cd9660_bmap.ln: $S/fs/cd9660/cd9660_bmap.c
	${NORMAL_LINT}

cd9660_bmap.o: $S/fs/cd9660/cd9660_bmap.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

cd9660_lookup.ln: $S/fs/cd9660/cd9660_lookup.c
	${NORMAL_LINT}

cd9660_lookup.o: $S/fs/cd9660/cd9660_lookup.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

cd9660_node.ln: $S/fs/cd9660/cd9660_node.c
	${NORMAL_LINT}

cd9660_node.o: $S/fs/cd9660/cd9660_node.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

cd9660_rrip.ln: $S/fs/cd9660/cd9660_rrip.c
	${NORMAL_LINT}

cd9660_rrip.o: $S/fs/cd9660/cd9660_rrip.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

cd9660_util.ln: $S/fs/cd9660/cd9660_util.c
	${NORMAL_LINT}

cd9660_util.o: $S/fs/cd9660/cd9660_util.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

cd9660_vfsops.ln: $S/fs/cd9660/cd9660_vfsops.c
	${NORMAL_LINT}

cd9660_vfsops.o: $S/fs/cd9660/cd9660_vfsops.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

cd9660_vnops.ln: $S/fs/cd9660/cd9660_vnops.c
	${NORMAL_LINT}

cd9660_vnops.o: $S/fs/cd9660/cd9660_vnops.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

bus_if.ln: $S/kern/bus_if.m
	${NORMAL_LINT}

bus_if.o: $S/kern/bus_if.m
	${NORMAL_M}

	${NORMAL_CTFCONVERT}

clock_if.ln: $S/kern/clock_if.m
	${NORMAL_LINT}

clock_if.o: $S/kern/clock_if.m
	${NORMAL_M}

	${NORMAL_CTFCONVERT}

cpufreq_if.ln: $S/kern/cpufreq_if.m
	${NORMAL_LINT}

cpufreq_if.o: $S/kern/cpufreq_if.m
	${NORMAL_M}

	${NORMAL_CTFCONVERT}

device_if.ln: $S/kern/device_if.m
	${NORMAL_LINT}

device_if.o: $S/kern/device_if.m
	${NORMAL_M}

	${NORMAL_CTFCONVERT}

imgact_elf.ln: $S/kern/imgact_elf.c
	${NORMAL_LINT}

imgact_elf.o: $S/kern/imgact_elf.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

imgact_shell.ln: $S/kern/imgact_shell.c
	${NORMAL_LINT}

imgact_shell.o: $S/kern/imgact_shell.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

init_main.ln: $S/kern/init_main.c
	${NORMAL_LINT}

init_main.o: $S/kern/init_main.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

init_sysent.ln: $S/kern/init_sysent.c
	${NORMAL_LINT}

init_sysent.o: $S/kern/init_sysent.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

ksched.ln: $S/kern/ksched.c
	${NORMAL_LINT}

ksched.o: $S/kern/ksched.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_acct.ln: $S/kern/kern_acct.c
	${NORMAL_LINT}

kern_acct.o: $S/kern/kern_acct.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_clock.ln: $S/kern/kern_clock.c
	${NORMAL_LINT}

kern_clock.o: $S/kern/kern_clock.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_condvar.ln: $S/kern/kern_condvar.c
	${NORMAL_LINT}

kern_condvar.o: $S/kern/kern_condvar.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_conf.ln: $S/kern/kern_conf.c
	${NORMAL_LINT}

kern_conf.o: $S/kern/kern_conf.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_cons.ln: $S/kern/kern_cons.c
	${NORMAL_LINT}

kern_cons.o: $S/kern/kern_cons.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_cpu.ln: $S/kern/kern_cpu.c
	${NORMAL_LINT}

kern_cpu.o: $S/kern/kern_cpu.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_cpuset.ln: $S/kern/kern_cpuset.c
	${NORMAL_LINT}

kern_cpuset.o: $S/kern/kern_cpuset.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_context.ln: $S/kern/kern_context.c
	${NORMAL_LINT}

kern_context.o: $S/kern/kern_context.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_descrip.ln: $S/kern/kern_descrip.c
	${NORMAL_LINT}

kern_descrip.o: $S/kern/kern_descrip.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_environment.ln: $S/kern/kern_environment.c
	${NORMAL_LINT}

kern_environment.o: $S/kern/kern_environment.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_et.ln: $S/kern/kern_et.c
	${NORMAL_LINT}

kern_et.o: $S/kern/kern_et.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_event.ln: $S/kern/kern_event.c
	${NORMAL_LINT}

kern_event.o: $S/kern/kern_event.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_exec.ln: $S/kern/kern_exec.c
	${NORMAL_LINT}

kern_exec.o: $S/kern/kern_exec.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_exit.ln: $S/kern/kern_exit.c
	${NORMAL_LINT}

kern_exit.o: $S/kern/kern_exit.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_fail.ln: $S/kern/kern_fail.c
	${NORMAL_LINT}

kern_fail.o: $S/kern/kern_fail.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_ffclock.ln: $S/kern/kern_ffclock.c
	${NORMAL_LINT}

kern_ffclock.o: $S/kern/kern_ffclock.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_fork.ln: $S/kern/kern_fork.c
	${NORMAL_LINT}

kern_fork.o: $S/kern/kern_fork.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_hhook.ln: $S/kern/kern_hhook.c
	${NORMAL_LINT}

kern_hhook.o: $S/kern/kern_hhook.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_idle.ln: $S/kern/kern_idle.c
	${NORMAL_LINT}

kern_idle.o: $S/kern/kern_idle.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_intr.ln: $S/kern/kern_intr.c
	${NORMAL_LINT}

kern_intr.o: $S/kern/kern_intr.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_jail.ln: $S/kern/kern_jail.c
	${NORMAL_LINT}

kern_jail.o: $S/kern/kern_jail.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_khelp.ln: $S/kern/kern_khelp.c
	${NORMAL_LINT}

kern_khelp.o: $S/kern/kern_khelp.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_kthread.ln: $S/kern/kern_kthread.c
	${NORMAL_LINT}

kern_kthread.o: $S/kern/kern_kthread.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_ktrace.ln: $S/kern/kern_ktrace.c
	${NORMAL_LINT}

kern_ktrace.o: $S/kern/kern_ktrace.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_linker.ln: $S/kern/kern_linker.c
	${NORMAL_LINT}

kern_linker.o: $S/kern/kern_linker.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_lock.ln: $S/kern/kern_lock.c
	${NORMAL_LINT}

kern_lock.o: $S/kern/kern_lock.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_lockf.ln: $S/kern/kern_lockf.c
	${NORMAL_LINT}

kern_lockf.o: $S/kern/kern_lockf.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_loginclass.ln: $S/kern/kern_loginclass.c
	${NORMAL_LINT}

kern_loginclass.o: $S/kern/kern_loginclass.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_malloc.ln: $S/kern/kern_malloc.c
	${NORMAL_LINT}

kern_malloc.o: $S/kern/kern_malloc.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_mbuf.ln: $S/kern/kern_mbuf.c
	${NORMAL_LINT}

kern_mbuf.o: $S/kern/kern_mbuf.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_mib.ln: $S/kern/kern_mib.c
	${NORMAL_LINT}

kern_mib.o: $S/kern/kern_mib.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_module.ln: $S/kern/kern_module.c
	${NORMAL_LINT}

kern_module.o: $S/kern/kern_module.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_mtxpool.ln: $S/kern/kern_mtxpool.c
	${NORMAL_LINT}

kern_mtxpool.o: $S/kern/kern_mtxpool.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_mutex.ln: $S/kern/kern_mutex.c
	${NORMAL_LINT}

kern_mutex.o: $S/kern/kern_mutex.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_ntptime.ln: $S/kern/kern_ntptime.c
	${NORMAL_LINT}

kern_ntptime.o: $S/kern/kern_ntptime.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_osd.ln: $S/kern/kern_osd.c
	${NORMAL_LINT}

kern_osd.o: $S/kern/kern_osd.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_physio.ln: $S/kern/kern_physio.c
	${NORMAL_LINT}

kern_physio.o: $S/kern/kern_physio.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_pmc.ln: $S/kern/kern_pmc.c
	${NORMAL_LINT}

kern_pmc.o: $S/kern/kern_pmc.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_priv.ln: $S/kern/kern_priv.c
	${NORMAL_LINT}

kern_priv.o: $S/kern/kern_priv.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_proc.ln: $S/kern/kern_proc.c
	${NORMAL_LINT}

kern_proc.o: $S/kern/kern_proc.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_prot.ln: $S/kern/kern_prot.c
	${NORMAL_LINT}

kern_prot.o: $S/kern/kern_prot.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_racct.ln: $S/kern/kern_racct.c
	${NORMAL_LINT}

kern_racct.o: $S/kern/kern_racct.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_rctl.ln: $S/kern/kern_rctl.c
	${NORMAL_LINT}

kern_rctl.o: $S/kern/kern_rctl.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_resource.ln: $S/kern/kern_resource.c
	${NORMAL_LINT}

kern_resource.o: $S/kern/kern_resource.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_rmlock.ln: $S/kern/kern_rmlock.c
	${NORMAL_LINT}

kern_rmlock.o: $S/kern/kern_rmlock.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_rwlock.ln: $S/kern/kern_rwlock.c
	${NORMAL_LINT}

kern_rwlock.o: $S/kern/kern_rwlock.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_sema.ln: $S/kern/kern_sema.c
	${NORMAL_LINT}

kern_sema.o: $S/kern/kern_sema.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_shutdown.ln: $S/kern/kern_shutdown.c
	${NORMAL_LINT}

kern_shutdown.o: $S/kern/kern_shutdown.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_sig.ln: $S/kern/kern_sig.c
	${NORMAL_LINT}

kern_sig.o: $S/kern/kern_sig.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_switch.ln: $S/kern/kern_switch.c
	${NORMAL_LINT}

kern_switch.o: $S/kern/kern_switch.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_sx.ln: $S/kern/kern_sx.c
	${NORMAL_LINT}

kern_sx.o: $S/kern/kern_sx.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_synch.ln: $S/kern/kern_synch.c
	${NORMAL_LINT}

kern_synch.o: $S/kern/kern_synch.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_syscalls.ln: $S/kern/kern_syscalls.c
	${NORMAL_LINT}

kern_syscalls.o: $S/kern/kern_syscalls.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_sysctl.ln: $S/kern/kern_sysctl.c
	${NORMAL_LINT}

kern_sysctl.o: $S/kern/kern_sysctl.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_tc.ln: $S/kern/kern_tc.c
	${NORMAL_LINT}

kern_tc.o: $S/kern/kern_tc.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_thr.ln: $S/kern/kern_thr.c
	${NORMAL_LINT}

kern_thr.o: $S/kern/kern_thr.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_thread.ln: $S/kern/kern_thread.c
	${NORMAL_LINT}

kern_thread.o: $S/kern/kern_thread.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_time.ln: $S/kern/kern_time.c
	${NORMAL_LINT}

kern_time.o: $S/kern/kern_time.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_timeout.ln: $S/kern/kern_timeout.c
	${NORMAL_LINT}

kern_timeout.o: $S/kern/kern_timeout.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_umtx.ln: $S/kern/kern_umtx.c
	${NORMAL_LINT}

kern_umtx.o: $S/kern/kern_umtx.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_uuid.ln: $S/kern/kern_uuid.c
	${NORMAL_LINT}

kern_uuid.o: $S/kern/kern_uuid.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

kern_xxx.ln: $S/kern/kern_xxx.c
	${NORMAL_LINT}

kern_xxx.o: $S/kern/kern_xxx.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

link_elf.ln: $S/kern/link_elf.c
	${NORMAL_LINT}

link_elf.o: $S/kern/link_elf.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

linker_if.ln: $S/kern/linker_if.m
	${NORMAL_LINT}

linker_if.o: $S/kern/linker_if.m
	${NORMAL_M}

	${NORMAL_CTFCONVERT}

md5c.ln: $S/kern/md5c.c
	${NORMAL_LINT}

md5c.o: $S/kern/md5c.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

p1003_1b.ln: $S/kern/p1003_1b.c
	${NORMAL_LINT}

p1003_1b.o: $S/kern/p1003_1b.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

posix4_mib.ln: $S/kern/posix4_mib.c
	${NORMAL_LINT}

posix4_mib.o: $S/kern/posix4_mib.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

sched_ule.ln: $S/kern/sched_ule.c
	${NORMAL_LINT}

sched_ule.o: $S/kern/sched_ule.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

serdev_if.ln: $S/kern/serdev_if.m
	${NORMAL_LINT}

serdev_if.o: $S/kern/serdev_if.m
	${NORMAL_M}

	${NORMAL_CTFCONVERT}

stack_protector.ln: $S/kern/stack_protector.c
	${NORMAL_LINT}

stack_protector.o: $S/kern/stack_protector.c
	${NORMAL_C:N-fstack-protector*}
	${NORMAL_CTFCONVERT}

subr_acl_nfs4.ln: $S/kern/subr_acl_nfs4.c
	${NORMAL_LINT}

subr_acl_nfs4.o: $S/kern/subr_acl_nfs4.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

subr_acl_posix1e.ln: $S/kern/subr_acl_posix1e.c
	${NORMAL_LINT}

subr_acl_posix1e.o: $S/kern/subr_acl_posix1e.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

subr_autoconf.ln: $S/kern/subr_autoconf.c
	${NORMAL_LINT}

subr_autoconf.o: $S/kern/subr_autoconf.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

subr_blist.ln: $S/kern/subr_blist.c
	${NORMAL_LINT}

subr_blist.o: $S/kern/subr_blist.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

subr_bus.ln: $S/kern/subr_bus.c
	${NORMAL_LINT}

subr_bus.o: $S/kern/subr_bus.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

subr_bufring.ln: $S/kern/subr_bufring.c
	${NORMAL_LINT}

subr_bufring.o: $S/kern/subr_bufring.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

subr_clock.ln: $S/kern/subr_clock.c
	${NORMAL_LINT}

subr_clock.o: $S/kern/subr_clock.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

subr_devstat.ln: $S/kern/subr_devstat.c
	${NORMAL_LINT}

subr_devstat.o: $S/kern/subr_devstat.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

subr_disk.ln: $S/kern/subr_disk.c
	${NORMAL_LINT}

subr_disk.o: $S/kern/subr_disk.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

subr_eventhandler.ln: $S/kern/subr_eventhandler.c
	${NORMAL_LINT}

subr_eventhandler.o: $S/kern/subr_eventhandler.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

subr_fattime.ln: $S/kern/subr_fattime.c
	${NORMAL_LINT}

subr_fattime.o: $S/kern/subr_fattime.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

subr_firmware.ln: $S/kern/subr_firmware.c
	${NORMAL_LINT}

subr_firmware.o: $S/kern/subr_firmware.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

subr_hash.ln: $S/kern/subr_hash.c
	${NORMAL_LINT}

subr_hash.o: $S/kern/subr_hash.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

subr_hints.ln: $S/kern/subr_hints.c
	${NORMAL_LINT}

subr_hints.o: $S/kern/subr_hints.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

subr_kdb.ln: $S/kern/subr_kdb.c
	${NORMAL_LINT}

subr_kdb.o: $S/kern/subr_kdb.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

subr_kobj.ln: $S/kern/subr_kobj.c
	${NORMAL_LINT}

subr_kobj.o: $S/kern/subr_kobj.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

subr_lock.ln: $S/kern/subr_lock.c
	${NORMAL_LINT}

subr_lock.o: $S/kern/subr_lock.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

subr_log.ln: $S/kern/subr_log.c
	${NORMAL_LINT}

subr_log.o: $S/kern/subr_log.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

subr_module.ln: $S/kern/subr_module.c
	${NORMAL_LINT}

subr_module.o: $S/kern/subr_module.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

subr_msgbuf.ln: $S/kern/subr_msgbuf.c
	${NORMAL_LINT}

subr_msgbuf.o: $S/kern/subr_msgbuf.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

subr_param.ln: $S/kern/subr_param.c
	${NORMAL_LINT}

subr_param.o: $S/kern/subr_param.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

subr_pcpu.ln: $S/kern/subr_pcpu.c
	${NORMAL_LINT}

subr_pcpu.o: $S/kern/subr_pcpu.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

subr_power.ln: $S/kern/subr_power.c
	${NORMAL_LINT}

subr_power.o: $S/kern/subr_power.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

subr_prf.ln: $S/kern/subr_prf.c
	${NORMAL_LINT}

subr_prf.o: $S/kern/subr_prf.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

subr_prof.ln: $S/kern/subr_prof.c
	${NORMAL_LINT}

subr_prof.o: $S/kern/subr_prof.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

subr_rman.ln: $S/kern/subr_rman.c
	${NORMAL_LINT}

subr_rman.o: $S/kern/subr_rman.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

subr_rtc.ln: $S/kern/subr_rtc.c
	${NORMAL_LINT}

subr_rtc.o: $S/kern/subr_rtc.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

subr_sbuf.ln: $S/kern/subr_sbuf.c
	${NORMAL_LINT}

subr_sbuf.o: $S/kern/subr_sbuf.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

subr_scanf.ln: $S/kern/subr_scanf.c
	${NORMAL_LINT}

subr_scanf.o: $S/kern/subr_scanf.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

subr_sglist.ln: $S/kern/subr_sglist.c
	${NORMAL_LINT}

subr_sglist.o: $S/kern/subr_sglist.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

subr_sleepqueue.ln: $S/kern/subr_sleepqueue.c
	${NORMAL_LINT}

subr_sleepqueue.o: $S/kern/subr_sleepqueue.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

subr_smp.ln: $S/kern/subr_smp.c
	${NORMAL_LINT}

subr_smp.o: $S/kern/subr_smp.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

subr_stack.ln: $S/kern/subr_stack.c
	${NORMAL_LINT}

subr_stack.o: $S/kern/subr_stack.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

subr_taskqueue.ln: $S/kern/subr_taskqueue.c
	${NORMAL_LINT}

subr_taskqueue.o: $S/kern/subr_taskqueue.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

subr_trap.ln: $S/kern/subr_trap.c
	${NORMAL_LINT}

subr_trap.o: $S/kern/subr_trap.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

subr_turnstile.ln: $S/kern/subr_turnstile.c
	${NORMAL_LINT}

subr_turnstile.o: $S/kern/subr_turnstile.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

subr_uio.ln: $S/kern/subr_uio.c
	${NORMAL_LINT}

subr_uio.o: $S/kern/subr_uio.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

subr_unit.ln: $S/kern/subr_unit.c
	${NORMAL_LINT}

subr_unit.o: $S/kern/subr_unit.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

subr_witness.ln: $S/kern/subr_witness.c
	${NORMAL_LINT}

subr_witness.o: $S/kern/subr_witness.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

sys_capability.ln: $S/kern/sys_capability.c
	${NORMAL_LINT}

sys_capability.o: $S/kern/sys_capability.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

sys_generic.ln: $S/kern/sys_generic.c
	${NORMAL_LINT}

sys_generic.o: $S/kern/sys_generic.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

sys_pipe.ln: $S/kern/sys_pipe.c
	${NORMAL_LINT}

sys_pipe.o: $S/kern/sys_pipe.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

sys_procdesc.ln: $S/kern/sys_procdesc.c
	${NORMAL_LINT}

sys_procdesc.o: $S/kern/sys_procdesc.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

sys_process.ln: $S/kern/sys_process.c
	${NORMAL_LINT}

sys_process.o: $S/kern/sys_process.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

sys_socket.ln: $S/kern/sys_socket.c
	${NORMAL_LINT}

sys_socket.o: $S/kern/sys_socket.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

syscalls.ln: $S/kern/syscalls.c
	${NORMAL_LINT}

syscalls.o: $S/kern/syscalls.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

sysv_ipc.ln: $S/kern/sysv_ipc.c
	${NORMAL_LINT}

sysv_ipc.o: $S/kern/sysv_ipc.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

sysv_msg.ln: $S/kern/sysv_msg.c
	${NORMAL_LINT}

sysv_msg.o: $S/kern/sysv_msg.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

sysv_sem.ln: $S/kern/sysv_sem.c
	${NORMAL_LINT}

sysv_sem.o: $S/kern/sysv_sem.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

sysv_shm.ln: $S/kern/sysv_shm.c
	${NORMAL_LINT}

sysv_shm.o: $S/kern/sysv_shm.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

tty.ln: $S/kern/tty.c
	${NORMAL_LINT}

tty.o: $S/kern/tty.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

tty_info.ln: $S/kern/tty_info.c
	${NORMAL_LINT}

tty_info.o: $S/kern/tty_info.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

tty_inq.ln: $S/kern/tty_inq.c
	${NORMAL_LINT}

tty_inq.o: $S/kern/tty_inq.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

tty_outq.ln: $S/kern/tty_outq.c
	${NORMAL_LINT}

tty_outq.o: $S/kern/tty_outq.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

tty_pts.ln: $S/kern/tty_pts.c
	${NORMAL_LINT}

tty_pts.o: $S/kern/tty_pts.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

tty_tty.ln: $S/kern/tty_tty.c
	${NORMAL_LINT}

tty_tty.o: $S/kern/tty_tty.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

tty_ttydisc.ln: $S/kern/tty_ttydisc.c
	${NORMAL_LINT}

tty_ttydisc.o: $S/kern/tty_ttydisc.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

uipc_accf.ln: $S/kern/uipc_accf.c
	${NORMAL_LINT}

uipc_accf.o: $S/kern/uipc_accf.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

uipc_debug.ln: $S/kern/uipc_debug.c
	${NORMAL_LINT}

uipc_debug.o: $S/kern/uipc_debug.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

uipc_domain.ln: $S/kern/uipc_domain.c
	${NORMAL_LINT}

uipc_domain.o: $S/kern/uipc_domain.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

uipc_mbuf.ln: $S/kern/uipc_mbuf.c
	${NORMAL_LINT}

uipc_mbuf.o: $S/kern/uipc_mbuf.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

uipc_mbuf2.ln: $S/kern/uipc_mbuf2.c
	${NORMAL_LINT}

uipc_mbuf2.o: $S/kern/uipc_mbuf2.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

uipc_shm.ln: $S/kern/uipc_shm.c
	${NORMAL_LINT}

uipc_shm.o: $S/kern/uipc_shm.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

uipc_sockbuf.ln: $S/kern/uipc_sockbuf.c
	${NORMAL_LINT}

uipc_sockbuf.o: $S/kern/uipc_sockbuf.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

uipc_socket.ln: $S/kern/uipc_socket.c
	${NORMAL_LINT}

uipc_socket.o: $S/kern/uipc_socket.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

uipc_syscalls.ln: $S/kern/uipc_syscalls.c
	${NORMAL_LINT}

uipc_syscalls.o: $S/kern/uipc_syscalls.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

uipc_usrreq.ln: $S/kern/uipc_usrreq.c
	${NORMAL_LINT}

uipc_usrreq.o: $S/kern/uipc_usrreq.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

vfs_acl.ln: $S/kern/vfs_acl.c
	${NORMAL_LINT}

vfs_acl.o: $S/kern/vfs_acl.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

vfs_bio.ln: $S/kern/vfs_bio.c
	${NORMAL_LINT}

vfs_bio.o: $S/kern/vfs_bio.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

vfs_cache.ln: $S/kern/vfs_cache.c
	${NORMAL_LINT}

vfs_cache.o: $S/kern/vfs_cache.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

vfs_cluster.ln: $S/kern/vfs_cluster.c
	${NORMAL_LINT}

vfs_cluster.o: $S/kern/vfs_cluster.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

vfs_default.ln: $S/kern/vfs_default.c
	${NORMAL_LINT}

vfs_default.o: $S/kern/vfs_default.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

vfs_export.ln: $S/kern/vfs_export.c
	${NORMAL_LINT}

vfs_export.o: $S/kern/vfs_export.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

vfs_extattr.ln: $S/kern/vfs_extattr.c
	${NORMAL_LINT}

vfs_extattr.o: $S/kern/vfs_extattr.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

vfs_hash.ln: $S/kern/vfs_hash.c
	${NORMAL_LINT}

vfs_hash.o: $S/kern/vfs_hash.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

vfs_init.ln: $S/kern/vfs_init.c
	${NORMAL_LINT}

vfs_init.o: $S/kern/vfs_init.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

vfs_lookup.ln: $S/kern/vfs_lookup.c
	${NORMAL_LINT}

vfs_lookup.o: $S/kern/vfs_lookup.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

vfs_mount.ln: $S/kern/vfs_mount.c
	${NORMAL_LINT}

vfs_mount.o: $S/kern/vfs_mount.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

vfs_mountroot.ln: $S/kern/vfs_mountroot.c
	${NORMAL_LINT}

vfs_mountroot.o: $S/kern/vfs_mountroot.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

vfs_subr.ln: $S/kern/vfs_subr.c
	${NORMAL_LINT}

vfs_subr.o: $S/kern/vfs_subr.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

vfs_syscalls.ln: $S/kern/vfs_syscalls.c
	${NORMAL_LINT}

vfs_syscalls.o: $S/kern/vfs_syscalls.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

vfs_vnops.ln: $S/kern/vfs_vnops.c
	${NORMAL_LINT}

vfs_vnops.o: $S/kern/vfs_vnops.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

arc4random.ln: $S/libkern/arc4random.c
	${NORMAL_LINT}

arc4random.o: $S/libkern/arc4random.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

bcd.ln: $S/libkern/bcd.c
	${NORMAL_LINT}

bcd.o: $S/libkern/bcd.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

bsearch.ln: $S/libkern/bsearch.c
	${NORMAL_LINT}

bsearch.o: $S/libkern/bsearch.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

crc32.ln: $S/libkern/crc32.c
	${NORMAL_LINT}

crc32.o: $S/libkern/crc32.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

fnmatch.ln: $S/libkern/fnmatch.c
	${NORMAL_LINT}

fnmatch.o: $S/libkern/fnmatch.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

inet_aton.ln: $S/libkern/inet_aton.c
	${NORMAL_LINT}

inet_aton.o: $S/libkern/inet_aton.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

inet_ntoa.ln: $S/libkern/inet_ntoa.c
	${NORMAL_LINT}

inet_ntoa.o: $S/libkern/inet_ntoa.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

inet_ntop.ln: $S/libkern/inet_ntop.c
	${NORMAL_LINT}

inet_ntop.o: $S/libkern/inet_ntop.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

inet_pton.ln: $S/libkern/inet_pton.c
	${NORMAL_LINT}

inet_pton.o: $S/libkern/inet_pton.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

memcchr.ln: $S/libkern/memcchr.c
	${NORMAL_LINT}

memcchr.o: $S/libkern/memcchr.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

memcmp.ln: $S/libkern/memcmp.c
	${NORMAL_LINT}

memcmp.o: $S/libkern/memcmp.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

qsort.ln: $S/libkern/qsort.c
	${NORMAL_LINT}

qsort.o: $S/libkern/qsort.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

qsort_r.ln: $S/libkern/qsort_r.c
	${NORMAL_LINT}

qsort_r.o: $S/libkern/qsort_r.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

random.ln: $S/libkern/random.c
	${NORMAL_LINT}

random.o: $S/libkern/random.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

scanc.ln: $S/libkern/scanc.c
	${NORMAL_LINT}

scanc.o: $S/libkern/scanc.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

strcasecmp.ln: $S/libkern/strcasecmp.c
	${NORMAL_LINT}

strcasecmp.o: $S/libkern/strcasecmp.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

strcat.ln: $S/libkern/strcat.c
	${NORMAL_LINT}

strcat.o: $S/libkern/strcat.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

strchr.ln: $S/libkern/strchr.c
	${NORMAL_LINT}

strchr.o: $S/libkern/strchr.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

strcmp.ln: $S/libkern/strcmp.c
	${NORMAL_LINT}

strcmp.o: $S/libkern/strcmp.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

strcpy.ln: $S/libkern/strcpy.c
	${NORMAL_LINT}

strcpy.o: $S/libkern/strcpy.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

strcspn.ln: $S/libkern/strcspn.c
	${NORMAL_LINT}

strcspn.o: $S/libkern/strcspn.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

strdup.ln: $S/libkern/strdup.c
	${NORMAL_LINT}

strdup.o: $S/libkern/strdup.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

strlcat.ln: $S/libkern/strlcat.c
	${NORMAL_LINT}

strlcat.o: $S/libkern/strlcat.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

strlcpy.ln: $S/libkern/strlcpy.c
	${NORMAL_LINT}

strlcpy.o: $S/libkern/strlcpy.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

strlen.ln: $S/libkern/strlen.c
	${NORMAL_LINT}

strlen.o: $S/libkern/strlen.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

strncmp.ln: $S/libkern/strncmp.c
	${NORMAL_LINT}

strncmp.o: $S/libkern/strncmp.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

strncpy.ln: $S/libkern/strncpy.c
	${NORMAL_LINT}

strncpy.o: $S/libkern/strncpy.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

strnlen.ln: $S/libkern/strnlen.c
	${NORMAL_LINT}

strnlen.o: $S/libkern/strnlen.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

strrchr.ln: $S/libkern/strrchr.c
	${NORMAL_LINT}

strrchr.o: $S/libkern/strrchr.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

strsep.ln: $S/libkern/strsep.c
	${NORMAL_LINT}

strsep.o: $S/libkern/strsep.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

strspn.ln: $S/libkern/strspn.c
	${NORMAL_LINT}

strspn.o: $S/libkern/strspn.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

strstr.ln: $S/libkern/strstr.c
	${NORMAL_LINT}

strstr.o: $S/libkern/strstr.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

strtol.ln: $S/libkern/strtol.c
	${NORMAL_LINT}

strtol.o: $S/libkern/strtol.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

strtoq.ln: $S/libkern/strtoq.c
	${NORMAL_LINT}

strtoq.o: $S/libkern/strtoq.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

strtoul.ln: $S/libkern/strtoul.c
	${NORMAL_LINT}

strtoul.o: $S/libkern/strtoul.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

strtouq.ln: $S/libkern/strtouq.c
	${NORMAL_LINT}

strtouq.o: $S/libkern/strtouq.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

strvalid.ln: $S/libkern/strvalid.c
	${NORMAL_LINT}

strvalid.o: $S/libkern/strvalid.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

bpf.ln: $S/net/bpf.c
	${NORMAL_LINT}

bpf.o: $S/net/bpf.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

bpf_buffer.ln: $S/net/bpf_buffer.c
	${NORMAL_LINT}

bpf_buffer.o: $S/net/bpf_buffer.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

bpf_filter.ln: $S/net/bpf_filter.c
	${NORMAL_LINT}

bpf_filter.o: $S/net/bpf_filter.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

bpf_zerocopy.ln: $S/net/bpf_zerocopy.c
	${NORMAL_LINT}

bpf_zerocopy.o: $S/net/bpf_zerocopy.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

if.ln: $S/net/if.c
	${NORMAL_LINT}

if.o: $S/net/if.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

if_clone.ln: $S/net/if_clone.c
	${NORMAL_LINT}

if_clone.o: $S/net/if_clone.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

if_dead.ln: $S/net/if_dead.c
	${NORMAL_LINT}

if_dead.o: $S/net/if_dead.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

if_debug.ln: $S/net/if_debug.c
	${NORMAL_LINT}

if_debug.o: $S/net/if_debug.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

if_ethersubr.ln: $S/net/if_ethersubr.c
	${NORMAL_LINT}

if_ethersubr.o: $S/net/if_ethersubr.c
	${NORMAL_C} -I$S/contrib/pf
	${NORMAL_CTFCONVERT}

if_faith.ln: $S/net/if_faith.c
	${NORMAL_LINT}

if_faith.o: $S/net/if_faith.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

if_gif.ln: $S/net/if_gif.c
	${NORMAL_LINT}

if_gif.o: $S/net/if_gif.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

if_loop.ln: $S/net/if_loop.c
	${NORMAL_LINT}

if_loop.o: $S/net/if_loop.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

if_llatbl.ln: $S/net/if_llatbl.c
	${NORMAL_LINT}

if_llatbl.o: $S/net/if_llatbl.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

if_media.ln: $S/net/if_media.c
	${NORMAL_LINT}

if_media.o: $S/net/if_media.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

if_mib.ln: $S/net/if_mib.c
	${NORMAL_LINT}

if_mib.o: $S/net/if_mib.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

if_tun.ln: $S/net/if_tun.c
	${NORMAL_LINT}

if_tun.o: $S/net/if_tun.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

if_vlan.ln: $S/net/if_vlan.c
	${NORMAL_LINT}

if_vlan.o: $S/net/if_vlan.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

netisr.ln: $S/net/netisr.c
	${NORMAL_LINT}

netisr.o: $S/net/netisr.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

pfil.ln: $S/net/pfil.c
	${NORMAL_LINT}

pfil.o: $S/net/pfil.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

radix.ln: $S/net/radix.c
	${NORMAL_LINT}

radix.o: $S/net/radix.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

radix_mpath.ln: $S/net/radix_mpath.c
	${NORMAL_LINT}

radix_mpath.o: $S/net/radix_mpath.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

raw_cb.ln: $S/net/raw_cb.c
	${NORMAL_LINT}

raw_cb.o: $S/net/raw_cb.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

raw_usrreq.ln: $S/net/raw_usrreq.c
	${NORMAL_LINT}

raw_usrreq.o: $S/net/raw_usrreq.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

route.ln: $S/net/route.c
	${NORMAL_LINT}

route.o: $S/net/route.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

rtsock.ln: $S/net/rtsock.c
	${NORMAL_LINT}

rtsock.o: $S/net/rtsock.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

if_ether.ln: $S/netinet/if_ether.c
	${NORMAL_LINT}

if_ether.o: $S/netinet/if_ether.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

igmp.ln: $S/netinet/igmp.c
	${NORMAL_LINT}

igmp.o: $S/netinet/igmp.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

in.ln: $S/netinet/in.c
	${NORMAL_LINT}

in.o: $S/netinet/in.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

in_debug.ln: $S/netinet/in_debug.c
	${NORMAL_LINT}

in_debug.o: $S/netinet/in_debug.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

in_gif.ln: $S/netinet/in_gif.c
	${NORMAL_LINT}

in_gif.o: $S/netinet/in_gif.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

ip_id.ln: $S/netinet/ip_id.c
	${NORMAL_LINT}

ip_id.o: $S/netinet/ip_id.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

in_mcast.ln: $S/netinet/in_mcast.c
	${NORMAL_LINT}

in_mcast.o: $S/netinet/in_mcast.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

in_pcb.ln: $S/netinet/in_pcb.c
	${NORMAL_LINT}

in_pcb.o: $S/netinet/in_pcb.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

in_proto.ln: $S/netinet/in_proto.c
	${NORMAL_LINT}

in_proto.o: $S/netinet/in_proto.c
	${NORMAL_C} -I$S/contrib/pf
	${NORMAL_CTFCONVERT}

in_rmx.ln: $S/netinet/in_rmx.c
	${NORMAL_LINT}

in_rmx.o: $S/netinet/in_rmx.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

ip_ecn.ln: $S/netinet/ip_ecn.c
	${NORMAL_LINT}

ip_ecn.o: $S/netinet/ip_ecn.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

ip_encap.ln: $S/netinet/ip_encap.c
	${NORMAL_LINT}

ip_encap.o: $S/netinet/ip_encap.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

ip_fastfwd.ln: $S/netinet/ip_fastfwd.c
	${NORMAL_LINT}

ip_fastfwd.o: $S/netinet/ip_fastfwd.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

ip_icmp.ln: $S/netinet/ip_icmp.c
	${NORMAL_LINT}

ip_icmp.o: $S/netinet/ip_icmp.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

ip_input.ln: $S/netinet/ip_input.c
	${NORMAL_LINT}

ip_input.o: $S/netinet/ip_input.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

ip_options.ln: $S/netinet/ip_options.c
	${NORMAL_LINT}

ip_options.o: $S/netinet/ip_options.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

ip_output.ln: $S/netinet/ip_output.c
	${NORMAL_LINT}

ip_output.o: $S/netinet/ip_output.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

raw_ip.ln: $S/netinet/raw_ip.c
	${NORMAL_LINT}

raw_ip.o: $S/netinet/raw_ip.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

cc.ln: $S/netinet/cc/cc.c
	${NORMAL_LINT}

cc.o: $S/netinet/cc/cc.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

cc_newreno.ln: $S/netinet/cc/cc_newreno.c
	${NORMAL_LINT}

cc_newreno.o: $S/netinet/cc/cc_newreno.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

tcp_hostcache.ln: $S/netinet/tcp_hostcache.c
	${NORMAL_LINT}

tcp_hostcache.o: $S/netinet/tcp_hostcache.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

tcp_input.ln: $S/netinet/tcp_input.c
	${NORMAL_LINT}

tcp_input.o: $S/netinet/tcp_input.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

tcp_lro.ln: $S/netinet/tcp_lro.c
	${NORMAL_LINT}

tcp_lro.o: $S/netinet/tcp_lro.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

tcp_output.ln: $S/netinet/tcp_output.c
	${NORMAL_LINT}

tcp_output.o: $S/netinet/tcp_output.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

tcp_offload.ln: $S/netinet/tcp_offload.c
	${NORMAL_LINT}

tcp_offload.o: $S/netinet/tcp_offload.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

tcp_reass.ln: $S/netinet/tcp_reass.c
	${NORMAL_LINT}

tcp_reass.o: $S/netinet/tcp_reass.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

tcp_sack.ln: $S/netinet/tcp_sack.c
	${NORMAL_LINT}

tcp_sack.o: $S/netinet/tcp_sack.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

tcp_subr.ln: $S/netinet/tcp_subr.c
	${NORMAL_LINT}

tcp_subr.o: $S/netinet/tcp_subr.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

tcp_syncache.ln: $S/netinet/tcp_syncache.c
	${NORMAL_LINT}

tcp_syncache.o: $S/netinet/tcp_syncache.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

tcp_timer.ln: $S/netinet/tcp_timer.c
	${NORMAL_LINT}

tcp_timer.o: $S/netinet/tcp_timer.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

tcp_timewait.ln: $S/netinet/tcp_timewait.c
	${NORMAL_LINT}

tcp_timewait.o: $S/netinet/tcp_timewait.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

tcp_usrreq.ln: $S/netinet/tcp_usrreq.c
	${NORMAL_LINT}

tcp_usrreq.o: $S/netinet/tcp_usrreq.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

udp_usrreq.ln: $S/netinet/udp_usrreq.c
	${NORMAL_LINT}

udp_usrreq.o: $S/netinet/udp_usrreq.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

dest6.ln: $S/netinet6/dest6.c
	${NORMAL_LINT}

dest6.o: $S/netinet6/dest6.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

frag6.ln: $S/netinet6/frag6.c
	${NORMAL_LINT}

frag6.o: $S/netinet6/frag6.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

icmp6.ln: $S/netinet6/icmp6.c
	${NORMAL_LINT}

icmp6.o: $S/netinet6/icmp6.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

in6.ln: $S/netinet6/in6.c
	${NORMAL_LINT}

in6.o: $S/netinet6/in6.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

in6_cksum.ln: $S/netinet6/in6_cksum.c
	${NORMAL_LINT}

in6_cksum.o: $S/netinet6/in6_cksum.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

in6_gif.ln: $S/netinet6/in6_gif.c
	${NORMAL_LINT}

in6_gif.o: $S/netinet6/in6_gif.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

in6_ifattach.ln: $S/netinet6/in6_ifattach.c
	${NORMAL_LINT}

in6_ifattach.o: $S/netinet6/in6_ifattach.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

in6_mcast.ln: $S/netinet6/in6_mcast.c
	${NORMAL_LINT}

in6_mcast.o: $S/netinet6/in6_mcast.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

in6_pcb.ln: $S/netinet6/in6_pcb.c
	${NORMAL_LINT}

in6_pcb.o: $S/netinet6/in6_pcb.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

in6_proto.ln: $S/netinet6/in6_proto.c
	${NORMAL_LINT}

in6_proto.o: $S/netinet6/in6_proto.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

in6_rmx.ln: $S/netinet6/in6_rmx.c
	${NORMAL_LINT}

in6_rmx.o: $S/netinet6/in6_rmx.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

in6_src.ln: $S/netinet6/in6_src.c
	${NORMAL_LINT}

in6_src.o: $S/netinet6/in6_src.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

ip6_forward.ln: $S/netinet6/ip6_forward.c
	${NORMAL_LINT}

ip6_forward.o: $S/netinet6/ip6_forward.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

ip6_id.ln: $S/netinet6/ip6_id.c
	${NORMAL_LINT}

ip6_id.o: $S/netinet6/ip6_id.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

ip6_input.ln: $S/netinet6/ip6_input.c
	${NORMAL_LINT}

ip6_input.o: $S/netinet6/ip6_input.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

ip6_output.ln: $S/netinet6/ip6_output.c
	${NORMAL_LINT}

ip6_output.o: $S/netinet6/ip6_output.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

mld6.ln: $S/netinet6/mld6.c
	${NORMAL_LINT}

mld6.o: $S/netinet6/mld6.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

nd6.ln: $S/netinet6/nd6.c
	${NORMAL_LINT}

nd6.o: $S/netinet6/nd6.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

nd6_nbr.ln: $S/netinet6/nd6_nbr.c
	${NORMAL_LINT}

nd6_nbr.o: $S/netinet6/nd6_nbr.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

nd6_rtr.ln: $S/netinet6/nd6_rtr.c
	${NORMAL_LINT}

nd6_rtr.o: $S/netinet6/nd6_rtr.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

raw_ip6.ln: $S/netinet6/raw_ip6.c
	${NORMAL_LINT}

raw_ip6.o: $S/netinet6/raw_ip6.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

route6.ln: $S/netinet6/route6.c
	${NORMAL_LINT}

route6.o: $S/netinet6/route6.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

scope6.ln: $S/netinet6/scope6.c
	${NORMAL_LINT}

scope6.o: $S/netinet6/scope6.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

udp6_usrreq.ln: $S/netinet6/udp6_usrreq.c
	${NORMAL_LINT}

udp6_usrreq.o: $S/netinet6/udp6_usrreq.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

nfs_diskless.ln: $S/nfs/nfs_diskless.c
	${NORMAL_LINT}

nfs_diskless.o: $S/nfs/nfs_diskless.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

nfs_lock.ln: $S/nfs/nfs_lock.c
	${NORMAL_LINT}

nfs_lock.o: $S/nfs/nfs_lock.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

nfs_nfssvc.ln: $S/nfs/nfs_nfssvc.c
	${NORMAL_LINT}

nfs_nfssvc.o: $S/nfs/nfs_nfssvc.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

nlm_advlock.ln: $S/nlm/nlm_advlock.c
	${NORMAL_LINT}

nlm_advlock.o: $S/nlm/nlm_advlock.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

nlm_prot_clnt.ln: $S/nlm/nlm_prot_clnt.c
	${NORMAL_LINT}

nlm_prot_clnt.o: $S/nlm/nlm_prot_clnt.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

nlm_prot_impl.ln: $S/nlm/nlm_prot_impl.c
	${NORMAL_LINT}

nlm_prot_impl.o: $S/nlm/nlm_prot_impl.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

nlm_prot_server.ln: $S/nlm/nlm_prot_server.c
	${NORMAL_LINT}

nlm_prot_server.o: $S/nlm/nlm_prot_server.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

nlm_prot_svc.ln: $S/nlm/nlm_prot_svc.c
	${NORMAL_LINT}

nlm_prot_svc.o: $S/nlm/nlm_prot_svc.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

nlm_prot_xdr.ln: $S/nlm/nlm_prot_xdr.c
	${NORMAL_LINT}

nlm_prot_xdr.o: $S/nlm/nlm_prot_xdr.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

sm_inter_xdr.ln: $S/nlm/sm_inter_xdr.c
	${NORMAL_LINT}

sm_inter_xdr.o: $S/nlm/sm_inter_xdr.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

auth_none.ln: $S/rpc/auth_none.c
	${NORMAL_LINT}

auth_none.o: $S/rpc/auth_none.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

auth_unix.ln: $S/rpc/auth_unix.c
	${NORMAL_LINT}

auth_unix.o: $S/rpc/auth_unix.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

authunix_prot.ln: $S/rpc/authunix_prot.c
	${NORMAL_LINT}

authunix_prot.o: $S/rpc/authunix_prot.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

clnt_dg.ln: $S/rpc/clnt_dg.c
	${NORMAL_LINT}

clnt_dg.o: $S/rpc/clnt_dg.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

clnt_rc.ln: $S/rpc/clnt_rc.c
	${NORMAL_LINT}

clnt_rc.o: $S/rpc/clnt_rc.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

clnt_vc.ln: $S/rpc/clnt_vc.c
	${NORMAL_LINT}

clnt_vc.o: $S/rpc/clnt_vc.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

getnetconfig.ln: $S/rpc/getnetconfig.c
	${NORMAL_LINT}

getnetconfig.o: $S/rpc/getnetconfig.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

replay.ln: $S/rpc/replay.c
	${NORMAL_LINT}

replay.o: $S/rpc/replay.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

rpc_callmsg.ln: $S/rpc/rpc_callmsg.c
	${NORMAL_LINT}

rpc_callmsg.o: $S/rpc/rpc_callmsg.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

rpc_generic.ln: $S/rpc/rpc_generic.c
	${NORMAL_LINT}

rpc_generic.o: $S/rpc/rpc_generic.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

rpc_prot.ln: $S/rpc/rpc_prot.c
	${NORMAL_LINT}

rpc_prot.o: $S/rpc/rpc_prot.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

rpcb_clnt.ln: $S/rpc/rpcb_clnt.c
	${NORMAL_LINT}

rpcb_clnt.o: $S/rpc/rpcb_clnt.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

rpcb_prot.ln: $S/rpc/rpcb_prot.c
	${NORMAL_LINT}

rpcb_prot.o: $S/rpc/rpcb_prot.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

svc.ln: $S/rpc/svc.c
	${NORMAL_LINT}

svc.o: $S/rpc/svc.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

svc_auth.ln: $S/rpc/svc_auth.c
	${NORMAL_LINT}

svc_auth.o: $S/rpc/svc_auth.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

svc_auth_unix.ln: $S/rpc/svc_auth_unix.c
	${NORMAL_LINT}

svc_auth_unix.o: $S/rpc/svc_auth_unix.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

svc_dg.ln: $S/rpc/svc_dg.c
	${NORMAL_LINT}

svc_dg.o: $S/rpc/svc_dg.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

svc_generic.ln: $S/rpc/svc_generic.c
	${NORMAL_LINT}

svc_generic.o: $S/rpc/svc_generic.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

svc_vc.ln: $S/rpc/svc_vc.c
	${NORMAL_LINT}

svc_vc.o: $S/rpc/svc_vc.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

audit.ln: $S/security/audit/audit.c
	${NORMAL_LINT}

audit.o: $S/security/audit/audit.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

audit_arg.ln: $S/security/audit/audit_arg.c
	${NORMAL_LINT}

audit_arg.o: $S/security/audit/audit_arg.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

audit_bsm.ln: $S/security/audit/audit_bsm.c
	${NORMAL_LINT}

audit_bsm.o: $S/security/audit/audit_bsm.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

audit_bsm_domain.ln: $S/security/audit/audit_bsm_domain.c
	${NORMAL_LINT}

audit_bsm_domain.o: $S/security/audit/audit_bsm_domain.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

audit_bsm_errno.ln: $S/security/audit/audit_bsm_errno.c
	${NORMAL_LINT}

audit_bsm_errno.o: $S/security/audit/audit_bsm_errno.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

audit_bsm_fcntl.ln: $S/security/audit/audit_bsm_fcntl.c
	${NORMAL_LINT}

audit_bsm_fcntl.o: $S/security/audit/audit_bsm_fcntl.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

audit_bsm_klib.ln: $S/security/audit/audit_bsm_klib.c
	${NORMAL_LINT}

audit_bsm_klib.o: $S/security/audit/audit_bsm_klib.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

audit_bsm_socket_type.ln: $S/security/audit/audit_bsm_socket_type.c
	${NORMAL_LINT}

audit_bsm_socket_type.o: $S/security/audit/audit_bsm_socket_type.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

audit_bsm_token.ln: $S/security/audit/audit_bsm_token.c
	${NORMAL_LINT}

audit_bsm_token.o: $S/security/audit/audit_bsm_token.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

audit_pipe.ln: $S/security/audit/audit_pipe.c
	${NORMAL_LINT}

audit_pipe.o: $S/security/audit/audit_pipe.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

audit_syscalls.ln: $S/security/audit/audit_syscalls.c
	${NORMAL_LINT}

audit_syscalls.o: $S/security/audit/audit_syscalls.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

audit_trigger.ln: $S/security/audit/audit_trigger.c
	${NORMAL_LINT}

audit_trigger.o: $S/security/audit/audit_trigger.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

audit_worker.ln: $S/security/audit/audit_worker.c
	${NORMAL_LINT}

audit_worker.o: $S/security/audit/audit_worker.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

mac_syscalls.ln: $S/security/mac/mac_syscalls.c
	${NORMAL_LINT}

mac_syscalls.o: $S/security/mac/mac_syscalls.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

ffs_alloc.ln: $S/ufs/ffs/ffs_alloc.c
	${NORMAL_LINT}

ffs_alloc.o: $S/ufs/ffs/ffs_alloc.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

ffs_balloc.ln: $S/ufs/ffs/ffs_balloc.c
	${NORMAL_LINT}

ffs_balloc.o: $S/ufs/ffs/ffs_balloc.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

ffs_inode.ln: $S/ufs/ffs/ffs_inode.c
	${NORMAL_LINT}

ffs_inode.o: $S/ufs/ffs/ffs_inode.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

ffs_snapshot.ln: $S/ufs/ffs/ffs_snapshot.c
	${NORMAL_LINT}

ffs_snapshot.o: $S/ufs/ffs/ffs_snapshot.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

ffs_softdep.ln: $S/ufs/ffs/ffs_softdep.c
	${NORMAL_LINT}

ffs_softdep.o: $S/ufs/ffs/ffs_softdep.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

ffs_subr.ln: $S/ufs/ffs/ffs_subr.c
	${NORMAL_LINT}

ffs_subr.o: $S/ufs/ffs/ffs_subr.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

ffs_tables.ln: $S/ufs/ffs/ffs_tables.c
	${NORMAL_LINT}

ffs_tables.o: $S/ufs/ffs/ffs_tables.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

ffs_vfsops.ln: $S/ufs/ffs/ffs_vfsops.c
	${NORMAL_LINT}

ffs_vfsops.o: $S/ufs/ffs/ffs_vfsops.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

ffs_vnops.ln: $S/ufs/ffs/ffs_vnops.c
	${NORMAL_LINT}

ffs_vnops.o: $S/ufs/ffs/ffs_vnops.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

ufs_acl.ln: $S/ufs/ufs/ufs_acl.c
	${NORMAL_LINT}

ufs_acl.o: $S/ufs/ufs/ufs_acl.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

ufs_bmap.ln: $S/ufs/ufs/ufs_bmap.c
	${NORMAL_LINT}

ufs_bmap.o: $S/ufs/ufs/ufs_bmap.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

ufs_dirhash.ln: $S/ufs/ufs/ufs_dirhash.c
	${NORMAL_LINT}

ufs_dirhash.o: $S/ufs/ufs/ufs_dirhash.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

ufs_extattr.ln: $S/ufs/ufs/ufs_extattr.c
	${NORMAL_LINT}

ufs_extattr.o: $S/ufs/ufs/ufs_extattr.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

ufs_gjournal.ln: $S/ufs/ufs/ufs_gjournal.c
	${NORMAL_LINT}

ufs_gjournal.o: $S/ufs/ufs/ufs_gjournal.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

ufs_inode.ln: $S/ufs/ufs/ufs_inode.c
	${NORMAL_LINT}

ufs_inode.o: $S/ufs/ufs/ufs_inode.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

ufs_lookup.ln: $S/ufs/ufs/ufs_lookup.c
	${NORMAL_LINT}

ufs_lookup.o: $S/ufs/ufs/ufs_lookup.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

ufs_quota.ln: $S/ufs/ufs/ufs_quota.c
	${NORMAL_LINT}

ufs_quota.o: $S/ufs/ufs/ufs_quota.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

ufs_vfsops.ln: $S/ufs/ufs/ufs_vfsops.c
	${NORMAL_LINT}

ufs_vfsops.o: $S/ufs/ufs/ufs_vfsops.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

ufs_vnops.ln: $S/ufs/ufs/ufs_vnops.c
	${NORMAL_LINT}

ufs_vnops.o: $S/ufs/ufs/ufs_vnops.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

default_pager.ln: $S/vm/default_pager.c
	${NORMAL_LINT}

default_pager.o: $S/vm/default_pager.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

device_pager.ln: $S/vm/device_pager.c
	${NORMAL_LINT}

device_pager.o: $S/vm/device_pager.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

phys_pager.ln: $S/vm/phys_pager.c
	${NORMAL_LINT}

phys_pager.o: $S/vm/phys_pager.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

sg_pager.ln: $S/vm/sg_pager.c
	${NORMAL_LINT}

sg_pager.o: $S/vm/sg_pager.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

swap_pager.ln: $S/vm/swap_pager.c
	${NORMAL_LINT}

swap_pager.o: $S/vm/swap_pager.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

uma_core.ln: $S/vm/uma_core.c
	${NORMAL_LINT}

uma_core.o: $S/vm/uma_core.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

uma_dbg.ln: $S/vm/uma_dbg.c
	${NORMAL_LINT}

uma_dbg.o: $S/vm/uma_dbg.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

vm_contig.ln: $S/vm/vm_contig.c
	${NORMAL_LINT}

vm_contig.o: $S/vm/vm_contig.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

vm_fault.ln: $S/vm/vm_fault.c
	${NORMAL_LINT}

vm_fault.o: $S/vm/vm_fault.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

vm_glue.ln: $S/vm/vm_glue.c
	${NORMAL_LINT}

vm_glue.o: $S/vm/vm_glue.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

vm_init.ln: $S/vm/vm_init.c
	${NORMAL_LINT}

vm_init.o: $S/vm/vm_init.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

vm_kern.ln: $S/vm/vm_kern.c
	${NORMAL_LINT}

vm_kern.o: $S/vm/vm_kern.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

vm_map.ln: $S/vm/vm_map.c
	${NORMAL_LINT}

vm_map.o: $S/vm/vm_map.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

vm_meter.ln: $S/vm/vm_meter.c
	${NORMAL_LINT}

vm_meter.o: $S/vm/vm_meter.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

vm_mmap.ln: $S/vm/vm_mmap.c
	${NORMAL_LINT}

vm_mmap.o: $S/vm/vm_mmap.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

vm_object.ln: $S/vm/vm_object.c
	${NORMAL_LINT}

vm_object.o: $S/vm/vm_object.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

vm_page.ln: $S/vm/vm_page.c
	${NORMAL_LINT}

vm_page.o: $S/vm/vm_page.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

vm_pageout.ln: $S/vm/vm_pageout.c
	${NORMAL_LINT}

vm_pageout.o: $S/vm/vm_pageout.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

vm_pager.ln: $S/vm/vm_pager.c
	${NORMAL_LINT}

vm_pager.o: $S/vm/vm_pager.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

vm_phys.ln: $S/vm/vm_phys.c
	${NORMAL_LINT}

vm_phys.o: $S/vm/vm_phys.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

vm_reserv.ln: $S/vm/vm_reserv.c
	${NORMAL_LINT}

vm_reserv.o: $S/vm/vm_reserv.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

vm_unix.ln: $S/vm/vm_unix.c
	${NORMAL_LINT}

vm_unix.o: $S/vm/vm_unix.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

vm_zeroidle.ln: $S/vm/vm_zeroidle.c
	${NORMAL_LINT}

vm_zeroidle.o: $S/vm/vm_zeroidle.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

vnode_pager.ln: $S/vm/vnode_pager.c
	${NORMAL_LINT}

vnode_pager.o: $S/vm/vnode_pager.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

xdr.ln: $S/xdr/xdr.c
	${NORMAL_LINT}

xdr.o: $S/xdr/xdr.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

xdr_array.ln: $S/xdr/xdr_array.c
	${NORMAL_LINT}

xdr_array.o: $S/xdr/xdr_array.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

xdr_mbuf.ln: $S/xdr/xdr_mbuf.c
	${NORMAL_LINT}

xdr_mbuf.o: $S/xdr/xdr_mbuf.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

xdr_mem.ln: $S/xdr/xdr_mem.c
	${NORMAL_LINT}

xdr_mem.o: $S/xdr/xdr_mem.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

xdr_reference.ln: $S/xdr/xdr_reference.c
	${NORMAL_LINT}

xdr_reference.o: $S/xdr/xdr_reference.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}

xdr_sizeof.ln: $S/xdr/xdr_sizeof.c
	${NORMAL_LINT}

xdr_sizeof.o: $S/xdr/xdr_sizeof.c
	${NORMAL_C}

	${NORMAL_CTFCONVERT}


#.include "$S/conf/kern.post.mk"
