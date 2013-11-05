#\n\
# GENERIC -- Generic kernel configuration file for FreeBSD/amd64\n\
#\n\
# For more information on this file, please read the config(5) manual page,\n\
# and/or the handbook section on Kernel Configuration Files:\n\
#\n\
#    http://www.FreeBSD.org/doc/en_US.ISO8859-1/books/handbook/kernelconfig-config.html\n\
#\n\
# The handbook is also available locally in /usr/share/doc/handbook\n\
# if you\'ve installed the doc distribution, otherwise always see the\n\
# FreeBSD World Wide Web server (http://www.FreeBSD.org/) for the\n\
# latest information.\n\
#\n\
# An exhaustive list of options and more detailed explanations of the\n\
# device lines is also present in the ../../conf/NOTES and NOTES files.\n\
# If you are in doubt as to the purpose or necessity of a line, check first\n\
# in NOTES.\n\
#\n\
# $FreeBSD$\n\
\n\
machine		sim\n\
cpu		SIMCPU\n\
ident		DCE\n\
\n\
makeoptions	DEBUG=-g		# Build kernel with gdb(1) debug symbols\n\
\n\
options 	SCHED_ULE		# ULE scheduler\n\
options 	PREEMPTION		# Enable kernel thread preemption\n\
options 	INET			# InterNETworking\n\
options 	INET6			# IPv6 communications protocols\n\
\n\
options 	FFS			# Berkeley Fast Filesystem\n\
options 	SOFTUPDATES		# Enable FFS soft updates support\n\
options 	UFS_ACL			# Support for access control lists\n\
options 	UFS_DIRHASH		# Improve performance on big directories\n\
options 	UFS_GJOURNAL		# Enable gjournal-based UFS journaling\n\
options 	MD_ROOT			# MD is a potential root device\n\
options 	NFSCL			# New Network Filesystem Client\n\
options 	NFSD			# New Network Filesystem Server\n\
options 	NFSLOCKD		# Network Lock Manager\n\
options 	NFS_ROOT		# NFS usable as /, requires NFSCL\n\
options 	MSDOSFS			# MSDOS Filesystem\n\
options 	CD9660			# ISO 9660 Filesystem\n\
options 	PROCFS			# Process filesystem (requires PSEUDOFS)\n\
options 	PSEUDOFS		# Pseudo-filesystem framework\n\
options 	GEOM_PART_GPT		# GUID Partition Tables.\n\
options 	GEOM_LABEL		# Provides labelization\n\
options 	COMPAT_FREEBSD4		# Compatible with FreeBSD4\n\
options 	COMPAT_FREEBSD5		# Compatible with FreeBSD5\n\
options 	COMPAT_FREEBSD6		# Compatible with FreeBSD6\n\
options 	COMPAT_FREEBSD7		# Compatible with FreeBSD7\n\
options 	SCSI_DELAY=5000		# Delay (in ms) before probing SCSI\n\
options 	KTRACE			# ktrace(1) support\n\
options 	STACK			# stack(9) support\n\
options 	SYSVSHM			# SYSV-style shared memory\n\
options 	SYSVMSG			# SYSV-style message queues\n\
options 	SYSVSEM			# SYSV-style semaphores\n\
options 	_KPOSIX_PRIORITY_SCHEDULING # POSIX P1003_1B real-time extensions\n\
options 	PRINTF_BUFR_SIZE=128	# Prevent printf output being interspersed.\n\
options 	KBD_INSTALL_CDEV	# install a CDEV entry in /dev\n\
options 	HWPMC_HOOKS		# Necessary kernel hooks for hwpmc(4)\n\
options 	AUDIT			# Security event auditing\n\
options 	CAPABILITY_MODE		# Capsicum capability mode\n\
options 	CAPABILITIES		# Capsicum capabilities\n\
\n\
#options 	KDTRACE_FRAME		# Ensure frames are compiled in\n\
#options 	KDTRACE_HOOKS		# Kernel DTrace hooks\n\
options 	INCLUDE_CONFIG_FILE     # Include this file in kernel\n\
\n\
# Debugging support.  Always need this:\n\
options 	KDB			# Enable kernel debugger support.\n\
# For minimum debugger support (stable branch) use:\n\
#options 	KDB_TRACE		# Print a stack trace for a panic.\n\
# For full debugger support use this instead:\n\
options 	DDB			# Support DDB.\n\
options 	GDB			# Support remote GDB.\n\
options 	DEADLKRES		# Enable the deadlock resolver\n\
options 	INVARIANTS		# Enable calls of extra sanity checking\n\
options 	INVARIANT_SUPPORT	# Extra sanity checks of internal structures, required by INVARIANTS\n\
options 	WITNESS			# Enable checks to detect deadlocks and cycles\n\
options 	WITNESS_SKIPSPIN	# Don\'t run witness on spinlocks for speed\n\
options 	MALLOC_DEBUG_MAXZONES=8	# Separate malloc(9) zones\n\
\n\
\n\
# CPU frequency control\n\
device		cpufreq\n\
\n\
\n\
# Pseudo devices.\n\
device		loop		# Network loopback\n\
device		random		# Entropy device\n\
device		ether		# Ethernet support\n\
device		vlan		# 802.1Q VLAN support\n\
device		tun		# Packet tunnel.\n\
device		pty		# BSD-style compatibility pseudo ttys\n\
device		md		# Memory \"disks\"\n\
device		gif		# IPv6 and IPv4 tunneling\n\
device		faith		# IPv6-to-IPv4 relaying (translation)\n\
device		firmware	# firmware assist module\n\
\n\
# The `bpf\' device enables the Berkeley Packet Filter.\n\
# Be aware of the administrative consequences of enabling this!\n\
# Note that \'bpf\' is required for DHCP.\n\
device		bpf		# Berkeley packet filter\n\
\n\
