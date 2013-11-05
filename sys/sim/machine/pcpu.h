#undef PCPU_GET
#define	PCPU_GET(member)	(__pcpu.pc_ ## member)
#undef PCPU_ADD
#define	PCPU_ADD(member, val)	(__pcpu.pc_ ## member, += (val))
#undef PCPU_INC
#define	PCPU_INC(member)	PCPU_ADD(__pcpu.pc_ ## member, 1)
#undef PCPU_PTR
#define	PCPU_PTR(member)	(&(__pcpu.pc_ ## member))
#undef PCPU_SET
#define	PCPU_SET(member, val)	(__pcpu.pc_ ## member = val)
#undef curthread
#define curthread __pcpu.pc_curthread
