// some of this is copied from various parts of kernel source tree,
// github issues, etc etc
//
// you will probably need to add and augment this for your project

// https://github.com/iovisor/bcc/issues/2119
#ifdef asm_volatile_goto
#undef asm_volatile_goto
#endif
#define asm_volatile_goto(x...) asm volatile("invalid use of asm_volatile_goto")

// include any headers you will need to import from kernel
#include <linux/kconfig.h>
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>

// section naming sugar
#define SEC(NAME) __attribute__((section(NAME), used))

// LOCK XADD sugar
#ifndef lock_xadd
# define lock_xadd(ptr, val)              \
    ((void)__sync_fetch_and_add(ptr, val))
#endif

// what a map looks like
struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
    unsigned int inner_map_idx;
    unsigned int numa_node;
};

/* helper functions called from eBPF programs written in C */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) =
	(void *) BPF_FUNC_map_lookup_elem;
static int (*bpf_map_update_elem)(void *map, const void *key, const void *value,
        unsigned long long flags) =
	(void *) BPF_FUNC_map_update_elem;
static int (*bpf_map_delete_elem)(void *map, const void *key) =
        (void *) BPF_FUNC_map_delete_elem;
static unsigned long long (*bpf_get_current_task)(void) =
	(void *) BPF_FUNC_get_current_task;
static int (*bpf_probe_read)(void *dst, int size, void *unsafe_ptr) =
	(void *) BPF_FUNC_probe_read;
static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) =
	(void *) BPF_FUNC_trace_printk;
static unsigned long long (*bpf_ktime_get_ns)(void) =
	(void *) BPF_FUNC_ktime_get_ns;
static unsigned long long (*bpf_get_current_pid_tgid)(void) =
        (void *) BPF_FUNC_get_current_pid_tgid;

// helpers pulled across from bcc project
static inline __attribute__((always_inline))                                    
unsigned int bpf_log2(unsigned int v)                                           
{                                                                               
  unsigned int r;                                                               
  unsigned int shift;                                                           
                                                                                
  r = (v > 0xFFFF) << 4; v >>= r;                                               
  shift = (v > 0xFF) << 3; v >>= shift; r |= shift;                             
  shift = (v > 0xF) << 2; v >>= shift; r |= shift;                              
  shift = (v > 0x3) << 1; v >>= shift; r |= shift;                              
  r |= (v >> 1);                                                                
  return r;                                                                     
}                                                                               
                                                                                
static inline __attribute__((always_inline))                                    
unsigned int bpf_log2l(unsigned long v)                                         
{                                                                               
  unsigned int hi = v >> 32;                                                    
  if (hi)                                                                       
    return bpf_log2(hi) + 32 + 1;                                               
  else                                                                          
    return bpf_log2(v) + 1;                                                     
}                                                                               

