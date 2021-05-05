#include "common.h"
#include "bpf_helpers.h"

/***/

char __license[] SEC("license") = "Dual MIT/GPL";


/* Rhis buffer is filled with literal CPU IDs so the program can easily get
 * the current CPU. This can then key into a BPF_MAP_TYPE_ARRAY, which doesn't
 * have a 32KB limitation like BPF_MAP_TYPE_PERCPU_ARRAY.
 * This is all a hack, and should be replaced with ringbuf, except this is
 * compatible with older kernels for now.
 */
struct bpf_map_def cpu_to_index SEC("maps") = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
	.max_entries = 1,
};
#define MAX_CPU 128

#define MAX_STACK_LEN (48<<10)

struct ruby_span_extra {
  u64 ns_since_end;

  u64 rb_stack_len;
  const char *rb_stack;

  u64 metadata_len;
  const char *metadata;
};

struct event {
	u64 pid, tid;

	u64 time_emit_nsec;
	u64 end_delta_nsec;
	u64 duration_nsec;
	char span_item[64];
	char span_name[64];

	char span_context[8192];

	char rb_stack[MAX_STACK_LEN];
};

struct bpf_map_def span_events SEC("maps") = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
};

struct bpf_map_def span_heap SEC("maps") = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct event),
	.max_entries = MAX_CPU,
};

#define usdt_arg_preamble(arg_index, name) \
	{ \
		name = 0; \
		void *arg; \
    	asm volatile("%0 = %1; %0 += %2" : "=r"(arg) : "r"(ctx->rsp), "i"(0xFF00 + arg_index)); \
		if (bpf_probe_read(&name, sizeof(name), arg) != 0) return 0; \
	}

SEC("uprobe/ruby__span")
int tracecap_ruby__span(struct pt_regs *ctx) {
	u64 duration;
	char *component;
	char *description;
	struct ruby_span_extra *context;
	usdt_arg_preamble(0, duration);
	usdt_arg_preamble(1, component);
	usdt_arg_preamble(2, description);
	usdt_arg_preamble(3, context);

    u64 len = 0;
    u32 zero = 0;
	int ret;
    u32 *giant_heap_index = bpf_map_lookup_elem(&cpu_to_index, &zero);
    if (giant_heap_index == 0) return 0;

	struct event *lheap = bpf_map_lookup_elem(&span_heap, giant_heap_index);
	if (lheap == 0) return 0;

	u64 pid_tgid = bpf_get_current_pid_tgid();
	lheap->pid = pid_tgid >> 32;
	lheap->tid = pid_tgid & 0xffffffff;

	bpf_probe_read_str(&lheap->span_item, sizeof(lheap->span_item), component);
	bpf_probe_read_str(&lheap->span_name, sizeof(lheap->span_name), description);

	lheap->time_emit_nsec = bpf_ktime_get_ns();
	lheap->duration_nsec = duration;

	struct ruby_span_extra st_context;
	bpf_probe_read(&st_context, sizeof(struct ruby_span_extra), context);

	lheap->end_delta_nsec = st_context.ns_since_end;

	len = st_context.metadata_len;
    if (len > sizeof(lheap->span_context) - 1)
        len = sizeof(lheap->span_context) - 1;
    ret = bpf_probe_read(lheap->span_context, len, (void *)st_context.metadata);
	if (len >= 0)
		lheap->span_context[len] = 0;
	
	len = st_context.rb_stack_len;
    if (len > sizeof(lheap->rb_stack) - 1)
        len = sizeof(lheap->rb_stack) - 1;
    ret = bpf_probe_read(lheap->rb_stack, len, (void *)st_context.rb_stack);
	if (len >= 0)
		lheap->rb_stack[len] = 0;

	bpf_perf_event_output(ctx, &span_events, BPF_F_CURRENT_CPU, lheap, sizeof(struct event));

    return 0;
}

struct ruby_sample {
    struct {
        u64 total;
        u64 free;
    } object_space;
};

struct profile {
	u64 pid, tid;

	u64 time_emit_nsec;

	u64 object_space_free;
	u64 object_space_total;

	char rb_stack[MAX_STACK_LEN];
};

struct bpf_map_def profile_events SEC("maps") = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
};

struct bpf_map_def prof_heap SEC("maps") = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct profile),
	.max_entries = MAX_CPU,
};

SEC("uprobe/ruby__sample__std")
int tracecap_ruby__sample__std(struct pt_regs *ctx) {
	struct ruby_sample *sample_ptr;
	u64 stack_len;
	char *stack;
	usdt_arg_preamble(0, sample_ptr);
	usdt_arg_preamble(1, stack_len);
	usdt_arg_preamble(2, stack);

    u32 zero = 0;
	int ret;

	u32 *giant_heap_index = bpf_map_lookup_elem(&cpu_to_index, &zero);
    if (giant_heap_index == 0) return 0;

	struct profile *pheap = bpf_map_lookup_elem(&prof_heap, giant_heap_index);
    if (pheap == 0) return 0;

	u64 pid_tgid = bpf_get_current_pid_tgid();
	pheap->pid = pid_tgid >> 32;
	pheap->tid = pid_tgid & 0xffffffff;

	pheap->time_emit_nsec = bpf_ktime_get_ns();

	if (stack_len > sizeof(pheap->rb_stack) - 1)
		stack_len = sizeof(pheap->rb_stack) - 1;
	bpf_probe_read(&pheap->rb_stack, stack_len, stack);

	struct ruby_sample sample;
	bpf_probe_read(&sample, sizeof(sample), sample_ptr);

	pheap->object_space_free = sample.object_space.free;
	pheap->object_space_total = sample.object_space.total;

	bpf_perf_event_output(ctx, &profile_events, BPF_F_CURRENT_CPU, pheap, sizeof(struct profile));

	return 0;
}
