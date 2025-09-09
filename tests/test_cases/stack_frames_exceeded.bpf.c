#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 32);
    __type(key, __u32);
    __type(value, __u32);
} tail_call_map SEC(".maps");

struct large_struct {
    char data[512];
    int counters[64];
    long values[32];
};

static __noinline int level_10(struct __sk_buff *skb)
{
    struct large_struct s;
    __builtin_memset(&s, 0, sizeof(s));
    
    bpf_tail_call(skb, &tail_call_map, 1);
    return 0;
}

static __noinline int level_9(struct __sk_buff *skb)
{
    struct large_struct s;
    __builtin_memset(&s, 0, sizeof(s));
    return level_10(skb);
}

static __noinline int level_8(struct __sk_buff *skb)
{
    struct large_struct s;
    __builtin_memset(&s, 0, sizeof(s));
    return level_9(skb);
}

static __noinline int level_7(struct __sk_buff *skb)
{
    struct large_struct s;
    __builtin_memset(&s, 0, sizeof(s));
    return level_8(skb);
}

static __noinline int level_6(struct __sk_buff *skb)
{
    struct large_struct s;
    __builtin_memset(&s, 0, sizeof(s));
    return level_7(skb);
}

static __noinline int level_5(struct __sk_buff *skb)
{
    struct large_struct s;
    __builtin_memset(&s, 0, sizeof(s));
    return level_6(skb);
}

static __noinline int level_4(struct __sk_buff *skb)
{
    struct large_struct s;
    __builtin_memset(&s, 0, sizeof(s));
    return level_5(skb);
}

static __noinline int level_3(struct __sk_buff *skb)
{
    struct large_struct s;
    __builtin_memset(&s, 0, sizeof(s));
    return level_4(skb);
}

static __noinline int level_2(struct __sk_buff *skb)
{
    struct large_struct s;
    __builtin_memset(&s, 0, sizeof(s));
    return level_3(skb);
}

static __noinline int level_1(struct __sk_buff *skb)
{
    struct large_struct s;
    __builtin_memset(&s, 0, sizeof(s));
    return level_2(skb);
}

SEC("tc")
int main_program(struct __sk_buff *skb)
{
    struct large_struct s;
    __builtin_memset(&s, 0, sizeof(s));
    
    return level_1(skb);
}

SEC("tc")
int tail_call_target(struct __sk_buff *skb)
{
    return 0;
}

char _license[] SEC("license") = "GPL";
