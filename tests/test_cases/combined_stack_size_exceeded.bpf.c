#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* Map per le tail calls */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 32);
    __type(key, __u32);
    __type(value, __u32);
} tail_call_map SEC(".maps");

#define FORCE_STACK_USAGE(buf, size)           \
    do {                                      \
        volatile unsigned char* _buf = buf;   \
        int _tmp = 0;                         \
        /* disable unroll per garantire che il loop rimanga */ \
        _Pragma("clang loop unroll(disable)") \
        for (int _i = 0; _i < size; _i++) {  \
            _buf[_i] = 0;                     \
            _tmp += _buf[_i];                 \
        }                                     \
        _buf[0] = 0;                          \
        _buf[size-1] = 0;                     \
        /* operazione fittizia per mantenere tmp vivo */ \
        _tmp += _buf[size/2];                 \
    } while(0)


static __noinline int create_deep_call_chain(struct __sk_buff *skb)
{
    char buffer[150];  
    FORCE_STACK_USAGE(buffer, 150);
    
    return 0;
}

SEC("tc")
int main_program(struct __sk_buff *skb)
{
    char main_buffer[500]; 
    FORCE_STACK_USAGE(main_buffer, 500);
    
    return create_deep_call_chain(skb);
}


char _license[] SEC("license") = "GPL";
