#!/usr/bin/env python3

###########################################################################################################
# Copyright (C) 2023 Intel Corporation
# SPDX-License-Identifier: MIT
###########################################################################################################

from __future__ import division
from __future__ import print_function
from time import sleep
from datetime import datetime
import argparse
import signal
import os
from struct import unpack
import resource
import sys
import yaml

try:
    from bcc import BPF, Perf, PerfType
except (ModuleNotFoundError, ImportError):
    print(
        "BCC modules (BPF, Perf, & PerfType) are not installed. Did you compile and build BCC from the source? https://github.com/iovisor/bcc/blob/master/INSTALL.md#source"
    )
    sys.exit(1)

userid = os.geteuid()
if userid != 0:
    print(
        "Root privileges are needed to run this script.\nPlease try again using 'sudo'. Exiting."
    )
    sys.exit(1)

parser = argparse.ArgumentParser(
    description="eBPF based Core metrics by PID",
    formatter_class=argparse.RawDescriptionHelpFormatter,
)
parser.add_argument(
    "-f",
    "--sample_freq",
    type=int,
    default=10000000,
    help="Sample one in this many number of events",
)
parser.add_argument("-d", "--duration", type=int, help="duration")
parser.add_argument("-i", "--interval", type=int, default=1, help="interval in seconds")
parser.add_argument(
    "--aggregate_cpus",
    action="store_true",
    help="Aggregate all the counters across CPUs, the cpu field will be set to zero for all PIDs/Containers",
)
parser.add_argument(
    "--aggregate_cgroup",
    action="store_true",
    help="Aggregate all the counters on cgroup level, every container will then have a single row",
)
parser.add_argument(
    "--acc",
    action="store_true",
    help="collect events in accumulate mode. If not set, all counter cleared in each round",
)
parser.add_argument(
    "-v", "--verbose", action="store_true", help="show raw counters in every interval"
)
parser.add_argument("--ebpf", action="store_true", help=argparse.SUPPRESS)
args = parser.parse_args()

interval = float(args.interval)
duration = args.duration

# Read events names and codes from events.yaml
events_file_path = "events.yaml"
check_file = os.path.exists(events_file_path)
if not check_file:
    print("events.yaml files is not present in the directory. Exiting..")
    sys.exit("events.yaml file does not exist!")

with open(events_file_path) as f:
    try:
        events = yaml.safe_load(f)["events"]

    except yaml.scanner.ScannerError:
        print("Format error in " + events_file_path + ". Exiting..")
        sys.exit("Format error")


# Increase open file limits
if args.verbose:
    print(
        "Setting open files limit to 10K. The limit should increase for more cores and/or groups"
    )

resource.setrlimit(resource.RLIMIT_NOFILE, (10000, 10000))


# Get processor information
def get_cpuinfo():
    cpuinfo = []
    temp_dict = {}
    try:
        file_getcpuinfo = open("/proc/cpuinfo", "r")
    except OSError as err:
        print("OS error: {0}".format(err))
        sys.exit("OS error")
    else:
        for line in file_getcpuinfo:
            try:
                key, value = list(map(str.strip, line.split(":", 1)))
            except ValueError:
                cpuinfo.append(temp_dict)
                temp_dict = {}
            else:
                temp_dict[key] = value
        file_getcpuinfo.close()
    return cpuinfo


# Get current architecture and check if it supports OCR counters
def check_OCR_support():
    procinfo_arch = get_cpuinfo()
    # check procinfo_arch is not empty and contains model, cpu family, and stepping
    assert len(procinfo_arch) > 0
    assert "model" in procinfo_arch[0]
    assert "cpu family" in procinfo_arch[0]
    assert "stepping" in procinfo_arch[0]

    model = int(procinfo_arch[0]["model"].strip())
    cpufamily = int(procinfo_arch[0]["cpu family"].strip())
    stepping = int(procinfo_arch[0]["stepping"].strip())
    if model == 106 and cpufamily == 6 and stepping >= 0:
        current_arch = "icelake"
    elif model == 143 and cpufamily == 6 and stepping >= 3:
        current_arch = "sapphirerapid"
    elif model == 85 and cpufamily == 6 and (4 <= stepping < 10):
        current_arch = "cascadelake/skylake"
    else:
        print(
            "Current architecture does not support OCR counters. OCR counters are supported in Cascadelake/Icelake/SapphireRapid architectures."
        )
        # if system does not support OCR counters, call sys.exit()
        sys.exit("System not supported")

    print("Architecture: ", current_arch.upper(), " has OCR support!")
    return current_arch, True


# load BPF program
bpf_text = """
#include <linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/init_task.h>

struct key_t {
    u64 pid;
    char name[TASK_COMM_LEN];
    int cgroupid;
};

BPF_PERCPU_HASH(ref_count, struct key_t);
BPF_PERCPU_HASH(cycles_count, struct key_t);
BPF_PERCPU_HASH(insts_count, struct key_t);
BPF_PERCPU_HASH(l1imiss_count, struct key_t);
BPF_PERCPU_HASH(l1dmiss_count, struct key_t);
BPF_PERCPU_HASH(l1dhit_count, struct key_t);
BPF_PERCPU_HASH(l2miss_count, struct key_t);
BPF_PERCPU_HASH(l3miss_count, struct key_t);
BPF_PERCPU_HASH(ocr_ev1_count, struct key_t);
BPF_PERCPU_HASH(ocr_ev2_count, struct key_t);
BPF_PERCPU_HASH(ocr_ev3_count, struct key_t);
BPF_PERCPU_HASH(ocr_ev4_count, struct key_t);
BPF_PERCPU_HASH(disk_io_R_count, struct key_t);
BPF_PERCPU_HASH(disk_io_W_count, struct key_t);
BPF_PERCPU_HASH(ipv4_send_bytes, struct key_t);
BPF_PERCPU_HASH(ipv4_recv_bytes, struct key_t);
BPF_PERCPU_HASH(sock_store, u32, struct sock *);
BPF_PERCPU_HASH(qlen_sum, struct key_t);
BPF_PERCPU_HASH(qlen_count, struct key_t);
BPF_PERCPU_HASH(qlat_accum, struct key_t);
BPF_PERCPU_HASH(mem_sizes, struct key_t);
BPF_PERCPU_HASH(memptrs, u64, u64);
BPF_PERCPU_HASH(start_runq, u64);

static inline __attribute__((always_inline)) void get_key(struct key_t* key) {
    if(!GROUPID_FILTER)
    {
       key->pid = bpf_get_current_pid_tgid() >> 32;
       bpf_get_current_comm(&(key->name), sizeof(key->name));
    }
    else{
          key->pid = bpf_get_current_cgroup_id();
    }
}
int on_ref(struct bpf_perf_event_data *ctx) {
    struct key_t key = {};
    get_key(&key);
    if(key.pid > 0) {
        u64 *val;
        u64 sample_period = (u64)ctx->sample_period;
        val = ref_count.lookup_or_try_init(&key, &sample_period);
        if (val) {
           *val += sample_period;
        }
    }
    return 0;
}
int on_cycles(struct bpf_perf_event_data *ctx) {
    struct key_t key = {};
    get_key(&key);
    if(key.pid > 0) {
        u64 *val;
        u64 sample_period = (u64)ctx->sample_period;
        val = cycles_count.lookup_or_try_init(&key, &sample_period);
        if (val) {
           *val += sample_period;
        }
    }
    return 0;
}
int on_insts(struct bpf_perf_event_data *ctx) {
    struct key_t key = {};
    get_key(&key);
    if(key.pid > 0) {
        u64 *val;
        u64 sample_period = (u64)ctx->sample_period;
        val = insts_count.lookup_or_try_init(&key, &sample_period);
        if (val) {
           *val += sample_period;
        }
    }
    return 0;
}
int on_l1imiss(struct bpf_perf_event_data *ctx) {
    struct key_t key = {};
    get_key(&key);
    if(key.pid > 0) {
        u64 *val;
        u64 sample_period = (u64)ctx->sample_period;
        val = l1imiss_count.lookup_or_try_init(&key, &sample_period);
        if (val) {
          *val += sample_period;
        }
    }
    return 0;
}
int on_l1dmiss(struct bpf_perf_event_data *ctx) {
    struct key_t key = {};
    get_key(&key);
    if(key.pid > 0) {
        u64 *val;
        u64 sample_period = (u64)ctx->sample_period;
        val = l1dmiss_count.lookup_or_try_init(&key, &sample_period);
        if (val) {
          *val += sample_period;
        }
    }
    return 0;
}
int on_l1dhit(struct bpf_perf_event_data *ctx) {
    struct key_t key = {};
    get_key(&key);
    if(key.pid > 0) {
        u64 *val;
        u64 sample_period = (u64)ctx->sample_period;
        val = l1dhit_count.lookup_or_try_init(&key, &sample_period);
        if (val) {
          *val += sample_period;
        }
    }
    return 0;
}
int on_l2miss(struct bpf_perf_event_data *ctx) {
    struct key_t key = {};
    get_key(&key);
    if(key.pid > 0) {
        u64 *val;
        u64 sample_period = (u64)ctx->sample_period;
        val = l2miss_count.lookup_or_try_init(&key, &sample_period);
        if (val) {
          *val += sample_period;
        }
    }
    return 0;
}
int on_l3miss(struct bpf_perf_event_data *ctx) {
    struct key_t key = {};
    get_key(&key);
    if(key.pid > 0) {
        u64 *val;
        u64 sample_period = (u64)ctx->sample_period;
        val = l3miss_count.lookup_or_try_init(&key, &sample_period);
        if (val) {
          *val += sample_period;
        }
    }
    return 0;
}
int on_ocr_ev1(struct bpf_perf_event_data *ctx) {
    struct key_t key = {};
    get_key(&key);
    if(key.pid > 0) {
        u64 *val;
        u64 sample_period = (u64)ctx->sample_period;
        val = ocr_ev1_count.lookup_or_try_init(&key, &sample_period);
        if (val) {
           *val += sample_period;
        }
    }
    return 0;
}
int on_ocr_ev2(struct bpf_perf_event_data *ctx) {
    struct key_t key = {};
    get_key(&key);
    if(key.pid > 0) {
        u64 *val;
        u64 sample_period = (u64)ctx->sample_period;
        val = ocr_ev2_count.lookup_or_try_init(&key, &sample_period);
        if (val) {
           *val += sample_period;
        }
    }
    return 0;
}
int on_ocr_ev3(struct bpf_perf_event_data *ctx) {
    struct key_t key = {};
    get_key(&key);
    if(key.pid > 0) {
        u64 *val;
        u64 sample_period = (u64)ctx->sample_period;
        val = ocr_ev3_count.lookup_or_try_init(&key, &sample_period);
        if (val) {
           *val += sample_period;
        }
    }
    return 0;
}
int on_ocr_ev4(struct bpf_perf_event_data *ctx) {
    struct key_t key = {};
    get_key(&key);
    if(key.pid > 0) {
        u64 *val;
        u64 sample_period = (u64)ctx->sample_period;
        val = ocr_ev4_count.lookup_or_try_init(&key, &sample_period);
        if (val) {
           *val += sample_period;
        }
    }
    return 0;
}
// Trace point for block io issue events
// We can break this down further by the device using args->device parameter
TRACEPOINT_PROBE(block, block_rq_issue) {
    struct key_t key = {};
    get_key(&key);
    char R_W = args->rwbs[0];
    u64 *val;
    if(R_W == 'R'){
        u64 bytes = (u64)args->bytes;
        val = disk_io_R_count.lookup_or_try_init(&key, &bytes);
        if (val) {
           *val += args->bytes;
        }
    }
    else {
        u64 bytes = (u64)args->bytes;
        val = disk_io_W_count.lookup_or_try_init(&key, &bytes);
        if (val) {
           *val += args->bytes;
        }
    }
    return 0;
}
// Code for tracing network throughput: Adopted from https://github.com/iovisor/bcc/blob/master/tools/tcptop.py
static int tcp_sendstat(int size)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    struct sock **sockpp;
    sockpp = sock_store.lookup(&tid);
    if (sockpp == 0) {
        return 0; //miss the entry
    }
    struct sock *sk = *sockpp;
    u16 dport = 0, family;
    bpf_probe_read_kernel(&family, sizeof(family),
        &sk->__sk_common.skc_family);

    if (family == AF_INET || family == AF_INET6) {
        struct key_t key = {};
        get_key(&key) ;
        u64 *val;
        u64 size_u64 = (u64)size;
        val = ipv4_send_bytes.lookup_or_try_init(&key, &size_u64);
        if (val) {
           *val += size;
        }
    }

    sock_store.delete(&tid);

    return 0;
}
int kretprobe__tcp_sendmsg(struct pt_regs *ctx)
{
    int size = PT_REGS_RC(ctx);
    if (size > 0)
        return tcp_sendstat(size);
    else
        return 0;
}
int kretprobe__tcp_sendpage(struct pt_regs *ctx)
{
    int size = PT_REGS_RC(ctx);
    if (size > 0)
        return tcp_sendstat(size);
    else
        return 0;
}
static int tcp_send_entry(struct sock *sk)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    //FILTER_PID
    u32 tid = bpf_get_current_pid_tgid();
    u16 family = sk->__sk_common.skc_family;
    struct sock **val;
    val  = sock_store.lookup_or_try_init(&tid, &sk);
    if (val) {
       *val = sk;
    }
    return 0;
}
int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk,
    struct msghdr *msg, size_t size)
{
    return tcp_send_entry(sk);
}
int kprobe__tcp_sendpage(struct pt_regs *ctx, struct sock *sk,
    struct page *page, int offset, size_t size)
{
    return tcp_send_entry(sk);
}
/*
 * tcp_recvmsg() would be obvious to trace, but is less suitable because:
 * - we'd need to trace both entry and return, to have both sock and size
 * - misses tcp_read_sock() traffic
 * we'd much prefer tracepoints once they are available.
 */
int kprobe__tcp_cleanup_rbuf(struct pt_regs *ctx, struct sock *sk, int copied)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u16 dport = 0, family = sk->__sk_common.skc_family;
    u64 *val, zero = 0;
    if (copied <= 0)
        return 0;

    if (family == AF_INET || family == AF_INET6) {
        struct key_t key = {};
        get_key(&key);
        u64 *val;
        u64 copied_u64 = (u64)copied;
        val = ipv4_recv_bytes.lookup_or_try_init(&key, &copied_u64);
        if (val) {
           *val += copied;
        }
    }
    return 0;
}

/// code for tracing queue latency and length per PID
static int trace_enqueue(struct key_t key)
{
    u64 ts = bpf_ktime_get_ns();
    ts /= 1000000; //msec
    u64 *val;
    val = start_runq.lookup_or_try_init(&key.pid, &ts);
    if (val) {
       *val = ts;
    }
    return 0;
}
RAW_TRACEPOINT_PROBE(sched_wakeup)
{
    struct key_t key = {};
    get_key(&key);
    return trace_enqueue(key);
}
RAW_TRACEPOINT_PROBE(sched_wakeup_new)
{
    struct key_t key = {};
    get_key(&key);
    return trace_enqueue(key);
}
struct cfs_rq_partial {
    struct load_weight load;
    unsigned int nr_running, h_nr_running;
};
RAW_TRACEPOINT_PROBE(sched_switch)
{
    struct task_struct *prev = (struct task_struct *)ctx->args[1];
    struct task_struct *next= (struct task_struct *)ctx->args[2];
    s32 prev_tgid, next_tgid;

    bpf_probe_read_kernel(&prev_tgid, sizeof(prev->tgid), &prev->tgid);
    bpf_probe_read_kernel(&next_tgid, sizeof(next->tgid), &next->tgid);

    u32 prev_pid = prev_tgid;
    u32 next_pid = next_tgid;
    // skip swapper or sched (pid=0)
    if (prev_pid == 0 || next_pid == 0)
    {
       return 0;
    }
    struct key_t key = {};
    get_key(&key);

    // ivcsw: treat like an enqueue event and store timestamp
    if (prev->STATE_FIELD == TASK_RUNNING) {
        if (!(prev_pid == 0)) {
           key.pid = prev_pid;
           trace_enqueue(key);
        }
    }
    struct key_t key_next = {};
    get_key(&key_next);
    key_next.pid = next_pid;

    u64 *tsp, delta;
    u64 prev_tsp;
    u64 ts_zero = 0;
    tsp = start_runq.lookup_or_try_init(&key_next.pid, &ts_zero);
    if(tsp) {
       if(*tsp ==0){
          return 0;
       }
       prev_tsp = *tsp;
       *tsp = ts_zero;
    }
    else{
       return 0; //missed enqueue
    }
    struct cfs_rq_partial *my_q = NULL;
    my_q = (struct cfs_rq_partial *)next->se.cfs_rq;

    unsigned int len = 0;
    len = my_q->nr_running;

    delta = bpf_ktime_get_ns();
    delta /= 1000000; // msecs
    delta = delta - prev_tsp;

    u64 *val;
    val = qlat_accum.lookup_or_try_init(&key, &ts_zero);
    if (val) {
        *val += delta;
    }

    u64 len_u64 = (u64)len;
    val = qlen_sum.lookup_or_try_init(&key, &len_u64);
    if (val) {
        *val += len;
    }
    u64 step = 1;
    val = qlen_count.lookup_or_try_init(&key, &step);
    if (val) {
        *val += 1;
    }

    return 0;
}
"""
# eBPF program code substitutions
if BPF.kernel_struct_has_field(b"task_struct", b"__state") == 1:
    bpf_text = bpf_text.replace("STATE_FIELD", "__state")
else:
    bpf_text = bpf_text.replace("STATE_FIELD", "state")

if args.aggregate_cgroup:
    bpf_text = bpf_text.replace("GROUPID_FILTER", "1")
else:
    bpf_text = bpf_text.replace("GROUPID_FILTER", "0")

if args.ebpf:
    print(bpf_text)
    sys.exit("print bpf text")

# Create BPF object
try:
    b = BPF(text=bpf_text)
except Exception as e:
    print("Failed to load bpf program.", e)
    sys.exit(1)


def create_group_and_attach(events_list, gname, sample_freq):
    leader = None
    count = 0
    try:
        for hexcode, fn_name, config1 in events_list:
            count += 1
            attr = Perf.perf_event_attr()
            attr.type = PerfType.RAW
            attr.config = int(hexcode, 16)
            attr.sample_period = sample_freq
            attr.sample_type = int("10000", 16)
            attr.read_format = int(
                "f", 16
            )  # TOTAL_TIME_ENABLED|TOTAL_TIME_RUNNING|ID|GROUP
            if len(config1) > 0:
                attr._bp_addr_union.config1 = int(config1, 16)
            if count == 1:
                attr.disabled = 1
                b.attach_perf_event_raw(attr=attr, fn_name=fn_name, pid=-1, cpu=-1)
                leader = b.open_perf_events[(attr.type, attr.config)]
            else:
                attr.disabled = 0
                for c in leader.keys():
                    b.attach_perf_event_raw(
                        attr=attr,
                        fn_name=fn_name,
                        pid=-1,
                        cpu=c,
                        group_fd=leader[c],
                    )
    except Exception as e:
        print(
            "**Warning**: Failed to attach to events in "
            + gname
            + ". Is this a virtual machine?",
            e,
            " -> Skipping...",
        )

    if args.verbose:
        print("Events in " + gname + " created and attached successfully")

    return leader, len(events_list)


# Check if OCR counters are supported by the current SKU
current_arch, OCR_support = check_OCR_support()

# Create 1st group and attach
fo_s = []  # file objects list
group_sizes = []
fd, g_s = create_group_and_attach(
    [
        (events[current_arch]["refs"], "on_ref", ""),
        (events[current_arch]["cycles"], "on_cycles", ""),
        (events[current_arch]["insts"], "on_insts", ""),
        (events[current_arch]["l1imiss"], "on_l1imiss", ""),
        (events[current_arch]["l1dmiss"], "on_l1dmiss", ""),
        (events[current_arch]["l1dhit"], "on_l1dhit", ""),
    ],
    "L1_cache_group",
    args.sample_freq,
)

# Open fd and add file object to file objects list
fd_id = fd[0]
fo_s.append(os.fdopen(fd_id, "rb", encoding=None))
group_sizes.append(g_s)


# Create 2nd group and attach
fd, g_s = create_group_and_attach(
    [
        (events[current_arch]["refs"], "on_ref", ""),
        (events[current_arch]["cycles"], "on_cycles", ""),
        (events[current_arch]["insts"], "on_insts", ""),
        (events[current_arch]["l2miss"], "on_l2miss", ""),
        (events[current_arch]["l3miss"], "on_l3miss", ""),
    ],
    "L2_L3_cache_group",
    args.sample_freq,
)

# Open fd and add file object to file objects list
fd_id = fd[0]
fo_s.append(os.fdopen(fd_id, "rb", encoding=None))
group_sizes.append(g_s)

if OCR_support:
    OCR_Local = [
        (events[current_arch]["refs"], "on_ref", ""),
        (events[current_arch]["cycles"], "on_cycles", ""),
        (events[current_arch]["insts"], "on_insts", ""),
    ]

    OCR_Remote = OCR_Local.copy()

    if "ocr_ev1" in events[current_arch]:
        event_config_pair = events[current_arch]["ocr_ev1"].split(",")
        OCR_Local.append((event_config_pair[0], "on_ocr_ev1", event_config_pair[1]))

    if "ocr_ev2" in events[current_arch]:
        event_config_pair = events[current_arch]["ocr_ev2"].split(",")
        OCR_Local.append((event_config_pair[0], "on_ocr_ev2", event_config_pair[1]))

    if "ocr_ev3" in events[current_arch]:
        event_config_pair = events[current_arch]["ocr_ev3"].split(",")
        OCR_Remote.append((event_config_pair[0], "on_ocr_ev3", event_config_pair[1]))

    if "ocr_ev4" in events[current_arch]:
        event_config_pair = events[current_arch]["ocr_ev4"].split(",")
        OCR_Remote.append((event_config_pair[0], "on_ocr_ev4", event_config_pair[1]))

    # Attach OCR_L1 events
    fd, g_s = create_group_and_attach(OCR_Local, "ocr_local_group", args.sample_freq)

    fd_id = fd[0]
    # Open fd and add file object to file objects list
    fo_s.append(os.fdopen(fd_id, "rb", encoding=None))
    group_sizes.append(g_s)

    # Attach OCR_L2 events
    fd, g_s = create_group_and_attach(OCR_Remote, "ocr_remote_group", args.sample_freq)

    fd_id = fd[0]
    # Open fd and add file object to file objects list
    fo_s.append(
        os.fdopen(fd_id, "rb", encoding=None)
    )  # open fd and add file object to file objects list
    group_sizes.append(g_s)


# Collect events counters
def group1_collect(ebpf_counters):
    # Calculate scale factor
    # We extract the scale factor from group 0, we assume the scale factor is identical across groups
    scale = 1
    if len(fo_s) > 0 and len(group_sizes) > 0:
        group_size = group_sizes[0]
        num_of_fields = (
            3 + group_size * 2
        )  # we have three u64 (8 Bytes) fields (nr, time_enabled, time_running) + two u64 fields for each counter (value, id)
        rf_data = fo_s[0].read(8 * num_of_fields)  # Each field is of type u64 (8 Bytes)
        tup = unpack(
            "q" * num_of_fields, rf_data
        )  # q represents c type long long (https://docs.python.org/3/library/struct.html)
        # tup[0]: The number of events
        # tup[1]: has time_enabled
        # tup[2]: has time_running
        if args.verbose:
            print(tup)
        if tup[1] == tup[2] or tup[2] == 0:
            scale = 1
        else:
            scale = round(tup[1] / (tup[2]), 2)
        if args.verbose:
            print("SCALE: " + str(scale))
    # *** Notice that we don't scale ref, cycles, or insts as they are counted in both groups

    global_dict = {}
    for i in range(len(ebpf_counters)):
        if ebpf_counters[i] not in global_dict:
            global_dict[ebpf_counters[i]] = {}

        if args.acc:
            for k, per_cpu_array in b[ebpf_counters[i]].items():
                for cpu_id, value in enumerate(per_cpu_array):
                    if ebpf_counters[i] in [
                        "l1dmiss_count",
                        "l1imiss_count",
                        "l2miss_count",
                        "l3miss_count",
                        "ocr_ev1_count",
                        "ocr_ev2_count",
                        "ocr_ev3_count",
                        "ocr_ev4_count",
                    ]:
                        value = value * scale
                    global_dict[ebpf_counters[i]][
                        (k.pid, k.name, cpu_id, k.cgroupid)
                    ] = value
        else:
            for k, per_cpu_array in b[ebpf_counters[i]].items():
                for cpu_id, value in enumerate(per_cpu_array):
                    if ebpf_counters[i] in [
                        "l1dmiss_count",
                        "l1imiss_count",
                        "l2miss_count",
                        "l3miss_count",
                        "ocr_ev1_count",
                        "ocr_ev2_count",
                        "ocr_ev3_count",
                        "ocr_ev4_count",
                    ]:
                        value = value * scale
                    global_dict[ebpf_counters[i]][
                        (k.pid, k.name, cpu_id, k.cgroupid)
                    ] = value
            b[ebpf_counters[i]].clear()
    if args.verbose:
        print("CYCLES:", len(global_dict["cycles_count"]), global_dict["cycles_count"])
        print(
            "INSTRUCTIONS:", len(global_dict["insts_count"]), global_dict["insts_count"]
        )
        print("REFEREENCES:", len(global_dict["ref_count"]), global_dict["ref_count"])
        print(
            "L1DMiss:", len(global_dict["l1dmiss_count"]), global_dict["l1dmiss_count"]
        )
        print("L1DHit:", len(global_dict["l1dhit_count"]), global_dict["l1dhit_count"])
        print(
            "L1IMiss:", len(global_dict["l1imiss_count"]), global_dict["l1imiss_count"]
        )
        print("L2Miss:", len(global_dict["l2miss_count"]), global_dict["l2miss_count"])
        print("L3Miss:", len(global_dict["l3miss_count"]), global_dict["l3miss_count"])
        print(
            "OCR_EV1:", len(global_dict["ocr_ev1_count"]), global_dict["ocr_ev1_count"]
        )
        print(
            "OCR_EV2:", len(global_dict["ocr_ev2_count"]), global_dict["ocr_ev2_count"]
        )
        print(
            "OCR_EV3:", len(global_dict["ocr_ev3_count"]), global_dict["ocr_ev3_count"]
        )
        print(
            "OCR_EV4:", len(global_dict["ocr_ev4_count"]), global_dict["ocr_ev4_count"]
        )
        print(
            "DISK_READS:",
            len(global_dict["disk_io_R_count"]),
            global_dict["disk_io_R_count"],
        )
        print(
            "DISK_WRITES:",
            len(global_dict["disk_io_W_count"]),
            global_dict["disk_io_W_count"],
        )
        print(
            "NETWORK_TX:",
            len(global_dict["ipv4_send_bytes"]),
            global_dict["ipv4_send_bytes"],
        )
        print(
            "NETWORK_RX:",
            len(global_dict["ipv4_recv_bytes"]),
            global_dict["ipv4_recv_bytes"],
        )
        print("MEMORY_SIZES:", len(global_dict["mem_sizes"]), global_dict["mem_sizes"])
        print("___________________________________________")

    print(
        "Timestamp,PID,process,cgroupID,core,cycles,insts,cpi,l1i_mpi,l1d_hit_ratio,l1d_miss_ratio,l2_miss_ratio,l3_miss_ratio,local_bw,remote_bw,disk_reads,disk_writes,network_tx,network_rx,scheduled_count,avg_q_len,avg_q_latency"
    )
    inst = 0
    cycles = 0
    l1d_miss = 0
    l1d_hit = 0
    l1i_miss = 0
    l2_miss = 0
    l3_miss = 0
    ocr_ev1 = 0
    ocr_ev2 = 0
    ocr_ev3 = 0
    ocr_ev4 = 0
    disk_reads = 0
    disk_writes = 0
    qlen_sum = 0
    qlen_count = 0
    qlat_accum = 0
    # *** Notice that we scale the counters to account for multiplixing: https://perf.wiki.kernel.org/index.php/Tutorial#multiplexing_and_scaling_events (see multiplexing and scaling events section)
    # *** We don't scale ref, cycles, or insts as they are counted in all groups
    # *** We also don't scale disk or network counters as they are counted in kernel tracepoints (no multiplixing)
    for k, v in global_dict["insts_count"].items():
        if "insts_count" in global_dict:
            inst = global_dict["insts_count"].get(k, 0)
        if inst > 0:
            if "cycles_count" in global_dict:
                cycles = global_dict["cycles_count"].get(k, 0)
            if "l1imiss_count" in global_dict:
                l1i_miss = global_dict["l1imiss_count"].get(k, 0)
            if "l1dmiss_count" in global_dict:
                l1d_miss = global_dict["l1dmiss_count"].get(k, 0)
            if "l1dhit_count" in global_dict:
                l1d_hit = global_dict["l1dhit_count"].get(k, 0)
            if "l2miss_count" in global_dict:
                l2_miss = global_dict["l2miss_count"].get(k, 0)
            if "l3miss_count" in global_dict:
                l3_miss = global_dict["l3miss_count"].get(k, 0)
            if "ocr_ev1_count" in global_dict:
                ocr_ev1 = global_dict["ocr_ev1_count"].get(k, 0)
            if "ocr_ev2_count" in global_dict:
                ocr_ev2 = global_dict["ocr_ev2_count"].get(k, 0)
            if "ocr_ev3_count" in global_dict:
                ocr_ev3 = global_dict["ocr_ev3_count"].get(k, 0)
            if "ocr_ev4_count" in global_dict:
                ocr_ev4 = global_dict["ocr_ev4_count"].get(k, 0)
            if "disk_io_R_count" in global_dict:
                disk_reads = (
                    global_dict["disk_io_R_count"].get(k, 0) / 1000000
                )  # MB/sec
            if "disk_io_W_count" in global_dict:
                disk_writes = (
                    global_dict["disk_io_W_count"].get(k, 0) / 1000000
                )  # MB/sec
            if "ipv4_send_bytes" in global_dict:
                network_TX = (
                    global_dict["ipv4_send_bytes"].get(k, 0) / 1000000
                )  # MB/sec
            if "ipv4_recv_bytes" in global_dict:
                network_RX = (
                    global_dict["ipv4_recv_bytes"].get(k, 0) / 1000000
                )  # MB/sec
            if "qlen_sum" in global_dict:
                qlen_sum = global_dict["qlen_sum"].get(k, 0)
            if "qlen_count" in global_dict:
                qlen_count = global_dict["qlen_count"].get(k, 0)
            if "qlat_accum" in global_dict:
                qlat_accum = global_dict["qlat_accum"].get(k, 0)
            # we add 1 to the denominator for every metric below to avoid division by zero
            cpi = cycles / (inst + 1)
            l1i_mpi = l1i_miss / (inst + 1)
            l1d_miss_ratio = min(1, l1d_miss / (l1d_miss + l1d_hit + 1))
            l1d_hit_ratio = min(1, l1d_hit / (l1d_miss + l1d_hit + 1))
            l2_miss_ratio = min(1, l2_miss / (l1d_miss + 1))
            l3_miss_ratio = min(1, l3_miss / (l2_miss + 1))
            local_bw = (ocr_ev1 + ocr_ev2) * 64 / 1000000  # MB/sec
            remote_bw = (ocr_ev3 + ocr_ev4) * 64 / 1000000  # MB/sec

            if qlen_count == 0:
                qlen_avg = 0
            else:
                qlen_avg = int(qlen_sum / qlen_count)
        # if inst = 0, set all counters to 0
        else:
            cpi = 0
            l1i_mpi = 0
            l1d_miss_ratio = 0
            l1d_hit_ratio = 0
            l2_miss_ratio = 0
            l3_miss_ratio = 0
            local_bw = 0
            remote_bw = 0
            qlen_avg = 0
            qlat_accum = 0
        t = datetime.now().timestamp()
        if cycles > 0 and inst > 0:
            print(
                "{},{:d},{:s},{:d},{:d},{:d},{:d},{:0.2f},{:0.2f},{:0.2f},{:0.2f},{:0.2f},{:0.2f},{:0.2f},{:0.2f},{:0.2f},{:0.2f},{:0.2f},{:0.2f},{:0.2f},{:0.2f},{:0.2f}".format(
                    t,
                    k[0],
                    k[1].decode("utf-8", "replace"),
                    k[3],
                    k[2],
                    cycles,
                    inst,
                    cpi,
                    l1i_mpi,
                    l1d_hit_ratio,
                    l1d_miss_ratio,
                    l2_miss_ratio,
                    l3_miss_ratio,
                    local_bw,
                    remote_bw,
                    disk_reads,
                    disk_writes,
                    network_TX,
                    network_RX,
                    qlen_count,
                    qlen_avg,
                    qlat_accum,
                )
            )


# Function below is not needed when items_lookup_and_delete_batch() is used, since it reads the items and clears the content in one syscall
def clear_nonbatch_counters():
    b["start_runq"].clear()


ebpf_counters = [
    "insts_count",
    "cycles_count",
    "ref_count",
    "l1imiss_count",
    "l1dmiss_count",
    "l1dhit_count",
    "l2miss_count",
    "l3miss_count",
    "ocr_ev1_count",
    "ocr_ev2_count",
    "ocr_ev3_count",
    "ocr_ev4_count",
    "disk_io_R_count",
    "disk_io_W_count",
    "ipv4_send_bytes",
    "ipv4_recv_bytes",
    "qlen_sum",
    "qlen_count",
    "qlat_accum",
    "mem_sizes",
]

exiting = 0
seconds = 0
while 1:
    try:
        sys.stdout.flush()
        sleep(interval)
        seconds += interval
        group1_collect(ebpf_counters)

        if duration and seconds >= duration:
            exiting = 1

        print(
            "---------------------------------------------------------------------------------"
        )
        clear_nonbatch_counters()
    except KeyboardInterrupt:
        exiting = 1
        signal.signal(signal.SIGINT, lambda signal, frame: print())
    if exiting:
        print("Done. Detaching and exiting...")
        sys.exit(0)
