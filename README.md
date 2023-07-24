<div align="center">

<div id="user-content-toc">
  <ul>
    <summary><h1 style="display: inline-block;">Workload Interference Detector</h1></summary>
  </ul>
</div>

![CodeQL](https://github.com/intel/interferencedetector/actions/workflows/codeql.yml/badge.svg)[![License](https://img.shields.io/badge/License-MIT-blue)](https://github.com/intel/interferencedetector/blob/master/LICENSE)

[Requirements](#requirements) | [Usage](#usage) | [Demo](#demo) | [Notes](#notes)
</div>

Workload Interference Detector uses a combination of hardware events and ebpf to capture a wholistic signature of a workload's performance at very low overhead.
1. instruction efficiency
    - cycles
    - instructions
    - cycles per instruction
2. disk IO
    - local bandwidth (MB/s)
    - remote bandwidth (MB/s)
    - disk reads (MB/s)
    - disk writes (MB/s)
3. network IO
    - network transmitted (MB/s)
    - network received (MB/s)
4. cache
    - L1 instrutions misses per instruction
    - L1 data hit ratio
    - L1 data miss ratio
    - L2 miss ratio
    - L3 miss ratio
5. scheduling
    - scheduled count
    - average queue length
    - average queue latency (ms)

## Requirements
1. Linux Perf
2. [BCC compiled from source.](https://github.com/iovisor/bcc/blob/master/INSTALL.md#source)
3. `pip install -r requirements.txt`
4. Access to PMU
    - Bare-metal
    - VM with vPMU exposed (uncore metrics like disk IO will be zero)
5. Intel Xeon chip
    - Skylake
    - Cascade Lake
    - Ice Lake
    - Sapphire Rapids
6. Python

## Usage
1. Monitor processes
```
sudo python3 procmon.py
```
2. Monitor containers (can also export to cloudwatch)
```
sudo python3 cmon.py
```
3. Detect process or container interference. A list of workloads that likely caused the performance degradation is shown.
```
# process
sudo python3 NN_detect.py --pid <process-pid> --ref_signature <processes's reference signature> --distance_ratio 0.15

# container
sudo python3 NN_detect.py --cid <container id> --ref_signature <container's reference signature> --distance_ratio 0.15
```

## Demo

![basic_stats](https://raw.githubusercontent.com/wiki/intel/interferencedetector/NN_demo1.gif)

## Notes:
** Interference Detector was developed using the following as references:
1. github.com/iovisor/bcc/tools/llcstat.py (Apache 2.0)
2. github.com/iovisor/bcc/tools/tcptop.py (Apache 2.0)
3. github.com/iovisor/bcc/blob/master/examples/tracing/disksnoop.py (Apache 2.0)
4. github.com/iovisor/bcc/blob/master/tools/runqlen.py (Apache 2.0)
5. github.com/iovisor/bcc/blob/master/tools/runqlat.py (Apache 2.0)