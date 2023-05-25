#!/usr/bin/env python3

###########################################################################################################
# Copyright (C) 2023 Intel Corporation
# SPDX-License-Identifier: MIT
###########################################################################################################

from subprocess import Popen, PIPE, check_output
import argparse
import sys
import re
import os
from os.path import exists
from enum import Enum
from datetime import datetime


class bcolors:
    HEADER = "\033[95m"
    OKGREEN = "\033[92m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"


parser = argparse.ArgumentParser(
    description="Detect Noisy Neighbors for a given PID (process-level) or container ID (container-level). ",
    formatter_class=argparse.RawDescriptionHelpFormatter,
)

parser.add_argument("-p", "--pid", type=str, help="PID (process-level)")
parser.add_argument("-c", "--cid", type=str, help="Container ID (container-level)")
parser.add_argument(
    "--outfile", type=str, help="Output file to save live-updated performance data"
)
parser.add_argument(
    "-r",
    "--ref_signature",
    required=True,
    type=str,
    help="The tool will use this signature as a baseline. Use the ouput of either procmon or dockermon to collect the signature. The first element in the signature is `cycles`. All live updated signatures will be compared to this reference signature. Use a standalone signature (when the proccess is the only process executing in the system), or any signature collected over a performance-acceptable duration.",
)

parser.add_argument(
    "-d",
    "--distance_ratio",
    type=float,
    default=0.1,
    help="Acceptable ratio of change in signature from reference, default is 0.1. If the distance is higher than this value, the monitored workload will flagged as a noisy neigbor victim.",
)

args = parser.parse_args()

# Check that only pid or cid arguments are passed, but not both
if (args.pid and args.cid) or (not args.pid and not args.cid):
    print(
        "Please set either -p/--pid flag for process-level monitoring, or -c/--cid flag for container-level moitoring (but not both)."
    )
    sys.exit()

# Check if output file already exists
if args.outfile:
    file_exists = exists(os.curdir + "/" + args.outfile)

    if file_exists:
        print(
            "Output file",
            args.outfile,
            "already exists. Please change the output file name",
        )
        sys.exit()
    else:
        out_file = open(args.outfile, "w")


# Dictionaries that maps a header to its index and vice versa
header_index_dict = {}
index_header_dict = {}


class Direction(Enum):
    ANY = 0
    HIGHER_IS_BETTER = 1
    LOWER_IS_BETTER = 2
    IGNORE = 3


# Mapping of countrers to performance degredation events (i.e. lower the better vs higher the better):
metric_to_perf_direction = {
    "cycles": Direction.ANY,
    "insts": Direction.ANY,
    "cpi": Direction.LOWER_IS_BETTER,
    "l1i_mpi": Direction.LOWER_IS_BETTER,
    "l1d_hit_ratio": Direction.HIGHER_IS_BETTER,
    "l1d_miss_ratio": Direction.LOWER_IS_BETTER,
    "l2_miss_ratio": Direction.LOWER_IS_BETTER,
    "l3_miss_ratio": Direction.LOWER_IS_BETTER,
    "local_bw": Direction.HIGHER_IS_BETTER,
    "remote_bw": Direction.HIGHER_IS_BETTER,
    "disk_reads": Direction.HIGHER_IS_BETTER,
    "disk_writes": Direction.HIGHER_IS_BETTER,
    "network_tx": Direction.HIGHER_IS_BETTER,
    "network_rx": Direction.HIGHER_IS_BETTER,
    "avg_q_len": Direction.IGNORE,
    "scheduled_count": Direction.IGNORE,
    "avg_q_latency": Direction.IGNORE,
}


def get_CPU_to_NUMA_Mapping():
    core_to_NUMA = {}
    num_of_threads_per_core = 0
    NUMA_indx = 0
    cpu_info = check_output(["lscpu"])
    if cpu_info:
        cpu_info_list = cpu_info.decode().split("\n")
        for cpu_info_line in cpu_info_list:
            # if("NUMA node" in cpu_info_line and "CPU(s)" in cpu_info_line):
            if re.match(r"NUMA node.* CPU\(s\):", cpu_info_line):
                cpus_groups_list = cpu_info_line.split(":")
                if len(cpus_groups_list) > 1:
                    cpu_groups = cpus_groups_list[1].split(",")
                    for cpus in cpu_groups:
                        start_end_indxs = cpus.split("-")
                        start_indx = int(start_end_indxs[0])
                        end_indx = int(start_end_indxs[1]) + 1
                        for index in range(start_indx, end_indx):
                            core_to_NUMA[str(index)] = NUMA_indx
                NUMA_indx += 1
            elif re.match(r"Thread\(s\) per core: *", cpu_info_line):
                thread_per_core_str = cpu_info_line.split(":")
                if len(thread_per_core_str) > 1:
                    num_of_threads_per_core = int(thread_per_core_str[1])

    if len(core_to_NUMA) == 0:
        print("Failed to read CPU to NUMA mapping. Exiting...")
        sys.exit()

    if num_of_threads_per_core == 0:
        print("Failed to read Number of threads per core. Exiting...")
        sys.exit()

    num_of_physical_cores = len(core_to_NUMA) / num_of_threads_per_core

    return core_to_NUMA, num_of_physical_cores


def get_signature(signature_str, start_index):
    signature_str_list = signature_str.split(",")[start_index:]
    return [float(elem) for elem in signature_str_list]


def get_min_distance_from_neighbor(
    nn_signature, detected_signature, same_core=True, same_numa=True
):
    # check if both signatures have the same length
    assert len(nn_signature) == len(detected_signature)

    min_dist = float("inf")
    contention_metric = "[]"
    # If the two workloads are running on different cores, exclude on-core counters: cycles insts cpi l1i_mpi l1d_mpi l2_mpi
    # If the two workloads are running on different cores and different NUMA, execulde NUMA shared resources: l3_mpi local_bw
    assert "cycles" in header_index_dict

    if same_core:
        index = 0
    elif same_numa:
        assert "l3_miss_ratio" in header_index_dict
        index = header_index_dict["l3_miss_ratio"] - header_index_dict["cycles"]
    else:  # Different cores and different NUMA
        assert "remote_bw" in header_index_dict
        index = header_index_dict["remote_bw"] - header_index_dict["cycles"]

    for i in range(index, len(detected_signature)):
        metric = index_header_dict[i + header_index_dict["cycles"]]
        perf_direction = metric_to_perf_direction[metric]

        if perf_direction == Direction.IGNORE:
            continue
        # Skip counter if it is zero in one of the two signatures
        if detected_signature[i] == 0 or nn_signature[i] == 0:
            continue
        # Get distance between detected signature and neighbor
        dist = abs(nn_signature[i] - detected_signature[i]) / nn_signature[i]
        if dist < min_dist:
            min_dist = dist
            contention_metric = index_header_dict[i + header_index_dict["cycles"]]

    return min_dist, contention_metric


def get_impacted_metrics_list(ref_signature, detected_signature, distance_ratio):
    # Verify if both signatures have the same length (this should always be the case)
    assert len(ref_signature) == len(detected_signature)

    max_dist = -1
    impacted_metrics_list = []

    for i in range(len(detected_signature)):
        metric = index_header_dict[i + header_index_dict["cycles"]]
        perf_direction = metric_to_perf_direction[metric]

        if perf_direction == Direction.IGNORE:
            continue

        elif (perf_direction == Direction.HIGHER_IS_BETTER) and (
            detected_signature[i] > ref_signature[i]
        ):
            # performance is better than reference, skip
            continue
        elif (perf_direction == Direction.LOWER_IS_BETTER) and (
            detected_signature[i] < ref_signature[i]
        ):
            # performance is better than reference, skip
            continue

        dist = abs(ref_signature[i] - detected_signature[i]) / max(ref_signature[i], 1)
        if dist > distance_ratio:
            impacted_metrics_list.append(i)
        if dist > max_dist:
            max_dist = dist

    return max_dist, impacted_metrics_list


def represents_int(s):
    try:
        int(s)
    except ValueError:
        return False
    else:
        return True


# Returnes True if the two core IDs are hyperthreads on the same physical core
def is_hyperthread(num_of_physical_cores, process_core, neighbor_core):
    # Check that both core ids can be represented as int
    assert represents_int(process_core)
    assert represents_int(neighbor_core)
    # Example: A system with 48 physical cores and 2 threads per core has 96 threads in total. Thread 0 will be hyperthreaded with thread 48, 1 with 49, and so on..
    return abs(int(process_core) - int(neighbor_core)) == num_of_physical_cores


# Clear console screen
def clear_screen():
    print("\033[H\033[J", end="")


def get_impacted_metrics_list_string(metrics, impacted_metric_list):
    str_list = []
    for i in impacted_metric_list:
        str_list.append(metrics[header_index_dict["cycles"] + i])

    return ",".join(str_list)


def run_NN_detect():
    CPU_to_NUMA, num_of_physical_cores = get_CPU_to_NUMA_Mapping()
    ref_signature = get_signature(args.ref_signature, 0)
    if args.pid:
        # run procmon
        proc = Popen(
            ["python3", "procmon.py"],
            stdin=PIPE,
            stdout=PIPE,
            stderr=PIPE,
        )
    else:
        # Run dockermon
        proc = Popen(
            ["python3", "dockermon.py", "--aggregate_on_core"],
            stdin=PIPE,
            stdout=PIPE,
            stderr=PIPE,
        )

    neighbors = []
    process_signature_line_list = []
    metrics = []
    header = ""

    pid_or_cid = args.pid if args.pid else args.cid

    while True:
        if not proc.stdout:
            print("Reading procmon's or dockermon's stdout failed. Exiting...")
            return

        line = proc.stdout.readline().decode("utf-8").rstrip()
        if not line or "Exiting.." in line:
            error_message = line
            print("Calling procmon or dockermon failed. Exiting...", error_message)
            return

        parts = line.split(",")
        if "Timestamp" in line:
            # Read the metrics names from procmon header
            metrics = parts

        elif (
            "------------" in line
        ):  # indicates new collection interval in procmon/dockermon
            # Clear console screen
            clear_screen()
            # Write to console
            print("-----------------------------------------------------------------")
            # Write to file
            if args.outfile and out_file:
                out_file.write(
                    "-----------------------------------------------------------------"
                    + "\n"
                )

            print(bcolors.HEADER, "Header:\t\t\t", header, bcolors.ENDC)
            print("Reference Signature:\t\t", ref_signature)
            for process_signature_line in process_signature_line_list:
                detected_signature = get_signature(
                    process_signature_line, header_index_dict["cycles"]
                )
                process_core = process_signature_line.split(",")[
                    header_index_dict["core"]
                ]

                now = datetime.now()  # current date and time
                date_time = now.strftime("%m/%d/%Y, %H:%M:%S")
                detected_str = (
                    "At time: "
                    + date_time
                    + " detected signature on core "
                    + process_core
                    + ":\t"
                    + str(detected_signature)
                )
                # Write to console
                print(detected_str)
                # Write to file
                if args.outfile and out_file:
                    out_file.write(detected_str + "\n")

                dist_from_reference, impacted_metric_list = get_impacted_metrics_list(
                    ref_signature, detected_signature, args.distance_ratio
                )

                if dist_from_reference < args.distance_ratio:
                    status_str = (
                        "Distance from reference: "
                        + str(round(dist_from_reference * 100, 2))
                        + "%\t"
                        + " ==> Performance is OK"
                    )
                    # Write to console
                    print(bcolors.OKGREEN + status_str + bcolors.ENDC)
                    # Write to file
                    if args.outfile and out_file:
                        out_file.write(status_str + "\n")
                else:
                    impacted_metrics_string = get_impacted_metrics_list_string(
                        metrics, impacted_metric_list
                    )
                    status_str = (
                        "Distance from reference: "
                        + str(round(dist_from_reference * 100, 2))
                        + "%\t"
                        + " ==> Performance may suffer. Imapacted metrics: "
                        + impacted_metrics_string
                    )
                    # Write to console
                    print(bcolors.FAIL + status_str + bcolors.ENDC)
                    # Write to file
                    if args.outfile and out_file:
                        out_file.write(status_str + "\n")

                    nn_same_core_distance_line_tuple_list = []
                    nn_same_numa_distance_line_tuple_list = []
                    nn_different_core_distance_line_tuple_list = []

                    for nn in neighbors:
                        neighbor_signature = get_signature(
                            nn, header_index_dict["cycles"]
                        )
                        neighbor_core = nn.split(",")[header_index_dict["core"]]

                        # identify the level of deployment
                        if process_core == neighbor_core or is_hyperthread(
                            num_of_physical_cores, process_core, neighbor_core
                        ):
                            _same_core = True
                            _same_numa = True
                            list_to_append = nn_same_core_distance_line_tuple_list
                        elif CPU_to_NUMA[process_core] == CPU_to_NUMA[neighbor_core]:
                            _same_core = False
                            _same_numa = True
                            list_to_append = nn_same_numa_distance_line_tuple_list
                        else:
                            _same_core = False
                            _same_numa = False
                            list_to_append = nn_different_core_distance_line_tuple_list

                        (
                            dist_from_neighbor,
                            contention_metric,
                        ) = get_min_distance_from_neighbor(
                            neighbor_signature,
                            detected_signature,
                            same_core=_same_core,
                            same_numa=_same_numa,
                        )

                        list_to_append.append(
                            (
                                dist_from_neighbor,
                                nn,
                                neighbor_signature,
                                contention_metric,
                            )
                        )

                    # Sort neighbors ascendingly based on distance (less distance -> more noise)
                    nn_same_core_distance_line_tuple_list.sort()
                    nn_same_numa_distance_line_tuple_list.sort()
                    nn_different_core_distance_line_tuple_list.sort()

                    # Show Same-core Noisy Neighbors in order, most noisy on top
                    i = 0
                    for nn_tup in nn_same_core_distance_line_tuple_list:
                        # skip processes with less than 10M cycles/sec
                        if nn_tup[2][0] < 10000000:
                            continue
                        if nn_tup[0] < args.distance_ratio:
                            NN_status_str = (
                                "[Same-Core/Thread] Noisy Neighbor #"
                                + str(i)
                                + ":\t"
                                + nn_tup[1]
                                + " Min distance: "
                                + str(round(nn_tup[0], 2))
                                + " Max similarity in: "
                                + nn_tup[3]
                            )
                            # Write to console
                            print(bcolors.FAIL + NN_status_str + bcolors.ENDC)
                            # Write to file
                            if args.outfile and out_file:
                                out_file.write(NN_status_str + "\n")
                            i += 1

                    # Show Same-NUMA Noisy Neighbors in order, most noisy on top
                    i = 0
                    for nn_tup in nn_same_numa_distance_line_tuple_list:
                        # skip processes with less than 10M cycles/sec
                        if nn_tup[2][0] < 10000000:
                            continue
                        if nn_tup[0] < args.distance_ratio:
                            NN_status_str = (
                                "[Same-NUMA] Noisy Neighbor #"
                                + str(i)
                                + ":\t"
                                + nn_tup[1]
                                + " Min distance: "
                                + str(round(nn_tup[0], 2))
                                + " Max similarity in: "
                                + nn_tup[3]
                            )
                            # Write to console
                            print(bcolors.FAIL + NN_status_str + bcolors.ENDC)
                            # Write to file
                            if args.outfile and out_file:
                                out_file.write(NN_status_str + "\n")
                            i += 1

                    # Show Different-core Noisy Neighbors in order, most noisy on top
                    i = 0
                    for nn_tup in nn_different_core_distance_line_tuple_list:
                        # skip processes with less than 10M cycles/sec
                        if nn_tup[2][0] < 10000000:
                            continue
                        if nn_tup[0] < args.distance_ratio:
                            NN_status_str = (
                                "[Diff-Core] Noisy Neighbor #"
                                + str(i)
                                + ":\t"
                                + nn_tup[1]
                                + " Min distance: "
                                + str(round(nn_tup[0], 2))
                                + " Max similarity in: "
                                + nn_tup[3]
                            )
                            # Write to console
                            print(bcolors.FAILl + NN_status_str + bcolors.ENDC)
                            # Write to file
                            if args.outfile and out_file:
                                out_file.write(NN_status_str + "\n")
                            i += 1

            process_signature_line_list = []
            neighbors = []

        elif (
            "containerID" in header_index_dict
            and pid_or_cid == parts[header_index_dict["containerID"]]
        ):
            process_signature_line_list.append(line)

        elif (
            "PID" in header_index_dict and pid_or_cid == parts[header_index_dict["PID"]]
        ):
            process_signature_line_list.append(line)

        elif "cycles" not in line and "Architecture:" not in line:
            neighbors.append(line)

        if "cycles" in line:
            header = line
            header_elements = header.split(",")

            for index, he in enumerate(header_elements):
                header_index_dict[he] = index
                index_header_dict[index] = he


if __name__ == "__main__":
    try:
        run_NN_detect()
    except KeyboardInterrupt:
        if args.outfile and out_file:
            out_file.close()
        print("Interrupted by user. Exiting...")
        sys.exit()
