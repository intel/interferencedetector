#!/usr/bin/env python3

###########################################################################################################
# Copyright (C) 2023 Intel Corporation
# SPDX-License-Identifier: MIT
###########################################################################################################

import subprocess
from subprocess import Popen, PIPE, SubprocessError
import argparse
from multiprocessing import Manager, Process, Lock
import time
from datetime import datetime
import sys
from time import sleep
import pandas as pd
import os
import boto3
import botocore

# List of metrics to average across PIDs running within the same container
metrics_to_average = {
    "cpi",
    "l1i_mpi",
    "l1d_hit_ratio",
    "l1d_miss_ratio",
    "l2_miss_ratio",
    "l3_miss_ratio",
    "avg_q_len",
    "avg_q_latency",
}


def get_procmon_out(
    container_to_PID_dict,
    lock,
    container_to_signature_dict=None,
    duration=0,
    client=None,
    cloudwatch_sampling_duration_in_sec=10,
):
    metrics = []
    # The following dictionary has data for each process and each core
    process_data_dict = {}
    process_PID_index = 1
    process_index = 2
    core_index = 4
    procmon_command = ["python3", "procmon.py"]
    seconds_to_skip = max(cloudwatch_sampling_duration_in_sec - 1, 0)
    seconds_counter = 0
    if duration > 0:
        procmon_command += ["-d", str(duration)]
    proc = Popen(procmon_command, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    try:
        while True:
            line = proc.stdout.readline().decode("utf-8").rstrip()
            if not line or "Exiting.." in line:
                print("No output from procmon. Exiting...", line)
                return
            if "Timestamp" in line:
                metrics = line.split(",")
                for i in range(len(metrics)):
                    if metrics[i] == "PID":
                        process_PID_index = i
                    elif metrics[i] == "core":
                        core_index = i
                    elif metrics[i] == "process":
                        process_index = i

            elif "Architecture:" in line:
                continue

            elif "------------" in line:
                seconds_counter += 1
                # print dockermon output
                sys.stdout.flush()
                # waiting for lock on container_to_PID_dict
                lock.acquire()
                try:
                    if (
                        args.aggregate_on_containerID
                    ):  # show a single record per container
                        container_aggregate_vec = {}
                        for PID in process_data_dict:
                            if PID in container_to_PID_dict:
                                container_ID = container_to_PID_dict[PID]
                                container_aggregate_vec[container_ID] = {}
                                aggregate_vec_dict = container_aggregate_vec[
                                    container_ID
                                ]
                                data_metrics = metrics[core_index + 1 :]
                                for data_line in process_data_dict[PID]:
                                    line_parts = data_line[core_index + 1 :]
                                    for i, data_point in enumerate(line_parts):
                                        if data_metrics[i] not in aggregate_vec_dict:
                                            aggregate_vec_dict[data_metrics[i]] = []

                                        aggregate_vec_dict[data_metrics[i]].append(
                                            float(data_point)
                                        )
                        print(
                            "---------------------------------------------------------------------------------"
                        )
                        header = "Timestamp,containerID," + ",".join(
                            metrics[core_index + 1 :]
                        )
                        print(header)
                        if container_to_signature_dict is not None:
                            if "header" not in container_to_signature_dict:
                                container_to_signature_dict["header"] = ",".join(
                                    metrics[core_index + 1 :]
                                )
                            if "key" not in container_to_signature_dict:
                                container_to_signature_dict["key"] = "container_ID"
                        for container_ID in container_aggregate_vec:
                            aggregate_vec_dict = container_aggregate_vec[container_ID]

                            aggregate_vec = []
                            for dm in data_metrics:
                                if dm in metrics_to_average:
                                    aggregate_vec.append(
                                        str(
                                            round(
                                                sum(aggregate_vec_dict[dm])
                                                / len(aggregate_vec_dict[dm]),
                                                2,
                                            )
                                        )
                                    )
                                else:
                                    aggregate_vec.append(
                                        str(sum(aggregate_vec_dict[dm]))
                                    )

                            t = datetime.now().timestamp()
                            print(
                                str(t)
                                + ","
                                + container_ID
                                + ","
                                + ",".join(aggregate_vec)
                            )
                            if container_to_signature_dict is not None:
                                if container_ID not in container_to_signature_dict:
                                    container_to_signature_dict[container_ID] = []
                                container_to_signature_dict[
                                    container_ID
                                ] = container_to_signature_dict[container_ID] + [
                                    (t, ",".join(aggregate_vec))
                                ]
                            if client is not None:
                                if seconds_counter >= seconds_to_skip:
                                    send_to_cloud_watch(
                                        client,
                                        ",".join(metrics[core_index + 1 :]),
                                        container_ID,
                                        ",".join(aggregate_vec),
                                    )

                    elif (
                        args.aggregate_on_core
                    ):  # Show a single record per ContainerID/Core
                        container_aggregate_vec = {}
                        for PID in process_data_dict:
                            if PID in container_to_PID_dict:
                                container_ID = container_to_PID_dict[PID]
                                container_aggregate_vec[container_ID] = {}
                                aggregate_vec_dict = container_aggregate_vec[
                                    container_ID
                                ]
                                data_metrics = metrics[core_index + 1 :]
                                for vec in process_data_dict[PID]:
                                    vec_parts = vec[core_index + 1 :]
                                    core = vec[core_index]
                                    if core not in aggregate_vec_dict:
                                        aggregate_vec_dict[core] = {}

                                    for i, data_point in enumerate(vec_parts):
                                        if (
                                            data_metrics[i]
                                            not in aggregate_vec_dict[core]
                                        ):
                                            aggregate_vec_dict[core][
                                                data_metrics[i]
                                            ] = []

                                        aggregate_vec_dict[core][
                                            data_metrics[i]
                                        ].append(float(data_point))
                        print(
                            "---------------------------------------------------------------------------------"
                        )
                        header = "Timestamp,containerID,core," + ",".join(
                            metrics[core_index + 1 :]
                        )
                        print(header)
                        if container_to_signature_dict is not None:
                            if "header" not in container_to_signature_dict:
                                container_to_signature_dict["header"] = ",".join(
                                    metrics[core_index + 1 :]
                                )
                            if "key" not in container_to_signature_dict:
                                container_to_signature_dict["key"] = "containerID_core"
                        for container_ID in container_aggregate_vec:
                            for core in container_aggregate_vec[container_ID]:
                                aggregate_vec_dict = container_aggregate_vec[
                                    container_ID
                                ][core]

                                aggregate_vec = []
                                for dm in data_metrics:
                                    if dm in metrics_to_average:
                                        aggregate_vec.append(
                                            str(
                                                sum(aggregate_vec_dict[dm])
                                                / len(aggregate_vec_dict[dm])
                                            )
                                        )
                                    else:
                                        aggregate_vec.append(
                                            str(sum(aggregate_vec_dict[dm]))
                                        )

                                t = datetime.now().timestamp()
                                print(
                                    str(t)
                                    + ","
                                    + container_ID
                                    + ","
                                    + str(core)
                                    + ","
                                    + ",".join(aggregate_vec)
                                )
                                key = container_ID + "_" + str(core)
                                if container_to_signature_dict is not None:
                                    if key not in container_to_signature_dict:
                                        container_to_signature_dict[key] = []
                                    container_to_signature_dict[
                                        key
                                    ] = container_to_signature_dict[key] + [
                                        (t, ",".join(aggregate_vec))
                                    ]
                                if client is not None:
                                    if seconds_counter >= seconds_to_skip:
                                        send_to_cloud_watch(
                                            client,
                                            ",".join(metrics[core_index + 1 :]),
                                            key,
                                            ",".join(aggregate_vec),
                                        )
                    else:  # Show a single record per PID
                        print(
                            "---------------------------------------------------------------------------------"
                        )
                        header = "Timestamp,containerID,PID,process," + ",".join(
                            metrics[process_index + 1 :]
                        )
                        print(header)
                        if container_to_signature_dict is not None:
                            if "header" not in container_to_signature_dict:
                                container_to_signature_dict["header"] = ",".join(
                                    metrics[process_index:]
                                )
                            if "key" not in container_to_signature_dict:
                                container_to_signature_dict["key"] = "containerID_PID"

                        for PID in process_data_dict:
                            if PID in container_to_PID_dict:
                                for line in process_data_dict[PID]:
                                    t = datetime.now().timestamp()
                                    print(
                                        str(t)
                                        + ","
                                        + container_to_PID_dict[PID]
                                        + ","
                                        + PID
                                        + ","
                                        + ",".join(line[process_index:])
                                    )
                                    key = container_to_PID_dict[PID] + "_" + PID
                                    if container_to_signature_dict is not None:
                                        if key not in container_to_signature_dict:
                                            container_to_signature_dict[key] = []
                                        container_to_signature_dict[
                                            key
                                        ] = container_to_signature_dict[key] + [
                                            (t, ",".join(line[process_index:]))
                                        ]
                                    if client is not None:
                                        if seconds_counter >= seconds_to_skip:
                                            send_to_cloud_watch(
                                                client,
                                                ",".join(metrics[process_index:]),
                                                key,
                                                ",".join(line[process_index:]),
                                            )
                    if seconds_counter >= seconds_to_skip:
                        seconds_counter = 0
                finally:
                    # Releasing the lock
                    lock.release()
                # clear Process data
                process_data_dict = {}

            elif line.startswith("**Warning**"):
                print(line)
            else:
                dataVals = line.split(",")
                if process_PID_index < len(dataVals):
                    if dataVals[process_PID_index] not in process_data_dict:
                        process_data_dict[dataVals[process_PID_index]] = []
                    process_data_dict[dataVals[process_PID_index]].append(dataVals)

    except KeyboardInterrupt:
        print("Exiting procmon thread")
        return


def get_process_to_container_mapping(container_to_PID_dict, lock):
    while True:
        try:
            local_container_to_PID_dict = {}

            t0 = time.time()

            p = subprocess.Popen(
                ["sudo", "ps", "-e", "-o", "pid,cgroup"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            p2 = subprocess.Popen(
                ["grep", "docker-"],
                stdin=p.stdout,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            p.stdout.close()

            try:
                out, _err = p2.communicate()
            except SubprocessError as e:
                print("Failed to get process to container mapping.", e)
                print("Exiting...")
                sys.exit()

            t1 = time.time()
            diff = t1 - t0
            if args.verbose:
                print("Sudo ps and grep Latency: ", str(round(diff, 2)), " seconds")
            out_lines = out.decode("utf-8").split("\n")

            for line in out_lines:
                parts = line.strip().split(" ")
                if len(parts) > 1:
                    cont_short_name = parts[1].split("docker-")[1][0:12]
                    local_container_to_PID_dict[parts[0]] = cont_short_name

            t1 = time.time()
            diff = t1 - t0

            # Waiting for lock on container_to_PID_dict
            lock.acquire()

            try:
                # Here we copy the data from the local dictionary to the shared dictionary
                container_to_PID_dict.clear()
                for k in local_container_to_PID_dict:
                    container_to_PID_dict[k] = local_container_to_PID_dict[k]
            finally:
                # Releasing the lock
                lock.release()

            sys.stdout.flush()
            sleep(1)
            if args.verbose:
                print("Total API Calls Latency: ", str(round(diff, 2)), " seconds")
            # return cont_pids,cont_names
        except KeyboardInterrupt:
            print("Exiting docker thread")
            return


def get_args():
    parser = argparse.ArgumentParser(
        description="Display procmon data on docker container level",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-v", "--verbose", action="store_true", help="show raw verbose logging info."
    )

    parser.add_argument(
        "--collect_signatures",
        action="store_true",
        help="collect signatures of running containers and dump to: signatures_*.csv",
    )

    parser.add_argument(
        "-d",
        "--duration",
        type=int,
        default=0,
        help="Collection duration in seconds. Default is 0 (indefinitely)",
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--aggregate_on_core",
        action="store_true",
        help="Show a single aggregated record for each containerID + core. This option is mutually exclusive with '--aggregate_on_containerID'",
    )

    group.add_argument(
        "--aggregate_on_containerID",
        action="store_true",
        help="Show a single aggregated record for each containerID. This option is mutually exclusive with '--aggregate_on_core'",
    )

    # cloudwatch arguments
    parser.add_argument(
        "--export_to_cloudwatch",
        action="store_true",
        help="Export collected data to cloudwatch. Expects the following AWS parameters to be configured in `aws cli`: aws_access_key_id, aws_secret_access_key, aws_region.",
    )

    parser.add_argument(
        "--cloudwatch_sampling_duration_in_sec",
        type=int,
        default=10,
        help="Duration between samples of data points sent to cloudwatch. Default is 10 (one sample every 10 seconds). The minimum duration is 1 second. Note: this argument is only effective when --export_to_cloudwatch is set.",
    )

    args = parser.parse_args()
    if args.cloudwatch_sampling_duration_in_sec < 1:
        parser.error(
            "Wrong value error. Minimum value of --cloudwatch_sampling_duration_in_sec is 1 (one sample per second)"
        )

    return args


def initialize_cloudwatch_client():
    try:
        client = boto3.client("cloudwatch")
    except (
        botocore.exceptions.ClientError,
        botocore.exceptions.EndpointConnectionError,
    ) as err:
        print("Failed to export data to cloudwatch. ", str(err))
        sys.exit()
    return client


def send_to_cloud_watch(client, header, key, line):
    header_fields = header.split(",")
    values = line.split(",")
    metric_data_list = []
    for i, h in enumerate(header_fields):
        try:
            float_value = float(values[i])
        except ValueError:
            continue
        key_parts = key.split("_")
        metric_data_list.append(
            {
                "MetricName": str(h),
                "Dimensions": [
                    {"Name": "ContainerID", "Value": key_parts[0]},
                ],
                "Value": float_value,
                "Unit": "Count",
            }
        )
    try:
        response = client.put_metric_data(
            Namespace="Dockermon",
            MetricData=metric_data_list,
        )
    except (
        botocore.exceptions.ClientError,
        botocore.exceptions.EndpointConnectionError,
    ) as err:
        print("Failed to export data to cloudwatch. ", str(err))
        sys.exit()
    return response


def save_signatures_to_CSV(container_to_signature_dict):
    if len(container_to_signature_dict) == 2:  # header and key only
        print("No data to save. Exiting...")
        sys.exit()
    timestr = time.strftime("%Y-%m-%d_%H-%M-%S")
    current_directory = os.getcwd()
    folder_name = "dockermon_" + timestr
    output_directory = os.path.join(current_directory, folder_name)
    if os.path.exists(output_directory):
        print(
            "Cannot create directory",
            output_directory,
            "directory already exists!\nExiting...",
        )
        sys.exit()
    try:
        os.makedirs(output_directory)
    except OSError as error:
        print("Output directory can not be created\n", error.message)
        sys.exit()
    columns = (
        [container_to_signature_dict["key"]]
        + ["TimeStamp"]
        + container_to_signature_dict["header"].split(",")
    )
    data_list = []
    for key in container_to_signature_dict:
        if key == "header" or key == "key":
            continue
        for event_list in container_to_signature_dict[key]:
            data_list.append([key] + [event_list[0]] + event_list[1].split(","))
    # prepare dataframe
    df = pd.DataFrame(data_list)
    df.columns = columns
    df = df[
        [container_to_signature_dict["key"]]
        + ["TimeStamp"]
        + columns[columns.index("cycles") :]
    ]
    df = df.apply(pd.to_numeric, errors="ignore")
    df.round(2).to_csv(
        output_directory + "//" + "signatures_time_series.csv", index=False
    )
    # prepare mean and max dataframes
    df.insert(
        loc=1,
        column="TimeStamp_Count",
        value=df.groupby(container_to_signature_dict["key"])["TimeStamp"].transform(
            "nunique"
        ),
    )
    df = df.drop(["TimeStamp"], axis=1)
    mean_df = df.groupby(container_to_signature_dict["key"]).agg("mean")
    mean_df.round(2).to_csv(output_directory + "//" + "signatures_mean.csv")
    min_df = df.groupby(container_to_signature_dict["key"]).agg("min")
    min_df.round(2).to_csv(output_directory + "//" + "signatures_min.csv")
    max_df = df.groupby(container_to_signature_dict["key"]).agg("max")
    max_df.round(2).to_csv(output_directory + "//" + "signatures_max.csv")
    print("Successfully saved signatures to: ", folder_name)


if __name__ == "__main__":
    args = get_args()
    try:
        lock = Lock()
        manager = Manager()
        container_to_PID_dict = manager.dict()
        cloudwatch_client = None
        if args.export_to_cloudwatch:
            cloudwatch_client = initialize_cloudwatch_client()

        if args.collect_signatures:
            container_to_signature_dict = manager.dict()
            procmon = Process(
                target=get_procmon_out,
                args=(
                    container_to_PID_dict,
                    lock,
                    container_to_signature_dict,
                    args.duration,
                    cloudwatch_client,
                    args.cloudwatch_sampling_duration_in_sec,
                ),
            )
        else:
            procmon = Process(
                target=get_procmon_out,
                args=(
                    container_to_PID_dict,
                    lock,
                    None,
                    args.duration,
                    cloudwatch_client,
                    args.cloudwatch_sampling_duration_in_sec,
                ),
            )
        docker = Process(
            target=get_process_to_container_mapping, args=(container_to_PID_dict, lock)
        )

        procmon.start()
        docker.start()

        while procmon.is_alive() and docker.is_alive():
            sleep(2)

        # If procmon or docker processes are not alive, terminate
        procmon.terminate()
        docker.terminate()

        procmon.join()
        docker.join()

        global procmon_exit, docker_exit
        procmon_exit = False
        docker_exit = False

    except (KeyboardInterrupt, Exception) as e:
        print("Exiting Main Thread", e)
        if procmon:
            procmon.terminate()
        if docker:
            docker.terminate()

    if args.collect_signatures and container_to_signature_dict is not None:
        save_signatures_to_CSV(container_to_signature_dict)
    sys.exit()
