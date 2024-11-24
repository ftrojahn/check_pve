#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ------------------------------------------------------------------------------
# check_pve.py - A check plugin for Proxmox Virtual Environment (PVE).
# Copyright (C) 2018-2024  Nicolai Buchwitz <nb@tipi-net.de>
# Thoralf Rickert-Wendt <trw@acoby.de>
#
# Version: 1.4.0a
#
# ------------------------------------------------------------------------------
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
# ------------------------------------------------------------------------------

import sys
import subprocess
import json
import re
from typing import Callable, Dict, Optional, Union, List

try:
    import argparse
    from datetime import datetime, timezone
    from enum import Enum
    from packaging import version

except ImportError as e:
    print("Missing python module: {}".format(e.message))
    sys.exit(255)


def compare_thresholds(
    threshold_warning: Dict, threshold_critical: Dict, comparator: Callable
) -> bool:
    """Perform sanity checks on thresholds parameters (used for argparse validation)."""
    ok = True
    keys = set(list(threshold_warning.keys()) + list(threshold_critical.keys()))
    for key in keys:
        if (key in threshold_warning and key in threshold_critical) or (
            None in threshold_warning and None in threshold_critical
        ):
            ok = ok and comparator(threshold_warning[key], threshold_critical[key])
        elif key in threshold_warning and None in threshold_critical:
            ok = ok and comparator(threshold_warning[key], threshold_critical[None])
        elif key in threshold_critical and None in threshold_warning:
            ok = ok and comparator(threshold_warning[None], threshold_critical[key])

    return ok


class CheckState(Enum):
    """Check return values."""

    OK = 0
    WARNING = 1
    CRITICAL = 2
    UNKNOWN = 3


def to_text(obj, encoding='utf-8', errors=None, nonstring='simplerepr'):
    if isinstance(obj, str):
        return obj

    if isinstance(obj, bytes):
        return obj.decode(encoding, 'surrogateescape')

    if nonstring == 'simplerepr':
        try:
            return str(obj)
        except UnicodeError:
            try:
                return repr(obj)
            except UnicodeError:
                # Giving up
                return u''
    return u''


class CheckThreshold:
    """Threshold representation used by the check command."""

    def __init__(self, value: float) -> None:
        self.value = value

    def __eq__(self, other: "CheckThreshold") -> bool:
        """Threshold is equal to given one."""
        return self.value == other.value

    def __lt__(self, other: "CheckThreshold") -> bool:
        """Threshold is lower to given one."""
        return self.value < other.value

    def __le__(self, other: "CheckThreshold") -> bool:
        """Threshold is lower or equal to given one."""
        return self.value <= other.value

    def __gt__(self, other: "CheckThreshold") -> bool:
        """Threshold is greater than given one."""
        return self.value > other.value

    def __ge__(self, other: "CheckThreshold") -> bool:
        """Threshold is greater or equal than given one."""
        return self.value >= other.value

    def check(self, value: float, lower: bool = False) -> bool:
        """Check threshold value as upper or lower boundary for given value."""
        if lower:
            return value < self.value

        return value > self.value

    @staticmethod
    def threshold_type(arg: str) -> Dict[str, "CheckThreshold"]:
        """Convert string argument(s) to threshold dict."""
        thresholds = {}

        try:
            thresholds[None] = CheckThreshold(float(arg))
        except ValueError:
            for t in arg.split(","):
                m = re.match("([a-z_0-9]+):([0-9.]+)", t)

                if m:
                    thresholds[m.group(1)] = CheckThreshold(float(m.group(2)))
                else:
                    raise argparse.ArgumentTypeError(f"Invalid threshold format: {t}")  # noqa: B904

        return thresholds


class RequestError(Exception):
    """Exception for request related errors."""

    def __init__(self, message: str, rc: int) -> None:
        self.message = message
        self.rc = rc

        super().__init__(self.message)


class CheckPVE:
    """Check command for Proxmox VE."""

    VERSION = "1.4.0a"
    UNIT_SCALE = {
            "GB": 10**9,
            "MB": 10**6,
            "KB": 10**3,
            "GiB": 2**30,
            "MiB": 2**20,
            "KiB": 2**10,
            "B": 1
        }

    def check_output(self) -> None:
        """Print check command output with perfdata and return code."""
        message = self.check_message
        if self.perfdata:
            message += self.get_perfdata()

        self.output(self.check_result, message)

    @staticmethod
    def output(rc: CheckState, message: str) -> None:
        """Print message to stdout and exit with given return code."""
        prefix = rc.name
        print(f"{prefix} - {message}")
        sys.exit(rc.value)

    def get_url(self, command):
        return command

    def run_command(self, handler, resource, **params):
        # pvesh strips these before handling, so might as well
        resource = resource.strip('/')
        # pvesh only has lowercase handlers
        handler = handler.lower()
        command = [
            "/usr/bin/pvesh",
            handler,
            resource,
            "--output=json"]
        for parameter, value in params.items():
            command += ["-{}".format(parameter), "{}".format(value)]
    
        pipe = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (result, stderr) = pipe.communicate()
        result = to_text(result)
        stderr = to_text(stderr).splitlines()
        
        if len(stderr) == 0:
            if not result:
                return {u"status": 200}
    
            # Attempt to marshall the data into JSON
            try:
                data = json.loads(result)
            except ValueError:
                return {u"status": 200, u"data": result}
    
            # Otherwise return data as a string
            return {u"status": 200, u"data": data}
    
        if len(stderr) >= 1:
            # This will occur when a param's value is invalid
            if stderr[0] == "400 Parameter verification failed.":
                return {u"status": 400, u"message": "\n".join(stderr[1:-1])}
    
            if stderr[0] == "no '{}' handler for '{}'".format(handler, resource):
                return {u"status": 405, u"message": stderr[0]}
    
            if handler == "get":
                if any(re.match(pattern, stderr[0]) for pattern in [
                    "^no such user \('.{3,64}?'\)$",
                    "^(group|role) '[A-Za-z0-9\.\-_]+' does not exist$",
                    "^domain '[A-Za-z][A-Za-z0-9\.\-_]+' does not exist$"]):
                    return {u"status": 404, u"message": stderr[0]}
    
            # This will occur when a param is invalid
            if len(stderr) >=2 and stderr[-2].startswith("400 unable to parse"):
                return {u"status": 400, u"message": "\n".join(stderr[:-1])}
    
            return {u"status": 500, u"message": u"\n".join(stderr), u"data": result}
    
        return {u"status": 500, u"message": u"Unexpected result occurred but no error message was provided by pvesh."}

    def request(self, url, method='get', **kwargs):
        response = None
        try:
            if method == 'post':
                response = self.run_command("post", url, kwargs.get('data', None))
            elif method == 'get':
                response = self.run_command("get", url)
            else:
                self.output(CheckState.CRITICAL, "Unsupport request method: {}".format(method))
        except Exception:
            self.output(CheckState.UNKNOWN, "Could not connect to PVE: Failed to run command")

        if response["status"] == 200:
            return response['data']
        else:
            message = "Could not fetch data from API: "
            message += "HTTP error code was {}".format(response.status)
            message += response["message"]

        if kwargs.get("raise_error", False):
            raise RequestError(message, response.status_code)

        self.output(CheckState.UNKNOWN, message)

    def check_api_value(self, url, message, **kwargs):
        result = self.request(url)
        used = None

        if "key" in kwargs:
            result = result[kwargs.get("key")]

        if isinstance(result, (dict,)):
            used_percent = self.get_value(result["used"], result["total"])
            used = self.get_value(result["used"])
            total = self.get_value(result["total"])

            self.add_perfdata(kwargs.get("perfkey", "usage"), used_percent)
            self.add_perfdata(
                kwargs.get("perfkey", "used"), used, max=total, unit=self.options.unit
            )
        else:
            used_percent = round(float(result) * 100, 2)
            self.add_perfdata(kwargs.get("perfkey", "usage"), used_percent)

        if self.options.values_mb:
            message += f" {used} {self.options.unit}"
            value = used
        else:
            message += f" {used_percent} %"
            value = used_percent

        self.check_thresholds(value, message)

    def check_vm_status(self, idx: Union[str, int], **kwargs: str) -> None:
        """Check status of virtual machine by vmid or name."""
        url = self.get_url(
            "cluster/resources",
        )
        data = self.request(url, params={"type": "vm"})

        expected_state = kwargs.get("expected_state", "running")
        only_status = kwargs.get("only_status", False)

        found = False
        for vm in data:
            if idx in (vm.get("name", None), vm.get("vmid", None)):
                # Check if VM (default) or LXC
                vm_type = "VM"
                if vm["type"] == "lxc":
                    vm_type = "LXC"

                if vm["status"] != expected_state:
                    self.check_message = (
                        f"{vm_type} '{vm['name']}' is {vm['status']} (expected: {expected_state})"
                    )
                    if not self.options.ignore_vm_status:
                        self.check_result = CheckState.CRITICAL
                else:
                    if self.options.node and self.options.node != vm["node"]:
                        self.check_message = (
                            f"{vm_type} '{vm['name']}' is {expected_state}, "
                            f"but located on node '{vm['node']}' instead of '{self.options.node}'"
                        )
                        self.check_result = CheckState.WARNING
                    else:
                        self.check_message = (
                            f"{vm_type} '{vm['name']}' is {expected_state} on node '{vm['node']}'"
                        )

                if vm["status"] == "running" and not only_status:
                    cpu = round(vm["cpu"] * 100, 2)
                    self.add_perfdata("cpu", cpu)

                    if self.options.values_mb:
                        memory = self.scale_value(vm["mem"])
                        self.add_perfdata(
                            "memory",
                            memory,
                            unit=self.options.unit,
                            max=self.scale_value(vm["maxmem"]),
                        )
                        disk = self.scale_value(vm["disk"])
                        self.add_perfdata(
                            "disk",
                            disk,
                            unit=self.options.unit,
                            max=self.scale_value(vm["maxdisk"]),
                        )

                    else:
                        memory = self.get_value(vm["mem"], vm["maxmem"])
                        self.add_perfdata("memory", memory)
                        disk = self.get_value(vm["disk"], vm["maxdisk"])
                        self.add_perfdata("disk", disk)

                    self.check_thresholds(
                        {"cpu": cpu, "memory": memory, "disk": disk}, message=self.check_message
                    )

                found = True
                break

        if not found:
            self.check_message = "VM or LXC '{}' not found".format(idx)
            self.check_result = CheckState.WARNING

    def check_disks(self) -> None:
        """Check disk health on specific Proxmox VE node."""
        url = self.get_url(f"nodes/{self.options.node}/disks")

        failed = []
        unknown = []
        disks = self.request(url + "/list")
        for disk in disks:
            name = disk["devpath"].replace("/dev/", "")

            if name in self.options.ignore_disks:
                continue

            if disk["health"] == "UNKNOWN":
                self.check_result = CheckState.WARNING
                unknown.append({"serial": disk["serial"], "device": disk["devpath"]})

            elif disk["health"] not in ("PASSED", "OK"):
                self.check_result = CheckState.WARNING
                failed.append({"serial": disk["serial"], "device": disk["devpath"]})

            if disk["wearout"] != "N/A":
                self.add_perfdata(f"wearout_{name}", disk["wearout"])

        if failed:
            self.check_message = f"{len(failed)} of {len(disks)} disks failed the health test:\n"
            for disk in failed:
                self.check_message += f"- {disk['device']} with serial '{disk['serial']}'\n"

        if unknown:
            self.check_message += (
                f"{len(unknown)} of {len(disks)} disks have unknown health status:\n"
            )
            for disk in unknown:
                self.check_message += f"- {disk['device']} with serial '{disk['serial']}'\n"

        if not failed and not unknown:
            self.check_message = "All disks are healthy"

    def check_replication(self) -> None:
        """Check replication status for either all or one specific vm / container."""
        url = self.get_url(f"nodes/{self.options.node}/replication")

        if self.options.vmid:
            data = self.request(url, params={"guest": self.options.vmid})
        else:
            data = self.request(url)

        failed_jobs = []  # format: [{guest: str, fail_count: int, error: str}]
        performance_data = []

        for job in data:
            if job["fail_count"] > 0:
                failed_jobs.append(
                    {"guest": job["guest"], "fail_count": job["fail_count"], "error": job["error"]}
                )
            else:
                performance_data.append({"id": job["id"], "duration": job["duration"]})

        if len(failed_jobs) > 0:
            message = f"Failed replication jobs on {self.options.node}: "
            for job in failed_jobs:
                message = (
                    message
                    + "GUEST: {j[guest]}, FAIL_COUNT: {j[fail_count]}, ERROR: {j[error]} ; ".format(
                        j=job
                    )
                )
            self.check_message = message
            self.check_result = CheckState.WARNING
        else:
            self.check_message = f"No failed replication jobs on {self.options.node}"
            self.check_result = CheckState.OK

        if len(performance_data) > 0:
            for metric in performance_data:
                self.add_perfdata("duration_" + metric["id"], metric["duration"], unit="s")

    def check_services(self) -> None:
        """Check state of core services on Proxmox VE node."""
        url = self.get_url(f"nodes/{self.options.node}/services")
        data = self.request(url)

        failed = {}
        for service in data:
            if (
                service["state"] != "running"
                and service.get("active-state", "active") == "active"
                and service["name"] not in self.options.ignore_services
            ):
                failed[service["name"]] = service["desc"]

        if failed:
            self.check_result = CheckState.CRITICAL
            message = f"{len(failed)} services are not running:\n\n"
            for name, description in failed.items():
                message += f"- {description} ({name}) is not running\n"
            self.check_message = message
        else:
            self.check_message = "All services are running"

    def check_subscription(self) -> None:
        """Check subscription status on Proxmox VE node."""
        url = self.get_url(f"nodes/{self.options.node}/subscription")
        data = self.request(url)

        if data["status"].lower() == "notfound":
            self.check_result = CheckState.WARNING
            self.check_message = "No valid subscription found"
        if data["status"].lower() == "inactive":
            self.check_result = CheckState.CRITICAL
            self.check_message = "Subscription expired"
        elif data["status"].lower() == "active":
            subscription_due_date = data["nextduedate"]
            subscription_product_name = data["productname"]

            date_expire = datetime.strptime(subscription_due_date, "%Y-%m-%d")
            date_today = datetime.today()
            delta = (date_expire - date_today).days

            message = f"{subscription_product_name} is valid until {subscription_due_date}"
            message_warning_critical = (
                "{subscription_product_name} will expire in {delta} days ({subscription_due_date})"
            )

            self.check_thresholds(
                delta,
                message,
                messageWarning=message_warning_critical,
                messageCritical=message_warning_critical,
                lowerValue=True,
            )

    def check_updates(self) -> None:
        """Check for package updates on Proxmox VE node."""
        url = self.get_url(f"nodes/{self.options.node}/apt/update")
        count = len(self.request(url))

        if count:
            self.check_result = CheckState.WARNING
            msg = "{} pending update"
            if count > 1:
                msg += "s"
            self.check_message = msg.format(count)
        else:
            self.check_message = "System up to date"

    def check_cluster_status(self) -> None:
        """Check if cluster is operational."""
        url = self.get_url("cluster/status")
        data = self.request(url)

        nodes = {}
        quorate = None
        cluster = ""
        for elem in data:
            if elem["type"] == "cluster":
                quorate = elem["quorate"]
                cluster = elem["name"]
            elif elem["type"] == "node":
                nodes[elem["name"]] = elem["online"]

        if quorate is None:
            self.check_message = "No cluster configuration found"
        elif quorate:
            node_count = len(nodes)
            nodes_online_count = len({k: v for k, v in nodes.items() if v})

            if node_count > nodes_online_count:
                diff = node_count - nodes_online_count
                self.check_result = CheckState.WARNING
                self.check_message = f"Cluster '{cluster}' is healthy, but {diff} node(s) offline'"
            else:
                self.check_message = f"Cluster '{cluster}' is healthy'"

            self.add_perfdata("nodes_total", node_count, unit="")
            self.add_perfdata("nodes_online", nodes_online_count, unit="")
        else:
            self.check_result = CheckState.CRITICAL
            self.check_message = "Cluster is unhealthy - no quorum"

    def check_zfs_fragmentation(self, name: Optional[str] = None) -> None:
        """Check all or one specific ZFS pool for fragmentation."""
        url = self.get_url(f"nodes/{self.options.node}/disks/zfs")
        data = self.request(url)

        warnings = []
        critical = []
        found = name is None
        for pool in data:
            found = found or name == pool["name"]
            if (name is not None and name == pool["name"]) or name is None:
                key = "fragmentation"
                if name is None:
                    key += f"_{pool['name']}"
                self.add_perfdata(key, pool["frag"])

                threshold_name = f"fragmentation_{name}"
                threshold_warning = self.threshold_warning(threshold_name)
                threshold_critical = self.threshold_critical(threshold_name)

                if threshold_critical is not None and pool["frag"] > float(
                    threshold_critical.value
                ):
                    critical.append(pool)
                elif threshold_warning is not None and pool["frag"] > float(
                    threshold_warning.value
                ):
                    warnings.append(pool)

        if not found:
            self.check_result = CheckState.UNKNOWN
            self.check_message = f"Could not fetch fragmentation of ZFS pool '{name}'"
        else:
            if warnings or critical:
                value = None
                if critical:
                    self.check_result = CheckState.CRITICAL
                    if name is not None:
                        value = critical[0]["frag"]
                else:
                    self.check_result = CheckState.WARNING
                    if name is not None:
                        value = warnings[0]["frag"]

                if name is not None:
                    self.check_message = (
                        f"Fragmentation of ZFS pool '{name}' is above thresholds: {value} %"
                    )
                else:
                    pool_above = len(warnings) + len(critical)
                    message = (
                        f"{pool_above} of {len(data)} ZFS pools are above fragmentation "
                        "thresholds:\n\n"
                    )
                    message += "\n".join(
                        [f"- {pool['name']} ({pool['frag']} %) is CRITICAL\n" for pool in critical]
                    )
                    message += "\n".join(
                        [f"- {pool['name']} ({pool['frag']} %) is WARNING\n" for pool in warnings]
                    )
                    self.check_message = message
            else:
                self.check_result = CheckState.OK
                if name is not None:
                    self.check_message = f"Fragmentation of ZFS pool '{name}' is OK"
                else:
                    self.check_message = "Fragmentation of all ZFS pools is OK"

    def check_zfs_health(self, name: Optional[str] = None) -> None:
        """Check all or one specific ZFS pool for health."""
        url = self.get_url(f"nodes/{self.options.node}/disks/zfs")
        data = self.request(url)

        unhealthy = []
        found = name is None
        healthy_conditions = ["online"]
        for pool in data:
            found = found or name == pool["name"]
            if (name is not None and name == pool["name"]) or name is None:
                if pool["health"].lower() not in healthy_conditions:
                    unhealthy.append(pool)

        if not found:
            self.check_result = CheckState.UNKNOWN
            self.check_message = f"Could not fetch health of ZFS pool '{name}'"
        else:
            if unhealthy:
                self.check_result = CheckState.CRITICAL
                message = f"{len(unhealthy)} ZFS pools are not healthy:\n\n"
                message += "\n".join(
                    [f"- {pool['name']} ({pool['health']}) is not healthy" for pool in unhealthy]
                )
                self.check_message = message
            else:
                self.check_result = CheckState.OK
                if name is not None:
                    self.check_message = f"ZFS pool '{name}' is healthy"
                else:
                    self.check_message = "All ZFS pools are healthy"

    def check_ceph_health(self) -> None:
        """Check health of CEPH cluster."""
        url = self.get_url("cluster/ceph/status")
        data = self.request(url)
        ceph_health = data.get("health", {})

        if "status" not in ceph_health:
            self.check_result = CheckState.UNKNOWN
            self.check_message = (
                "Could not fetch Ceph status from API. "
                "Check the output of 'pvesh get cluster/ceph' on your node"
            )
            return

        if ceph_health["status"] == "HEALTH_OK":
            self.check_result = CheckState.OK
            self.check_message = "Ceph Cluster is healthy"
        elif ceph_health["status"] == "HEALTH_WARN":
            self.check_result = CheckState.WARNING
            self.check_message = "Ceph Cluster is in warning state"
        elif ceph_health["status"] == "HEALTH_CRIT":
            self.check_result = CheckState.CRITICAL
            self.check_message = "Ceph Cluster is in critical state"
        else:
            self.check_result = CheckState.UNKNOWN
            self.check_message = "Ceph Cluster is in unknown state"

    def check_storage(self, name: str) -> None:
        """Check if storage exists and return usage."""
        url = self.get_url(f"nodes/{self.options.node}/storage")
        data = self.request(url)

        if not any(s["storage"] == name for s in data):
            self.check_result = CheckState.CRITICAL
            self.check_message = f"Storage '{name}' doesn't exist on node '{self.options.node}'"
            return

        url = self.get_url(f"nodes/{self.options.node}/storage/{name}/status")
        self.check_api_value(url, f"Usage of storage '{name}' is")

    def check_version(self) -> None:
        """Check PVE version."""
        url = self.get_url("version")
        data = self.request(url)
        if not data["version"]:
            self.check_result = CheckState.UNKNOWN
            self.check_message = "Unable to determine pve version"
        elif self.options.min_version and version.parse(self.options.min_version) > version.parse(
            data["version"]
        ):
            self.check_result = CheckState.CRITICAL
            self.check_message = (
                f"Current PVE version '{data['version']}' "
                f"({data['repoid']}) is lower than the min. "
                f"required version '{self.options.min_version}'"
            )
        else:
            self.check_message = (
                f"Your PVE instance version '{data['version']}' ({data['repoid']}) is up to date"
            )

    def _get_pool_members(self, pool: str) -> List[int]:
        """Get a list of vmids, which are members of a given resource pool.

        NOTE: The request needs the Pool.Audit permission!
        """
        members = []

        try:
            url = self.get_url(f"pools/{pool}")
            pools = self.request(url, raise_error=True)
            for pool in pools.get("members", []):
                members.append(pool["vmid"])
        except RequestError:
            print(
                f"Unable to fetch members of pool '{pool}'. "
                "Check if the name is correct and the role has the 'Pool.Audit' permission"
            )

        return members

    def check_vzdump_backup(self, name: Optional[str] = None) -> None:
        """Check for failed vzdump backup jobs."""
        tasks_url = self.get_url("cluster/tasks")
        tasks = self.request(tasks_url)
        tasks = [t for t in tasks if t["type"] == "vzdump"]

        # Filter by node id, if one is provided
        if self.options.node is not None:
            tasks = [t for t in tasks if t["node"] == self.options.node]

        # Filter by timestamp, if provided
        delta = self.threshold_critical("delta")
        if delta is not None:
            now = datetime.now(timezone.utc).timestamp()

            tasks = [t for t in tasks if not delta.check(now - t["starttime"])]

        # absent status = job still running
        tasks = [t for t in tasks if "status" in t]
        failed = len([t for t in tasks if t["status"] != "OK"])
        success = len(tasks) - failed
        self.check_message = f"{success} backup tasks successful, {failed} backup tasks failed"

        if failed > 0:
            self.check_result = CheckState.CRITICAL
        else:
            self.check_result = CheckState.OK
        if delta is not None:
            self.check_message += f" within the last {delta.value}s"

        nbu_url = self.get_url("cluster/backup-info/not-backed-up")
        not_backed_up = self.request(nbu_url)

        if len(not_backed_up) > 0:
            guest_ids = []

            for guest in not_backed_up:
                guest_ids.append(str(guest["vmid"]))

            ignored_vmids = []
            for pool in self.options.ignore_pools:
                ignored_vmids += map(str, self._get_pool_members(pool))

            remaining_not_backed_up = sorted(list(set(guest_ids) - set(ignored_vmids)))
            if len(remaining_not_backed_up) > 0:
                if self.check_result not in [CheckState.CRITICAL, CheckState.UNKNOWN]:
                    self.check_result = CheckState.WARNING
                    self.check_message += (
                        "\nThere are unignored guests not covered by any backup schedule: "
                        + ", ".join(remaining_not_backed_up)
                    )

    def check_memory(self) -> None:
        """Check memory usage of Proxmox VE node."""
        url = self.get_url(f"nodes/{self.options.node}/status")
        self.check_api_value(url, "Memory usage is", key="memory")

    def check_swap(self) -> None:
        """Check swap usage of Proxmox VE node."""
        url = self.get_url(f"nodes/{self.options.node}/status")
        self.check_api_value(url, "Swap usage is", key="swap")

    def check_cpu(self) -> None:
        """Check cpu usage of Proxmox VE node."""
        url = self.get_url(f"nodes/{self.options.node}/status")
        self.check_api_value(url, "CPU usage is", key="cpu")

    def check_io_wait(self) -> None:
        """Check io wait of Proxmox VE node."""
        url = self.get_url(f"nodes/{self.options.node}/status")
        self.check_api_value(url, "IO wait is", key="wait", perfkey="wait")

    def check_thresholds(
        self,
        values: Union[Dict[str, Union[int, float]], Union[int, float]],
        message: str,
        **kwargs: Dict,
    ) -> None:
        """Check numeric value against threshold for given metric name."""
        is_warning = False
        is_critical = False

        if not isinstance(values, dict):
            values = {None: values}

        for metric, value in values.items():
            value_warning = self.threshold_warning(metric)
            if value_warning is not None:
                is_warning = is_warning or value_warning.check(
                    value, kwargs.get("lowerValue", False)
                )

            value_critical = self.threshold_critical(metric)
            if value_critical is not None:
                is_critical = is_critical or value_critical.check(
                    value, kwargs.get("lowerValue", False)
                )

        if is_critical:
            self.check_result = CheckState.CRITICAL
            self.check_message = kwargs.get("messageCritical", message)
        elif is_warning:
            self.check_result = CheckState.WARNING
            self.check_message = kwargs.get("messageWarning", message)
        else:
            self.check_message = message

    def scale_value(self, value: Union[int, float]) -> float:
        """Scale value according to unit."""
        if self.options.unit in self.UNIT_SCALE:
            return value / self.UNIT_SCALE[self.options.unit]

        raise ValueError("wrong unit")

    def threshold_warning(self, name: str) -> CheckThreshold:
        """Get warning threshold for metric name (empty if none)."""
        return self.options.threshold_warning.get(
            name, self.options.threshold_warning.get(None, None)
        )

    def threshold_critical(self, name: str) -> CheckThreshold:
        """Get critical threshold for metric name (empty if none)."""
        return self.options.threshold_critical.get(
            name, self.options.threshold_critical.get(None, None)
        )

    def get_value(
        self, value: Union[int, float], total: Optional[Union[int, float]] = None
    ) -> float:
        """Get value scaled or as percentage."""
        value = float(value)

        if total:
            value /= float(total) / 100
        else:
            value = self.scale_value(value)

        return round(value, 2)

    def add_perfdata(self, name: str, value: Union[int, float], **kwargs: Dict) -> None:
        """Add metric to perfdata output."""
        unit = kwargs.get("unit", "%")

        perfdata = f"{name}={value}{unit}"

        threshold_warning = self.threshold_warning(name)
        threshold_critical = self.threshold_critical(name)

        perfdata += ";"
        if threshold_warning:
            perfdata += str(threshold_warning.value)

        perfdata += ";"
        if threshold_critical:
            perfdata += str(threshold_critical.value)

        perfdata += ";" + str(kwargs.get("min", 0))
        perfdata += ";" + str(kwargs.get("max", ""))

        self.perfdata.append(perfdata)

    def get_perfdata(self) -> str:
        """Get perfdata string."""
        perfdata = ""

        if self.perfdata:
            perfdata = "|"
            perfdata += " ".join(self.perfdata)

        return perfdata

    def check(self) -> None:
        """Execute the real check command."""
        self.check_result = CheckState.OK

        if self.options.mode == "cluster":
            self.check_cluster_status()
        elif self.options.mode == "version":
            self.check_version()
        elif self.options.mode == "memory":
            self.check_memory()
        elif self.options.mode == "swap":
            self.check_swap()
        elif self.options.mode in ("io_wait", "io-wait"):
            self.check_io_wait()
        elif self.options.mode == "disk-health":
            self.check_disks()
        elif self.options.mode == "cpu":
            self.check_cpu()
        elif self.options.mode == "services":
            self.check_services()
        elif self.options.mode == "updates":
            self.check_updates()
        elif self.options.mode == "subscription":
            self.check_subscription()
        elif self.options.mode == "storage":
            self.check_storage(self.options.name)
        elif self.options.mode in ["vm", "vm_status", "vm-status"]:
            only_status = self.options.mode in ["vm_status", "vm-status"]

            if self.options.name:
                idx = self.options.name
            else:
                idx = self.options.vmid

            if self.options.expected_vm_status:
                self.check_vm_status(
                    idx, expected_state=self.options.expected_vm_status, only_status=only_status
                )
            else:
                self.check_vm_status(idx, only_status=only_status)
        elif self.options.mode == "replication":
            self.check_replication()
        elif self.options.mode == "ceph-health":
            self.check_ceph_health()
        elif self.options.mode == "zfs-health":
            self.check_zfs_health(self.options.name)
        elif self.options.mode == "zfs-fragmentation":
            self.check_zfs_fragmentation(self.options.name)
        elif self.options.mode == "backup":
            self.check_vzdump_backup(self.options.name)
        else:
            message = f"Check mode '{self.options.mode}' not known"
            self.output(CheckState.UNKNOWN, message)

        self.check_output()

    def parse_args(self):
        p = argparse.ArgumentParser(description='Check command for PVE hosts via PVESH')

        check_opts = p.add_argument_group('Check Options')

        check_opts.add_argument(
            "-m",
            "--mode",
            choices=(
                "cluster",
                "version",
                "cpu",
                "memory",
                "swap",
                "storage",
                "io_wait",
                "io-wait",
                "updates",
                "services",
                "subscription",
                "vm",
                "vm_status",
                "vm-status",
                "replication",
                "disk-health",
                "ceph-health",
                "zfs-health",
                "zfs-fragmentation",
                "backup",
            ),
            required=True,
            help="Mode to use.",
        )

        check_opts.add_argument(
            "-n",
            "--node",
            dest="node",
            help="Node to check (necessary for all modes except cluster, version and backup)",
        )

        check_opts.add_argument("--name", dest="name", help="Name of storage, vm, or container")

        check_opts.add_argument(
            "--vmid", dest="vmid", type=int, help="ID of virtual machine or container"
        )

        check_opts.add_argument(
            "--expected-vm-status",
            choices=("running", "stopped", "paused"),
            help="Expected VM status",
        )

        check_opts.add_argument(
            "--ignore-vm-status",
            dest="ignore_vm_status",
            action="store_true",
            help="Ignore VM status in checks",
            default=False,
        )

        check_opts.add_argument(
            "--ignore-service",
            dest="ignore_services",
            action="append",
            metavar="NAME",
            help="Ignore service NAME in checks",
            default=[],
        )

        check_opts.add_argument(
            "--ignore-disk",
            dest="ignore_disks",
            action="append",
            metavar="NAME",
            help="Ignore disk NAME in health check",
            default=[],
        )

        check_opts.add_argument(
            "--ignore-pools",
            dest="ignore_pools",
            action="append",
            metavar="NAME",
            help="Ignore vms and containers in pool(s) NAME in checks",
            default=[],
        )

        check_opts.add_argument(
            "-w",
            "--warning",
            dest="threshold_warning",
            type=CheckThreshold.threshold_type,
            default={},
            help="Warning threshold for check value. Mutiple thresholds with name:value,name:value",
        )
        check_opts.add_argument(
            "-c",
            "--critical",
            dest="threshold_critical",
            type=CheckThreshold.threshold_type,
            default={},
            help=(
                "Critical threshold for check value. "
                "Mutiple thresholds with name:value,name:value"
            ),
        )
        check_opts.add_argument(
            "-M",
            dest="values_mb",
            action="store_true",
            default=False,
            help=(
                "Values are shown in the unit which is set with --unit (if available). "
                "Thresholds are also treated in this unit"
            ),
        )
        check_opts.add_argument(
            "-V",
            "--min-version",
            dest="min_version",
            type=str,
            help="The minimal pve version to check for. Any version lower than this will return "
            "CRITICAL.",
        )

        check_opts.add_argument(
            "--unit",
            choices=self.UNIT_SCALE.keys(),
            default="MiB",
            help="Unit which is used for performance data and other values",
        )

        options = p.parse_args()

        if not options.node and options.mode not in [
            "cluster",
            "vm",
            "vm_status",
            "version",
            "ceph-health",
            "backup",
        ]:
            p.print_usage()
            message = f"{p.prog}: error: --mode {options.mode} requires node name (--node)"
            self.output(CheckState.UNKNOWN, message)

        if (
            not options.vmid
            and not options.name
            and options.mode in ("vm", "vm_status", "vm-status")
        ):
            p.print_usage()
            message = (
                f"{p.prog}: error: --mode {options.mode} requires either "
                "vm name (--name) or id (--vmid)",
            )
            self.output(CheckState.UNKNOWN, message)

        if not options.name and options.mode == "storage":
            p.print_usage()
            message = f"{p.prog}: error: --mode {options.mode} requires storage name (--name)"
            self.output(CheckState.UNKNOWN, message)

        if options.threshold_warning and options.threshold_critical:
            if options.mode != "subscription" and not compare_thresholds(
                options.threshold_warning, options.threshold_critical, lambda w, c: w <= c
            ):
                p.error("Critical value must be greater than warning value")
            elif options.mode == "subscription" and not compare_thresholds(
                options.threshold_warning, options.threshold_critical, lambda w, c: w >= c
            ):
                p.error("Critical value must be lower than warning value")

        self.options = options

    def __init__(self) -> None:
        self.options = {}
        self.perfdata = []
        self.check_result = CheckState.UNKNOWN
        self.check_message = ""

        self.parse_args()


pve = CheckPVE()
pve.check()
