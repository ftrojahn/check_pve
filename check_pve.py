#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ------------------------------------------------------------------------------
# check_pve.py - A check plugin for Proxmox Virtual Environment (PVE).
# Copyright (C) 2018-2020  Nicolai Buchwitz <nb@tipi-net.de>, 
# Thoralf Rickert-Wendt <trw@acoby.de>
#
# Version: 1.2.0a
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

try:
    from enum import Enum
    from datetime import datetime
    from distutils.version import LooseVersion
    import argparse

except ImportError as e:
    print("Missing python module: {}".format(e.message))
    sys.exit(255)

class CheckState(Enum):
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


class CheckPVE:
    VERSION = '1.2.0a'

    def check_output(self):
        message = self.check_message
        if self.perfdata:
            message += self.get_perfdata()

        self.output(self.check_result, message)

    @staticmethod
    def output(rc, message):
        prefix = rc.name
        message = '{} - {}'.format(prefix, message)

        print(message)
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

            self.output(CheckState.UNKNOWN, message)

    def check_api_value(self, url, message, **kwargs):
        result = self.request(url)
        used = None

        if 'key' in kwargs:
            result = result[kwargs.get('key')]

        if isinstance(result, (dict,)):
            used_percent = self.get_value(result['used'], result['total'])
            used = self.get_value(result['used'])
            total = self.get_value(result['total'])

            self.add_perfdata(kwargs.get('perfkey', 'usage'), used_percent)
            self.add_perfdata(kwargs.get('perfkey', 'used'), used, max=total, unit='MB')
        else:
            used_percent = round(float(result) * 100, 2)
            self.add_perfdata(kwargs.get('perfkey', 'usage'), used_percent)

        if self.options.values_mb:
            message += ' {} {}'.format(used, 'MB')
            value = used
        else:
            message += ' {} {}'.format(used_percent, '%')
            value = used_percent

        self.check_thresholds(value, message)

    def check_vm_status(self, idx, **kwargs):
        url = self.get_url('cluster/resources', )
        data = self.request(url, params={'type': 'vm'})

        expected_state = kwargs.get("expected_state", "running")
        only_status = kwargs.get("only_status", False)

        found = False
        for vm in data:
            if vm['name'] == idx or vm['vmid'] == idx:
                # Check if VM (default) or LXC
                vm_type = "VM"
                if vm['type'] == 'lxc':
                    vm_type = "LXC"

                if vm['status'] != expected_state:
                    self.check_message = "{} '{}' is {} (expected: {})".format(vm_type, vm['name'], vm['status'], expected_state)
                    if not self.options.ignore_vm_status:
                        self.check_result = CheckState.CRITICAL
                else:
                    if self.options.node and self.options.node != vm['node']:
                        self.check_message = "{} '{}' is {}, but located on node '{}' instead of '{}'" \
                            .format(vm_type, vm['name'], expected_state, vm['node'], self.options.node)
                        self.check_result = CheckState.OK
                    else:
                        self.check_message = "{} '{}' on node '{}' is {}" \
                            .format(vm_type, vm['name'], vm['node'], expected_state)

                if vm['status'] == 'running' and not only_status:
                    self.add_perfdata("cpu", round(vm['cpu'] * 100, 2))

                    if self.options.values_mb:
                        memory = vm['mem'] / 1024 / 1024
                        self.add_perfdata("memory", memory, unit="MB", max=vm['maxmem'] / 1024 / 1024)

                    else:
                        memory = self.get_value(vm['mem'], vm['maxmem'])
                        self.add_perfdata("memory", memory)

                    self.check_thresholds(memory, message=self.check_message)

                found = True
                break

        if not found:
            self.check_message = "VM or LXC '{}' not found".format(idx)
            self.check_result = CheckState.WARNING

    def check_disks(self):
        url = self.get_url('nodes/{}/disks'.format(self.options.node))

        failed = []
        unknown = []
        disks = self.request(url + '/list')
        for disk in disks:
            name = disk['devpath'].replace('/dev/', '')

            if name in self.options.ignore_disks:
                continue

            if disk['health'] in ('UNKNOWN'):
                self.check_result = CheckState.WARNING
                unknown.append({"serial": disk["serial"], "device": disk['devpath']})

            elif disk['health'] not in ('PASSED', 'OK'):
                self.check_result = CheckState.WARNING
                failed.append({"serial": disk["serial"], "device": disk['devpath']})

            if disk['wearout'] != 'N/A':
                self.add_perfdata('wearout_{}'.format(name), disk['wearout'])

        if failed:
            self.check_message = "{} of {} disks failed the health test:\n".format(len(failed), len(disks))
            for disk in failed:
                self.check_message += "- {} with serial '{}'\n".format(disk['device'], disk['serial'])

        if unknown:
            self.check_message += "{} of {} disks have unknown health status:\n".format(len(unknown), len(disks))
            for disk in unknown:
                self.check_message += "- {} with serial '{}'\n".format(disk['device'], disk['serial'])

        if not failed and not unknown:
            self.check_message = "All disks are healthy"

    def check_replication(self, name):
        url = self.get_url('nodes/{}/replication'.format(self.options.node))

        if self.options.vmid:
            data = self.request(url, params={'guest': self.options.vmid})
        else:
            data = self.request(url)

        failed_jobs = []  # format: [{guest: str, fail_count: int, error: str}]
        performance_data = []

        for job in data:
            if job['fail_count'] > 0:
                failed_jobs.append({'guest': job['guest'], 'fail_count': job['fail_count'], 'error': job['error']})
            else:
                performance_data.append({'id': job['id'], 'duration': job['duration']})

        if len(failed_jobs) > 0:
            message = "Failed replication jobs on {}: ".format(self.options.node)
            for job in failed_jobs:
                message = message + "GUEST: {j[guest]}, FAIL_COUNT: {j[fail_count]}, ERROR: {j[error]} ; ".format(j=job)
            self.check_message = message
            self.check_result = CheckState.WARNING
        else:
            self.check_message = "No failed replication jobs on {}".format(self.options.node)
            self.check_result = CheckState.OK

        if len(performance_data) > 0:
            for metric in performance_data:
                self.add_perfdata('duration_' + metric['id'], metric['duration'], unit='s')

    def check_services(self):
        url = self.get_url('nodes/{}/services'.format(self.options.node))
        data = self.request(url)

        failed = {}
        for service in data:
            if service['state'] != 'running' and service['active-state'] == 'active' and service['name'] not in self.options.ignore_services:
                failed[service['name']] = service['desc']


        if failed:
            self.check_result = CheckState.CRITICAL
            message = "{} services are not running:\n\n".format(len(failed))
            message += "\n".join(['- {} ({}) is not running'.format(failed[i], i) for i in failed])
            self.check_message = message
        else:
            self.check_message = "All services are running"

    def check_subscription(self):
        url = self.get_url('nodes/{}/subscription'.format(self.options.node))
        data = self.request(url)

        if data['status'] == 'NotFound':
            self.check_result = CheckState.WARNING
            self.check_message = "No valid subscription found"
        if data['status'] == 'Inactive':
            self.check_result = CheckState.CRITICAL
            self.check_message = "Subscription expired"
        elif data['status'] == 'Active':
            subscription_due_date = data['nextduedate']
            subscription_product_name = data['productname']

            date_expire = datetime.strptime(subscription_due_date, '%Y-%m-%d')
            date_today = datetime.today()
            delta = (date_expire - date_today).days

            message = '{} is valid until {}'.format(
                subscription_product_name,
                subscription_due_date)
            message_warning_critical = '{} will expire in {} days ({})'.format(
                subscription_product_name,
                delta,
                subscription_due_date)

            self.check_thresholds(delta, message, messageWarning=message_warning_critical,
                                  messageCritical=message_warning_critical, lowerValue=True)

    def check_updates(self):
        url = self.get_url('nodes/{}/apt/update'.format(self.options.node))
        count = len(self.request(url))

        if count:
            self.check_result = CheckState.WARNING
            msg = "{} pending update"
            if count > 1:
                msg += "s"
            self.check_message = msg.format(count)
        else:
            self.check_message = "System up to date"

    def check_cluster_status(self):
        url = self.get_url('cluster/status')
        data = self.request(url)

        nodes = {}
        quorate = None
        cluster = ''
        for elem in data:
            if elem['type'] == 'cluster':
                quorate = elem['quorate']
                cluster = elem['name']
            elif elem['type'] == 'node':
                nodes[elem['name']] = elem['online']

        if quorate is None:
            self.check_message = 'No cluster configuration found'
        elif quorate:
            node_count = len(nodes)
            nodes_online_count = len({k: v for k, v in nodes.items() if v})

            if node_count > nodes_online_count:
                diff = node_count - nodes_online_count
                self.check_result = CheckState.WARNING
                self.check_message = "Cluster '{}' is healthy, but {} node(s) offline'".format(cluster, diff)
            else:
                self.check_message = "Cluster '{}' is healthy'".format(cluster)

            self.add_perfdata('nodes_total', node_count, unit='')
            self.add_perfdata('nodes_online', nodes_online_count, unit='')
        else:
            self.check_result = CheckState.CRITICAL
            self.check_message = 'Cluster is unhealthy - no quorum'

    def check_zfs_fragmentation(self, name=None):
        url = self.get_url('nodes/{}/disks/zfs'.format(self.options.node))
        data = self.request(url)

        warnings = []
        critical = []
        found = name is None
        for pool in data:
            found = found or name == pool['name']
            if (name is not None and name == pool['name']) or name is None:
                key = "fragmentation"
                if name is None:
                    key += '_{}'.format(pool['name'])
                self.add_perfdata(key, pool['frag'])

                if self.options.threshold_critical is not None and pool['frag'] > float(
                        self.options.threshold_critical):
                    critical.append(pool)
                elif self.options.threshold_warning is not None and pool['frag'] > float(
                        self.options.threshold_warning):
                    warnings.append(pool)

        if not found:
            self.check_result = CheckState.UNKNOWN
            self.check_message = "Could not fetch fragmentation of ZFS pool '{}'".format(name)
        else:
            if warnings or critical:
                if critical:
                    self.check_result = CheckState.CRITICAL
                else:
                    self.check_result = CheckState.WARNING

                message = "{} of {} ZFS pools are above fragmentation thresholds:\n\n".format(
                    len(warnings) + len(critical), len(data))
                message += "\n".join(
                    ['- {} ({} %) is CRITICAL\n'.format(pool['name'], pool['frag']) for pool in critical])
                message += "\n".join(
                    ['- {} ({} %) is WARNING\n'.format(pool['name'], pool['frag']) for pool in warnings])
                self.check_message = message
            else:
                self.check_result = CheckState.OK
                if name is not None:
                    self.check_message = "Fragmentation of ZFS pool '{}' is OK".format(name)
                else:
                    self.check_message = "Fragmentation of all ZFS pools is OK"

    def check_zfs_health(self, name=None):
        url = self.get_url('nodes/{}/disks/zfs'.format(self.options.node))
        data = self.request(url)

        unhealthy = []
        found = name is None
        healthy_conditions = ['online']
        for pool in data:
            found = found or name == pool['name']
            if (name is not None and name == pool['name']) or name is None:
                if pool['health'].lower() not in healthy_conditions:
                    unhealthy.append(pool)

        if not found:
            self.check_result = CheckState.UNKNOWN
            self.check_message = "Could not fetch health of ZFS pool '{}'".format(name)
        else:
            if unhealthy:
                self.check_result = CheckState.CRITICAL
                message = "{} ZFS pools are not healthy:\n\n".format(len(unhealthy))
                message += "\n".join(
                    ['- {} ({}) is not healthy'.format(pool['name'], pool['health']) for pool in unhealthy])
                self.check_message = message
            else:
                self.check_result = CheckState.OK
                if name is not None:
                    self.check_message = "ZFS pool '{}' is healthy".format(name)
                else:
                    self.check_message = "All ZFS pools are healthy"

    def check_ceph_health(self):
        url = self.get_url('cluster/ceph/status')
        data = self.request(url)
        ceph_health = data.get('health', {})

        if 'status' not in ceph_health:
            self.check_result = CheckState.UNKNOWN
            self.check_message = "Could not fetch Ceph status from API. Check the output of 'pvesh get cluster/ceph' on your node"
            return

        if ceph_health['status'] == 'HEALTH_OK':
            self.check_result = CheckState.OK
            self.check_message = "Ceph Cluster is healthy"
        elif ceph_health['status'] == 'HEALTH_WARN':
            self.check_result = CheckState.WARNING
            self.check_message = "Ceph Cluster is in warning state"
        elif ceph_health['status'] == 'HEALTH_CRIT':
            self.check_result = CheckState.CRITICAL
            self.check_message = "Ceph Cluster is in critical state"
        else:
            self.check_result = CheckState.UNKNOWN
            self.check_message = "Ceph Cluster is in unknown state"

    def check_storage(self, name):
        # check if storage exists
        url = self.get_url('nodes/{}/storage'.format(self.options.node))
        data = self.request(url)

        if not any(s['storage'] == name for s in data):
            self.check_result = CheckState.CRITICAL
            self.check_message = "Storage '{}' doesn't exist on node '{}'".format(name, self.options.node)
            return

        url = self.get_url('nodes/{}/storage/{}/status'.format(self.options.node, name))
        self.check_api_value(url, "Usage of storage '{}' is".format(name))

    def check_version(self):
        url = self.get_url('version')
        data = self.request(url)
        if not data['version']:
            self.check_result = CheckState.UNKNOWN
            self.check_message = "Unable to determine pve version"
        elif self.options.min_version and LooseVersion(self.options.min_version) > LooseVersion(data['version']):
            self.check_result = CheckState.CRITICAL
            self.check_message = "Current pve version '{}' ({}) is lower than the min. required version '{}'".format(
                data['version'], data['repoid'], self.options.min_version)
        else:
            self.check_message = "Your pve instance version '{}' ({}) is up to date".format(data['version'], data['repoid'])

    def check_memory(self):
        url = self.get_url('nodes/{}/status'.format(self.options.node))
        self.check_api_value(url, 'Memory usage is', key='memory')

    def check_cpu(self):
        url = self.get_url('nodes/{}/status'.format(self.options.node))
        self.check_api_value(url, 'CPU usage is', key='cpu')

    def check_io_wait(self):
        url = self.get_url('nodes/{}/status'.format(self.options.node))
        self.check_api_value(url, 'IO wait is', key='wait', perfkey='wait')

    def check_thresholds(self, value, message, **kwargs):
        if kwargs.get('lowerValue', False):
            is_warning = self.options.threshold_warning and value < float(self.options.threshold_warning)
            is_critical = self.options.threshold_critical and value < float(self.options.threshold_critical)
        else:
            is_warning = self.options.threshold_warning and value > float(self.options.threshold_warning)
            is_critical = self.options.threshold_critical and value > float(self.options.threshold_critical)

        if is_critical:
            self.check_result = CheckState.CRITICAL
            self.check_message = kwargs.get('messageCritical', message)
        elif is_warning:
            self.check_result = CheckState.WARNING
            self.check_message = kwargs.get('messageWarning', message)
        else:
            self.check_message = message

    @staticmethod
    def get_value(value, total=None):
        value = float(value)

        if total:
            value /= float(total) / 100
        else:
            value /= 1024 * 1024

        return round(value, 2)

    def add_perfdata(self, name, value, **kwargs):
        unit = kwargs.get('unit', '%')

        perfdata = '{}={}{}'.format(name, value, unit)

        if self.options.threshold_warning and (self.options.values_mb == (unit == 'MB')):
            perfdata += ';{}'.format(self.options.threshold_warning)
        else:
            perfdata += ';'

        if self.options.threshold_critical and (self.options.values_mb == (unit == 'MB')):
            perfdata += ';{}'.format(self.options.threshold_critical)
        else:
            perfdata += ';'

        if 'max' in kwargs:
            perfdata += ';{}'.format(kwargs.get('max'))

        self.perfdata.append(perfdata)

    def get_perfdata(self):
        perfdata = ''

        if len(self.perfdata):
            perfdata = '|'
            perfdata += ' '.join(self.perfdata)

        return perfdata

    def check(self):
        self.check_result = CheckState.OK

        if self.options.mode == 'cluster':
            self.check_cluster_status()
        elif self.options.mode == 'version':
            self.check_version()
        elif self.options.mode == 'memory':
            self.check_memory()
        elif self.options.mode == 'io_wait':
            self.check_io_wait()
        elif self.options.mode == 'disk-health':
            self.check_disks()
        elif self.options.mode == 'cpu':
            self.check_cpu()
        elif self.options.mode == 'services':
            self.check_services()
        elif self.options.mode == 'updates':
            self.check_updates()
        elif self.options.mode == 'subscription':
            self.check_subscription()
        elif self.options.mode == 'storage':
            self.check_storage(self.options.name)
        elif self.options.mode in ['vm', 'vm_status']:
            only_status = self.options.mode == 'vm_status'

            if self.options.name:
                idx = self.options.name
            else:
                idx = self.options.vmid

            if self.options.expected_vm_status:
                self.check_vm_status(idx, expected_state=self.options.expected_vm_status, only_status=only_status)
            else:
                self.check_vm_status(idx, only_status=only_status)
        elif self.options.mode == 'replication':
            self.check_replication(self.options.name)
        elif self.options.mode == 'ceph-health':
            self.check_ceph_health()
        elif self.options.mode == 'zfs-health':
            self.check_zfs_health(self.options.name)
        elif self.options.mode == 'zfs-fragmentation':
            self.check_zfs_fragmentation(self.options.name)
        else:
            message = "Check mode '{}' not known".format(self.options.mode)
            self.output(CheckState.UNKNOWN, message)

        self.check_output()

    def parse_args(self):
        p = argparse.ArgumentParser(description='Check command for PVE hosts via PVESH')

        check_opts = p.add_argument_group('Check Options')

        check_opts.add_argument("-m", "--mode",
                                choices=(
                                    'cluster', 'version', 'cpu', 'memory', 'storage', 'io_wait', 'updates', 'services',
                                    'subscription', 'vm', 'vm_status', 'replication', 'disk-health', 'ceph-health',
                                    'zfs-health', 'zfs-fragmentation'),
                                required=True,
                                help="Mode to use.")

        check_opts.add_argument('-n', '--node', dest='node',
                                help='Node to check (necessary for all modes except cluster and version)')

        check_opts.add_argument('--name', dest='name',
                                help='Name of storage, vm, or container')

        check_opts.add_argument('--vmid', dest='vmid', type=int,
                                help='ID of virtual machine or container')

        check_opts.add_argument('--expected-vm-status', choices=('running', 'stopped', 'paused'),
                                help='Expected VM status')

        check_opts.add_argument('--ignore-vm-status', dest='ignore_vm_status', action='store_true',
                                help='Ignore VM status in checks',
                                default=False)

        check_opts.add_argument('--ignore-service', dest='ignore_services', action='append', metavar='NAME',
                                help='Ignore service NAME in checks', default=[])

        check_opts.add_argument('--ignore-disk', dest='ignore_disks', action='append', metavar='NAME',
                                help='Ignore disk NAME in health check', default=[])

        check_opts.add_argument('-w', '--warning', dest='threshold_warning', type=float,
                                help='Warning threshold for check value')
        check_opts.add_argument('-c', '--critical', dest='threshold_critical', type=float,
                                help='Critical threshold for check value')
        check_opts.add_argument('-M', dest='values_mb', action='store_true', default=False,
                                help='Values are shown in MB (if available). Thresholds are also treated as MB values')
        check_opts.add_argument('-V', '--min-version', dest='min_version', type=str,
                                help='The minimal pve version to check for. Any version lower than this will return '
                                     'CRITICAL.')

        options = p.parse_args()

        if not options.node and options.mode not in ['cluster', 'vm', 'version', 'ceph-health', 'zfs-health']:
            p.print_usage()
            message = "{}: error: --mode {} requires node name (--node)".format(p.prog, options.mode)
            self.output(CheckState.UNKNOWN, message)

        if not options.vmid and not options.name and options.mode == 'vm':
            p.print_usage()
            message = "{}: error: --mode {} requires either vm name (--name) or id (--vmid)".format(p.prog,options.mode)
            self.output(CheckState.UNKNOWN, message)

        if not options.name and options.mode == 'storage':
            p.print_usage()
            message = "{}: error: --mode {} requires storage name (--name)".format(p.prog, options.mode)
            self.output(CheckState.UNKNOWN, message)

        if options.threshold_warning and options.threshold_critical:
            if options.mode != 'subscription' and options.threshold_critical <= options.threshold_warning:
                p.error("Critical value must be greater than warning value")
            elif options.mode == 'subscription' and options.threshold_critical >= options.threshold_warning:
                p.error("Critical value must be lower than warning value")

        self.options = options

    def __init__(self):
        self.options = {}
        self.perfdata = []
        self.check_result = -1
        self.check_message = ""

        self.parse_args()


pve = CheckPVE()
pve.check()
