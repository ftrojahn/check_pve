# check_pve
Icinga check command for Proxmox VE via PVESH

## Setup

### Requirements

This check command depends on **Python 3** and the following modules:
 * argparse
 * packaging

**Installation on Debian / Ubuntu**
```
apt install python3 python3-packaging
```

**Installation on Rocky / Alma Linux 9**
```
yum install python3 python3-packaging
```

**Installation on FreeBSD**
```
pkg install python3 py39-packaging
```

**Installation from requirements file**
```
pip3 install -r requirements.txt
```

## Usage

The ``icinga2`` folder contains the command definition and service examples for use with Icinga2.

```
usage: check_pve.py [-h] -m
                    {cluster,version,cpu,memory,swap,storage,io_wait,io-wait,updates,services,subscription,vm,vm_status,vm-status,replication,disk-health,ceph-health,zfs-health,zfs-fragmentation,backup}
                    [-n NODE] [--name NAME] [--vmid VMID]
                    [--expected-vm-status {running,stopped,paused}]
                    [--ignore-vm-status] [--ignore-service NAME]
                    [--ignore-disk NAME] [-w TRESHOLD_WARNING]
                    [-c TRESHOLD_CRITICAL] [-M] [-V MIN_VERSION]
                    [--unit {GB,MB,KB,GiB,MiB,KiB,B}]

Check command for PVE hosts via PVESH

options:
  -h, --help            show this help message and exit

Check Options:
  -m {cluster,version,cpu,memory,swap,storage,io_wait,io-wait,updates,services,subscription,vm,vm_status,vm-status,replication,disk-health,ceph-health,zfs-health,zfs-fragmentation,backup}, --mode {cluster,version,cpu,memory,swap,storage,io_wait,io-wait,updates,services,subscription,vm,vm_status,vm-status,replication,disk-health,ceph-health,zfs-health,zfs-fragmentation,backup}
                        Mode to use.
  -n NODE, --node NODE  Node to check (necessary for all modes except cluster and version)
  --name NAME           Name of storage, vm, or container
  --vmid VMID           ID of virtual machine or container
  --expected-vm-status {running,stopped,paused}
                        Expected VM status
  --ignore-vm-status    Ignore VM status in checks
  --ignore-service NAME
                        Ignore service NAME in checks
  --ignore-disk NAME    Ignore disk NAME in health check
  -w THRESHOLD_WARNING, --warning THRESHOLD_WARNING
                        Warning threshold for check value. Multiple thresholds with name:value,name:value
  -c THRESHOLD_CRITICAL, --critical THRESHOLD_CRITICAL
                        Critical threshold for check value Multiple thresholds with name:value,name:value
  -M                    Values are shown in the unit which is set with --unit (if available). Thresholds are also treated in this unit
  -V MIN_VERSION, --min-version MIN_VERSION
                        The minimal pve version to check for. Any version lower than this will return CRITICAL.
  --unit {GB,MB,KB,GiB,MiB,KiB,B}
                        Unit which is used for performance data and other values
```

## Examples

**Check cluster health**
```
./check_pve.py -m cluster
OK - Cluster 'proxmox1' is healthy'
```

**Check PVE version**
```
./check_pve.py -m version -V 5.0.0
OK - Your pve instance version '5.2' (0fcd7879) is up to date
```

**Check CPU load**
```
./check_pve.py -m cpu -n node1
OK - CPU usage is 2.4%|usage=2.4%;;
```

**Check memory usage**
```
./check_pve.py -m memory -n node1
OK - Memory usage is 37.44%|usage=37.44%;; used=96544.72MB;;;257867.91
```

**Check disk-health**
```
./check_pve.py -m disk-health -n node1
OK - All disks are healthy|wearout_sdb=96%;; wearout_sdc=96%;; wearout_sdd=96%;; wearout_sde=96%;;
```

**Check storage usage**
```
./check_pve.py -m storage -n node1 --name local
OK - Storage usage is 54.23%|usage=54.23%;; used=128513.11MB;;;236980.36

./check_pve.py -m storage -n node1 --name vms-disx
CRITICAL - Storage 'vms-disx' doesn't exist on node 'node01'
```

**Check subscription status**
```
./check_pve.py -m subscription -n node1 -w 50 -c 10
OK - Subscription of level 'Community' is valid until 2019-01-09
```

**Check VM status**

Without specifying a node name:
```
./check_pve.py -m vm --name test-vm
OK - VM 'test-vm' is running on 'node1'|cpu=1.85%;; memory=8.33%;;
```

You can also pass a container name for the VM check:
```
./check_pve.py -m vm --name test-lxc
OK - LXC 'test-lxc' on node 'node1' is running|cpu=0.11%;; memory=13.99%;;
```

With memory thresholds:
```
./check_pve.py -m vm --name test-vm -w 50 -c 80
OK - VM 'test-vm' is running on 'node1'|cpu=1.85%;; memory=40.33%;50.0;80.0
```

With a specified node name, the check plugin verifies on which node the VM runs.
```
./check_pve.py -m vm -n node1 --name test-vm
OK - VM 'test-vm' is running on node 'node1'|cpu=1.85%;; memory=8.33%;;

./check_pve.py -m vm -n node1 --name test-vm
WARNING - VM 'test-vm' is running on node 'node2' instead of 'node1'|cpu=1.85%;; memory=8.33%;;
```

If you only want to gather metrics and don't care about the vm status add the ``--ignore-vm-status`` flag:
```
./check_pve.py -m vm --name test-vm --ignore-vm-status
OK - VM 'test-vm' is not running
```

Specify the expected VM status:
```
./check_pve.py -m vm --name test-vm --expected-vm-status stopped
OK - VM 'test-vm' is not running

```

For hostalive checks without gathering performance data use ``vm_status`` instead of ``vm``. The parameters are the same as with ``vm``.

**Check swap usage**
```
./check_pve.py -m swap -n pve
OK - Swap usage is 0.0 %|usage=0.0%;; used=0.0MB;;;8192.0
```

**Check storage replication status**
```
./check_pve.py -m replication -n node1
OK - No failed replication jobs on node1
```

**Check ceph cluster health**
```
./check_pve.py -m ceph-health
WARNING - Ceph Cluster is in warning state
```

**Check ZFS pool health**
```
./check_pve.py -m zfs-health -n pve 
OK - All ZFS pools are healthy
```

Check for specific pool:
```
./check_pve.py -m zfs-health -n pve --name rpool
OK - ZFS pool 'rpool' is healthy
```

**Check ZFS pool fragmentation**
```
./check_pve.py -m zfs-fragmentation -n pve -w 40 -c 60
CRITICAL - 2 of 2 ZFS pools are above fragmentation thresholds:

- rpool (71 %) is CRITICAL
- diskpool (50 %) is WARNING
|fragmentation_diskpool=50%;40.0;60.0 fragmentation_rpool=71%;40.0;60.0

```

Check for specific pool:
```
./check_pve.py -m zfs-fragmentation -n pve --name diskpool -w 40 -c 60
WARNING - Fragmentation of ZFS pool 'diskpool' is above thresholds: 50 %|fragmentation=50%;40.0;60.0
```

**Check VZDump Backups**

Check task history on all nodes:

```
./check_pve.py -u <API_USER> -p <API_PASSWORD> -e <API_ENDPOINT> -m backup
CRITICAL - 8 backup tasks successful, 3 backup tasks failed
```

Check for specific node and time frame:

```
./check_pve.py -u <API_USER> -p <API_PASSWORD> -e <API_ENDPOINT> -m backup -n pve -c 86400
OK - 2 backup tasks successful, 0 backup tasks failed within the last 86400.0s
```

## FAQ

### Individual thresholds per metric

You can either specify a threshold for warning or critical which is applied to all metrics or define individual thresholds like this (`name:value,name:value,...`):

```
./check_pve.py -m vm --name test-vm -w memory:50 -c cpu:50,memory:80
OK - VM 'test-vm' is running on 'node1'|cpu=1.85%;50.0; memory=40.33%;50.0;80.0
```

## Contributors

* Alexey Kukushkin ([meshok0](https://github.com/meshok0))
