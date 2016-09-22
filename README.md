nvme-kmod
=========
A collection of kernel module to provide special functionalities on top of
NVMe-SSD for some PostgreSQL workloads.

[NVMe-Strom]

NVMe-Strom is a Linux kernel module which provides the SSD-to-GPU direct DMA.
It allows to (1) map a particular GPU device memory on PCI BAR memory area,
and (2) launch P2P DMA from the source file blocks to the mapped GPU device
memory without intermediation by the main memory.

Requirements
------------
* NVIDIA Tesla or Quadro GPU
* NVMe SSD
* Red Hat Enterprise Linux 7.x, or compatible kernel
* Ext4 or XFS filesystem on the raw block device
  (Any RAID should not be constructed on the device)


[PG-Blitz]

PG-Blitz is a pair of PostgreSQL enhancement and Linux kernel module for
higher TPS (transactions per second) on typical OLTP workloads.
It allows to (1) map certain amount of DMA buffers on user space using mmap(2),
and (2) write out the contents of the buffer to a particular blocks of files.
It enables to submit i/o request without additional buffer copy and extra
abstruction by VFS.

Requirements
------------
* NVMe SSD
* Red Hat Enterprise Linux 7.x, or compatible kernel
* Ext4 or XFS filesystem on the raw block device
  (Any RAID should not be constructed on the device)
