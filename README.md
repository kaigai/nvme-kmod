NVMe-Strom
==========

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

