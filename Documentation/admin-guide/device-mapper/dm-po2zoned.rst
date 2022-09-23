===========
dm-po2zoned
===========
The dm-po2zoned device mapper target exposes a zoned block device with a
non-power-of-2(npo2) number of sectors per zone as a power-of-2(po2)
number of sectors per zone(zone size).
The filesystems that support zoned block devices such as F2FS and BTRFS
assume po2 zone size as the kernel has traditionally only supported
those devices. However, as the kernel now supports zoned block devices with
npo2 zone sizes, the filesystems can run on top of the dm-po2zoned target before
adding native support.

Partial mapping of the underlying device is not supported by this target as
there is no use-case for it.

.. note::
   This target is **not related** to **dm-zoned target**, which exposes a
   zoned block device as a regular block device without any write constraint.

   This target only exposes a different **zone size** than the underlying device.
   The underlying device's other **constraints** will be exposed to the target.

Algorithm
=========
The device mapper target maps the underlying device's zone size to the
zone capacity and changes the zone size to the nearest po2 zone size.
The gap between the zone capacity and the zone size is emulated in the target.
E.g., a zoned block device with a zone size (and capacity) of 3M will have an
equivalent target layout with mapping as follows:

::

  0M           3M  4M        6M 8M
  |             |  |          |  |
  +x------------+--+x---------+--+x-------  Target
  |x            |  |x         |  |x
   x               x             x
   x               x             x
   x              x             x
   x             x             x
  |x            |x            |x
  +x------------+x------------+x----------  Device
  |             |             |
  0M           3M            6M

A simple remap is performed for all the BIOs that do not cross the
emulation gap area, i.e., the area between the zone capacity and size.

If a BIO lies in the emulation gap area, the following operations are performed:

	Read:
		- If the BIO lies entirely in the emulation gap area, then zero out the BIO and complete it.
		- If the BIO spans the emulation gap area, split the BIO across the zone capacity boundary
                  and remap only the BIO within the zone capacity boundary. The other part of the split BIO
                  will be zeroed out.

	Other operations:
                - Return an error

Table parameters
================

::

  <dev path>

Mandatory parameters:

    <dev path>:
        Full pathname to the underlying block-device, or a
        "major:minor" device-number.

Examples
========

::

  #!/bin/sh
  echo "0 `blockdev --getsz $1` po2zoned $1" | dmsetup create po2z
