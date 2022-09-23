// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Samsung Electronics Co., Ltd.
 */

#include <linux/device-mapper.h>

#define DM_MSG_PREFIX "po2zoned"

struct dm_po2z_target {
	struct dm_dev *dev;
	sector_t zone_size; /* Actual zone size of the underlying dev*/
	sector_t zone_size_po2; /* zone_size rounded to the nearest po2 value */
	unsigned int zone_size_po2_shift;
	sector_t zone_size_diff; /* diff between zone_size_po2 and zone_size */
	unsigned int nr_zones;
};

static inline unsigned int npo2_zone_no(struct dm_po2z_target *dmh,
					sector_t sect)
{
	return div64_u64(sect, dmh->zone_size);
}

static inline unsigned int po2_zone_no(struct dm_po2z_target *dmh,
				       sector_t sect)
{
	return sect >> dmh->zone_size_po2_shift;
}

static inline sector_t device_to_target_sect(struct dm_target *ti,
					     sector_t sect)
{
	struct dm_po2z_target *dmh = ti->private;

	return sect + (npo2_zone_no(dmh, sect) * dmh->zone_size_diff) +
	       ti->begin;
}

/*
 * This target works on the complete zoned device. Partial mapping is not
 * supported.
 * Construct a zoned po2 logical device: <dev-path>
 */
static int dm_po2z_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct dm_po2z_target *dmh = NULL;
	int ret;
	sector_t zone_size;
	sector_t dev_capacity;

	if (argc != 1)
		return -EINVAL;

	dmh = kmalloc(sizeof(*dmh), GFP_KERNEL);
	if (!dmh)
		return -ENOMEM;

	ret = dm_get_device(ti, argv[0], dm_table_get_mode(ti->table),
			    &dmh->dev);
	if (ret) {
		ti->error = "Device lookup failed";
		goto free;
	}

	if (!bdev_is_zoned(dmh->dev->bdev)) {
		DMERR("%pg is not a zoned device", dmh->dev->bdev);
		ret = -EINVAL;
		goto bad;
	}

	zone_size = bdev_zone_sectors(dmh->dev->bdev);
	dev_capacity = get_capacity(dmh->dev->bdev->bd_disk);
	if (ti->len != dev_capacity) {
		DMERR("%pg Partial mapping of the target is not supported",
		      dmh->dev->bdev);
		ret = -EINVAL;
		goto bad;
	}

	if (is_power_of_2(zone_size))
		DMWARN("%pg: underlying device has a power-of-2 number of sectors per zone",
		       dmh->dev->bdev);

	dmh->zone_size = zone_size;
	dmh->zone_size_po2 = 1 << get_count_order_long(zone_size);
	dmh->zone_size_po2_shift = ilog2(dmh->zone_size_po2);
	dmh->zone_size_diff = dmh->zone_size_po2 - dmh->zone_size;
	ti->private = dmh;
	ti->max_io_len = dmh->zone_size_po2;
	dmh->nr_zones = npo2_zone_no(dmh, ti->len);
	ti->len = dmh->zone_size_po2 * dmh->nr_zones;
	return 0;

bad:
	dm_put_device(ti, dmh->dev);
free:
	kfree(dmh);
	return ret;
}

static void dm_po2z_dtr(struct dm_target *ti)
{
	struct dm_po2z_target *dmh = ti->private;

	dm_put_device(ti, dmh->dev);
	kfree(dmh);
}

static int dm_po2z_report_zones_cb(struct blk_zone *zone, unsigned int idx,
				   void *data)
{
	struct dm_report_zones_args *args = data;
	struct dm_target *ti = args->tgt;
	struct dm_po2z_target *dmh = ti->private;

	zone->start = device_to_target_sect(ti, zone->start);
	zone->wp = device_to_target_sect(ti, zone->wp);
	zone->len = dmh->zone_size_po2;
	args->next_sector = zone->start + zone->len;

	return args->orig_cb(zone, args->zone_idx++, args->orig_data);
}

static int dm_po2z_report_zones(struct dm_target *ti,
				struct dm_report_zones_args *args,
				unsigned int nr_zones)
{
	struct dm_po2z_target *dmh = ti->private;
	sector_t sect =
		po2_zone_no(dmh, dm_target_offset(ti, args->next_sector)) *
		dmh->zone_size;

	return blkdev_report_zones(dmh->dev->bdev, sect, nr_zones,
				   dm_po2z_report_zones_cb, args);
}

static int dm_po2z_end_io(struct dm_target *ti, struct bio *bio,
			  blk_status_t *error)
{
	if (bio->bi_status == BLK_STS_OK && bio_op(bio) == REQ_OP_ZONE_APPEND)
		bio->bi_iter.bi_sector =
			device_to_target_sect(ti, bio->bi_iter.bi_sector);

	return DM_ENDIO_DONE;
}

static void dm_po2z_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	struct dm_po2z_target *dmh = ti->private;

	limits->chunk_sectors = dmh->zone_size_po2;
}

static void dm_po2z_status(struct dm_target *ti, status_type_t type,
			   unsigned int status_flags, char *result,
			   unsigned int maxlen)
{
	struct dm_po2z_target *dmh = ti->private;
	size_t sz = 0;

	switch (type) {
	case STATUSTYPE_INFO:
		DMEMIT("%s %lld", dmh->dev->name,
		       (unsigned long long)dmh->zone_size);
		break;

	case STATUSTYPE_TABLE:
		DMEMIT("%s", dmh->dev->name);
		break;

	case STATUSTYPE_IMA:
		result[0] = '\0';
		break;
	}
}

/**
 * dm_po2z_bio_in_emulated_zone_area - check if bio is in the emulated zone area
 * @dmh:	target data
 * @bio:	bio
 * @offset:	bio offset to emulated zone boundary
 *
 * Check if a @bio is partly or completely in the emulated zone area. If the
 * @bio is partly in the emulated zone area, @offset can be used to split
 * the @bio across the emulated zone boundary. @offset
 * will be negative if the @bio completely lies in the emulated area.
 *
 */
static bool dm_po2z_bio_in_emulated_zone_area(struct dm_po2z_target *dmh,
					      struct bio *bio, int *offset)
{
	unsigned int zone_idx = po2_zone_no(dmh, bio->bi_iter.bi_sector);
	sector_t nr_sectors = bio->bi_iter.bi_size >> SECTOR_SHIFT;
	sector_t sector_offset =
		bio->bi_iter.bi_sector - (zone_idx << dmh->zone_size_po2_shift);

	*offset = dmh->zone_size - sector_offset;

	return sector_offset + nr_sectors > dmh->zone_size;
}

static inline void dm_po2z_read_zeroes(struct bio *bio)
{
	zero_fill_bio(bio);
	bio_endio(bio);
}

static int dm_po2z_map(struct dm_target *ti, struct bio *bio)
{
	struct dm_po2z_target *dmh = ti->private;
	int split_io_pos;

	bio_set_dev(bio, dmh->dev->bdev);
	bio->bi_iter.bi_sector = dm_target_offset(ti, bio->bi_iter.bi_sector);

	if (op_is_zone_mgmt(bio_op(bio)) || !bio_sectors(bio))
		goto remap_sector;

	if (!dm_po2z_bio_in_emulated_zone_area(dmh, bio, &split_io_pos))
		goto remap_sector;

	/*
	 * Read operation on the emulated zone area (between zone capacity
	 * and zone size) will fill the bio with zeroes. Any other operation
	 * in the emulated area should return an error.
	 */
	if (bio_op(bio) == REQ_OP_READ) {
		/*
		 * If the bio is across emulated zone boundary, split the bio at
		 * the boundary.
		 */
		if (split_io_pos > 0) {
			dm_accept_partial_bio(bio, split_io_pos);
			goto remap_sector;
		}

		dm_po2z_read_zeroes(bio);
		return DM_MAPIO_SUBMITTED;
	}
	/* Other IOs in emulated zone area should result in an error */
	return DM_MAPIO_KILL;

remap_sector:
	/* convert from target sector to device sector */
	bio->bi_iter.bi_sector -= (po2_zone_no(dmh, bio->bi_iter.bi_sector) *
				   dmh->zone_size_diff);
	return DM_MAPIO_REMAPPED;
}

static int dm_po2z_iterate_devices(struct dm_target *ti,
				   iterate_devices_callout_fn fn, void *data)
{
	struct dm_po2z_target *dmh = ti->private;
	sector_t len = dmh->nr_zones * dmh->zone_size;

	return fn(ti, dmh->dev, 0, len, data);
}

static struct target_type dm_po2z_target = {
	.name = "po2zoned",
	.version = { 1, 0, 0 },
	.features = DM_TARGET_ZONED_HM | DM_TARGET_EMULATED_ZONES |
		    DM_TARGET_NOWAIT,
	.map = dm_po2z_map,
	.end_io = dm_po2z_end_io,
	.report_zones = dm_po2z_report_zones,
	.iterate_devices = dm_po2z_iterate_devices,
	.module = THIS_MODULE,
	.io_hints = dm_po2z_io_hints,
	.status = dm_po2z_status,
	.ctr = dm_po2z_ctr,
	.dtr = dm_po2z_dtr,
};

static int __init dm_po2z_init(void)
{
	return dm_register_target(&dm_po2z_target);
}

static void __exit dm_po2z_exit(void)
{
	dm_unregister_target(&dm_po2z_target);
}

/* Module hooks */
module_init(dm_po2z_init);
module_exit(dm_po2z_exit);

MODULE_DESCRIPTION(DM_NAME "power-of-2 zoned target");
MODULE_AUTHOR("Pankaj Raghav <p.raghav@samsung.com>");
MODULE_LICENSE("GPL");

