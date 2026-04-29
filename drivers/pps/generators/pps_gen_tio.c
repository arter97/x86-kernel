// SPDX-License-Identifier: GPL-2.0-only
/*
 * Intel PPS signal Generator Driver
 *
 * Copyright (C) 2026 Intel Corporation
 */
#include <linux/auxiliary_bus.h>
#include <linux/cleanup.h>
#include <linux/container_of.h>
#include <linux/device.h>
#include <linux/hrtimer.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/pps_gen_kernel.h>
#include <linux/spinlock.h>
#include <linux/timekeeping.h>
#include <linux/types.h>

#include <asm/cpu_device_id.h>

#include "pps_tio_plat.h"

/* Safety time to set hrtimer early */
#define SAFE_TIME_NS		(10 * NSEC_PER_MSEC)

#define MAGIC_CONST		(NSEC_PER_SEC - SAFE_TIME_NS)
#define ART_HW_DELAY_CYCLES	2

struct pps_tio_gen {
	struct auxiliary_device *aux_dev;
	struct pps_gen_source_info gen_info;
	struct pps_gen_device *pps_gen;
	struct pps_tio_plat_data *pdata;
	struct hrtimer timer;
	spinlock_t gen_lock; /* gen lock */
	u64 prev_count;
};

static inline ktime_t first_event(struct pps_tio_gen *tio)
{
	return ktime_set(ktime_get_real_seconds() + 1, MAGIC_CONST);
}

static int pps_tio_gen_enable(struct pps_gen_device *pps_gen, bool enable)
{
	struct pps_tio_gen *tio_gen =
		container_of(pps_gen->info, struct pps_tio_gen, gen_info);
	struct pps_tio_plat_data *pdata = tio_gen->pdata;
	struct auxiliary_device *aux_dev = tio_gen->aux_dev;
	struct pps_tio_ops_req req;
	int ret;

	if (!timekeeping_clocksource_has_base(CSID_X86_ART)) {
		dev_err_once(&aux_dev->dev, "PPS cannot be used as clock is not related to ART");
		return -ENODEV;
	}

	guard(spinlock)(&tio_gen->gen_lock);

	if (enable && !pps_gen->enabled) {
		tio_gen->pps_gen->enabled = false;
		tio_gen->prev_count = 0;
		req = PPS_TIO_OPS_REQ(CONFIG, 0, 0, TIO_GEN);
		ret = pps_ops_req(pdata, &req);
		if (ret < 0) {
			dev_err(&aux_dev->dev, "tio_gen configure failed");
			return ret;
		}
		tio_gen->pps_gen->enabled = true;
		hrtimer_start(&tio_gen->timer, first_event(tio_gen),
			      HRTIMER_MODE_ABS);
	} else if (!enable && pps_gen->enabled) {
		hrtimer_cancel(&tio_gen->timer);
		req = PPS_TIO_OPS_REQ(DISABLE, 0, 0, 0);
		pps_ops_req(pdata, &req);
		tio_gen->pps_gen->enabled = false;
		tio_gen->prev_count = 0;
	}

	return 0;
}

static int pps_tio_get_time(struct pps_gen_device *pps_gen,
			    struct timespec64 *time)
{
	struct system_time_snapshot snap;

	ktime_get_snapshot(&snap);
	*time = ktime_to_timespec64(snap.real);

	return 0;
}

static bool pps_generate_next_pulse(ktime_t expires,
				    struct pps_tio_gen *tio_gen)
{
	struct pps_tio_ops_req req;
	u64 art;

	if (!ktime_real_to_base_clock(expires, CSID_X86_ART, &art)) {
		req = PPS_TIO_OPS_REQ(DISABLE, 0, 0, 0);
		pps_ops_req(tio_gen->pdata, &req);
		tio_gen->pps_gen->enabled = false;
		tio_gen->prev_count = 0;
		return false;
	}

	req = PPS_TIO_OPS_REQ(WRITE_COMPV, 0, (art - ART_HW_DELAY_CYCLES), 0);
	pps_ops_req(tio_gen->pdata, &req);

	return true;
}

static enum hrtimer_restart hrtimer_callback(struct hrtimer *timer)
{
	ktime_t expires, now;
	u64 event_count;
	struct pps_tio_gen *tio_gen = container_of(timer,
						     struct pps_tio_gen, timer);
	struct pps_tio_plat_data *pdata = tio_gen->pdata;
	struct pps_tio_ops_req req;

	guard(spinlock)(&tio_gen->gen_lock);

	/*
	 * Check if any event is missed.
	 * If an event is missed, TIO will be disabled.
	 */

	req = PPS_TIO_OPS_REQ(READ_REG, pdata->tio_data->regs.ec, 0, 0);
	pps_ops_req(pdata, &req);

	event_count = req.value;
	if (tio_gen->prev_count && tio_gen->prev_count == event_count)
		goto err;
	tio_gen->prev_count = event_count;

	expires = hrtimer_get_expires(timer);

	now = ktime_get_real();
	if (now - expires >= SAFE_TIME_NS)
		goto err;

	tio_gen->pps_gen->enabled = pps_generate_next_pulse(expires + SAFE_TIME_NS, tio_gen);
	if (!tio_gen->pps_gen->enabled)
		return HRTIMER_NORESTART;

	hrtimer_forward(timer, now, NSEC_PER_SEC / 2);
	return HRTIMER_RESTART;

err:
	dev_err(&tio_gen->aux_dev->dev, "Event missed, Disabling Timed I/O");
	req = PPS_TIO_OPS_REQ(DISABLE, 0, 0, 0);
	pps_ops_req(pdata, &req);
	tio_gen->pps_gen->enabled = false;
	tio_gen->prev_count = 0;
	pps_gen_event(tio_gen->pps_gen, PPS_GEN_EVENT_MISSEDPULSE, NULL);
	return HRTIMER_NORESTART;
}

static int pps_gen_tio_probe(struct auxiliary_device *aux_dev,
			     const struct auxiliary_device_id *id)
{
	struct pps_tio_gen *tio_gen;
	struct pps_tio_ops_req req;

	tio_gen = devm_kzalloc(&aux_dev->dev, sizeof(*tio_gen), GFP_KERNEL);
	if (!tio_gen)
		return -ENOMEM;

	dev_set_drvdata(&aux_dev->dev, tio_gen);

	tio_gen->aux_dev = aux_dev;

	tio_gen->gen_info.use_system_clock = true;
	tio_gen->gen_info.enable = pps_tio_gen_enable;
	tio_gen->gen_info.get_time = pps_tio_get_time;
	tio_gen->gen_info.owner = THIS_MODULE;

	spin_lock_init(&tio_gen->gen_lock);

	tio_gen->pdata = dev_get_platdata(&aux_dev->dev);

	tio_gen->pps_gen = pps_gen_register_source(&tio_gen->gen_info);
	if (IS_ERR(tio_gen->pps_gen))
		return PTR_ERR(tio_gen->pps_gen);

	tio_gen->pps_gen->enabled = false;
	tio_gen->prev_count = 0;
	req = PPS_TIO_OPS_REQ(DISABLE, 0, 0, 0);
	pps_ops_req(tio_gen->pdata, &req);
	hrtimer_setup(&tio_gen->timer, hrtimer_callback, CLOCK_REALTIME,
		      HRTIMER_MODE_ABS);

	return 0;
}

static void pps_gen_tio_remove(struct auxiliary_device *aux_dev)
{
	struct pps_tio_gen *tio_gen;
	struct pps_tio_ops_req req;

	tio_gen = dev_get_drvdata(&aux_dev->dev);

	hrtimer_cancel(&tio_gen->timer);
	req = PPS_TIO_OPS_REQ(DISABLE, 0, 0, 0);
	pps_ops_req(tio_gen->pdata, &req);
	tio_gen->pps_gen->enabled = false;
	tio_gen->prev_count = 0;
	pps_gen_unregister_source(tio_gen->pps_gen);
}

static const struct auxiliary_device_id pps_gen_tio_id[] = {
	{ .name = "pps_tio_plat.generator" },
	{ },
};
MODULE_DEVICE_TABLE(auxiliary, pps_gen_tio_id);

static struct auxiliary_driver pps_gen_tio = {
	.name = "generator",
	.probe = pps_gen_tio_probe,
	.remove = pps_gen_tio_remove,
	.id_table = pps_gen_tio_id,
};

module_auxiliary_driver(pps_gen_tio);

MODULE_IMPORT_NS("PPS_TIO");

MODULE_AUTHOR("Christopher Hall <christopher.s.hall@intel.com>");
MODULE_AUTHOR("Lakshmi Sowjanya D <lakshmi.sowjanya.d@intel.com>");
MODULE_AUTHOR("Pandith N <pandith.n@intel.com>");
MODULE_AUTHOR("Thejesh Reddy T R <thejesh.reddy.t.r@intel.com>");
MODULE_AUTHOR("Subramanian Mohan <subramanian.mohan@intel.com>");
MODULE_DESCRIPTION("Intel PMC Time-Aware IO Generator Driver");
MODULE_LICENSE("GPL");
