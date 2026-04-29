/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __PPS_TIO_PLAT_H__
#define __PPS_TIO_PLAT_H__

#include <linux/bitfield.h>
#include <linux/bits.h>

#include <linux/io-64-nonatomic-hi-lo.h>

/* Intel PMC TGPIO 64-bit registers in two 32-bit reg
 * Example : TIOCOMPV_PMC interpreted as:
 * TIOCOMPV_PMC0_31[LSB] and TIOCOMPV_PMC32_64[MSB]
 */
#define TIOCTL_PMC		0x00
#define TIOCOMPV_PMC		0x10
#define TIOEC_PMC		0x30
#define TIOTCV_PMC		0x20
#define TIOECCV_PMC		0x28

/* Control Register */
#define TIOCTL_EN			BIT(0)
#define TIOCTL_DIR			BIT(1)
#define TIOCTL_EP			GENMASK(3, 2)
#define TIOCTL_EP_RISING_EDGE		FIELD_PREP(TIOCTL_EP, 0)
#define TIOCTL_EP_FALLING_EDGE		FIELD_PREP(TIOCTL_EP, 1)
#define TIOCTL_EP_TOGGLE_EDGE		FIELD_PREP(TIOCTL_EP, 2)

enum tio_mode {
	TIO_GEN,
	TIO_CLIENT,
	TIO_INVALID
};

struct pps_tio_regs {
	u64 ctl;
	u64 compv;
	u64 ec;
	u64 tcv;
	u64 eccv;
};

struct pps_tio_data {
	struct pps_tio_regs regs;
};

/* Shared Data for Aux Devices */
struct pps_tio_plat_data {
	const struct pps_tio_data *tio_data;
	const struct pps_tio_ops *req;
	void __iomem *sh_res_base;
	spinlock_t res_lock; /* resource lock */
	unsigned int id;
	enum tio_mode mode;
	bool gen_cli_enabled;
	struct mutex mode_lock; /* tio_mode lock */
};

/* Intel PPS TIO */
struct pps_tio {
	struct auxiliary_device *gen_aux;	/* PPS Generator Child */
	struct auxiliary_device *cl_aux;	/* PPS Client Child */
	struct pps_tio_plat_data *pdata;	/* Platform + Shared Data */
};

/* Aux devices operations */
struct pps_tio_ops {
	void (*read)(struct pps_tio_plat_data *pdata, u32 offset, u64 *val);
	void (*set_compv)(struct pps_tio_plat_data *pdata, u64 compv);
	void (*set_ctrl)(struct pps_tio_plat_data *pdata, u64 compv);
	void (*enable)(struct pps_tio_plat_data *pdata);
	void (*disable)(struct pps_tio_plat_data *pdata, u64 *val);
	int (*config_tio)(struct pps_tio_plat_data *pdata, int mode);
};

enum pps_tio_req_type {
	READ_REG,
	WRITE_COMPV,
	WRITE_CTRL,
	ENABLE,
	DISABLE,
	CONFIG,
};

struct pps_tio_ops_req {
	enum pps_tio_req_type type;
	u32 offset;
	u64 value;
	int mode;
};

int pps_ops_req(struct pps_tio_plat_data *pdata, struct pps_tio_ops_req *req);

#define PPS_TIO_OPS_REQ(req_type, offset_val, value_val, mode_val) \
((struct pps_tio_ops_req){ \
.type = (req_type), \
.offset = (offset_val), \
.value = (value_val), \
.mode = (mode_val), \
})

#endif
