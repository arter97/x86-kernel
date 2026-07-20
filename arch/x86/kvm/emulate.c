// SPDX-License-Identifier: GPL-2.0-only
/******************************************************************************
 * emulate.c
 *
 * Generic x86 (32-bit and 64-bit) instruction decoder and emulator.
 *
 * Copyright (c) 2005 Keir Fraser
 *
 * Linux coding style, mod r/m decoder, segment base fixes, real-mode
 * privileged instructions:
 *
 * Copyright (C) 2006 Qumranet
 * Copyright 2010 Red Hat, Inc. and/or its affiliates.
 *
 *   Avi Kivity <avi@qumranet.com>
 *   Yaniv Kamay <yaniv@qumranet.com>
 *
 * From: xen-unstable 10676:af9809f51f81a3c43f276f00c81a52ef558afda4
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kvm_host.h>
#include "kvm_cache_regs.h"
#include "kvm_emulate.h"
#include <linux/stringify.h>
#include <asm/debugreg.h>
#include <asm/nospec-branch.h>
#include <asm/ibt.h>
#include <asm/text-patching.h>

#include "x86.h"
#include "tss.h"
#include "mmu.h"
#include "pmu.h"

/*
 * Operand types
 */
#define OpNone             0ull
#define OpImplicit         1ull  /* No generic decode */
#define OpReg              2ull  /* Register */
#define OpMem              3ull  /* Memory */
#define OpAcc              4ull  /* Accumulator: AL/AX/EAX/RAX */
#define OpDI               5ull  /* ES:DI/EDI/RDI */
#define OpMem64            6ull  /* Memory, 64-bit */
#define OpImmUByte         7ull  /* Zero-extended 8-bit immediate */
#define OpDX               8ull  /* DX register */
#define OpCL               9ull  /* CL register (for shifts) */
#define OpImmByte         10ull  /* 8-bit sign extended immediate */
#define OpOne             11ull  /* Implied 1 */
#define OpImm             12ull  /* Sign extended up to 32-bit immediate */
#define OpMem16           13ull  /* Memory operand (16-bit). */
#define OpMem32           14ull  /* Memory operand (32-bit). */
#define OpImmU            15ull  /* Immediate operand, zero extended */
#define OpSI              16ull  /* SI/ESI/RSI */
#define OpImmFAddr        17ull  /* Immediate far address */
#define OpMemFAddr        18ull  /* Far address in memory */
#define OpImmU16          19ull  /* Immediate operand, 16 bits, zero extended */
#define OpES              20ull  /* ES */
#define OpCS              21ull  /* CS */
#define OpSS              22ull  /* SS */
#define OpDS              23ull  /* DS */
#define OpFS              24ull  /* FS */
#define OpGS              25ull  /* GS */
#define OpMem8            26ull  /* 8-bit zero extended memory operand */
#define OpImm64           27ull  /* Sign extended 16/32/64-bit immediate */
#define OpXLat            28ull  /* memory at BX/EBX/RBX + zero-extended AL */
#define OpAccLo           29ull  /* Low part of extended acc (AX/AX/EAX/RAX) */
#define OpAccHi           30ull  /* High part of extended acc (-/DX/EDX/RDX) */
#define OpVexReg          31ull  /* VEX.vvvv register */

#define OpBits             5  /* Width of operand field */
#define OpMask             ((1ull << OpBits) - 1)

/*
 * Opcode effective-address decode tables.
 * Note that we only emulate instructions that have at least one memory
 * operand (excluding implicit stack references). We assume that stack
 * references and instruction fetches will never occur in special memory
 * areas that require emulation. So, for example, 'mov <imm>,<reg>' need
 * not be handled.
 */

/* Operand sizes: 8-bit operands or specified/overridden size. */
#define ByteOp      (1<<0)      /* 8-bit operands. */
#define DstShift    1           /* Destination operand type at bits 1-5 */
#define ImplicitOps (OpImplicit << DstShift)
#define DstReg      (OpReg << DstShift)
#define DstMem      (OpMem << DstShift)
#define DstAcc      (OpAcc << DstShift)
#define DstDI       (OpDI << DstShift)
#define DstMem64    (OpMem64 << DstShift)
#define DstMem32    (OpMem32 << DstShift)
#define DstMem16    (OpMem16 << DstShift)
#define DstImmUByte (OpImmUByte << DstShift)
#define DstDX       (OpDX << DstShift)
#define DstAccLo    (OpAccLo << DstShift)
#define DstMask     (OpMask << DstShift)
#define SrcShift    6           /* Source operand type at bits 6-10 */
#define SrcNone     (OpNone << SrcShift)
#define SrcReg      (OpReg << SrcShift)
#define SrcMem      (OpMem << SrcShift)
#define SrcMem16    (OpMem16 << SrcShift)
#define SrcMem32    (OpMem32 << SrcShift)
#define SrcImm      (OpImm << SrcShift)
#define SrcImmByte  (OpImmByte << SrcShift)
#define SrcOne      (OpOne << SrcShift)
#define SrcImmUByte (OpImmUByte << SrcShift)
#define SrcImmU     (OpImmU << SrcShift)
#define SrcSI       (OpSI << SrcShift)
#define SrcXLat     (OpXLat << SrcShift)
#define SrcImmFAddr (OpImmFAddr << SrcShift)
#define SrcMemFAddr (OpMemFAddr << SrcShift)
#define SrcAcc      (OpAcc << SrcShift)
#define SrcImmU16   (OpImmU16 << SrcShift)
#define SrcImm64    (OpImm64 << SrcShift)
#define SrcDX       (OpDX << SrcShift)
#define SrcMem8     (OpMem8 << SrcShift)
#define SrcMem64    (OpMem64 << SrcShift)
#define SrcAccHi    (OpAccHi << SrcShift)
#define SrcMask     (OpMask << SrcShift)
#define BitOp       (1<<11)
#define MemAbs      (1<<12)     /* Memory operand is absolute displacement */
#define String      (1<<13)     /* String instruction (rep capable) */
#define Stack       (1<<14)     /* Stack instruction (push/pop) */
#define GroupMask   (7<<15)     /* Group mechanisms, at bits 15-17 */
#define Group       (1<<15)     /* Bits 3:5 of modrm byte extend opcode */
#define GroupDual   (2<<15)     /* Alternate decoding of mod == 3 */
#define Prefix      (3<<15)     /* Instruction varies with 66/f2/f3 prefix */
#define RMExt       (4<<15)     /* Opcode extension in ModRM r/m if mod == 3 */
#define Escape      (5<<15)     /* Escape to coprocessor instruction */
#define InstrDual   (6<<15)     /* Alternate instruction decoding of mod == 3 */
#define ModeDual    (7<<15)     /* Different instruction for 32/64 bit */
#define Sse         (1<<18)     /* SSE Vector instruction */
#define ModRM       (1<<19)     /* Generic ModRM decode. */
#define Mov         (1<<20)     /* Destination is only written; never read. */
#define Prot        (1<<21) /* instruction generates #UD if not in prot-mode */
#define EmulateOnUD (1<<22) /* Emulate if unsupported by the host */
#define NoAccess    (1<<23) /* Don't access memory (lea/invlpg/verr etc) */
#define Op3264      (1<<24) /* Operand is 64b in long mode, 32b otherwise */
#define Undefined   (1<<25) /* No Such Instruction */
#define Lock        (1<<26) /* lock prefix is allowed for the instruction */
#define Priv        (1<<27) /* instruction generates #GP if current CPL != 0 */
#define No64        (1<<28)     /* Instruction generates #UD in 64-bit mode */
#define PageTable   (1 << 29)   /* instruction used to write page table */
#define NotImpl     (1 << 30)   /* instruction is not implemented */
#define Avx         ((u64)1 << 31)   /* Instruction uses VEX prefix */
#define Src2Shift   (32)        /* Source 2 operand type at bits 32-36 */
#define Src2None    (OpNone << Src2Shift)
#define Src2Mem     (OpMem << Src2Shift)
#define Src2CL      (OpCL << Src2Shift)
#define Src2ImmByte (OpImmByte << Src2Shift)
#define Src2One     (OpOne << Src2Shift)
#define Src2Imm     (OpImm << Src2Shift)
#define Src2ES      (OpES << Src2Shift)
#define Src2CS      (OpCS << Src2Shift)
#define Src2SS      (OpSS << Src2Shift)
#define Src2DS      (OpDS << Src2Shift)
#define Src2FS      (OpFS << Src2Shift)
#define Src2GS      (OpGS << Src2Shift)
#define Src2VexReg  (OpVexReg << Src2Shift)
#define Src2Mask    (OpMask << Src2Shift)
/* free: 37-39 */
#define Mmx         ((u64)1 << 40)  /* MMX Vector instruction */
#define AlignMask   ((u64)3 << 41)  /* Memory alignment requirement at bits 41-42 */
#define Aligned     ((u64)1 << 41)  /* Explicitly aligned (e.g. MOVDQA) */
#define Unaligned   ((u64)2 << 41)  /* Explicitly unaligned (e.g. MOVDQU) */
#define Aligned16   ((u64)3 << 41)  /* Aligned to 16 byte boundary (e.g. FXSAVE) */
/* free: 43-44 */
#define NoWrite     ((u64)1 << 45)  /* No writeback */
#define SrcWrite    ((u64)1 << 46)  /* Write back src operand */
#define NoMod	    ((u64)1 << 47)  /* Mod field is ignored */
#define Intercept   ((u64)1 << 48)  /* Has valid intercept field */
#define CheckPerm   ((u64)1 << 49)  /* Has valid check_perm field */
#define PrivUD      ((u64)1 << 51)  /* #UD instead of #GP on CPL > 0 */
#define NearBranch  ((u64)1 << 52)  /* Near branches */
#define No16	    ((u64)1 << 53)  /* No 16 bit operand */
#define IncSP       ((u64)1 << 54)  /* SP is incremented before ModRM calc */
#define TwoMemOp    ((u64)1 << 55)  /* Instruction has two memory operand */
#define IsBranch    ((u64)1 << 56)  /* Instruction is considered a branch. */
#define ShadowStack ((u64)1 << 57)  /* Instruction affects Shadow Stacks. */

#define DstXacc     (DstAccLo | SrcAccHi | SrcWrite)

#define X2(x...) x, x
#define X3(x...) X2(x), x
#define X4(x...) X2(x), X2(x)
#define X5(x...) X4(x), x
#define X6(x...) X4(x), X2(x)
#define X7(x...) X4(x), X3(x)
#define X8(x...) X4(x), X4(x)
#define X16(x...) X8(x), X8(x)

struct opcode {
	u64 flags;
	u8 intercept;
	u8 pad[7];
	union {
		int (*execute)(struct x86_emulate_ctxt *ctxt);
		const struct opcode *group;
		const struct group_dual *gdual;
		const struct gprefix *gprefix;
		const struct escape *esc;
		const struct instr_dual *idual;
		const struct mode_dual *mdual;
	} u;
	int (*check_perm)(struct x86_emulate_ctxt *ctxt);
};

struct group_dual {
	struct opcode mod012[8];
	struct opcode mod3[8];
};

struct gprefix {
	struct opcode pfx_no;
	struct opcode pfx_66;
	struct opcode pfx_f2;
	struct opcode pfx_f3;
};

struct escape {
	struct opcode op[8];
	struct opcode high[64];
};

struct instr_dual {
	struct opcode mod012;
	struct opcode mod3;
};

struct mode_dual {
	struct opcode mode32;
	struct opcode mode64;
};

#define EFLG_RESERVED_ZEROS_MASK 0xffc0802a

enum x86_transfer_type {
	X86_TRANSFER_NONE,
	X86_TRANSFER_CALL_JMP,
	X86_TRANSFER_RET,
	X86_TRANSFER_TASK_SWITCH,
};

enum rex_bits {
	REX_B = 1,
	REX_X = 2,
	REX_R = 4,
	REX_W = 8,
};

static void writeback_registers(struct x86_emulate_ctxt *ctxt)
{
	unsigned long dirty = ctxt->regs_dirty;
	unsigned reg;

	for_each_set_bit(reg, &dirty, NR_EMULATOR_GPRS)
		ctxt->ops->write_gpr(ctxt, reg, ctxt->_regs[reg]);
}

static void invalidate_registers(struct x86_emulate_ctxt *ctxt)
{
	ctxt->regs_dirty = 0;
	ctxt->regs_valid = 0;
}

/*
 * These EFLAGS bits are restored from saved value during emulation, and
 * any changes are written back to the saved value after emulation.
 */
#define EFLAGS_MASK (X86_EFLAGS_OF|X86_EFLAGS_SF|X86_EFLAGS_ZF|X86_EFLAGS_AF|\
		     X86_EFLAGS_PF|X86_EFLAGS_CF)

#ifdef CONFIG_X86_64
#define ON64(x...) x
#else
#define ON64(x...)
#endif

#define EM_ASM_START(op) \
static int em_##op(struct x86_emulate_ctxt *ctxt) \
{ \
	unsigned long flags = (ctxt->eflags & EFLAGS_MASK) | X86_EFLAGS_IF; \
	int bytes = 1, ok = 1; \
	if (!(ctxt->d & ByteOp)) \
		bytes = ctxt->dst.bytes; \
	switch (bytes) {

#define __EM_ASM(str) \
		asm("push %[flags]; popf \n\t" \
		    "10: " str \
		    "pushf; pop %[flags] \n\t" \
		    "11: \n\t" \
		    : "+a" (ctxt->dst.val), \
		      "+d" (ctxt->src.val), \
		      [flags] "+D" (flags), \
		      "+S" (ok) \
		    : "c" (ctxt->src2.val))

#define __EM_ASM_1(op, dst) \
		__EM_ASM(#op " %%" #dst " \n\t")

#define __EM_ASM_1_EX(op, dst) \
		__EM_ASM(#op " %%" #dst " \n\t" \
			 _ASM_EXTABLE_TYPE_REG(10b, 11f, EX_TYPE_ZERO_REG, %%esi))

#define __EM_ASM_2(op, dst, src) \
		__EM_ASM(#op " %%" #src ", %%" #dst " \n\t")

#define __EM_ASM_3(op, dst, src, src2) \
		__EM_ASM(#op " %%" #src2 ", %%" #src ", %%" #dst " \n\t")

#define EM_ASM_END \
	} \
	ctxt->eflags = (ctxt->eflags & ~EFLAGS_MASK) | (flags & EFLAGS_MASK); \
	return !ok ? emulate_de(ctxt) : X86EMUL_CONTINUE; \
}

/* 1-operand, using "a" (dst) */
#define EM_ASM_1(op) \
	EM_ASM_START(op) \
	case 1: __EM_ASM_1(op##b, al); break; \
	case 2: __EM_ASM_1(op##w, ax); break; \
	case 4: __EM_ASM_1(op##l, eax); break; \
	ON64(case 8: __EM_ASM_1(op##q, rax); break;) \
	EM_ASM_END

/* 1-operand, using "c" (src2) */
#define EM_ASM_1SRC2(op, name) \
	EM_ASM_START(name) \
	case 1: __EM_ASM_1(op##b, cl); break; \
	case 2: __EM_ASM_1(op##w, cx); break; \
	case 4: __EM_ASM_1(op##l, ecx); break; \
	ON64(case 8: __EM_ASM_1(op##q, rcx); break;) \
	EM_ASM_END

/* 1-operand, using "c" (src2) with exception */
#define EM_ASM_1SRC2EX(op, name) \
	EM_ASM_START(name) \
	case 1: __EM_ASM_1_EX(op##b, cl); break; \
	case 2: __EM_ASM_1_EX(op##w, cx); break; \
	case 4: __EM_ASM_1_EX(op##l, ecx); break; \
	ON64(case 8: __EM_ASM_1_EX(op##q, rcx); break;) \
	EM_ASM_END

/* 2-operand, using "a" (dst), "d" (src) */
#define EM_ASM_2(op) \
	EM_ASM_START(op) \
	case 1: __EM_ASM_2(op##b, al, dl); break; \
	case 2: __EM_ASM_2(op##w, ax, dx); break; \
	case 4: __EM_ASM_2(op##l, eax, edx); break; \
	ON64(case 8: __EM_ASM_2(op##q, rax, rdx); break;) \
	EM_ASM_END

/* 2-operand, reversed */
#define EM_ASM_2R(op, name) \
	EM_ASM_START(name) \
	case 1: __EM_ASM_2(op##b, dl, al); break; \
	case 2: __EM_ASM_2(op##w, dx, ax); break; \
	case 4: __EM_ASM_2(op##l, edx, eax); break; \
	ON64(case 8: __EM_ASM_2(op##q, rdx, rax); break;) \
	EM_ASM_END

/* 2-operand, word only (no byte op) */
#define EM_ASM_2W(op) \
	EM_ASM_START(op) \
	case 1: break; \
	case 2: __EM_ASM_2(op##w, ax, dx); break; \
	case 4: __EM_ASM_2(op##l, eax, edx); break; \
	ON64(case 8: __EM_ASM_2(op##q, rax, rdx); break;) \
	EM_ASM_END

/* 2-operand, using "a" (dst) and CL (src2) */
#define EM_ASM_2CL(op) \
	EM_ASM_START(op) \
	case 1: __EM_ASM_2(op##b, al, cl); break; \
	case 2: __EM_ASM_2(op##w, ax, cl); break; \
	case 4: __EM_ASM_2(op##l, eax, cl); break; \
	ON64(case 8: __EM_ASM_2(op##q, rax, cl); break;) \
	EM_ASM_END

/* 3-operand, using "a" (dst), "d" (src) and CL (src2) */
#define EM_ASM_3WCL(op) \
	EM_ASM_START(op) \
	case 1: break; \
	case 2: __EM_ASM_3(op##w, ax, dx, cl); break; \
	case 4: __EM_ASM_3(op##l, eax, edx, cl); break; \
	ON64(case 8: __EM_ASM_3(op##q, rax, rdx, cl); break;) \
	EM_ASM_END

static int em_salc(struct x86_emulate_ctxt *ctxt)
{
	/*
	 * Set AL 0xFF if CF is set, or 0x00 when clear.
	 */
	ctxt->dst.val = 0xFF * !!(ctxt->eflags & X86_EFLAGS_CF);
	return X86EMUL_CONTINUE;
}

/*
 * XXX: inoutclob user must know where the argument is being expanded.
 *      Using asm goto would allow us to remove _fault.
 */
#define asm_safe(insn, inoutclob...) \
({ \
	int _fault = 0; \
 \
	asm volatile("1:" insn "\n" \
	             "2:\n" \
		     _ASM_EXTABLE_TYPE_REG(1b, 2b, EX_TYPE_ONE_REG, %[_fault]) \
	             : [_fault] "+r"(_fault) inoutclob ); \
 \
	_fault ? X86EMUL_UNHANDLEABLE : X86EMUL_CONTINUE; \
})

static int emulator_check_intercept(struct x86_emulate_ctxt *ctxt,
				    enum x86_intercept intercept,
				    enum x86_intercept_stage stage)
{
	struct x86_instruction_info info = {
		.intercept  = intercept,
		.rep_prefix = ctxt->rep_prefix,
		.modrm_mod  = ctxt->modrm_mod,
		.modrm_reg  = ctxt->modrm_reg,
		.modrm_rm   = ctxt->modrm_rm,
		.src_val    = ctxt->src.val64,
		.dst_val    = ctxt->dst.val64,
		.src_bytes  = ctxt->src.bytes,
		.dst_bytes  = ctxt->dst.bytes,
		.src_type   = ctxt->src.type,
		.dst_type   = ctxt->dst.type,
		.ad_bytes   = ctxt->ad_bytes,
		.rip	    = ctxt->eip,
		.next_rip   = ctxt->_eip,
	};

	return ctxt->ops->intercept(ctxt, &info, stage);
}

static void assign_masked(ulong *dest, ulong src, ulong mask)
{
	*dest = (*dest & ~mask) | (src & mask);
}

static void assign_register(unsigned long *reg, u64 val, int bytes)
{
	/* The 4-byte case *is* correct: in 64-bit mode we zero-extend. */
	switch (bytes) {
	case 1:
		*(u8 *)reg = (u8)val;
		break;
	case 2:
		*(u16 *)reg = (u16)val;
		break;
	case 4:
		*reg = (u32)val;
		break;	/* 64b: zero-extend */
	case 8:
		*reg = val;
		break;
	}
}

static inline unsigned long ad_mask(struct x86_emulate_ctxt *ctxt)
{
	return (1UL << (ctxt->ad_bytes << 3)) - 1;
}

static ulong stack_mask(struct x86_emulate_ctxt *ctxt)
{
	u16 sel;
	struct desc_struct ss;

	if (ctxt->mode == X86EMUL_MODE_PROT64)
		return ~0UL;
	ctxt->ops->get_segment(ctxt, &sel, &ss, NULL, VCPU_SREG_SS);
	return ~0U >> ((ss.d ^ 1) * 16);  /* d=0: 0xffff; d=1: 0xffffffff */
}

static int stack_size(struct x86_emulate_ctxt *ctxt)
{
	return (__fls(stack_mask(ctxt)) + 1) >> 3;
}

/* Access/update address held in a register, based on addressing mode. */
static inline unsigned long
address_mask(struct x86_emulate_ctxt *ctxt, unsigned long reg)
{
	if (ctxt->ad_bytes == sizeof(unsigned long))
		return reg;
	else
		return reg & ad_mask(ctxt);
}

static inline unsigned long
register_address(struct x86_emulate_ctxt *ctxt, int reg)
{
	return address_mask(ctxt, reg_read(ctxt, reg));
}

static void masked_increment(ulong *reg, ulong mask, int inc)
{
	assign_masked(reg, *reg + inc, mask);
}

static inline void
register_address_increment(struct x86_emulate_ctxt *ctxt, int reg, int inc)
{
	ulong *preg = reg_rmw(ctxt, reg);

	assign_register(preg, *preg + inc, ctxt->ad_bytes);
}

static void rsp_increment(struct x86_emulate_ctxt *ctxt, int inc)
{
	masked_increment(reg_rmw(ctxt, VCPU_REGS_RSP), stack_mask(ctxt), inc);
}

static u32 desc_limit_scaled(struct desc_struct *desc)
{
	u32 limit = get_desc_limit(desc);

	return desc->g ? (limit << 12) | 0xfff : limit;
}

static unsigned long seg_base(struct x86_emulate_ctxt *ctxt, int seg)
{
	if (ctxt->mode == X86EMUL_MODE_PROT64 && seg < VCPU_SREG_FS)
		return 0;

	return ctxt->ops->get_cached_segment_base(ctxt, seg);
}

static int emulate_exception(struct x86_emulate_ctxt *ctxt, int vec,
			     u32 error, bool valid)
{
	if (KVM_EMULATOR_BUG_ON(vec > 0x1f, ctxt))
		return X86EMUL_UNHANDLEABLE;

	ctxt->exception.vector = vec;
	ctxt->exception.error_code = error;
	ctxt->exception.error_code_valid = valid;
	return X86EMUL_PROPAGATE_FAULT;
}

static int emulate_db(struct x86_emulate_ctxt *ctxt)
{
	return emulate_exception(ctxt, DB_VECTOR, 0, false);
}

static int emulate_gp(struct x86_emulate_ctxt *ctxt, int err)
{
	return emulate_exception(ctxt, GP_VECTOR, err, true);
}

static int emulate_ss(struct x86_emulate_ctxt *ctxt, int err)
{
	return emulate_exception(ctxt, SS_VECTOR, err, true);
}

static int emulate_ud(struct x86_emulate_ctxt *ctxt)
{
	return emulate_exception(ctxt, UD_VECTOR, 0, false);
}

static int emulate_ts(struct x86_emulate_ctxt *ctxt, int err)
{
	return emulate_exception(ctxt, TS_VECTOR, err, true);
}

static int emulate_de(struct x86_emulate_ctxt *ctxt)
{
	return emulate_exception(ctxt, DE_VECTOR, 0, false);
}

static int emulate_nm(struct x86_emulate_ctxt *ctxt)
{
	return emulate_exception(ctxt, NM_VECTOR, 0, false);
}

static u16 get_segment_selector(struct x86_emulate_ctxt *ctxt, unsigned seg)
{
	u16 selector;
	struct desc_struct desc;

	ctxt->ops->get_segment(ctxt, &selector, &desc, NULL, seg);
	return selector;
}

static void set_segment_selector(struct x86_emulate_ctxt *ctxt, u16 selector,
				 unsigned seg)
{
	u16 dummy;
	u32 base3;
	struct desc_struct desc;

	ctxt->ops->get_segment(ctxt, &dummy, &desc, &base3, seg);
	ctxt->ops->set_segment(ctxt, selector, &desc, base3, seg);
}

static inline u8 ctxt_virt_addr_bits(struct x86_emulate_ctxt *ctxt)
{
	return (ctxt->ops->get_cr(ctxt, 4) & X86_CR4_LA57) ? 57 : 48;
}

static inline bool emul_is_noncanonical_address(u64 la,
						struct x86_emulate_ctxt *ctxt,
						unsigned int flags)
{
	return !ctxt->ops->is_canonical_addr(ctxt, la, flags);
}

/*
 * x86 defines three classes of vector instructions: explicitly
 * aligned, explicitly unaligned, and the rest, which change behaviour
 * depending on whether they're AVX encoded or not.
 *
 * Also included is CMPXCHG16B which is not a vector instruction, yet it is
 * subject to the same check.  FXSAVE and FXRSTOR are checked here too as their
 * 512 bytes of data must be aligned to a 16 byte boundary.
 */
static unsigned insn_alignment(struct x86_emulate_ctxt *ctxt, unsigned size)
{
	u64 alignment = ctxt->d & AlignMask;

	if (likely(size < 16))
		return 1;

	switch (alignment) {
	case Unaligned:
		return 1;
	case Aligned16:
		return 16;
	case Aligned:
	default:
		return size;
	}
}

static __always_inline int __linearize(struct x86_emulate_ctxt *ctxt,
				       struct segmented_address addr,
				       unsigned *max_size, unsigned size,
				       enum x86emul_mode mode, ulong *linear,
				       unsigned int flags)
{
	struct desc_struct desc;
	bool usable;
	ulong la;
	u32 lim;
	u16 sel;
	u8  va_bits;

	la = seg_base(ctxt, addr.seg) + addr.ea;
	*max_size = 0;
	switch (mode) {
	case X86EMUL_MODE_PROT64:
		*linear = la = ctxt->ops->get_untagged_addr(ctxt, la, flags);
		va_bits = ctxt_virt_addr_bits(ctxt);
		if (!__is_canonical_address(la, va_bits))
			goto bad;

		*max_size = min_t(u64, ~0u, (1ull << va_bits) - la);
		if (size > *max_size)
			goto bad;
		break;
	default:
		*linear = la = (u32)la;
		usable = ctxt->ops->get_segment(ctxt, &sel, &desc, NULL,
						addr.seg);
		if (!usable)
			goto bad;
		/* code segment in protected mode or read-only data segment */
		if ((((ctxt->mode != X86EMUL_MODE_REAL) && (desc.type & 8)) || !(desc.type & 2)) &&
		    (flags & X86EMUL_F_WRITE))
			goto bad;
		/* unreadable code segment */
		if (!(flags & X86EMUL_F_FETCH) && (desc.type & 8) && !(desc.type & 2))
			goto bad;
		lim = desc_limit_scaled(&desc);
		if (!(desc.type & 8) && (desc.type & 4)) {
			/* expand-down segment */
			if (addr.ea <= lim)
				goto bad;
			lim = desc.d ? 0xffffffff : 0xffff;
		}
		if (addr.ea > lim)
			goto bad;
		if (lim == 0xffffffff)
			*max_size = ~0u;
		else {
			*max_size = (u64)lim + 1 - addr.ea;
			if (size > *max_size)
				goto bad;
		}
		break;
	}
	if (la & (insn_alignment(ctxt, size) - 1))
		return emulate_gp(ctxt, 0);
	return X86EMUL_CONTINUE;
bad:
	if (addr.seg == VCPU_SREG_SS)
		return emulate_ss(ctxt, 0);
	else
		return emulate_gp(ctxt, 0);
}

static int linearize(struct x86_emulate_ctxt *ctxt,
		     struct segmented_address addr,
		     unsigned size, bool write,
		     ulong *linear)
{
	unsigned max_size;
	return __linearize(ctxt, addr, &max_size, size, ctxt->mode, linear,
			   write ? X86EMUL_F_WRITE : 0);
}

static inline int assign_eip(struct x86_emulate_ctxt *ctxt, ulong dst)
{
	ulong linear;
	int rc;
	unsigned max_size;
	struct segmented_address addr = { .seg = VCPU_SREG_CS,
					   .ea = dst };

	if (ctxt->op_bytes != sizeof(unsigned long))
		addr.ea = dst & ((1UL << (ctxt->op_bytes << 3)) - 1);
	rc = __linearize(ctxt, addr, &max_size, 1, ctxt->mode, &linear,
			 X86EMUL_F_FETCH);
	if (rc == X86EMUL_CONTINUE)
		ctxt->_eip = addr.ea;
	return rc;
}

static inline int emulator_recalc_and_set_mode(struct x86_emulate_ctxt *ctxt)
{
	u64 efer;
	struct desc_struct cs;
	u16 selector;
	u32 base3;

	ctxt->ops->get_msr(ctxt, MSR_EFER, &efer);

	if (!(ctxt->ops->get_cr(ctxt, 0) & X86_CR0_PE)) {
		/* Real mode. cpu must not have long mode active */
		if (efer & EFER_LMA)
			return X86EMUL_UNHANDLEABLE;
		ctxt->mode = X86EMUL_MODE_REAL;
		return X86EMUL_CONTINUE;
	}

	if (ctxt->eflags & X86_EFLAGS_VM) {
		/* Protected/VM86 mode. cpu must not have long mode active */
		if (efer & EFER_LMA)
			return X86EMUL_UNHANDLEABLE;
		ctxt->mode = X86EMUL_MODE_VM86;
		return X86EMUL_CONTINUE;
	}

	if (!ctxt->ops->get_segment(ctxt, &selector, &cs, &base3, VCPU_SREG_CS))
		return X86EMUL_UNHANDLEABLE;

	if (efer & EFER_LMA) {
		if (cs.l) {
			/* Proper long mode */
			ctxt->mode = X86EMUL_MODE_PROT64;
		} else if (cs.d) {
			/* 32 bit compatibility mode*/
			ctxt->mode = X86EMUL_MODE_PROT32;
		} else {
			ctxt->mode = X86EMUL_MODE_PROT16;
		}
	} else {
		/* Legacy 32 bit / 16 bit mode */
		ctxt->mode = cs.d ? X86EMUL_MODE_PROT32 : X86EMUL_MODE_PROT16;
	}

	return X86EMUL_CONTINUE;
}

static inline int assign_eip_near(struct x86_emulate_ctxt *ctxt, ulong dst)
{
	return assign_eip(ctxt, dst);
}

static int assign_eip_far(struct x86_emulate_ctxt *ctxt, ulong dst)
{
	int rc = emulator_recalc_and_set_mode(ctxt);

	if (rc != X86EMUL_CONTINUE)
		return rc;

	return assign_eip(ctxt, dst);
}

static inline int jmp_rel(struct x86_emulate_ctxt *ctxt, int rel)
{
	return assign_eip_near(ctxt, ctxt->_eip + rel);
}

static int linear_read_system(struct x86_emulate_ctxt *ctxt, ulong linear,
			      void *data, unsigned size)
{
	return ctxt->ops->read_std(ctxt, linear, data, size, &ctxt->exception, true);
}

static int linear_write_system(struct x86_emulate_ctxt *ctxt,
			       ulong linear, void *data,
			       unsigned int size)
{
	return ctxt->ops->write_std(ctxt, linear, data, size, &ctxt->exception, true);
}

static int segmented_read_std(struct x86_emulate_ctxt *ctxt,
			      struct segmented_address addr,
			      void *data,
			      unsigned size)
{
	int rc;
	ulong linear;

	rc = linearize(ctxt, addr, size, false, &linear);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	return ctxt->ops->read_std(ctxt, linear, data, size, &ctxt->exception, false);
}

static int segmented_write_std(struct x86_emulate_ctxt *ctxt,
			       struct segmented_address addr,
			       void *data,
			       unsigned int size)
{
	int rc;
	ulong linear;

	rc = linearize(ctxt, addr, size, true, &linear);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	return ctxt->ops->write_std(ctxt, linear, data, size, &ctxt->exception, false);
}

/*
 * Prefetch the remaining bytes of the instruction without crossing page
 * boundary if they are not in fetch_cache yet.
 */
static int __do_insn_fetch_bytes(struct x86_emulate_ctxt *ctxt, int op_size)
{
	int rc;
	unsigned size, max_size;
	unsigned long linear;
	int cur_size = ctxt->fetch.end - ctxt->fetch.data;
	struct segmented_address addr = { .seg = VCPU_SREG_CS,
					   .ea = ctxt->eip + cur_size };

	/*
	 * We do not know exactly how many bytes will be needed, and
	 * __linearize is expensive, so fetch as much as possible.  We
	 * just have to avoid going beyond the 15 byte limit, the end
	 * of the segment, or the end of the page.
	 *
	 * __linearize is called with size 0 so that it does not do any
	 * boundary check itself.  Instead, we use max_size to check
	 * against op_size.
	 */
	rc = __linearize(ctxt, addr, &max_size, 0, ctxt->mode, &linear,
			 X86EMUL_F_FETCH);
	if (unlikely(rc != X86EMUL_CONTINUE))
		return rc;

	size = min_t(unsigned, 15UL ^ cur_size, max_size);
	size = min_t(unsigned, size, PAGE_SIZE - offset_in_page(linear));

	/*
	 * One instruction can only straddle two pages,
	 * and one has been loaded at the beginning of
	 * x86_decode_insn.  So, if not enough bytes
	 * still, we must have hit the 15-byte boundary.
	 */
	if (unlikely(size < op_size))
		return emulate_gp(ctxt, 0);

	rc = ctxt->ops->fetch(ctxt, linear, ctxt->fetch.end,
			      size, &ctxt->exception);
	if (unlikely(rc != X86EMUL_CONTINUE))
		return rc;
	ctxt->fetch.end += size;
	return X86EMUL_CONTINUE;
}

static __always_inline int do_insn_fetch_bytes(struct x86_emulate_ctxt *ctxt,
					       unsigned size)
{
	unsigned done_size = ctxt->fetch.end - ctxt->fetch.ptr;

	if (unlikely(done_size < size))
		return __do_insn_fetch_bytes(ctxt, size - done_size);
	else
		return X86EMUL_CONTINUE;
}

/* Fetch next part of the instruction being emulated. */
#define insn_fetch(_type, _ctxt)					\
({	_type _x;							\
									\
	rc = do_insn_fetch_bytes(_ctxt, sizeof(_type));			\
	if (rc != X86EMUL_CONTINUE)					\
		goto done;						\
	ctxt->_eip += sizeof(_type);					\
	memcpy(&_x, ctxt->fetch.ptr, sizeof(_type));			\
	ctxt->fetch.ptr += sizeof(_type);				\
	_x;								\
})

#define insn_fetch_arr(_arr, _size, _ctxt)				\
({									\
	rc = do_insn_fetch_bytes(_ctxt, _size);				\
	if (rc != X86EMUL_CONTINUE)					\
		goto done;						\
	ctxt->_eip += (_size);						\
	memcpy(_arr, ctxt->fetch.ptr, _size);				\
	ctxt->fetch.ptr += (_size);					\
})

/*
 * Given the 'reg' portion of a ModRM byte, and a register block, return a
 * pointer into the block that addresses the relevant register.
 * @highbyte_regs specifies whether to decode AH,CH,DH,BH.
 */
static void *decode_register(struct x86_emulate_ctxt *ctxt, u8 modrm_reg,
			     int byteop)
{
	void *p;
	int highbyte_regs = (ctxt->rex_prefix == REX_NONE) && byteop;

	if (highbyte_regs && modrm_reg >= 4 && modrm_reg < 8)
		p = (unsigned char *)reg_rmw(ctxt, modrm_reg & 3) + 1;
	else
		p = reg_rmw(ctxt, modrm_reg);
	return p;
}

static int read_descriptor(struct x86_emulate_ctxt *ctxt,
			   struct segmented_address addr,
			   u16 *size, unsigned long *address, int op_bytes)
{
	int rc;

	if (op_bytes == 2)
		op_bytes = 3;
	*address = 0;
	rc = segmented_read_std(ctxt, addr, size, 2);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	addr.ea += 2;
	rc = segmented_read_std(ctxt, addr, address, op_bytes);
	return rc;
}

EM_ASM_2(add);
EM_ASM_2(or);
EM_ASM_2(adc);
EM_ASM_2(sbb);
EM_ASM_2(and);
EM_ASM_2(sub);
EM_ASM_2(xor);
EM_ASM_2(cmp);
EM_ASM_2(test);
EM_ASM_2(xadd);

EM_ASM_1SRC2(mul, mul_ex);
EM_ASM_1SRC2(imul, imul_ex);
EM_ASM_1SRC2EX(div, div_ex);
EM_ASM_1SRC2EX(idiv, idiv_ex);

EM_ASM_3WCL(shld);
EM_ASM_3WCL(shrd);

EM_ASM_2W(imul);

EM_ASM_1(not);
EM_ASM_1(neg);
EM_ASM_1(inc);
EM_ASM_1(dec);

EM_ASM_2CL(rol);
EM_ASM_2CL(ror);
EM_ASM_2CL(rcl);
EM_ASM_2CL(rcr);
EM_ASM_2CL(shl);
EM_ASM_2CL(shr);
EM_ASM_2CL(sar);

EM_ASM_2W(bsf);
EM_ASM_2W(bsr);
EM_ASM_2W(bt);
EM_ASM_2W(bts);
EM_ASM_2W(btr);
EM_ASM_2W(btc);

EM_ASM_2R(cmp, cmp_r);

static int em_bsf_c(struct x86_emulate_ctxt *ctxt)
{
	/* If src is zero, do not writeback, but update flags */
	if (ctxt->src.val == 0)
		ctxt->dst.type = OP_NONE;
	return em_bsf(ctxt);
}

static int em_bsr_c(struct x86_emulate_ctxt *ctxt)
{
	/* If src is zero, do not writeback, but update flags */
	if (ctxt->src.val == 0)
		ctxt->dst.type = OP_NONE;
	return em_bsr(ctxt);
}

static __always_inline u8 test_cc(unsigned int condition, unsigned long flags)
{
	return __emulate_cc(flags, condition & 0xf);
}

static void fetch_register_operand(struct operand *op)
{
	switch (op->bytes) {
	case 1:
		op->val = *(u8 *)op->addr.reg;
		break;
	case 2:
		op->val = *(u16 *)op->addr.reg;
		break;
	case 4:
		op->val = *(u32 *)op->addr.reg;
		break;
	case 8:
		op->val = *(u64 *)op->addr.reg;
		break;
	}
	op->orig_val = op->val;
}

static int flush_pending_x87_faults(struct x86_emulate_ctxt *ctxt);

static int prepare_x87_waiting_instruction(struct x86_emulate_ctxt *ctxt)
{
	if (ctxt->ops->get_cr(ctxt, 0) & (X86_CR0_TS | X86_CR0_EM))
		return emulate_nm(ctxt);

	return flush_pending_x87_faults(ctxt);
}

static int complete_x87_waiting_instruction(struct x86_emulate_ctxt *ctxt,
					    int rc)
{
	if (rc != X86EMUL_CONTINUE)
		return emulate_exception(ctxt, MF_VECTOR, 0, false);

	ctxt->dst.type = OP_NONE;
	return X86EMUL_CONTINUE;
}

/*
 * FLD m32fp: load 32-bit single-precision float onto x87 FPU stack.
 * Used for D9 /0 with memory operand.
 */
static int em_fld(struct x86_emulate_ctxt *ctxt)
{
	u32 float_val;
	int rc;

	rc = prepare_x87_waiting_instruction(ctxt);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	memcpy(&float_val, ctxt->src.valptr, sizeof(float_val));

	kvm_fpu_get();
	rc = asm_safe("flds %[src]", : [src] "m" (float_val));
	kvm_fpu_put();
	return complete_x87_waiting_instruction(ctxt, rc);
}

#define X87_M32FP_OP(_name, _insn)					\
static int _name(struct x86_emulate_ctxt *ctxt)				\
{									\
	u32 float_val;							\
	int rc;								\
									\
	rc = prepare_x87_waiting_instruction(ctxt);			\
	if (rc != X86EMUL_CONTINUE)					\
		return rc;						\
									\
	memcpy(&float_val, ctxt->src.valptr, sizeof(float_val));	\
									\
	kvm_fpu_get();							\
	rc = asm_safe(_insn " %[src]", : [src] "m" (float_val));	\
	kvm_fpu_put();							\
									\
	return complete_x87_waiting_instruction(ctxt, rc);		\
}

/*
 * FST m32fp: store ST(0) to memory as 32-bit float (no pop).
 * Used for D9 /2 with memory operand.
 */
static int em_fst_m32fp(struct x86_emulate_ctxt *ctxt)
{
	u32 float_val;
	int rc;

	rc = prepare_x87_waiting_instruction(ctxt);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	kvm_fpu_get();
	rc = asm_safe("fsts %[dst]", , [dst] "=m" (float_val));
	kvm_fpu_put();
	if (rc != X86EMUL_CONTINUE)
		return complete_x87_waiting_instruction(ctxt, rc);

	ctxt->dst.val = float_val;
	return X86EMUL_CONTINUE;
}

/*
 * FSTP m32fp: store ST(0) to memory as 32-bit float and pop.
 * Used for D9 /3 with memory operand.
 */
static int em_fstp_m32fp(struct x86_emulate_ctxt *ctxt)
{
	u32 float_val;
	int rc;

	rc = prepare_x87_waiting_instruction(ctxt);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	kvm_fpu_get();
	rc = asm_safe("fstps %[dst]", , [dst] "=m" (float_val));
	kvm_fpu_put();
	if (rc != X86EMUL_CONTINUE)
		return complete_x87_waiting_instruction(ctxt, rc);

	ctxt->dst.val = float_val;
	return X86EMUL_CONTINUE;
}

/*
 * FLD m64fp: load 64-bit double from memory onto x87 stack.
 * Used for DD /0 with memory operand.
 */
static int em_fld_m64fp(struct x86_emulate_ctxt *ctxt)
{
	u64 float_val;
	int rc;

	rc = prepare_x87_waiting_instruction(ctxt);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	memcpy(&float_val, ctxt->src.valptr, sizeof(float_val));

	kvm_fpu_get();
	rc = asm_safe("fldl %[src]", : [src] "m" (float_val));
	kvm_fpu_put();
	return complete_x87_waiting_instruction(ctxt, rc);
}

/*
 * FST m64fp: store ST(0) to memory as 64-bit double (no pop).
 * Used for DD /2 with memory operand.
 */
static int em_fst_m64fp(struct x86_emulate_ctxt *ctxt)
{
	u64 float_val;
	int rc;

	rc = prepare_x87_waiting_instruction(ctxt);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	kvm_fpu_get();
	rc = asm_safe("fstl %[dst]", , [dst] "=m" (float_val));
	kvm_fpu_put();
	if (rc != X86EMUL_CONTINUE)
		return complete_x87_waiting_instruction(ctxt, rc);

	memcpy(ctxt->dst.valptr, &float_val, sizeof(float_val));
	ctxt->dst.bytes = sizeof(float_val);
	return X86EMUL_CONTINUE;
}

/*
 * FSTP m64fp: store ST(0) to memory as 64-bit double and pop.
 * Used for DD /3 with memory operand.
 */
static int em_fstp_m64fp(struct x86_emulate_ctxt *ctxt)
{
	u64 float_val;
	int rc;

	rc = prepare_x87_waiting_instruction(ctxt);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	kvm_fpu_get();
	rc = asm_safe("fstpl %[dst]", , [dst] "=m" (float_val));
	kvm_fpu_put();
	if (rc != X86EMUL_CONTINUE)
		return complete_x87_waiting_instruction(ctxt, rc);

	memcpy(ctxt->dst.valptr, &float_val, sizeof(float_val));
	ctxt->dst.bytes = sizeof(float_val);
	return X86EMUL_CONTINUE;
}

/*
 * FSTP m80fp: store ST(0) to memory as 80-bit extended-precision float and pop.
 * Used for DB /7 with memory operand. There is no OpMem80, so the table entry
 * uses generic DstMem and the writeback length is overridden to 10 bytes here.
 */
static int em_fstp_m80fp(struct x86_emulate_ctxt *ctxt)
{
	u8 float_val[10];
	int rc;

	rc = prepare_x87_waiting_instruction(ctxt);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	kvm_fpu_get();
	rc = asm_safe("fstpt %[dst]", , [dst] "=m" (float_val));
	kvm_fpu_put();
	if (rc != X86EMUL_CONTINUE)
		return complete_x87_waiting_instruction(ctxt, rc);

	memcpy(ctxt->dst.valptr, float_val, sizeof(float_val));
	ctxt->dst.bytes = sizeof(float_val);
	return X86EMUL_CONTINUE;
}

X87_M32FP_OP(em_fadd_m32fp, "fadds")
X87_M32FP_OP(em_fmul_m32fp, "fmuls")
X87_M32FP_OP(em_fcom_m32fp, "fcoms")
X87_M32FP_OP(em_fcomp_m32fp, "fcomps")
X87_M32FP_OP(em_fsub_m32fp, "fsubs")
X87_M32FP_OP(em_fsubr_m32fp, "fsubrs")
X87_M32FP_OP(em_fdiv_m32fp, "fdivs")
X87_M32FP_OP(em_fdivr_m32fp, "fdivrs")

#define X87_D8_REG_CASE(_modrm, _modrm_text)			\
	case _modrm:						\
		rc = asm_safe(".byte 0xd8, " _modrm_text);	\
		break

static int em_x87_d8_reg(struct x86_emulate_ctxt *ctxt)
{
	int rc;

	rc = prepare_x87_waiting_instruction(ctxt);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	kvm_fpu_get();

	/* Emit the exact D8 xx opcode so ST(i) ordering matches hardware. */
	switch (ctxt->modrm) {
	X87_D8_REG_CASE(0xc0, "0xc0");
	X87_D8_REG_CASE(0xc1, "0xc1");
	X87_D8_REG_CASE(0xc2, "0xc2");
	X87_D8_REG_CASE(0xc3, "0xc3");
	X87_D8_REG_CASE(0xc4, "0xc4");
	X87_D8_REG_CASE(0xc5, "0xc5");
	X87_D8_REG_CASE(0xc6, "0xc6");
	X87_D8_REG_CASE(0xc7, "0xc7");
	X87_D8_REG_CASE(0xc8, "0xc8");
	X87_D8_REG_CASE(0xc9, "0xc9");
	X87_D8_REG_CASE(0xca, "0xca");
	X87_D8_REG_CASE(0xcb, "0xcb");
	X87_D8_REG_CASE(0xcc, "0xcc");
	X87_D8_REG_CASE(0xcd, "0xcd");
	X87_D8_REG_CASE(0xce, "0xce");
	X87_D8_REG_CASE(0xcf, "0xcf");
	X87_D8_REG_CASE(0xd0, "0xd0");
	X87_D8_REG_CASE(0xd1, "0xd1");
	X87_D8_REG_CASE(0xd2, "0xd2");
	X87_D8_REG_CASE(0xd3, "0xd3");
	X87_D8_REG_CASE(0xd4, "0xd4");
	X87_D8_REG_CASE(0xd5, "0xd5");
	X87_D8_REG_CASE(0xd6, "0xd6");
	X87_D8_REG_CASE(0xd7, "0xd7");
	X87_D8_REG_CASE(0xd8, "0xd8");
	X87_D8_REG_CASE(0xd9, "0xd9");
	X87_D8_REG_CASE(0xda, "0xda");
	X87_D8_REG_CASE(0xdb, "0xdb");
	X87_D8_REG_CASE(0xdc, "0xdc");
	X87_D8_REG_CASE(0xdd, "0xdd");
	X87_D8_REG_CASE(0xde, "0xde");
	X87_D8_REG_CASE(0xdf, "0xdf");
	X87_D8_REG_CASE(0xe0, "0xe0");
	X87_D8_REG_CASE(0xe1, "0xe1");
	X87_D8_REG_CASE(0xe2, "0xe2");
	X87_D8_REG_CASE(0xe3, "0xe3");
	X87_D8_REG_CASE(0xe4, "0xe4");
	X87_D8_REG_CASE(0xe5, "0xe5");
	X87_D8_REG_CASE(0xe6, "0xe6");
	X87_D8_REG_CASE(0xe7, "0xe7");
	X87_D8_REG_CASE(0xe8, "0xe8");
	X87_D8_REG_CASE(0xe9, "0xe9");
	X87_D8_REG_CASE(0xea, "0xea");
	X87_D8_REG_CASE(0xeb, "0xeb");
	X87_D8_REG_CASE(0xec, "0xec");
	X87_D8_REG_CASE(0xed, "0xed");
	X87_D8_REG_CASE(0xee, "0xee");
	X87_D8_REG_CASE(0xef, "0xef");
	X87_D8_REG_CASE(0xf0, "0xf0");
	X87_D8_REG_CASE(0xf1, "0xf1");
	X87_D8_REG_CASE(0xf2, "0xf2");
	X87_D8_REG_CASE(0xf3, "0xf3");
	X87_D8_REG_CASE(0xf4, "0xf4");
	X87_D8_REG_CASE(0xf5, "0xf5");
	X87_D8_REG_CASE(0xf6, "0xf6");
	X87_D8_REG_CASE(0xf7, "0xf7");
	X87_D8_REG_CASE(0xf8, "0xf8");
	X87_D8_REG_CASE(0xf9, "0xf9");
	X87_D8_REG_CASE(0xfa, "0xfa");
	X87_D8_REG_CASE(0xfb, "0xfb");
	X87_D8_REG_CASE(0xfc, "0xfc");
	X87_D8_REG_CASE(0xfd, "0xfd");
	X87_D8_REG_CASE(0xfe, "0xfe");
	X87_D8_REG_CASE(0xff, "0xff");
	default:
		rc = EMULATION_FAILED;
		break;
	}

	kvm_fpu_put();

	if (rc == EMULATION_FAILED)
		return rc;

	return complete_x87_waiting_instruction(ctxt, rc);
}

#undef X87_D8_REG_CASE
#undef X87_M32FP_OP

static int em_fninit(struct x86_emulate_ctxt *ctxt)
{
	if (ctxt->ops->get_cr(ctxt, 0) & (X86_CR0_TS | X86_CR0_EM))
		return emulate_nm(ctxt);

	kvm_fpu_get();
	asm volatile("fninit");
	kvm_fpu_put();
	return X86EMUL_CONTINUE;
}

static int em_fnstcw(struct x86_emulate_ctxt *ctxt)
{
	u16 fcw;

	if (ctxt->ops->get_cr(ctxt, 0) & (X86_CR0_TS | X86_CR0_EM))
		return emulate_nm(ctxt);

	kvm_fpu_get();
	asm volatile("fnstcw %0": "+m"(fcw));
	kvm_fpu_put();

	ctxt->dst.val = fcw;

	return X86EMUL_CONTINUE;
}

static int em_fnstsw(struct x86_emulate_ctxt *ctxt)
{
	u16 fsw;

	if (ctxt->ops->get_cr(ctxt, 0) & (X86_CR0_TS | X86_CR0_EM))
		return emulate_nm(ctxt);

	kvm_fpu_get();
	asm volatile("fnstsw %0": "+m"(fsw));
	kvm_fpu_put();

	ctxt->dst.val = fsw;

	return X86EMUL_CONTINUE;
}

static void __decode_register_operand(struct x86_emulate_ctxt *ctxt,
				      struct operand *op, int reg)
{
	if ((ctxt->d & Avx) && ctxt->op_bytes == 32) {
		op->type = OP_YMM;
		op->bytes = 32;
		op->addr.xmm = reg;
		kvm_read_avx_reg(reg, &op->vec_val2);
		return;
	}
	if (ctxt->d & (Avx|Sse)) {
		op->type = OP_XMM;
		op->bytes = 16;
		op->addr.xmm = reg;
		kvm_read_sse_reg(reg, &op->vec_val);
		return;
	}
	if (ctxt->d & Mmx) {
		reg &= 7;
		op->type = OP_MM;
		op->bytes = 8;
		op->addr.mm = reg;
		return;
	}

	op->type = OP_REG;
	op->bytes = (ctxt->d & ByteOp) ? 1 : ctxt->op_bytes;
	op->addr.reg = decode_register(ctxt, reg, ctxt->d & ByteOp);
	fetch_register_operand(op);
}

static void decode_register_operand(struct x86_emulate_ctxt *ctxt,
				    struct operand *op)
{
	unsigned int reg;

	if (ctxt->d & ModRM)
		reg = ctxt->modrm_reg;
	else
		reg = (ctxt->b & 7) | (ctxt->rex_bits & REX_B ? 8 : 0);

	__decode_register_operand(ctxt, op, reg);
}

static void adjust_modrm_seg(struct x86_emulate_ctxt *ctxt, int base_reg)
{
	if (base_reg == VCPU_REGS_RSP || base_reg == VCPU_REGS_RBP)
		ctxt->modrm_seg = VCPU_SREG_SS;
}

static int decode_modrm(struct x86_emulate_ctxt *ctxt,
			struct operand *op)
{
	u8 sib;
	int index_reg, base_reg, scale;
	int rc = X86EMUL_CONTINUE;
	ulong modrm_ea = 0;

	ctxt->modrm_reg = (ctxt->rex_bits & REX_R ? 8 : 0);
	index_reg = (ctxt->rex_bits & REX_X ? 8 : 0);
	base_reg = (ctxt->rex_bits & REX_B ? 8 : 0);

	ctxt->modrm_mod = (ctxt->modrm & 0xc0) >> 6;
	ctxt->modrm_reg |= (ctxt->modrm & 0x38) >> 3;
	ctxt->modrm_rm = base_reg | (ctxt->modrm & 0x07);
	ctxt->modrm_seg = VCPU_SREG_DS;

	if (ctxt->modrm_mod == 3 || (ctxt->d & NoMod)) {
		__decode_register_operand(ctxt, op, ctxt->modrm_rm);
		return rc;
	}

	op->type = OP_MEM;

	if (ctxt->ad_bytes == 2) {
		unsigned bx = reg_read(ctxt, VCPU_REGS_RBX);
		unsigned bp = reg_read(ctxt, VCPU_REGS_RBP);
		unsigned si = reg_read(ctxt, VCPU_REGS_RSI);
		unsigned di = reg_read(ctxt, VCPU_REGS_RDI);

		/* 16-bit ModR/M decode. */
		switch (ctxt->modrm_mod) {
		case 0:
			if (ctxt->modrm_rm == 6)
				modrm_ea += insn_fetch(u16, ctxt);
			break;
		case 1:
			modrm_ea += insn_fetch(s8, ctxt);
			break;
		case 2:
			modrm_ea += insn_fetch(u16, ctxt);
			break;
		}
		switch (ctxt->modrm_rm) {
		case 0:
			modrm_ea += bx + si;
			break;
		case 1:
			modrm_ea += bx + di;
			break;
		case 2:
			modrm_ea += bp + si;
			break;
		case 3:
			modrm_ea += bp + di;
			break;
		case 4:
			modrm_ea += si;
			break;
		case 5:
			modrm_ea += di;
			break;
		case 6:
			if (ctxt->modrm_mod != 0)
				modrm_ea += bp;
			break;
		case 7:
			modrm_ea += bx;
			break;
		}
		if (ctxt->modrm_rm == 2 || ctxt->modrm_rm == 3 ||
		    (ctxt->modrm_rm == 6 && ctxt->modrm_mod != 0))
			ctxt->modrm_seg = VCPU_SREG_SS;
		modrm_ea = (u16)modrm_ea;
	} else {
		/* 32/64-bit ModR/M decode. */
		if ((ctxt->modrm_rm & 7) == 4) {
			sib = insn_fetch(u8, ctxt);
			index_reg |= (sib >> 3) & 7;
			base_reg |= sib & 7;
			scale = sib >> 6;

			if ((base_reg & 7) == 5 && ctxt->modrm_mod == 0)
				modrm_ea += insn_fetch(s32, ctxt);
			else {
				modrm_ea += reg_read(ctxt, base_reg);
				adjust_modrm_seg(ctxt, base_reg);
				/* Increment ESP on POP [ESP] */
				if ((ctxt->d & IncSP) &&
				    base_reg == VCPU_REGS_RSP)
					modrm_ea += ctxt->op_bytes;
			}
			if (index_reg != 4)
				modrm_ea += reg_read(ctxt, index_reg) << scale;
		} else if ((ctxt->modrm_rm & 7) == 5 && ctxt->modrm_mod == 0) {
			modrm_ea += insn_fetch(s32, ctxt);
			if (ctxt->mode == X86EMUL_MODE_PROT64)
				ctxt->rip_relative = 1;
		} else {
			base_reg = ctxt->modrm_rm;
			modrm_ea += reg_read(ctxt, base_reg);
			adjust_modrm_seg(ctxt, base_reg);
		}
		switch (ctxt->modrm_mod) {
		case 1:
			modrm_ea += insn_fetch(s8, ctxt);
			break;
		case 2:
			modrm_ea += insn_fetch(s32, ctxt);
			break;
		}
	}
	op->addr.mem.ea = modrm_ea;
	if (ctxt->ad_bytes != 8)
		ctxt->memop.addr.mem.ea = (u32)ctxt->memop.addr.mem.ea;

done:
	return rc;
}

static int decode_abs(struct x86_emulate_ctxt *ctxt,
		      struct operand *op)
{
	int rc = X86EMUL_CONTINUE;

	op->type = OP_MEM;
	switch (ctxt->ad_bytes) {
	case 2:
		op->addr.mem.ea = insn_fetch(u16, ctxt);
		break;
	case 4:
		op->addr.mem.ea = insn_fetch(u32, ctxt);
		break;
	case 8:
		op->addr.mem.ea = insn_fetch(u64, ctxt);
		break;
	}
done:
	return rc;
}

static void fetch_bit_operand(struct x86_emulate_ctxt *ctxt)
{
	long sv = 0, mask;

	if (ctxt->dst.type == OP_MEM && ctxt->src.type == OP_REG) {
		mask = ~((long)ctxt->dst.bytes * 8 - 1);

		if (ctxt->src.bytes == 2)
			sv = (s16)ctxt->src.val & (s16)mask;
		else if (ctxt->src.bytes == 4)
			sv = (s32)ctxt->src.val & (s32)mask;
		else
			sv = (s64)ctxt->src.val & (s64)mask;

		ctxt->dst.addr.mem.ea = address_mask(ctxt,
					   ctxt->dst.addr.mem.ea + (sv >> 3));
	}

	/* only subword offset */
	ctxt->src.val &= (ctxt->dst.bytes << 3) - 1;
}

static int read_emulated(struct x86_emulate_ctxt *ctxt,
			 unsigned long addr, void *dest, unsigned size)
{
	int rc;
	struct read_cache *mc = &ctxt->mem_read;

	if (mc->pos < mc->end)
		goto read_cached;

	if (KVM_EMULATOR_BUG_ON((mc->end + size) >= sizeof(mc->data), ctxt))
		return X86EMUL_UNHANDLEABLE;

	rc = ctxt->ops->read_emulated(ctxt, addr, mc->data + mc->end, size,
				      &ctxt->exception);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	mc->end += size;

read_cached:
	memcpy(dest, mc->data + mc->pos, size);
	mc->pos += size;
	return X86EMUL_CONTINUE;
}

static int segmented_read(struct x86_emulate_ctxt *ctxt,
			  struct segmented_address addr,
			  void *data,
			  unsigned size)
{
	int rc;
	ulong linear;

	rc = linearize(ctxt, addr, size, false, &linear);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	return read_emulated(ctxt, linear, data, size);
}

static int segmented_write(struct x86_emulate_ctxt *ctxt,
			   struct segmented_address addr,
			   const void *data,
			   unsigned size)
{
	int rc;
	ulong linear;

	rc = linearize(ctxt, addr, size, true, &linear);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	return ctxt->ops->write_emulated(ctxt, linear, data, size,
					 &ctxt->exception);
}

static int segmented_cmpxchg(struct x86_emulate_ctxt *ctxt,
			     struct segmented_address addr,
			     const void *orig_data, const void *data,
			     unsigned size)
{
	int rc;
	ulong linear;

	rc = linearize(ctxt, addr, size, true, &linear);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	return ctxt->ops->cmpxchg_emulated(ctxt, linear, orig_data, data,
					   size, &ctxt->exception);
}

static int pio_in_emulated(struct x86_emulate_ctxt *ctxt,
			   unsigned int size, unsigned short port,
			   void *dest)
{
	struct read_cache *rc = &ctxt->io_read;

	if (rc->pos == rc->end) { /* refill pio read ahead */
		unsigned int in_page, n;
		unsigned int count = ctxt->rep_prefix ?
			address_mask(ctxt, reg_read(ctxt, VCPU_REGS_RCX)) : 1;
		in_page = (ctxt->eflags & X86_EFLAGS_DF) ?
			offset_in_page(reg_read(ctxt, VCPU_REGS_RDI)) :
			PAGE_SIZE - offset_in_page(reg_read(ctxt, VCPU_REGS_RDI));
		n = min3(in_page, (unsigned int)sizeof(rc->data) / size, count);
		if (n == 0)
			n = 1;
		rc->pos = rc->end = 0;
		if (!ctxt->ops->pio_in_emulated(ctxt, size, port, rc->data, n))
			return 0;
		rc->end = n * size;
	}

	if (ctxt->rep_prefix && (ctxt->d & String) &&
	    !(ctxt->eflags & X86_EFLAGS_DF)) {
		ctxt->dst.data = rc->data + rc->pos;
		ctxt->dst.type = OP_MEM_STR;
		ctxt->dst.count = (rc->end - rc->pos) / size;
		rc->pos = rc->end;
	} else {
		memcpy(dest, rc->data + rc->pos, size);
		rc->pos += size;
	}
	return 1;
}

static int read_interrupt_descriptor(struct x86_emulate_ctxt *ctxt,
				     u16 index, struct desc_struct *desc)
{
	struct desc_ptr dt;
	ulong addr;

	ctxt->ops->get_idt(ctxt, &dt);

	if (dt.size < index * 8 + 7)
		return emulate_gp(ctxt, index << 3 | 0x2);

	addr = dt.address + index * 8;
	return linear_read_system(ctxt, addr, desc, sizeof(*desc));
}

static void get_descriptor_table_ptr(struct x86_emulate_ctxt *ctxt,
				     u16 selector, struct desc_ptr *dt)
{
	const struct x86_emulate_ops *ops = ctxt->ops;
	u32 base3 = 0;

	if (selector & 1 << 2) {
		struct desc_struct desc;
		u16 sel;

		memset(dt, 0, sizeof(*dt));
		if (!ops->get_segment(ctxt, &sel, &desc, &base3,
				      VCPU_SREG_LDTR))
			return;

		dt->size = desc_limit_scaled(&desc); /* what if limit > 65535? */
		dt->address = get_desc_base(&desc) | ((u64)base3 << 32);
	} else
		ops->get_gdt(ctxt, dt);
}

static int get_descriptor_ptr(struct x86_emulate_ctxt *ctxt,
			      u16 selector, ulong *desc_addr_p)
{
	struct desc_ptr dt;
	u16 index = selector >> 3;
	ulong addr;

	get_descriptor_table_ptr(ctxt, selector, &dt);

	if (dt.size < index * 8 + 7)
		return emulate_gp(ctxt, selector & 0xfffc);

	addr = dt.address + index * 8;

#ifdef CONFIG_X86_64
	if (addr >> 32 != 0) {
		u64 efer = 0;

		ctxt->ops->get_msr(ctxt, MSR_EFER, &efer);
		if (!(efer & EFER_LMA))
			addr &= (u32)-1;
	}
#endif

	*desc_addr_p = addr;
	return X86EMUL_CONTINUE;
}

/* allowed just for 8 bytes segments */
static int read_segment_descriptor(struct x86_emulate_ctxt *ctxt,
				   u16 selector, struct desc_struct *desc,
				   ulong *desc_addr_p)
{
	int rc;

	rc = get_descriptor_ptr(ctxt, selector, desc_addr_p);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	return linear_read_system(ctxt, *desc_addr_p, desc, sizeof(*desc));
}

/* allowed just for 8 bytes segments */
static int write_segment_descriptor(struct x86_emulate_ctxt *ctxt,
				    u16 selector, struct desc_struct *desc)
{
	int rc;
	ulong addr;

	rc = get_descriptor_ptr(ctxt, selector, &addr);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	return linear_write_system(ctxt, addr, desc, sizeof(*desc));
}

static bool emulator_is_ssp_invalid(struct x86_emulate_ctxt *ctxt, u8 cpl)
{
	const u32 MSR_IA32_X_CET = cpl == 3 ? MSR_IA32_U_CET : MSR_IA32_S_CET;
	u64 efer = 0, cet = 0, ssp = 0;

	if (!(ctxt->ops->get_cr(ctxt, 4) & X86_CR4_CET))
		return false;

	if (ctxt->ops->get_msr(ctxt, MSR_EFER, &efer))
		return true;

	/* SSP is guaranteed to be valid if the vCPU was already in 32-bit mode. */
	if (!(efer & EFER_LMA))
		return false;

	if (ctxt->ops->get_msr(ctxt, MSR_IA32_X_CET, &cet))
		return true;

	if (!(cet & CET_SHSTK_EN))
		return false;

	if (ctxt->ops->get_msr(ctxt, MSR_KVM_INTERNAL_GUEST_SSP, &ssp))
		return true;

	/*
	 * On transfer from 64-bit mode to compatibility mode, SSP[63:32] must
	 * be 0, i.e. SSP must be a 32-bit value outside of 64-bit mode.
	 */
	return ssp >> 32;
}

static int __load_segment_descriptor(struct x86_emulate_ctxt *ctxt,
				     u16 selector, int seg, u8 cpl,
				     enum x86_transfer_type transfer,
				     struct desc_struct *desc)
{
	struct desc_struct seg_desc, old_desc;
	u8 dpl, rpl;
	unsigned err_vec = GP_VECTOR;
	u32 err_code = 0;
	bool null_selector = !(selector & ~0x3); /* 0000-0003 are null */
	ulong desc_addr;
	int ret;
	u16 dummy;
	u32 base3 = 0;

	memset(&seg_desc, 0, sizeof(seg_desc));

	if (ctxt->mode == X86EMUL_MODE_REAL) {
		/* set real mode segment descriptor (keep limit etc. for
		 * unreal mode) */
		ctxt->ops->get_segment(ctxt, &dummy, &seg_desc, NULL, seg);
		set_desc_base(&seg_desc, selector << 4);
		goto load;
	} else if (seg <= VCPU_SREG_GS && ctxt->mode == X86EMUL_MODE_VM86) {
		/* VM86 needs a clean new segment descriptor */
		set_desc_base(&seg_desc, selector << 4);
		set_desc_limit(&seg_desc, 0xffff);
		seg_desc.type = 3;
		seg_desc.p = 1;
		seg_desc.s = 1;
		seg_desc.dpl = 3;
		goto load;
	}

	rpl = selector & 3;

	/* TR should be in GDT only */
	if (seg == VCPU_SREG_TR && (selector & (1 << 2)))
		goto exception;

	/* NULL selector is not valid for TR, CS and (except for long mode) SS */
	if (null_selector) {
		if (seg == VCPU_SREG_CS || seg == VCPU_SREG_TR)
			goto exception;

		if (seg == VCPU_SREG_SS) {
			if (ctxt->mode != X86EMUL_MODE_PROT64 || rpl != cpl)
				goto exception;

			/*
			 * ctxt->ops->set_segment expects the CPL to be in
			 * SS.DPL, so fake an expand-up 32-bit data segment.
			 */
			seg_desc.type = 3;
			seg_desc.p = 1;
			seg_desc.s = 1;
			seg_desc.dpl = cpl;
			seg_desc.d = 1;
			seg_desc.g = 1;
		}

		/* Skip all following checks */
		goto load;
	}

	ret = read_segment_descriptor(ctxt, selector, &seg_desc, &desc_addr);
	if (ret != X86EMUL_CONTINUE)
		return ret;

	err_code = selector & 0xfffc;
	err_vec = (transfer == X86_TRANSFER_TASK_SWITCH) ? TS_VECTOR :
							   GP_VECTOR;

	/* can't load system descriptor into segment selector */
	if (seg <= VCPU_SREG_GS && !seg_desc.s) {
		if (transfer == X86_TRANSFER_CALL_JMP)
			return X86EMUL_UNHANDLEABLE;
		goto exception;
	}

	dpl = seg_desc.dpl;

	switch (seg) {
	case VCPU_SREG_SS:
		/*
		 * segment is not a writable data segment or segment
		 * selector's RPL != CPL or DPL != CPL
		 */
		if (rpl != cpl || (seg_desc.type & 0xa) != 0x2 || dpl != cpl)
			goto exception;
		break;
	case VCPU_SREG_CS:
		/*
		 * KVM uses "none" when loading CS as part of emulating Real
		 * Mode exceptions and IRET (handled above).  In all other
		 * cases, loading CS without a control transfer is a KVM bug.
		 */
		if (WARN_ON_ONCE(transfer == X86_TRANSFER_NONE))
			goto exception;

		if (!(seg_desc.type & 8))
			goto exception;

		if (transfer == X86_TRANSFER_RET) {
			/* RET can never return to an inner privilege level. */
			if (rpl < cpl)
				goto exception;
			/* Outer-privilege level return is not implemented */
			if (rpl > cpl)
				return X86EMUL_UNHANDLEABLE;
		}
		if (transfer == X86_TRANSFER_RET || transfer == X86_TRANSFER_TASK_SWITCH) {
			if (seg_desc.type & 4) {
				/* conforming */
				if (dpl > rpl)
					goto exception;
			} else {
				/* nonconforming */
				if (dpl != rpl)
					goto exception;
			}
		} else { /* X86_TRANSFER_CALL_JMP */
			if (seg_desc.type & 4) {
				/* conforming */
				if (dpl > cpl)
					goto exception;
			} else {
				/* nonconforming */
				if (rpl > cpl || dpl != cpl)
					goto exception;
			}
		}
		/* in long-mode d/b must be clear if l is set */
		if (seg_desc.d && seg_desc.l) {
			u64 efer = 0;

			ctxt->ops->get_msr(ctxt, MSR_EFER, &efer);
			if (efer & EFER_LMA)
				goto exception;
		}
		if (!seg_desc.l && emulator_is_ssp_invalid(ctxt, cpl)) {
			err_code = 0;
			goto exception;
		}

		/* CS(RPL) <- CPL */
		selector = (selector & 0xfffc) | cpl;
		break;
	case VCPU_SREG_TR:
		if (seg_desc.s || (seg_desc.type != 1 && seg_desc.type != 9))
			goto exception;
		break;
	case VCPU_SREG_LDTR:
		if (seg_desc.s || seg_desc.type != 2)
			goto exception;
		break;
	default: /*  DS, ES, FS, or GS */
		/*
		 * segment is not a data or readable code segment or
		 * ((segment is a data or nonconforming code segment)
		 * and ((RPL > DPL) or (CPL > DPL)))
		 */
		if ((seg_desc.type & 0xa) == 0x8 ||
		    (((seg_desc.type & 0xc) != 0xc) &&
		     (rpl > dpl || cpl > dpl)))
			goto exception;
		break;
	}

	if (!seg_desc.p) {
		err_vec = (seg == VCPU_SREG_SS) ? SS_VECTOR : NP_VECTOR;
		goto exception;
	}

	if (seg_desc.s) {
		/* mark segment as accessed */
		if (!(seg_desc.type & 1)) {
			seg_desc.type |= 1;
			ret = write_segment_descriptor(ctxt, selector,
						       &seg_desc);
			if (ret != X86EMUL_CONTINUE)
				return ret;
		}
	} else if (ctxt->mode == X86EMUL_MODE_PROT64) {
		ret = linear_read_system(ctxt, desc_addr+8, &base3, sizeof(base3));
		if (ret != X86EMUL_CONTINUE)
			return ret;
		if (emul_is_noncanonical_address(get_desc_base(&seg_desc) |
						 ((u64)base3 << 32), ctxt,
						 X86EMUL_F_DT_LOAD))
			return emulate_gp(ctxt, err_code);
	}

	if (seg == VCPU_SREG_TR) {
		old_desc = seg_desc;
		seg_desc.type |= 2; /* busy */
		ret = ctxt->ops->cmpxchg_emulated(ctxt, desc_addr, &old_desc, &seg_desc,
						  sizeof(seg_desc), &ctxt->exception);
		if (ret != X86EMUL_CONTINUE)
			return ret;
	}
load:
	ctxt->ops->set_segment(ctxt, selector, &seg_desc, base3, seg);
	if (desc)
		*desc = seg_desc;
	return X86EMUL_CONTINUE;
exception:
	return emulate_exception(ctxt, err_vec, err_code, true);
}

static int load_segment_descriptor(struct x86_emulate_ctxt *ctxt,
				   u16 selector, int seg)
{
	u8 cpl = ctxt->ops->cpl(ctxt);

	/*
	 * None of MOV, POP and LSS can load a NULL selector in CPL=3, but
	 * they can load it at CPL<3 (Intel's manual says only LSS can,
	 * but it's wrong).
	 *
	 * However, the Intel manual says that putting IST=1/DPL=3 in
	 * an interrupt gate will result in SS=3 (the AMD manual instead
	 * says it doesn't), so allow SS=3 in __load_segment_descriptor
	 * and only forbid it here.
	 */
	if (seg == VCPU_SREG_SS && selector == 3 &&
	    ctxt->mode == X86EMUL_MODE_PROT64)
		return emulate_exception(ctxt, GP_VECTOR, 0, true);

	return __load_segment_descriptor(ctxt, selector, seg, cpl,
					 X86_TRANSFER_NONE, NULL);
}

static void write_register_operand(struct operand *op)
{
	return assign_register(op->addr.reg, op->val, op->bytes);
}

static int writeback(struct x86_emulate_ctxt *ctxt, struct operand *op)
{
	switch (op->type) {
	case OP_REG:
		write_register_operand(op);
		break;
	case OP_MEM:
		if (ctxt->lock_prefix)
			return segmented_cmpxchg(ctxt,
						 op->addr.mem,
						 &op->orig_val,
						 &op->val,
						 op->bytes);
		else
			return segmented_write(ctxt,
					       op->addr.mem,
					       &op->val,
					       op->bytes);
	case OP_MEM_STR:
		return segmented_write(ctxt,
				       op->addr.mem,
				       op->data,
				       op->bytes * op->count);
	case OP_XMM:
		if (!(ctxt->d & Avx)) {
			kvm_write_sse_reg(op->addr.xmm, &op->vec_val);
			break;
		}
		/* full YMM write but with high bytes cleared */
		memset(op->valptr + 16, 0, 16);
		fallthrough;
	case OP_YMM:
		kvm_write_avx_reg(op->addr.xmm, &op->vec_val2);
		break;
	case OP_MM:
		kvm_write_mmx_reg(op->addr.mm, &op->mm_val);
		break;
	case OP_NONE:
		/* no writeback */
		break;
	default:
		break;
	}
	return X86EMUL_CONTINUE;
}

static int emulate_push(struct x86_emulate_ctxt *ctxt, const void *data, int len)
{
	struct segmented_address addr;

	rsp_increment(ctxt, -len);
	addr.ea = reg_read(ctxt, VCPU_REGS_RSP) & stack_mask(ctxt);
	addr.seg = VCPU_SREG_SS;

	return segmented_write(ctxt, addr, data, len);
}

static int em_push(struct x86_emulate_ctxt *ctxt)
{
	/* Disable writeback. */
	ctxt->dst.type = OP_NONE;
	return emulate_push(ctxt, &ctxt->src.val, ctxt->op_bytes);
}

static int emulate_pop(struct x86_emulate_ctxt *ctxt,
		       void *dest, int len)
{
	int rc;
	struct segmented_address addr;

	addr.ea = reg_read(ctxt, VCPU_REGS_RSP) & stack_mask(ctxt);
	addr.seg = VCPU_SREG_SS;
	rc = segmented_read(ctxt, addr, dest, len);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	rsp_increment(ctxt, len);
	return rc;
}

static int em_pop(struct x86_emulate_ctxt *ctxt)
{
	return emulate_pop(ctxt, &ctxt->dst.val, ctxt->op_bytes);
}

static int emulate_popf(struct x86_emulate_ctxt *ctxt,
			void *dest, int len)
{
	int rc;
	unsigned long val = 0;
	unsigned long change_mask;
	int iopl = (ctxt->eflags & X86_EFLAGS_IOPL) >> X86_EFLAGS_IOPL_BIT;
	int cpl = ctxt->ops->cpl(ctxt);

	rc = emulate_pop(ctxt, &val, len);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	change_mask = X86_EFLAGS_CF | X86_EFLAGS_PF | X86_EFLAGS_AF |
		      X86_EFLAGS_ZF | X86_EFLAGS_SF | X86_EFLAGS_OF |
		      X86_EFLAGS_TF | X86_EFLAGS_DF | X86_EFLAGS_NT |
		      X86_EFLAGS_AC | X86_EFLAGS_ID;

	switch(ctxt->mode) {
	case X86EMUL_MODE_PROT64:
	case X86EMUL_MODE_PROT32:
	case X86EMUL_MODE_PROT16:
		if (cpl == 0)
			change_mask |= X86_EFLAGS_IOPL;
		if (cpl <= iopl)
			change_mask |= X86_EFLAGS_IF;
		break;
	case X86EMUL_MODE_VM86:
		if (iopl < 3)
			return emulate_gp(ctxt, 0);
		change_mask |= X86_EFLAGS_IF;
		break;
	default: /* real mode */
		change_mask |= (X86_EFLAGS_IOPL | X86_EFLAGS_IF);
		break;
	}

	*(unsigned long *)dest =
		(ctxt->eflags & ~change_mask) | (val & change_mask);

	return rc;
}

static int em_popf(struct x86_emulate_ctxt *ctxt)
{
	ctxt->dst.type = OP_REG;
	ctxt->dst.addr.reg = &ctxt->eflags;
	ctxt->dst.bytes = ctxt->op_bytes;
	return emulate_popf(ctxt, &ctxt->dst.val, ctxt->op_bytes);
}

static int em_enter(struct x86_emulate_ctxt *ctxt)
{
	int rc;
	unsigned frame_size = ctxt->src.val;
	unsigned nesting_level = ctxt->src2.val & 31;
	ulong rbp;

	if (nesting_level)
		return X86EMUL_UNHANDLEABLE;

	rbp = reg_read(ctxt, VCPU_REGS_RBP);
	rc = emulate_push(ctxt, &rbp, stack_size(ctxt));
	if (rc != X86EMUL_CONTINUE)
		return rc;
	assign_masked(reg_rmw(ctxt, VCPU_REGS_RBP), reg_read(ctxt, VCPU_REGS_RSP),
		      stack_mask(ctxt));
	assign_masked(reg_rmw(ctxt, VCPU_REGS_RSP),
		      reg_read(ctxt, VCPU_REGS_RSP) - frame_size,
		      stack_mask(ctxt));
	return X86EMUL_CONTINUE;
}

static int em_leave(struct x86_emulate_ctxt *ctxt)
{
	assign_masked(reg_rmw(ctxt, VCPU_REGS_RSP), reg_read(ctxt, VCPU_REGS_RBP),
		      stack_mask(ctxt));
	return emulate_pop(ctxt, reg_rmw(ctxt, VCPU_REGS_RBP), ctxt->op_bytes);
}

static int em_push_sreg(struct x86_emulate_ctxt *ctxt)
{
	int seg = ctxt->src2.val;

	ctxt->src.val = get_segment_selector(ctxt, seg);
	if (ctxt->op_bytes == 4) {
		rsp_increment(ctxt, -2);
		ctxt->op_bytes = 2;
	}

	return em_push(ctxt);
}

static int em_pop_sreg(struct x86_emulate_ctxt *ctxt)
{
	int seg = ctxt->src2.val;
	unsigned long selector = 0;
	int rc;

	rc = emulate_pop(ctxt, &selector, 2);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	if (seg == VCPU_SREG_SS)
		ctxt->interruptibility = KVM_X86_SHADOW_INT_MOV_SS;
	if (ctxt->op_bytes > 2)
		rsp_increment(ctxt, ctxt->op_bytes - 2);

	rc = load_segment_descriptor(ctxt, (u16)selector, seg);
	return rc;
}

static int em_pusha(struct x86_emulate_ctxt *ctxt)
{
	unsigned long old_esp = reg_read(ctxt, VCPU_REGS_RSP);
	int rc = X86EMUL_CONTINUE;
	int reg = VCPU_REGS_RAX;

	while (reg <= VCPU_REGS_RDI) {
		(reg == VCPU_REGS_RSP) ?
		(ctxt->src.val = old_esp) : (ctxt->src.val = reg_read(ctxt, reg));

		rc = em_push(ctxt);
		if (rc != X86EMUL_CONTINUE)
			return rc;

		++reg;
	}

	return rc;
}

static int em_pushf(struct x86_emulate_ctxt *ctxt)
{
	ctxt->src.val = (unsigned long)ctxt->eflags & ~X86_EFLAGS_VM;
	return em_push(ctxt);
}

static int em_popa(struct x86_emulate_ctxt *ctxt)
{
	int rc = X86EMUL_CONTINUE;
	int reg = VCPU_REGS_RDI;
	u32 val = 0;

	while (reg >= VCPU_REGS_RAX) {
		if (reg == VCPU_REGS_RSP) {
			rsp_increment(ctxt, ctxt->op_bytes);
			--reg;
		}

		rc = emulate_pop(ctxt, &val, ctxt->op_bytes);
		if (rc != X86EMUL_CONTINUE)
			break;
		assign_register(reg_rmw(ctxt, reg), val, ctxt->op_bytes);
		--reg;
	}
	return rc;
}

static int __emulate_int_real(struct x86_emulate_ctxt *ctxt, int irq)
{
	const struct x86_emulate_ops *ops = ctxt->ops;
	int rc;
	struct desc_ptr dt;
	gva_t cs_addr;
	gva_t eip_addr;
	u16 cs, eip;

	/* TODO: Add limit checks */
	ctxt->src.val = ctxt->eflags;
	rc = em_push(ctxt);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	ctxt->eflags &= ~(X86_EFLAGS_IF | X86_EFLAGS_TF | X86_EFLAGS_AC);

	ctxt->src.val = get_segment_selector(ctxt, VCPU_SREG_CS);
	rc = em_push(ctxt);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	ctxt->src.val = ctxt->_eip;
	rc = em_push(ctxt);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	ops->get_idt(ctxt, &dt);

	eip_addr = dt.address + (irq << 2);
	cs_addr = dt.address + (irq << 2) + 2;

	rc = linear_read_system(ctxt, cs_addr, &cs, 2);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	rc = linear_read_system(ctxt, eip_addr, &eip, 2);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	rc = load_segment_descriptor(ctxt, cs, VCPU_SREG_CS);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	ctxt->_eip = eip;

	return rc;
}

int emulate_int_real(struct x86_emulate_ctxt *ctxt, int irq)
{
	int rc;

	invalidate_registers(ctxt);
	rc = __emulate_int_real(ctxt, irq);
	if (rc == X86EMUL_CONTINUE)
		writeback_registers(ctxt);
	return rc;
}

static int emulate_int(struct x86_emulate_ctxt *ctxt, int irq)
{
	switch(ctxt->mode) {
	case X86EMUL_MODE_REAL:
		return __emulate_int_real(ctxt, irq);
	case X86EMUL_MODE_VM86:
	case X86EMUL_MODE_PROT16:
	case X86EMUL_MODE_PROT32:
	case X86EMUL_MODE_PROT64:
	default:
		/* Protected mode interrupts unimplemented yet */
		return X86EMUL_UNHANDLEABLE;
	}
}

static int emulate_iret_real(struct x86_emulate_ctxt *ctxt)
{
	int rc = X86EMUL_CONTINUE;
	unsigned long temp_eip = 0;
	unsigned long temp_eflags = 0;
	unsigned long cs = 0;
	unsigned long mask = X86_EFLAGS_CF | X86_EFLAGS_PF | X86_EFLAGS_AF |
			     X86_EFLAGS_ZF | X86_EFLAGS_SF | X86_EFLAGS_TF |
			     X86_EFLAGS_IF | X86_EFLAGS_DF | X86_EFLAGS_OF |
			     X86_EFLAGS_IOPL | X86_EFLAGS_NT | X86_EFLAGS_RF |
			     X86_EFLAGS_AC | X86_EFLAGS_ID |
			     X86_EFLAGS_FIXED;
	unsigned long vm86_mask = X86_EFLAGS_VM | X86_EFLAGS_VIF |
				  X86_EFLAGS_VIP;

	/* TODO: Add stack limit check */

	rc = emulate_pop(ctxt, &temp_eip, ctxt->op_bytes);

	if (rc != X86EMUL_CONTINUE)
		return rc;

	if (temp_eip & ~0xffff)
		return emulate_gp(ctxt, 0);

	rc = emulate_pop(ctxt, &cs, ctxt->op_bytes);

	if (rc != X86EMUL_CONTINUE)
		return rc;

	rc = emulate_pop(ctxt, &temp_eflags, ctxt->op_bytes);

	if (rc != X86EMUL_CONTINUE)
		return rc;

	rc = load_segment_descriptor(ctxt, (u16)cs, VCPU_SREG_CS);

	if (rc != X86EMUL_CONTINUE)
		return rc;

	ctxt->_eip = temp_eip;

	if (ctxt->op_bytes == 4)
		ctxt->eflags = ((temp_eflags & mask) | (ctxt->eflags & vm86_mask));
	else if (ctxt->op_bytes == 2) {
		ctxt->eflags &= ~0xffff;
		ctxt->eflags |= temp_eflags;
	}

	ctxt->eflags &= ~EFLG_RESERVED_ZEROS_MASK; /* Clear reserved zeros */
	ctxt->eflags |= X86_EFLAGS_FIXED;
	ctxt->ops->set_nmi_mask(ctxt, false);

	return rc;
}

static int em_iret(struct x86_emulate_ctxt *ctxt)
{
	switch(ctxt->mode) {
	case X86EMUL_MODE_REAL:
		return emulate_iret_real(ctxt);
	case X86EMUL_MODE_VM86:
	case X86EMUL_MODE_PROT16:
	case X86EMUL_MODE_PROT32:
	case X86EMUL_MODE_PROT64:
	default:
		/* iret from protected mode unimplemented yet */
		return X86EMUL_UNHANDLEABLE;
	}
}

static int em_jmp_far(struct x86_emulate_ctxt *ctxt)
{
	int rc;
	unsigned short sel;
	struct desc_struct new_desc;
	u8 cpl = ctxt->ops->cpl(ctxt);

	memcpy(&sel, ctxt->src.valptr + ctxt->op_bytes, 2);

	rc = __load_segment_descriptor(ctxt, sel, VCPU_SREG_CS, cpl,
				       X86_TRANSFER_CALL_JMP,
				       &new_desc);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	rc = assign_eip_far(ctxt, ctxt->src.val);
	/* Error handling is not implemented. */
	if (rc != X86EMUL_CONTINUE)
		return X86EMUL_UNHANDLEABLE;

	return rc;
}

static int em_jmp_abs(struct x86_emulate_ctxt *ctxt)
{
	return assign_eip_near(ctxt, ctxt->src.val);
}

static int em_call_near_abs(struct x86_emulate_ctxt *ctxt)
{
	int rc;
	long int old_eip;

	old_eip = ctxt->_eip;
	rc = assign_eip_near(ctxt, ctxt->src.val);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	ctxt->src.val = old_eip;
	rc = em_push(ctxt);
	return rc;
}

static int em_cmpxchg8b(struct x86_emulate_ctxt *ctxt)
{
	u64 old = ctxt->dst.orig_val64;

	if (ctxt->dst.bytes == 16)
		return X86EMUL_UNHANDLEABLE;

	if (((u32) (old >> 0) != (u32) reg_read(ctxt, VCPU_REGS_RAX)) ||
	    ((u32) (old >> 32) != (u32) reg_read(ctxt, VCPU_REGS_RDX))) {
		*reg_write(ctxt, VCPU_REGS_RAX) = (u32) (old >> 0);
		*reg_write(ctxt, VCPU_REGS_RDX) = (u32) (old >> 32);
		ctxt->eflags &= ~X86_EFLAGS_ZF;
	} else {
		ctxt->dst.val64 = ((u64)reg_read(ctxt, VCPU_REGS_RCX) << 32) |
			(u32) reg_read(ctxt, VCPU_REGS_RBX);

		ctxt->eflags |= X86_EFLAGS_ZF;
	}
	return X86EMUL_CONTINUE;
}

static int em_ret(struct x86_emulate_ctxt *ctxt)
{
	int rc;
	unsigned long eip = 0;

	rc = emulate_pop(ctxt, &eip, ctxt->op_bytes);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	return assign_eip_near(ctxt, eip);
}

static int em_ret_far(struct x86_emulate_ctxt *ctxt)
{
	int rc;
	unsigned long eip = 0;
	unsigned long cs = 0;
	int cpl = ctxt->ops->cpl(ctxt);
	struct desc_struct new_desc;

	rc = emulate_pop(ctxt, &eip, ctxt->op_bytes);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	rc = emulate_pop(ctxt, &cs, ctxt->op_bytes);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	rc = __load_segment_descriptor(ctxt, (u16)cs, VCPU_SREG_CS, cpl,
				       X86_TRANSFER_RET,
				       &new_desc);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	rc = assign_eip_far(ctxt, eip);
	/* Error handling is not implemented. */
	if (rc != X86EMUL_CONTINUE)
		return X86EMUL_UNHANDLEABLE;

	return rc;
}

static int em_ret_far_imm(struct x86_emulate_ctxt *ctxt)
{
        int rc;

        rc = em_ret_far(ctxt);
        if (rc != X86EMUL_CONTINUE)
                return rc;
        rsp_increment(ctxt, ctxt->src.val);
        return X86EMUL_CONTINUE;
}

static int em_cmpxchg(struct x86_emulate_ctxt *ctxt)
{
	/* Save real source value, then compare EAX against destination. */
	ctxt->dst.orig_val = ctxt->dst.val;
	ctxt->dst.val = reg_read(ctxt, VCPU_REGS_RAX);
	ctxt->src.orig_val = ctxt->src.val;
	ctxt->src.val = ctxt->dst.orig_val;
	em_cmp(ctxt);

	if (ctxt->eflags & X86_EFLAGS_ZF) {
		/* Success: write back to memory; no update of EAX */
		ctxt->src.type = OP_NONE;
		ctxt->dst.val = ctxt->src.orig_val;
	} else {
		/* Failure: write the value we saw to EAX. */
		ctxt->src.type = OP_REG;
		ctxt->src.addr.reg = reg_rmw(ctxt, VCPU_REGS_RAX);
		ctxt->src.val = ctxt->dst.orig_val;
		/* Create write-cycle to dest by writing the same value */
		ctxt->dst.val = ctxt->dst.orig_val;
	}
	return X86EMUL_CONTINUE;
}

static int em_lseg(struct x86_emulate_ctxt *ctxt)
{
	int seg = ctxt->src2.val;
	unsigned short sel;
	int rc;

	memcpy(&sel, ctxt->src.valptr + ctxt->op_bytes, 2);

	rc = load_segment_descriptor(ctxt, sel, seg);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	ctxt->dst.val = ctxt->src.val;
	return rc;
}

static int em_rsm(struct x86_emulate_ctxt *ctxt)
{
	if (!ctxt->ops->is_smm(ctxt))
		return emulate_ud(ctxt);

	if (ctxt->ops->leave_smm(ctxt))
		ctxt->ops->triple_fault(ctxt);

	return emulator_recalc_and_set_mode(ctxt);
}

static void
setup_syscalls_segments(struct desc_struct *cs, struct desc_struct *ss)
{
	cs->l = 0;		/* will be adjusted later */
	set_desc_base(cs, 0);	/* flat segment */
	cs->g = 1;		/* 4kb granularity */
	set_desc_limit(cs, 0xfffff);	/* 4GB limit */
	cs->type = 0x0b;	/* Read, Execute, Accessed */
	cs->s = 1;
	cs->dpl = 0;		/* will be adjusted later */
	cs->p = 1;
	cs->d = 1;
	cs->avl = 0;

	set_desc_base(ss, 0);	/* flat segment */
	set_desc_limit(ss, 0xfffff);	/* 4GB limit */
	ss->g = 1;		/* 4kb granularity */
	ss->s = 1;
	ss->type = 0x03;	/* Read/Write, Accessed */
	ss->d = 1;		/* 32bit stack segment */
	ss->dpl = 0;
	ss->p = 1;
	ss->l = 0;
	ss->avl = 0;
}

static int em_syscall(struct x86_emulate_ctxt *ctxt)
{
	const struct x86_emulate_ops *ops = ctxt->ops;
	struct desc_struct cs, ss;
	u64 msr_data;
	u16 cs_sel, ss_sel;
	u64 efer = 0;

	/* syscall is not available in real mode */
	if (ctxt->mode == X86EMUL_MODE_REAL ||
	    ctxt->mode == X86EMUL_MODE_VM86)
		return emulate_ud(ctxt);

	/*
	 * Intel compatible CPUs only support SYSCALL in 64-bit mode, whereas
	 * AMD allows SYSCALL in any flavor of protected mode.  Note, it's
	 * infeasible to emulate Intel behavior when running on AMD hardware,
	 * as SYSCALL won't fault in the "wrong" mode, i.e. there is no #UD
	 * for KVM to trap-and-emulate, unlike emulating AMD on Intel.
	 */
	if (ctxt->mode != X86EMUL_MODE_PROT64 &&
	    ctxt->ops->guest_cpuid_is_intel_compatible(ctxt))
		return emulate_ud(ctxt);

	ops->get_msr(ctxt, MSR_EFER, &efer);
	if (!(efer & EFER_SCE))
		return emulate_ud(ctxt);

	setup_syscalls_segments(&cs, &ss);
	ops->get_msr(ctxt, MSR_STAR, &msr_data);
	msr_data >>= 32;
	cs_sel = (u16)(msr_data & 0xfffc);
	ss_sel = (u16)(msr_data + 8);

	if (efer & EFER_LMA) {
		cs.d = 0;
		cs.l = 1;
	}
	ops->set_segment(ctxt, cs_sel, &cs, 0, VCPU_SREG_CS);
	ops->set_segment(ctxt, ss_sel, &ss, 0, VCPU_SREG_SS);

	*reg_write(ctxt, VCPU_REGS_RCX) = ctxt->_eip;
	if (efer & EFER_LMA) {
#ifdef CONFIG_X86_64
		*reg_write(ctxt, VCPU_REGS_R11) = ctxt->eflags;

		ops->get_msr(ctxt,
			     ctxt->mode == X86EMUL_MODE_PROT64 ?
			     MSR_LSTAR : MSR_CSTAR, &msr_data);
		ctxt->_eip = msr_data;

		ops->get_msr(ctxt, MSR_SYSCALL_MASK, &msr_data);
		ctxt->eflags &= ~msr_data;
		ctxt->eflags |= X86_EFLAGS_FIXED;
#endif
	} else {
		/* legacy mode */
		ops->get_msr(ctxt, MSR_STAR, &msr_data);
		ctxt->_eip = (u32)msr_data;

		ctxt->eflags &= ~(X86_EFLAGS_VM | X86_EFLAGS_IF);
	}

	ctxt->tf = (ctxt->eflags & X86_EFLAGS_TF) != 0;
	return X86EMUL_CONTINUE;
}

static int em_sysenter(struct x86_emulate_ctxt *ctxt)
{
	const struct x86_emulate_ops *ops = ctxt->ops;
	struct desc_struct cs, ss;
	u64 msr_data;
	u16 cs_sel, ss_sel;
	u64 efer = 0;

	ops->get_msr(ctxt, MSR_EFER, &efer);
	/* inject #GP if in real mode */
	if (ctxt->mode == X86EMUL_MODE_REAL)
		return emulate_gp(ctxt, 0);

	/*
	 * Intel's architecture allows SYSENTER in compatibility mode, but AMD
	 * does not.  Note, AMD does allow SYSENTER in legacy protected mode.
	 */
	if ((ctxt->mode != X86EMUL_MODE_PROT64) && (efer & EFER_LMA) &&
	    !ctxt->ops->guest_cpuid_is_intel_compatible(ctxt))
		return emulate_ud(ctxt);

	/* sysenter/sysexit have not been tested in 64bit mode. */
	if (ctxt->mode == X86EMUL_MODE_PROT64)
		return X86EMUL_UNHANDLEABLE;

	ops->get_msr(ctxt, MSR_IA32_SYSENTER_CS, &msr_data);
	if ((msr_data & 0xfffc) == 0x0)
		return emulate_gp(ctxt, 0);

	setup_syscalls_segments(&cs, &ss);
	ctxt->eflags &= ~(X86_EFLAGS_VM | X86_EFLAGS_IF);
	cs_sel = (u16)msr_data & ~SEGMENT_RPL_MASK;
	ss_sel = cs_sel + 8;
	if (efer & EFER_LMA) {
		cs.d = 0;
		cs.l = 1;
	}

	ops->set_segment(ctxt, cs_sel, &cs, 0, VCPU_SREG_CS);
	ops->set_segment(ctxt, ss_sel, &ss, 0, VCPU_SREG_SS);

	ops->get_msr(ctxt, MSR_IA32_SYSENTER_EIP, &msr_data);
	ctxt->_eip = (efer & EFER_LMA) ? msr_data : (u32)msr_data;

	ops->get_msr(ctxt, MSR_IA32_SYSENTER_ESP, &msr_data);
	*reg_write(ctxt, VCPU_REGS_RSP) = (efer & EFER_LMA) ? msr_data :
							      (u32)msr_data;
	if (efer & EFER_LMA)
		ctxt->mode = X86EMUL_MODE_PROT64;

	return X86EMUL_CONTINUE;
}

static int em_sysexit(struct x86_emulate_ctxt *ctxt)
{
	const struct x86_emulate_ops *ops = ctxt->ops;
	struct desc_struct cs, ss;
	u64 msr_data, rcx, rdx;
	int usermode;
	u16 cs_sel = 0, ss_sel = 0;

	/* inject #GP if in real mode or Virtual 8086 mode */
	if (ctxt->mode == X86EMUL_MODE_REAL ||
	    ctxt->mode == X86EMUL_MODE_VM86)
		return emulate_gp(ctxt, 0);

	setup_syscalls_segments(&cs, &ss);

	if (ctxt->rex_bits & REX_W)
		usermode = X86EMUL_MODE_PROT64;
	else
		usermode = X86EMUL_MODE_PROT32;

	rcx = reg_read(ctxt, VCPU_REGS_RCX);
	rdx = reg_read(ctxt, VCPU_REGS_RDX);

	cs.dpl = 3;
	ss.dpl = 3;
	ops->get_msr(ctxt, MSR_IA32_SYSENTER_CS, &msr_data);
	switch (usermode) {
	case X86EMUL_MODE_PROT32:
		cs_sel = (u16)(msr_data + 16);
		if ((msr_data & 0xfffc) == 0x0)
			return emulate_gp(ctxt, 0);
		ss_sel = (u16)(msr_data + 24);
		rcx = (u32)rcx;
		rdx = (u32)rdx;
		break;
	case X86EMUL_MODE_PROT64:
		cs_sel = (u16)(msr_data + 32);
		if (msr_data == 0x0)
			return emulate_gp(ctxt, 0);
		ss_sel = cs_sel + 8;
		cs.d = 0;
		cs.l = 1;
		if (emul_is_noncanonical_address(rcx, ctxt, 0) ||
		    emul_is_noncanonical_address(rdx, ctxt, 0))
			return emulate_gp(ctxt, 0);
		break;
	}
	cs_sel |= SEGMENT_RPL_MASK;
	ss_sel |= SEGMENT_RPL_MASK;

	ops->set_segment(ctxt, cs_sel, &cs, 0, VCPU_SREG_CS);
	ops->set_segment(ctxt, ss_sel, &ss, 0, VCPU_SREG_SS);

	ctxt->_eip = rdx;
	ctxt->mode = usermode;
	*reg_write(ctxt, VCPU_REGS_RSP) = rcx;

	return X86EMUL_CONTINUE;
}

static bool emulator_bad_iopl(struct x86_emulate_ctxt *ctxt)
{
	int iopl;
	if (ctxt->mode == X86EMUL_MODE_REAL)
		return false;
	if (ctxt->mode == X86EMUL_MODE_VM86)
		return true;
	iopl = (ctxt->eflags & X86_EFLAGS_IOPL) >> X86_EFLAGS_IOPL_BIT;
	return ctxt->ops->cpl(ctxt) > iopl;
}

#define VMWARE_PORT_VMPORT	(0x5658)
#define VMWARE_PORT_VMRPC	(0x5659)

static bool emulator_io_port_access_allowed(struct x86_emulate_ctxt *ctxt,
					    u16 port, u16 len)
{
	const struct x86_emulate_ops *ops = ctxt->ops;
	struct desc_struct tr_seg;
	u32 base3;
	int r;
	u16 tr, io_bitmap_ptr, perm, bit_idx = port & 0x7;
	unsigned mask = (1 << len) - 1;
	unsigned long base;

	/*
	 * VMware allows access to these ports even if denied
	 * by TSS I/O permission bitmap. Mimic behavior.
	 */
	if (enable_vmware_backdoor &&
	    ((port == VMWARE_PORT_VMPORT) || (port == VMWARE_PORT_VMRPC)))
		return true;

	ops->get_segment(ctxt, &tr, &tr_seg, &base3, VCPU_SREG_TR);
	if (!tr_seg.p)
		return false;
	if (desc_limit_scaled(&tr_seg) < 103)
		return false;
	base = get_desc_base(&tr_seg);
#ifdef CONFIG_X86_64
	base |= ((u64)base3) << 32;
#endif
	r = ops->read_std(ctxt, base + 102, &io_bitmap_ptr, 2, NULL, true);
	if (r != X86EMUL_CONTINUE)
		return false;
	if (io_bitmap_ptr + port/8 > desc_limit_scaled(&tr_seg))
		return false;
	r = ops->read_std(ctxt, base + io_bitmap_ptr + port/8, &perm, 2, NULL, true);
	if (r != X86EMUL_CONTINUE)
		return false;
	if ((perm >> bit_idx) & mask)
		return false;
	return true;
}

static bool emulator_io_permitted(struct x86_emulate_ctxt *ctxt,
				  u16 port, u16 len)
{
	if (ctxt->perm_ok)
		return true;

	if (emulator_bad_iopl(ctxt))
		if (!emulator_io_port_access_allowed(ctxt, port, len))
			return false;

	ctxt->perm_ok = true;

	return true;
}

static void string_registers_quirk(struct x86_emulate_ctxt *ctxt)
{
	/*
	 * Intel CPUs mask the counter and pointers in quite strange
	 * manner when ECX is zero due to REP-string optimizations.
	 */
#ifdef CONFIG_X86_64
	u32 eax, ebx, ecx, edx;

	if (ctxt->ad_bytes != 4)
		return;

	eax = ecx = 0;
	ctxt->ops->get_cpuid(ctxt, &eax, &ebx, &ecx, &edx, true);
	if (!is_guest_vendor_intel(ebx, ecx, edx))
		return;

	*reg_write(ctxt, VCPU_REGS_RCX) = 0;

	switch (ctxt->b) {
	case 0xa4:	/* movsb */
	case 0xa5:	/* movsd/w */
		*reg_rmw(ctxt, VCPU_REGS_RSI) &= (u32)-1;
		fallthrough;
	case 0xaa:	/* stosb */
	case 0xab:	/* stosd/w */
		*reg_rmw(ctxt, VCPU_REGS_RDI) &= (u32)-1;
	}
#endif
}

static void save_state_to_tss16(struct x86_emulate_ctxt *ctxt,
				struct tss_segment_16 *tss)
{
	tss->ip = ctxt->_eip;
	tss->flag = ctxt->eflags;
	tss->ax = reg_read(ctxt, VCPU_REGS_RAX);
	tss->cx = reg_read(ctxt, VCPU_REGS_RCX);
	tss->dx = reg_read(ctxt, VCPU_REGS_RDX);
	tss->bx = reg_read(ctxt, VCPU_REGS_RBX);
	tss->sp = reg_read(ctxt, VCPU_REGS_RSP);
	tss->bp = reg_read(ctxt, VCPU_REGS_RBP);
	tss->si = reg_read(ctxt, VCPU_REGS_RSI);
	tss->di = reg_read(ctxt, VCPU_REGS_RDI);

	tss->es = get_segment_selector(ctxt, VCPU_SREG_ES);
	tss->cs = get_segment_selector(ctxt, VCPU_SREG_CS);
	tss->ss = get_segment_selector(ctxt, VCPU_SREG_SS);
	tss->ds = get_segment_selector(ctxt, VCPU_SREG_DS);
	tss->ldt = get_segment_selector(ctxt, VCPU_SREG_LDTR);
}

static int load_state_from_tss16(struct x86_emulate_ctxt *ctxt,
				 struct tss_segment_16 *tss)
{
	int ret;
	u8 cpl;

	ctxt->_eip = tss->ip;
	ctxt->eflags = tss->flag | 2;
	*reg_write(ctxt, VCPU_REGS_RAX) = tss->ax;
	*reg_write(ctxt, VCPU_REGS_RCX) = tss->cx;
	*reg_write(ctxt, VCPU_REGS_RDX) = tss->dx;
	*reg_write(ctxt, VCPU_REGS_RBX) = tss->bx;
	*reg_write(ctxt, VCPU_REGS_RSP) = tss->sp;
	*reg_write(ctxt, VCPU_REGS_RBP) = tss->bp;
	*reg_write(ctxt, VCPU_REGS_RSI) = tss->si;
	*reg_write(ctxt, VCPU_REGS_RDI) = tss->di;

	/*
	 * SDM says that segment selectors are loaded before segment
	 * descriptors
	 */
	set_segment_selector(ctxt, tss->ldt, VCPU_SREG_LDTR);
	set_segment_selector(ctxt, tss->es, VCPU_SREG_ES);
	set_segment_selector(ctxt, tss->cs, VCPU_SREG_CS);
	set_segment_selector(ctxt, tss->ss, VCPU_SREG_SS);
	set_segment_selector(ctxt, tss->ds, VCPU_SREG_DS);

	cpl = tss->cs & 3;

	/*
	 * Now load segment descriptors. If fault happens at this stage
	 * it is handled in a context of new task
	 */
	ret = __load_segment_descriptor(ctxt, tss->ldt, VCPU_SREG_LDTR, cpl,
					X86_TRANSFER_TASK_SWITCH, NULL);
	if (ret != X86EMUL_CONTINUE)
		return ret;
	ret = __load_segment_descriptor(ctxt, tss->es, VCPU_SREG_ES, cpl,
					X86_TRANSFER_TASK_SWITCH, NULL);
	if (ret != X86EMUL_CONTINUE)
		return ret;
	ret = __load_segment_descriptor(ctxt, tss->cs, VCPU_SREG_CS, cpl,
					X86_TRANSFER_TASK_SWITCH, NULL);
	if (ret != X86EMUL_CONTINUE)
		return ret;
	ret = __load_segment_descriptor(ctxt, tss->ss, VCPU_SREG_SS, cpl,
					X86_TRANSFER_TASK_SWITCH, NULL);
	if (ret != X86EMUL_CONTINUE)
		return ret;
	ret = __load_segment_descriptor(ctxt, tss->ds, VCPU_SREG_DS, cpl,
					X86_TRANSFER_TASK_SWITCH, NULL);
	if (ret != X86EMUL_CONTINUE)
		return ret;

	return X86EMUL_CONTINUE;
}

static int task_switch_16(struct x86_emulate_ctxt *ctxt, u16 old_tss_sel,
			  ulong old_tss_base, struct desc_struct *new_desc)
{
	struct tss_segment_16 tss_seg;
	int ret;
	u32 new_tss_base = get_desc_base(new_desc);

	ret = linear_read_system(ctxt, old_tss_base, &tss_seg, sizeof(tss_seg));
	if (ret != X86EMUL_CONTINUE)
		return ret;

	save_state_to_tss16(ctxt, &tss_seg);

	ret = linear_write_system(ctxt, old_tss_base, &tss_seg, sizeof(tss_seg));
	if (ret != X86EMUL_CONTINUE)
		return ret;

	ret = linear_read_system(ctxt, new_tss_base, &tss_seg, sizeof(tss_seg));
	if (ret != X86EMUL_CONTINUE)
		return ret;

	if (old_tss_sel != 0xffff) {
		tss_seg.prev_task_link = old_tss_sel;

		ret = linear_write_system(ctxt, new_tss_base,
					  &tss_seg.prev_task_link,
					  sizeof(tss_seg.prev_task_link));
		if (ret != X86EMUL_CONTINUE)
			return ret;
	}

	return load_state_from_tss16(ctxt, &tss_seg);
}

static void save_state_to_tss32(struct x86_emulate_ctxt *ctxt,
				struct tss_segment_32 *tss)
{
	/* CR3 and ldt selector are not saved intentionally */
	tss->eip = ctxt->_eip;
	tss->eflags = ctxt->eflags;
	tss->eax = reg_read(ctxt, VCPU_REGS_RAX);
	tss->ecx = reg_read(ctxt, VCPU_REGS_RCX);
	tss->edx = reg_read(ctxt, VCPU_REGS_RDX);
	tss->ebx = reg_read(ctxt, VCPU_REGS_RBX);
	tss->esp = reg_read(ctxt, VCPU_REGS_RSP);
	tss->ebp = reg_read(ctxt, VCPU_REGS_RBP);
	tss->esi = reg_read(ctxt, VCPU_REGS_RSI);
	tss->edi = reg_read(ctxt, VCPU_REGS_RDI);

	tss->es = get_segment_selector(ctxt, VCPU_SREG_ES);
	tss->cs = get_segment_selector(ctxt, VCPU_SREG_CS);
	tss->ss = get_segment_selector(ctxt, VCPU_SREG_SS);
	tss->ds = get_segment_selector(ctxt, VCPU_SREG_DS);
	tss->fs = get_segment_selector(ctxt, VCPU_SREG_FS);
	tss->gs = get_segment_selector(ctxt, VCPU_SREG_GS);
}

static int load_state_from_tss32(struct x86_emulate_ctxt *ctxt,
				 struct tss_segment_32 *tss)
{
	int ret;
	u8 cpl;

	if (ctxt->ops->set_cr(ctxt, 3, tss->cr3))
		return emulate_gp(ctxt, 0);
	ctxt->_eip = tss->eip;
	ctxt->eflags = tss->eflags | 2;

	/* General purpose registers */
	*reg_write(ctxt, VCPU_REGS_RAX) = tss->eax;
	*reg_write(ctxt, VCPU_REGS_RCX) = tss->ecx;
	*reg_write(ctxt, VCPU_REGS_RDX) = tss->edx;
	*reg_write(ctxt, VCPU_REGS_RBX) = tss->ebx;
	*reg_write(ctxt, VCPU_REGS_RSP) = tss->esp;
	*reg_write(ctxt, VCPU_REGS_RBP) = tss->ebp;
	*reg_write(ctxt, VCPU_REGS_RSI) = tss->esi;
	*reg_write(ctxt, VCPU_REGS_RDI) = tss->edi;

	/*
	 * SDM says that segment selectors are loaded before segment
	 * descriptors.  This is important because CPL checks will
	 * use CS.RPL.
	 */
	set_segment_selector(ctxt, tss->ldt_selector, VCPU_SREG_LDTR);
	set_segment_selector(ctxt, tss->es, VCPU_SREG_ES);
	set_segment_selector(ctxt, tss->cs, VCPU_SREG_CS);
	set_segment_selector(ctxt, tss->ss, VCPU_SREG_SS);
	set_segment_selector(ctxt, tss->ds, VCPU_SREG_DS);
	set_segment_selector(ctxt, tss->fs, VCPU_SREG_FS);
	set_segment_selector(ctxt, tss->gs, VCPU_SREG_GS);

	/*
	 * If we're switching between Protected Mode and VM86, we need to make
	 * sure to update the mode before loading the segment descriptors so
	 * that the selectors are interpreted correctly.
	 */
	if (ctxt->eflags & X86_EFLAGS_VM) {
		ctxt->mode = X86EMUL_MODE_VM86;
		cpl = 3;
	} else {
		ctxt->mode = X86EMUL_MODE_PROT32;
		cpl = tss->cs & 3;
	}

	/*
	 * Now load segment descriptors. If fault happens at this stage
	 * it is handled in a context of new task
	 */
	ret = __load_segment_descriptor(ctxt, tss->ldt_selector, VCPU_SREG_LDTR,
					cpl, X86_TRANSFER_TASK_SWITCH, NULL);
	if (ret != X86EMUL_CONTINUE)
		return ret;
	ret = __load_segment_descriptor(ctxt, tss->es, VCPU_SREG_ES, cpl,
					X86_TRANSFER_TASK_SWITCH, NULL);
	if (ret != X86EMUL_CONTINUE)
		return ret;
	ret = __load_segment_descriptor(ctxt, tss->cs, VCPU_SREG_CS, cpl,
					X86_TRANSFER_TASK_SWITCH, NULL);
	if (ret != X86EMUL_CONTINUE)
		return ret;
	ret = __load_segment_descriptor(ctxt, tss->ss, VCPU_SREG_SS, cpl,
					X86_TRANSFER_TASK_SWITCH, NULL);
	if (ret != X86EMUL_CONTINUE)
		return ret;
	ret = __load_segment_descriptor(ctxt, tss->ds, VCPU_SREG_DS, cpl,
					X86_TRANSFER_TASK_SWITCH, NULL);
	if (ret != X86EMUL_CONTINUE)
		return ret;
	ret = __load_segment_descriptor(ctxt, tss->fs, VCPU_SREG_FS, cpl,
					X86_TRANSFER_TASK_SWITCH, NULL);
	if (ret != X86EMUL_CONTINUE)
		return ret;
	ret = __load_segment_descriptor(ctxt, tss->gs, VCPU_SREG_GS, cpl,
					X86_TRANSFER_TASK_SWITCH, NULL);

	return ret;
}

static int task_switch_32(struct x86_emulate_ctxt *ctxt, u16 old_tss_sel,
			  ulong old_tss_base, struct desc_struct *new_desc)
{
	struct tss_segment_32 tss_seg;
	int ret;
	u32 new_tss_base = get_desc_base(new_desc);
	u32 eip_offset = offsetof(struct tss_segment_32, eip);
	u32 ldt_sel_offset = offsetof(struct tss_segment_32, ldt_selector);

	ret = linear_read_system(ctxt, old_tss_base, &tss_seg, sizeof(tss_seg));
	if (ret != X86EMUL_CONTINUE)
		return ret;

	save_state_to_tss32(ctxt, &tss_seg);

	/* Only GP registers and segment selectors are saved */
	ret = linear_write_system(ctxt, old_tss_base + eip_offset, &tss_seg.eip,
				  ldt_sel_offset - eip_offset);
	if (ret != X86EMUL_CONTINUE)
		return ret;

	ret = linear_read_system(ctxt, new_tss_base, &tss_seg, sizeof(tss_seg));
	if (ret != X86EMUL_CONTINUE)
		return ret;

	if (old_tss_sel != 0xffff) {
		tss_seg.prev_task_link = old_tss_sel;

		ret = linear_write_system(ctxt, new_tss_base,
					  &tss_seg.prev_task_link,
					  sizeof(tss_seg.prev_task_link));
		if (ret != X86EMUL_CONTINUE)
			return ret;
	}

	return load_state_from_tss32(ctxt, &tss_seg);
}

static int emulator_do_task_switch(struct x86_emulate_ctxt *ctxt,
				   u16 tss_selector, int idt_index, int reason,
				   bool has_error_code, u32 error_code)
{
	const struct x86_emulate_ops *ops = ctxt->ops;
	struct desc_struct curr_tss_desc, next_tss_desc;
	int ret;
	u16 old_tss_sel = get_segment_selector(ctxt, VCPU_SREG_TR);
	ulong old_tss_base =
		ops->get_cached_segment_base(ctxt, VCPU_SREG_TR);
	u32 desc_limit;
	ulong desc_addr, dr7;

	/* FIXME: old_tss_base == ~0 ? */

	ret = read_segment_descriptor(ctxt, tss_selector, &next_tss_desc, &desc_addr);
	if (ret != X86EMUL_CONTINUE)
		return ret;
	ret = read_segment_descriptor(ctxt, old_tss_sel, &curr_tss_desc, &desc_addr);
	if (ret != X86EMUL_CONTINUE)
		return ret;

	/* FIXME: check that next_tss_desc is tss */

	/*
	 * Check privileges. The three cases are task switch caused by...
	 *
	 * 1. jmp/call/int to task gate: Check against DPL of the task gate
	 * 2. Exception/IRQ/iret: No check is performed
	 * 3. jmp/call to TSS/task-gate: No check is performed since the
	 *    hardware checks it before exiting.
	 */
	if (reason == TASK_SWITCH_GATE) {
		if (idt_index != -1) {
			/* Software interrupts */
			struct desc_struct task_gate_desc;
			int dpl;

			ret = read_interrupt_descriptor(ctxt, idt_index,
							&task_gate_desc);
			if (ret != X86EMUL_CONTINUE)
				return ret;

			dpl = task_gate_desc.dpl;
			if ((tss_selector & 3) > dpl || ops->cpl(ctxt) > dpl)
				return emulate_gp(ctxt, (idt_index << 3) | 0x2);
		}
	}

	desc_limit = desc_limit_scaled(&next_tss_desc);
	if (!next_tss_desc.p ||
	    ((desc_limit < 0x67 && (next_tss_desc.type & 8)) ||
	     desc_limit < 0x2b)) {
		return emulate_ts(ctxt, tss_selector & 0xfffc);
	}

	if (reason == TASK_SWITCH_IRET || reason == TASK_SWITCH_JMP) {
		curr_tss_desc.type &= ~(1 << 1); /* clear busy flag */
		write_segment_descriptor(ctxt, old_tss_sel, &curr_tss_desc);
	}

	if (reason == TASK_SWITCH_IRET)
		ctxt->eflags = ctxt->eflags & ~X86_EFLAGS_NT;

	/* set back link to prev task only if NT bit is set in eflags
	   note that old_tss_sel is not used after this point */
	if (reason != TASK_SWITCH_CALL && reason != TASK_SWITCH_GATE)
		old_tss_sel = 0xffff;

	if (next_tss_desc.type & 8)
		ret = task_switch_32(ctxt, old_tss_sel, old_tss_base, &next_tss_desc);
	else
		ret = task_switch_16(ctxt, old_tss_sel,
				     old_tss_base, &next_tss_desc);
	if (ret != X86EMUL_CONTINUE)
		return ret;

	if (reason == TASK_SWITCH_CALL || reason == TASK_SWITCH_GATE)
		ctxt->eflags = ctxt->eflags | X86_EFLAGS_NT;

	if (reason != TASK_SWITCH_IRET) {
		next_tss_desc.type |= (1 << 1); /* set busy flag */
		write_segment_descriptor(ctxt, tss_selector, &next_tss_desc);
	}

	ops->set_cr(ctxt, 0,  ops->get_cr(ctxt, 0) | X86_CR0_TS);
	ops->set_segment(ctxt, tss_selector, &next_tss_desc, 0, VCPU_SREG_TR);

	if (has_error_code) {
		ctxt->op_bytes = ctxt->ad_bytes = (next_tss_desc.type & 8) ? 4 : 2;
		ctxt->lock_prefix = 0;
		ctxt->src.val = (unsigned long) error_code;
		ret = em_push(ctxt);
	}

	dr7 = ops->get_dr(ctxt, 7);
	ops->set_dr(ctxt, 7, dr7 & ~(DR_LOCAL_ENABLE_MASK | DR_LOCAL_SLOWDOWN));

	return ret;
}

int emulator_task_switch(struct x86_emulate_ctxt *ctxt,
			 u16 tss_selector, int idt_index, int reason,
			 bool has_error_code, u32 error_code)
{
	int rc;

	invalidate_registers(ctxt);
	ctxt->_eip = ctxt->eip;
	ctxt->dst.type = OP_NONE;

	rc = emulator_do_task_switch(ctxt, tss_selector, idt_index, reason,
				     has_error_code, error_code);

	if (rc == X86EMUL_CONTINUE) {
		ctxt->eip = ctxt->_eip;
		writeback_registers(ctxt);
	}

	return (rc == X86EMUL_UNHANDLEABLE) ? EMULATION_FAILED : EMULATION_OK;
}

static void string_addr_inc(struct x86_emulate_ctxt *ctxt, int reg,
		struct operand *op)
{
	int df = (ctxt->eflags & X86_EFLAGS_DF) ? -op->count : op->count;

	register_address_increment(ctxt, reg, df * op->bytes);
	op->addr.mem.ea = register_address(ctxt, reg);
}

static int em_das(struct x86_emulate_ctxt *ctxt)
{
	u8 al, old_al;
	bool af, cf, old_cf;

	cf = ctxt->eflags & X86_EFLAGS_CF;
	al = ctxt->dst.val;

	old_al = al;
	old_cf = cf;
	cf = false;
	af = ctxt->eflags & X86_EFLAGS_AF;
	if ((al & 0x0f) > 9 || af) {
		al -= 6;
		cf = old_cf | (al >= 250);
		af = true;
	} else {
		af = false;
	}
	if (old_al > 0x99 || old_cf) {
		al -= 0x60;
		cf = true;
	}

	ctxt->dst.val = al;
	/* Set PF, ZF, SF */
	ctxt->src.type = OP_IMM;
	ctxt->src.val = 0;
	ctxt->src.bytes = 1;
	em_or(ctxt);
	ctxt->eflags &= ~(X86_EFLAGS_AF | X86_EFLAGS_CF);
	if (cf)
		ctxt->eflags |= X86_EFLAGS_CF;
	if (af)
		ctxt->eflags |= X86_EFLAGS_AF;
	return X86EMUL_CONTINUE;
}

static int em_aam(struct x86_emulate_ctxt *ctxt)
{
	u8 al, ah;

	if (ctxt->src.val == 0)
		return emulate_de(ctxt);

	al = ctxt->dst.val & 0xff;
	ah = al / ctxt->src.val;
	al %= ctxt->src.val;

	ctxt->dst.val = (ctxt->dst.val & 0xffff0000) | al | (ah << 8);

	/* Set PF, ZF, SF */
	ctxt->src.type = OP_IMM;
	ctxt->src.val = 0;
	ctxt->src.bytes = 1;
	em_or(ctxt);

	return X86EMUL_CONTINUE;
}

static int em_aad(struct x86_emulate_ctxt *ctxt)
{
	u8 al = ctxt->dst.val & 0xff;
	u8 ah = (ctxt->dst.val >> 8) & 0xff;

	al = (al + (ah * ctxt->src.val)) & 0xff;

	ctxt->dst.val = (ctxt->dst.val & 0xffff0000) | al;

	/* Set PF, ZF, SF */
	ctxt->src.type = OP_IMM;
	ctxt->src.val = 0;
	ctxt->src.bytes = 1;
	em_or(ctxt);

	return X86EMUL_CONTINUE;
}

static int em_call(struct x86_emulate_ctxt *ctxt)
{
	int rc;
	long rel = ctxt->src.val;

	ctxt->src.val = (unsigned long)ctxt->_eip;
	rc = jmp_rel(ctxt, rel);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	return em_push(ctxt);
}

static int em_call_far(struct x86_emulate_ctxt *ctxt)
{
	u16 sel, old_cs;
	ulong old_eip;
	int rc;
	struct desc_struct old_desc, new_desc;
	const struct x86_emulate_ops *ops = ctxt->ops;
	int cpl = ctxt->ops->cpl(ctxt);
	enum x86emul_mode prev_mode = ctxt->mode;

	old_eip = ctxt->_eip;
	ops->get_segment(ctxt, &old_cs, &old_desc, NULL, VCPU_SREG_CS);

	memcpy(&sel, ctxt->src.valptr + ctxt->op_bytes, 2);
	rc = __load_segment_descriptor(ctxt, sel, VCPU_SREG_CS, cpl,
				       X86_TRANSFER_CALL_JMP, &new_desc);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	rc = assign_eip_far(ctxt, ctxt->src.val);
	if (rc != X86EMUL_CONTINUE)
		goto fail;

	ctxt->src.val = old_cs;
	rc = em_push(ctxt);
	if (rc != X86EMUL_CONTINUE)
		goto fail;

	ctxt->src.val = old_eip;
	rc = em_push(ctxt);
	/* If we failed, we tainted the memory, but the very least we should
	   restore cs */
	if (rc != X86EMUL_CONTINUE) {
		pr_warn_once("faulting far call emulation tainted memory\n");
		goto fail;
	}
	return rc;
fail:
	ops->set_segment(ctxt, old_cs, &old_desc, 0, VCPU_SREG_CS);
	ctxt->mode = prev_mode;
	return rc;

}

static int em_ret_near_imm(struct x86_emulate_ctxt *ctxt)
{
	int rc;
	unsigned long eip = 0;

	rc = emulate_pop(ctxt, &eip, ctxt->op_bytes);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	rc = assign_eip_near(ctxt, eip);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	rsp_increment(ctxt, ctxt->src.val);
	return X86EMUL_CONTINUE;
}

static int em_xchg(struct x86_emulate_ctxt *ctxt)
{
	/* Write back the register source. */
	ctxt->src.val = ctxt->dst.val;
	write_register_operand(&ctxt->src);

	/* Write back the memory destination with implicit LOCK prefix. */
	ctxt->dst.val = ctxt->src.orig_val;
	ctxt->lock_prefix = 1;
	return X86EMUL_CONTINUE;
}

static int em_imul_3op(struct x86_emulate_ctxt *ctxt)
{
	ctxt->dst.val = ctxt->src2.val;
	return em_imul(ctxt);
}

static int em_cwd(struct x86_emulate_ctxt *ctxt)
{
	ctxt->dst.type = OP_REG;
	ctxt->dst.bytes = ctxt->src.bytes;
	ctxt->dst.addr.reg = reg_rmw(ctxt, VCPU_REGS_RDX);
	ctxt->dst.val = ~((ctxt->src.val >> (ctxt->src.bytes * 8 - 1)) - 1);

	return X86EMUL_CONTINUE;
}

static int em_rdpid(struct x86_emulate_ctxt *ctxt)
{
	u64 tsc_aux = 0;

	if (!ctxt->ops->guest_has_rdpid(ctxt))
		return emulate_ud(ctxt);

	ctxt->ops->get_msr(ctxt, MSR_TSC_AUX, &tsc_aux);
	ctxt->dst.val = tsc_aux;
	return X86EMUL_CONTINUE;
}

static int em_rdtsc(struct x86_emulate_ctxt *ctxt)
{
	u64 tsc = 0;

	ctxt->ops->get_msr(ctxt, MSR_IA32_TSC, &tsc);
	*reg_write(ctxt, VCPU_REGS_RAX) = (u32)tsc;
	*reg_write(ctxt, VCPU_REGS_RDX) = tsc >> 32;
	return X86EMUL_CONTINUE;
}

static int em_rdpmc(struct x86_emulate_ctxt *ctxt)
{
	u64 pmc;

	if (ctxt->ops->read_pmc(ctxt, reg_read(ctxt, VCPU_REGS_RCX), &pmc))
		return emulate_gp(ctxt, 0);
	*reg_write(ctxt, VCPU_REGS_RAX) = (u32)pmc;
	*reg_write(ctxt, VCPU_REGS_RDX) = pmc >> 32;
	return X86EMUL_CONTINUE;
}

static int em_mov(struct x86_emulate_ctxt *ctxt)
{
	memcpy(ctxt->dst.valptr, ctxt->src.valptr, sizeof(ctxt->src.valptr));
	return X86EMUL_CONTINUE;
}

static void write_xmm_reg(struct x86_emulate_ctxt *ctxt, unsigned int reg,
			  const sse128_t *vec)
{
	if (ctxt->d & Avx) {
		avx256_t ymm = {};

		memcpy(&ymm, vec, sizeof(*vec));
		kvm_write_avx_reg(reg, &ymm);
		return;
	}

	kvm_write_sse_reg(reg, vec);
}

static unsigned int scalar_gpr_bytes(struct x86_emulate_ctxt *ctxt)
{
	return (ctxt->rex_bits & REX_W) ? 8 : 4;
}

static int read_modrm_mem(struct x86_emulate_ctxt *ctxt, void *buf,
			  unsigned int bytes)
{
	return segmented_read(ctxt, ctxt->memop.addr.mem, buf, bytes);
}

static int write_modrm_mem(struct x86_emulate_ctxt *ctxt, const void *buf,
			   unsigned int bytes)
{
	return segmented_write(ctxt, ctxt->memop.addr.mem, buf, bytes);
}

static int read_modrm_int_operand(struct x86_emulate_ctxt *ctxt, u64 *val,
				  unsigned int bytes)
{
	if (ctxt->modrm_mod == 3) {
		*val = reg_read(ctxt, ctxt->modrm_rm);
		if (bytes == 4)
			*val &= GENMASK_ULL(31, 0);
		return X86EMUL_CONTINUE;
	}

	*val = 0;
	return read_modrm_mem(ctxt, val, bytes);
}

/*
 * MOVSS/VMOVSS xmm, xmm/m32
 * Legacy reg-reg preserves destination upper bits, legacy memory loads zero
 * them, and VEX copies bits[127:32] from VEX.vvvv and clears upper YMM state.
 */
static int em_movss_load(struct x86_emulate_ctxt *ctxt)
{
	__sse128_u dst = {};
	sse128_t reg;
	u32 val;
	int rc;

	if (ctxt->d & Avx)
		kvm_read_sse_reg(ctxt->vex_reg, &dst.vec);
	else if (ctxt->modrm_mod == 3)
		kvm_read_sse_reg(ctxt->modrm_reg, &dst.vec);

	if (ctxt->modrm_mod == 3) {
		kvm_read_sse_reg(ctxt->modrm_rm, &reg);
		val = sse128_l0(reg);
	} else {
		rc = read_modrm_mem(ctxt, &val, sizeof(val));
		if (rc != X86EMUL_CONTINUE)
			return rc;
	}

	dst.as_u32[0] = val;
	write_xmm_reg(ctxt, ctxt->modrm_reg, &dst.vec);
	ctxt->dst.type = OP_NONE;
	return X86EMUL_CONTINUE;
}

/*
 * MOVSD/VMOVSD xmm, xmm/m64
 * Legacy reg-reg preserves destination upper qword, legacy memory loads zero
 * it, and VEX copies bits[127:64] from VEX.vvvv and clears upper YMM state.
 */
static int em_movsd_load(struct x86_emulate_ctxt *ctxt)
{
	__sse128_u dst = {};
	sse128_t reg;
	u64 val;
	int rc;

	if (ctxt->d & Avx)
		kvm_read_sse_reg(ctxt->vex_reg, &dst.vec);
	else if (ctxt->modrm_mod == 3)
		kvm_read_sse_reg(ctxt->modrm_reg, &dst.vec);

	if (ctxt->modrm_mod == 3) {
		kvm_read_sse_reg(ctxt->modrm_rm, &reg);
		val = sse128_lo(reg);
	} else {
		rc = read_modrm_mem(ctxt, &val, sizeof(val));
		if (rc != X86EMUL_CONTINUE)
			return rc;
	}

	dst.as_u64[0] = val;
	write_xmm_reg(ctxt, ctxt->modrm_reg, &dst.vec);
	ctxt->dst.type = OP_NONE;
	return X86EMUL_CONTINUE;
}

/*
 * MOVSS/VMOVSS m32/xmm, xmm
 * Legacy stores to memory or preserves the upper bits of the register
 * destination; VEX register form merges with VEX.vvvv and memory form
 * requires reserved VEX.vvvv=1111b.
 */
static int em_movss_store(struct x86_emulate_ctxt *ctxt)
{
	__sse128_u dst;
	sse128_t src;

	kvm_read_sse_reg(ctxt->modrm_reg, &src);

	if (ctxt->modrm_mod != 3) {
		if ((ctxt->d & Avx) && ctxt->vex_reg)
			return emulate_ud(ctxt);
		*(u32 *)ctxt->dst.valptr = sse128_l0(src);
		return write_modrm_mem(ctxt, ctxt->dst.valptr, sizeof(u32));
	}

	if (ctxt->d & Avx)
		kvm_read_sse_reg(ctxt->vex_reg, &dst.vec);
	else
		kvm_read_sse_reg(ctxt->modrm_rm, &dst.vec);

	dst.as_u32[0] = sse128_l0(src);
	write_xmm_reg(ctxt, ctxt->modrm_rm, &dst.vec);
	ctxt->dst.type = OP_NONE;
	return X86EMUL_CONTINUE;
}

/*
 * MOVSD/VMOVSD m64/xmm, xmm
 * Legacy stores to memory or preserves the upper qword of the register
 * destination; VEX register form merges with VEX.vvvv and memory form
 * requires reserved VEX.vvvv=1111b.
 */
static int em_movsd_store(struct x86_emulate_ctxt *ctxt)
{
	__sse128_u dst;
	sse128_t src;

	kvm_read_sse_reg(ctxt->modrm_reg, &src);

	if (ctxt->modrm_mod != 3) {
		if ((ctxt->d & Avx) && ctxt->vex_reg)
			return emulate_ud(ctxt);
		*(u64 *)ctxt->dst.valptr = sse128_lo(src);
		return write_modrm_mem(ctxt, ctxt->dst.valptr, sizeof(u64));
	}

	if (ctxt->d & Avx)
		kvm_read_sse_reg(ctxt->vex_reg, &dst.vec);
	else
		kvm_read_sse_reg(ctxt->modrm_rm, &dst.vec);

	dst.as_u64[0] = sse128_lo(src);
	write_xmm_reg(ctxt, ctxt->modrm_rm, &dst.vec);
	ctxt->dst.type = OP_NONE;
	return X86EMUL_CONTINUE;
}

/*
 * MOVLPS/MOVLPD/VMOVLPS/VMOVLPD and MOVHLPS/VMOVHLPS
 */
static int em_movlps(struct x86_emulate_ctxt *ctxt)
{
	__sse128_u dst;
	sse128_t src2;
	u64 val;
	int rc;

	if (ctxt->modrm_mod == 3) {
		if (ctxt->op_prefix)
			return emulate_ud(ctxt);

		if (ctxt->d & Avx)
			kvm_read_sse_reg(ctxt->vex_reg, &dst.vec);
		else
			kvm_read_sse_reg(ctxt->modrm_reg, &dst.vec);

		kvm_read_sse_reg(ctxt->modrm_rm, &src2);
		dst.as_u64[0] = sse128_hi(src2);
	} else {
		rc = read_modrm_mem(ctxt, &val, sizeof(val));
		if (rc != X86EMUL_CONTINUE)
			return rc;

		if (ctxt->d & Avx)
			kvm_read_sse_reg(ctxt->vex_reg, &dst.vec);
		else
			kvm_read_sse_reg(ctxt->modrm_reg, &dst.vec);

		dst.as_u64[0] = val;
	}

	write_xmm_reg(ctxt, ctxt->modrm_reg, &dst.vec);
	ctxt->dst.type = OP_NONE;
	return X86EMUL_CONTINUE;
}

/*
 * MOVLPS/MOVLPD/VMOVLPS/VMOVLPD store to memory.
 */
static int em_movlps_store(struct x86_emulate_ctxt *ctxt)
{
	sse128_t src;

	if (ctxt->modrm_mod == 3)
		return emulate_ud(ctxt);
	if ((ctxt->d & Avx) && ctxt->vex_reg)
		return emulate_ud(ctxt);

	kvm_read_sse_reg(ctxt->modrm_reg, &src);
	/* Store in persistent ctxt buffer for cross-page MMIO fragment safety */
	*(u64 *)ctxt->dst.valptr = sse128_lo(src);
	return write_modrm_mem(ctxt, ctxt->dst.valptr, sizeof(u64));
}

/*
 * MOVHPS/MOVHPD/VMOVHPS/VMOVHPD and MOVLHPS/VMOVLHPS
 */
static int em_movhps_load(struct x86_emulate_ctxt *ctxt)
{
	__sse128_u dst;
	sse128_t src2;
	u64 val;
	int rc;

	if (ctxt->modrm_mod == 3) {
		if (ctxt->op_prefix)
			return emulate_ud(ctxt);

		if (ctxt->d & Avx)
			kvm_read_sse_reg(ctxt->vex_reg, &dst.vec);
		else
			kvm_read_sse_reg(ctxt->modrm_reg, &dst.vec);

		kvm_read_sse_reg(ctxt->modrm_rm, &src2);
		dst.as_u64[1] = sse128_lo(src2);
	} else {
		rc = read_modrm_mem(ctxt, &val, sizeof(val));
		if (rc != X86EMUL_CONTINUE)
			return rc;

		if (ctxt->d & Avx)
			kvm_read_sse_reg(ctxt->vex_reg, &dst.vec);
		else
			kvm_read_sse_reg(ctxt->modrm_reg, &dst.vec);

		dst.as_u64[1] = val;
	}

	write_xmm_reg(ctxt, ctxt->modrm_reg, &dst.vec);
	ctxt->dst.type = OP_NONE;
	return X86EMUL_CONTINUE;
}

/*
 * MOVHPS/MOVHPD/VMOVHPS/VMOVHPD store to memory.
 */
static int em_movhps_store(struct x86_emulate_ctxt *ctxt)
{
	sse128_t src;

	if (ctxt->modrm_mod == 3)
		return emulate_ud(ctxt);
	if ((ctxt->d & Avx) && ctxt->vex_reg)
		return emulate_ud(ctxt);

	kvm_read_sse_reg(ctxt->modrm_reg, &src);
	/* Store in persistent ctxt buffer for cross-page MMIO fragment safety */
	*(u64 *)ctxt->dst.valptr = sse128_hi(src);
	return write_modrm_mem(ctxt, ctxt->dst.valptr, sizeof(u64));
}

/*
 * VMOVD/Q xmm, r/m32|64 and MOVD/Q xmm, r/m32|64
 */
static int em_movd_xmm_load(struct x86_emulate_ctxt *ctxt)
{
	__sse128_u dst = {};
	u64 val;
	int rc;

	rc = read_modrm_int_operand(ctxt, &val, scalar_gpr_bytes(ctxt));
	if (rc != X86EMUL_CONTINUE)
		return rc;

	memcpy(&dst, &val, scalar_gpr_bytes(ctxt));
	write_xmm_reg(ctxt, ctxt->modrm_reg, &dst.vec);
	ctxt->dst.type = OP_NONE;
	return X86EMUL_CONTINUE;
}

/*
 * VMOVD/Q r/m32|64, xmm and MOVD/Q r/m32|64, xmm
 */
static int em_movd_xmm_store(struct x86_emulate_ctxt *ctxt)
{
	sse128_t src;
	unsigned int bytes = scalar_gpr_bytes(ctxt);

	kvm_read_sse_reg(ctxt->modrm_reg, &src);

	if (ctxt->modrm_mod == 3) {
		assign_register(reg_rmw(ctxt, ctxt->modrm_rm), sse128_lo(src), bytes);
		return X86EMUL_CONTINUE;
	}

	*(u64 *)ctxt->dst.valptr = sse128_lo(src);
	return write_modrm_mem(ctxt, ctxt->dst.valptr, bytes);
}

/*
 * MOVQ/VMOVQ xmm, xmm/m64
 */
static int em_movq_load(struct x86_emulate_ctxt *ctxt)
{
	__sse128_u dst = {};
	sse128_t src;
	u64 val;
	int rc;

	if (ctxt->modrm_mod == 3) {
		kvm_read_sse_reg(ctxt->modrm_rm, &src);
		val = sse128_lo(src);
	} else {
		rc = read_modrm_mem(ctxt, &val, sizeof(val));
		if (rc != X86EMUL_CONTINUE)
			return rc;
	}

	dst.as_u64[0] = val;
	write_xmm_reg(ctxt, ctxt->modrm_reg, &dst.vec);
	ctxt->dst.type = OP_NONE;
	return X86EMUL_CONTINUE;
}

/*
 * MOVQ/VMOVQ xmm/m64, xmm
 */
static int em_movq_store(struct x86_emulate_ctxt *ctxt)
{
	__sse128_u dst = {};
	sse128_t src;

	kvm_read_sse_reg(ctxt->modrm_reg, &src);

	if (ctxt->modrm_mod == 3) {
		dst.as_u64[0] = sse128_lo(src);
		write_xmm_reg(ctxt, ctxt->modrm_rm, &dst.vec);
		ctxt->dst.type = OP_NONE;
		return X86EMUL_CONTINUE;
	}

	*(u64 *)ctxt->dst.valptr = sse128_lo(src);
	return write_modrm_mem(ctxt, ctxt->dst.valptr, sizeof(u64));
}

/*
 * SSE prerequisite checking helper for instructions that cannot use the
 * Sse flag (e.g., MOVD/MOVQ which need mixed GPR/XMM operand types).
 */
static int em_check_sse_prereqs(struct x86_emulate_ctxt *ctxt)
{
	if (ctxt->ops->get_cr(ctxt, 0) & X86_CR0_EM)
		return emulate_ud(ctxt);
	if (!(ctxt->ops->get_cr(ctxt, 4) & X86_CR4_OSFXSR))
		return emulate_ud(ctxt);
	if (ctxt->ops->get_cr(ctxt, 0) & X86_CR0_TS)
		return emulate_nm(ctxt);
	return X86EMUL_CONTINUE;
}

static int emulate_simd_fp_exception(struct x86_emulate_ctxt *ctxt)
{
	if (!(ctxt->ops->get_cr(ctxt, 4) & X86_CR4_OSXMMEXCPT))
		return emulate_ud(ctxt);

	return emulate_exception(ctxt, XM_VECTOR, 0, false);
}

/*
 * MOVSLDUP: duplicate even-indexed single-precision floats.
 * {a, b, c, d} -> {a, a, c, c}.  For 256-bit: also handles upper lane.
 * Used for F3 0F 12 /r.
 */
static int em_movsldup(struct x86_emulate_ctxt *ctxt)
{
	u32 *src = (u32 *)ctxt->src.valptr;
	u32 *dst = (u32 *)ctxt->dst.valptr;

	dst[0] = src[0]; dst[1] = src[0];
	dst[2] = src[2]; dst[3] = src[2];

	if (ctxt->op_bytes == 32) {
		dst[4] = src[4]; dst[5] = src[4];
		dst[6] = src[6]; dst[7] = src[6];
	}
	return X86EMUL_CONTINUE;
}

/*
 * MOVSHDUP: duplicate odd-indexed single-precision floats.
 * {a, b, c, d} -> {b, b, d, d}.  For 256-bit: also handles upper lane.
 * Used for F3 0F 16 /r.
 */
static int em_movshdup(struct x86_emulate_ctxt *ctxt)
{
	u32 *src = (u32 *)ctxt->src.valptr;
	u32 *dst = (u32 *)ctxt->dst.valptr;

	dst[0] = src[1]; dst[1] = src[1];
	dst[2] = src[3]; dst[3] = src[3];

	if (ctxt->op_bytes == 32) {
		dst[4] = src[5]; dst[5] = src[5];
		dst[6] = src[7]; dst[7] = src[7];
	}
	return X86EMUL_CONTINUE;
}

/*
 * MOVDDUP: duplicate low qword to both halves of XMM.
 * {lo, hi} -> {lo, lo}.  Used for F2 0F 12 /r.
 */
static int em_movddup(struct x86_emulate_ctxt *ctxt)
{
	u64 *src = (u64 *)ctxt->src.valptr;
	u64 *dst = (u64 *)ctxt->dst.valptr;

	memset(ctxt->dst.valptr, 0, sizeof(ctxt->dst.valptr));
	dst[0] = src[0]; dst[1] = src[0];
	return X86EMUL_CONTINUE;
}

/*
 * PCMPEQB: packed compare for equal bytes.
 * For AVX, the first source comes from VEX.vvvv instead of the destination.
 */
static int em_pcmpeqb(struct x86_emulate_ctxt *ctxt)
{
	u8 *dst = (u8 *)ctxt->dst.valptr;
	u8 *src = (u8 *)ctxt->src.valptr;
	u8 *src1 = ctxt->src2.type == OP_NONE ? dst : (u8 *)ctxt->src2.valptr;
	int i;

	for (i = 0; i < ctxt->dst.bytes; i++)
		dst[i] = (src1[i] == src[i]) ? 0xff : 0x00;
	return X86EMUL_CONTINUE;
}

/*
 * PMINUB: packed minimum of unsigned bytes.
 * For AVX, the first source comes from VEX.vvvv instead of the destination.
 */
static int em_pminub(struct x86_emulate_ctxt *ctxt)
{
	u8 *dst = (u8 *)ctxt->dst.valptr;
	u8 *src = (u8 *)ctxt->src.valptr;
	u8 *src1 = ctxt->src2.type == OP_NONE ? dst : (u8 *)ctxt->src2.valptr;
	int i;

	for (i = 0; i < ctxt->dst.bytes; i++)
		dst[i] = min(src1[i], src[i]);
	return X86EMUL_CONTINUE;
}

/*
 * PAVGB: packed average of unsigned bytes.
 * For AVX, the first source comes from VEX.vvvv instead of the destination.
 */
static int em_pavgb(struct x86_emulate_ctxt *ctxt)
{
	u8 *dst = (u8 *)ctxt->dst.valptr;
	u8 *src = (u8 *)ctxt->src.valptr;
	u8 *src1 = ctxt->src2.type == OP_NONE ? dst : (u8 *)ctxt->src2.valptr;
	int i;

	for (i = 0; i < ctxt->dst.bytes; i++)
		dst[i] = ((u16)src1[i] + (u16)src[i] + 1) >> 1;
	return X86EMUL_CONTINUE;
}

/*
 * POR: bitwise OR of packed integers.
 * For AVX, the first source comes from VEX.vvvv instead of the destination.
 */
static int em_por(struct x86_emulate_ctxt *ctxt)
{
	u64 *dst = (u64 *)ctxt->dst.valptr;
	u64 *src = (u64 *)ctxt->src.valptr;
	u64 *src1 = ctxt->src2.type == OP_NONE ? dst : (u64 *)ctxt->src2.valptr;
	int i;

	for (i = 0; i < ctxt->dst.bytes / sizeof(*dst); i++)
		dst[i] = src1[i] | src[i];
	return X86EMUL_CONTINUE;
}

/*
 * PAND: bitwise AND of packed integers.
 * For AVX, the first source comes from VEX.vvvv instead of the destination.
 */
static int em_pand(struct x86_emulate_ctxt *ctxt)
{
	u64 *dst = (u64 *)ctxt->dst.valptr;
	u64 *src = (u64 *)ctxt->src.valptr;
	u64 *src1 = ctxt->src2.type == OP_NONE ? dst : (u64 *)ctxt->src2.valptr;
	int i;

	for (i = 0; i < ctxt->dst.bytes / sizeof(*dst); i++)
		dst[i] = src1[i] & src[i];
	return X86EMUL_CONTINUE;
}

/*
 * PANDN: bitwise AND NOT of packed integers.  dst = ~src1 & src.
 * For AVX, the first source comes from VEX.vvvv instead of the destination.
 */
static int em_pandn(struct x86_emulate_ctxt *ctxt)
{
	u64 *dst = (u64 *)ctxt->dst.valptr;
	u64 *src = (u64 *)ctxt->src.valptr;
	u64 *src1 = ctxt->src2.type == OP_NONE ? dst : (u64 *)ctxt->src2.valptr;
	int i;

	for (i = 0; i < ctxt->dst.bytes / sizeof(*dst); i++)
		dst[i] = ~src1[i] & src[i];
	return X86EMUL_CONTINUE;
}

/*
 * PXOR: bitwise XOR of packed integers.
 * For AVX, the first source comes from VEX.vvvv instead of the destination.
 */
static int em_pxor(struct x86_emulate_ctxt *ctxt)
{
	u64 *dst = (u64 *)ctxt->dst.valptr;
	u64 *src = (u64 *)ctxt->src.valptr;
	u64 *src1 = ctxt->src2.type == OP_NONE ? dst : (u64 *)ctxt->src2.valptr;
	int i;

	for (i = 0; i < ctxt->dst.bytes / sizeof(*dst); i++)
		dst[i] = src1[i] ^ src[i];
	return X86EMUL_CONTINUE;
}

/*
 * PADDB: packed add bytes.
 * For AVX, the first source comes from VEX.vvvv instead of the destination.
 */
static int em_paddb(struct x86_emulate_ctxt *ctxt)
{
	u8 *dst = (u8 *)ctxt->dst.valptr;
	u8 *src = (u8 *)ctxt->src.valptr;
	u8 *src1 = ctxt->src2.type == OP_NONE ? dst : (u8 *)ctxt->src2.valptr;
	int i;

	for (i = 0; i < ctxt->dst.bytes; i++)
		dst[i] = src1[i] + src[i];
	return X86EMUL_CONTINUE;
}

/*
 * PSUBB: packed subtract bytes.
 * For AVX, the first source comes from VEX.vvvv instead of the destination.
 */
static int em_psubb(struct x86_emulate_ctxt *ctxt)
{
	u8 *dst = (u8 *)ctxt->dst.valptr;
	u8 *src = (u8 *)ctxt->src.valptr;
	u8 *src1 = ctxt->src2.type == OP_NONE ? dst : (u8 *)ctxt->src2.valptr;
	int i;

	for (i = 0; i < ctxt->dst.bytes; i++)
		dst[i] = src1[i] - src[i];
	return X86EMUL_CONTINUE;
}

/*
 * PCMPEQD: packed compare for equal dwords.
 * For AVX, the first source comes from VEX.vvvv instead of the destination.
 */
static int em_pcmpeqd(struct x86_emulate_ctxt *ctxt)
{
	u32 *dst = (u32 *)ctxt->dst.valptr;
	u32 *src = (u32 *)ctxt->src.valptr;
	u32 *src1 = ctxt->src2.type == OP_NONE ? dst : (u32 *)ctxt->src2.valptr;
	int i;

	for (i = 0; i < ctxt->dst.bytes / sizeof(*dst); i++)
		dst[i] = (src1[i] == src[i]) ? 0xffffffff : 0x00000000;
	return X86EMUL_CONTINUE;
}

/*
 * PCMPGTB: packed compare for greater than bytes (signed).
 * For AVX, the first source comes from VEX.vvvv instead of the destination.
 */
static int em_pcmpgtb(struct x86_emulate_ctxt *ctxt)
{
	s8 *dst = (s8 *)ctxt->dst.valptr;
	s8 *src = (s8 *)ctxt->src.valptr;
	s8 *src1 = ctxt->src2.type == OP_NONE ? dst : (s8 *)ctxt->src2.valptr;
	int i;

	for (i = 0; i < ctxt->dst.bytes; i++)
		dst[i] = (src1[i] > src[i]) ? (s8)0xff : (s8)0x00;
	return X86EMUL_CONTINUE;
}

/*
 * PADDW: packed add words.
 * For AVX, the first source comes from VEX.vvvv instead of the destination.
 */
static int em_paddw(struct x86_emulate_ctxt *ctxt)
{
	u16 *dst = (u16 *)ctxt->dst.valptr;
	u16 *src = (u16 *)ctxt->src.valptr;
	u16 *src1 = ctxt->src2.type == OP_NONE ? dst : (u16 *)ctxt->src2.valptr;
	int i;

	for (i = 0; i < ctxt->dst.bytes / sizeof(*dst); i++)
		dst[i] = src1[i] + src[i];
	return X86EMUL_CONTINUE;
}

/*
 * PADDD: packed add dwords.
 * For AVX, the first source comes from VEX.vvvv instead of the destination.
 */
static int em_paddd(struct x86_emulate_ctxt *ctxt)
{
	u32 *dst = (u32 *)ctxt->dst.valptr;
	u32 *src = (u32 *)ctxt->src.valptr;
	u32 *src1 = ctxt->src2.type == OP_NONE ? dst : (u32 *)ctxt->src2.valptr;
	int i;

	for (i = 0; i < ctxt->dst.bytes / sizeof(*dst); i++)
		dst[i] = src1[i] + src[i];
	return X86EMUL_CONTINUE;
}

/*
 * PADDQ: packed add quadwords.
 * For AVX, the first source comes from VEX.vvvv instead of the destination.
 */
static int em_paddq(struct x86_emulate_ctxt *ctxt)
{
	u64 *dst = (u64 *)ctxt->dst.valptr;
	u64 *src = (u64 *)ctxt->src.valptr;
	u64 *src1 = ctxt->src2.type == OP_NONE ? dst : (u64 *)ctxt->src2.valptr;
	int i;

	for (i = 0; i < ctxt->dst.bytes / sizeof(*dst); i++)
		dst[i] = src1[i] + src[i];
	return X86EMUL_CONTINUE;
}

/*
 * PSUBW: packed subtract words.
 * For AVX, the first source comes from VEX.vvvv instead of the destination.
 */
static int em_psubw(struct x86_emulate_ctxt *ctxt)
{
	u16 *dst = (u16 *)ctxt->dst.valptr;
	u16 *src = (u16 *)ctxt->src.valptr;
	u16 *src1 = ctxt->src2.type == OP_NONE ? dst : (u16 *)ctxt->src2.valptr;
	int i;

	for (i = 0; i < ctxt->dst.bytes / sizeof(*dst); i++)
		dst[i] = src1[i] - src[i];
	return X86EMUL_CONTINUE;
}

/*
 * PSUBD: packed subtract dwords.
 * For AVX, the first source comes from VEX.vvvv instead of the destination.
 */
static int em_psubd(struct x86_emulate_ctxt *ctxt)
{
	u32 *dst = (u32 *)ctxt->dst.valptr;
	u32 *src = (u32 *)ctxt->src.valptr;
	u32 *src1 = ctxt->src2.type == OP_NONE ? dst : (u32 *)ctxt->src2.valptr;
	int i;

	for (i = 0; i < ctxt->dst.bytes / sizeof(*dst); i++)
		dst[i] = src1[i] - src[i];
	return X86EMUL_CONTINUE;
}

/*
 * PSUBQ: packed subtract quadwords.
 * For AVX, the first source comes from VEX.vvvv instead of the destination.
 */
static int em_psubq(struct x86_emulate_ctxt *ctxt)
{
	u64 *dst = (u64 *)ctxt->dst.valptr;
	u64 *src = (u64 *)ctxt->src.valptr;
	u64 *src1 = ctxt->src2.type == OP_NONE ? dst : (u64 *)ctxt->src2.valptr;
	int i;

	for (i = 0; i < ctxt->dst.bytes / sizeof(*dst); i++)
		dst[i] = src1[i] - src[i];
	return X86EMUL_CONTINUE;
}

/*
 * PCMPEQW: packed compare for equal words.
 * For AVX, the first source comes from VEX.vvvv instead of the destination.
 */
static int em_pcmpeqw(struct x86_emulate_ctxt *ctxt)
{
	u16 *dst = (u16 *)ctxt->dst.valptr;
	u16 *src = (u16 *)ctxt->src.valptr;
	u16 *src1 = ctxt->src2.type == OP_NONE ? dst : (u16 *)ctxt->src2.valptr;
	int i;

	for (i = 0; i < ctxt->dst.bytes / sizeof(*dst); i++)
		dst[i] = (src1[i] == src[i]) ? 0xffff : 0x0000;
	return X86EMUL_CONTINUE;
}

/*
 * PCMPGTW: packed compare for greater than words (signed).
 * For AVX, the first source comes from VEX.vvvv instead of the destination.
 */
static int em_pcmpgtw(struct x86_emulate_ctxt *ctxt)
{
	s16 *dst = (s16 *)ctxt->dst.valptr;
	s16 *src = (s16 *)ctxt->src.valptr;
	s16 *src1 = ctxt->src2.type == OP_NONE ? dst : (s16 *)ctxt->src2.valptr;
	int i;

	for (i = 0; i < ctxt->dst.bytes / sizeof(*dst); i++)
		dst[i] = (src1[i] > src[i]) ? (s16)0xffff : (s16)0x0000;
	return X86EMUL_CONTINUE;
}

/*
 * PCMPGTD: packed compare for greater than dwords (signed).
 * For AVX, the first source comes from VEX.vvvv instead of the destination.
 */
static int em_pcmpgtd(struct x86_emulate_ctxt *ctxt)
{
	s32 *dst = (s32 *)ctxt->dst.valptr;
	s32 *src = (s32 *)ctxt->src.valptr;
	s32 *src1 = ctxt->src2.type == OP_NONE ? dst : (s32 *)ctxt->src2.valptr;
	int i;

	for (i = 0; i < ctxt->dst.bytes / sizeof(*dst); i++)
		dst[i] = (src1[i] > src[i]) ? (s32)0xffffffff : (s32)0x00000000;
	return X86EMUL_CONTINUE;
}

/*
 * PMULLW: packed multiply low words.
 * For AVX, the first source comes from VEX.vvvv instead of the destination.
 */
static int em_pmullw(struct x86_emulate_ctxt *ctxt)
{
	u16 *dst = (u16 *)ctxt->dst.valptr;
	u16 *src = (u16 *)ctxt->src.valptr;
	u16 *src1 = ctxt->src2.type == OP_NONE ? dst : (u16 *)ctxt->src2.valptr;
	int i;

	for (i = 0; i < ctxt->dst.bytes / sizeof(*dst); i++)
		dst[i] = src1[i] * src[i];
	return X86EMUL_CONTINUE;
}

/*
 * PMINUD: packed minimum of unsigned dwords.
 * For AVX, the first source comes from VEX.vvvv instead of the destination.
 */
static int em_pminud(struct x86_emulate_ctxt *ctxt)
{
	u32 *dst = (u32 *)ctxt->dst.valptr;
	u32 *src = (u32 *)ctxt->src.valptr;
	u32 *src1 = ctxt->src2.type == OP_NONE ? dst : (u32 *)ctxt->src2.valptr;
	int i;

	for (i = 0; i < ctxt->dst.bytes / sizeof(*dst); i++)
		dst[i] = min(src1[i], src[i]);
	return X86EMUL_CONTINUE;
}

/*
 * PMAXUD: packed maximum of unsigned dwords.
 * For AVX, the first source comes from VEX.vvvv instead of the destination.
 */
static int em_pmaxud(struct x86_emulate_ctxt *ctxt)
{
	u32 *dst = (u32 *)ctxt->dst.valptr;
	u32 *src = (u32 *)ctxt->src.valptr;
	u32 *src1 = ctxt->src2.type == OP_NONE ? dst : (u32 *)ctxt->src2.valptr;
	int i;

	for (i = 0; i < ctxt->dst.bytes / sizeof(*dst); i++)
		dst[i] = max(src1[i], src[i]);
	return X86EMUL_CONTINUE;
}

/*
 * PCMPEQQ: compare packed qwords for equality.
 * For AVX, the first source comes from VEX.vvvv instead of the destination.
 */
static int em_pcmpeqq(struct x86_emulate_ctxt *ctxt)
{
	u64 *dst = (u64 *)ctxt->dst.valptr;
	u64 *src = (u64 *)ctxt->src.valptr;
	u64 *src1 = ctxt->src2.type == OP_NONE ? dst : (u64 *)ctxt->src2.valptr;
	int i;

	for (i = 0; i < ctxt->dst.bytes / sizeof(*dst); i++)
		dst[i] = (src1[i] == src[i]) ? ~(u64)0 : 0;
	return X86EMUL_CONTINUE;
}

/*
 * PCMPGTQ: compare packed signed qwords for greater-than.
 * For AVX, the first source comes from VEX.vvvv instead of the destination.
 */
static int em_pcmpgtq(struct x86_emulate_ctxt *ctxt)
{
	u64 *dst = (u64 *)ctxt->dst.valptr;
	u64 *src = (u64 *)ctxt->src.valptr;
	u64 *src1 = ctxt->src2.type == OP_NONE ? dst : (u64 *)ctxt->src2.valptr;
	int i;

	for (i = 0; i < ctxt->dst.bytes / sizeof(*dst); i++)
		dst[i] = ((s64)src1[i] > (s64)src[i]) ? ~(u64)0 : 0;
	return X86EMUL_CONTINUE;
}

/*
 * PMULLD: multiply packed signed dwords, store low 32 bits.
 * For AVX, the first source comes from VEX.vvvv instead of the destination.
 */
static int em_pmulld(struct x86_emulate_ctxt *ctxt)
{
	u32 *dst = (u32 *)ctxt->dst.valptr;
	u32 *src = (u32 *)ctxt->src.valptr;
	u32 *src1 = ctxt->src2.type == OP_NONE ? dst : (u32 *)ctxt->src2.valptr;
	int i;

	for (i = 0; i < ctxt->dst.bytes / sizeof(*dst); i++)
		dst[i] = src1[i] * src[i];
	return X86EMUL_CONTINUE;
}

/*
 * PACKUSDW: pack dwords to unsigned words with saturation.
 * For AVX, the first source comes from VEX.vvvv instead of the destination.
 */
static int em_packusdw(struct x86_emulate_ctxt *ctxt)
{
	s32 *src = (s32 *)ctxt->src.valptr;
	s32 *src1 = ctxt->src2.type == OP_NONE ? (s32 *)ctxt->dst.valptr : (s32 *)ctxt->src2.valptr;
	u16 *dst = (u16 *)ctxt->dst.valptr;
	u16 tmp[16];
	int i;

	/* For 128-bit: src1[0..3] -> tmp[0..3], src[0..3] -> tmp[4..7] */
	for (i = 0; i < 4; i++)
		tmp[i] = (src1[i] < 0) ? 0 : (src1[i] > 0xFFFF) ? 0xFFFF : src1[i];
	for (i = 0; i < 4; i++)
		tmp[4 + i] = (src[i] < 0) ? 0 : (src[i] > 0xFFFF) ? 0xFFFF : src[i];
	memcpy(dst, tmp, 16);
	/* For 256-bit: process each 128-bit lane independently */
	if (ctxt->dst.bytes == 32) {
		for (i = 0; i < 4; i++)
			tmp[8 + i] = (src1[4+i] < 0) ? 0 : (src1[4+i] > 0xFFFF) ? 0xFFFF : src1[4+i];
		for (i = 0; i < 4; i++)
			tmp[12 + i] = (src[4+i] < 0) ? 0 : (src[4+i] > 0xFFFF) ? 0xFFFF : src[4+i];
		memcpy(dst + 8, tmp + 8, 16);
	}
	return X86EMUL_CONTINUE;
}

/*
 * PMADDUBSW: multiply unsigned bytes by signed bytes, add adjacent
 * pairs to signed words with saturation.
 * For AVX, the first source comes from VEX.vvvv instead of the destination.
 */
static int em_pmaddubsw(struct x86_emulate_ctxt *ctxt)
{
	u8 *src1_u = (u8 *)(ctxt->src2.type == OP_NONE ? ctxt->dst.valptr : ctxt->src2.valptr);
	s8 *src_s = (s8 *)ctxt->src.valptr;
	s16 *dst = (s16 *)ctxt->dst.valptr;
	s16 tmp[16];
	int i;

	for (i = 0; i < ctxt->dst.bytes / 2; i++) {
		s32 t = (s32)(u32)src1_u[2*i] * (s32)src_s[2*i] +
			(s32)(u32)src1_u[2*i+1] * (s32)src_s[2*i+1];
		tmp[i] = (t > 32767) ? 32767 : (t < -32768) ? -32768 : t;
	}
	memcpy(dst, tmp, ctxt->dst.bytes);
	return X86EMUL_CONTINUE;
}

/*
 * UCOMISS: unordered compare scalar single-precision floats, set EFLAGS.
 * Used for NP 0F 2E /r — UCOMISS xmm1, xmm2/m32.
 * Sets ZF, PF, CF; clears OF, SF, AF.
 */
static int em_ucomiss(struct x86_emulate_ctxt *ctxt)
{
	sse128_t reg;
	sse128_t saved_xmm0;
	u32 src1, src2;
	unsigned long flags;
	int rc;

	rc = em_check_sse_prereqs(ctxt);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	kvm_read_sse_reg(ctxt->modrm_reg, &reg);
	src1 = sse128_l0(reg);
	if (ctxt->modrm_mod == 3) {
		kvm_read_sse_reg(ctxt->modrm_rm, &reg);
		src2 = sse128_l0(reg);
	} else {
		memcpy(&src2, ctxt->src.valptr, sizeof(src2));
	}

	kvm_fpu_get();
	_kvm_read_sse_reg(0, &saved_xmm0);
	rc = asm_safe("movss %[src1], %%xmm0; ucomiss %[src2], %%xmm0; pushf; pop %[flags]",
		      , [flags] "=r" (flags)
		      : [src1] "m" (src1), [src2] "m" (src2)
		      : "cc");
	_kvm_write_sse_reg(0, &saved_xmm0);
	kvm_fpu_put();
	if (rc != X86EMUL_CONTINUE)
		return emulate_simd_fp_exception(ctxt);

	ctxt->eflags = (ctxt->eflags & ~(X86_EFLAGS_ZF | X86_EFLAGS_PF |
			X86_EFLAGS_CF | X86_EFLAGS_OF | X86_EFLAGS_SF |
			X86_EFLAGS_AF)) |
		       (flags & (X86_EFLAGS_ZF | X86_EFLAGS_PF | X86_EFLAGS_CF));

	ctxt->dst.type = OP_NONE;
	return X86EMUL_CONTINUE;
}

/*
 * UCOMISD: unordered compare scalar double-precision floats and set EFLAGS.
 * Used for 66 0F 2E /r — UCOMISD xmm1, xmm2/m64.
 * Sets ZF, PF, CF; clears OF, SF, AF.
 */
static int em_ucomisd(struct x86_emulate_ctxt *ctxt)
{
	sse128_t reg;
	sse128_t saved_xmm0;
	u64 src1, src2;
	unsigned long flags;
	int rc;

	rc = em_check_sse_prereqs(ctxt);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	kvm_read_sse_reg(ctxt->modrm_reg, &reg);
	src1 = sse128_lo(reg);
	if (ctxt->modrm_mod == 3) {
		kvm_read_sse_reg(ctxt->modrm_rm, &reg);
		src2 = sse128_lo(reg);
	} else {
		memcpy(&src2, ctxt->src.valptr, sizeof(src2));
	}

	kvm_fpu_get();
	_kvm_read_sse_reg(0, &saved_xmm0);
	rc = asm_safe("movsd %[src1], %%xmm0; ucomisd %[src2], %%xmm0; pushf; pop %[flags]",
		      , [flags] "=r" (flags)
		      : [src1] "m" (src1), [src2] "m" (src2)
		      : "cc");
	_kvm_write_sse_reg(0, &saved_xmm0);
	kvm_fpu_put();
	if (rc != X86EMUL_CONTINUE)
		return emulate_simd_fp_exception(ctxt);

	ctxt->eflags = (ctxt->eflags & ~(X86_EFLAGS_ZF | X86_EFLAGS_PF |
			X86_EFLAGS_CF | X86_EFLAGS_OF | X86_EFLAGS_SF |
			X86_EFLAGS_AF)) |
		       (flags & (X86_EFLAGS_ZF | X86_EFLAGS_PF | X86_EFLAGS_CF));

	ctxt->dst.type = OP_NONE;
	return X86EMUL_CONTINUE;
}

/*
 * COMISD: ordered compare scalar double-precision floats and set EFLAGS.
 * Used for 66 0F 2F /r — COMISD xmm1, xmm2/m64.
 * Sets ZF, PF, CF; clears OF, SF, AF.
 */
static int em_comisd(struct x86_emulate_ctxt *ctxt)
{
	sse128_t reg;
	sse128_t saved_xmm0;
	u64 src1, src2;
	unsigned long flags;
	int rc;

	rc = em_check_sse_prereqs(ctxt);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	kvm_read_sse_reg(ctxt->modrm_reg, &reg);
	src1 = sse128_lo(reg);
	if (ctxt->modrm_mod == 3) {
		kvm_read_sse_reg(ctxt->modrm_rm, &reg);
		src2 = sse128_lo(reg);
	} else {
		memcpy(&src2, ctxt->src.valptr, sizeof(src2));
	}

	kvm_fpu_get();
	_kvm_read_sse_reg(0, &saved_xmm0);
	rc = asm_safe("movsd %[src1], %%xmm0; comisd %[src2], %%xmm0; pushf; pop %[flags]",
		      , [flags] "=r" (flags)
		      : [src1] "m" (src1), [src2] "m" (src2)
		      : "cc");
	_kvm_write_sse_reg(0, &saved_xmm0);
	kvm_fpu_put();
	if (rc != X86EMUL_CONTINUE)
		return emulate_simd_fp_exception(ctxt);

	ctxt->eflags = (ctxt->eflags & ~(X86_EFLAGS_ZF | X86_EFLAGS_PF |
			X86_EFLAGS_CF | X86_EFLAGS_OF | X86_EFLAGS_SF |
			X86_EFLAGS_AF)) |
		       (flags & (X86_EFLAGS_ZF | X86_EFLAGS_PF | X86_EFLAGS_CF));

	ctxt->dst.type = OP_NONE;
	return X86EMUL_CONTINUE;
}

/*
 * COMISS: ordered compare scalar single-precision floats and set EFLAGS.
 * Used for NP 0F 2F /r — COMISS xmm1, xmm2/m32.
 * Sets ZF, PF, CF; clears OF, SF, AF.
 */
static int em_comiss(struct x86_emulate_ctxt *ctxt)
{
	sse128_t reg;
	sse128_t saved_xmm0;
	u32 src1, src2;
	unsigned long flags;
	int rc;

	rc = em_check_sse_prereqs(ctxt);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	kvm_read_sse_reg(ctxt->modrm_reg, &reg);
	src1 = sse128_l0(reg);
	if (ctxt->modrm_mod == 3) {
		kvm_read_sse_reg(ctxt->modrm_rm, &reg);
		src2 = sse128_l0(reg);
	} else {
		memcpy(&src2, ctxt->src.valptr, sizeof(src2));
	}

	kvm_fpu_get();
	_kvm_read_sse_reg(0, &saved_xmm0);
	rc = asm_safe("movss %[src1], %%xmm0; comiss %[src2], %%xmm0; pushf; pop %[flags]",
		      , [flags] "=r" (flags)
		      : [src1] "m" (src1), [src2] "m" (src2)
		      : "cc");
	_kvm_write_sse_reg(0, &saved_xmm0);
	kvm_fpu_put();
	if (rc != X86EMUL_CONTINUE)
		return emulate_simd_fp_exception(ctxt);

	ctxt->eflags = (ctxt->eflags & ~(X86_EFLAGS_ZF | X86_EFLAGS_PF |
			X86_EFLAGS_CF | X86_EFLAGS_OF | X86_EFLAGS_SF |
			X86_EFLAGS_AF)) |
		       (flags & (X86_EFLAGS_ZF | X86_EFLAGS_PF | X86_EFLAGS_CF));

	ctxt->dst.type = OP_NONE;
	return X86EMUL_CONTINUE;
}

/*
 * CVTSS2SI: convert scalar single-precision float to signed integer.
 * Used for F3 0F 2D /r — CVTSS2SI r32/r64, xmm1/m32.
 * Rounding is controlled by guest MXCSR (already loaded via kvm_fpu_get).
 */
static int em_cvtss2si(struct x86_emulate_ctxt *ctxt)
{
	sse128_t reg;
	u32 float_val;
	unsigned int bytes = scalar_gpr_bytes(ctxt);
	int rc;

	rc = em_check_sse_prereqs(ctxt);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	if (ctxt->modrm_mod == 3) {
		kvm_read_sse_reg(ctxt->modrm_rm, &reg);
		float_val = sse128_l0(reg);
	} else {
		rc = read_modrm_mem(ctxt, &float_val, sizeof(float_val));
		if (rc != X86EMUL_CONTINUE)
			return rc;
	}

	kvm_fpu_get();
	if (bytes == 8) {
		u64 result;

		rc = asm_safe("cvtss2siq %[src], %[dst]",
			      , [dst] "=r" (result)
			      : [src] "m" (float_val));
		if (rc != X86EMUL_CONTINUE) {
			kvm_fpu_put();
			return emulate_simd_fp_exception(ctxt);
		}
		assign_register(reg_rmw(ctxt, ctxt->modrm_reg), result, bytes);
	} else {
		u32 result;

		rc = asm_safe("cvtss2sil %[src], %[dst]",
			      , [dst] "=r" (result)
			      : [src] "m" (float_val));
		if (rc != X86EMUL_CONTINUE) {
			kvm_fpu_put();
			return emulate_simd_fp_exception(ctxt);
		}
		assign_register(reg_rmw(ctxt, ctxt->modrm_reg), result, bytes);
	}
	kvm_fpu_put();

	ctxt->dst.type = OP_NONE;
	return X86EMUL_CONTINUE;
}

/*
 * CVTTSS2SI: convert with truncation scalar single-precision float to
 * signed integer.
 * Used for F3 0F 2C /r — CVTTSS2SI r32/r64, xmm1/m32.
 */
static int em_cvttss2si(struct x86_emulate_ctxt *ctxt)
{
	sse128_t reg;
	u32 float_val;
	unsigned int bytes = scalar_gpr_bytes(ctxt);
	int rc;

	rc = em_check_sse_prereqs(ctxt);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	if (ctxt->modrm_mod == 3) {
		kvm_read_sse_reg(ctxt->modrm_rm, &reg);
		float_val = sse128_l0(reg);
	} else {
		rc = read_modrm_mem(ctxt, &float_val, sizeof(float_val));
		if (rc != X86EMUL_CONTINUE)
			return rc;
	}

	kvm_fpu_get();
	if (bytes == 8) {
		u64 result;

		rc = asm_safe("cvttss2siq %[src], %[dst]",
			      , [dst] "=r" (result)
			      : [src] "m" (float_val));
		if (rc != X86EMUL_CONTINUE) {
			kvm_fpu_put();
			return emulate_simd_fp_exception(ctxt);
		}
		assign_register(reg_rmw(ctxt, ctxt->modrm_reg), result, bytes);
	} else {
		u32 result;

		rc = asm_safe("cvttss2sil %[src], %[dst]",
			      , [dst] "=r" (result)
			      : [src] "m" (float_val));
		if (rc != X86EMUL_CONTINUE) {
			kvm_fpu_put();
			return emulate_simd_fp_exception(ctxt);
		}
		assign_register(reg_rmw(ctxt, ctxt->modrm_reg), result, bytes);
	}
	kvm_fpu_put();

	ctxt->dst.type = OP_NONE;
	return X86EMUL_CONTINUE;
}

/*
 * CVTSI2SD and VCVTSI2SD.
 * Legacy preserves the high qword of the destination, VEX copies it from
 * VEX.vvvv and clears upper YMM state.
 */
static int em_cvtsi2sd(struct x86_emulate_ctxt *ctxt)
{
	__sse128_u xmm;
	sse128_t saved_xmm0;
	u64 result;
	u64 src = 0;
	unsigned int bytes = scalar_gpr_bytes(ctxt);
	int rc;

	rc = em_check_sse_prereqs(ctxt);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	rc = read_modrm_int_operand(ctxt, &src, bytes);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	kvm_fpu_get();
	_kvm_read_sse_reg(0, &saved_xmm0);
	if (bytes == 8) {
		rc = asm_safe("cvtsi2sdq %[src], %%xmm0; movsd %%xmm0, %[result]",
			      , [result] "=m" (result)
			      : [src] "m" (src));
	} else {
		u32 src32 = src;

		rc = asm_safe("cvtsi2sdl %[src], %%xmm0; movsd %%xmm0, %[result]",
			      , [result] "=m" (result)
			      : [src] "m" (src32));
	}
	_kvm_write_sse_reg(0, &saved_xmm0);
	kvm_fpu_put();
	if (rc != X86EMUL_CONTINUE)
		return emulate_simd_fp_exception(ctxt);

	kvm_read_sse_reg((ctxt->d & Avx) ? ctxt->vex_reg : ctxt->modrm_reg,
			 &xmm.vec);
	xmm.as_u64[0] = result;
	write_xmm_reg(ctxt, ctxt->modrm_reg, &xmm.vec);
	ctxt->dst.type = OP_NONE;

	return X86EMUL_CONTINUE;
}

/*
 * CVTSI2SS and VCVTSI2SS: convert signed integer to scalar single-precision.
 * Legacy preserves bits[127:32] of dest, VEX copies from VEX.vvvv.
 */
static int em_cvtsi2ss(struct x86_emulate_ctxt *ctxt)
{
	__sse128_u xmm;
	sse128_t saved_xmm0;
	u32 result;
	u64 src = 0;
	unsigned int bytes = scalar_gpr_bytes(ctxt);
	int rc;

	rc = em_check_sse_prereqs(ctxt);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	rc = read_modrm_int_operand(ctxt, &src, bytes);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	kvm_fpu_get();
	_kvm_read_sse_reg(0, &saved_xmm0);
	if (bytes == 8) {
		rc = asm_safe("cvtsi2ssq %[src], %%xmm0; movss %%xmm0, %[result]",
			      , [result] "=m" (result)
			      : [src] "m" (src));
	} else {
		u32 src32 = src;

		rc = asm_safe("cvtsi2ssl %[src], %%xmm0; movss %%xmm0, %[result]",
			      , [result] "=m" (result)
			      : [src] "m" (src32));
	}
	_kvm_write_sse_reg(0, &saved_xmm0);
	kvm_fpu_put();
	if (rc != X86EMUL_CONTINUE)
		return emulate_simd_fp_exception(ctxt);

	kvm_read_sse_reg((ctxt->d & Avx) ? ctxt->vex_reg : ctxt->modrm_reg,
			 &xmm.vec);
	xmm.as_u32[0] = result;
	write_xmm_reg(ctxt, ctxt->modrm_reg, &xmm.vec);
	ctxt->dst.type = OP_NONE;

	return X86EMUL_CONTINUE;
}

/*
 * CVTSD2SI: convert scalar double-precision float to signed integer.
 * Used for F2 0F 2D /r.
 */
static int em_cvtsd2si(struct x86_emulate_ctxt *ctxt)
{
	sse128_t reg;
	u64 double_val;
	unsigned int bytes = scalar_gpr_bytes(ctxt);
	int rc;

	rc = em_check_sse_prereqs(ctxt);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	if (ctxt->modrm_mod == 3) {
		kvm_read_sse_reg(ctxt->modrm_rm, &reg);
		double_val = sse128_lo(reg);
	} else {
		rc = read_modrm_mem(ctxt, &double_val, sizeof(double_val));
		if (rc != X86EMUL_CONTINUE)
			return rc;
	}

	kvm_fpu_get();
	if (bytes == 8) {
		u64 result;

		rc = asm_safe("cvtsd2siq %[src], %[dst]",
			      , [dst] "=r" (result)
			      : [src] "m" (double_val));
		if (rc != X86EMUL_CONTINUE) {
			kvm_fpu_put();
			return emulate_simd_fp_exception(ctxt);
		}
		assign_register(reg_rmw(ctxt, ctxt->modrm_reg), result, bytes);
	} else {
		u32 result;

		rc = asm_safe("cvtsd2sil %[src], %[dst]",
			      , [dst] "=r" (result)
			      : [src] "m" (double_val));
		if (rc != X86EMUL_CONTINUE) {
			kvm_fpu_put();
			return emulate_simd_fp_exception(ctxt);
		}
		assign_register(reg_rmw(ctxt, ctxt->modrm_reg), result, bytes);
	}
	kvm_fpu_put();

	ctxt->dst.type = OP_NONE;
	return X86EMUL_CONTINUE;
}

/*
 * CVTTSD2SI: convert with truncation scalar double-precision float to
 * signed integer.
 * Used for F2 0F 2C /r.
 */
static int em_cvttsd2si(struct x86_emulate_ctxt *ctxt)
{
	sse128_t reg;
	u64 double_val;
	unsigned int bytes = scalar_gpr_bytes(ctxt);
	int rc;

	rc = em_check_sse_prereqs(ctxt);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	if (ctxt->modrm_mod == 3) {
		kvm_read_sse_reg(ctxt->modrm_rm, &reg);
		double_val = sse128_lo(reg);
	} else {
		rc = read_modrm_mem(ctxt, &double_val, sizeof(double_val));
		if (rc != X86EMUL_CONTINUE)
			return rc;
	}

	kvm_fpu_get();
	if (bytes == 8) {
		u64 result;

		rc = asm_safe("cvttsd2siq %[src], %[dst]",
			      , [dst] "=r" (result)
			      : [src] "m" (double_val));
		if (rc != X86EMUL_CONTINUE) {
			kvm_fpu_put();
			return emulate_simd_fp_exception(ctxt);
		}
		assign_register(reg_rmw(ctxt, ctxt->modrm_reg), result, bytes);
	} else {
		u32 result;

		rc = asm_safe("cvttsd2sil %[src], %[dst]",
			      , [dst] "=r" (result)
			      : [src] "m" (double_val));
		if (rc != X86EMUL_CONTINUE) {
			kvm_fpu_put();
			return emulate_simd_fp_exception(ctxt);
		}
		assign_register(reg_rmw(ctxt, ctxt->modrm_reg), result, bytes);
	}
	kvm_fpu_put();

	ctxt->dst.type = OP_NONE;
	return X86EMUL_CONTINUE;
}

/*
 * CVTSS2SD and VCVTSS2SD: convert scalar single-precision to double-precision.
 * Legacy preserves the high qword, VEX copies it from VEX.vvvv.
 */
static int em_cvtss2sd(struct x86_emulate_ctxt *ctxt)
{
	__sse128_u xmm;
	sse128_t saved_xmm0;
	u64 result;
	u32 float_val;
	sse128_t reg;
	int rc;

	rc = em_check_sse_prereqs(ctxt);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	if (ctxt->modrm_mod == 3) {
		kvm_read_sse_reg(ctxt->modrm_rm, &reg);
		float_val = sse128_l0(reg);
	} else {
		rc = read_modrm_mem(ctxt, &float_val, sizeof(float_val));
		if (rc != X86EMUL_CONTINUE)
			return rc;
	}

	kvm_fpu_get();
	_kvm_read_sse_reg(0, &saved_xmm0);
	rc = asm_safe("cvtss2sd %[src], %%xmm0; movsd %%xmm0, %[result]",
		      , [result] "=m" (result)
		      : [src] "m" (float_val));
	_kvm_write_sse_reg(0, &saved_xmm0);
	kvm_fpu_put();
	if (rc != X86EMUL_CONTINUE)
		return emulate_simd_fp_exception(ctxt);

	kvm_read_sse_reg((ctxt->d & Avx) ? ctxt->vex_reg : ctxt->modrm_reg,
			 &xmm.vec);
	xmm.as_u64[0] = result;
	write_xmm_reg(ctxt, ctxt->modrm_reg, &xmm.vec);
	ctxt->dst.type = OP_NONE;
	return X86EMUL_CONTINUE;
}

/*
 * CVTSD2SS and VCVTSD2SS: convert scalar double-precision to single-precision.
 * Legacy preserves the upper 96 bits, VEX copies bits[127:32] from VEX.vvvv.
 */
static int em_cvtsd2ss(struct x86_emulate_ctxt *ctxt)
{
	__sse128_u xmm;
	sse128_t saved_xmm0;
	u32 result;
	u64 double_val;
	sse128_t reg;
	int rc;

	rc = em_check_sse_prereqs(ctxt);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	if (ctxt->modrm_mod == 3) {
		kvm_read_sse_reg(ctxt->modrm_rm, &reg);
		double_val = sse128_lo(reg);
	} else {
		rc = read_modrm_mem(ctxt, &double_val, sizeof(double_val));
		if (rc != X86EMUL_CONTINUE)
			return rc;
	}

	kvm_fpu_get();
	_kvm_read_sse_reg(0, &saved_xmm0);
	rc = asm_safe("cvtsd2ss %[src], %%xmm0; movss %%xmm0, %[result]",
		      , [result] "=m" (result)
		      : [src] "m" (double_val));
	_kvm_write_sse_reg(0, &saved_xmm0);
	kvm_fpu_put();
	if (rc != X86EMUL_CONTINUE)
		return emulate_simd_fp_exception(ctxt);

	kvm_read_sse_reg((ctxt->d & Avx) ? ctxt->vex_reg : ctxt->modrm_reg,
			 &xmm.vec);
	xmm.as_u32[0] = result;
	write_xmm_reg(ctxt, ctxt->modrm_reg, &xmm.vec);
	ctxt->dst.type = OP_NONE;
	return X86EMUL_CONTINUE;
}

/*
 * Scalar single-precision arithmetic: ADDSS, SUBSS, MULSS, DIVSS, MINSS, MAXSS.
 * Legacy preserves bits[127:32] of dest, VEX copies from VEX.vvvv.
 */
#define SSE_SCALAR_SS_OP(_name, _insn)						\
static int _name(struct x86_emulate_ctxt *ctxt)					\
{										\
	__sse128_u xmm;								\
	sse128_t saved_xmm0, saved_xmm1;					\
	u32 src_val, result;							\
	sse128_t reg;								\
	int rc;									\
										\
	rc = em_check_sse_prereqs(ctxt);					\
	if (rc != X86EMUL_CONTINUE)						\
		return rc;							\
										\
	if (ctxt->modrm_mod == 3) {						\
		kvm_read_sse_reg(ctxt->modrm_rm, &reg);			\
		src_val = sse128_l0(reg);					\
	} else {								\
		rc = read_modrm_mem(ctxt, &src_val, sizeof(src_val));		\
		if (rc != X86EMUL_CONTINUE)					\
			return rc;						\
	}									\
										\
	kvm_read_sse_reg((ctxt->d & Avx) ? ctxt->vex_reg : ctxt->modrm_reg,	\
			 &xmm.vec);						\
										\
	kvm_fpu_get();								\
	_kvm_read_sse_reg(0, &saved_xmm0);					\
	_kvm_read_sse_reg(1, &saved_xmm1);					\
	rc = asm_safe("movss %[dst_val], %%xmm0; " _insn " %[src], %%xmm0; "	\
		      "movss %%xmm0, %[result]",				\
		      , [result] "=m" (result)					\
		      : [dst_val] "m" (xmm.as_u32[0]), [src] "m" (src_val)	\
		      );							\
	_kvm_write_sse_reg(0, &saved_xmm0);					\
	_kvm_write_sse_reg(1, &saved_xmm1);					\
	kvm_fpu_put();								\
	if (rc != X86EMUL_CONTINUE)						\
		return emulate_simd_fp_exception(ctxt);				\
										\
	xmm.as_u32[0] = result;						\
	write_xmm_reg(ctxt, ctxt->modrm_reg, &xmm.vec);			\
	ctxt->dst.type = OP_NONE;						\
	return X86EMUL_CONTINUE;						\
}

SSE_SCALAR_SS_OP(em_addss, "addss")
SSE_SCALAR_SS_OP(em_subss, "subss")
SSE_SCALAR_SS_OP(em_mulss, "mulss")
SSE_SCALAR_SS_OP(em_divss, "divss")
SSE_SCALAR_SS_OP(em_minss, "minss")
SSE_SCALAR_SS_OP(em_maxss, "maxss")
SSE_SCALAR_SS_OP(em_sqrtss, "sqrtss")

/*
 * Scalar double-precision arithmetic: ADDSD, SUBSD, MULSD, DIVSD, MINSD, MAXSD.
 * Legacy preserves bits[127:64] of dest, VEX copies from VEX.vvvv.
 */
#define SSE_SCALAR_SD_OP(_name, _insn)						\
static int _name(struct x86_emulate_ctxt *ctxt)					\
{										\
	__sse128_u xmm;								\
	sse128_t saved_xmm0, saved_xmm1;					\
	u64 src_val, result;							\
	sse128_t reg;								\
	int rc;									\
										\
	rc = em_check_sse_prereqs(ctxt);					\
	if (rc != X86EMUL_CONTINUE)						\
		return rc;							\
										\
	if (ctxt->modrm_mod == 3) {						\
		kvm_read_sse_reg(ctxt->modrm_rm, &reg);			\
		src_val = sse128_lo(reg);					\
	} else {								\
		rc = read_modrm_mem(ctxt, &src_val, sizeof(src_val));		\
		if (rc != X86EMUL_CONTINUE)					\
			return rc;						\
	}									\
										\
	kvm_read_sse_reg((ctxt->d & Avx) ? ctxt->vex_reg : ctxt->modrm_reg,	\
			 &xmm.vec);						\
										\
	kvm_fpu_get();								\
	_kvm_read_sse_reg(0, &saved_xmm0);					\
	_kvm_read_sse_reg(1, &saved_xmm1);					\
	rc = asm_safe("movsd %[dst_val], %%xmm0; " _insn " %[src], %%xmm0; "	\
		      "movsd %%xmm0, %[result]",				\
		      , [result] "=m" (result)					\
		      : [dst_val] "m" (xmm.as_u64[0]), [src] "m" (src_val)	\
		      );							\
	_kvm_write_sse_reg(0, &saved_xmm0);					\
	_kvm_write_sse_reg(1, &saved_xmm1);					\
	kvm_fpu_put();								\
	if (rc != X86EMUL_CONTINUE)						\
		return emulate_simd_fp_exception(ctxt);				\
										\
	xmm.as_u64[0] = result;						\
	write_xmm_reg(ctxt, ctxt->modrm_reg, &xmm.vec);			\
	ctxt->dst.type = OP_NONE;						\
	return X86EMUL_CONTINUE;						\
}

SSE_SCALAR_SD_OP(em_addsd, "addsd")
SSE_SCALAR_SD_OP(em_subsd, "subsd")
SSE_SCALAR_SD_OP(em_mulsd, "mulsd")
SSE_SCALAR_SD_OP(em_divsd, "divsd")
SSE_SCALAR_SD_OP(em_minsd, "minsd")
SSE_SCALAR_SD_OP(em_maxsd, "maxsd")
SSE_SCALAR_SD_OP(em_sqrtsd, "sqrtsd")

#undef SSE_SCALAR_SS_OP
#undef SSE_SCALAR_SD_OP

/*
 * Packed FP arithmetic macros.
 * SSE_PACKED_OP: binary ops (two sources).
 * SSE_PACKED_UNARY_OP: unary ops (one source).
 */
#define SSE_PACKED_OP(_name, _insn)						\
static int _name(struct x86_emulate_ctxt *ctxt)					\
{										\
	u8 *dst = (u8 *)ctxt->dst.valptr;					\
	u8 *src = (u8 *)ctxt->src.valptr;					\
	u8 *src1 = ctxt->src2.type == OP_NONE ? dst : (u8 *)ctxt->src2.valptr;	\
	unsigned int bytes = ctxt->dst.bytes;					\
	sse128_t saved_xmm0, saved_xmm1;					\
	u8 tmp_dst[32] __aligned(32);						\
	int i;									\
										\
	kvm_fpu_get();								\
	_kvm_read_sse_reg(0, &saved_xmm0);					\
	_kvm_read_sse_reg(1, &saved_xmm1);					\
	for (i = 0; i < bytes; i += 16) {					\
		asm volatile("movdqu %0, %%xmm0" : : "m"(*(sse128_t *)&src1[i])); \
		asm volatile(_insn " %0, %%xmm0" : : "m"(*(sse128_t *)&src[i])); \
		asm volatile("movdqu %%xmm0, %0" : "=m"(*(sse128_t *)&tmp_dst[i])); \
	}									\
	_kvm_write_sse_reg(0, &saved_xmm0);					\
	_kvm_write_sse_reg(1, &saved_xmm1);					\
	kvm_fpu_put();								\
	memcpy(dst, tmp_dst, bytes);						\
	return X86EMUL_CONTINUE;						\
}

#define SSE_PACKED_UNARY_OP(_name, _insn)					\
static int _name(struct x86_emulate_ctxt *ctxt)					\
{										\
	u8 *dst = (u8 *)ctxt->dst.valptr;					\
	u8 *src = (u8 *)ctxt->src.valptr;					\
	unsigned int bytes = ctxt->dst.bytes;					\
	sse128_t saved_xmm0;							\
	u8 tmp_dst[32] __aligned(32);						\
	int i;									\
										\
	kvm_fpu_get();								\
	_kvm_read_sse_reg(0, &saved_xmm0);					\
	for (i = 0; i < bytes; i += 16) {					\
		asm volatile(_insn " %1, %%xmm0; movdqu %%xmm0, %0"		\
			     : "=m"(*(sse128_t *)&tmp_dst[i])			\
			     : "m"(*(sse128_t *)&src[i]));			\
	}									\
	_kvm_write_sse_reg(0, &saved_xmm0);					\
	kvm_fpu_put();								\
	memcpy(dst, tmp_dst, bytes);						\
	return X86EMUL_CONTINUE;						\
}

/* Group 1: Packed FP arithmetic */
SSE_PACKED_OP(em_addps, "addps")
SSE_PACKED_OP(em_addpd, "addpd")
SSE_PACKED_OP(em_subps, "subps")
SSE_PACKED_OP(em_subpd, "subpd")
SSE_PACKED_OP(em_mulps, "mulps")
SSE_PACKED_OP(em_mulpd, "mulpd")
SSE_PACKED_OP(em_divps, "divps")
SSE_PACKED_OP(em_divpd, "divpd")
SSE_PACKED_OP(em_minps, "minps")
SSE_PACKED_OP(em_minpd, "minpd")
SSE_PACKED_OP(em_maxps, "maxps")
SSE_PACKED_OP(em_maxpd, "maxpd")

SSE_PACKED_UNARY_OP(em_sqrtps, "sqrtps")
SSE_PACKED_UNARY_OP(em_sqrtpd, "sqrtpd")
SSE_PACKED_UNARY_OP(em_rcpps, "rcpps")
SSE_PACKED_UNARY_OP(em_rsqrtps, "rsqrtps")

/* Conversion instructions */
SSE_PACKED_UNARY_OP(em_cvtdq2ps, "cvtdq2ps")
SSE_PACKED_UNARY_OP(em_cvtps2dq, "cvtps2dq")
SSE_PACKED_UNARY_OP(em_cvttps2dq, "cvttps2dq")
SSE_PACKED_UNARY_OP(em_cvtpd2dq, "cvtpd2dq")
SSE_PACKED_UNARY_OP(em_cvttpd2dq, "cvttpd2dq")
SSE_PACKED_UNARY_OP(em_cvtpd2ps, "cvtpd2ps")

/*
 * CVTPS2PD / VCVTPS2PD (NP 0F 5A) and CVTDQ2PD / VCVTDQ2PD (F3 0F E6).
 * These widen the source: the memory operand is half the destination width.
 *   128-bit form: xmm, xmm/m64   — 8B src -> 16B dst
 *   256-bit form: ymm, xmm/m128 — 16B src -> 32B dst
 * The default SrcMem decode path fetches op_bytes (16/32) from memory, which
 * over-reads by 2x.  On MMIO the extra bytes can straddle an unmapped page
 * and raise a spurious #PF; the guest then reports SIGSEGV on an instruction
 * that was a valid narrow load in reality.  We fetch exactly src_bytes.
 */
#define SSE_WIDEN_PACKED_UNARY_OP(_name, _insn)				\
static int _name(struct x86_emulate_ctxt *ctxt)				\
{									\
	u8 src_buf[16] __aligned(16) = { 0 };				\
	u8 dst_buf[32] __aligned(32) = { 0 };				\
	sse128_t saved_xmm0;						\
	unsigned int dst_bytes = ctxt->op_bytes;			\
	unsigned int src_bytes = dst_bytes / 2;				\
	int rc, i;							\
									\
	rc = em_check_sse_prereqs(ctxt);				\
	if (rc != X86EMUL_CONTINUE)					\
		return rc;						\
									\
	if (ctxt->modrm_mod == 3) {					\
		sse128_t reg;						\
		kvm_read_sse_reg(ctxt->modrm_rm, &reg);			\
		memcpy(src_buf, &reg, src_bytes);			\
	} else {							\
		rc = read_modrm_mem(ctxt, src_buf, src_bytes);		\
		if (rc != X86EMUL_CONTINUE)				\
			return rc;					\
	}								\
									\
	kvm_fpu_get();							\
	_kvm_read_sse_reg(0, &saved_xmm0);				\
	for (i = 0; i < dst_bytes; i += 16) {				\
		asm volatile(_insn " %1, %%xmm0; movdqu %%xmm0, %0"	\
			     : "=m"(*(sse128_t *)&dst_buf[i])		\
			     : "m"(*(u64 *)&src_buf[i / 2]));		\
	}								\
	_kvm_write_sse_reg(0, &saved_xmm0);				\
	kvm_fpu_put();							\
									\
	if (dst_bytes == 32) {						\
		avx256_t ymm;						\
		memcpy(&ymm, dst_buf, 32);				\
		kvm_write_avx_reg(ctxt->modrm_reg, &ymm);		\
	} else {							\
		sse128_t xmm;						\
		memcpy(&xmm, dst_buf, 16);				\
		write_xmm_reg(ctxt, ctxt->modrm_reg, &xmm);		\
	}								\
	ctxt->dst.type = OP_NONE;					\
	return X86EMUL_CONTINUE;					\
}

SSE_WIDEN_PACKED_UNARY_OP(em_cvtps2pd, "cvtps2pd")
SSE_WIDEN_PACKED_UNARY_OP(em_cvtdq2pd, "cvtdq2pd")

/* AES-NI instructions */
SSE_PACKED_OP(em_aesenc, "aesenc")
SSE_PACKED_OP(em_aesdec, "aesdec")
SSE_PACKED_OP(em_aesenclast, "aesenclast")
SSE_PACKED_OP(em_aesdeclast, "aesdeclast")
SSE_PACKED_UNARY_OP(em_aesimc, "aesimc")

/* CMP packed/scalar with imm8 predicate */

/* Horizontal add/sub */
SSE_PACKED_OP(em_haddps, "haddps")
SSE_PACKED_OP(em_haddpd, "haddpd")
SSE_PACKED_OP(em_hsubps, "hsubps")
SSE_PACKED_OP(em_hsubpd, "hsubpd")

/* Unpack/interleave FP */
SSE_PACKED_OP(em_unpcklps, "unpcklps")
SSE_PACKED_OP(em_unpckhps, "unpckhps")
SSE_PACKED_OP(em_unpcklpd, "unpcklpd")
SSE_PACKED_OP(em_unpckhpd, "unpckhpd")

/* PACK/PUNPCK integer operations using host CPU */
SSE_PACKED_OP(em_punpcklbw, "punpcklbw")
SSE_PACKED_OP(em_punpcklwd, "punpcklwd")
SSE_PACKED_OP(em_punpckldq, "punpckldq")
SSE_PACKED_OP(em_packsswb, "packsswb")
SSE_PACKED_OP(em_packuswb, "packuswb")
SSE_PACKED_OP(em_punpckhbw, "punpckhbw")
SSE_PACKED_OP(em_punpckhwd, "punpckhwd")
SSE_PACKED_OP(em_punpckhdq, "punpckhdq")
SSE_PACKED_OP(em_packssdw, "packssdw")
SSE_PACKED_OP(em_punpcklqdq, "punpcklqdq")
SSE_PACKED_OP(em_punpckhqdq, "punpckhqdq")

/* Saturating add/sub */
SSE_PACKED_OP(em_paddsb, "paddsb")
SSE_PACKED_OP(em_paddsw, "paddsw")
SSE_PACKED_OP(em_paddusb, "paddusb")
SSE_PACKED_OP(em_paddusw, "paddusw")
SSE_PACKED_OP(em_psubsb, "psubsb")
SSE_PACKED_OP(em_psubsw, "psubsw")
SSE_PACKED_OP(em_psubusb, "psubusb")
SSE_PACKED_OP(em_psubusw, "psubusw")

/* More min/max */
SSE_PACKED_OP(em_pmaxub, "pmaxub")
SSE_PACKED_OP(em_pmaxsw, "pmaxsw")
SSE_PACKED_OP(em_pminsw, "pminsw")

/* Multiply variants */
SSE_PACKED_OP(em_pmulhw, "pmulhw")
SSE_PACKED_OP(em_pmulhuw, "pmulhuw")
SSE_PACKED_OP(em_pmuludq, "pmuludq")

/* PMADDWD, PSADBW */
SSE_PACKED_OP(em_pmaddwd, "pmaddwd")
SSE_PACKED_OP(em_psadbw, "psadbw")

/* PAVGW */
SSE_PACKED_OP(em_pavgw, "pavgw")

/* SSE3: Alternating add/subtract */
SSE_PACKED_OP(em_addsubps, "addsubps")
SSE_PACKED_OP(em_addsubpd, "addsubpd")

#undef SSE_PACKED_OP
#undef SSE_PACKED_UNARY_OP

/*
 * PSHUFB (66 0F 38 00): Shuffle bytes using control mask.
 * For each byte i: if src[i] & 0x80, dst[i] = 0; else dst[i] = src1[src[i] & 0xF]
 * 256-bit: each 128-bit lane is independent.
 */
static int em_pshufb(struct x86_emulate_ctxt *ctxt)
{
	u8 *dst = (u8 *)ctxt->dst.valptr;
	u8 *src = (u8 *)ctxt->src.valptr;
	u8 *src1 = ctxt->src2.type == OP_NONE ? dst : (u8 *)ctxt->src2.valptr;
	u8 tmp[32];
	int i;

	for (i = 0; i < ctxt->dst.bytes; i++) {
		int lane_base = (i / 16) * 16;
		if (src[i] & 0x80)
			tmp[i] = 0;
		else
			tmp[i] = src1[lane_base + (src[i] & 0x0F)];
	}
	memcpy(dst, tmp, ctxt->dst.bytes);
	return X86EMUL_CONTINUE;
}

/*
 * PSHUFD (66 0F 70): Shuffle packed dwords with imm8.
 * dst[0] = src[imm & 3], dst[1] = src[(imm>>2) & 3], etc.
 * 256-bit: each 128-bit lane is independent.
 */
static int em_pshufd(struct x86_emulate_ctxt *ctxt)
{
	u32 *dst = (u32 *)ctxt->dst.valptr;
	u32 *src = (u32 *)ctxt->src.valptr;
	u32 tmp[8];
	u8 imm;
	int rc, i;

	rc = do_insn_fetch_bytes(ctxt, 1);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	imm = *ctxt->fetch.ptr++;

	for (i = 0; i < ctxt->dst.bytes / 4; i++) {
		int lane_base = (i / 4) * 4;
		int sel = (imm >> ((i % 4) * 2)) & 3;
		tmp[i] = src[lane_base + sel];
	}
	memcpy(dst, tmp, ctxt->dst.bytes);
	return X86EMUL_CONTINUE;
}

/*
 * PSHUFHW (F3 0F 70): Shuffle high words with imm8.
 * Low qword copied, high qword shuffled.
 */
static int em_pshufhw(struct x86_emulate_ctxt *ctxt)
{
	u16 *dst = (u16 *)ctxt->dst.valptr;
	u16 *src = (u16 *)ctxt->src.valptr;
	u16 tmp[16];
	u8 imm;
	int rc, i, lane;

	rc = do_insn_fetch_bytes(ctxt, 1);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	imm = *ctxt->fetch.ptr++;

	for (lane = 0; lane < ctxt->dst.bytes / 16; lane++) {
		int base = lane * 8;
		/* Copy low 4 words */
		for (i = 0; i < 4; i++)
			tmp[base + i] = src[base + i];
		/* Shuffle high 4 words */
		for (i = 0; i < 4; i++)
			tmp[base + 4 + i] = src[base + 4 + ((imm >> (i * 2)) & 3)];
	}
	memcpy(dst, tmp, ctxt->dst.bytes);
	return X86EMUL_CONTINUE;
}

/*
 * PSHUFLW (F2 0F 70): Shuffle low words with imm8.
 * High qword copied, low qword shuffled.
 */
static int em_pshuflw(struct x86_emulate_ctxt *ctxt)
{
	u16 *dst = (u16 *)ctxt->dst.valptr;
	u16 *src = (u16 *)ctxt->src.valptr;
	u16 tmp[16];
	u8 imm;
	int rc, i, lane;

	rc = do_insn_fetch_bytes(ctxt, 1);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	imm = *ctxt->fetch.ptr++;

	for (lane = 0; lane < ctxt->dst.bytes / 16; lane++) {
		int base = lane * 8;
		/* Shuffle low 4 words */
		for (i = 0; i < 4; i++)
			tmp[base + i] = src[base + ((imm >> (i * 2)) & 3)];
		/* Copy high 4 words */
		for (i = 4; i < 8; i++)
			tmp[base + i] = src[base + i];
	}
	memcpy(dst, tmp, ctxt->dst.bytes);
	return X86EMUL_CONTINUE;
}

/*
 * SHUFPS (NP 0F C6): Shuffle packed single-precision with imm8.
 * For 128-bit: dst[0]=src1[imm&3], dst[1]=src1[(imm>>2)&3],
 *              dst[2]=src[(imm>>4)&3], dst[3]=src[(imm>>6)&3]
 */
static int em_shufps(struct x86_emulate_ctxt *ctxt)
{
	u32 *dst = (u32 *)ctxt->dst.valptr;
	u32 *src = (u32 *)ctxt->src.valptr;
	u32 *src1 = ctxt->src2.type == OP_NONE ? dst : (u32 *)ctxt->src2.valptr;
	u32 tmp[8];
	u8 imm;
	int rc, lane;

	rc = do_insn_fetch_bytes(ctxt, 1);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	imm = *ctxt->fetch.ptr++;

	for (lane = 0; lane < ctxt->dst.bytes / 16; lane++) {
		int base = lane * 4;
		tmp[base + 0] = src1[base + (imm & 3)];
		tmp[base + 1] = src1[base + ((imm >> 2) & 3)];
		tmp[base + 2] = src[base + ((imm >> 4) & 3)];
		tmp[base + 3] = src[base + ((imm >> 6) & 3)];
	}
	memcpy(dst, tmp, ctxt->dst.bytes);
	return X86EMUL_CONTINUE;
}

/*
 * SHUFPD (66 0F C6): Shuffle packed double-precision with imm8.
 * For 128-bit: dst[0]=src1[imm&1], dst[1]=src[(imm>>1)&1]
 */
static int em_shufpd(struct x86_emulate_ctxt *ctxt)
{
	u64 *dst = (u64 *)ctxt->dst.valptr;
	u64 *src = (u64 *)ctxt->src.valptr;
	u64 *src1 = ctxt->src2.type == OP_NONE ? dst : (u64 *)ctxt->src2.valptr;
	u64 tmp[4];
	u8 imm;
	int rc, lane;

	rc = do_insn_fetch_bytes(ctxt, 1);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	imm = *ctxt->fetch.ptr++;

	for (lane = 0; lane < ctxt->dst.bytes / 16; lane++) {
		int base = lane * 2;
		int shift = lane * 2;
		tmp[base + 0] = src1[base + ((imm >> shift) & 1)];
		tmp[base + 1] = src[base + ((imm >> (shift + 1)) & 1)];
	}
	memcpy(dst, tmp, ctxt->dst.bytes);
	return X86EMUL_CONTINUE;
}

/*
 * CMPPS with imm8 (NP 0F C2): Compare packed singles.
 * CMPPD with imm8 (66 0F C2): Compare packed doubles.
 * CMPSS with imm8 (F3 0F C2): Compare scalar single.
 * CMPSD with imm8 (F2 0F C2): Compare scalar double.
 * These need the actual FPU. The imm8 selects the comparison predicate.
 */
static int em_cmpps_imm(struct x86_emulate_ctxt *ctxt)
{
	u8 *dst = (u8 *)ctxt->dst.valptr;
	u8 *src = (u8 *)ctxt->src.valptr;
	u8 *src1 = ctxt->src2.type == OP_NONE ? dst : (u8 *)ctxt->src2.valptr;
	unsigned int bytes = ctxt->dst.bytes;
	sse128_t saved_xmm0, saved_xmm1;
	u8 tmp_dst[32] __aligned(32);
	u8 imm;
	int rc, i;

	rc = do_insn_fetch_bytes(ctxt, 1);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	imm = *ctxt->fetch.ptr++;

	kvm_fpu_get();
	_kvm_read_sse_reg(0, &saved_xmm0);
	_kvm_read_sse_reg(1, &saved_xmm1);
	for (i = 0; i < bytes; i += 16) {
		asm volatile("movdqu %0, %%xmm0" : : "m"(*(sse128_t *)&src1[i]));
		asm volatile("movdqu %0, %%xmm1" : : "m"(*(sse128_t *)&src[i]));
		switch (imm & 7) {
		case 0: asm volatile("cmpeqps %%xmm1, %%xmm0" :::); break;
		case 1: asm volatile("cmpltps %%xmm1, %%xmm0" :::); break;
		case 2: asm volatile("cmpleps %%xmm1, %%xmm0" :::); break;
		case 3: asm volatile("cmpunordps %%xmm1, %%xmm0" :::); break;
		case 4: asm volatile("cmpneqps %%xmm1, %%xmm0" :::); break;
		case 5: asm volatile("cmpnltps %%xmm1, %%xmm0" :::); break;
		case 6: asm volatile("cmpnleps %%xmm1, %%xmm0" :::); break;
		case 7: asm volatile("cmpordps %%xmm1, %%xmm0" :::); break;
		}
		asm volatile("movdqu %%xmm0, %0" : "=m"(*(sse128_t *)&tmp_dst[i]));
	}
	_kvm_write_sse_reg(0, &saved_xmm0);
	_kvm_write_sse_reg(1, &saved_xmm1);
	kvm_fpu_put();
	memcpy(dst, tmp_dst, bytes);
	return X86EMUL_CONTINUE;
}

static int em_cmppd_imm(struct x86_emulate_ctxt *ctxt)
{
	u8 *dst = (u8 *)ctxt->dst.valptr;
	u8 *src = (u8 *)ctxt->src.valptr;
	u8 *src1 = ctxt->src2.type == OP_NONE ? dst : (u8 *)ctxt->src2.valptr;
	unsigned int bytes = ctxt->dst.bytes;
	sse128_t saved_xmm0, saved_xmm1;
	u8 tmp_dst[32] __aligned(32);
	u8 imm;
	int rc, i;

	rc = do_insn_fetch_bytes(ctxt, 1);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	imm = *ctxt->fetch.ptr++;

	kvm_fpu_get();
	_kvm_read_sse_reg(0, &saved_xmm0);
	_kvm_read_sse_reg(1, &saved_xmm1);
	for (i = 0; i < bytes; i += 16) {
		asm volatile("movdqu %0, %%xmm0" : : "m"(*(sse128_t *)&src1[i]));
		asm volatile("movdqu %0, %%xmm1" : : "m"(*(sse128_t *)&src[i]));
		switch (imm & 7) {
		case 0: asm volatile("cmpeqpd %%xmm1, %%xmm0" :::); break;
		case 1: asm volatile("cmpltpd %%xmm1, %%xmm0" :::); break;
		case 2: asm volatile("cmplepd %%xmm1, %%xmm0" :::); break;
		case 3: asm volatile("cmpunordpd %%xmm1, %%xmm0" :::); break;
		case 4: asm volatile("cmpneqpd %%xmm1, %%xmm0" :::); break;
		case 5: asm volatile("cmpnltpd %%xmm1, %%xmm0" :::); break;
		case 6: asm volatile("cmpnlepd %%xmm1, %%xmm0" :::); break;
		case 7: asm volatile("cmpordpd %%xmm1, %%xmm0" :::); break;
		}
		asm volatile("movdqu %%xmm0, %0" : "=m"(*(sse128_t *)&tmp_dst[i]));
	}
	_kvm_write_sse_reg(0, &saved_xmm0);
	_kvm_write_sse_reg(1, &saved_xmm1);
	kvm_fpu_put();
	memcpy(dst, tmp_dst, bytes);
	return X86EMUL_CONTINUE;
}

/*
 * CMPSS (F3 0F C2): Compare scalar single with imm8.
 */
static int em_cmpss_imm(struct x86_emulate_ctxt *ctxt)
{
	__sse128_u xmm;
	sse128_t saved_xmm0, saved_xmm1;
	u32 src_val, result;
	sse128_t reg;
	u8 imm;
	int rc;

	rc = em_check_sse_prereqs(ctxt);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	if (ctxt->modrm_mod == 3) {
		kvm_read_sse_reg(ctxt->modrm_rm, &reg);
		src_val = sse128_l0(reg);
	} else {
		rc = read_modrm_mem(ctxt, &src_val, sizeof(src_val));
		if (rc != X86EMUL_CONTINUE)
			return rc;
	}

	rc = do_insn_fetch_bytes(ctxt, 1);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	imm = *ctxt->fetch.ptr++;

	kvm_read_sse_reg((ctxt->d & Avx) ? ctxt->vex_reg : ctxt->modrm_reg,
			 &xmm.vec);

	kvm_fpu_get();
	_kvm_read_sse_reg(0, &saved_xmm0);
	_kvm_read_sse_reg(1, &saved_xmm1);
	asm volatile("movss %0, %%xmm0" : : "m"(xmm.as_u32[0]));
	asm volatile("movss %0, %%xmm1" : : "m"(src_val));
	switch (imm & 7) {
	case 0: asm volatile("cmpeqss %%xmm1, %%xmm0" :::); break;
	case 1: asm volatile("cmpltss %%xmm1, %%xmm0" :::); break;
	case 2: asm volatile("cmpless %%xmm1, %%xmm0" :::); break;
	case 3: asm volatile("cmpunordss %%xmm1, %%xmm0" :::); break;
	case 4: asm volatile("cmpneqss %%xmm1, %%xmm0" :::); break;
	case 5: asm volatile("cmpnltss %%xmm1, %%xmm0" :::); break;
	case 6: asm volatile("cmpnless %%xmm1, %%xmm0" :::); break;
	case 7: asm volatile("cmpordss %%xmm1, %%xmm0" :::); break;
	}
	asm volatile("movss %%xmm0, %0" : "=m"(result));
	_kvm_write_sse_reg(0, &saved_xmm0);
	_kvm_write_sse_reg(1, &saved_xmm1);
	kvm_fpu_put();

	xmm.as_u32[0] = result;
	write_xmm_reg(ctxt, ctxt->modrm_reg, &xmm.vec);
	ctxt->dst.type = OP_NONE;
	return X86EMUL_CONTINUE;
}

/*
 * CMPSD (F2 0F C2): Compare scalar double with imm8.
 */
static int em_cmpsd_imm(struct x86_emulate_ctxt *ctxt)
{
	__sse128_u xmm;
	sse128_t saved_xmm0, saved_xmm1;
	u64 src_val, result;
	sse128_t reg;
	u8 imm;
	int rc;

	rc = em_check_sse_prereqs(ctxt);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	if (ctxt->modrm_mod == 3) {
		kvm_read_sse_reg(ctxt->modrm_rm, &reg);
		src_val = sse128_lo(reg);
	} else {
		rc = read_modrm_mem(ctxt, &src_val, sizeof(src_val));
		if (rc != X86EMUL_CONTINUE)
			return rc;
	}

	rc = do_insn_fetch_bytes(ctxt, 1);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	imm = *ctxt->fetch.ptr++;

	kvm_read_sse_reg((ctxt->d & Avx) ? ctxt->vex_reg : ctxt->modrm_reg,
			 &xmm.vec);

	kvm_fpu_get();
	_kvm_read_sse_reg(0, &saved_xmm0);
	_kvm_read_sse_reg(1, &saved_xmm1);
	asm volatile("movsd %0, %%xmm0" : : "m"(xmm.as_u64[0]));
	asm volatile("movsd %0, %%xmm1" : : "m"(src_val));
	switch (imm & 7) {
	case 0: asm volatile("cmpeqsd %%xmm1, %%xmm0" :::); break;
	case 1: asm volatile("cmpltsd %%xmm1, %%xmm0" :::); break;
	case 2: asm volatile("cmplesd %%xmm1, %%xmm0" :::); break;
	case 3: asm volatile("cmpunordsd %%xmm1, %%xmm0" :::); break;
	case 4: asm volatile("cmpneqsd %%xmm1, %%xmm0" :::); break;
	case 5: asm volatile("cmpnltsd %%xmm1, %%xmm0" :::); break;
	case 6: asm volatile("cmpnlesd %%xmm1, %%xmm0" :::); break;
	case 7: asm volatile("cmpordsd %%xmm1, %%xmm0" :::); break;
	}
	asm volatile("movsd %%xmm0, %0" : "=m"(result));
	_kvm_write_sse_reg(0, &saved_xmm0);
	_kvm_write_sse_reg(1, &saved_xmm1);
	kvm_fpu_put();

	xmm.as_u64[0] = result;
	write_xmm_reg(ctxt, ctxt->modrm_reg, &xmm.vec);
	ctxt->dst.type = OP_NONE;
	return X86EMUL_CONTINUE;
}

/*
 * PABSB/PABSW/PABSD (66 0F 38 1C/1D/1E): Absolute value.
 */
static int em_pabsb(struct x86_emulate_ctxt *ctxt)
{
	s8 *src = (s8 *)ctxt->src.valptr;
	u8 *dst = (u8 *)ctxt->dst.valptr;
	int i;

	for (i = 0; i < ctxt->dst.bytes; i++)
		dst[i] = (src[i] < 0) ? -src[i] : src[i];
	return X86EMUL_CONTINUE;
}

static int em_pabsw(struct x86_emulate_ctxt *ctxt)
{
	s16 *src = (s16 *)ctxt->src.valptr;
	u16 *dst = (u16 *)ctxt->dst.valptr;
	int i;

	for (i = 0; i < ctxt->dst.bytes / 2; i++)
		dst[i] = (src[i] < 0) ? -src[i] : src[i];
	return X86EMUL_CONTINUE;
}

static int em_pabsd(struct x86_emulate_ctxt *ctxt)
{
	s32 *src = (s32 *)ctxt->src.valptr;
	u32 *dst = (u32 *)ctxt->dst.valptr;
	int i;

	for (i = 0; i < ctxt->dst.bytes / 4; i++)
		dst[i] = (src[i] < 0) ? -src[i] : src[i];
	return X86EMUL_CONTINUE;
}

/*
 * PMULDQ (66 0F 38 28): Multiply packed signed dword integers, producing
 * packed signed qword results.
 */
static int em_pmuldq(struct x86_emulate_ctxt *ctxt)
{
	u8 *dst_b = (u8 *)ctxt->dst.valptr;
	u8 *src_b = (u8 *)ctxt->src.valptr;
	u8 *src1_b = ctxt->src2.type == OP_NONE ? dst_b : (u8 *)ctxt->src2.valptr;
	int i;

	for (i = 0; i < ctxt->dst.bytes / 8; i++) {
		s32 a, b;
		s64 result;
		memcpy(&a, &src1_b[i * 8], 4);
		memcpy(&b, &src_b[i * 8], 4);
		result = (s64)a * (s64)b;
		memcpy(&dst_b[i * 8], &result, 8);
	}
	return X86EMUL_CONTINUE;
}

/*
 * PMAXSB (66 0F 38 3C): Packed maximum of signed bytes.
 */
static int em_pmaxsb(struct x86_emulate_ctxt *ctxt)
{
	s8 *dst = (s8 *)ctxt->dst.valptr;
	s8 *src = (s8 *)ctxt->src.valptr;
	s8 *src1 = ctxt->src2.type == OP_NONE ? dst : (s8 *)ctxt->src2.valptr;
	int i;

	for (i = 0; i < ctxt->dst.bytes; i++)
		dst[i] = (src1[i] > src[i]) ? src1[i] : src[i];
	return X86EMUL_CONTINUE;
}

/*
 * PMAXSD (66 0F 38 3D): Packed maximum of signed dwords.
 */
static int em_pmaxsd(struct x86_emulate_ctxt *ctxt)
{
	s32 *dst = (s32 *)ctxt->dst.valptr;
	s32 *src = (s32 *)ctxt->src.valptr;
	s32 *src1 = ctxt->src2.type == OP_NONE ? dst : (s32 *)ctxt->src2.valptr;
	int i;

	for (i = 0; i < ctxt->dst.bytes / 4; i++)
		dst[i] = (src1[i] > src[i]) ? src1[i] : src[i];
	return X86EMUL_CONTINUE;
}

/*
 * PMAXUW (66 0F 38 3E): Packed maximum of unsigned words.
 */
static int em_pmaxuw(struct x86_emulate_ctxt *ctxt)
{
	u16 *dst = (u16 *)ctxt->dst.valptr;
	u16 *src = (u16 *)ctxt->src.valptr;
	u16 *src1 = ctxt->src2.type == OP_NONE ? dst : (u16 *)ctxt->src2.valptr;
	int i;

	for (i = 0; i < ctxt->dst.bytes / 2; i++)
		dst[i] = (src1[i] > src[i]) ? src1[i] : src[i];
	return X86EMUL_CONTINUE;
}

/*
 * PMINSB (66 0F 38 38): Packed minimum of signed bytes.
 */
static int em_pminsb(struct x86_emulate_ctxt *ctxt)
{
	s8 *dst = (s8 *)ctxt->dst.valptr;
	s8 *src = (s8 *)ctxt->src.valptr;
	s8 *src1 = ctxt->src2.type == OP_NONE ? dst : (s8 *)ctxt->src2.valptr;
	int i;

	for (i = 0; i < ctxt->dst.bytes; i++)
		dst[i] = (src1[i] < src[i]) ? src1[i] : src[i];
	return X86EMUL_CONTINUE;
}

/*
 * PMINSD (66 0F 38 39): Packed minimum of signed dwords.
 */
static int em_pminsd(struct x86_emulate_ctxt *ctxt)
{
	s32 *dst = (s32 *)ctxt->dst.valptr;
	s32 *src = (s32 *)ctxt->src.valptr;
	s32 *src1 = ctxt->src2.type == OP_NONE ? dst : (s32 *)ctxt->src2.valptr;
	int i;

	for (i = 0; i < ctxt->dst.bytes / 4; i++)
		dst[i] = (src1[i] < src[i]) ? src1[i] : src[i];
	return X86EMUL_CONTINUE;
}

/*
 * PMINUW (66 0F 38 3A): Packed minimum of unsigned words.
 */
static int em_pminuw(struct x86_emulate_ctxt *ctxt)
{
	u16 *dst = (u16 *)ctxt->dst.valptr;
	u16 *src = (u16 *)ctxt->src.valptr;
	u16 *src1 = ctxt->src2.type == OP_NONE ? dst : (u16 *)ctxt->src2.valptr;
	int i;

	for (i = 0; i < ctxt->dst.bytes / 2; i++)
		dst[i] = (src1[i] < src[i]) ? src1[i] : src[i];
	return X86EMUL_CONTINUE;
}

/*
 * PMOVSXxx / PMOVZXxx (66 0F 38 20-25, 30-35) and VEX 256-bit forms.
 * Same shape as CVTPS2PD/CVTDQ2PD: memory source is narrower than the
 * destination (src_bytes = dst_bytes >> _shift).  The generic SrcMem
 * auto-fetch would read op_bytes (16 SSE / 32 AVX), over-reading up to
 * 30 bytes (PMOVZXBQ ymm: need 4, fetch 32) and tripping SIGSEGV on
 * MMIO when the extra bytes cross an unmapped page.  We fetch exactly
 * src_bytes and then run the real hardware widen per 128-bit lane.
 *   _shift=1: 2x widen (BW/WD/DQ, src=dst/2)
 *   _shift=2: 4x widen (BD/WQ,    src=dst/4)
 *   _shift=3: 8x widen (BQ,       src=dst/8)
 */
#define SSE_WIDEN_PACKED_SX_OP(_name, _insn, _shift)			\
static int _name(struct x86_emulate_ctxt *ctxt)				\
{									\
	u8 src_buf[32] __aligned(32) = { 0 };				\
	u8 dst_buf[32] __aligned(32) = { 0 };				\
	sse128_t saved_xmm0;						\
	unsigned int dst_bytes = ctxt->op_bytes;			\
	unsigned int src_bytes = dst_bytes >> (_shift);			\
	unsigned int per_lane_src = 16u >> (_shift);			\
	int rc, i;							\
									\
	rc = em_check_sse_prereqs(ctxt);				\
	if (rc != X86EMUL_CONTINUE)					\
		return rc;						\
									\
	if (ctxt->modrm_mod == 3) {					\
		sse128_t reg;						\
		kvm_read_sse_reg(ctxt->modrm_rm, &reg);			\
		memcpy(src_buf, &reg, src_bytes);			\
	} else {							\
		rc = read_modrm_mem(ctxt, src_buf, src_bytes);		\
		if (rc != X86EMUL_CONTINUE)				\
			return rc;					\
	}								\
									\
	kvm_fpu_get();							\
	_kvm_read_sse_reg(0, &saved_xmm0);				\
	for (i = 0; i < dst_bytes; i += 16) {				\
		asm volatile(_insn " %1, %%xmm0; movdqu %%xmm0, %0"	\
			     : "=m"(*(sse128_t *)&dst_buf[i])		\
			     : "m"(src_buf[(i / 16) * per_lane_src]));	\
	}								\
	_kvm_write_sse_reg(0, &saved_xmm0);				\
	kvm_fpu_put();							\
									\
	if (dst_bytes == 32) {						\
		avx256_t ymm;						\
		memcpy(&ymm, dst_buf, 32);				\
		kvm_write_avx_reg(ctxt->modrm_reg, &ymm);		\
	} else {							\
		sse128_t xmm;						\
		memcpy(&xmm, dst_buf, 16);				\
		write_xmm_reg(ctxt, ctxt->modrm_reg, &xmm);		\
	}								\
	ctxt->dst.type = OP_NONE;					\
	return X86EMUL_CONTINUE;					\
}

SSE_WIDEN_PACKED_SX_OP(em_pmovsxbw, "pmovsxbw", 1)
SSE_WIDEN_PACKED_SX_OP(em_pmovsxbd, "pmovsxbd", 2)
SSE_WIDEN_PACKED_SX_OP(em_pmovsxbq, "pmovsxbq", 3)
SSE_WIDEN_PACKED_SX_OP(em_pmovsxwd, "pmovsxwd", 1)
SSE_WIDEN_PACKED_SX_OP(em_pmovsxwq, "pmovsxwq", 2)
SSE_WIDEN_PACKED_SX_OP(em_pmovsxdq, "pmovsxdq", 1)
SSE_WIDEN_PACKED_SX_OP(em_pmovzxbw, "pmovzxbw", 1)
SSE_WIDEN_PACKED_SX_OP(em_pmovzxbd, "pmovzxbd", 2)
SSE_WIDEN_PACKED_SX_OP(em_pmovzxbq, "pmovzxbq", 3)
SSE_WIDEN_PACKED_SX_OP(em_pmovzxwd, "pmovzxwd", 1)
SSE_WIDEN_PACKED_SX_OP(em_pmovzxwq, "pmovzxwq", 2)
SSE_WIDEN_PACKED_SX_OP(em_pmovzxdq, "pmovzxdq", 1)

/*
 * PTEST (66 0F 38 17): Set ZF if (src AND dst) == 0, CF if (src ANDNOT dst) == 0.
 */
static int em_ptest(struct x86_emulate_ctxt *ctxt)
{
	u64 *dst = (u64 *)ctxt->dst.valptr;
	u64 *src = (u64 *)ctxt->src.valptr;
	int i;
	u64 and_result = 0, andn_result = 0;

	for (i = 0; i < ctxt->dst.bytes / 8; i++) {
		and_result |= (dst[i] & src[i]);
		andn_result |= (~dst[i] & src[i]);
	}

	ctxt->eflags &= ~(X86_EFLAGS_ZF | X86_EFLAGS_CF | X86_EFLAGS_AF |
			   X86_EFLAGS_OF | X86_EFLAGS_PF | X86_EFLAGS_SF);
	if (and_result == 0)
		ctxt->eflags |= X86_EFLAGS_ZF;
	if (andn_result == 0)
		ctxt->eflags |= X86_EFLAGS_CF;

	ctxt->dst.type = OP_NONE;
	return X86EMUL_CONTINUE;
}

/*
 * PSIGNB/PSIGNW/PSIGND (66 0F 38 08/09/0A): Packed sign.
 * For each element: if src < 0, dst = -src1; if src == 0, dst = 0; if src > 0, dst = src1.
 */
static int em_psignb(struct x86_emulate_ctxt *ctxt)
{
	s8 *dst = (s8 *)ctxt->dst.valptr;
	s8 *src = (s8 *)ctxt->src.valptr;
	s8 *src1 = ctxt->src2.type == OP_NONE ? dst : (s8 *)ctxt->src2.valptr;
	int i;

	for (i = 0; i < ctxt->dst.bytes; i++) {
		if (src[i] < 0)
			dst[i] = -src1[i];
		else if (src[i] == 0)
			dst[i] = 0;
		else
			dst[i] = src1[i];
	}
	return X86EMUL_CONTINUE;
}

static int em_psignw(struct x86_emulate_ctxt *ctxt)
{
	s16 *dst = (s16 *)ctxt->dst.valptr;
	s16 *src = (s16 *)ctxt->src.valptr;
	s16 *src1 = ctxt->src2.type == OP_NONE ? dst : (s16 *)ctxt->src2.valptr;
	int i;

	for (i = 0; i < ctxt->dst.bytes / 2; i++) {
		if (src[i] < 0)
			dst[i] = -src1[i];
		else if (src[i] == 0)
			dst[i] = 0;
		else
			dst[i] = src1[i];
	}
	return X86EMUL_CONTINUE;
}

static int em_psignd(struct x86_emulate_ctxt *ctxt)
{
	s32 *dst = (s32 *)ctxt->dst.valptr;
	s32 *src = (s32 *)ctxt->src.valptr;
	s32 *src1 = ctxt->src2.type == OP_NONE ? dst : (s32 *)ctxt->src2.valptr;
	int i;

	for (i = 0; i < ctxt->dst.bytes / 4; i++) {
		if (src[i] < 0)
			dst[i] = -src1[i];
		else if (src[i] == 0)
			dst[i] = 0;
		else
			dst[i] = src1[i];
	}
	return X86EMUL_CONTINUE;
}

/*
 * PHADDW/PHADDD/PHSUBW/PHSUBD (66 0F 38 01-06): Horizontal add/sub.
 */
static int em_phaddw(struct x86_emulate_ctxt *ctxt)
{
	s16 *dst = (s16 *)ctxt->dst.valptr;
	s16 *src = (s16 *)ctxt->src.valptr;
	s16 *src1 = ctxt->src2.type == OP_NONE ? dst : (s16 *)ctxt->src2.valptr;
	s16 tmp[16];
	int lane, i;

	for (lane = 0; lane < ctxt->dst.bytes / 16; lane++) {
		int base = lane * 8;
		for (i = 0; i < 4; i++)
			tmp[base + i] = src1[base + i * 2] + src1[base + i * 2 + 1];
		for (i = 0; i < 4; i++)
			tmp[base + 4 + i] = src[base + i * 2] + src[base + i * 2 + 1];
	}
	memcpy(dst, tmp, ctxt->dst.bytes);
	return X86EMUL_CONTINUE;
}

static int em_phaddd(struct x86_emulate_ctxt *ctxt)
{
	s32 *dst = (s32 *)ctxt->dst.valptr;
	s32 *src = (s32 *)ctxt->src.valptr;
	s32 *src1 = ctxt->src2.type == OP_NONE ? dst : (s32 *)ctxt->src2.valptr;
	s32 tmp[8];
	int lane, i;

	for (lane = 0; lane < ctxt->dst.bytes / 16; lane++) {
		int base = lane * 4;
		for (i = 0; i < 2; i++)
			tmp[base + i] = src1[base + i * 2] + src1[base + i * 2 + 1];
		for (i = 0; i < 2; i++)
			tmp[base + 2 + i] = src[base + i * 2] + src[base + i * 2 + 1];
	}
	memcpy(dst, tmp, ctxt->dst.bytes);
	return X86EMUL_CONTINUE;
}

static int em_phsubw(struct x86_emulate_ctxt *ctxt)
{
	s16 *dst = (s16 *)ctxt->dst.valptr;
	s16 *src = (s16 *)ctxt->src.valptr;
	s16 *src1 = ctxt->src2.type == OP_NONE ? dst : (s16 *)ctxt->src2.valptr;
	s16 tmp[16];
	int lane, i;

	for (lane = 0; lane < ctxt->dst.bytes / 16; lane++) {
		int base = lane * 8;
		for (i = 0; i < 4; i++)
			tmp[base + i] = src1[base + i * 2] - src1[base + i * 2 + 1];
		for (i = 0; i < 4; i++)
			tmp[base + 4 + i] = src[base + i * 2] - src[base + i * 2 + 1];
	}
	memcpy(dst, tmp, ctxt->dst.bytes);
	return X86EMUL_CONTINUE;
}

static int em_phsubd(struct x86_emulate_ctxt *ctxt)
{
	s32 *dst = (s32 *)ctxt->dst.valptr;
	s32 *src = (s32 *)ctxt->src.valptr;
	s32 *src1 = ctxt->src2.type == OP_NONE ? dst : (s32 *)ctxt->src2.valptr;
	s32 tmp[8];
	int lane, i;

	for (lane = 0; lane < ctxt->dst.bytes / 16; lane++) {
		int base = lane * 4;
		for (i = 0; i < 2; i++)
			tmp[base + i] = src1[base + i * 2] - src1[base + i * 2 + 1];
		for (i = 0; i < 2; i++)
			tmp[base + 2 + i] = src[base + i * 2] - src[base + i * 2 + 1];
	}
	memcpy(dst, tmp, ctxt->dst.bytes);
	return X86EMUL_CONTINUE;
}

/*
 * PHADDSW (66 0F 38 03): Horizontal add with saturation (signed words).
 */
static int em_phaddsw(struct x86_emulate_ctxt *ctxt)
{
	s16 *dst = (s16 *)ctxt->dst.valptr;
	s16 *src = (s16 *)ctxt->src.valptr;
	s16 *src1 = ctxt->src2.type == OP_NONE ? dst : (s16 *)ctxt->src2.valptr;
	s16 tmp[16];
	int lane, i;

	for (lane = 0; lane < ctxt->dst.bytes / 16; lane++) {
		int base = lane * 8;
		for (i = 0; i < 4; i++) {
			s32 sum = (s32)src1[base + i * 2] + (s32)src1[base + i * 2 + 1];
			tmp[base + i] = (sum > 32767) ? 32767 : (sum < -32768) ? -32768 : sum;
		}
		for (i = 0; i < 4; i++) {
			s32 sum = (s32)src[base + i * 2] + (s32)src[base + i * 2 + 1];
			tmp[base + 4 + i] = (sum > 32767) ? 32767 : (sum < -32768) ? -32768 : sum;
		}
	}
	memcpy(dst, tmp, ctxt->dst.bytes);
	return X86EMUL_CONTINUE;
}

/*
 * PHSUBSW (66 0F 38 07): Horizontal subtract with saturation (signed words).
 */
static int em_phsubsw(struct x86_emulate_ctxt *ctxt)
{
	s16 *dst = (s16 *)ctxt->dst.valptr;
	s16 *src = (s16 *)ctxt->src.valptr;
	s16 *src1 = ctxt->src2.type == OP_NONE ? dst : (s16 *)ctxt->src2.valptr;
	s16 tmp[16];
	int lane, i;

	for (lane = 0; lane < ctxt->dst.bytes / 16; lane++) {
		int base = lane * 8;
		for (i = 0; i < 4; i++) {
			s32 diff = (s32)src1[base + i * 2] - (s32)src1[base + i * 2 + 1];
			tmp[base + i] = (diff > 32767) ? 32767 : (diff < -32768) ? -32768 : diff;
		}
		for (i = 0; i < 4; i++) {
			s32 diff = (s32)src[base + i * 2] - (s32)src[base + i * 2 + 1];
			tmp[base + 4 + i] = (diff > 32767) ? 32767 : (diff < -32768) ? -32768 : diff;
		}
	}
	memcpy(dst, tmp, ctxt->dst.bytes);
	return X86EMUL_CONTINUE;
}

/*
 * PMULHRSW (66 0F 38 0B): Packed multiply high with round and scale.
 */
static int em_pmulhrsw(struct x86_emulate_ctxt *ctxt)
{
	s16 *dst = (s16 *)ctxt->dst.valptr;
	s16 *src = (s16 *)ctxt->src.valptr;
	s16 *src1 = ctxt->src2.type == OP_NONE ? dst : (s16 *)ctxt->src2.valptr;
	int i;

	for (i = 0; i < ctxt->dst.bytes / 2; i++) {
		s32 product = (s32)src1[i] * (s32)src[i];
		dst[i] = (s16)(((product >> 14) + 1) >> 1);
	}
	return X86EMUL_CONTINUE;
}

/*
 * Shift instructions: PSLLW/PSLLD/PSLLQ/PSRLW/PSRLD/PSRLQ/PSRAW/PSRAD.
 * These take the shift count from the low 64 bits of the src (xmm/m128).
 */
static int em_psllw(struct x86_emulate_ctxt *ctxt)
{
	u16 *dst = (u16 *)ctxt->dst.valptr;
	u64 *src64 = (u64 *)ctxt->src.valptr;
	u16 *src1 = ctxt->src2.type == OP_NONE ? dst : (u16 *)ctxt->src2.valptr;
	u64 count = src64[0];
	int i;

	for (i = 0; i < ctxt->dst.bytes / 2; i++)
		dst[i] = (count > 15) ? 0 : (src1[i] << count);
	return X86EMUL_CONTINUE;
}

static int em_pslld(struct x86_emulate_ctxt *ctxt)
{
	u32 *dst = (u32 *)ctxt->dst.valptr;
	u64 *src64 = (u64 *)ctxt->src.valptr;
	u32 *src1 = ctxt->src2.type == OP_NONE ? dst : (u32 *)ctxt->src2.valptr;
	u64 count = src64[0];
	int i;

	for (i = 0; i < ctxt->dst.bytes / 4; i++)
		dst[i] = (count > 31) ? 0 : (src1[i] << count);
	return X86EMUL_CONTINUE;
}

static int em_psllq(struct x86_emulate_ctxt *ctxt)
{
	u64 *dst = (u64 *)ctxt->dst.valptr;
	u64 *src64 = (u64 *)ctxt->src.valptr;
	u64 *src1 = ctxt->src2.type == OP_NONE ? dst : (u64 *)ctxt->src2.valptr;
	u64 count = src64[0];
	int i;

	for (i = 0; i < ctxt->dst.bytes / 8; i++)
		dst[i] = (count > 63) ? 0 : (src1[i] << count);
	return X86EMUL_CONTINUE;
}

static int em_psrlw(struct x86_emulate_ctxt *ctxt)
{
	u16 *dst = (u16 *)ctxt->dst.valptr;
	u64 *src64 = (u64 *)ctxt->src.valptr;
	u16 *src1 = ctxt->src2.type == OP_NONE ? dst : (u16 *)ctxt->src2.valptr;
	u64 count = src64[0];
	int i;

	for (i = 0; i < ctxt->dst.bytes / 2; i++)
		dst[i] = (count > 15) ? 0 : (src1[i] >> count);
	return X86EMUL_CONTINUE;
}

static int em_psrld(struct x86_emulate_ctxt *ctxt)
{
	u32 *dst = (u32 *)ctxt->dst.valptr;
	u64 *src64 = (u64 *)ctxt->src.valptr;
	u32 *src1 = ctxt->src2.type == OP_NONE ? dst : (u32 *)ctxt->src2.valptr;
	u64 count = src64[0];
	int i;

	for (i = 0; i < ctxt->dst.bytes / 4; i++)
		dst[i] = (count > 31) ? 0 : (src1[i] >> count);
	return X86EMUL_CONTINUE;
}

static int em_psrlq(struct x86_emulate_ctxt *ctxt)
{
	u64 *dst = (u64 *)ctxt->dst.valptr;
	u64 *src64 = (u64 *)ctxt->src.valptr;
	u64 *src1 = ctxt->src2.type == OP_NONE ? dst : (u64 *)ctxt->src2.valptr;
	u64 count = src64[0];
	int i;

	for (i = 0; i < ctxt->dst.bytes / 8; i++)
		dst[i] = (count > 63) ? 0 : (src1[i] >> count);
	return X86EMUL_CONTINUE;
}

static int em_psraw(struct x86_emulate_ctxt *ctxt)
{
	s16 *dst = (s16 *)ctxt->dst.valptr;
	u64 *src64 = (u64 *)ctxt->src.valptr;
	s16 *src1 = ctxt->src2.type == OP_NONE ? dst : (s16 *)ctxt->src2.valptr;
	u64 count = src64[0];
	int i;

	if (count > 15)
		count = 15;
	for (i = 0; i < ctxt->dst.bytes / 2; i++)
		dst[i] = src1[i] >> count;
	return X86EMUL_CONTINUE;
}

static int em_psrad(struct x86_emulate_ctxt *ctxt)
{
	s32 *dst = (s32 *)ctxt->dst.valptr;
	u64 *src64 = (u64 *)ctxt->src.valptr;
	s32 *src1 = ctxt->src2.type == OP_NONE ? dst : (s32 *)ctxt->src2.valptr;
	u64 count = src64[0];
	int i;

	if (count > 31)
		count = 31;
	for (i = 0; i < ctxt->dst.bytes / 4; i++)
		dst[i] = src1[i] >> count;
	return X86EMUL_CONTINUE;
}

/*
 * PSLLDQ (66 0F 73 /7 ib): Shift double quadword left by imm8 bytes.
 * PSRLDQ (66 0F 73 /3 ib): Shift double quadword right by imm8 bytes.
 * These use immediate byte, decoded differently (group opcode).
 * We implement them as standalone functions called from the shift group.
 */

/*
 * MOVMSKPS (NP 0F 50): Extract sign bits from packed single-precision.
 * Source is XMM (modrm_rm), destination is GPR (modrm_reg).
 */
static int em_movmskps(struct x86_emulate_ctxt *ctxt)
{
	sse128_t reg;
	__sse128_u u;
	int i, result = 0;
	int num_elements = (ctxt->d & Avx && ctxt->op_bytes == 32) ? 8 : 4;

	if (num_elements <= 4) {
		kvm_read_sse_reg(ctxt->modrm_rm, &reg);
		memcpy(&u, &reg, sizeof(u));
		for (i = 0; i < 4; i++)
			if (u.as_u32[i] & 0x80000000)
				result |= (1 << i);
	}
	/* For AVX 256-bit, would need to read YMM - skip for now */

	*reg_write(ctxt, ctxt->modrm_reg) = result;
	ctxt->dst.type = OP_NONE;
	return X86EMUL_CONTINUE;
}

/*
 * MOVMSKPD (66 0F 50): Extract sign bits from packed double-precision.
 */
static int em_movmskpd(struct x86_emulate_ctxt *ctxt)
{
	sse128_t reg;
	__sse128_u u;
	int i, result = 0;

	kvm_read_sse_reg(ctxt->modrm_rm, &reg);
	memcpy(&u, &reg, sizeof(u));
	for (i = 0; i < 2; i++)
		if (u.as_u64[i] & 0x8000000000000000ULL)
			result |= (1 << i);

	*reg_write(ctxt, ctxt->modrm_reg) = result;
	ctxt->dst.type = OP_NONE;
	return X86EMUL_CONTINUE;
}

/*
 * PMOVMSKB (66 0F D7): Move byte mask.
 * Extracts the MSB of each byte and stores to a GPR.
 */
static int em_pmovmskb(struct x86_emulate_ctxt *ctxt)
{
	sse128_t reg;
	u8 bytes[16];
	int i, result = 0;

	kvm_read_sse_reg(ctxt->modrm_rm, &reg);
	memcpy(bytes, &reg, 16);
	for (i = 0; i < 16; i++)
		if (bytes[i] & 0x80)
			result |= (1 << i);

	*reg_write(ctxt, ctxt->modrm_reg) = result;
	ctxt->dst.type = OP_NONE;
	return X86EMUL_CONTINUE;
}

/*
 * LDDQU (F2 0F F0): Load unaligned integer 128 bits.
 * Functionally equivalent to MOVDQU for our purposes.
 */
static int em_lddqu(struct x86_emulate_ctxt *ctxt)
{
	return em_mov(ctxt);
}

/*
 * 0F 3A instructions (with imm8):
 */

/*
 * PALIGNR (66 0F 3A 0F): Byte-align concatenation with shift.
 * Concatenates src1 (HIGH) : src (LOW) into 32-byte temp, shifts right by imm8 bytes,
 * takes low 16 bytes.
 */
static int em_palignr(struct x86_emulate_ctxt *ctxt)
{
	u8 *dst = (u8 *)ctxt->dst.valptr;
	u8 *src = (u8 *)ctxt->src.valptr;
	u8 *src1 = ctxt->src2.type == OP_NONE ? dst : (u8 *)ctxt->src2.valptr;
	u8 imm;
	int rc, lane;

	rc = do_insn_fetch_bytes(ctxt, 1);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	imm = *ctxt->fetch.ptr++;

	for (lane = 0; lane < ctxt->dst.bytes / 16; lane++) {
		u8 concat[32];
		int base = lane * 16;
		int i;

		memcpy(concat, src + base, 16);        /* bytes 0-15 = src (LOW) */
		memcpy(concat + 16, src1 + base, 16);  /* bytes 16-31 = src1 (HIGH) */

		for (i = 0; i < 16; i++) {
			if (i + imm < 32)
				dst[base + i] = concat[i + imm];
			else
				dst[base + i] = 0;
		}
	}
	return X86EMUL_CONTINUE;
}

/*
 * PCMPISTRI (66 0F 3A 63): Packed compare implicit string, returning index.
 * Very complex - delegate to actual CPU instruction.
 */
static int em_pcmpistri(struct x86_emulate_ctxt *ctxt)
{
	u8 *dst = (u8 *)ctxt->dst.valptr;
	u8 *src = (u8 *)ctxt->src.valptr;
	sse128_t saved_xmm0, saved_xmm1;
	unsigned long flags;
	u32 ecx_result;
	u8 imm;
	int rc;

	rc = do_insn_fetch_bytes(ctxt, 1);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	imm = *ctxt->fetch.ptr++;

	kvm_fpu_get();
	_kvm_read_sse_reg(0, &saved_xmm0);
	_kvm_read_sse_reg(1, &saved_xmm1);

	asm volatile("movdqu %0, %%xmm0" : : "m"(*(sse128_t *)dst));
	asm volatile("movdqu %0, %%xmm1" : : "m"(*(sse128_t *)src));
#define PCMPISTRI_CASE(n)						\
	case n:								\
		asm volatile("pcmpistri $" #n ", %%xmm1, %%xmm0\n\t"	\
			     "pushf\n\t"				\
			     "pop %[flags]\n\t"				\
			     "mov %%ecx, %[ecx]"			\
			     : [flags] "=r" (flags), [ecx] "=r" (ecx_result) \
			     : : "ecx", "cc");				\
		break

	switch (imm) {
	PCMPISTRI_CASE(0x00); PCMPISTRI_CASE(0x01); PCMPISTRI_CASE(0x02); PCMPISTRI_CASE(0x03);
	PCMPISTRI_CASE(0x04); PCMPISTRI_CASE(0x05); PCMPISTRI_CASE(0x06); PCMPISTRI_CASE(0x07);
	PCMPISTRI_CASE(0x08); PCMPISTRI_CASE(0x09); PCMPISTRI_CASE(0x0a); PCMPISTRI_CASE(0x0b);
	PCMPISTRI_CASE(0x0c); PCMPISTRI_CASE(0x0d); PCMPISTRI_CASE(0x0e); PCMPISTRI_CASE(0x0f);
	PCMPISTRI_CASE(0x10); PCMPISTRI_CASE(0x11); PCMPISTRI_CASE(0x12); PCMPISTRI_CASE(0x13);
	PCMPISTRI_CASE(0x14); PCMPISTRI_CASE(0x15); PCMPISTRI_CASE(0x16); PCMPISTRI_CASE(0x17);
	PCMPISTRI_CASE(0x18); PCMPISTRI_CASE(0x19); PCMPISTRI_CASE(0x1a); PCMPISTRI_CASE(0x1b);
	PCMPISTRI_CASE(0x1c); PCMPISTRI_CASE(0x1d); PCMPISTRI_CASE(0x1e); PCMPISTRI_CASE(0x1f);
	PCMPISTRI_CASE(0x20); PCMPISTRI_CASE(0x21); PCMPISTRI_CASE(0x22); PCMPISTRI_CASE(0x23);
	PCMPISTRI_CASE(0x24); PCMPISTRI_CASE(0x25); PCMPISTRI_CASE(0x26); PCMPISTRI_CASE(0x27);
	PCMPISTRI_CASE(0x28); PCMPISTRI_CASE(0x29); PCMPISTRI_CASE(0x2a); PCMPISTRI_CASE(0x2b);
	PCMPISTRI_CASE(0x2c); PCMPISTRI_CASE(0x2d); PCMPISTRI_CASE(0x2e); PCMPISTRI_CASE(0x2f);
	PCMPISTRI_CASE(0x30); PCMPISTRI_CASE(0x31); PCMPISTRI_CASE(0x32); PCMPISTRI_CASE(0x33);
	PCMPISTRI_CASE(0x34); PCMPISTRI_CASE(0x35); PCMPISTRI_CASE(0x36); PCMPISTRI_CASE(0x37);
	PCMPISTRI_CASE(0x38); PCMPISTRI_CASE(0x39); PCMPISTRI_CASE(0x3a); PCMPISTRI_CASE(0x3b);
	PCMPISTRI_CASE(0x3c); PCMPISTRI_CASE(0x3d); PCMPISTRI_CASE(0x3e); PCMPISTRI_CASE(0x3f);
	PCMPISTRI_CASE(0x40); PCMPISTRI_CASE(0x41); PCMPISTRI_CASE(0x42); PCMPISTRI_CASE(0x43);
	PCMPISTRI_CASE(0x44); PCMPISTRI_CASE(0x45); PCMPISTRI_CASE(0x46); PCMPISTRI_CASE(0x47);
	PCMPISTRI_CASE(0x48); PCMPISTRI_CASE(0x49); PCMPISTRI_CASE(0x4a); PCMPISTRI_CASE(0x4b);
	PCMPISTRI_CASE(0x4c); PCMPISTRI_CASE(0x4d); PCMPISTRI_CASE(0x4e); PCMPISTRI_CASE(0x4f);
	default:
		_kvm_write_sse_reg(0, &saved_xmm0);
		_kvm_write_sse_reg(1, &saved_xmm1);
		kvm_fpu_put();
		return X86EMUL_UNHANDLEABLE;
	}
#undef PCMPISTRI_CASE

	_kvm_write_sse_reg(0, &saved_xmm0);
	_kvm_write_sse_reg(1, &saved_xmm1);
	kvm_fpu_put();

	/* PCMPISTRI writes result to ECX */
	*reg_write(ctxt, VCPU_REGS_RCX) = ecx_result;

	/* Update flags */
	ctxt->eflags = (ctxt->eflags & ~(X86_EFLAGS_CF | X86_EFLAGS_ZF |
			X86_EFLAGS_SF | X86_EFLAGS_OF | X86_EFLAGS_AF |
			X86_EFLAGS_PF)) |
		       (flags & (X86_EFLAGS_CF | X86_EFLAGS_ZF |
				 X86_EFLAGS_SF | X86_EFLAGS_OF));

	ctxt->dst.type = OP_NONE;
	return X86EMUL_CONTINUE;
}

/*
 * PINSRD/PINSRQ (66 0F 3A 22): Insert dword/qword from GPR/m into XMM at imm8 position.
 */
static int em_pinsrd(struct x86_emulate_ctxt *ctxt)
{
	u8 *dst = (u8 *)ctxt->dst.valptr;
	u32 src_val;
	u8 imm;
	int rc;

	memcpy(&src_val, ctxt->src.valptr, 4);

	rc = do_insn_fetch_bytes(ctxt, 1);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	imm = *ctxt->fetch.ptr++;

	/* Insert at position (imm & 3) for dword */
	memcpy(dst + (imm & 3) * 4, &src_val, 4);
	return X86EMUL_CONTINUE;
}

/*
 * PEXTRD/PEXTRQ (66 0F 3A 16): Extract dword/qword from XMM to GPR/m at imm8 position.
 */
static int em_pextrd(struct x86_emulate_ctxt *ctxt)
{
	u8 *src = (u8 *)ctxt->src.valptr;
	u8 imm;
	int rc;

	rc = do_insn_fetch_bytes(ctxt, 1);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	imm = *ctxt->fetch.ptr++;

	/* Extract from position (imm & 3) for dword */
	memcpy(ctxt->dst.valptr, src + (imm & 3) * 4, 4);
	ctxt->dst.bytes = 4;
	return X86EMUL_CONTINUE;
}

/*
 * PEXTRB (66 0F 3A 14): Extract byte from XMM at imm8 position.
 */
static int em_pextrb(struct x86_emulate_ctxt *ctxt)
{
	u8 *src = (u8 *)ctxt->src.valptr;
	u8 imm;
	int rc;

	rc = do_insn_fetch_bytes(ctxt, 1);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	imm = *ctxt->fetch.ptr++;

	ctxt->dst.val = src[imm & 15];
	ctxt->dst.bytes = 4; /* zero-extended to 32/64 bits */
	return X86EMUL_CONTINUE;
}

/*
 * PINSRB (66 0F 3A 20): Insert byte from GPR/m8 into XMM at imm8 position.
 */
static int em_pinsrb(struct x86_emulate_ctxt *ctxt)
{
	u8 *dst = (u8 *)ctxt->dst.valptr;
	u8 src_val = (u8)ctxt->src.val;
	u8 imm;
	int rc;

	rc = do_insn_fetch_bytes(ctxt, 1);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	imm = *ctxt->fetch.ptr++;

	dst[imm & 15] = src_val;
	return X86EMUL_CONTINUE;
}

/*
 * BLENDPS (66 0F 3A 0C): Blend packed singles using imm8 mask.
 * For each bit i in imm8: if set, dst[i] = src[i]; else dst[i] = src1[i].
 */
static int em_blendps(struct x86_emulate_ctxt *ctxt)
{
	u32 *dst = (u32 *)ctxt->dst.valptr;
	u32 *src = (u32 *)ctxt->src.valptr;
	u32 *src1 = ctxt->src2.type == OP_NONE ? dst : (u32 *)ctxt->src2.valptr;
	u32 tmp[8];
	u8 imm;
	int rc, i;

	rc = do_insn_fetch_bytes(ctxt, 1);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	imm = *ctxt->fetch.ptr++;

	for (i = 0; i < ctxt->dst.bytes / 4; i++)
		tmp[i] = (imm & (1 << i)) ? src[i] : src1[i];
	memcpy(dst, tmp, ctxt->dst.bytes);
	return X86EMUL_CONTINUE;
}

/*
 * BLENDPD (66 0F 3A 0D): Blend packed doubles using imm8 mask.
 */
static int em_blendpd(struct x86_emulate_ctxt *ctxt)
{
	u64 *dst = (u64 *)ctxt->dst.valptr;
	u64 *src = (u64 *)ctxt->src.valptr;
	u64 *src1 = ctxt->src2.type == OP_NONE ? dst : (u64 *)ctxt->src2.valptr;
	u64 tmp[4];
	u8 imm;
	int rc, i;

	rc = do_insn_fetch_bytes(ctxt, 1);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	imm = *ctxt->fetch.ptr++;

	for (i = 0; i < ctxt->dst.bytes / 8; i++)
		tmp[i] = (imm & (1 << i)) ? src[i] : src1[i];
	memcpy(dst, tmp, ctxt->dst.bytes);
	return X86EMUL_CONTINUE;
}

/*
 * PBLENDW (66 0F 3A 0E): Blend packed words using imm8 mask.
 */
static int em_pblendw(struct x86_emulate_ctxt *ctxt)
{
	u16 *dst = (u16 *)ctxt->dst.valptr;
	u16 *src = (u16 *)ctxt->src.valptr;
	u16 *src1 = ctxt->src2.type == OP_NONE ? dst : (u16 *)ctxt->src2.valptr;
	u16 tmp[16];
	u8 imm;
	int rc, i;

	rc = do_insn_fetch_bytes(ctxt, 1);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	imm = *ctxt->fetch.ptr++;

	for (i = 0; i < ctxt->dst.bytes / 2; i++)
		tmp[i] = (imm & (1 << (i % 8))) ? src[i] : src1[i];
	memcpy(dst, tmp, ctxt->dst.bytes);
	return X86EMUL_CONTINUE;
}

/*
 * PBLENDVB (66 0F 38 10): Variable blend packed bytes using XMM0 as mask.
 * For each byte i: if XMM0[i] bit 7 set, dst[i] = src[i]; else dst[i] = src1[i].
 */
static int em_pblendvb(struct x86_emulate_ctxt *ctxt)
{
	u8 *dst = (u8 *)ctxt->dst.valptr;
	u8 *src = (u8 *)ctxt->src.valptr;
	u8 *src1 = ctxt->src2.type == OP_NONE ? dst : (u8 *)ctxt->src2.valptr;
	sse128_t xmm0_val;
	u8 *mask;
	u8 tmp[32];
	int i;

	kvm_read_sse_reg(0, &xmm0_val);
	mask = (u8 *)&xmm0_val;

	for (i = 0; i < ctxt->dst.bytes && i < 16; i++)
		tmp[i] = (mask[i] & 0x80) ? src[i] : src1[i];
	memcpy(dst, tmp, min_t(int, ctxt->dst.bytes, 16));
	return X86EMUL_CONTINUE;
}

/*
 * BLENDVPS (66 0F 38 14): Variable blend packed singles using XMM0 as mask.
 * For each dword i: if XMM0[i] bit 31 set, dst[i] = src[i]; else dst[i] = src1[i].
 */
static int em_blendvps(struct x86_emulate_ctxt *ctxt)
{
	u32 *dst = (u32 *)ctxt->dst.valptr;
	u32 *src = (u32 *)ctxt->src.valptr;
	u32 *src1 = ctxt->src2.type == OP_NONE ? dst : (u32 *)ctxt->src2.valptr;
	sse128_t xmm0_val;
	u32 *mask;
	u32 tmp[8];
	int i;

	kvm_read_sse_reg(0, &xmm0_val);
	mask = (u32 *)&xmm0_val;

	for (i = 0; i < ctxt->dst.bytes / 4 && i < 4; i++)
		tmp[i] = (mask[i] & 0x80000000) ? src[i] : src1[i];
	memcpy(dst, tmp, min_t(int, ctxt->dst.bytes, 16));
	return X86EMUL_CONTINUE;
}

/*
 * BLENDVPD (66 0F 38 15): Variable blend packed doubles using XMM0 as mask.
 * For each qword i: if XMM0[i] bit 63 set, dst[i] = src[i]; else dst[i] = src1[i].
 */
static int em_blendvpd(struct x86_emulate_ctxt *ctxt)
{
	u64 *dst = (u64 *)ctxt->dst.valptr;
	u64 *src = (u64 *)ctxt->src.valptr;
	u64 *src1 = ctxt->src2.type == OP_NONE ? dst : (u64 *)ctxt->src2.valptr;
	sse128_t xmm0_val;
	u64 *mask;
	u64 tmp[4];
	int i;

	kvm_read_sse_reg(0, &xmm0_val);
	mask = (u64 *)&xmm0_val;

	for (i = 0; i < ctxt->dst.bytes / 8 && i < 2; i++)
		tmp[i] = (mask[i] & 0x8000000000000000ULL) ? src[i] : src1[i];
	memcpy(dst, tmp, min_t(int, ctxt->dst.bytes, 16));
	return X86EMUL_CONTINUE;
}

/*
 * ROUNDSS (66 0F 3A 0A): Round scalar single with imm8.
 * ROUNDSD (66 0F 3A 0B): Round scalar double with imm8.
 * ROUNDPS (66 0F 3A 08): Round packed singles with imm8.
 * ROUNDPD (66 0F 3A 09): Round packed doubles with imm8.
 * Use kvm_fpu_get/put and execute on host CPU.
 */
static int em_roundps(struct x86_emulate_ctxt *ctxt)
{
	u8 *dst = (u8 *)ctxt->dst.valptr;
	u8 *src = (u8 *)ctxt->src.valptr;
	unsigned int bytes = ctxt->dst.bytes;
	sse128_t saved_xmm0, saved_xmm1;
	u8 tmp_dst[32] __aligned(32);
	u8 imm;
	int rc, i;

	rc = do_insn_fetch_bytes(ctxt, 1);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	imm = *ctxt->fetch.ptr++;

	kvm_fpu_get();
	_kvm_read_sse_reg(0, &saved_xmm0);
	_kvm_read_sse_reg(1, &saved_xmm1);
	for (i = 0; i < bytes; i += 16) {
		asm volatile("movdqu %0, %%xmm1" : : "m"(*(sse128_t *)&src[i]));
#define ROUNDPS_CASE(n)							\
		case n:							\
			asm volatile("roundps $" #n ", %%xmm1, %%xmm0" :::); \
			break
		switch (imm & 0x0f) {
		ROUNDPS_CASE(0); ROUNDPS_CASE(1); ROUNDPS_CASE(2); ROUNDPS_CASE(3);
		ROUNDPS_CASE(4); ROUNDPS_CASE(5); ROUNDPS_CASE(6); ROUNDPS_CASE(7);
		ROUNDPS_CASE(8); ROUNDPS_CASE(9); ROUNDPS_CASE(10); ROUNDPS_CASE(11);
		ROUNDPS_CASE(12); ROUNDPS_CASE(13); ROUNDPS_CASE(14); ROUNDPS_CASE(15);
		}
#undef ROUNDPS_CASE
		asm volatile("movdqu %%xmm0, %0" : "=m"(*(sse128_t *)&tmp_dst[i]));
	}
	_kvm_write_sse_reg(0, &saved_xmm0);
	_kvm_write_sse_reg(1, &saved_xmm1);
	kvm_fpu_put();
	memcpy(dst, tmp_dst, bytes);
	return X86EMUL_CONTINUE;
}

static int em_roundpd(struct x86_emulate_ctxt *ctxt)
{
	u8 *dst = (u8 *)ctxt->dst.valptr;
	u8 *src = (u8 *)ctxt->src.valptr;
	unsigned int bytes = ctxt->dst.bytes;
	sse128_t saved_xmm0, saved_xmm1;
	u8 tmp_dst[32] __aligned(32);
	u8 imm;
	int rc, i;

	rc = do_insn_fetch_bytes(ctxt, 1);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	imm = *ctxt->fetch.ptr++;

	kvm_fpu_get();
	_kvm_read_sse_reg(0, &saved_xmm0);
	_kvm_read_sse_reg(1, &saved_xmm1);
	for (i = 0; i < bytes; i += 16) {
		asm volatile("movdqu %0, %%xmm1" : : "m"(*(sse128_t *)&src[i]));
#define ROUNDPD_CASE(n)							\
		case n:							\
			asm volatile("roundpd $" #n ", %%xmm1, %%xmm0" :::); \
			break
		switch (imm & 0x0f) {
		ROUNDPD_CASE(0); ROUNDPD_CASE(1); ROUNDPD_CASE(2); ROUNDPD_CASE(3);
		ROUNDPD_CASE(4); ROUNDPD_CASE(5); ROUNDPD_CASE(6); ROUNDPD_CASE(7);
		ROUNDPD_CASE(8); ROUNDPD_CASE(9); ROUNDPD_CASE(10); ROUNDPD_CASE(11);
		ROUNDPD_CASE(12); ROUNDPD_CASE(13); ROUNDPD_CASE(14); ROUNDPD_CASE(15);
		}
#undef ROUNDPD_CASE
		asm volatile("movdqu %%xmm0, %0" : "=m"(*(sse128_t *)&tmp_dst[i]));
	}
	_kvm_write_sse_reg(0, &saved_xmm0);
	_kvm_write_sse_reg(1, &saved_xmm1);
	kvm_fpu_put();
	memcpy(dst, tmp_dst, bytes);
	return X86EMUL_CONTINUE;
}

static int em_roundss(struct x86_emulate_ctxt *ctxt)
{
	u8 *dst = (u8 *)ctxt->dst.valptr;
	u8 *src = (u8 *)ctxt->src.valptr;
	u8 *src1 = ctxt->src2.type == OP_NONE ? dst : (u8 *)ctxt->src2.valptr;
	sse128_t saved_xmm0, saved_xmm1;
	u8 tmp_dst[16] __aligned(16);
	u8 imm;
	int rc;

	rc = do_insn_fetch_bytes(ctxt, 1);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	imm = *ctxt->fetch.ptr++;

	kvm_fpu_get();
	_kvm_read_sse_reg(0, &saved_xmm0);
	_kvm_read_sse_reg(1, &saved_xmm1);
	asm volatile("movdqu %0, %%xmm0" : : "m"(*(sse128_t *)src1));
	asm volatile("movdqu %0, %%xmm1" : : "m"(*(sse128_t *)src));
#define ROUNDSS_CASE(n)							\
	case n:								\
		asm volatile("roundss $" #n ", %%xmm1, %%xmm0" :::); \
		break
	switch (imm & 0x0f) {
	ROUNDSS_CASE(0); ROUNDSS_CASE(1); ROUNDSS_CASE(2); ROUNDSS_CASE(3);
	ROUNDSS_CASE(4); ROUNDSS_CASE(5); ROUNDSS_CASE(6); ROUNDSS_CASE(7);
	ROUNDSS_CASE(8); ROUNDSS_CASE(9); ROUNDSS_CASE(10); ROUNDSS_CASE(11);
	ROUNDSS_CASE(12); ROUNDSS_CASE(13); ROUNDSS_CASE(14); ROUNDSS_CASE(15);
	}
#undef ROUNDSS_CASE
	asm volatile("movdqu %%xmm0, %0" : "=m"(*(sse128_t *)tmp_dst));
	_kvm_write_sse_reg(0, &saved_xmm0);
	_kvm_write_sse_reg(1, &saved_xmm1);
	kvm_fpu_put();
	memcpy(dst, tmp_dst, 16);
	return X86EMUL_CONTINUE;
}

static int em_roundsd(struct x86_emulate_ctxt *ctxt)
{
	u8 *dst = (u8 *)ctxt->dst.valptr;
	u8 *src = (u8 *)ctxt->src.valptr;
	u8 *src1 = ctxt->src2.type == OP_NONE ? dst : (u8 *)ctxt->src2.valptr;
	sse128_t saved_xmm0, saved_xmm1;
	u8 tmp_dst[16] __aligned(16);
	u8 imm;
	int rc;

	rc = do_insn_fetch_bytes(ctxt, 1);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	imm = *ctxt->fetch.ptr++;

	kvm_fpu_get();
	_kvm_read_sse_reg(0, &saved_xmm0);
	_kvm_read_sse_reg(1, &saved_xmm1);
	asm volatile("movdqu %0, %%xmm0" : : "m"(*(sse128_t *)src1));
	asm volatile("movdqu %0, %%xmm1" : : "m"(*(sse128_t *)src));
#define ROUNDSD_CASE(n)							\
	case n:								\
		asm volatile("roundsd $" #n ", %%xmm1, %%xmm0" :::); \
		break
	switch (imm & 0x0f) {
	ROUNDSD_CASE(0); ROUNDSD_CASE(1); ROUNDSD_CASE(2); ROUNDSD_CASE(3);
	ROUNDSD_CASE(4); ROUNDSD_CASE(5); ROUNDSD_CASE(6); ROUNDSD_CASE(7);
	ROUNDSD_CASE(8); ROUNDSD_CASE(9); ROUNDSD_CASE(10); ROUNDSD_CASE(11);
	ROUNDSD_CASE(12); ROUNDSD_CASE(13); ROUNDSD_CASE(14); ROUNDSD_CASE(15);
	}
#undef ROUNDSD_CASE
	asm volatile("movdqu %%xmm0, %0" : "=m"(*(sse128_t *)tmp_dst));
	_kvm_write_sse_reg(0, &saved_xmm0);
	_kvm_write_sse_reg(1, &saved_xmm1);
	kvm_fpu_put();
	memcpy(dst, tmp_dst, 16);
	return X86EMUL_CONTINUE;
}

/*
 * AESKEYGENASSIST (66 0F 3A DF): AES key generation assist with imm8.
 */
static int em_aeskeygenassist(struct x86_emulate_ctxt *ctxt)
{
	u8 *dst = (u8 *)ctxt->dst.valptr;
	u8 *src = (u8 *)ctxt->src.valptr;
	sse128_t saved_xmm0, saved_xmm1;
	u8 tmp_dst[16] __aligned(16);
	u8 imm;
	int rc;

	rc = do_insn_fetch_bytes(ctxt, 1);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	imm = *ctxt->fetch.ptr++;

	kvm_fpu_get();
	_kvm_read_sse_reg(0, &saved_xmm0);
	_kvm_read_sse_reg(1, &saved_xmm1);
	asm volatile("movdqu %0, %%xmm1" : : "m"(*(sse128_t *)src));

#define AESKG_CASE(n)							\
	case n:								\
		asm volatile("aeskeygenassist $" #n ", %%xmm1, %%xmm0" :::); \
		break
	switch (imm) {
	AESKG_CASE(0x00); AESKG_CASE(0x01); AESKG_CASE(0x02); AESKG_CASE(0x03);
	AESKG_CASE(0x04); AESKG_CASE(0x05); AESKG_CASE(0x06); AESKG_CASE(0x07);
	AESKG_CASE(0x08); AESKG_CASE(0x09); AESKG_CASE(0x0a); AESKG_CASE(0x0b);
	AESKG_CASE(0x0c); AESKG_CASE(0x0d); AESKG_CASE(0x0e); AESKG_CASE(0x0f);
	AESKG_CASE(0x10); AESKG_CASE(0x11); AESKG_CASE(0x12); AESKG_CASE(0x13);
	AESKG_CASE(0x14); AESKG_CASE(0x15); AESKG_CASE(0x16); AESKG_CASE(0x17);
	AESKG_CASE(0x18); AESKG_CASE(0x19); AESKG_CASE(0x1a); AESKG_CASE(0x1b);
	AESKG_CASE(0x1c); AESKG_CASE(0x1d); AESKG_CASE(0x1e); AESKG_CASE(0x1f);
	AESKG_CASE(0x20); AESKG_CASE(0x21); AESKG_CASE(0x22); AESKG_CASE(0x23);
	AESKG_CASE(0x24); AESKG_CASE(0x25); AESKG_CASE(0x26); AESKG_CASE(0x27);
	AESKG_CASE(0x28); AESKG_CASE(0x29); AESKG_CASE(0x2a); AESKG_CASE(0x2b);
	AESKG_CASE(0x2c); AESKG_CASE(0x2d); AESKG_CASE(0x2e); AESKG_CASE(0x2f);
	AESKG_CASE(0x30); AESKG_CASE(0x31); AESKG_CASE(0x32); AESKG_CASE(0x33);
	AESKG_CASE(0x34); AESKG_CASE(0x35); AESKG_CASE(0x36); AESKG_CASE(0x37);
	AESKG_CASE(0x38); AESKG_CASE(0x39); AESKG_CASE(0x3a); AESKG_CASE(0x3b);
	AESKG_CASE(0x3c); AESKG_CASE(0x3d); AESKG_CASE(0x3e); AESKG_CASE(0x3f);
	default:
		/* AES key gen only uses RCON values, typically 0x01-0x36 */
		_kvm_write_sse_reg(0, &saved_xmm0);
		_kvm_write_sse_reg(1, &saved_xmm1);
		kvm_fpu_put();
		return X86EMUL_UNHANDLEABLE;
	}
#undef AESKG_CASE

	asm volatile("movdqu %%xmm0, %0" : "=m"(*(sse128_t *)tmp_dst));
	_kvm_write_sse_reg(0, &saved_xmm0);
	_kvm_write_sse_reg(1, &saved_xmm1);
	kvm_fpu_put();
	memcpy(dst, tmp_dst, 16);
	return X86EMUL_CONTINUE;
}

/*
 * PCLMULQDQ (66 0F 3A 44): Carry-less multiply with imm8.
 */
static int em_pclmulqdq(struct x86_emulate_ctxt *ctxt)
{
	u8 *dst = (u8 *)ctxt->dst.valptr;
	u8 *src = (u8 *)ctxt->src.valptr;
	u8 *src1 = ctxt->src2.type == OP_NONE ? dst : (u8 *)ctxt->src2.valptr;
	sse128_t saved_xmm0, saved_xmm1;
	u8 tmp_dst[16] __aligned(16);
	u8 imm;
	int rc;

	rc = do_insn_fetch_bytes(ctxt, 1);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	imm = *ctxt->fetch.ptr++;

	kvm_fpu_get();
	_kvm_read_sse_reg(0, &saved_xmm0);
	_kvm_read_sse_reg(1, &saved_xmm1);
	asm volatile("movdqu %0, %%xmm0" : : "m"(*(sse128_t *)src1));
	asm volatile("movdqu %0, %%xmm1" : : "m"(*(sse128_t *)src));

#define PCLMUL_CASE(n)							\
	case n:								\
		asm volatile("pclmulqdq $" #n ", %%xmm1, %%xmm0" :::); \
		break
	switch (imm & 0x11) {
	PCLMUL_CASE(0x00);
	PCLMUL_CASE(0x01);
	PCLMUL_CASE(0x10);
	PCLMUL_CASE(0x11);
	}
#undef PCLMUL_CASE

	asm volatile("movdqu %%xmm0, %0" : "=m"(*(sse128_t *)tmp_dst));
	_kvm_write_sse_reg(0, &saved_xmm0);
	_kvm_write_sse_reg(1, &saved_xmm1);
	kvm_fpu_put();
	memcpy(dst, tmp_dst, 16);
	return X86EMUL_CONTINUE;
}

/*
 * PSLLDQ (66 0F 73 /7 ib): Shift double quadword left by imm8 bytes.
 * Operates within each 128-bit lane independently.
 */
static int em_pslldq(struct x86_emulate_ctxt *ctxt)
{
	sse128_t xmm;
	u8 *data;
	u8 imm;
	int rc, i;
	u8 tmp[16];

	rc = em_check_sse_prereqs(ctxt);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	rc = do_insn_fetch_bytes(ctxt, 1);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	imm = *ctxt->fetch.ptr++;
	if (imm > 15)
		imm = 16;

	kvm_read_sse_reg(ctxt->modrm_rm, &xmm);
	data = (u8 *)&xmm;

	for (i = 0; i < 16; i++)
		tmp[i] = (i >= imm) ? data[i - imm] : 0;

	memcpy(&xmm, tmp, 16);
	write_xmm_reg(ctxt, ctxt->modrm_rm, &xmm);

	ctxt->dst.type = OP_NONE;
	return X86EMUL_CONTINUE;
}

/*
 * PSRLDQ (66 0F 73 /3 ib): Shift double quadword right by imm8 bytes.
 * Operates within each 128-bit lane independently.
 */
static int em_psrldq(struct x86_emulate_ctxt *ctxt)
{
	sse128_t xmm;
	u8 *data;
	u8 imm;
	int rc, i;
	u8 tmp[16];

	rc = em_check_sse_prereqs(ctxt);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	rc = do_insn_fetch_bytes(ctxt, 1);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	imm = *ctxt->fetch.ptr++;
	if (imm > 15)
		imm = 16;

	kvm_read_sse_reg(ctxt->modrm_rm, &xmm);
	data = (u8 *)&xmm;

	for (i = 0; i < 16; i++)
		tmp[i] = (i + imm < 16) ? data[i + imm] : 0;

	memcpy(&xmm, tmp, 16);
	write_xmm_reg(ctxt, ctxt->modrm_rm, &xmm);

	ctxt->dst.type = OP_NONE;
	return X86EMUL_CONTINUE;
}

/*
 * PINSRW (66 0F C4): Insert word from r32/m16 into XMM at position imm8.
 * This is ImplicitOps because src is GPR/m16, not XMM.
 */
static int em_pinsrw(struct x86_emulate_ctxt *ctxt)
{
	__sse128_u dst;
	u16 val;
	u8 imm;
	int rc;

	rc = em_check_sse_prereqs(ctxt);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	/* Read source (GPR or m16) */
	if (ctxt->modrm_mod == 3) {
		val = (u16)reg_read(ctxt, ctxt->modrm_rm);
	} else {
		u64 tmp = 0;

		rc = read_modrm_mem(ctxt, &tmp, 2);
		if (rc != X86EMUL_CONTINUE)
			return rc;
		val = (u16)tmp;
	}

	rc = do_insn_fetch_bytes(ctxt, 1);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	imm = *ctxt->fetch.ptr++ & 7;

	/* Read destination XMM (or VEX.vvvv source for AVX) */
	if (ctxt->d & Avx)
		kvm_read_sse_reg(ctxt->vex_reg, &dst.vec);
	else
		kvm_read_sse_reg(ctxt->modrm_reg, &dst.vec);

	/* Treat XMM as array of u16 */
	((u16 *)&dst)[imm] = val;
	write_xmm_reg(ctxt, ctxt->modrm_reg, &dst.vec);

	ctxt->dst.type = OP_NONE;
	return X86EMUL_CONTINUE;
}

/*
 * PEXTRW (66 0F C5): Extract word from XMM to GPR.
 * This is ImplicitOps because dst is GPR, src is XMM.
 */
static int em_pextrw(struct x86_emulate_ctxt *ctxt)
{
	sse128_t xmm;
	u8 imm;
	int rc;

	rc = em_check_sse_prereqs(ctxt);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	kvm_read_sse_reg(ctxt->modrm_rm, &xmm);

	rc = do_insn_fetch_bytes(ctxt, 1);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	imm = *ctxt->fetch.ptr++ & 7;

	/* Result goes to GPR (modrm_reg), zero-extended */
	*reg_write(ctxt, ctxt->modrm_reg) = ((u16 *)&xmm)[imm];

	ctxt->dst.type = OP_NONE;
	return X86EMUL_CONTINUE;
}

/*
 * PEXTRW (66 0F 3A 15): Alternate encoding - extract word to r/m16.
 * Unlike 0F C5, this can write to memory.
 */
static int em_pextrw_3a(struct x86_emulate_ctxt *ctxt)
{
	u8 *src = (u8 *)ctxt->src.valptr;
	u8 imm;
	int rc;

	rc = do_insn_fetch_bytes(ctxt, 1);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	imm = *ctxt->fetch.ptr++;

	ctxt->dst.val = *(u16 *)(src + (imm & 7) * 2);
	ctxt->dst.bytes = 4; /* zero-extended to 32/64 bits */
	return X86EMUL_CONTINUE;
}

/*
 * EXTRACTPS (66 0F 3A 17): Extract float (dword) from XMM to r/m32.
 */
static int em_extractps(struct x86_emulate_ctxt *ctxt)
{
	u8 *src = (u8 *)ctxt->src.valptr;
	u8 imm;
	int rc;

	rc = do_insn_fetch_bytes(ctxt, 1);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	imm = *ctxt->fetch.ptr++;

	memcpy(ctxt->dst.valptr, src + (imm & 3) * 4, 4);
	ctxt->dst.bytes = 4;
	return X86EMUL_CONTINUE;
}

/*
 * INSERTPS (66 0F 3A 21): Insert float with imm8 controlling positions.
 * Use host FPU to execute.
 */
static int em_insertps(struct x86_emulate_ctxt *ctxt)
{
	u8 *dst = (u8 *)ctxt->dst.valptr;
	u8 *src = (u8 *)ctxt->src.valptr;
	u8 *src1 = ctxt->src2.type == OP_NONE ? dst : (u8 *)ctxt->src2.valptr;
	sse128_t saved_xmm0, saved_xmm1;
	u8 tmp_dst[16] __aligned(16);
	u8 imm;
	int rc;

	rc = do_insn_fetch_bytes(ctxt, 1);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	imm = *ctxt->fetch.ptr++;

	kvm_fpu_get();
	_kvm_read_sse_reg(0, &saved_xmm0);
	_kvm_read_sse_reg(1, &saved_xmm1);
	asm volatile("movdqu %0, %%xmm0" : : "m"(*(sse128_t *)src1));
	asm volatile("movdqu %0, %%xmm1" : : "m"(*(sse128_t *)src));

#define INSERTPS_CASE(n)						\
	case n:								\
		asm volatile("insertps $" #n ", %%xmm1, %%xmm0" :::); \
		break
	switch (imm) {
	INSERTPS_CASE(0x00); INSERTPS_CASE(0x01); INSERTPS_CASE(0x02); INSERTPS_CASE(0x03);
	INSERTPS_CASE(0x04); INSERTPS_CASE(0x05); INSERTPS_CASE(0x06); INSERTPS_CASE(0x07);
	INSERTPS_CASE(0x08); INSERTPS_CASE(0x09); INSERTPS_CASE(0x0a); INSERTPS_CASE(0x0b);
	INSERTPS_CASE(0x0c); INSERTPS_CASE(0x0d); INSERTPS_CASE(0x0e); INSERTPS_CASE(0x0f);
	INSERTPS_CASE(0x10); INSERTPS_CASE(0x11); INSERTPS_CASE(0x12); INSERTPS_CASE(0x13);
	INSERTPS_CASE(0x14); INSERTPS_CASE(0x15); INSERTPS_CASE(0x16); INSERTPS_CASE(0x17);
	INSERTPS_CASE(0x18); INSERTPS_CASE(0x19); INSERTPS_CASE(0x1a); INSERTPS_CASE(0x1b);
	INSERTPS_CASE(0x1c); INSERTPS_CASE(0x1d); INSERTPS_CASE(0x1e); INSERTPS_CASE(0x1f);
	INSERTPS_CASE(0x20); INSERTPS_CASE(0x21); INSERTPS_CASE(0x22); INSERTPS_CASE(0x23);
	INSERTPS_CASE(0x24); INSERTPS_CASE(0x25); INSERTPS_CASE(0x26); INSERTPS_CASE(0x27);
	INSERTPS_CASE(0x28); INSERTPS_CASE(0x29); INSERTPS_CASE(0x2a); INSERTPS_CASE(0x2b);
	INSERTPS_CASE(0x2c); INSERTPS_CASE(0x2d); INSERTPS_CASE(0x2e); INSERTPS_CASE(0x2f);
	INSERTPS_CASE(0x30); INSERTPS_CASE(0x31); INSERTPS_CASE(0x32); INSERTPS_CASE(0x33);
	INSERTPS_CASE(0x34); INSERTPS_CASE(0x35); INSERTPS_CASE(0x36); INSERTPS_CASE(0x37);
	INSERTPS_CASE(0x38); INSERTPS_CASE(0x39); INSERTPS_CASE(0x3a); INSERTPS_CASE(0x3b);
	INSERTPS_CASE(0x3c); INSERTPS_CASE(0x3d); INSERTPS_CASE(0x3e); INSERTPS_CASE(0x3f);
	INSERTPS_CASE(0x40); INSERTPS_CASE(0x41); INSERTPS_CASE(0x42); INSERTPS_CASE(0x43);
	INSERTPS_CASE(0x44); INSERTPS_CASE(0x45); INSERTPS_CASE(0x46); INSERTPS_CASE(0x47);
	INSERTPS_CASE(0x48); INSERTPS_CASE(0x49); INSERTPS_CASE(0x4a); INSERTPS_CASE(0x4b);
	INSERTPS_CASE(0x4c); INSERTPS_CASE(0x4d); INSERTPS_CASE(0x4e); INSERTPS_CASE(0x4f);
	INSERTPS_CASE(0x50); INSERTPS_CASE(0x51); INSERTPS_CASE(0x52); INSERTPS_CASE(0x53);
	INSERTPS_CASE(0x54); INSERTPS_CASE(0x55); INSERTPS_CASE(0x56); INSERTPS_CASE(0x57);
	INSERTPS_CASE(0x58); INSERTPS_CASE(0x59); INSERTPS_CASE(0x5a); INSERTPS_CASE(0x5b);
	INSERTPS_CASE(0x5c); INSERTPS_CASE(0x5d); INSERTPS_CASE(0x5e); INSERTPS_CASE(0x5f);
	INSERTPS_CASE(0x60); INSERTPS_CASE(0x61); INSERTPS_CASE(0x62); INSERTPS_CASE(0x63);
	INSERTPS_CASE(0x64); INSERTPS_CASE(0x65); INSERTPS_CASE(0x66); INSERTPS_CASE(0x67);
	INSERTPS_CASE(0x68); INSERTPS_CASE(0x69); INSERTPS_CASE(0x6a); INSERTPS_CASE(0x6b);
	INSERTPS_CASE(0x6c); INSERTPS_CASE(0x6d); INSERTPS_CASE(0x6e); INSERTPS_CASE(0x6f);
	INSERTPS_CASE(0x70); INSERTPS_CASE(0x71); INSERTPS_CASE(0x72); INSERTPS_CASE(0x73);
	INSERTPS_CASE(0x74); INSERTPS_CASE(0x75); INSERTPS_CASE(0x76); INSERTPS_CASE(0x77);
	INSERTPS_CASE(0x78); INSERTPS_CASE(0x79); INSERTPS_CASE(0x7a); INSERTPS_CASE(0x7b);
	INSERTPS_CASE(0x7c); INSERTPS_CASE(0x7d); INSERTPS_CASE(0x7e); INSERTPS_CASE(0x7f);
	INSERTPS_CASE(0x80); INSERTPS_CASE(0x81); INSERTPS_CASE(0x82); INSERTPS_CASE(0x83);
	INSERTPS_CASE(0x84); INSERTPS_CASE(0x85); INSERTPS_CASE(0x86); INSERTPS_CASE(0x87);
	INSERTPS_CASE(0x88); INSERTPS_CASE(0x89); INSERTPS_CASE(0x8a); INSERTPS_CASE(0x8b);
	INSERTPS_CASE(0x8c); INSERTPS_CASE(0x8d); INSERTPS_CASE(0x8e); INSERTPS_CASE(0x8f);
	INSERTPS_CASE(0x90); INSERTPS_CASE(0x91); INSERTPS_CASE(0x92); INSERTPS_CASE(0x93);
	INSERTPS_CASE(0x94); INSERTPS_CASE(0x95); INSERTPS_CASE(0x96); INSERTPS_CASE(0x97);
	INSERTPS_CASE(0x98); INSERTPS_CASE(0x99); INSERTPS_CASE(0x9a); INSERTPS_CASE(0x9b);
	INSERTPS_CASE(0x9c); INSERTPS_CASE(0x9d); INSERTPS_CASE(0x9e); INSERTPS_CASE(0x9f);
	INSERTPS_CASE(0xa0); INSERTPS_CASE(0xa1); INSERTPS_CASE(0xa2); INSERTPS_CASE(0xa3);
	INSERTPS_CASE(0xa4); INSERTPS_CASE(0xa5); INSERTPS_CASE(0xa6); INSERTPS_CASE(0xa7);
	INSERTPS_CASE(0xa8); INSERTPS_CASE(0xa9); INSERTPS_CASE(0xaa); INSERTPS_CASE(0xab);
	INSERTPS_CASE(0xac); INSERTPS_CASE(0xad); INSERTPS_CASE(0xae); INSERTPS_CASE(0xaf);
	INSERTPS_CASE(0xb0); INSERTPS_CASE(0xb1); INSERTPS_CASE(0xb2); INSERTPS_CASE(0xb3);
	INSERTPS_CASE(0xb4); INSERTPS_CASE(0xb5); INSERTPS_CASE(0xb6); INSERTPS_CASE(0xb7);
	INSERTPS_CASE(0xb8); INSERTPS_CASE(0xb9); INSERTPS_CASE(0xba); INSERTPS_CASE(0xbb);
	INSERTPS_CASE(0xbc); INSERTPS_CASE(0xbd); INSERTPS_CASE(0xbe); INSERTPS_CASE(0xbf);
	INSERTPS_CASE(0xc0); INSERTPS_CASE(0xc1); INSERTPS_CASE(0xc2); INSERTPS_CASE(0xc3);
	INSERTPS_CASE(0xc4); INSERTPS_CASE(0xc5); INSERTPS_CASE(0xc6); INSERTPS_CASE(0xc7);
	INSERTPS_CASE(0xc8); INSERTPS_CASE(0xc9); INSERTPS_CASE(0xca); INSERTPS_CASE(0xcb);
	INSERTPS_CASE(0xcc); INSERTPS_CASE(0xcd); INSERTPS_CASE(0xce); INSERTPS_CASE(0xcf);
	INSERTPS_CASE(0xd0); INSERTPS_CASE(0xd1); INSERTPS_CASE(0xd2); INSERTPS_CASE(0xd3);
	INSERTPS_CASE(0xd4); INSERTPS_CASE(0xd5); INSERTPS_CASE(0xd6); INSERTPS_CASE(0xd7);
	INSERTPS_CASE(0xd8); INSERTPS_CASE(0xd9); INSERTPS_CASE(0xda); INSERTPS_CASE(0xdb);
	INSERTPS_CASE(0xdc); INSERTPS_CASE(0xdd); INSERTPS_CASE(0xde); INSERTPS_CASE(0xdf);
	INSERTPS_CASE(0xe0); INSERTPS_CASE(0xe1); INSERTPS_CASE(0xe2); INSERTPS_CASE(0xe3);
	INSERTPS_CASE(0xe4); INSERTPS_CASE(0xe5); INSERTPS_CASE(0xe6); INSERTPS_CASE(0xe7);
	INSERTPS_CASE(0xe8); INSERTPS_CASE(0xe9); INSERTPS_CASE(0xea); INSERTPS_CASE(0xeb);
	INSERTPS_CASE(0xec); INSERTPS_CASE(0xed); INSERTPS_CASE(0xee); INSERTPS_CASE(0xef);
	INSERTPS_CASE(0xf0); INSERTPS_CASE(0xf1); INSERTPS_CASE(0xf2); INSERTPS_CASE(0xf3);
	INSERTPS_CASE(0xf4); INSERTPS_CASE(0xf5); INSERTPS_CASE(0xf6); INSERTPS_CASE(0xf7);
	INSERTPS_CASE(0xf8); INSERTPS_CASE(0xf9); INSERTPS_CASE(0xfa); INSERTPS_CASE(0xfb);
	INSERTPS_CASE(0xfc); INSERTPS_CASE(0xfd); INSERTPS_CASE(0xfe); INSERTPS_CASE(0xff);
	}
#undef INSERTPS_CASE

	asm volatile("movdqu %%xmm0, %0" : "=m"(*(sse128_t *)tmp_dst));
	_kvm_write_sse_reg(0, &saved_xmm0);
	_kvm_write_sse_reg(1, &saved_xmm1);
	kvm_fpu_put();
	memcpy(dst, tmp_dst, 16);
	return X86EMUL_CONTINUE;
}

/*
 * DPPS (66 0F 3A 40): Dot product of packed singles with imm8 mask.
 * Use host FPU.
 */
static int em_dpps(struct x86_emulate_ctxt *ctxt)
{
	u8 *dst = (u8 *)ctxt->dst.valptr;
	u8 *src = (u8 *)ctxt->src.valptr;
	u8 *src1 = ctxt->src2.type == OP_NONE ? dst : (u8 *)ctxt->src2.valptr;
	sse128_t saved_xmm0, saved_xmm1;
	u8 tmp_dst[16] __aligned(16);
	u8 imm;
	int rc;

	rc = do_insn_fetch_bytes(ctxt, 1);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	imm = *ctxt->fetch.ptr++;

	kvm_fpu_get();
	_kvm_read_sse_reg(0, &saved_xmm0);
	_kvm_read_sse_reg(1, &saved_xmm1);
	asm volatile("movdqu %0, %%xmm0" : : "m"(*(sse128_t *)src1));
	asm volatile("movdqu %0, %%xmm1" : : "m"(*(sse128_t *)src));

#define DPPS_CASE(n)							\
	case n:								\
		asm volatile("dpps $" #n ", %%xmm1, %%xmm0" :::); \
		break
	switch (imm) {
	DPPS_CASE(0x00); DPPS_CASE(0x01); DPPS_CASE(0x02); DPPS_CASE(0x03);
	DPPS_CASE(0x04); DPPS_CASE(0x05); DPPS_CASE(0x06); DPPS_CASE(0x07);
	DPPS_CASE(0x08); DPPS_CASE(0x09); DPPS_CASE(0x0a); DPPS_CASE(0x0b);
	DPPS_CASE(0x0c); DPPS_CASE(0x0d); DPPS_CASE(0x0e); DPPS_CASE(0x0f);
	DPPS_CASE(0x10); DPPS_CASE(0x11); DPPS_CASE(0x12); DPPS_CASE(0x13);
	DPPS_CASE(0x14); DPPS_CASE(0x15); DPPS_CASE(0x16); DPPS_CASE(0x17);
	DPPS_CASE(0x18); DPPS_CASE(0x19); DPPS_CASE(0x1a); DPPS_CASE(0x1b);
	DPPS_CASE(0x1c); DPPS_CASE(0x1d); DPPS_CASE(0x1e); DPPS_CASE(0x1f);
	DPPS_CASE(0x20); DPPS_CASE(0x21); DPPS_CASE(0x22); DPPS_CASE(0x23);
	DPPS_CASE(0x24); DPPS_CASE(0x25); DPPS_CASE(0x26); DPPS_CASE(0x27);
	DPPS_CASE(0x28); DPPS_CASE(0x29); DPPS_CASE(0x2a); DPPS_CASE(0x2b);
	DPPS_CASE(0x2c); DPPS_CASE(0x2d); DPPS_CASE(0x2e); DPPS_CASE(0x2f);
	DPPS_CASE(0x30); DPPS_CASE(0x31); DPPS_CASE(0x32); DPPS_CASE(0x33);
	DPPS_CASE(0x34); DPPS_CASE(0x35); DPPS_CASE(0x36); DPPS_CASE(0x37);
	DPPS_CASE(0x38); DPPS_CASE(0x39); DPPS_CASE(0x3a); DPPS_CASE(0x3b);
	DPPS_CASE(0x3c); DPPS_CASE(0x3d); DPPS_CASE(0x3e); DPPS_CASE(0x3f);
	DPPS_CASE(0x40); DPPS_CASE(0x41); DPPS_CASE(0x42); DPPS_CASE(0x43);
	DPPS_CASE(0x44); DPPS_CASE(0x45); DPPS_CASE(0x46); DPPS_CASE(0x47);
	DPPS_CASE(0x48); DPPS_CASE(0x49); DPPS_CASE(0x4a); DPPS_CASE(0x4b);
	DPPS_CASE(0x4c); DPPS_CASE(0x4d); DPPS_CASE(0x4e); DPPS_CASE(0x4f);
	DPPS_CASE(0x50); DPPS_CASE(0x51); DPPS_CASE(0x52); DPPS_CASE(0x53);
	DPPS_CASE(0x54); DPPS_CASE(0x55); DPPS_CASE(0x56); DPPS_CASE(0x57);
	DPPS_CASE(0x58); DPPS_CASE(0x59); DPPS_CASE(0x5a); DPPS_CASE(0x5b);
	DPPS_CASE(0x5c); DPPS_CASE(0x5d); DPPS_CASE(0x5e); DPPS_CASE(0x5f);
	DPPS_CASE(0x60); DPPS_CASE(0x61); DPPS_CASE(0x62); DPPS_CASE(0x63);
	DPPS_CASE(0x64); DPPS_CASE(0x65); DPPS_CASE(0x66); DPPS_CASE(0x67);
	DPPS_CASE(0x68); DPPS_CASE(0x69); DPPS_CASE(0x6a); DPPS_CASE(0x6b);
	DPPS_CASE(0x6c); DPPS_CASE(0x6d); DPPS_CASE(0x6e); DPPS_CASE(0x6f);
	DPPS_CASE(0x70); DPPS_CASE(0x71); DPPS_CASE(0x72); DPPS_CASE(0x73);
	DPPS_CASE(0x74); DPPS_CASE(0x75); DPPS_CASE(0x76); DPPS_CASE(0x77);
	DPPS_CASE(0x78); DPPS_CASE(0x79); DPPS_CASE(0x7a); DPPS_CASE(0x7b);
	DPPS_CASE(0x7c); DPPS_CASE(0x7d); DPPS_CASE(0x7e); DPPS_CASE(0x7f);
	DPPS_CASE(0x80); DPPS_CASE(0x81); DPPS_CASE(0x82); DPPS_CASE(0x83);
	DPPS_CASE(0x84); DPPS_CASE(0x85); DPPS_CASE(0x86); DPPS_CASE(0x87);
	DPPS_CASE(0x88); DPPS_CASE(0x89); DPPS_CASE(0x8a); DPPS_CASE(0x8b);
	DPPS_CASE(0x8c); DPPS_CASE(0x8d); DPPS_CASE(0x8e); DPPS_CASE(0x8f);
	DPPS_CASE(0x90); DPPS_CASE(0x91); DPPS_CASE(0x92); DPPS_CASE(0x93);
	DPPS_CASE(0x94); DPPS_CASE(0x95); DPPS_CASE(0x96); DPPS_CASE(0x97);
	DPPS_CASE(0x98); DPPS_CASE(0x99); DPPS_CASE(0x9a); DPPS_CASE(0x9b);
	DPPS_CASE(0x9c); DPPS_CASE(0x9d); DPPS_CASE(0x9e); DPPS_CASE(0x9f);
	DPPS_CASE(0xa0); DPPS_CASE(0xa1); DPPS_CASE(0xa2); DPPS_CASE(0xa3);
	DPPS_CASE(0xa4); DPPS_CASE(0xa5); DPPS_CASE(0xa6); DPPS_CASE(0xa7);
	DPPS_CASE(0xa8); DPPS_CASE(0xa9); DPPS_CASE(0xaa); DPPS_CASE(0xab);
	DPPS_CASE(0xac); DPPS_CASE(0xad); DPPS_CASE(0xae); DPPS_CASE(0xaf);
	DPPS_CASE(0xb0); DPPS_CASE(0xb1); DPPS_CASE(0xb2); DPPS_CASE(0xb3);
	DPPS_CASE(0xb4); DPPS_CASE(0xb5); DPPS_CASE(0xb6); DPPS_CASE(0xb7);
	DPPS_CASE(0xb8); DPPS_CASE(0xb9); DPPS_CASE(0xba); DPPS_CASE(0xbb);
	DPPS_CASE(0xbc); DPPS_CASE(0xbd); DPPS_CASE(0xbe); DPPS_CASE(0xbf);
	DPPS_CASE(0xc0); DPPS_CASE(0xc1); DPPS_CASE(0xc2); DPPS_CASE(0xc3);
	DPPS_CASE(0xc4); DPPS_CASE(0xc5); DPPS_CASE(0xc6); DPPS_CASE(0xc7);
	DPPS_CASE(0xc8); DPPS_CASE(0xc9); DPPS_CASE(0xca); DPPS_CASE(0xcb);
	DPPS_CASE(0xcc); DPPS_CASE(0xcd); DPPS_CASE(0xce); DPPS_CASE(0xcf);
	DPPS_CASE(0xd0); DPPS_CASE(0xd1); DPPS_CASE(0xd2); DPPS_CASE(0xd3);
	DPPS_CASE(0xd4); DPPS_CASE(0xd5); DPPS_CASE(0xd6); DPPS_CASE(0xd7);
	DPPS_CASE(0xd8); DPPS_CASE(0xd9); DPPS_CASE(0xda); DPPS_CASE(0xdb);
	DPPS_CASE(0xdc); DPPS_CASE(0xdd); DPPS_CASE(0xde); DPPS_CASE(0xdf);
	DPPS_CASE(0xe0); DPPS_CASE(0xe1); DPPS_CASE(0xe2); DPPS_CASE(0xe3);
	DPPS_CASE(0xe4); DPPS_CASE(0xe5); DPPS_CASE(0xe6); DPPS_CASE(0xe7);
	DPPS_CASE(0xe8); DPPS_CASE(0xe9); DPPS_CASE(0xea); DPPS_CASE(0xeb);
	DPPS_CASE(0xec); DPPS_CASE(0xed); DPPS_CASE(0xee); DPPS_CASE(0xef);
	DPPS_CASE(0xf0); DPPS_CASE(0xf1); DPPS_CASE(0xf2); DPPS_CASE(0xf3);
	DPPS_CASE(0xf4); DPPS_CASE(0xf5); DPPS_CASE(0xf6); DPPS_CASE(0xf7);
	DPPS_CASE(0xf8); DPPS_CASE(0xf9); DPPS_CASE(0xfa); DPPS_CASE(0xfb);
	DPPS_CASE(0xfc); DPPS_CASE(0xfd); DPPS_CASE(0xfe); DPPS_CASE(0xff);
	}
#undef DPPS_CASE

	asm volatile("movdqu %%xmm0, %0" : "=m"(*(sse128_t *)tmp_dst));
	_kvm_write_sse_reg(0, &saved_xmm0);
	_kvm_write_sse_reg(1, &saved_xmm1);
	kvm_fpu_put();
	memcpy(dst, tmp_dst, 16);
	return X86EMUL_CONTINUE;
}

/*
 * DPPD (66 0F 3A 41): Dot product of packed doubles with imm8 mask.
 * Use host FPU.
 */
static int em_dppd(struct x86_emulate_ctxt *ctxt)
{
	u8 *dst = (u8 *)ctxt->dst.valptr;
	u8 *src = (u8 *)ctxt->src.valptr;
	u8 *src1 = ctxt->src2.type == OP_NONE ? dst : (u8 *)ctxt->src2.valptr;
	sse128_t saved_xmm0, saved_xmm1;
	u8 tmp_dst[16] __aligned(16);
	u8 imm;
	int rc;

	rc = do_insn_fetch_bytes(ctxt, 1);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	imm = *ctxt->fetch.ptr++;

	kvm_fpu_get();
	_kvm_read_sse_reg(0, &saved_xmm0);
	_kvm_read_sse_reg(1, &saved_xmm1);
	asm volatile("movdqu %0, %%xmm0" : : "m"(*(sse128_t *)src1));
	asm volatile("movdqu %0, %%xmm1" : : "m"(*(sse128_t *)src));

#define DPPD_CASE(n)							\
	case n:								\
		asm volatile("dppd $" #n ", %%xmm1, %%xmm0" :::); \
		break
	switch (imm & 0x3f) {
	DPPD_CASE(0x00); DPPD_CASE(0x01); DPPD_CASE(0x02); DPPD_CASE(0x03);
	DPPD_CASE(0x04); DPPD_CASE(0x05); DPPD_CASE(0x06); DPPD_CASE(0x07);
	DPPD_CASE(0x08); DPPD_CASE(0x09); DPPD_CASE(0x0a); DPPD_CASE(0x0b);
	DPPD_CASE(0x0c); DPPD_CASE(0x0d); DPPD_CASE(0x0e); DPPD_CASE(0x0f);
	DPPD_CASE(0x10); DPPD_CASE(0x11); DPPD_CASE(0x12); DPPD_CASE(0x13);
	DPPD_CASE(0x14); DPPD_CASE(0x15); DPPD_CASE(0x16); DPPD_CASE(0x17);
	DPPD_CASE(0x18); DPPD_CASE(0x19); DPPD_CASE(0x1a); DPPD_CASE(0x1b);
	DPPD_CASE(0x1c); DPPD_CASE(0x1d); DPPD_CASE(0x1e); DPPD_CASE(0x1f);
	DPPD_CASE(0x20); DPPD_CASE(0x21); DPPD_CASE(0x22); DPPD_CASE(0x23);
	DPPD_CASE(0x24); DPPD_CASE(0x25); DPPD_CASE(0x26); DPPD_CASE(0x27);
	DPPD_CASE(0x28); DPPD_CASE(0x29); DPPD_CASE(0x2a); DPPD_CASE(0x2b);
	DPPD_CASE(0x2c); DPPD_CASE(0x2d); DPPD_CASE(0x2e); DPPD_CASE(0x2f);
	DPPD_CASE(0x30); DPPD_CASE(0x31); DPPD_CASE(0x32); DPPD_CASE(0x33);
	DPPD_CASE(0x34); DPPD_CASE(0x35); DPPD_CASE(0x36); DPPD_CASE(0x37);
	DPPD_CASE(0x38); DPPD_CASE(0x39); DPPD_CASE(0x3a); DPPD_CASE(0x3b);
	DPPD_CASE(0x3c); DPPD_CASE(0x3d); DPPD_CASE(0x3e); DPPD_CASE(0x3f);
	}
#undef DPPD_CASE

	asm volatile("movdqu %%xmm0, %0" : "=m"(*(sse128_t *)tmp_dst));
	_kvm_write_sse_reg(0, &saved_xmm0);
	_kvm_write_sse_reg(1, &saved_xmm1);
	kvm_fpu_put();
	memcpy(dst, tmp_dst, 16);
	return X86EMUL_CONTINUE;
}

/*
 * MPSADBW (66 0F 3A 42): Multiple sum of absolute differences.
 * Very complex - delegate to host CPU.
 */
static int em_mpsadbw(struct x86_emulate_ctxt *ctxt)
{
	u8 *dst = (u8 *)ctxt->dst.valptr;
	u8 *src = (u8 *)ctxt->src.valptr;
	u8 *src1 = ctxt->src2.type == OP_NONE ? dst : (u8 *)ctxt->src2.valptr;
	sse128_t saved_xmm0, saved_xmm1;
	u8 tmp_dst[16] __aligned(16);
	u8 imm;
	int rc;

	rc = do_insn_fetch_bytes(ctxt, 1);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	imm = *ctxt->fetch.ptr++;

	kvm_fpu_get();
	_kvm_read_sse_reg(0, &saved_xmm0);
	_kvm_read_sse_reg(1, &saved_xmm1);
	asm volatile("movdqu %0, %%xmm0" : : "m"(*(sse128_t *)src1));
	asm volatile("movdqu %0, %%xmm1" : : "m"(*(sse128_t *)src));

#define MPSADBW_CASE(n)							\
	case n:								\
		asm volatile("mpsadbw $" #n ", %%xmm1, %%xmm0" :::); \
		break
	switch (imm & 0x07) {
	MPSADBW_CASE(0); MPSADBW_CASE(1); MPSADBW_CASE(2); MPSADBW_CASE(3);
	MPSADBW_CASE(4); MPSADBW_CASE(5); MPSADBW_CASE(6); MPSADBW_CASE(7);
	}
#undef MPSADBW_CASE

	asm volatile("movdqu %%xmm0, %0" : "=m"(*(sse128_t *)tmp_dst));
	_kvm_write_sse_reg(0, &saved_xmm0);
	_kvm_write_sse_reg(1, &saved_xmm1);
	kvm_fpu_put();
	memcpy(dst, tmp_dst, 16);
	return X86EMUL_CONTINUE;
}

/*
 * PCMPESTRM (66 0F 3A 60): Explicit-length string compare, mask output.
 * Very complex - delegate to host CPU.
 */
static int em_pcmpestrm(struct x86_emulate_ctxt *ctxt)
{
	u8 *dst = (u8 *)ctxt->dst.valptr;
	u8 *src = (u8 *)ctxt->src.valptr;
	sse128_t saved_xmm0, saved_xmm1;
	unsigned long flags;
	u8 imm;
	int rc;
	u32 eax_val, edx_val;

	rc = do_insn_fetch_bytes(ctxt, 1);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	imm = *ctxt->fetch.ptr++;

	eax_val = (u32)reg_read(ctxt, VCPU_REGS_RAX);
	edx_val = (u32)reg_read(ctxt, VCPU_REGS_RDX);

	kvm_fpu_get();
	_kvm_read_sse_reg(0, &saved_xmm0);
	_kvm_read_sse_reg(1, &saved_xmm1);

	asm volatile("movdqu %0, %%xmm0" : : "m"(*(sse128_t *)dst));
	asm volatile("movdqu %0, %%xmm1" : : "m"(*(sse128_t *)src));

#define PCMPESTRM_CASE(n)						\
	case n:								\
		asm volatile("pcmpestrm $" #n ", %%xmm1, %%xmm0\n\t"	\
			     "pushf\n\t"				\
			     "pop %[flags]"				\
			     : [flags] "=r" (flags)			\
			     : "a" (eax_val), "d" (edx_val)		\
			     : "cc");					\
		break
	switch (imm) {
	PCMPESTRM_CASE(0x00); PCMPESTRM_CASE(0x01); PCMPESTRM_CASE(0x02); PCMPESTRM_CASE(0x03);
	PCMPESTRM_CASE(0x04); PCMPESTRM_CASE(0x05); PCMPESTRM_CASE(0x06); PCMPESTRM_CASE(0x07);
	PCMPESTRM_CASE(0x08); PCMPESTRM_CASE(0x09); PCMPESTRM_CASE(0x0a); PCMPESTRM_CASE(0x0b);
	PCMPESTRM_CASE(0x0c); PCMPESTRM_CASE(0x0d); PCMPESTRM_CASE(0x0e); PCMPESTRM_CASE(0x0f);
	PCMPESTRM_CASE(0x10); PCMPESTRM_CASE(0x11); PCMPESTRM_CASE(0x12); PCMPESTRM_CASE(0x13);
	PCMPESTRM_CASE(0x14); PCMPESTRM_CASE(0x15); PCMPESTRM_CASE(0x16); PCMPESTRM_CASE(0x17);
	PCMPESTRM_CASE(0x18); PCMPESTRM_CASE(0x19); PCMPESTRM_CASE(0x1a); PCMPESTRM_CASE(0x1b);
	PCMPESTRM_CASE(0x1c); PCMPESTRM_CASE(0x1d); PCMPESTRM_CASE(0x1e); PCMPESTRM_CASE(0x1f);
	PCMPESTRM_CASE(0x20); PCMPESTRM_CASE(0x21); PCMPESTRM_CASE(0x22); PCMPESTRM_CASE(0x23);
	PCMPESTRM_CASE(0x24); PCMPESTRM_CASE(0x25); PCMPESTRM_CASE(0x26); PCMPESTRM_CASE(0x27);
	PCMPESTRM_CASE(0x28); PCMPESTRM_CASE(0x29); PCMPESTRM_CASE(0x2a); PCMPESTRM_CASE(0x2b);
	PCMPESTRM_CASE(0x2c); PCMPESTRM_CASE(0x2d); PCMPESTRM_CASE(0x2e); PCMPESTRM_CASE(0x2f);
	PCMPESTRM_CASE(0x30); PCMPESTRM_CASE(0x31); PCMPESTRM_CASE(0x32); PCMPESTRM_CASE(0x33);
	PCMPESTRM_CASE(0x34); PCMPESTRM_CASE(0x35); PCMPESTRM_CASE(0x36); PCMPESTRM_CASE(0x37);
	PCMPESTRM_CASE(0x38); PCMPESTRM_CASE(0x39); PCMPESTRM_CASE(0x3a); PCMPESTRM_CASE(0x3b);
	PCMPESTRM_CASE(0x3c); PCMPESTRM_CASE(0x3d); PCMPESTRM_CASE(0x3e); PCMPESTRM_CASE(0x3f);
	PCMPESTRM_CASE(0x40); PCMPESTRM_CASE(0x41); PCMPESTRM_CASE(0x42); PCMPESTRM_CASE(0x43);
	PCMPESTRM_CASE(0x44); PCMPESTRM_CASE(0x45); PCMPESTRM_CASE(0x46); PCMPESTRM_CASE(0x47);
	PCMPESTRM_CASE(0x48); PCMPESTRM_CASE(0x49); PCMPESTRM_CASE(0x4a); PCMPESTRM_CASE(0x4b);
	PCMPESTRM_CASE(0x4c); PCMPESTRM_CASE(0x4d); PCMPESTRM_CASE(0x4e); PCMPESTRM_CASE(0x4f);
	default:
		_kvm_write_sse_reg(0, &saved_xmm0);
		_kvm_write_sse_reg(1, &saved_xmm1);
		kvm_fpu_put();
		return X86EMUL_UNHANDLEABLE;
	}
#undef PCMPESTRM_CASE

	/* PCMPESTRM writes result mask to XMM0 - read it into dst */
	{
		sse128_t result;
		_kvm_read_sse_reg(0, &result);
		memcpy(dst, &result, 16);
	}

	_kvm_write_sse_reg(0, &saved_xmm0);
	_kvm_write_sse_reg(1, &saved_xmm1);
	kvm_fpu_put();

	/* Update flags */
	ctxt->eflags = (ctxt->eflags & ~(X86_EFLAGS_CF | X86_EFLAGS_ZF |
			X86_EFLAGS_SF | X86_EFLAGS_OF | X86_EFLAGS_AF |
			X86_EFLAGS_PF)) |
		       (flags & (X86_EFLAGS_CF | X86_EFLAGS_ZF |
				 X86_EFLAGS_SF | X86_EFLAGS_OF));

	return X86EMUL_CONTINUE;
}

/*
 * PCMPESTRI (66 0F 3A 61): Explicit-length string compare, index output.
 * Very complex - delegate to host CPU.
 */
static int em_pcmpestri(struct x86_emulate_ctxt *ctxt)
{
	u8 *dst = (u8 *)ctxt->dst.valptr;
	u8 *src = (u8 *)ctxt->src.valptr;
	sse128_t saved_xmm0, saved_xmm1;
	unsigned long flags;
	u32 ecx_result;
	u8 imm;
	int rc;
	u32 eax_val, edx_val;

	rc = do_insn_fetch_bytes(ctxt, 1);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	imm = *ctxt->fetch.ptr++;

	eax_val = (u32)reg_read(ctxt, VCPU_REGS_RAX);
	edx_val = (u32)reg_read(ctxt, VCPU_REGS_RDX);

	kvm_fpu_get();
	_kvm_read_sse_reg(0, &saved_xmm0);
	_kvm_read_sse_reg(1, &saved_xmm1);

	asm volatile("movdqu %0, %%xmm0" : : "m"(*(sse128_t *)dst));
	asm volatile("movdqu %0, %%xmm1" : : "m"(*(sse128_t *)src));

#define PCMPESTRI_CASE(n)						\
	case n:								\
		asm volatile("pcmpestri $" #n ", %%xmm1, %%xmm0\n\t"	\
			     "pushf\n\t"				\
			     "pop %[flags]\n\t"				\
			     "mov %%ecx, %[ecx]"			\
			     : [flags] "=r" (flags), [ecx] "=r" (ecx_result) \
			     : "a" (eax_val), "d" (edx_val)		\
			     : "ecx", "cc");				\
		break
	switch (imm) {
	PCMPESTRI_CASE(0x00); PCMPESTRI_CASE(0x01); PCMPESTRI_CASE(0x02); PCMPESTRI_CASE(0x03);
	PCMPESTRI_CASE(0x04); PCMPESTRI_CASE(0x05); PCMPESTRI_CASE(0x06); PCMPESTRI_CASE(0x07);
	PCMPESTRI_CASE(0x08); PCMPESTRI_CASE(0x09); PCMPESTRI_CASE(0x0a); PCMPESTRI_CASE(0x0b);
	PCMPESTRI_CASE(0x0c); PCMPESTRI_CASE(0x0d); PCMPESTRI_CASE(0x0e); PCMPESTRI_CASE(0x0f);
	PCMPESTRI_CASE(0x10); PCMPESTRI_CASE(0x11); PCMPESTRI_CASE(0x12); PCMPESTRI_CASE(0x13);
	PCMPESTRI_CASE(0x14); PCMPESTRI_CASE(0x15); PCMPESTRI_CASE(0x16); PCMPESTRI_CASE(0x17);
	PCMPESTRI_CASE(0x18); PCMPESTRI_CASE(0x19); PCMPESTRI_CASE(0x1a); PCMPESTRI_CASE(0x1b);
	PCMPESTRI_CASE(0x1c); PCMPESTRI_CASE(0x1d); PCMPESTRI_CASE(0x1e); PCMPESTRI_CASE(0x1f);
	PCMPESTRI_CASE(0x20); PCMPESTRI_CASE(0x21); PCMPESTRI_CASE(0x22); PCMPESTRI_CASE(0x23);
	PCMPESTRI_CASE(0x24); PCMPESTRI_CASE(0x25); PCMPESTRI_CASE(0x26); PCMPESTRI_CASE(0x27);
	PCMPESTRI_CASE(0x28); PCMPESTRI_CASE(0x29); PCMPESTRI_CASE(0x2a); PCMPESTRI_CASE(0x2b);
	PCMPESTRI_CASE(0x2c); PCMPESTRI_CASE(0x2d); PCMPESTRI_CASE(0x2e); PCMPESTRI_CASE(0x2f);
	PCMPESTRI_CASE(0x30); PCMPESTRI_CASE(0x31); PCMPESTRI_CASE(0x32); PCMPESTRI_CASE(0x33);
	PCMPESTRI_CASE(0x34); PCMPESTRI_CASE(0x35); PCMPESTRI_CASE(0x36); PCMPESTRI_CASE(0x37);
	PCMPESTRI_CASE(0x38); PCMPESTRI_CASE(0x39); PCMPESTRI_CASE(0x3a); PCMPESTRI_CASE(0x3b);
	PCMPESTRI_CASE(0x3c); PCMPESTRI_CASE(0x3d); PCMPESTRI_CASE(0x3e); PCMPESTRI_CASE(0x3f);
	PCMPESTRI_CASE(0x40); PCMPESTRI_CASE(0x41); PCMPESTRI_CASE(0x42); PCMPESTRI_CASE(0x43);
	PCMPESTRI_CASE(0x44); PCMPESTRI_CASE(0x45); PCMPESTRI_CASE(0x46); PCMPESTRI_CASE(0x47);
	PCMPESTRI_CASE(0x48); PCMPESTRI_CASE(0x49); PCMPESTRI_CASE(0x4a); PCMPESTRI_CASE(0x4b);
	PCMPESTRI_CASE(0x4c); PCMPESTRI_CASE(0x4d); PCMPESTRI_CASE(0x4e); PCMPESTRI_CASE(0x4f);
	default:
		_kvm_write_sse_reg(0, &saved_xmm0);
		_kvm_write_sse_reg(1, &saved_xmm1);
		kvm_fpu_put();
		return X86EMUL_UNHANDLEABLE;
	}
#undef PCMPESTRI_CASE

	_kvm_write_sse_reg(0, &saved_xmm0);
	_kvm_write_sse_reg(1, &saved_xmm1);
	kvm_fpu_put();

	/* PCMPESTRI writes result to ECX */
	*reg_write(ctxt, VCPU_REGS_RCX) = ecx_result;

	/* Update flags */
	ctxt->eflags = (ctxt->eflags & ~(X86_EFLAGS_CF | X86_EFLAGS_ZF |
			X86_EFLAGS_SF | X86_EFLAGS_OF | X86_EFLAGS_AF |
			X86_EFLAGS_PF)) |
		       (flags & (X86_EFLAGS_CF | X86_EFLAGS_ZF |
				 X86_EFLAGS_SF | X86_EFLAGS_OF));

	ctxt->dst.type = OP_NONE;
	return X86EMUL_CONTINUE;
}

/*
 * PCMPISTRM (66 0F 3A 62): Implicit-length string compare, mask output.
 * Very complex - delegate to host CPU.
 */
static int em_pcmpistrm(struct x86_emulate_ctxt *ctxt)
{
	u8 *dst = (u8 *)ctxt->dst.valptr;
	u8 *src = (u8 *)ctxt->src.valptr;
	sse128_t saved_xmm0, saved_xmm1;
	unsigned long flags;
	u8 imm;
	int rc;

	rc = do_insn_fetch_bytes(ctxt, 1);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	imm = *ctxt->fetch.ptr++;

	kvm_fpu_get();
	_kvm_read_sse_reg(0, &saved_xmm0);
	_kvm_read_sse_reg(1, &saved_xmm1);

	asm volatile("movdqu %0, %%xmm0" : : "m"(*(sse128_t *)dst));
	asm volatile("movdqu %0, %%xmm1" : : "m"(*(sse128_t *)src));

#define PCMPISTRM_CASE(n)						\
	case n:								\
		asm volatile("pcmpistrm $" #n ", %%xmm1, %%xmm0\n\t"	\
			     "pushf\n\t"				\
			     "pop %[flags]"				\
			     : [flags] "=r" (flags)			\
			     : : "cc");					\
		break
	switch (imm) {
	PCMPISTRM_CASE(0x00); PCMPISTRM_CASE(0x01); PCMPISTRM_CASE(0x02); PCMPISTRM_CASE(0x03);
	PCMPISTRM_CASE(0x04); PCMPISTRM_CASE(0x05); PCMPISTRM_CASE(0x06); PCMPISTRM_CASE(0x07);
	PCMPISTRM_CASE(0x08); PCMPISTRM_CASE(0x09); PCMPISTRM_CASE(0x0a); PCMPISTRM_CASE(0x0b);
	PCMPISTRM_CASE(0x0c); PCMPISTRM_CASE(0x0d); PCMPISTRM_CASE(0x0e); PCMPISTRM_CASE(0x0f);
	PCMPISTRM_CASE(0x10); PCMPISTRM_CASE(0x11); PCMPISTRM_CASE(0x12); PCMPISTRM_CASE(0x13);
	PCMPISTRM_CASE(0x14); PCMPISTRM_CASE(0x15); PCMPISTRM_CASE(0x16); PCMPISTRM_CASE(0x17);
	PCMPISTRM_CASE(0x18); PCMPISTRM_CASE(0x19); PCMPISTRM_CASE(0x1a); PCMPISTRM_CASE(0x1b);
	PCMPISTRM_CASE(0x1c); PCMPISTRM_CASE(0x1d); PCMPISTRM_CASE(0x1e); PCMPISTRM_CASE(0x1f);
	PCMPISTRM_CASE(0x20); PCMPISTRM_CASE(0x21); PCMPISTRM_CASE(0x22); PCMPISTRM_CASE(0x23);
	PCMPISTRM_CASE(0x24); PCMPISTRM_CASE(0x25); PCMPISTRM_CASE(0x26); PCMPISTRM_CASE(0x27);
	PCMPISTRM_CASE(0x28); PCMPISTRM_CASE(0x29); PCMPISTRM_CASE(0x2a); PCMPISTRM_CASE(0x2b);
	PCMPISTRM_CASE(0x2c); PCMPISTRM_CASE(0x2d); PCMPISTRM_CASE(0x2e); PCMPISTRM_CASE(0x2f);
	PCMPISTRM_CASE(0x30); PCMPISTRM_CASE(0x31); PCMPISTRM_CASE(0x32); PCMPISTRM_CASE(0x33);
	PCMPISTRM_CASE(0x34); PCMPISTRM_CASE(0x35); PCMPISTRM_CASE(0x36); PCMPISTRM_CASE(0x37);
	PCMPISTRM_CASE(0x38); PCMPISTRM_CASE(0x39); PCMPISTRM_CASE(0x3a); PCMPISTRM_CASE(0x3b);
	PCMPISTRM_CASE(0x3c); PCMPISTRM_CASE(0x3d); PCMPISTRM_CASE(0x3e); PCMPISTRM_CASE(0x3f);
	PCMPISTRM_CASE(0x40); PCMPISTRM_CASE(0x41); PCMPISTRM_CASE(0x42); PCMPISTRM_CASE(0x43);
	PCMPISTRM_CASE(0x44); PCMPISTRM_CASE(0x45); PCMPISTRM_CASE(0x46); PCMPISTRM_CASE(0x47);
	PCMPISTRM_CASE(0x48); PCMPISTRM_CASE(0x49); PCMPISTRM_CASE(0x4a); PCMPISTRM_CASE(0x4b);
	PCMPISTRM_CASE(0x4c); PCMPISTRM_CASE(0x4d); PCMPISTRM_CASE(0x4e); PCMPISTRM_CASE(0x4f);
	default:
		_kvm_write_sse_reg(0, &saved_xmm0);
		_kvm_write_sse_reg(1, &saved_xmm1);
		kvm_fpu_put();
		return X86EMUL_UNHANDLEABLE;
	}
#undef PCMPISTRM_CASE

	/* PCMPISTRM writes result mask to XMM0 - read it into dst */
	{
		sse128_t result;
		_kvm_read_sse_reg(0, &result);
		memcpy(dst, &result, 16);
	}

	_kvm_write_sse_reg(0, &saved_xmm0);
	_kvm_write_sse_reg(1, &saved_xmm1);
	kvm_fpu_put();

	/* Update flags */
	ctxt->eflags = (ctxt->eflags & ~(X86_EFLAGS_CF | X86_EFLAGS_ZF |
			X86_EFLAGS_SF | X86_EFLAGS_OF | X86_EFLAGS_AF |
			X86_EFLAGS_PF)) |
		       (flags & (X86_EFLAGS_CF | X86_EFLAGS_ZF |
				 X86_EFLAGS_SF | X86_EFLAGS_OF));

	return X86EMUL_CONTINUE;
}

/*
 * PHMINPOSUW (66 0F 38 41): Horizontal minimum of unsigned words.
 * Use host FPU.
 */
static int em_phminposuw(struct x86_emulate_ctxt *ctxt)
{
	u8 *dst = (u8 *)ctxt->dst.valptr;
	u8 *src = (u8 *)ctxt->src.valptr;
	sse128_t saved_xmm0, saved_xmm1;
	u8 tmp_dst[16] __aligned(16);

	kvm_fpu_get();
	_kvm_read_sse_reg(0, &saved_xmm0);
	_kvm_read_sse_reg(1, &saved_xmm1);
	asm volatile("movdqu %0, %%xmm1" : : "m"(*(sse128_t *)src));
	asm volatile("phminposuw %%xmm1, %%xmm0" :::);
	asm volatile("movdqu %%xmm0, %0" : "=m"(*(sse128_t *)tmp_dst));
	_kvm_write_sse_reg(0, &saved_xmm0);
	_kvm_write_sse_reg(1, &saved_xmm1);
	kvm_fpu_put();
	memcpy(dst, tmp_dst, 16);
	return X86EMUL_CONTINUE;
}

static int em_movbe(struct x86_emulate_ctxt *ctxt)
{
	u16 tmp;

	if (!ctxt->ops->guest_has_movbe(ctxt))
		return emulate_ud(ctxt);

	switch (ctxt->op_bytes) {
	case 2:
		/*
		 * From MOVBE definition: "...When the operand size is 16 bits,
		 * the upper word of the destination register remains unchanged
		 * ..."
		 *
		 * Both casting ->valptr and ->val to u16 breaks strict aliasing
		 * rules so we have to do the operation almost per hand.
		 */
		tmp = (u16)ctxt->src.val;
		ctxt->dst.val &= ~0xffffUL;
		ctxt->dst.val |= (unsigned long)swab16(tmp);
		break;
	case 4:
		ctxt->dst.val = swab32((u32)ctxt->src.val);
		break;
	case 8:
		ctxt->dst.val = swab64(ctxt->src.val);
		break;
	default:
		BUG();
	}
	return X86EMUL_CONTINUE;
}

static int em_cr_write(struct x86_emulate_ctxt *ctxt)
{
	int cr_num = ctxt->modrm_reg;
	int r;

	if (ctxt->ops->set_cr(ctxt, cr_num, ctxt->src.val))
		return emulate_gp(ctxt, 0);

	/* Disable writeback. */
	ctxt->dst.type = OP_NONE;

	if (cr_num == 0) {
		/*
		 * CR0 write might have updated CR0.PE and/or CR0.PG
		 * which can affect the cpu's execution mode.
		 */
		r = emulator_recalc_and_set_mode(ctxt);
		if (r != X86EMUL_CONTINUE)
			return r;
	}

	return X86EMUL_CONTINUE;
}

static int em_dr_write(struct x86_emulate_ctxt *ctxt)
{
	unsigned long val;

	if (ctxt->mode == X86EMUL_MODE_PROT64)
		val = ctxt->src.val & ~0ULL;
	else
		val = ctxt->src.val & ~0U;

	/* #UD condition is already handled. */
	if (ctxt->ops->set_dr(ctxt, ctxt->modrm_reg, val) < 0)
		return emulate_gp(ctxt, 0);

	/* Disable writeback. */
	ctxt->dst.type = OP_NONE;
	return X86EMUL_CONTINUE;
}

static int em_wrmsr(struct x86_emulate_ctxt *ctxt)
{
	u64 msr_index = reg_read(ctxt, VCPU_REGS_RCX);
	u64 msr_data;
	int r;

	msr_data = (u32)reg_read(ctxt, VCPU_REGS_RAX)
		| ((u64)reg_read(ctxt, VCPU_REGS_RDX) << 32);
	r = ctxt->ops->set_msr_with_filter(ctxt, msr_index, msr_data);

	if (r == X86EMUL_PROPAGATE_FAULT)
		return emulate_gp(ctxt, 0);

	return r;
}

static int em_rdmsr(struct x86_emulate_ctxt *ctxt)
{
	u64 msr_index = reg_read(ctxt, VCPU_REGS_RCX);
	u64 msr_data;
	int r;

	r = ctxt->ops->get_msr_with_filter(ctxt, msr_index, &msr_data);

	if (r == X86EMUL_PROPAGATE_FAULT)
		return emulate_gp(ctxt, 0);

	if (r == X86EMUL_CONTINUE) {
		*reg_write(ctxt, VCPU_REGS_RAX) = (u32)msr_data;
		*reg_write(ctxt, VCPU_REGS_RDX) = msr_data >> 32;
	}
	return r;
}

static int em_store_sreg(struct x86_emulate_ctxt *ctxt, int segment)
{
	if (segment > VCPU_SREG_GS &&
	    (ctxt->ops->get_cr(ctxt, 4) & X86_CR4_UMIP) &&
	    ctxt->ops->cpl(ctxt) > 0)
		return emulate_gp(ctxt, 0);

	ctxt->dst.val = get_segment_selector(ctxt, segment);
	if (ctxt->dst.bytes == 4 && ctxt->dst.type == OP_MEM)
		ctxt->dst.bytes = 2;
	return X86EMUL_CONTINUE;
}

static int em_mov_rm_sreg(struct x86_emulate_ctxt *ctxt)
{
	if (ctxt->modrm_reg > VCPU_SREG_GS)
		return emulate_ud(ctxt);

	return em_store_sreg(ctxt, ctxt->modrm_reg);
}

static int em_mov_sreg_rm(struct x86_emulate_ctxt *ctxt)
{
	u16 sel = ctxt->src.val;

	if (ctxt->modrm_reg == VCPU_SREG_CS || ctxt->modrm_reg > VCPU_SREG_GS)
		return emulate_ud(ctxt);

	if (ctxt->modrm_reg == VCPU_SREG_SS)
		ctxt->interruptibility = KVM_X86_SHADOW_INT_MOV_SS;

	/* Disable writeback. */
	ctxt->dst.type = OP_NONE;
	return load_segment_descriptor(ctxt, sel, ctxt->modrm_reg);
}

static int em_sldt(struct x86_emulate_ctxt *ctxt)
{
	return em_store_sreg(ctxt, VCPU_SREG_LDTR);
}

static int em_lldt(struct x86_emulate_ctxt *ctxt)
{
	u16 sel = ctxt->src.val;

	/* Disable writeback. */
	ctxt->dst.type = OP_NONE;
	return load_segment_descriptor(ctxt, sel, VCPU_SREG_LDTR);
}

static int em_str(struct x86_emulate_ctxt *ctxt)
{
	return em_store_sreg(ctxt, VCPU_SREG_TR);
}

static int em_ltr(struct x86_emulate_ctxt *ctxt)
{
	u16 sel = ctxt->src.val;

	/* Disable writeback. */
	ctxt->dst.type = OP_NONE;
	return load_segment_descriptor(ctxt, sel, VCPU_SREG_TR);
}

static int em_invlpg(struct x86_emulate_ctxt *ctxt)
{
	int rc;
	ulong linear;
	unsigned int max_size;

	rc = __linearize(ctxt, ctxt->src.addr.mem, &max_size, 1, ctxt->mode,
			 &linear, X86EMUL_F_INVLPG);
	if (rc == X86EMUL_CONTINUE)
		ctxt->ops->invlpg(ctxt, linear);
	/* Disable writeback. */
	ctxt->dst.type = OP_NONE;
	return X86EMUL_CONTINUE;
}

static int em_clts(struct x86_emulate_ctxt *ctxt)
{
	ulong cr0;

	cr0 = ctxt->ops->get_cr(ctxt, 0);
	cr0 &= ~X86_CR0_TS;
	ctxt->ops->set_cr(ctxt, 0, cr0);
	return X86EMUL_CONTINUE;
}

static int em_hypercall(struct x86_emulate_ctxt *ctxt)
{
	int rc = ctxt->ops->fix_hypercall(ctxt);

	if (rc != X86EMUL_CONTINUE)
		return rc;

	/* Let the processor re-execute the fixed hypercall */
	ctxt->_eip = ctxt->eip;
	/* Disable writeback. */
	ctxt->dst.type = OP_NONE;
	return X86EMUL_CONTINUE;
}

static int emulate_store_desc_ptr(struct x86_emulate_ctxt *ctxt,
				  void (*get)(struct x86_emulate_ctxt *ctxt,
					      struct desc_ptr *ptr))
{
	struct desc_ptr desc_ptr;

	if ((ctxt->ops->get_cr(ctxt, 4) & X86_CR4_UMIP) &&
	    ctxt->ops->cpl(ctxt) > 0)
		return emulate_gp(ctxt, 0);

	if (ctxt->mode == X86EMUL_MODE_PROT64)
		ctxt->op_bytes = 8;
	get(ctxt, &desc_ptr);
	if (ctxt->op_bytes == 2) {
		ctxt->op_bytes = 4;
		desc_ptr.address &= 0x00ffffff;
	}
	/* Disable writeback. */
	ctxt->dst.type = OP_NONE;
	return segmented_write_std(ctxt, ctxt->dst.addr.mem,
				   &desc_ptr, 2 + ctxt->op_bytes);
}

static int em_sgdt(struct x86_emulate_ctxt *ctxt)
{
	return emulate_store_desc_ptr(ctxt, ctxt->ops->get_gdt);
}

static int em_sidt(struct x86_emulate_ctxt *ctxt)
{
	return emulate_store_desc_ptr(ctxt, ctxt->ops->get_idt);
}

static int em_lgdt_lidt(struct x86_emulate_ctxt *ctxt, bool lgdt)
{
	struct desc_ptr desc_ptr;
	int rc;

	if (ctxt->mode == X86EMUL_MODE_PROT64)
		ctxt->op_bytes = 8;
	rc = read_descriptor(ctxt, ctxt->src.addr.mem,
			     &desc_ptr.size, &desc_ptr.address,
			     ctxt->op_bytes);
	if (rc != X86EMUL_CONTINUE)
		return rc;
	if (ctxt->mode == X86EMUL_MODE_PROT64 &&
	    emul_is_noncanonical_address(desc_ptr.address, ctxt,
					 X86EMUL_F_DT_LOAD))
		return emulate_gp(ctxt, 0);
	if (lgdt)
		ctxt->ops->set_gdt(ctxt, &desc_ptr);
	else
		ctxt->ops->set_idt(ctxt, &desc_ptr);
	/* Disable writeback. */
	ctxt->dst.type = OP_NONE;
	return X86EMUL_CONTINUE;
}

static int em_lgdt(struct x86_emulate_ctxt *ctxt)
{
	return em_lgdt_lidt(ctxt, true);
}

static int em_lidt(struct x86_emulate_ctxt *ctxt)
{
	return em_lgdt_lidt(ctxt, false);
}

static int em_smsw(struct x86_emulate_ctxt *ctxt)
{
	if ((ctxt->ops->get_cr(ctxt, 4) & X86_CR4_UMIP) &&
	    ctxt->ops->cpl(ctxt) > 0)
		return emulate_gp(ctxt, 0);

	if (ctxt->dst.type == OP_MEM)
		ctxt->dst.bytes = 2;
	ctxt->dst.val = ctxt->ops->get_cr(ctxt, 0);
	return X86EMUL_CONTINUE;
}

static int em_lmsw(struct x86_emulate_ctxt *ctxt)
{
	ctxt->ops->set_cr(ctxt, 0, (ctxt->ops->get_cr(ctxt, 0) & ~0x0eul)
			  | (ctxt->src.val & 0x0f));
	ctxt->dst.type = OP_NONE;
	return X86EMUL_CONTINUE;
}

static int em_loop(struct x86_emulate_ctxt *ctxt)
{
	int rc = X86EMUL_CONTINUE;

	register_address_increment(ctxt, VCPU_REGS_RCX, -1);
	if ((address_mask(ctxt, reg_read(ctxt, VCPU_REGS_RCX)) != 0) &&
	    (ctxt->b == 0xe2 || test_cc(ctxt->b ^ 0x5, ctxt->eflags)))
		rc = jmp_rel(ctxt, ctxt->src.val);

	return rc;
}

static int em_jcxz(struct x86_emulate_ctxt *ctxt)
{
	int rc = X86EMUL_CONTINUE;

	if (address_mask(ctxt, reg_read(ctxt, VCPU_REGS_RCX)) == 0)
		rc = jmp_rel(ctxt, ctxt->src.val);

	return rc;
}

static int em_in(struct x86_emulate_ctxt *ctxt)
{
	if (!pio_in_emulated(ctxt, ctxt->dst.bytes, ctxt->src.val,
			     &ctxt->dst.val))
		return X86EMUL_IO_NEEDED;

	return X86EMUL_CONTINUE;
}

static int em_out(struct x86_emulate_ctxt *ctxt)
{
	ctxt->ops->pio_out_emulated(ctxt, ctxt->src.bytes, ctxt->dst.val,
				    &ctxt->src.val, 1);
	/* Disable writeback. */
	ctxt->dst.type = OP_NONE;
	return X86EMUL_CONTINUE;
}

static int em_cli(struct x86_emulate_ctxt *ctxt)
{
	if (emulator_bad_iopl(ctxt))
		return emulate_gp(ctxt, 0);

	ctxt->eflags &= ~X86_EFLAGS_IF;
	return X86EMUL_CONTINUE;
}

static int em_sti(struct x86_emulate_ctxt *ctxt)
{
	if (emulator_bad_iopl(ctxt))
		return emulate_gp(ctxt, 0);

	ctxt->interruptibility = KVM_X86_SHADOW_INT_STI;
	ctxt->eflags |= X86_EFLAGS_IF;
	return X86EMUL_CONTINUE;
}

static int em_cpuid(struct x86_emulate_ctxt *ctxt)
{
	u32 eax, ebx, ecx, edx;
	u64 msr = 0;

	ctxt->ops->get_msr(ctxt, MSR_MISC_FEATURES_ENABLES, &msr);
	if (msr & MSR_MISC_FEATURES_ENABLES_CPUID_FAULT &&
	    ctxt->ops->cpl(ctxt)) {
		return emulate_gp(ctxt, 0);
	}

	eax = reg_read(ctxt, VCPU_REGS_RAX);
	ecx = reg_read(ctxt, VCPU_REGS_RCX);
	ctxt->ops->get_cpuid(ctxt, &eax, &ebx, &ecx, &edx, false);
	*reg_write(ctxt, VCPU_REGS_RAX) = eax;
	*reg_write(ctxt, VCPU_REGS_RBX) = ebx;
	*reg_write(ctxt, VCPU_REGS_RCX) = ecx;
	*reg_write(ctxt, VCPU_REGS_RDX) = edx;
	return X86EMUL_CONTINUE;
}

static int em_sahf(struct x86_emulate_ctxt *ctxt)
{
	u32 flags;

	flags = X86_EFLAGS_CF | X86_EFLAGS_PF | X86_EFLAGS_AF | X86_EFLAGS_ZF |
		X86_EFLAGS_SF;
	flags &= *reg_rmw(ctxt, VCPU_REGS_RAX) >> 8;

	ctxt->eflags &= ~0xffUL;
	ctxt->eflags |= flags | X86_EFLAGS_FIXED;
	return X86EMUL_CONTINUE;
}

static int em_lahf(struct x86_emulate_ctxt *ctxt)
{
	*reg_rmw(ctxt, VCPU_REGS_RAX) &= ~0xff00UL;
	*reg_rmw(ctxt, VCPU_REGS_RAX) |= (ctxt->eflags & 0xff) << 8;
	return X86EMUL_CONTINUE;
}

static int em_bswap(struct x86_emulate_ctxt *ctxt)
{
	switch (ctxt->op_bytes) {
#ifdef CONFIG_X86_64
	case 8:
		asm("bswap %0" : "+r"(ctxt->dst.val));
		break;
#endif
	default:
		asm("bswap %0" : "+r"(*(u32 *)&ctxt->dst.val));
		break;
	}
	return X86EMUL_CONTINUE;
}

static int em_clflush(struct x86_emulate_ctxt *ctxt)
{
	/* emulating clflush regardless of cpuid */
	return X86EMUL_CONTINUE;
}

static int em_clflushopt(struct x86_emulate_ctxt *ctxt)
{
	/* emulating clflushopt regardless of cpuid */
	return X86EMUL_CONTINUE;
}

static int em_movsxd(struct x86_emulate_ctxt *ctxt)
{
	ctxt->dst.val = (s32) ctxt->src.val;
	return X86EMUL_CONTINUE;
}

static int check_fxsr(struct x86_emulate_ctxt *ctxt)
{
	if (!ctxt->ops->guest_has_fxsr(ctxt))
		return emulate_ud(ctxt);

	if (ctxt->ops->get_cr(ctxt, 0) & (X86_CR0_TS | X86_CR0_EM))
		return emulate_nm(ctxt);

	return X86EMUL_CONTINUE;
}

/*
 * Hardware doesn't save and restore XMM 0-7 without CR4.OSFXSR, but does save
 * and restore MXCSR.
 */
static size_t __fxstate_size(int nregs)
{
	return offsetof(struct fxregs_state, xmm_space[0]) + nregs * 16;
}

static inline size_t fxstate_size(struct x86_emulate_ctxt *ctxt)
{
	bool cr4_osfxsr;
	if (ctxt->mode == X86EMUL_MODE_PROT64)
		return __fxstate_size(16);

	cr4_osfxsr = ctxt->ops->get_cr(ctxt, 4) & X86_CR4_OSFXSR;
	return __fxstate_size(cr4_osfxsr ? 8 : 0);
}

/*
 * FXSAVE and FXRSTOR have 4 different formats depending on execution mode,
 *  1) 16 bit mode
 *  2) 32 bit mode
 *     - like (1), but FIP and FDP (foo) are only 16 bit.  At least Intel CPUs
 *       preserve whole 32 bit values, though, so (1) and (2) are the same wrt.
 *       save and restore
 *  3) 64-bit mode without REX.W prefix
 *     - like (2), but XMM 8-15 are being saved and restored
 *  4) 64-bit mode with REX.W prefix (FXSAVE64 / FXRSTOR64)
 *     - like (3), but FIP and FDP are 64 bit
 *
 * The CPU on the host produces the right on-disk layout for us as long as we
 * use the right mnemonic: `fxsave` (no REX.W) for cases (1)-(3) and `fxsaveq`
 * (REX.W=1) for case (4).
 *
 * Note: Guest and host CPUID.(EAX=07H,ECX=0H):EBX[bit 13] (deprecate FPU CS
 * and FPU DS) should match.
 */
static int em_fxsave(struct x86_emulate_ctxt *ctxt)
{
	struct fxregs_state fx_state;
	int rc;

	rc = check_fxsr(ctxt);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	kvm_fpu_get();

	if (ctxt->mode == X86EMUL_MODE_PROT64 && (ctxt->rex_bits & REX_W))
		rc = asm_safe("fxsaveq %[fx]", , [fx] "+m"(fx_state));
	else
		rc = asm_safe("fxsave %[fx]", , [fx] "+m"(fx_state));

	kvm_fpu_put();

	if (rc != X86EMUL_CONTINUE)
		return rc;

	/*
	 * Use segmented_write (not segmented_write_std) so MMIO destinations
	 * are routed through the emulator's MMIO fragment path.  The std
	 * variant calls kvm_vcpu_write_guest, which fails on MMIO and would
	 * silently drop the FXSAVE bytes.
	 *
	 * The MMIO fragment captures *frag->data = val*, then complete_emulated_mmio
	 * walks the buffer 8 bytes at a time across many vmexits.  The source
	 * buffer therefore must outlive this function -- a kernel-stack local
	 * does NOT, since the emulator returns to userspace between chunks.
	 * Stash the saved state in ctxt->mem_read.data, which is part of the
	 * persistent vcpu emulate_ctxt and is large enough (1024 > 416 bytes).
	 */
	BUILD_BUG_ON(sizeof(ctxt->mem_read.data) <
		     offsetof(struct fxregs_state, xmm_space[0]) + 16 * 16);
	memcpy(ctxt->mem_read.data, &fx_state, fxstate_size(ctxt));
	return segmented_write(ctxt, ctxt->memop.addr.mem,
			       ctxt->mem_read.data, fxstate_size(ctxt));
}

/*
 * FXRSTOR might restore XMM registers not provided by the guest. Fill
 * in the host registers (via FXSAVE) instead, so they won't be modified.
 * (preemption has to stay disabled until FXRSTOR).
 *
 * Use noinline to keep the stack for other functions called by callers small.
 */
static noinline int fxregs_fixup(struct fxregs_state *fx_state,
				 const size_t used_size)
{
	struct fxregs_state fx_tmp;
	int rc;

	rc = asm_safe("fxsave %[fx]", , [fx] "+m"(fx_tmp));
	memcpy((void *)fx_state + used_size, (void *)&fx_tmp + used_size,
	       __fxstate_size(16) - used_size);

	return rc;
}

static int em_fxrstor(struct x86_emulate_ctxt *ctxt)
{
	struct fxregs_state fx_state;
	int rc;
	size_t size;

	rc = check_fxsr(ctxt);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	size = fxstate_size(ctxt);
	/* Use segmented_read so MMIO sources go through the emulator's
	 * MMIO fragment path, not kvm_vcpu_read_guest. */
	rc = segmented_read(ctxt, ctxt->memop.addr.mem, &fx_state, size);
	if (rc != X86EMUL_CONTINUE)
		return rc;

	kvm_fpu_get();

	if (size < __fxstate_size(16)) {
		rc = fxregs_fixup(&fx_state, size);
		if (rc != X86EMUL_CONTINUE)
			goto out;
	}

	if (fx_state.mxcsr >> 16) {
		rc = emulate_gp(ctxt, 0);
		goto out;
	}

	if (rc == X86EMUL_CONTINUE) {
		if (ctxt->mode == X86EMUL_MODE_PROT64 &&
		    (ctxt->rex_bits & REX_W))
			rc = asm_safe("fxrstorq %[fx]", : [fx] "m"(fx_state));
		else
			rc = asm_safe("fxrstor %[fx]", : [fx] "m"(fx_state));
	}

out:
	kvm_fpu_put();

	return rc;
}

static int em_xsetbv(struct x86_emulate_ctxt *ctxt)
{
	u32 eax, ecx, edx;

	if (!(ctxt->ops->get_cr(ctxt, 4) & X86_CR4_OSXSAVE))
		return emulate_ud(ctxt);

	eax = reg_read(ctxt, VCPU_REGS_RAX);
	edx = reg_read(ctxt, VCPU_REGS_RDX);
	ecx = reg_read(ctxt, VCPU_REGS_RCX);

	if (ctxt->ops->set_xcr(ctxt, ecx, ((u64)edx << 32) | eax))
		return emulate_gp(ctxt, 0);

	return X86EMUL_CONTINUE;
}

static bool valid_cr(int nr)
{
	switch (nr) {
	case 0:
	case 2 ... 4:
	case 8:
		return true;
	default:
		return false;
	}
}

static int check_cr_access(struct x86_emulate_ctxt *ctxt)
{
	if (!valid_cr(ctxt->modrm_reg))
		return emulate_ud(ctxt);

	return X86EMUL_CONTINUE;
}

static int check_dr_read(struct x86_emulate_ctxt *ctxt)
{
	int dr = ctxt->modrm_reg;
	u64 cr4;

	if (dr > 7)
		return emulate_ud(ctxt);

	cr4 = ctxt->ops->get_cr(ctxt, 4);
	if ((cr4 & X86_CR4_DE) && (dr == 4 || dr == 5))
		return emulate_ud(ctxt);

	if (ctxt->ops->get_dr(ctxt, 7) & DR7_GD) {
		ulong dr6;

		dr6 = ctxt->ops->get_dr(ctxt, 6);
		dr6 &= ~DR_TRAP_BITS;
		dr6 |= DR6_BD | DR6_ACTIVE_LOW;
		ctxt->ops->set_dr(ctxt, 6, dr6);
		return emulate_db(ctxt);
	}

	return X86EMUL_CONTINUE;
}

static int check_dr_write(struct x86_emulate_ctxt *ctxt)
{
	u64 new_val = ctxt->src.val64;
	int dr = ctxt->modrm_reg;

	if ((dr == 6 || dr == 7) && (new_val & 0xffffffff00000000ULL))
		return emulate_gp(ctxt, 0);

	return check_dr_read(ctxt);
}

static int check_svme(struct x86_emulate_ctxt *ctxt)
{
	u64 efer = 0;

	ctxt->ops->get_msr(ctxt, MSR_EFER, &efer);

	if (!(efer & EFER_SVME))
		return emulate_ud(ctxt);

	return X86EMUL_CONTINUE;
}

static int check_svme_pa(struct x86_emulate_ctxt *ctxt)
{
	u64 rax = reg_read(ctxt, VCPU_REGS_RAX);

	/* Valid physical address? */
	if (rax & 0xffff000000000000ULL)
		return emulate_gp(ctxt, 0);

	return check_svme(ctxt);
}

static int check_rdtsc(struct x86_emulate_ctxt *ctxt)
{
	u64 cr4 = ctxt->ops->get_cr(ctxt, 4);

	if (cr4 & X86_CR4_TSD && ctxt->ops->cpl(ctxt))
		return emulate_gp(ctxt, 0);

	return X86EMUL_CONTINUE;
}

static int check_rdpmc(struct x86_emulate_ctxt *ctxt)
{
	u64 cr4 = ctxt->ops->get_cr(ctxt, 4);
	u64 rcx = reg_read(ctxt, VCPU_REGS_RCX);

	/*
	 * VMware allows access to these Pseduo-PMCs even when read via RDPMC
	 * in Ring3 when CR4.PCE=0.
	 */
	if (enable_vmware_backdoor && is_vmware_backdoor_pmc(rcx))
		return X86EMUL_CONTINUE;

	/*
	 * If CR4.PCE is set, the SDM requires CPL=0 or CR0.PE=0.  The CR0.PE
	 * check however is unnecessary because CPL is always 0 outside
	 * protected mode.
	 */
	if ((!(cr4 & X86_CR4_PCE) && ctxt->ops->cpl(ctxt)) ||
	    ctxt->ops->check_rdpmc_early(ctxt, rcx))
		return emulate_gp(ctxt, 0);

	return X86EMUL_CONTINUE;
}

static int check_perm_in(struct x86_emulate_ctxt *ctxt)
{
	ctxt->dst.bytes = min(ctxt->dst.bytes, 4u);
	if (!emulator_io_permitted(ctxt, ctxt->src.val, ctxt->dst.bytes))
		return emulate_gp(ctxt, 0);

	return X86EMUL_CONTINUE;
}

static int check_perm_out(struct x86_emulate_ctxt *ctxt)
{
	ctxt->src.bytes = min(ctxt->src.bytes, 4u);
	if (!emulator_io_permitted(ctxt, ctxt->dst.val, ctxt->src.bytes))
		return emulate_gp(ctxt, 0);

	return X86EMUL_CONTINUE;
}

#define D(_y) { .flags = (_y) }
#define DI(_y, _i) { .flags = (_y)|Intercept, .intercept = x86_intercept_##_i }
#define DIP(_y, _i, _p) { .flags = (_y)|Intercept|CheckPerm, \
		      .intercept = x86_intercept_##_i, .check_perm = (_p) }
#define N    D(NotImpl)
#define EXT(_f, _e) { .flags = ((_f) | RMExt), .u.group = (_e) }
#define G(_f, _g) { .flags = ((_f) | Group | ModRM), .u.group = (_g) }
#define GD(_f, _g) { .flags = ((_f) | GroupDual | ModRM), .u.gdual = (_g) }
#define ID(_f, _i) { .flags = ((_f) | InstrDual | ModRM), .u.idual = (_i) }
#define MD(_f, _m) { .flags = ((_f) | ModeDual), .u.mdual = (_m) }
#define E(_f, _e) { .flags = ((_f) | Escape | ModRM), .u.esc = (_e) }
#define I(_f, _e) { .flags = (_f), .u.execute = (_e) }
#define II(_f, _e, _i) \
	{ .flags = (_f)|Intercept, .u.execute = (_e), .intercept = x86_intercept_##_i }
#define IIP(_f, _e, _i, _p) \
	{ .flags = (_f)|Intercept|CheckPerm, .u.execute = (_e), \
	  .intercept = x86_intercept_##_i, .check_perm = (_p) }
#define GP(_f, _g) { .flags = ((_f) | Prefix), .u.gprefix = (_g) }

#define D2bv(_f)      D((_f) | ByteOp), D(_f)
#define D2bvIP(_f, _i, _p) DIP((_f) | ByteOp, _i, _p), DIP(_f, _i, _p)
#define I2bv(_f, _e)  I((_f) | ByteOp, _e), I(_f, _e)
#define F2bv(_f, _e)  F((_f) | ByteOp, _e), F(_f, _e)
#define I2bvIP(_f, _e, _i, _p) \
	IIP((_f) | ByteOp, _e, _i, _p), IIP(_f, _e, _i, _p)

#define I6ALU(_f, _e) I2bv((_f) | DstMem | SrcReg | ModRM, _e),		\
		I2bv(((_f) | DstReg | SrcMem | ModRM) & ~Lock, _e),	\
		I2bv(((_f) & ~Lock) | DstAcc | SrcImm, _e)

static const struct opcode ud = I(SrcNone, emulate_ud);

static const struct opcode group7_rm0[] = {
	N,
	I(SrcNone | Priv | EmulateOnUD,	em_hypercall),
	N, N, N, N, N, N,
};

static const struct opcode group7_rm1[] = {
	DI(SrcNone | Priv, monitor),
	DI(SrcNone | Priv, mwait),
	N, N, N, N, N, N,
};

static const struct opcode group7_rm2[] = {
	N,
	II(ImplicitOps | Priv,			em_xsetbv,	xsetbv),
	N, N, N, N, N, N,
};

static const struct opcode group7_rm3[] = {
	DIP(SrcNone | Prot | Priv,		vmrun,		check_svme_pa),
	II(SrcNone  | Prot | EmulateOnUD,	em_hypercall,	vmmcall),
	DIP(SrcNone | Prot | Priv,		vmload,		check_svme_pa),
	DIP(SrcNone | Prot | Priv,		vmsave,		check_svme_pa),
	DIP(SrcNone | Prot | Priv,		stgi,		check_svme),
	DIP(SrcNone | Prot | Priv,		clgi,		check_svme),
	DIP(SrcNone | Prot | Priv,		skinit,		check_svme),
	DIP(SrcNone | Prot | Priv,		invlpga,	check_svme),
};

static const struct opcode group7_rm7[] = {
	N,
	DIP(SrcNone, rdtscp, check_rdtsc),
	N, N, N, N, N, N,
};

static const struct opcode group1[] = {
	I(Lock, em_add),
	I(Lock | PageTable, em_or),
	I(Lock, em_adc),
	I(Lock, em_sbb),
	I(Lock | PageTable, em_and),
	I(Lock, em_sub),
	I(Lock, em_xor),
	I(NoWrite, em_cmp),
};

static const struct opcode group1A[] = {
	I(DstMem | SrcNone | Mov | Stack | IncSP | TwoMemOp, em_pop), N, N, N, N, N, N, N,
};

static const struct opcode group2[] = {
	I(DstMem | ModRM, em_rol),
	I(DstMem | ModRM, em_ror),
	I(DstMem | ModRM, em_rcl),
	I(DstMem | ModRM, em_rcr),
	I(DstMem | ModRM, em_shl),
	I(DstMem | ModRM, em_shr),
	I(DstMem | ModRM, em_shl),
	I(DstMem | ModRM, em_sar),
};

static const struct opcode group3[] = {
	I(DstMem | SrcImm | NoWrite, em_test),
	I(DstMem | SrcImm | NoWrite, em_test),
	I(DstMem | SrcNone | Lock, em_not),
	I(DstMem | SrcNone | Lock, em_neg),
	I(DstXacc | Src2Mem, em_mul_ex),
	I(DstXacc | Src2Mem, em_imul_ex),
	I(DstXacc | Src2Mem, em_div_ex),
	I(DstXacc | Src2Mem, em_idiv_ex),
};

static const struct opcode group4[] = {
	I(ByteOp | DstMem | SrcNone | Lock, em_inc),
	I(ByteOp | DstMem | SrcNone | Lock, em_dec),
	N, N, N, N, N, N,
};

static const struct opcode group5[] = {
	I(DstMem | SrcNone | Lock,		em_inc),
	I(DstMem | SrcNone | Lock,		em_dec),
	I(SrcMem | NearBranch | IsBranch | ShadowStack | TwoMemOp, em_call_near_abs),
	I(SrcMemFAddr | ImplicitOps | IsBranch | ShadowStack | TwoMemOp, em_call_far),
	I(SrcMem | NearBranch | IsBranch,       em_jmp_abs),
	I(SrcMemFAddr | ImplicitOps | IsBranch, em_jmp_far),
	I(SrcMem | Stack | TwoMemOp,		em_push), D(Undefined),
};

static const struct opcode group6[] = {
	II(Prot | DstMem,	   em_sldt, sldt),
	II(Prot | DstMem,	   em_str, str),
	II(Prot | Priv | SrcMem16, em_lldt, lldt),
	II(Prot | Priv | SrcMem16, em_ltr, ltr),
	N, N, N, N,
};

static const struct group_dual group7 = { {
	II(Mov | DstMem,			em_sgdt, sgdt),
	II(Mov | DstMem,			em_sidt, sidt),
	II(SrcMem | Priv,			em_lgdt, lgdt),
	II(SrcMem | Priv,			em_lidt, lidt),
	II(SrcNone | DstMem | Mov,		em_smsw, smsw), N,
	II(SrcMem16 | Mov | Priv,		em_lmsw, lmsw),
	II(SrcMem | ByteOp | Priv | NoAccess,	em_invlpg, invlpg),
}, {
	EXT(0, group7_rm0),
	EXT(0, group7_rm1),
	EXT(0, group7_rm2),
	EXT(0, group7_rm3),
	II(SrcNone | DstMem | Mov,		em_smsw, smsw), N,
	II(SrcMem16 | Mov | Priv,		em_lmsw, lmsw),
	EXT(0, group7_rm7),
} };

static const struct opcode group8[] = {
	N, N, N, N,
	I(DstMem | SrcImmByte | NoWrite,		em_bt),
	I(DstMem | SrcImmByte | Lock | PageTable,	em_bts),
	I(DstMem | SrcImmByte | Lock,			em_btr),
	I(DstMem | SrcImmByte | Lock | PageTable,	em_btc),
};

/*
 * The "memory" destination is actually always a register, since we come
 * from the register case of group9.
 */
static const struct gprefix pfx_0f_c7_7 = {
	N, N, N, II(DstMem | ModRM | Op3264 | EmulateOnUD, em_rdpid, rdpid),
};


static const struct group_dual group9 = { {
	N, I(DstMem64 | Lock | PageTable, em_cmpxchg8b), N, N, N, N, N, N,
}, {
	N, N, N, N, N, N, N,
	GP(0, &pfx_0f_c7_7),
} };

static const struct opcode group11[] = {
	I(DstMem | SrcImm | Mov | PageTable, em_mov),
	X7(D(Undefined)),
};

static const struct gprefix pfx_0f_ae_7 = {
	I(SrcMem | ByteOp, em_clflush), I(SrcMem | ByteOp, em_clflushopt), N, N,
};

static const struct group_dual group15 = { {
	I(ModRM | Aligned16, em_fxsave),
	I(ModRM | Aligned16, em_fxrstor),
	N, N, N, N, N, GP(0, &pfx_0f_ae_7),
}, {
	N, N, N, N, N, N, N, N,
} };

/*
 * Group table for opcode 0F 73 (66 prefix only):
 * /2 = PSRLQ imm8, /3 = PSRLDQ imm8, /6 = PSLLQ imm8, /7 = PSLLDQ imm8
 * The group table is indexed by modrm_reg (bits 5:3).
 */
static const struct opcode group_0f_73[] = {
	N, N,
	N, /* /2: PSRLQ imm8 - not yet wired */
	I(ImplicitOps | Sse | Avx, em_psrldq),	/* /3: PSRLDQ */
	N, N,
	N, /* /6: PSLLQ imm8 - not yet wired */
	I(ImplicitOps | Sse | Avx, em_pslldq),	/* /7: PSLLDQ */
};

static const struct gprefix pfx_0f_73 = {
	N,
	G(Sse | Avx, group_0f_73),	/* 66: group for PSRLDQ/PSLLDQ */
	N, N,
};

/* 0F C4: PINSRW */
static const struct gprefix pfx_0f_c4 = {
	N,
	I(ImplicitOps | Sse | Avx, em_pinsrw),	/* 66: PINSRW */
	N, N,
};

/* 0F C5: PEXTRW */
static const struct gprefix pfx_0f_c5 = {
	N,
	I(ImplicitOps | Sse | Avx, em_pextrw),	/* 66: PEXTRW */
	N, N,
};

/* 0F D0: ADDSUBPD (66) / ADDSUBPS (F2) */
static const struct gprefix pfx_0f_d0 = {
	N,
	I(Sse | Avx | Src2VexReg, em_addsubpd),	/* 66: ADDSUBPD */
	I(Sse | Avx | Src2VexReg, em_addsubps),	/* F2: ADDSUBPS */
	N,
};

static const struct gprefix pfx_0f_6f_0f_7f = {
	I(Mmx, em_mov), I(Sse | Avx | Aligned, em_mov), N, I(Sse | Avx | Unaligned, em_mov),
};

static const struct instr_dual instr_dual_0f_2b = {
	I(0, em_mov), N
};

static const struct gprefix pfx_0f_2b = {
	ID(0, &instr_dual_0f_2b), ID(0, &instr_dual_0f_2b), N, N,
};

/* 0F 2A: CVTPI2PS (NP) / CVTPI2PD (66) / CVTSI2SD (F2) / CVTSI2SS (F3) */
static const struct gprefix pfx_0f_2a = {
	N,						/* NP: CVTPI2PS (MMX, not emulated) */
	N,						/* 66: CVTPI2PD (MMX, not emulated) */
	I(ImplicitOps | Sse | Avx | No16, em_cvtsi2sd),	/* F2: CVTSI2SD */
	I(ImplicitOps | Sse | Avx | No16, em_cvtsi2ss),	/* F3: CVTSI2SS */
};

/* 0F 2C: CVTTPS2PI (NP) / CVTTPD2PI (66) / CVTTSD2SI (F2) / CVTTSS2SI (F3) */
static const struct gprefix pfx_0f_2c = {
	N,						 /* NP: CVTTPS2PI (MMX, not emulated) */
	N,						 /* 66: CVTTPD2PI (MMX, not emulated) */
	I(ImplicitOps | Sse | Avx | No16, em_cvttsd2si), /* F2: CVTTSD2SI */
	I(ImplicitOps | Sse | Avx | No16, em_cvttss2si), /* F3: CVTTSS2SI */
};

/* 0F 2D: CVTPS2PI (NP) / CVTPD2PI (66) / CVTSD2SI (F2) / CVTSS2SI (F3) */
static const struct gprefix pfx_0f_2d = {
	N,						/* NP: CVTPS2PI (MMX, not emulated) */
	N,						/* 66: CVTPD2PI (MMX, not emulated) */
	I(ImplicitOps | Sse | Avx | No16, em_cvtsd2si), /* F2: CVTSD2SI */
	I(ImplicitOps | Sse | Avx | No16, em_cvtss2si), /* F3: CVTSS2SI */
};

/* 0F 2E: UCOMISS (NP) / UCOMISD (66) */
static const struct gprefix pfx_0f_2e = {
	I(ImplicitOps | SrcMem32 | Sse | Avx, em_ucomiss),	/* NP: UCOMISS */
	I(ImplicitOps | SrcMem64 | Sse | Avx, em_ucomisd),	/* 66: UCOMISD */
	N, N,
};

/* 0F 2F: COMISS (NP) / COMISD (66) */
static const struct gprefix pfx_0f_2f = {
	I(ImplicitOps | SrcMem32 | Sse | Avx, em_comiss),	/* NP: COMISS */
	I(ImplicitOps | SrcMem64 | Sse | Avx, em_comisd),	/* 66: COMISD */
	N, N,
};

/* 0F 50: MOVMSKPS (NP) / MOVMSKPD (66) */
static const struct gprefix pfx_0f_50 = {
	I(ImplicitOps | Sse | Avx, em_movmskps),	/* NP: MOVMSKPS */
	I(ImplicitOps | Sse | Avx, em_movmskpd),	/* 66: MOVMSKPD */
	N, N,
};

/* 0F 51: SQRTPS/SQRTPD/SQRTSD/SQRTSS */
static const struct gprefix pfx_0f_51 = {
	I(DstReg | SrcMem | Sse | Avx, em_sqrtps),		/* NP: SQRTPS */
	I(DstReg | SrcMem | Sse | Avx, em_sqrtpd),		/* 66: SQRTPD */
	I(ImplicitOps | Sse | Avx, em_sqrtsd),			/* F2: SQRTSD */
	I(ImplicitOps | Sse | Avx, em_sqrtss),			/* F3: SQRTSS */
};

/* 0F 52: RSQRTPS (NP) / RSQRTSS (F3) */
static const struct gprefix pfx_0f_52 = {
	I(DstReg | SrcMem | Sse | Avx, em_rsqrtps),		/* NP: RSQRTPS */
	N,							/* 66: undefined */
	N,							/* F2: undefined */
	I(DstReg | SrcMem | Sse | Avx, em_rsqrtps),		/* F3: RSQRTSS */
};

/* 0F 53: RCPPS (NP) / RCPSS (F3) */
static const struct gprefix pfx_0f_53 = {
	I(DstReg | SrcMem | Sse | Avx, em_rcpps),		/* NP: RCPPS */
	N,							/* 66: undefined */
	N,							/* F2: undefined */
	I(DstReg | SrcMem | Sse | Avx, em_rcpps),		/* F3: RCPSS */
};

/* 0F 54: ANDPS (NP) / ANDPD (66) */
static const struct gprefix pfx_0f_54 = {
	I(DstReg | SrcMem | Sse | Avx | Src2VexReg, em_pand),	/* NP: ANDPS */
	I(DstReg | SrcMem | Sse | Avx | Src2VexReg, em_pand),	/* 66: ANDPD */
	N, N,
};

/* 0F 55: ANDNPS (NP) / ANDNPD (66) */
static const struct gprefix pfx_0f_55 = {
	I(DstReg | SrcMem | Sse | Avx | Src2VexReg, em_pandn),	/* NP: ANDNPS */
	I(DstReg | SrcMem | Sse | Avx | Src2VexReg, em_pandn),	/* 66: ANDNPD */
	N, N,
};

/* 0F 56: ORPS (NP) / ORPD (66) */
static const struct gprefix pfx_0f_56 = {
	I(DstReg | SrcMem | Sse | Avx | Src2VexReg, em_por),	/* NP: ORPS */
	I(DstReg | SrcMem | Sse | Avx | Src2VexReg, em_por),	/* 66: ORPD */
	N, N,
};

/* 0F 57: XORPS (NP) / XORPD (66) */
static const struct gprefix pfx_0f_57 = {
	I(DstReg | SrcMem | Sse | Avx | Src2VexReg, em_pxor),	/* NP: XORPS */
	I(DstReg | SrcMem | Sse | Avx | Src2VexReg, em_pxor),	/* 66: XORPD */
	N, N,
};

/* 0F 58: ADDPS/ADDPD/ADDSD/ADDSS */
static const struct gprefix pfx_0f_58 = {
	I(DstReg | SrcMem | Sse | Avx | Src2VexReg, em_addps),	/* NP: ADDPS */
	I(DstReg | SrcMem | Sse | Avx | Src2VexReg, em_addpd),	/* 66: ADDPD */
	I(ImplicitOps | Sse | Avx, em_addsd),			/* F2: ADDSD */
	I(ImplicitOps | Sse | Avx, em_addss),			/* F3: ADDSS */
};

/* 0F 59: MULPS/MULPD/MULSD/MULSS */
static const struct gprefix pfx_0f_59 = {
	I(DstReg | SrcMem | Sse | Avx | Src2VexReg, em_mulps),	/* NP: MULPS */
	I(DstReg | SrcMem | Sse | Avx | Src2VexReg, em_mulpd),	/* 66: MULPD */
	I(ImplicitOps | Sse | Avx, em_mulsd),			/* F2: MULSD */
	I(ImplicitOps | Sse | Avx, em_mulss),			/* F3: MULSS */
};

/* 0F 5A: CVTPS2PD/CVTPD2PS/CVTSD2SS/CVTSS2SD */
static const struct gprefix pfx_0f_5a = {
	I(Sse | Avx, em_cvtps2pd),				/* NP: CVTPS2PD (src=dst/2, own fetch) */
	I(DstReg | SrcMem | Sse | Avx, em_cvtpd2ps),		/* 66: CVTPD2PS */
	I(ImplicitOps | Sse | Avx, em_cvtsd2ss),		/* F2: CVTSD2SS */
	I(ImplicitOps | Sse | Avx, em_cvtss2sd),		/* F3: CVTSS2SD */
};

/* 0F 5B: CVTDQ2PS (NP) / CVTPS2DQ (66) / CVTTPS2DQ (F3) */
static const struct gprefix pfx_0f_5b = {
	I(DstReg | SrcMem | Sse | Avx, em_cvtdq2ps),		/* NP: CVTDQ2PS */
	I(DstReg | SrcMem | Sse | Avx, em_cvtps2dq),		/* 66: CVTPS2DQ */
	N,							/* F2: undefined */
	I(DstReg | SrcMem | Sse | Avx, em_cvttps2dq),		/* F3: CVTTPS2DQ */
};

/* 0F 5C: SUBPS/SUBPD/SUBSD/SUBSS */
static const struct gprefix pfx_0f_5c = {
	I(DstReg | SrcMem | Sse | Avx | Src2VexReg, em_subps),	/* NP: SUBPS */
	I(DstReg | SrcMem | Sse | Avx | Src2VexReg, em_subpd),	/* 66: SUBPD */
	I(ImplicitOps | Sse | Avx, em_subsd),			/* F2: SUBSD */
	I(ImplicitOps | Sse | Avx, em_subss),			/* F3: SUBSS */
};

/* 0F 5D: MINPS/MINPD/MINSD/MINSS */
static const struct gprefix pfx_0f_5d = {
	I(DstReg | SrcMem | Sse | Avx | Src2VexReg, em_minps),	/* NP: MINPS */
	I(DstReg | SrcMem | Sse | Avx | Src2VexReg, em_minpd),	/* 66: MINPD */
	I(ImplicitOps | Sse | Avx, em_minsd),			/* F2: MINSD */
	I(ImplicitOps | Sse | Avx, em_minss),			/* F3: MINSS */
};

/* 0F 5E: DIVPS/DIVPD/DIVSD/DIVSS */
static const struct gprefix pfx_0f_5e = {
	I(DstReg | SrcMem | Sse | Avx | Src2VexReg, em_divps),	/* NP: DIVPS */
	I(DstReg | SrcMem | Sse | Avx | Src2VexReg, em_divpd),	/* 66: DIVPD */
	I(ImplicitOps | Sse | Avx, em_divsd),			/* F2: DIVSD */
	I(ImplicitOps | Sse | Avx, em_divss),			/* F3: DIVSS */
};

/* 0F 5F: MAXPS/MAXPD/MAXSD/MAXSS */
static const struct gprefix pfx_0f_5f = {
	I(DstReg | SrcMem | Sse | Avx | Src2VexReg, em_maxps),	/* NP: MAXPS */
	I(DstReg | SrcMem | Sse | Avx | Src2VexReg, em_maxpd),	/* 66: MAXPD */
	I(ImplicitOps | Sse | Avx, em_maxsd),			/* F2: MAXSD */
	I(ImplicitOps | Sse | Avx, em_maxss),			/* F3: MAXSS */
};

/*
 * 0F 10: MOVUPS / MOVUPD / MOVSD xmm,m64 / MOVSS xmm,m32
 * Refactored from shared pfx_0f_10_0f_11: operand flags moved inward
 * so scalar variants can have smaller memory access sizes.
 */
static const struct gprefix pfx_0f_10 = {
	I(DstReg | SrcMem | Sse | Avx | Unaligned | Mov, em_mov), /* MOVUPS */
	I(DstReg | SrcMem | Sse | Avx | Unaligned | Mov, em_mov), /* MOVUPD */
	I(ImplicitOps | Sse | Avx, em_movsd_load),		 /* MOVSD */
	I(ImplicitOps | Sse | Avx, em_movss_load),		 /* MOVSS */
};

/* 0F 11: MOVUPS / MOVUPD / MOVSD m64,xmm / MOVSS m32,xmm (store) */
static const struct gprefix pfx_0f_11 = {
	I(DstMem | SrcReg | Sse | Avx | Unaligned | Mov, em_mov), /* MOVUPS */
	I(DstMem | SrcReg | Sse | Avx | Unaligned | Mov, em_mov), /* MOVUPD */
	I(ImplicitOps | Sse | Avx, em_movsd_store),		 /* MOVSD */
	I(ImplicitOps | Sse | Avx, em_movss_store),		 /* MOVSS */
};

/* --- MOVLPS/MOVLPD (0F 12/13) + MOVSLDUP/MOVDDUP --- */

static const struct instr_dual instr_dual_movddup = {
	I(DstReg | SrcMem64 | Sse | Mov, em_movddup), N
};

/* 0F 12: MOVLPS / MOVLPD / MOVDDUP / MOVSLDUP */
static const struct gprefix pfx_0f_12 = {
	I(ImplicitOps | Sse | Avx, em_movlps),				/* MOVLPS/HLPS */
	I(ImplicitOps | Sse | Avx, em_movlps),				/* MOVLPD */
	ID(0, &instr_dual_movddup),					/* MOVDDUP */
	I(DstReg | SrcMem | Sse | Avx | Unaligned | Mov, em_movsldup),	/* MOVSLDUP */
};

/* 0F 13: MOVLPS m64,xmm / MOVLPD m64,xmm (store, memory-only) */
static const struct gprefix pfx_0f_13 = {
	I(ImplicitOps | Sse | Avx, em_movlps_store),
	I(ImplicitOps | Sse | Avx, em_movlps_store),
	N, N,
};

/* --- MOVHPS/MOVHPD (0F 16/17) + MOVSHDUP --- */

/* 0F 16: MOVHPS / MOVHPD / MOVSHDUP */
static const struct gprefix pfx_0f_16 = {
	I(ImplicitOps | Sse | Avx, em_movhps_load),			/* MOVHPS/LHPS */
	I(ImplicitOps | Sse | Avx, em_movhps_load),			/* MOVHPD */
	N,								/* F2: undef */
	I(DstReg | SrcMem | Sse | Avx | Unaligned | Mov, em_movshdup),	/* MOVSHDUP */
};

/* 0F 17: MOVHPS m64,xmm / MOVHPD m64,xmm (store, memory-only) */
static const struct gprefix pfx_0f_17 = {
	I(ImplicitOps | Sse | Avx, em_movhps_store),
	I(ImplicitOps | Sse | Avx, em_movhps_store),
	N, N,
};

/* --- UNPCKLPS/UNPCKHPS (0F 14/15) --- */
static const struct gprefix pfx_0f_14 = {
	I(Sse | Avx | Src2VexReg, em_unpcklps),	/* NP: UNPCKLPS */
	I(Sse | Avx | Src2VexReg, em_unpcklpd),	/* 66: UNPCKLPD */
	N, N,
};

static const struct gprefix pfx_0f_15 = {
	I(Sse | Avx | Src2VexReg, em_unpckhps),	/* NP: UNPCKHPS */
	I(Sse | Avx | Src2VexReg, em_unpckhpd),	/* 66: UNPCKHPD */
	N, N,
};

/* --- PUNPCK/PACK* (0F 60-6D with 66 prefix) --- */
static const struct gprefix pfx_0f_60 = {
	N,
	I(Sse | Avx | Src2VexReg, em_punpcklbw),	/* 66: PUNPCKLBW */
	N, N,
};

static const struct gprefix pfx_0f_61 = {
	N,
	I(Sse | Avx | Src2VexReg, em_punpcklwd),	/* 66: PUNPCKLWD */
	N, N,
};

static const struct gprefix pfx_0f_62 = {
	N,
	I(Sse | Avx | Src2VexReg, em_punpckldq),	/* 66: PUNPCKLDQ */
	N, N,
};

static const struct gprefix pfx_0f_63 = {
	N,
	I(Sse | Avx | Src2VexReg, em_packsswb),	/* 66: PACKSSWB */
	N, N,
};

static const struct gprefix pfx_0f_67 = {
	N,
	I(Sse | Avx | Src2VexReg, em_packuswb),	/* 66: PACKUSWB */
	N, N,
};

static const struct gprefix pfx_0f_68 = {
	N,
	I(Sse | Avx | Src2VexReg, em_punpckhbw),	/* 66: PUNPCKHBW */
	N, N,
};

static const struct gprefix pfx_0f_69 = {
	N,
	I(Sse | Avx | Src2VexReg, em_punpckhwd),	/* 66: PUNPCKHWD */
	N, N,
};

static const struct gprefix pfx_0f_6a = {
	N,
	I(Sse | Avx | Src2VexReg, em_punpckhdq),	/* 66: PUNPCKHDQ */
	N, N,
};

static const struct gprefix pfx_0f_6b = {
	N,
	I(Sse | Avx | Src2VexReg, em_packssdw),	/* 66: PACKSSDW */
	N, N,
};

static const struct gprefix pfx_0f_6c = {
	N,
	I(Sse | Avx | Src2VexReg, em_punpcklqdq),	/* 66: PUNPCKLQDQ */
	N, N,
};

static const struct gprefix pfx_0f_6d = {
	N,
	I(Sse | Avx | Src2VexReg, em_punpckhqdq),	/* 66: PUNPCKHQDQ */
	N, N,
};

/* --- 0F 70: PSHUFD / PSHUFHW / PSHUFLW --- */
static const struct gprefix pfx_0f_70 = {
	N,						/* NP: PSHUFW (MMX, skip) */
	I(Sse | Avx, em_pshufd),			/* 66: PSHUFD */
	I(Sse | Avx, em_pshuflw),			/* F2: PSHUFLW */
	I(Sse | Avx, em_pshufhw),			/* F3: PSHUFHW */
};

/* --- 0F C2: CMPPS/CMPPD/CMPSS/CMPSD (with imm8) --- */
static const struct gprefix pfx_0f_c2 = {
	I(Sse | Avx | Src2VexReg, em_cmpps_imm),	/* NP: CMPPS */
	I(Sse | Avx | Src2VexReg, em_cmppd_imm),	/* 66: CMPPD */
	I(ImplicitOps | Sse | Avx, em_cmpsd_imm),	/* F2: CMPSD */
	I(ImplicitOps | Sse | Avx, em_cmpss_imm),	/* F3: CMPSS */
};

/* --- 0F C6: SHUFPS / SHUFPD --- */
static const struct gprefix pfx_0f_c6 = {
	I(Sse | Avx | Src2VexReg, em_shufps),		/* NP: SHUFPS */
	I(Sse | Avx | Src2VexReg, em_shufpd),		/* 66: SHUFPD */
	N, N,
};

/* --- 0F D7: PMOVMSKB --- */
static const struct gprefix pfx_0f_d7 = {
	N,
	I(ImplicitOps | Sse | Avx, em_pmovmskb),	/* 66: PMOVMSKB */
	N, N,
};

/* --- Shift instructions (0F D1-D3, 0F E1-E2, 0F F1-F3) --- */
static const struct gprefix pfx_0f_d1 = {
	N,
	I(Sse | Avx | Src2VexReg, em_psrlw),		/* 66: PSRLW */
	N, N,
};

static const struct gprefix pfx_0f_d2 = {
	N,
	I(Sse | Avx | Src2VexReg, em_psrld),		/* 66: PSRLD */
	N, N,
};

static const struct gprefix pfx_0f_d3 = {
	N,
	I(Sse | Avx | Src2VexReg, em_psrlq),		/* 66: PSRLQ */
	N, N,
};

/* 0F D8: PSUBUSB */
static const struct gprefix pfx_0f_d8 = {
	N,
	I(Sse | Avx | Src2VexReg, em_psubusb),		/* 66: PSUBUSB */
	N, N,
};

/* 0F D9: PSUBUSW */
static const struct gprefix pfx_0f_d9 = {
	N,
	I(Sse | Avx | Src2VexReg, em_psubusw),		/* 66: PSUBUSW */
	N, N,
};

/* 0F DC: PADDUSB */
static const struct gprefix pfx_0f_dc = {
	N,
	I(Sse | Avx | Src2VexReg, em_paddusb),		/* 66: PADDUSB */
	N, N,
};

/* 0F DD: PADDUSW */
static const struct gprefix pfx_0f_dd = {
	N,
	I(Sse | Avx | Src2VexReg, em_paddusw),		/* 66: PADDUSW */
	N, N,
};

/* 0F DE: PMAXUB */
static const struct gprefix pfx_0f_de = {
	N,
	I(Sse | Avx | Src2VexReg, em_pmaxub),		/* 66: PMAXUB */
	N, N,
};

static const struct gprefix pfx_0f_e1 = {
	N,
	I(Sse | Avx | Src2VexReg, em_psraw),		/* 66: PSRAW */
	N, N,
};

static const struct gprefix pfx_0f_e2 = {
	N,
	I(Sse | Avx | Src2VexReg, em_psrad),		/* 66: PSRAD */
	N, N,
};

/* 0F E3: PAVGW */
static const struct gprefix pfx_0f_e3 = {
	N,
	I(Sse | Avx | Src2VexReg, em_pavgw),		/* 66: PAVGW */
	N, N,
};

/* 0F E4: PMULHUW */
static const struct gprefix pfx_0f_e4 = {
	N,
	I(Sse | Avx | Src2VexReg, em_pmulhuw),		/* 66: PMULHUW */
	N, N,
};

/* 0F E5: PMULHW */
static const struct gprefix pfx_0f_e5 = {
	N,
	I(Sse | Avx | Src2VexReg, em_pmulhw),		/* 66: PMULHW */
	N, N,
};

/* 0F E6: CVTPD2DQ (F2) / CVTTPD2DQ (66) / CVTDQ2PD (F3) */
static const struct gprefix pfx_0f_e6 = {
	N,
	I(DstReg | SrcMem | Sse | Avx, em_cvttpd2dq),	/* 66: CVTTPD2DQ */
	I(DstReg | SrcMem | Sse | Avx, em_cvtpd2dq),	/* F2: CVTPD2DQ */
	I(Sse | Avx, em_cvtdq2pd),			/* F3: CVTDQ2PD (src=dst/2, own fetch) */
};

/* 0F E8: PSUBSB */
static const struct gprefix pfx_0f_e8 = {
	N,
	I(Sse | Avx | Src2VexReg, em_psubsb),		/* 66: PSUBSB */
	N, N,
};

/* 0F E9: PSUBSW */
static const struct gprefix pfx_0f_e9 = {
	N,
	I(Sse | Avx | Src2VexReg, em_psubsw),		/* 66: PSUBSW */
	N, N,
};

/* 0F EA: PMINSW */
static const struct gprefix pfx_0f_ea = {
	N,
	I(Sse | Avx | Src2VexReg, em_pminsw),		/* 66: PMINSW */
	N, N,
};

/* 0F EC: PADDSB */
static const struct gprefix pfx_0f_ec = {
	N,
	I(Sse | Avx | Src2VexReg, em_paddsb),		/* 66: PADDSB */
	N, N,
};

/* 0F ED: PADDSW */
static const struct gprefix pfx_0f_ed = {
	N,
	I(Sse | Avx | Src2VexReg, em_paddsw),		/* 66: PADDSW */
	N, N,
};

/* 0F EE: PMAXSW */
static const struct gprefix pfx_0f_ee = {
	N,
	I(Sse | Avx | Src2VexReg, em_pmaxsw),		/* 66: PMAXSW */
	N, N,
};

static const struct gprefix pfx_0f_f1 = {
	N,
	I(Sse | Avx | Src2VexReg, em_psllw),		/* 66: PSLLW */
	N, N,
};

static const struct gprefix pfx_0f_f2 = {
	N,
	I(Sse | Avx | Src2VexReg, em_pslld),		/* 66: PSLLD */
	N, N,
};

static const struct gprefix pfx_0f_f3 = {
	N,
	I(Sse | Avx | Src2VexReg, em_psllq),		/* 66: PSLLQ */
	N, N,
};

/* 0F F4: PMULUDQ */
static const struct gprefix pfx_0f_f4 = {
	N,
	I(Sse | Avx | Src2VexReg, em_pmuludq),		/* 66: PMULUDQ */
	N, N,
};

/* 0F F5: PMADDWD */
static const struct gprefix pfx_0f_f5 = {
	N,
	I(Sse | Avx | Src2VexReg, em_pmaddwd),		/* 66: PMADDWD */
	N, N,
};

/* 0F F6: PSADBW */
static const struct gprefix pfx_0f_f6 = {
	N,
	I(Sse | Avx | Src2VexReg, em_psadbw),		/* 66: PSADBW */
	N, N,
};

/* 0F F0: LDDQU (F2) */
static const struct gprefix pfx_0f_f0 = {
	N, N,
	I(DstReg | SrcMem | Sse | Avx | Unaligned | Mov, em_lddqu),	/* F2: LDDQU */
	N,
};

/* 0F 7C: HADDPS (F2) / HADDPD (66) */
static const struct gprefix pfx_0f_7c = {
	N,
	I(Sse | Avx | Src2VexReg, em_haddpd),		/* 66: HADDPD */
	I(Sse | Avx | Src2VexReg, em_haddps),		/* F2: HADDPS */
	N,
};

/* 0F 7D: HSUBPS (F2) / HSUBPD (66) */
static const struct gprefix pfx_0f_7d = {
	N,
	I(Sse | Avx | Src2VexReg, em_hsubpd),		/* 66: HSUBPD */
	I(Sse | Avx | Src2VexReg, em_hsubps),		/* F2: HSUBPS */
	N,
};

/* --- MOVD/MOVQ XMM (0F 6E / 0F 7E / 0F D6) --- */

/* 0F 6E: MOVD mm,r/m32 (NP) / MOVD xmm,m32 or MOVQ xmm,m64 (66) */
static const struct gprefix pfx_0f_6e = {
	I(Mmx | DstReg | SrcMem | Mov, em_mov),			/* MOVD mm, r/m32 */
	I(ImplicitOps | Sse | Avx | No16, em_movd_xmm_load),	/* MOVD/Q xmm, r/m */
	N, N,
};

/* 0F 7E: MOVD r/m32,mm (NP) / MOVD m32/m64,xmm (66) / MOVQ xmm,m64 (F3) */
static const struct gprefix pfx_0f_7e = {
	I(Mmx | DstMem | SrcReg | Mov, em_mov),			/* MOVD r/m32, mm */
	I(ImplicitOps | Sse | Avx | No16, em_movd_xmm_store),	/* MOVD/Q r/m, xmm */
	N,							/* F2: undef */
	I(ImplicitOps | Sse | Avx, em_movq_load),		/* MOVQ xmm, xmm/m64 */
};

static const struct gprefix pfx_0f_d6 = {
	N,						 /* NP: undef */
	I(ImplicitOps | Sse | Avx, em_movq_store), /* MOVQ xmm/m64, xmm */
	N, N,						 /* F2/F3: MOVDQ2Q/MOVQ2DQ (skip) */
};

/* 0F EB: POR mm,mm/m64 (NP) / POR xmm,xmm/m128 (66) */
static const struct gprefix pfx_0f_eb = {
	N,							/* NP: MMX (not emulated) */
	I(Sse | Avx | Src2VexReg, em_por),		/* 66: POR/vPOR xmm */
	N, N,
};

/* 0F E0: PAVGB mm,mm/m64 (NP) / PAVGB xmm,xmm/m128 (66) */
static const struct gprefix pfx_0f_e0 = {
	N,							/* NP: MMX (not emulated) */
	I(Sse | Avx | Src2VexReg, em_pavgb),	/* 66: PAVGB/vPAVGB xmm */
	N, N,
};

/* 0F DA: PMINUB mm,mm/m64 (NP) / PMINUB xmm,xmm/m128 (66) */
static const struct gprefix pfx_0f_da = {
	N,							/* NP: MMX (not emulated) */
	I(Sse | Avx | Src2VexReg, em_pminub),	/* 66: PMINUB/vPMINUB xmm */
	N, N,
};

/* 0F 64: PCMPGTB mm,mm/m64 (NP) / PCMPGTB xmm,xmm/m128 (66) */
static const struct gprefix pfx_0f_64 = {
	N,							/* NP: MMX (not emulated) */
	I(Sse | Avx | Src2VexReg, em_pcmpgtb),	/* 66: PCMPGTB/vPCMPGTB */
	N, N,
};

/* 0F 65: PCMPGTW mm,mm/m64 (NP) / PCMPGTW xmm,xmm/m128 (66) */
static const struct gprefix pfx_0f_65 = {
	N,							/* NP: MMX (not emulated) */
	I(Sse | Avx | Src2VexReg, em_pcmpgtw),	/* 66: PCMPGTW/vPCMPGTW */
	N, N,
};

/* 0F 66: PCMPGTD mm,mm/m64 (NP) / PCMPGTD xmm,xmm/m128 (66) */
static const struct gprefix pfx_0f_66 = {
	N,							/* NP: MMX (not emulated) */
	I(Sse | Avx | Src2VexReg, em_pcmpgtd),	/* 66: PCMPGTD/vPCMPGTD */
	N, N,
};

/* 0F 74: PCMPEQB mm,mm/m64 (NP) / PCMPEQB xmm,xmm/m128 (66) */
static const struct gprefix pfx_0f_74 = {
	N,							 /* NP: MMX (not emulated) */
	I(Sse | Avx | Src2VexReg, em_pcmpeqb), /* 66: PCMPEQB/vPCMPEQB */
	N, N,
};

/* 0F 75: PCMPEQW mm,mm/m64 (NP) / PCMPEQW xmm,xmm/m128 (66) */
static const struct gprefix pfx_0f_75 = {
	N,							 /* NP: MMX (not emulated) */
	I(Sse | Avx | Src2VexReg, em_pcmpeqw), /* 66: PCMPEQW/vPCMPEQW */
	N, N,
};

/* 0F 76: PCMPEQD mm,mm/m64 (NP) / PCMPEQD xmm,xmm/m128 (66) */
static const struct gprefix pfx_0f_76 = {
	N,							/* NP: MMX (not emulated) */
	I(Sse | Avx | Src2VexReg, em_pcmpeqd),	/* 66: PCMPEQD/vPCMPEQD */
	N, N,
};

/* 0F DB: PAND mm,mm/m64 (NP) / PAND xmm,xmm/m128 (66) */
static const struct gprefix pfx_0f_db = {
	N,
	I(Sse | Avx | Src2VexReg, em_pand),	/* 66: PAND/vPAND */
	N, N,
};

/* 0F DF: PANDN mm,mm/m64 (NP) / PANDN xmm,xmm/m128 (66) */
static const struct gprefix pfx_0f_df = {
	N,
	I(Sse | Avx | Src2VexReg, em_pandn),	/* 66: PANDN/vPANDN */
	N, N,
};

/* 0F D4: PADDQ mm,mm/m64 (NP) / PADDQ xmm,xmm/m128 (66) */
static const struct gprefix pfx_0f_d4 = {
	N,
	I(Sse | Avx | Src2VexReg, em_paddq),	/* 66: PADDQ/vPADDQ */
	N, N,
};

/* 0F D5: PMULLW mm,mm/m64 (NP) / PMULLW xmm,xmm/m128 (66) */
static const struct gprefix pfx_0f_d5 = {
	N,
	I(Sse | Avx | Src2VexReg, em_pmullw),	/* 66: PMULLW/vPMULLW */
	N, N,
};

/* 0F EF: PXOR mm,mm/m64 (NP) / PXOR xmm,xmm/m128 (66) */
static const struct gprefix pfx_0f_ef = {
	N,
	I(Sse | Avx | Src2VexReg, em_pxor),	/* 66: PXOR/vPXOR */
	N, N,
};

/* 0F F8: PSUBB mm,mm/m64 (NP) / PSUBB xmm,xmm/m128 (66) */
static const struct gprefix pfx_0f_f8 = {
	N,
	I(Sse | Avx | Src2VexReg, em_psubb),	/* 66: PSUBB/vPSUBB */
	N, N,
};

/* 0F F9: PSUBW mm,mm/m64 (NP) / PSUBW xmm,xmm/m128 (66) */
static const struct gprefix pfx_0f_f9 = {
	N,
	I(Sse | Avx | Src2VexReg, em_psubw),	/* 66: PSUBW/vPSUBW */
	N, N,
};

/* 0F FA: PSUBD mm,mm/m64 (NP) / PSUBD xmm,xmm/m128 (66) */
static const struct gprefix pfx_0f_fa = {
	N,
	I(Sse | Avx | Src2VexReg, em_psubd),	/* 66: PSUBD/vPSUBD */
	N, N,
};

/* 0F FB: PSUBQ mm,mm/m64 (NP) / PSUBQ xmm,xmm/m128 (66) */
static const struct gprefix pfx_0f_fb = {
	N,
	I(Sse | Avx | Src2VexReg, em_psubq),	/* 66: PSUBQ/vPSUBQ */
	N, N,
};

/* 0F FC: PADDB mm,mm/m64 (NP) / PADDB xmm,xmm/m128 (66) */
static const struct gprefix pfx_0f_fc = {
	N,
	I(Sse | Avx | Src2VexReg, em_paddb),	/* 66: PADDB/vPADDB */
	N, N,
};

/* 0F FD: PADDW mm,mm/m64 (NP) / PADDW xmm,xmm/m128 (66) */
static const struct gprefix pfx_0f_fd = {
	N,
	I(Sse | Avx | Src2VexReg, em_paddw),	/* 66: PADDW/vPADDW */
	N, N,
};

/* 0F FE: PADDD mm,mm/m64 (NP) / PADDD xmm,xmm/m128 (66) */
static const struct gprefix pfx_0f_fe = {
	N,
	I(Sse | Avx | Src2VexReg, em_paddd),	/* 66: PADDD/vPADDD */
	N, N,
};

static const struct gprefix pfx_0f_28_0f_29 = {
	I(Aligned, em_mov), I(Aligned, em_mov), N, N,
};

static const struct gprefix pfx_0f_e7_0f_38_2a = {
	N, I(Sse | Avx, em_mov), N, N,
};

static const struct escape escape_d8 = { {
	I(SrcMem32 | ImplicitOps, em_fadd_m32fp),
	I(SrcMem32 | ImplicitOps, em_fmul_m32fp),
	I(SrcMem32 | ImplicitOps, em_fcom_m32fp),
	I(SrcMem32 | ImplicitOps, em_fcomp_m32fp),
	I(SrcMem32 | ImplicitOps, em_fsub_m32fp),
	I(SrcMem32 | ImplicitOps, em_fsubr_m32fp),
	I(SrcMem32 | ImplicitOps, em_fdiv_m32fp),
	I(SrcMem32 | ImplicitOps, em_fdivr_m32fp),
}, {
	/* 0xC0 - 0xC7 */
	X8(I(ImplicitOps, em_x87_d8_reg)),
	/* 0xC8 - 0xCF */
	X8(I(ImplicitOps, em_x87_d8_reg)),
	/* 0xD0 - 0xD7 */
	X8(I(ImplicitOps, em_x87_d8_reg)),
	/* 0xD8 - 0xDF */
	X8(I(ImplicitOps, em_x87_d8_reg)),
	/* 0xE0 - 0xE7 */
	X8(I(ImplicitOps, em_x87_d8_reg)),
	/* 0xE8 - 0xEF */
	X8(I(ImplicitOps, em_x87_d8_reg)),
	/* 0xF0 - 0xF7 */
	X8(I(ImplicitOps, em_x87_d8_reg)),
	/* 0xF8 - 0xFF */
	X8(I(ImplicitOps, em_x87_d8_reg)),
} };

static const struct escape escape_d9 = { {
	I(SrcMem32 | ImplicitOps, em_fld), N,
	I(DstMem32, em_fst_m32fp),
	I(DstMem32, em_fstp_m32fp),
	N, N, N, I(DstMem16 | Mov, em_fnstcw),
}, {
	/* 0xC0 - 0xC7 */
	N, N, N, N, N, N, N, N,
	/* 0xC8 - 0xCF */
	N, N, N, N, N, N, N, N,
	/* 0xD0 - 0xC7 */
	N, N, N, N, N, N, N, N,
	/* 0xD8 - 0xDF */
	N, N, N, N, N, N, N, N,
	/* 0xE0 - 0xE7 */
	N, N, N, N, N, N, N, N,
	/* 0xE8 - 0xEF */
	N, N, N, N, N, N, N, N,
	/* 0xF0 - 0xF7 */
	N, N, N, N, N, N, N, N,
	/* 0xF8 - 0xFF */
	N, N, N, N, N, N, N, N,
} };

static const struct escape escape_db = { {
	N, N, N, N, N, N, N, I(DstMem | Mov, em_fstp_m80fp),
}, {
	/* 0xC0 - 0xC7 */
	N, N, N, N, N, N, N, N,
	/* 0xC8 - 0xCF */
	N, N, N, N, N, N, N, N,
	/* 0xD0 - 0xC7 */
	N, N, N, N, N, N, N, N,
	/* 0xD8 - 0xDF */
	N, N, N, N, N, N, N, N,
	/* 0xE0 - 0xE7 */
	N, N, N, I(ImplicitOps, em_fninit), N, N, N, N,
	/* 0xE8 - 0xEF */
	N, N, N, N, N, N, N, N,
	/* 0xF0 - 0xF7 */
	N, N, N, N, N, N, N, N,
	/* 0xF8 - 0xFF */
	N, N, N, N, N, N, N, N,
} };

static const struct escape escape_dd = { {
	I(SrcMem64 | ImplicitOps, em_fld_m64fp),
	N,
	I(DstMem64, em_fst_m64fp),
	I(DstMem64, em_fstp_m64fp),
	N, N, N, I(DstMem16 | Mov, em_fnstsw),
}, {
	/* 0xC0 - 0xC7 */
	N, N, N, N, N, N, N, N,
	/* 0xC8 - 0xCF */
	N, N, N, N, N, N, N, N,
	/* 0xD0 - 0xC7 */
	N, N, N, N, N, N, N, N,
	/* 0xD8 - 0xDF */
	N, N, N, N, N, N, N, N,
	/* 0xE0 - 0xE7 */
	N, N, N, N, N, N, N, N,
	/* 0xE8 - 0xEF */
	N, N, N, N, N, N, N, N,
	/* 0xF0 - 0xF7 */
	N, N, N, N, N, N, N, N,
	/* 0xF8 - 0xFF */
	N, N, N, N, N, N, N, N,
} };

static const struct instr_dual instr_dual_0f_c3 = {
	I(DstMem | SrcReg | ModRM | No16 | Mov, em_mov), N
};

static const struct mode_dual mode_dual_63 = {
	N, I(DstReg | SrcMem32 | ModRM | Mov, em_movsxd)
};

static const struct instr_dual instr_dual_8d = {
	D(DstReg | SrcMem | ModRM | NoAccess), N
};

static const struct opcode opcode_table[256] = {
	/* 0x00 - 0x07 */
	I6ALU(Lock, em_add),
	I(ImplicitOps | Stack | No64 | Src2ES, em_push_sreg),
	I(ImplicitOps | Stack | No64 | Src2ES, em_pop_sreg),
	/* 0x08 - 0x0F */
	I6ALU(Lock | PageTable, em_or),
	I(ImplicitOps | Stack | No64 | Src2CS, em_push_sreg),
	N,
	/* 0x10 - 0x17 */
	I6ALU(Lock, em_adc),
	I(ImplicitOps | Stack | No64 | Src2SS, em_push_sreg),
	I(ImplicitOps | Stack | No64 | Src2SS, em_pop_sreg),
	/* 0x18 - 0x1F */
	I6ALU(Lock, em_sbb),
	I(ImplicitOps | Stack | No64 | Src2DS, em_push_sreg),
	I(ImplicitOps | Stack | No64 | Src2DS, em_pop_sreg),
	/* 0x20 - 0x27 */
	I6ALU(Lock | PageTable, em_and), N, N,
	/* 0x28 - 0x2F */
	I6ALU(Lock, em_sub), N, I(ByteOp | DstAcc | No64, em_das),
	/* 0x30 - 0x37 */
	I6ALU(Lock, em_xor), N, N,
	/* 0x38 - 0x3F */
	I6ALU(NoWrite, em_cmp), N, N,
	/* 0x40 - 0x4F */
	X8(I(DstReg, em_inc)), X8(I(DstReg, em_dec)),
	/* 0x50 - 0x57 */
	X8(I(SrcReg | Stack, em_push)),
	/* 0x58 - 0x5F */
	X8(I(DstReg | Stack, em_pop)),
	/* 0x60 - 0x67 */
	I(ImplicitOps | Stack | No64, em_pusha),
	I(ImplicitOps | Stack | No64, em_popa),
	N, MD(ModRM, &mode_dual_63),
	N, N, N, N,
	/* 0x68 - 0x6F */
	I(SrcImm | Mov | Stack, em_push),
	I(DstReg | SrcMem | ModRM | Src2Imm, em_imul_3op),
	I(SrcImmByte | Mov | Stack, em_push),
	I(DstReg | SrcMem | ModRM | Src2ImmByte, em_imul_3op),
	I2bvIP(DstDI | SrcDX | Mov | String | Unaligned, em_in, ins, check_perm_in), /* insb, insw/insd */
	I2bvIP(SrcSI | DstDX | String, em_out, outs, check_perm_out), /* outsb, outsw/outsd */
	/* 0x70 - 0x7F */
	X16(D(SrcImmByte | NearBranch | IsBranch)),
	/* 0x80 - 0x87 */
	G(ByteOp | DstMem | SrcImm, group1),
	G(DstMem | SrcImm, group1),
	G(ByteOp | DstMem | SrcImm | No64, group1),
	G(DstMem | SrcImmByte, group1),
	I2bv(DstMem | SrcReg | ModRM | NoWrite, em_test),
	I2bv(DstMem | SrcReg | ModRM | Lock | PageTable, em_xchg),
	/* 0x88 - 0x8F */
	I2bv(DstMem | SrcReg | ModRM | Mov | PageTable, em_mov),
	I2bv(DstReg | SrcMem | ModRM | Mov, em_mov),
	I(DstMem | SrcNone | ModRM | Mov | PageTable, em_mov_rm_sreg),
	ID(0, &instr_dual_8d),
	I(ImplicitOps | SrcMem16 | ModRM, em_mov_sreg_rm),
	G(0, group1A),
	/* 0x90 - 0x97 */
	DI(SrcAcc | DstReg, pause), X7(D(SrcAcc | DstReg)),
	/* 0x98 - 0x9F */
	D(DstAcc | SrcNone), I(ImplicitOps | SrcAcc, em_cwd),
	I(SrcImmFAddr | No64 | IsBranch | ShadowStack, em_call_far), N,
	II(ImplicitOps | Stack, em_pushf, pushf),
	II(ImplicitOps | Stack, em_popf, popf),
	I(ImplicitOps, em_sahf), I(ImplicitOps, em_lahf),
	/* 0xA0 - 0xA7 */
	I2bv(DstAcc | SrcMem | Mov | MemAbs, em_mov),
	I2bv(DstMem | SrcAcc | Mov | MemAbs | PageTable, em_mov),
	I2bv(SrcSI | DstDI | Mov | String | TwoMemOp, em_mov),
	I2bv(SrcSI | DstDI | String | NoWrite | TwoMemOp, em_cmp_r),
	/* 0xA8 - 0xAF */
	I2bv(DstAcc | SrcImm | NoWrite, em_test),
	I2bv(SrcAcc | DstDI | Mov | String, em_mov),
	I2bv(SrcSI | DstAcc | Mov | String, em_mov),
	I2bv(SrcAcc | DstDI | String | NoWrite, em_cmp_r),
	/* 0xB0 - 0xB7 */
	X8(I(ByteOp | DstReg | SrcImm | Mov, em_mov)),
	/* 0xB8 - 0xBF */
	X8(I(DstReg | SrcImm64 | Mov, em_mov)),
	/* 0xC0 - 0xC7 */
	G(ByteOp | Src2ImmByte, group2), G(Src2ImmByte, group2),
	I(ImplicitOps | NearBranch | SrcImmU16 | IsBranch | ShadowStack, em_ret_near_imm),
	I(ImplicitOps | NearBranch | IsBranch | ShadowStack, em_ret),
	I(DstReg | SrcMemFAddr | ModRM | No64 | Src2ES, em_lseg),
	I(DstReg | SrcMemFAddr | ModRM | No64 | Src2DS, em_lseg),
	G(ByteOp, group11), G(0, group11),
	/* 0xC8 - 0xCF */
	I(Stack | SrcImmU16 | Src2ImmByte, em_enter),
	I(Stack, em_leave),
	I(ImplicitOps | SrcImmU16 | IsBranch | ShadowStack, em_ret_far_imm),
	I(ImplicitOps | IsBranch | ShadowStack, em_ret_far),
	D(ImplicitOps | IsBranch), DI(SrcImmByte | IsBranch | ShadowStack, intn),
	D(ImplicitOps | No64 | IsBranch),
	II(ImplicitOps | IsBranch | ShadowStack, em_iret, iret),
	/* 0xD0 - 0xD7 */
	G(Src2One | ByteOp, group2), G(Src2One, group2),
	G(Src2CL | ByteOp, group2), G(Src2CL, group2),
	I(DstAcc | SrcImmUByte | No64, em_aam),
	I(DstAcc | SrcImmUByte | No64, em_aad),
	I(DstAcc | ByteOp | No64, em_salc),
	I(DstAcc | SrcXLat | ByteOp, em_mov),
	/* 0xD8 - 0xDF */
	E(0, &escape_d8), E(0, &escape_d9), N, E(0, &escape_db), N, E(0, &escape_dd), N, N,
	/* 0xE0 - 0xE7 */
	X3(I(SrcImmByte | NearBranch | IsBranch, em_loop)),
	I(SrcImmByte | NearBranch | IsBranch, em_jcxz),
	I2bvIP(SrcImmUByte | DstAcc, em_in,  in,  check_perm_in),
	I2bvIP(SrcAcc | DstImmUByte, em_out, out, check_perm_out),
	/* 0xE8 - 0xEF */
	I(SrcImm | NearBranch | IsBranch | ShadowStack, em_call),
	D(SrcImm | ImplicitOps | NearBranch | IsBranch),
	I(SrcImmFAddr | No64 | IsBranch, em_jmp_far),
	D(SrcImmByte | ImplicitOps | NearBranch | IsBranch),
	I2bvIP(SrcDX | DstAcc, em_in,  in,  check_perm_in),
	I2bvIP(SrcAcc | DstDX, em_out, out, check_perm_out),
	/* 0xF0 - 0xF7 */
	N, DI(ImplicitOps, icebp), N, N,
	DI(ImplicitOps | Priv, hlt), D(ImplicitOps),
	G(ByteOp, group3), G(0, group3),
	/* 0xF8 - 0xFF */
	D(ImplicitOps), D(ImplicitOps),
	I(ImplicitOps, em_cli), I(ImplicitOps, em_sti),
	D(ImplicitOps), D(ImplicitOps), G(0, group4), G(0, group5),
};

static const struct opcode twobyte_table[256] = {
	/* 0x00 - 0x0F */
	G(0, group6), GD(0, &group7), N, N,
	N, I(ImplicitOps | EmulateOnUD | IsBranch | ShadowStack, em_syscall),
	II(ImplicitOps | Priv, em_clts, clts), N,
	DI(ImplicitOps | Priv, invd), DI(ImplicitOps | Priv, wbinvd), N, N,
	N, D(ImplicitOps | ModRM | SrcMem | NoAccess), N, N,
	/* 0x10 - 0x1F */
	GP(ModRM, &pfx_0f_10),
	GP(ModRM, &pfx_0f_11),
	GP(ModRM, &pfx_0f_12),
	GP(ModRM, &pfx_0f_13),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_14),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_15),
	GP(ModRM, &pfx_0f_16),
	GP(ModRM, &pfx_0f_17),
	D(ImplicitOps | ModRM | SrcMem | NoAccess), /* 4 * prefetch + 4 * reserved NOP */
	D(ImplicitOps | ModRM | SrcMem | NoAccess), N, N,
	D(ImplicitOps | ModRM | SrcMem | NoAccess), /* 8 * reserved NOP */
	D(ImplicitOps | ModRM | SrcMem | NoAccess), /* 8 * reserved NOP */
	D(ImplicitOps | ModRM | SrcMem | NoAccess), /* 8 * reserved NOP */
	D(ImplicitOps | ModRM | SrcMem | NoAccess), /* NOP + 7 * reserved NOP */
	/* 0x20 - 0x2F */
	DIP(ModRM | DstMem | Priv | Op3264 | NoMod, cr_read, check_cr_access),
	DIP(ModRM | DstMem | Priv | Op3264 | NoMod, dr_read, check_dr_read),
	IIP(ModRM | SrcMem | Priv | Op3264 | NoMod, em_cr_write, cr_write,
						check_cr_access),
	IIP(ModRM | SrcMem | Priv | Op3264 | NoMod, em_dr_write, dr_write,
						check_dr_write),
	N, N, N, N,
	GP(ModRM | DstReg | SrcMem | Mov | Sse | Avx, &pfx_0f_28_0f_29),
	GP(ModRM | DstMem | SrcReg | Mov | Sse | Avx, &pfx_0f_28_0f_29),
	GP(ModRM | No16, &pfx_0f_2a),
	GP(ModRM | DstMem | SrcReg | Mov | Sse | Avx, &pfx_0f_2b),
	GP(ModRM | No16, &pfx_0f_2c),
	GP(ModRM | No16, &pfx_0f_2d),
	GP(ModRM, &pfx_0f_2e),
	GP(ModRM, &pfx_0f_2f),
	/* 0x30 - 0x3F */
	II(ImplicitOps | Priv, em_wrmsr, wrmsr),
	IIP(ImplicitOps, em_rdtsc, rdtsc, check_rdtsc),
	II(ImplicitOps | Priv, em_rdmsr, rdmsr),
	IIP(ImplicitOps, em_rdpmc, rdpmc, check_rdpmc),
	I(ImplicitOps | EmulateOnUD | IsBranch | ShadowStack, em_sysenter),
	I(ImplicitOps | Priv | EmulateOnUD | IsBranch | ShadowStack, em_sysexit),
	N, N,
	N, N, N, N, N, N, N, N,
	/* 0x40 - 0x4F */
	X16(D(DstReg | SrcMem | ModRM)),
	/* 0x50 - 0x5F */
	GP(ModRM, &pfx_0f_50),
	GP(ModRM, &pfx_0f_51), GP(ModRM, &pfx_0f_52), GP(ModRM, &pfx_0f_53),
	GP(ModRM, &pfx_0f_54),
	GP(ModRM, &pfx_0f_55),
	GP(ModRM, &pfx_0f_56),
	GP(ModRM, &pfx_0f_57),
	GP(ModRM, &pfx_0f_58), GP(ModRM, &pfx_0f_59), GP(ModRM, &pfx_0f_5a), GP(ModRM, &pfx_0f_5b),
	GP(ModRM, &pfx_0f_5c), GP(ModRM, &pfx_0f_5d), GP(ModRM, &pfx_0f_5e), GP(ModRM, &pfx_0f_5f),
	/* 0x60 - 0x6F */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_60),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_61),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_62),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_63),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_64),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_65),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_66),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_67),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_68),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_69),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_6a),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_6b),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_6c),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_6d),
	GP(ModRM, &pfx_0f_6e), GP(SrcMem | DstReg | ModRM | Mov, &pfx_0f_6f_0f_7f),
	/* 0x70 - 0x7F */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_70), N, N,
	GP(ModRM, &pfx_0f_73),				/* PSRLDQ/PSLLDQ group */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_74),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_75),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_76), N,
	N, N, N, N,
	GP(ModRM | DstReg | SrcMem, &pfx_0f_7c),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_7d),
	GP(ModRM, &pfx_0f_7e), GP(SrcReg | DstMem | ModRM | Mov, &pfx_0f_6f_0f_7f),
	/* 0x80 - 0x8F */
	X16(D(SrcImm | NearBranch | IsBranch)),
	/* 0x90 - 0x9F */
	X16(D(ByteOp | DstMem | SrcNone | ModRM| Mov)),
	/* 0xA0 - 0xA7 */
	I(Stack | Src2FS, em_push_sreg), I(Stack | Src2FS, em_pop_sreg),
	II(ImplicitOps, em_cpuid, cpuid),
	I(DstMem | SrcReg | ModRM | BitOp | NoWrite, em_bt),
	I(DstMem | SrcReg | Src2ImmByte | ModRM, em_shld),
	I(DstMem | SrcReg | Src2CL | ModRM, em_shld), N, N,
	/* 0xA8 - 0xAF */
	I(Stack | Src2GS, em_push_sreg), I(Stack | Src2GS, em_pop_sreg),
	II(EmulateOnUD | ImplicitOps, em_rsm, rsm),
	I(DstMem | SrcReg | ModRM | BitOp | Lock | PageTable, em_bts),
	I(DstMem | SrcReg | Src2ImmByte | ModRM, em_shrd),
	I(DstMem | SrcReg | Src2CL | ModRM, em_shrd),
	GD(0, &group15), I(DstReg | SrcMem | ModRM, em_imul),
	/* 0xB0 - 0xB7 */
	I2bv(DstMem | SrcReg | ModRM | Lock | PageTable | SrcWrite, em_cmpxchg),
	I(DstReg | SrcMemFAddr | ModRM | Src2SS, em_lseg),
	I(DstMem | SrcReg | ModRM | BitOp | Lock, em_btr),
	I(DstReg | SrcMemFAddr | ModRM | Src2FS, em_lseg),
	I(DstReg | SrcMemFAddr | ModRM | Src2GS, em_lseg),
	D(DstReg | SrcMem8 | ModRM | Mov), D(DstReg | SrcMem16 | ModRM | Mov),
	/* 0xB8 - 0xBF */
	N, N,
	G(BitOp, group8),
	I(DstMem | SrcReg | ModRM | BitOp | Lock | PageTable, em_btc),
	I(DstReg | SrcMem | ModRM, em_bsf_c),
	I(DstReg | SrcMem | ModRM, em_bsr_c),
	D(DstReg | SrcMem8 | ModRM | Mov), D(DstReg | SrcMem16 | ModRM | Mov),
	/* 0xC0 - 0xC7 */
	I2bv(DstMem | SrcReg | ModRM | SrcWrite | Lock, em_xadd),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_c2), ID(0, &instr_dual_0f_c3),
	GP(ModRM, &pfx_0f_c4),					/* PINSRW */
	GP(ModRM, &pfx_0f_c5),					/* PEXTRW */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_c6), GD(0, &group9),
	/* 0xC8 - 0xCF */
	X8(I(DstReg, em_bswap)),
	/* 0xD0 - 0xDF */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_d0),		/* ADDSUBPD/PS */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_d1),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_d2),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_d3),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_d4),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_d5),
	GP(ModRM, &pfx_0f_d6),
	GP(ModRM, &pfx_0f_d7),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_d8),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_d9),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_da),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_db),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_dc),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_dd),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_de),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_df),
	/* 0xE0 - 0xEF */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_e0),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_e1),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_e2),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_e3),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_e4),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_e5),
	GP(ModRM, &pfx_0f_e6),
	GP(SrcReg | DstMem | ModRM | Mov, &pfx_0f_e7_0f_38_2a),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_e8),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_e9),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_ea),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_eb),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_ec),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_ed),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_ee),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_ef),
	/* 0xF0 - 0xFF */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_f0),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_f1),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_f2),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_f3),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_f4),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_f5),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_f6),
	N,
	GP(ModRM | DstReg | SrcMem, &pfx_0f_f8),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_f9),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_fa),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_fb),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_fc),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_fd),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_fe), N
};

static const struct instr_dual instr_dual_0f_38_f0 = {
	I(DstReg | SrcMem | Mov, em_movbe), N
};

static const struct instr_dual instr_dual_0f_38_f1 = {
	I(DstMem | SrcReg | Mov, em_movbe), N
};

static const struct gprefix three_byte_0f_38_f0 = {
	ID(0, &instr_dual_0f_38_f0), ID(0, &instr_dual_0f_38_f0), N, N
};

static const struct gprefix three_byte_0f_38_f1 = {
	ID(0, &instr_dual_0f_38_f1), ID(0, &instr_dual_0f_38_f1), N, N
};

/*
 * Insns below are selected by the prefix which indexed by the third opcode
 * byte.
 */
/* 0F 38 00: PSHUFB */
static const struct gprefix pfx_0f_38_00 = {
	N,
	I(Sse | Avx | Src2VexReg, em_pshufb),	/* 66: PSHUFB */
	N, N,
};

/* 0F 38 01: PHADDW */
static const struct gprefix pfx_0f_38_01 = {
	N,
	I(Sse | Avx | Src2VexReg, em_phaddw),	/* 66: PHADDW */
	N, N,
};

/* 0F 38 02: PHADDD */
static const struct gprefix pfx_0f_38_02 = {
	N,
	I(Sse | Avx | Src2VexReg, em_phaddd),	/* 66: PHADDD */
	N, N,
};

/* 0F 38 03: PHADDSW */
static const struct gprefix pfx_0f_38_03 = {
	N,
	I(Sse | Avx | Src2VexReg, em_phaddsw),	/* 66: PHADDSW */
	N, N,
};

/* 0F 38 05: PHSUBW */
static const struct gprefix pfx_0f_38_05 = {
	N,
	I(Sse | Avx | Src2VexReg, em_phsubw),	/* 66: PHSUBW */
	N, N,
};

/* 0F 38 06: PHSUBD */
static const struct gprefix pfx_0f_38_06 = {
	N,
	I(Sse | Avx | Src2VexReg, em_phsubd),	/* 66: PHSUBD */
	N, N,
};

/* 0F 38 07: PHSUBSW */
static const struct gprefix pfx_0f_38_07 = {
	N,
	I(Sse | Avx | Src2VexReg, em_phsubsw),	/* 66: PHSUBSW */
	N, N,
};

/* 0F 38 08: PSIGNB */
static const struct gprefix pfx_0f_38_08 = {
	N,
	I(Sse | Avx | Src2VexReg, em_psignb),	/* 66: PSIGNB */
	N, N,
};

/* 0F 38 09: PSIGNW */
static const struct gprefix pfx_0f_38_09 = {
	N,
	I(Sse | Avx | Src2VexReg, em_psignw),	/* 66: PSIGNW */
	N, N,
};

/* 0F 38 0A: PSIGND */
static const struct gprefix pfx_0f_38_0a = {
	N,
	I(Sse | Avx | Src2VexReg, em_psignd),	/* 66: PSIGND */
	N, N,
};

/* 0F 38 0B: PMULHRSW */
static const struct gprefix pfx_0f_38_0b = {
	N,
	I(Sse | Avx | Src2VexReg, em_pmulhrsw), /* 66: PMULHRSW */
	N, N,
};

/* 0F 38 17: PTEST */
static const struct gprefix pfx_0f_38_17 = {
	N,
	I(Sse | Avx, em_ptest),		/* 66: PTEST */
	N, N,
};

/* 0F 38 1C: PABSB */
static const struct gprefix pfx_0f_38_1c = {
	N,
	I(Sse | Avx, em_pabsb),		/* 66: PABSB */
	N, N,
};

/* 0F 38 1D: PABSW */
static const struct gprefix pfx_0f_38_1d = {
	N,
	I(Sse | Avx, em_pabsw),		/* 66: PABSW */
	N, N,
};

/* 0F 38 1E: PABSD */
static const struct gprefix pfx_0f_38_1e = {
	N,
	I(Sse | Avx, em_pabsd),		/* 66: PABSD */
	N, N,
};

/* 0F 38 20-25: PMOVSXBW/BD/BQ/WD/WQ/DQ */
static const struct gprefix pfx_0f_38_20 = {
	N, I(Sse | Avx, em_pmovsxbw), N, N,
};
static const struct gprefix pfx_0f_38_21 = {
	N, I(Sse | Avx, em_pmovsxbd), N, N,
};
static const struct gprefix pfx_0f_38_22 = {
	N, I(Sse | Avx, em_pmovsxbq), N, N,
};
static const struct gprefix pfx_0f_38_23 = {
	N, I(Sse | Avx, em_pmovsxwd), N, N,
};
static const struct gprefix pfx_0f_38_24 = {
	N, I(Sse | Avx, em_pmovsxwq), N, N,
};
static const struct gprefix pfx_0f_38_25 = {
	N, I(Sse | Avx, em_pmovsxdq), N, N,
};

/* 0F 38 28: PMULDQ */
static const struct gprefix pfx_0f_38_28 = {
	N,
	I(Sse | Avx | Src2VexReg, em_pmuldq),	/* 66: PMULDQ */
	N, N,
};

/* 0F 38 30-35: PMOVZXBW/BD/BQ/WD/WQ/DQ */
static const struct gprefix pfx_0f_38_30 = {
	N, I(Sse | Avx, em_pmovzxbw), N, N,
};
static const struct gprefix pfx_0f_38_31 = {
	N, I(Sse | Avx, em_pmovzxbd), N, N,
};
static const struct gprefix pfx_0f_38_32 = {
	N, I(Sse | Avx, em_pmovzxbq), N, N,
};
static const struct gprefix pfx_0f_38_33 = {
	N, I(Sse | Avx, em_pmovzxwd), N, N,
};
static const struct gprefix pfx_0f_38_34 = {
	N, I(Sse | Avx, em_pmovzxwq), N, N,
};
static const struct gprefix pfx_0f_38_35 = {
	N, I(Sse | Avx, em_pmovzxdq), N, N,
};

/* 0F 38 38: PMINSB */
static const struct gprefix pfx_0f_38_38 = {
	N,
	I(Sse | Avx | Src2VexReg, em_pminsb),	/* 66: PMINSB */
	N, N,
};

/* 0F 38 39: PMINSD */
static const struct gprefix pfx_0f_38_39 = {
	N,
	I(Sse | Avx | Src2VexReg, em_pminsd),	/* 66: PMINSD */
	N, N,
};

/* 0F 38 3A: PMINUW */
static const struct gprefix pfx_0f_38_3a = {
	N,
	I(Sse | Avx | Src2VexReg, em_pminuw),	/* 66: PMINUW */
	N, N,
};

/* 0F 38 3B: PMINUD xmm,xmm/m128 (66) / VPMINUD (VEX.66) */
static const struct gprefix pfx_0f_38_3b = {
	N,
	I(Sse | Avx | Src2VexReg, em_pminud),	/* 66: PMINUD/vPMINUD */
	N, N,
};

/* 0F 38 3C: PMAXSB */
static const struct gprefix pfx_0f_38_3c = {
	N,
	I(Sse | Avx | Src2VexReg, em_pmaxsb),	/* 66: PMAXSB */
	N, N,
};

/* 0F 38 3D: PMAXSD */
static const struct gprefix pfx_0f_38_3d = {
	N,
	I(Sse | Avx | Src2VexReg, em_pmaxsd),	/* 66: PMAXSD */
	N, N,
};

/* 0F 38 3E: PMAXUW */
static const struct gprefix pfx_0f_38_3e = {
	N,
	I(Sse | Avx | Src2VexReg, em_pmaxuw),	/* 66: PMAXUW */
	N, N,
};

/* 0F 38 04: PMADDUBSW */
static const struct gprefix pfx_0f_38_04 = {
	N,
	I(Sse | Avx | Src2VexReg, em_pmaddubsw), /* 66: PMADDUBSW */
	N, N,
};

/* 0F 38 10: PBLENDVB */
static const struct gprefix pfx_0f_38_10 = {
	N,
	I(Sse | Avx | Src2VexReg, em_pblendvb),	/* 66: PBLENDVB */
	N, N,
};

/* 0F 38 14: BLENDVPS */
static const struct gprefix pfx_0f_38_14 = {
	N,
	I(Sse | Avx | Src2VexReg, em_blendvps),	/* 66: BLENDVPS */
	N, N,
};

/* 0F 38 15: BLENDVPD */
static const struct gprefix pfx_0f_38_15 = {
	N,
	I(Sse | Avx | Src2VexReg, em_blendvpd),	/* 66: BLENDVPD */
	N, N,
};

/* 0F 38 29: PCMPEQQ */
static const struct gprefix pfx_0f_38_29 = {
	N,
	I(Sse | Avx | Src2VexReg, em_pcmpeqq),	/* 66: PCMPEQQ */
	N, N,
};

/* 0F 38 2B: PACKUSDW */
static const struct gprefix pfx_0f_38_2b = {
	N,
	I(Sse | Avx | Src2VexReg, em_packusdw),	/* 66: PACKUSDW */
	N, N,
};

/* 0F 38 37: PCMPGTQ */
static const struct gprefix pfx_0f_38_37 = {
	N,
	I(Sse | Avx | Src2VexReg, em_pcmpgtq),	/* 66: PCMPGTQ */
	N, N,
};

/* 0F 38 3F: PMAXUD */
static const struct gprefix pfx_0f_38_3f = {
	N,
	I(Sse | Avx | Src2VexReg, em_pmaxud),	/* 66: PMAXUD */
	N, N,
};

/* 0F 38 40: PMULLD */
static const struct gprefix pfx_0f_38_40 = {
	N,
	I(Sse | Avx | Src2VexReg, em_pmulld),	/* 66: PMULLD */
	N, N,
};

/* 0F 38 41: PHMINPOSUW */
static const struct gprefix pfx_0f_38_41 = {
	N,
	I(Sse | Avx, em_phminposuw),		/* 66: PHMINPOSUW */
	N, N,
};

/* 0F 38 DC-DF,DB: AES-NI */
static const struct gprefix pfx_0f_38_db = {
	N,
	I(Sse | Avx, em_aesimc),		/* 66: AESIMC */
	N, N,
};

static const struct gprefix pfx_0f_38_dc = {
	N,
	I(Sse | Avx | Src2VexReg, em_aesenc),	/* 66: AESENC */
	N, N,
};

static const struct gprefix pfx_0f_38_dd = {
	N,
	I(Sse | Avx | Src2VexReg, em_aesenclast), /* 66: AESENCLAST */
	N, N,
};

static const struct gprefix pfx_0f_38_de = {
	N,
	I(Sse | Avx | Src2VexReg, em_aesdec),	/* 66: AESDEC */
	N, N,
};

static const struct gprefix pfx_0f_38_df = {
	N,
	I(Sse | Avx | Src2VexReg, em_aesdeclast), /* 66: AESDECLAST */
	N, N,
};

static const struct opcode opcode_map_0f_38[256] = {
	/* 0x00 - 0x0f */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_38_00),	/* PSHUFB */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_38_01),	/* PHADDW */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_38_02),	/* PHADDD */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_38_03),	/* PHADDSW */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_38_04),	/* PMADDUBSW */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_38_05),	/* PHSUBW */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_38_06),	/* PHSUBD */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_38_07),	/* PHSUBSW */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_38_08),	/* PSIGNB */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_38_09),	/* PSIGNW */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_38_0a),	/* PSIGND */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_38_0b),	/* PMULHRSW */
	X4(N),
	/* 0x10 - 0x1f */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_38_10),	/* PBLENDVB */
	N, N, N,
	GP(ModRM | DstReg | SrcMem, &pfx_0f_38_14),	/* BLENDVPS */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_38_15),	/* BLENDVPD */
	N,
	GP(ModRM | DstReg | SrcMem, &pfx_0f_38_17),	/* PTEST */
	X4(N),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_38_1c),	/* PABSB */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_38_1d),	/* PABSW */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_38_1e),	/* PABSD */
	N,
	/* 0x20 - 0x2f */
	GP(ModRM, &pfx_0f_38_20),	/* PMOVSXBW (src=dst/2, own fetch) */
	GP(ModRM, &pfx_0f_38_21),	/* PMOVSXBD (src=dst/4, own fetch) */
	GP(ModRM, &pfx_0f_38_22),	/* PMOVSXBQ (src=dst/8, own fetch) */
	GP(ModRM, &pfx_0f_38_23),	/* PMOVSXWD (src=dst/2, own fetch) */
	GP(ModRM, &pfx_0f_38_24),	/* PMOVSXWQ (src=dst/4, own fetch) */
	GP(ModRM, &pfx_0f_38_25),	/* PMOVSXDQ (src=dst/2, own fetch) */
	N, N,
	GP(ModRM | DstReg | SrcMem, &pfx_0f_38_28),	/* PMULDQ */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_38_29),	/* PCMPEQQ */
	GP(SrcReg | DstMem | ModRM | Mov | Aligned, &pfx_0f_e7_0f_38_2a),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_38_2b),	/* PACKUSDW */
	N, N, N, N,
	/* 0x30 - 0x3f */
	GP(ModRM, &pfx_0f_38_30),	/* PMOVZXBW (src=dst/2, own fetch) */
	GP(ModRM, &pfx_0f_38_31),	/* PMOVZXBD (src=dst/4, own fetch) */
	GP(ModRM, &pfx_0f_38_32),	/* PMOVZXBQ (src=dst/8, own fetch) */
	GP(ModRM, &pfx_0f_38_33),	/* PMOVZXWD (src=dst/2, own fetch) */
	GP(ModRM, &pfx_0f_38_34),	/* PMOVZXWQ (src=dst/4, own fetch) */
	GP(ModRM, &pfx_0f_38_35),	/* PMOVZXDQ (src=dst/2, own fetch) */
	N,
	GP(ModRM | DstReg | SrcMem, &pfx_0f_38_37),	/* PCMPGTQ */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_38_38),	/* PMINSB */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_38_39),	/* PMINSD */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_38_3a),	/* PMINUW */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_38_3b),	/* PMINUD */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_38_3c),	/* PMAXSB */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_38_3d),	/* PMAXSD */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_38_3e),	/* PMAXUW */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_38_3f),	/* PMAXUD */
	/* 0x40 - 0x7f */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_38_40),	/* PMULLD */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_38_41),	/* PHMINPOSUW */
	X6(N), X8(N), X16(N), X16(N), X16(N),
	/* 0x80 - 0xbf */
	X16(N), X16(N), X16(N), X16(N),
	/* 0xc0 - 0xcf */
	X16(N),
	/* 0xd0 - 0xdf */
	X8(N), X3(N),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_38_db),	/* AESIMC */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_38_dc),	/* AESENC */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_38_dd),	/* AESENCLAST */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_38_de),	/* AESDEC */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_38_df),	/* AESDECLAST */
	/* 0xe0 - 0xef */
	X16(N),
	/* 0xf0 - 0xf1 */
	GP(EmulateOnUD | ModRM, &three_byte_0f_38_f0),
	GP(EmulateOnUD | ModRM, &three_byte_0f_38_f1),
	/* 0xf2 - 0xff */
	N, N, X4(N), X8(N)
};

/*
 * 0F 3A instruction table (three-byte opcodes with imm8)
 */
/* 0F 3A 08: ROUNDPS */
static const struct gprefix pfx_0f_3a_08 = {
	N,
	I(Sse | Avx, em_roundps),		/* 66: ROUNDPS */
	N, N,
};

/* 0F 3A 09: ROUNDPD */
static const struct gprefix pfx_0f_3a_09 = {
	N,
	I(Sse | Avx, em_roundpd),		/* 66: ROUNDPD */
	N, N,
};

/* 0F 3A 0A: ROUNDSS */
static const struct gprefix pfx_0f_3a_0a = {
	N,
	I(Sse | Avx | Src2VexReg, em_roundss),	/* 66: ROUNDSS */
	N, N,
};

/* 0F 3A 0B: ROUNDSD */
static const struct gprefix pfx_0f_3a_0b = {
	N,
	I(Sse | Avx | Src2VexReg, em_roundsd),	/* 66: ROUNDSD */
	N, N,
};

/* 0F 3A 0C: BLENDPS */
static const struct gprefix pfx_0f_3a_0c = {
	N,
	I(Sse | Avx | Src2VexReg, em_blendps),	/* 66: BLENDPS */
	N, N,
};

/* 0F 3A 0D: BLENDPD */
static const struct gprefix pfx_0f_3a_0d = {
	N,
	I(Sse | Avx | Src2VexReg, em_blendpd),	/* 66: BLENDPD */
	N, N,
};

/* 0F 3A 0E: PBLENDW */
static const struct gprefix pfx_0f_3a_0e = {
	N,
	I(Sse | Avx | Src2VexReg, em_pblendw),	/* 66: PBLENDW */
	N, N,
};

/* 0F 3A 0F: PALIGNR */
static const struct gprefix pfx_0f_3a_0f = {
	N,
	I(Sse | Avx | Src2VexReg, em_palignr),	/* 66: PALIGNR */
	N, N,
};

/* 0F 3A 14: PEXTRB */
static const struct gprefix pfx_0f_3a_14 = {
	N,
	I(Sse | Avx, em_pextrb),		/* 66: PEXTRB */
	N, N,
};

/* 0F 3A 16: PEXTRD */
static const struct gprefix pfx_0f_3a_16 = {
	N,
	I(Sse | Avx, em_pextrd),		/* 66: PEXTRD */
	N, N,
};

/* 0F 3A 20: PINSRB */
static const struct gprefix pfx_0f_3a_20 = {
	N,
	I(Sse | Avx | Src2VexReg, em_pinsrb),	/* 66: PINSRB */
	N, N,
};

/* 0F 3A 22: PINSRD */
static const struct gprefix pfx_0f_3a_22 = {
	N,
	I(Sse | Avx | Src2VexReg, em_pinsrd),	/* 66: PINSRD */
	N, N,
};

/* 0F 3A 44: PCLMULQDQ */
static const struct gprefix pfx_0f_3a_44 = {
	N,
	I(Sse | Avx | Src2VexReg, em_pclmulqdq),	/* 66: PCLMULQDQ */
	N, N,
};

/* 0F 3A 63: PCMPISTRI */
static const struct gprefix pfx_0f_3a_63 = {
	N,
	I(Sse | Avx, em_pcmpistri),		/* 66: PCMPISTRI */
	N, N,
};

/* 0F 3A 15: PEXTRW (memory form) */
static const struct gprefix pfx_0f_3a_15 = {
	N,
	I(Sse | Avx, em_pextrw_3a),		/* 66: PEXTRW */
	N, N,
};

/* 0F 3A 17: EXTRACTPS */
static const struct gprefix pfx_0f_3a_17 = {
	N,
	I(Sse | Avx, em_extractps),		/* 66: EXTRACTPS */
	N, N,
};

/* 0F 3A 21: INSERTPS */
static const struct gprefix pfx_0f_3a_21 = {
	N,
	I(Sse | Avx | Src2VexReg, em_insertps),	/* 66: INSERTPS */
	N, N,
};

/* 0F 3A 40: DPPS */
static const struct gprefix pfx_0f_3a_40 = {
	N,
	I(Sse | Avx | Src2VexReg, em_dpps),	/* 66: DPPS */
	N, N,
};

/* 0F 3A 41: DPPD */
static const struct gprefix pfx_0f_3a_41 = {
	N,
	I(Sse | Avx | Src2VexReg, em_dppd),	/* 66: DPPD */
	N, N,
};

/* 0F 3A 42: MPSADBW */
static const struct gprefix pfx_0f_3a_42 = {
	N,
	I(Sse | Avx | Src2VexReg, em_mpsadbw),	/* 66: MPSADBW */
	N, N,
};

/* 0F 3A 60: PCMPESTRM */
static const struct gprefix pfx_0f_3a_60 = {
	N,
	I(Sse | Avx, em_pcmpestrm),		/* 66: PCMPESTRM */
	N, N,
};

/* 0F 3A 61: PCMPESTRI */
static const struct gprefix pfx_0f_3a_61 = {
	N,
	I(Sse | Avx, em_pcmpestri),		/* 66: PCMPESTRI */
	N, N,
};

/* 0F 3A 62: PCMPISTRM */
static const struct gprefix pfx_0f_3a_62 = {
	N,
	I(Sse | Avx, em_pcmpistrm),		/* 66: PCMPISTRM */
	N, N,
};

/* 0F 3A DF: AESKEYGENASSIST */
static const struct gprefix pfx_0f_3a_df = {
	N,
	I(Sse | Avx, em_aeskeygenassist),	/* 66: AESKEYGENASSIST */
	N, N,
};

static const struct opcode opcode_map_0f_3a[256] = {
	/* 0x00 - 0x07 */
	X8(N),
	/* 0x08 - 0x0f */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_3a_08),	/* ROUNDPS */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_3a_09),	/* ROUNDPD */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_3a_0a),	/* ROUNDSS */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_3a_0b),	/* ROUNDSD */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_3a_0c),	/* BLENDPS */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_3a_0d),	/* BLENDPD */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_3a_0e),	/* PBLENDW */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_3a_0f),	/* PALIGNR */
	/* 0x10 - 0x1f */
	X4(N),
	GP(ModRM | DstMem | SrcReg, &pfx_0f_3a_14),	/* PEXTRB */
	GP(ModRM | DstMem | SrcReg, &pfx_0f_3a_15),	/* PEXTRW */
	GP(ModRM | DstMem | SrcReg, &pfx_0f_3a_16),	/* PEXTRD */
	GP(ModRM | DstMem | SrcReg, &pfx_0f_3a_17),	/* EXTRACTPS */
	X8(N),
	/* 0x20 - 0x2f */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_3a_20),	/* PINSRB */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_3a_21),	/* INSERTPS */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_3a_22),	/* PINSRD */
	N, X4(N), X8(N),
	/* 0x30 - 0x3f */
	X16(N),
	/* 0x40 - 0x4f */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_3a_40),	/* DPPS */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_3a_41),	/* DPPD */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_3a_42),	/* MPSADBW */
	N,
	GP(ModRM | DstReg | SrcMem, &pfx_0f_3a_44),	/* PCLMULQDQ */
	X3(N), X8(N),
	/* 0x50 - 0x5f */
	X16(N),
	/* 0x60 - 0x6f */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_3a_60),	/* PCMPESTRM */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_3a_61),	/* PCMPESTRI */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_3a_62),	/* PCMPISTRM */
	GP(ModRM | DstReg | SrcMem, &pfx_0f_3a_63),	/* PCMPISTRI */
	X4(N), X8(N),
	/* 0x70 - 0xdf */
	X16(N), X16(N), X16(N), X16(N), X16(N), X16(N),
	/* 0xd0 - 0xde */
	X8(N), X7(N),
	GP(ModRM | DstReg | SrcMem, &pfx_0f_3a_df),	/* 0xDF: AESKEYGENASSIST */
	/* 0xe0 - 0xff */
	X16(N), X16(N),
};

#undef D
#undef N
#undef G
#undef GD
#undef I
#undef GP
#undef EXT
#undef MD
#undef ID

#undef D2bv
#undef D2bvIP
#undef I2bv
#undef I2bvIP
#undef I6ALU

static bool is_shstk_instruction(struct x86_emulate_ctxt *ctxt)
{
	return ctxt->d & ShadowStack;
}

static bool is_ibt_instruction(struct x86_emulate_ctxt *ctxt)
{
	u64 flags = ctxt->d;

	if (!(flags & IsBranch))
		return false;

	/*
	 * All far JMPs and CALLs (including SYSCALL, SYSENTER, and INTn) are
	 * indirect and thus affect IBT state.  All far RETs (including SYSEXIT
	 * and IRET) are protected via Shadow Stacks and thus don't affect IBT
	 * state.  IRET #GPs when returning to virtual-8086 and IBT or SHSTK is
	 * enabled, but that should be handled by IRET emulation (in the very
	 * unlikely scenario that KVM adds support for fully emulating IRET).
	 */
	if (!(flags & NearBranch))
		return ctxt->execute != em_iret &&
		       ctxt->execute != em_ret_far &&
		       ctxt->execute != em_ret_far_imm &&
		       ctxt->execute != em_sysexit;

	switch (flags & SrcMask) {
	case SrcReg:
	case SrcMem:
	case SrcMem16:
	case SrcMem32:
		return true;
	case SrcMemFAddr:
	case SrcImmFAddr:
		/* Far branches should be handled above. */
		WARN_ON_ONCE(1);
		return true;
	case SrcNone:
	case SrcImm:
	case SrcImmByte:
	/*
	 * Note, ImmU16 is used only for the stack adjustment operand on ENTER
	 * and RET instructions.  ENTER isn't a branch and RET FAR is handled
	 * by the NearBranch check above.  RET itself isn't an indirect branch.
	 */
	case SrcImmU16:
		return false;
	default:
		WARN_ONCE(1, "Unexpected Src operand '%llx' on branch",
			  flags & SrcMask);
		return false;
	}
}

static unsigned imm_size(struct x86_emulate_ctxt *ctxt)
{
	unsigned size;

	size = (ctxt->d & ByteOp) ? 1 : ctxt->op_bytes;
	if (size == 8)
		size = 4;
	return size;
}

static int decode_imm(struct x86_emulate_ctxt *ctxt, struct operand *op,
		      unsigned size, bool sign_extension)
{
	int rc = X86EMUL_CONTINUE;

	op->type = OP_IMM;
	op->bytes = size;
	op->addr.mem.ea = ctxt->_eip;
	/* NB. Immediates are sign-extended as necessary. */
	switch (op->bytes) {
	case 1:
		op->val = insn_fetch(s8, ctxt);
		break;
	case 2:
		op->val = insn_fetch(s16, ctxt);
		break;
	case 4:
		op->val = insn_fetch(s32, ctxt);
		break;
	case 8:
		op->val = insn_fetch(s64, ctxt);
		break;
	}
	if (!sign_extension) {
		switch (op->bytes) {
		case 1:
			op->val &= 0xff;
			break;
		case 2:
			op->val &= 0xffff;
			break;
		case 4:
			op->val &= 0xffffffff;
			break;
		}
	}
done:
	return rc;
}

static int decode_operand(struct x86_emulate_ctxt *ctxt, struct operand *op,
			  unsigned d)
{
	int rc = X86EMUL_CONTINUE;

	switch (d) {
	case OpReg:
		decode_register_operand(ctxt, op);
		break;
	case OpVexReg:
		if (!(ctxt->d & Avx)) {
			op->type = OP_NONE;
			break;
		}
		__decode_register_operand(ctxt, op, ctxt->vex_reg);
		break;
	case OpImmUByte:
		rc = decode_imm(ctxt, op, 1, false);
		break;
	case OpMem:
		ctxt->memop.bytes = (ctxt->d & ByteOp) ? 1 : ctxt->op_bytes;
	mem_common:
		*op = ctxt->memop;
		ctxt->memopp = op;
		if (ctxt->d & BitOp)
			fetch_bit_operand(ctxt);
		op->orig_val = op->val;
		break;
	case OpMem64:
		ctxt->memop.bytes = (ctxt->op_bytes == 8) ? 16 : 8;
		goto mem_common;
	case OpAcc:
		op->type = OP_REG;
		op->bytes = (ctxt->d & ByteOp) ? 1 : ctxt->op_bytes;
		op->addr.reg = reg_rmw(ctxt, VCPU_REGS_RAX);
		fetch_register_operand(op);
		break;
	case OpAccLo:
		op->type = OP_REG;
		op->bytes = (ctxt->d & ByteOp) ? 2 : ctxt->op_bytes;
		op->addr.reg = reg_rmw(ctxt, VCPU_REGS_RAX);
		fetch_register_operand(op);
		break;
	case OpAccHi:
		if (ctxt->d & ByteOp) {
			op->type = OP_NONE;
			break;
		}
		op->type = OP_REG;
		op->bytes = ctxt->op_bytes;
		op->addr.reg = reg_rmw(ctxt, VCPU_REGS_RDX);
		fetch_register_operand(op);
		break;
	case OpDI:
		op->type = OP_MEM;
		op->bytes = (ctxt->d & ByteOp) ? 1 : ctxt->op_bytes;
		op->addr.mem.ea =
			register_address(ctxt, VCPU_REGS_RDI);
		op->addr.mem.seg = VCPU_SREG_ES;
		op->val = 0;
		op->count = 1;
		break;
	case OpDX:
		op->type = OP_REG;
		op->bytes = 2;
		op->addr.reg = reg_rmw(ctxt, VCPU_REGS_RDX);
		fetch_register_operand(op);
		break;
	case OpCL:
		op->type = OP_IMM;
		op->bytes = 1;
		op->val = reg_read(ctxt, VCPU_REGS_RCX) & 0xff;
		break;
	case OpImmByte:
		rc = decode_imm(ctxt, op, 1, true);
		break;
	case OpOne:
		op->type = OP_IMM;
		op->bytes = 1;
		op->val = 1;
		break;
	case OpImm:
		rc = decode_imm(ctxt, op, imm_size(ctxt), true);
		break;
	case OpImm64:
		rc = decode_imm(ctxt, op, ctxt->op_bytes, true);
		break;
	case OpMem8:
		ctxt->memop.bytes = 1;
		if (ctxt->memop.type == OP_REG) {
			ctxt->memop.addr.reg = decode_register(ctxt,
					ctxt->modrm_rm, true);
			fetch_register_operand(&ctxt->memop);
		}
		goto mem_common;
	case OpMem16:
		ctxt->memop.bytes = 2;
		goto mem_common;
	case OpMem32:
		ctxt->memop.bytes = 4;
		goto mem_common;
	case OpImmU16:
		rc = decode_imm(ctxt, op, 2, false);
		break;
	case OpImmU:
		rc = decode_imm(ctxt, op, imm_size(ctxt), false);
		break;
	case OpSI:
		op->type = OP_MEM;
		op->bytes = (ctxt->d & ByteOp) ? 1 : ctxt->op_bytes;
		op->addr.mem.ea =
			register_address(ctxt, VCPU_REGS_RSI);
		op->addr.mem.seg = ctxt->seg_override;
		op->val = 0;
		op->count = 1;
		break;
	case OpXLat:
		op->type = OP_MEM;
		op->bytes = (ctxt->d & ByteOp) ? 1 : ctxt->op_bytes;
		op->addr.mem.ea =
			address_mask(ctxt,
				reg_read(ctxt, VCPU_REGS_RBX) +
				(reg_read(ctxt, VCPU_REGS_RAX) & 0xff));
		op->addr.mem.seg = ctxt->seg_override;
		op->val = 0;
		break;
	case OpImmFAddr:
		op->type = OP_IMM;
		op->addr.mem.ea = ctxt->_eip;
		op->bytes = ctxt->op_bytes + 2;
		insn_fetch_arr(op->valptr, op->bytes, ctxt);
		break;
	case OpMemFAddr:
		ctxt->memop.bytes = ctxt->op_bytes + 2;
		goto mem_common;
	case OpES:
		op->type = OP_IMM;
		op->val = VCPU_SREG_ES;
		break;
	case OpCS:
		op->type = OP_IMM;
		op->val = VCPU_SREG_CS;
		break;
	case OpSS:
		op->type = OP_IMM;
		op->val = VCPU_SREG_SS;
		break;
	case OpDS:
		op->type = OP_IMM;
		op->val = VCPU_SREG_DS;
		break;
	case OpFS:
		op->type = OP_IMM;
		op->val = VCPU_SREG_FS;
		break;
	case OpGS:
		op->type = OP_IMM;
		op->val = VCPU_SREG_GS;
		break;
	case OpImplicit:
		/* Special instructions do their own operand decoding. */
	default:
		op->type = OP_NONE; /* Disable writeback. */
		break;
	}

done:
	return rc;
}

static bool vex_uses_vvvv(u8 map, u8 pp, u8 opcode)
{
	if (map == 2) {
		/* 0F 38 map */
		switch (opcode) {
		case 0x00:	/* VPSHUFB */
		case 0x01:	/* VPHADDW */
		case 0x02:	/* VPHADDD */
		case 0x03:	/* VPHADDSW */
		case 0x05:	/* VPHSUBW */
		case 0x06:	/* VPHSUBD */
		case 0x07:	/* VPHSUBSW */
		case 0x08:	/* VPSIGNB */
		case 0x09:	/* VPSIGNW */
		case 0x0a:	/* VPSIGND */
		case 0x0b:	/* VPMULHRSW */
		case 0x04:	/* VPMADDUBSW */
		case 0x10:	/* VPBLENDVB */
		case 0x14:	/* VBLENDVPS */
		case 0x15:	/* VBLENDVPD */
		case 0x28:	/* VPMULDQ */
		case 0x29:	/* VPCMPEQQ */
		case 0x2b:	/* VPACKUSDW */
		case 0x37:	/* VPCMPGTQ */
		case 0x3f:	/* VPMAXUD */
		case 0x40:	/* VPMULLD */
		case 0x38:	/* VPMINSB */
		case 0x39:	/* VPMINSD */
		case 0x3a:	/* VPMINUW */
		case 0x3b:	/* VPMINUD */
		case 0x3c:	/* VPMAXSB */
		case 0x3d:	/* VPMAXSD */
		case 0x3e:	/* VPMAXUW */
		case 0xdc:	/* VAESENC */
		case 0xdd:	/* VAESENCLAST */
		case 0xde:	/* VAESDEC */
		case 0xdf:	/* VAESDECLAST */
			return pp == 1;
		default:
			return false;
		}
	}

	if (map == 3) {
		/* 0F 3A map */
		switch (opcode) {
		case 0x0a:	/* VROUNDSS */
		case 0x0b:	/* VROUNDSD */
		case 0x0c:	/* VBLENDPS */
		case 0x0d:	/* VBLENDPD */
		case 0x0e:	/* VPBLENDW */
		case 0x0f:	/* VPALIGNR */
		case 0x20:	/* VPINSRB */
		case 0x21:	/* VINSERTPS */
		case 0x22:	/* VPINSRD */
		case 0x40:	/* VDPPS */
		case 0x41:	/* VDPPD */
		case 0x42:	/* VMPSADBW */
		case 0x44:	/* VPCLMULQDQ */
			return pp == 1;
		default:
			return false;
		}
	}

	if (map != 1)
		return false;

	switch (opcode) {
	case 0x10:
	case 0x11:
		return pp == 2 || pp == 3;
	case 0x12:
	case 0x16:
		return pp == 0 || pp == 1;
	case 0x14:	/* VUNPCKLPS / VUNPCKLPD */
	case 0x15:	/* VUNPCKHPS / VUNPCKHPD */
		return pp == 0 || pp == 1;
	case 0x2a:
		return pp == 2 || pp == 3;
	case 0x51:	/* VSQRTSS / VSQRTSD (VEX.vvvv for scalar only) */
		return pp == 2 || pp == 3;
	case 0x54:	/* VANDPS / VANDPD */
	case 0x55:	/* VANDNPS / VANDNPD */
	case 0x56:	/* VORPS / VORPD */
	case 0x57:	/* VXORPS / VXORPD */
		return pp == 0 || pp == 1;
	case 0x58:	/* VADDPS/PD/SS/SD */
	case 0x59:	/* VMULPS/PD/SS/SD */
	case 0x5c:	/* VSUBPS/PD/SS/SD */
	case 0x5d:	/* VMINPS/PD/SS/SD */
	case 0x5e:	/* VDIVPS/PD/SS/SD */
	case 0x5f:	/* VMAXPS/PD/SS/SD */
		return true;
	case 0x5a:	/* VCVTSS2SD / VCVTSD2SS */
		return pp == 2 || pp == 3;
	case 0x60:	/* VPUNPCKLBW */
	case 0x61:	/* VPUNPCKLWD */
	case 0x62:	/* VPUNPCKLDQ */
	case 0x63:	/* VPACKSSWB */
	case 0x64:	/* VPCMPGTB */
	case 0x65:	/* VPCMPGTW */
	case 0x66:	/* VPCMPGTD */
	case 0x67:	/* VPACKUSWB */
	case 0x68:	/* VPUNPCKHBW */
	case 0x69:	/* VPUNPCKHWD */
	case 0x6a:	/* VPUNPCKHDQ */
	case 0x6b:	/* VPACKSSDW */
	case 0x6c:	/* VPUNPCKLQDQ */
	case 0x6d:	/* VPUNPCKHQDQ */
		return pp == 1;
	case 0x74:	/* VPCMPEQB */
	case 0x75:	/* VPCMPEQW */
	case 0x76:	/* VPCMPEQD */
		return pp == 1;
	case 0x7c:	/* VHADDPD (66) / VHADDPS (F2) */
	case 0x7d:	/* VHSUBPD (66) / VHSUBPS (F2) */
		return pp == 1 || pp == 3;
	case 0xc2:	/* VCMPPS/PD/SS/SD */
		return true;
	case 0xc4:	/* VPINSRW */
		return pp == 1;
	case 0xc6:	/* VSHUFPS / VSHUFPD */
		return pp == 0 || pp == 1;
	case 0xd0:	/* VADDSUBPD (66) / VADDSUBPS (F2) */
		return pp == 1 || pp == 3;
	case 0xd1:	/* VPSRLW */
	case 0xd2:	/* VPSRLD */
	case 0xd3:	/* VPSRLQ */
	case 0xd4:	/* VPADDQ */
	case 0xd5:	/* VPMULLW */
	case 0xd8:	/* VPSUBUSB */
	case 0xd9:	/* VPSUBUSW */
	case 0xda:	/* VPMINUB */
	case 0xdb:	/* VPAND */
	case 0xdc:	/* VPADDUSB */
	case 0xdd:	/* VPADDUSW */
	case 0xde:	/* VPMAXUB */
	case 0xdf:	/* VPANDN */
	case 0xe0:	/* VPAVGB */
	case 0xe1:	/* VPSRAW */
	case 0xe2:	/* VPSRAD */
	case 0xe3:	/* VPAVGW */
	case 0xe4:	/* VPMULHUW */
	case 0xe5:	/* VPMULHW */
	case 0xe8:	/* VPSUBSB */
	case 0xe9:	/* VPSUBSW */
	case 0xea:	/* VPMINSW */
	case 0xeb:	/* VPOR */
	case 0xec:	/* VPADDSB */
	case 0xed:	/* VPADDSW */
	case 0xee:	/* VPMAXSW */
	case 0xef:	/* VPXOR */
	case 0xf1:	/* VPSLLW */
	case 0xf2:	/* VPSLLD */
	case 0xf3:	/* VPSLLQ */
	case 0xf4:	/* VPMULUDQ */
	case 0xf5:	/* VPMADDWD */
	case 0xf6:	/* VPSADBW */
	case 0xf8:	/* VPSUBB */
	case 0xf9:	/* VPSUBW */
	case 0xfa:	/* VPSUBD */
	case 0xfb:	/* VPSUBQ */
	case 0xfc:	/* VPADDB */
	case 0xfd:	/* VPADDW */
	case 0xfe:	/* VPADDD */
		return pp == 1;
	default:
		return false;
	}
}

static bool vex_128_only(u8 map, u8 pp, u8 opcode)
{
	if (map == 2) {
		/* 0F 38 map: AES-NI and PHMINPOSUW are 128-bit only */
		switch (opcode) {
		case 0x41:	/* VPHMINPOSUW */
		case 0xdb:	/* VAESIMC */
		case 0xdc:	/* VAESENC */
		case 0xdd:	/* VAESENCLAST */
		case 0xde:	/* VAESDEC */
		case 0xdf:	/* VAESDECLAST */
			return pp == 1;
		default:
			return false;
		}
	}

	if (map == 3) {
		/* 0F 3A map */
		switch (opcode) {
		case 0x21:	/* VINSERTPS */
		case 0x41:	/* VDPPD */
		case 0x44:	/* VPCLMULQDQ */
		case 0x60:	/* VPCMPESTRM */
		case 0x61:	/* VPCMPESTRI */
		case 0x62:	/* VPCMPISTRM */
		case 0x63:	/* VPCMPISTRI */
		case 0xdf:	/* VAESKEYGENASSIST */
			return pp == 1;
		default:
			return false;
		}
	}

	if (map != 1)
		return false;

	switch (opcode) {
	case 0x10:
	case 0x11:
		return pp == 2 || pp == 3;
	case 0x12:
	case 0x16:
		return pp == 0 || pp == 1;
	case 0x2a:
		return pp == 2 || pp == 3;
	case 0x2c:
	case 0x2d:
		return pp == 2 || pp == 3;
	case 0x2e:
	case 0x2f:
		return pp == 0 || pp == 1;
	case 0x51:
		return pp == 2 || pp == 3;
	case 0x6e:
		return pp == 1;
	case 0xd6:
		return pp == 1;
	case 0x7e:
		return pp == 1 || pp == 2;
	default:
		return false;
	}
}

static int x86_decode_avx(struct x86_emulate_ctxt *ctxt,
			  u8 vex_1st, u8 vex_2nd, struct opcode *opcode)
{
	u8 vex_3rd, map, pp, l, v;
	int rc = X86EMUL_CONTINUE;

	if (ctxt->rep_prefix || ctxt->op_prefix || ctxt->rex_prefix)
		goto ud;

	if (vex_1st == 0xc5) {
		/* Expand RVVVVlpp to VEX3 format */
		vex_3rd = vex_2nd & ~0x80;         /* VVVVlpp from VEX2, w=0 */
		vex_2nd = (vex_2nd & 0x80) | 0x61; /* R from VEX2, X=1 B=1 mmmmm=00001 */
	} else {
		vex_3rd = insn_fetch(u8, ctxt);
	}

	/* vex_2nd = RXBmmmmm, vex_3rd = wVVVVlpp.  Fix polarity */
	vex_2nd ^= 0xE0; /* binary 11100000 */
	vex_3rd ^= 0x78; /* binary 01111000 */

	ctxt->rex_prefix = REX_PREFIX;
	ctxt->rex_bits = (vex_2nd & 0xE0) >> 5; /* RXB */
	ctxt->rex_bits |= (vex_3rd & 0x80) >> 4; /* w */
	if (ctxt->rex_bits && ctxt->mode != X86EMUL_MODE_PROT64)
		goto ud;

	map = vex_2nd & 0x1f;
	v = (vex_3rd >> 3) & 0xf;
	l = vex_3rd & 0x4;
	pp = vex_3rd & 0x3;
	ctxt->vex_reg = v;

	ctxt->b = insn_fetch(u8, ctxt);
	switch (map) {
	case 1:
		ctxt->opcode_len = 2;
		*opcode = twobyte_table[ctxt->b];
		break;
	case 2:
		ctxt->opcode_len = 3;
		*opcode = opcode_map_0f_38[ctxt->b];
		break;
	case 3:
		ctxt->opcode_len = 3;
		*opcode = opcode_map_0f_3a[ctxt->b];
		break;
	default:
		goto ud;
	}

	if (v && !vex_uses_vvvv(map, pp, ctxt->b))
		goto ud;

	if (l && vex_128_only(map, pp, ctxt->b))
		goto ud;

	if (l)
		ctxt->op_bytes = 32;
	else
		ctxt->op_bytes = 16;

	switch (pp) {
	case 0: break;
	case 1: ctxt->op_prefix = true; break;
	case 2: ctxt->rep_prefix = 0xf3; break;
	case 3: ctxt->rep_prefix = 0xf2; break;
	}

done:
	return rc;
ud:
	*opcode = ud;
	return rc;
}

int x86_decode_insn(struct x86_emulate_ctxt *ctxt, void *insn, int insn_len, int emulation_type)
{
	int rc = X86EMUL_CONTINUE;
	int mode = ctxt->mode;
	int def_op_bytes, def_ad_bytes, goffset, simd_prefix;
	bool vex_prefix = false;
	bool has_seg_override = false;
	struct opcode opcode;
	u16 dummy;
	struct desc_struct desc;

	ctxt->memop.type = OP_NONE;
	ctxt->memopp = NULL;
	ctxt->_eip = ctxt->eip;
	ctxt->fetch.ptr = ctxt->fetch.data;
	ctxt->fetch.end = ctxt->fetch.data + insn_len;
	ctxt->opcode_len = 1;
	ctxt->intercept = x86_intercept_none;
	if (insn_len > 0)
		memcpy(ctxt->fetch.data, insn, insn_len);
	else {
		rc = __do_insn_fetch_bytes(ctxt, 1);
		if (rc != X86EMUL_CONTINUE)
			goto done;
	}

	switch (mode) {
	case X86EMUL_MODE_REAL:
	case X86EMUL_MODE_VM86:
		def_op_bytes = def_ad_bytes = 2;
		ctxt->ops->get_segment(ctxt, &dummy, &desc, NULL, VCPU_SREG_CS);
		if (desc.d)
			def_op_bytes = def_ad_bytes = 4;
		break;
	case X86EMUL_MODE_PROT16:
		def_op_bytes = def_ad_bytes = 2;
		break;
	case X86EMUL_MODE_PROT32:
		def_op_bytes = def_ad_bytes = 4;
		break;
#ifdef CONFIG_X86_64
	case X86EMUL_MODE_PROT64:
		def_op_bytes = 4;
		def_ad_bytes = 8;
		break;
#endif
	default:
		return EMULATION_FAILED;
	}

	ctxt->op_bytes = def_op_bytes;
	ctxt->ad_bytes = def_ad_bytes;

	/* Legacy prefixes. */
	for (;;) {
		switch (ctxt->b = insn_fetch(u8, ctxt)) {
		case 0x66:	/* operand-size override */
			ctxt->op_prefix = true;
			/* switch between 2/4 bytes */
			ctxt->op_bytes = def_op_bytes ^ 6;
			break;
		case 0x67:	/* address-size override */
			if (mode == X86EMUL_MODE_PROT64)
				/* switch between 4/8 bytes */
				ctxt->ad_bytes = def_ad_bytes ^ 12;
			else
				/* switch between 2/4 bytes */
				ctxt->ad_bytes = def_ad_bytes ^ 6;
			break;
		case 0x26:	/* ES override */
			has_seg_override = true;
			ctxt->seg_override = VCPU_SREG_ES;
			break;
		case 0x2e:	/* CS override */
			has_seg_override = true;
			ctxt->seg_override = VCPU_SREG_CS;
			break;
		case 0x36:	/* SS override */
			has_seg_override = true;
			ctxt->seg_override = VCPU_SREG_SS;
			break;
		case 0x3e:	/* DS override */
			has_seg_override = true;
			ctxt->seg_override = VCPU_SREG_DS;
			break;
		case 0x64:	/* FS override */
			has_seg_override = true;
			ctxt->seg_override = VCPU_SREG_FS;
			break;
		case 0x65:	/* GS override */
			has_seg_override = true;
			ctxt->seg_override = VCPU_SREG_GS;
			break;
		case 0x40 ... 0x4f: /* REX */
			if (mode != X86EMUL_MODE_PROT64)
				goto done_prefixes;
			ctxt->rex_prefix = REX_PREFIX;
			ctxt->rex_bits   = ctxt->b & 0xf;
			continue;
		case 0xf0:	/* LOCK */
			ctxt->lock_prefix = 1;
			break;
		case 0xf2:	/* REPNE/REPNZ */
		case 0xf3:	/* REP/REPE/REPZ */
			ctxt->rep_prefix = ctxt->b;
			break;
		default:
			goto done_prefixes;
		}

		/* Any legacy prefix after a REX prefix nullifies its effect. */
		ctxt->rex_prefix = REX_NONE;
		ctxt->rex_bits = 0;
	}

done_prefixes:

	/* REX prefix. */
	if (ctxt->rex_bits & REX_W)
		ctxt->op_bytes = 8;

	/* Opcode byte(s). */
	if (ctxt->b == 0xc4 || ctxt->b == 0xc5) {
		/* VEX or LDS/LES */
		u8 vex_2nd = insn_fetch(u8, ctxt);
		if (mode != X86EMUL_MODE_PROT64 && (vex_2nd & 0xc0) != 0xc0) {
			opcode = opcode_table[ctxt->b];
			ctxt->modrm = vex_2nd;
			/* the Mod/RM byte has been fetched already!  */
			goto done_modrm;
		}

		vex_prefix = true;
		rc = x86_decode_avx(ctxt, ctxt->b, vex_2nd, &opcode);
		if (rc != X86EMUL_CONTINUE)
			goto done;
	} else if (ctxt->b == 0x0f) {
		/* Two- or three-byte opcode */
		ctxt->opcode_len = 2;
		ctxt->b = insn_fetch(u8, ctxt);
		opcode = twobyte_table[ctxt->b];

		/* 0F_38 opcode map */
		if (ctxt->b == 0x38) {
			ctxt->opcode_len = 3;
			ctxt->b = insn_fetch(u8, ctxt);
			opcode = opcode_map_0f_38[ctxt->b];
		}

		/* 0F_3A opcode map */
		if (ctxt->b == 0x3a) {
			ctxt->opcode_len = 3;
			ctxt->b = insn_fetch(u8, ctxt);
			opcode = opcode_map_0f_3a[ctxt->b];
		}
	} else {
		/* Opcode byte(s). */
		opcode = opcode_table[ctxt->b];
	}

	if (opcode.flags & ModRM)
		ctxt->modrm = insn_fetch(u8, ctxt);

done_modrm:
	ctxt->d = opcode.flags;
	while (ctxt->d & GroupMask) {
		switch (ctxt->d & GroupMask) {
		case Group:
			goffset = (ctxt->modrm >> 3) & 7;
			opcode = opcode.u.group[goffset];
			break;
		case GroupDual:
			goffset = (ctxt->modrm >> 3) & 7;
			if ((ctxt->modrm >> 6) == 3)
				opcode = opcode.u.gdual->mod3[goffset];
			else
				opcode = opcode.u.gdual->mod012[goffset];
			break;
		case RMExt:
			goffset = ctxt->modrm & 7;
			opcode = opcode.u.group[goffset];
			break;
		case Prefix:
			if (ctxt->rep_prefix && ctxt->op_prefix)
				return EMULATION_FAILED;
			simd_prefix = ctxt->op_prefix ? 0x66 : ctxt->rep_prefix;
			switch (simd_prefix) {
			case 0x00: opcode = opcode.u.gprefix->pfx_no; break;
			case 0x66: opcode = opcode.u.gprefix->pfx_66; break;
			case 0xf2: opcode = opcode.u.gprefix->pfx_f2; break;
			case 0xf3: opcode = opcode.u.gprefix->pfx_f3; break;
			}
			break;
		case Escape:
			if (ctxt->modrm > 0xbf) {
				size_t size = ARRAY_SIZE(opcode.u.esc->high);
				u32 index = array_index_nospec(
					ctxt->modrm - 0xc0, size);

				opcode = opcode.u.esc->high[index];
			} else {
				opcode = opcode.u.esc->op[(ctxt->modrm >> 3) & 7];
			}
			break;
		case InstrDual:
			if ((ctxt->modrm >> 6) == 3)
				opcode = opcode.u.idual->mod3;
			else
				opcode = opcode.u.idual->mod012;
			break;
		case ModeDual:
			if (ctxt->mode == X86EMUL_MODE_PROT64)
				opcode = opcode.u.mdual->mode64;
			else
				opcode = opcode.u.mdual->mode32;
			break;
		default:
			return EMULATION_FAILED;
		}

		ctxt->d &= ~(u64)GroupMask;
		ctxt->d |= opcode.flags;
	}

	ctxt->is_branch = opcode.flags & IsBranch;

	/* Unrecognised? */
	if (ctxt->d == 0)
		return EMULATION_FAILED;

	if (unlikely(vex_prefix)) {
		/*
		 * Only specifically marked instructions support VEX.  Since many
		 * instructions support it but are not annotated, return not implemented
		 * rather than #UD.
		 */
		if (!(ctxt->d & Avx))
			return EMULATION_FAILED;

		if (!(ctxt->d & AlignMask))
			ctxt->d |= Unaligned;
	} else {
		ctxt->d &= ~Avx;
	}

	ctxt->execute = opcode.u.execute;

	/*
	 * Reject emulation if KVM might need to emulate shadow stack updates
	 * and/or indirect branch tracking enforcement, which the emulator
	 * doesn't support.
	 */
	if ((is_ibt_instruction(ctxt) || is_shstk_instruction(ctxt)) &&
	    ctxt->ops->get_cr(ctxt, 4) & X86_CR4_CET) {
		u64 u_cet = 0, s_cet = 0;

		/*
		 * Check both User and Supervisor on far transfers as inter-
		 * privilege level transfers are impacted by CET at the target
		 * privilege level, and that is not known at this time.  The
		 * expectation is that the guest will not require emulation of
		 * any CET-affected instructions at any privilege level.
		 */
		if (!(ctxt->d & NearBranch))
			u_cet = s_cet = CET_SHSTK_EN | CET_ENDBR_EN;
		else if (ctxt->ops->cpl(ctxt) == 3)
			u_cet = CET_SHSTK_EN | CET_ENDBR_EN;
		else
			s_cet = CET_SHSTK_EN | CET_ENDBR_EN;

		if ((u_cet && ctxt->ops->get_msr(ctxt, MSR_IA32_U_CET, &u_cet)) ||
		    (s_cet && ctxt->ops->get_msr(ctxt, MSR_IA32_S_CET, &s_cet)))
			return EMULATION_FAILED;

		if ((u_cet | s_cet) & CET_SHSTK_EN && is_shstk_instruction(ctxt))
			return EMULATION_FAILED;

		if ((u_cet | s_cet) & CET_ENDBR_EN && is_ibt_instruction(ctxt))
			return EMULATION_FAILED;
	}

	if (unlikely(emulation_type & EMULTYPE_TRAP_UD) &&
	    likely(!(ctxt->d & EmulateOnUD)))
		return EMULATION_FAILED;

	if (unlikely(ctxt->d &
	    (NotImpl|Stack|Op3264|Sse|Mmx|Intercept|CheckPerm|NearBranch|
	     No16))) {
		/*
		 * These are copied unconditionally here, and checked unconditionally
		 * in x86_emulate_insn.
		 */
		ctxt->check_perm = opcode.check_perm;
		ctxt->intercept = opcode.intercept;

		if (ctxt->d & NotImpl)
			return EMULATION_FAILED;

		if (mode == X86EMUL_MODE_PROT64) {
			if (ctxt->op_bytes == 4 && (ctxt->d & Stack))
				ctxt->op_bytes = 8;
			else if (ctxt->d & NearBranch)
				ctxt->op_bytes = 8;
		}

		if (ctxt->d & Op3264) {
			if (mode == X86EMUL_MODE_PROT64)
				ctxt->op_bytes = 8;
			else
				ctxt->op_bytes = 4;
		}

		if ((ctxt->d & No16) && ctxt->op_bytes == 2)
			ctxt->op_bytes = 4;

		if (vex_prefix)
			;
		else if (ctxt->d & Sse)
			ctxt->op_bytes = 16;
		else if (ctxt->d & Mmx)
			ctxt->op_bytes = 8;
	}

	/* ModRM and SIB bytes. */
	if (ctxt->d & ModRM) {
		rc = decode_modrm(ctxt, &ctxt->memop);
		if (!has_seg_override) {
			has_seg_override = true;
			ctxt->seg_override = ctxt->modrm_seg;
		}
	} else if (ctxt->d & MemAbs)
		rc = decode_abs(ctxt, &ctxt->memop);
	if (rc != X86EMUL_CONTINUE)
		goto done;

	if (!has_seg_override)
		ctxt->seg_override = VCPU_SREG_DS;

	ctxt->memop.addr.mem.seg = ctxt->seg_override;

	/*
	 * Decode and fetch the source operand: register, memory
	 * or immediate.
	 */
	rc = decode_operand(ctxt, &ctxt->src, (ctxt->d >> SrcShift) & OpMask);
	if (rc != X86EMUL_CONTINUE)
		goto done;

	/*
	 * Decode and fetch the second source operand: register, memory
	 * or immediate.
	 */
	rc = decode_operand(ctxt, &ctxt->src2, (ctxt->d >> Src2Shift) & OpMask);
	if (rc != X86EMUL_CONTINUE)
		goto done;

	/* Decode and fetch the destination operand: register or memory. */
	rc = decode_operand(ctxt, &ctxt->dst, (ctxt->d >> DstShift) & OpMask);

	if (ctxt->rip_relative) {
		struct segmented_address *addr = likely(ctxt->memopp) ?
			&ctxt->memopp->addr.mem : &ctxt->memop.addr.mem;

		addr->ea = address_mask(ctxt, addr->ea + ctxt->_eip);
	}

done:
	if (rc == X86EMUL_PROPAGATE_FAULT)
		ctxt->have_exception = true;
	return (rc != X86EMUL_CONTINUE) ? EMULATION_FAILED : EMULATION_OK;
}

bool x86_page_table_writing_insn(struct x86_emulate_ctxt *ctxt)
{
	return ctxt->d & PageTable;
}

static bool string_insn_completed(struct x86_emulate_ctxt *ctxt)
{
	/* The second termination condition only applies for REPE
	 * and REPNE. Test if the repeat string operation prefix is
	 * REPE/REPZ or REPNE/REPNZ and if it's the case it tests the
	 * corresponding termination condition according to:
	 * 	- if REPE/REPZ and ZF = 0 then done
	 * 	- if REPNE/REPNZ and ZF = 1 then done
	 */
	if (((ctxt->b == 0xa6) || (ctxt->b == 0xa7) ||
	     (ctxt->b == 0xae) || (ctxt->b == 0xaf))
	    && (((ctxt->rep_prefix == REPE_PREFIX) &&
		 ((ctxt->eflags & X86_EFLAGS_ZF) == 0))
		|| ((ctxt->rep_prefix == REPNE_PREFIX) &&
		    ((ctxt->eflags & X86_EFLAGS_ZF) == X86_EFLAGS_ZF))))
		return true;

	return false;
}

static int flush_pending_x87_faults(struct x86_emulate_ctxt *ctxt)
{
	int rc;

	kvm_fpu_get();
	rc = asm_safe("fwait");
	kvm_fpu_put();

	if (unlikely(rc != X86EMUL_CONTINUE))
		return emulate_exception(ctxt, MF_VECTOR, 0, false);

	return X86EMUL_CONTINUE;
}

static void fetch_possible_mmx_operand(struct operand *op)
{
	if (op->type == OP_MM)
		kvm_read_mmx_reg(op->addr.mm, &op->mm_val);
}

void init_decode_cache(struct x86_emulate_ctxt *ctxt)
{
	/* Clear fields that are set conditionally but read without a guard. */
	ctxt->rip_relative = false;
	ctxt->rex_prefix = REX_NONE;
	ctxt->rex_bits = 0;
	ctxt->lock_prefix = 0;
	ctxt->op_prefix = false;
	ctxt->rep_prefix = 0;
	ctxt->vex_reg = 0;
	ctxt->regs_valid = 0;
	ctxt->regs_dirty = 0;

	ctxt->io_read.pos = 0;
	ctxt->io_read.end = 0;
	ctxt->mem_read.end = 0;
}

int x86_emulate_insn(struct x86_emulate_ctxt *ctxt, bool check_intercepts)
{
	const struct x86_emulate_ops *ops = ctxt->ops;
	int rc = X86EMUL_CONTINUE;
	int saved_dst_type = ctxt->dst.type;

	ctxt->mem_read.pos = 0;

	/* LOCK prefix is allowed only with some instructions */
	if (ctxt->lock_prefix && (!(ctxt->d & Lock) || ctxt->dst.type != OP_MEM)) {
		rc = emulate_ud(ctxt);
		goto done;
	}

	if ((ctxt->d & SrcMask) == SrcMemFAddr && ctxt->src.type != OP_MEM) {
		rc = emulate_ud(ctxt);
		goto done;
	}

	if (unlikely(ctxt->d &
		     (No64|Undefined|Avx|Sse|Mmx|Intercept|CheckPerm|Priv|Prot|String))) {
		if ((ctxt->mode == X86EMUL_MODE_PROT64 && (ctxt->d & No64)) ||
				(ctxt->d & Undefined)) {
			rc = emulate_ud(ctxt);
			goto done;
		}

		if ((ctxt->d & (Avx|Sse|Mmx)) && ((ops->get_cr(ctxt, 0) & X86_CR0_EM))) {
			rc = emulate_ud(ctxt);
			goto done;
		}

		if (ctxt->d & Avx) {
			u64 xcr = 0;
			if (!(ops->get_cr(ctxt, 4) & X86_CR4_OSXSAVE)
			    || ops->get_xcr(ctxt, 0, &xcr)
			    || !(xcr & XFEATURE_MASK_YMM)) {
				rc = emulate_ud(ctxt);
				goto done;
			}
		} else if (ctxt->d & Sse) {
			if (!(ops->get_cr(ctxt, 4) & X86_CR4_OSFXSR)) {
				rc = emulate_ud(ctxt);
				goto done;
			}
		}

		if ((ctxt->d & (Avx|Sse|Mmx)) && (ops->get_cr(ctxt, 0) & X86_CR0_TS)) {
			rc = emulate_nm(ctxt);
			goto done;
		}

		if (ctxt->d & Mmx) {
			rc = flush_pending_x87_faults(ctxt);
			if (rc != X86EMUL_CONTINUE)
				goto done;
			/*
			 * Now that we know the fpu is exception safe, we can fetch
			 * operands from it.
			 */
			fetch_possible_mmx_operand(&ctxt->src);
			fetch_possible_mmx_operand(&ctxt->src2);
			if (!(ctxt->d & Mov))
				fetch_possible_mmx_operand(&ctxt->dst);
		}

		if (unlikely(check_intercepts) && ctxt->intercept) {
			rc = emulator_check_intercept(ctxt, ctxt->intercept,
						      X86_ICPT_PRE_EXCEPT);
			if (rc != X86EMUL_CONTINUE)
				goto done;
		}

		/* Instruction can only be executed in protected mode */
		if ((ctxt->d & Prot) && ctxt->mode < X86EMUL_MODE_PROT16) {
			rc = emulate_ud(ctxt);
			goto done;
		}

		/* Privileged instruction can be executed only in CPL=0 */
		if ((ctxt->d & Priv) && ops->cpl(ctxt)) {
			if (ctxt->d & PrivUD)
				rc = emulate_ud(ctxt);
			else
				rc = emulate_gp(ctxt, 0);
			goto done;
		}

		/* Do instruction specific permission checks */
		if (ctxt->d & CheckPerm) {
			rc = ctxt->check_perm(ctxt);
			if (rc != X86EMUL_CONTINUE)
				goto done;
		}

		if (unlikely(check_intercepts) && (ctxt->d & Intercept)) {
			rc = emulator_check_intercept(ctxt, ctxt->intercept,
						      X86_ICPT_POST_EXCEPT);
			if (rc != X86EMUL_CONTINUE)
				goto done;
		}

		if (ctxt->rep_prefix && (ctxt->d & String)) {
			/* All REP prefixes have the same first termination condition */
			if (address_mask(ctxt, reg_read(ctxt, VCPU_REGS_RCX)) == 0) {
				string_registers_quirk(ctxt);
				ctxt->eip = ctxt->_eip;
				ctxt->eflags &= ~X86_EFLAGS_RF;
				goto done;
			}
		}
	}

	if ((ctxt->src.type == OP_MEM) && !(ctxt->d & NoAccess)) {
		rc = segmented_read(ctxt, ctxt->src.addr.mem,
				    ctxt->src.valptr, ctxt->src.bytes);
		if (rc != X86EMUL_CONTINUE)
			goto done;
		ctxt->src.orig_val64 = ctxt->src.val64;
	}

	if (ctxt->src2.type == OP_MEM) {
		rc = segmented_read(ctxt, ctxt->src2.addr.mem,
				    &ctxt->src2.val, ctxt->src2.bytes);
		if (rc != X86EMUL_CONTINUE)
			goto done;
	}

	if ((ctxt->d & DstMask) == ImplicitOps)
		goto special_insn;


	if ((ctxt->dst.type == OP_MEM) && !(ctxt->d & Mov)) {
		/* optimisation - avoid slow emulated read if Mov */
		rc = segmented_read(ctxt, ctxt->dst.addr.mem,
				   &ctxt->dst.val, ctxt->dst.bytes);
		if (rc != X86EMUL_CONTINUE) {
			if (!(ctxt->d & NoWrite) &&
			    rc == X86EMUL_PROPAGATE_FAULT &&
			    ctxt->exception.vector == PF_VECTOR)
				ctxt->exception.error_code |= PFERR_WRITE_MASK;
			goto done;
		}
	}
	/* Copy full 64-bit value for CMPXCHG8B.  */
	ctxt->dst.orig_val64 = ctxt->dst.val64;

special_insn:

	if (unlikely(check_intercepts) && (ctxt->d & Intercept)) {
		rc = emulator_check_intercept(ctxt, ctxt->intercept,
					      X86_ICPT_POST_MEMACCESS);
		if (rc != X86EMUL_CONTINUE)
			goto done;
	}

	if (ctxt->rep_prefix && (ctxt->d & String))
		ctxt->eflags |= X86_EFLAGS_RF;
	else
		ctxt->eflags &= ~X86_EFLAGS_RF;

	if (ctxt->execute) {
		rc = ctxt->execute(ctxt);
		if (rc != X86EMUL_CONTINUE)
			goto done;
		goto writeback;
	}

	if (ctxt->opcode_len == 2)
		goto twobyte_insn;
	else if (ctxt->opcode_len == 3)
		goto threebyte_insn;

	switch (ctxt->b) {
	case 0x70 ... 0x7f: /* jcc (short) */
		if (test_cc(ctxt->b, ctxt->eflags))
			rc = jmp_rel(ctxt, ctxt->src.val);
		break;
	case 0x8d: /* lea r16/r32, m */
		ctxt->dst.val = ctxt->src.addr.mem.ea;
		break;
	case 0x90 ... 0x97: /* nop / xchg reg, rax */
		if (ctxt->dst.addr.reg == reg_rmw(ctxt, VCPU_REGS_RAX))
			ctxt->dst.type = OP_NONE;
		else
			rc = em_xchg(ctxt);
		break;
	case 0x98: /* cbw/cwde/cdqe */
		switch (ctxt->op_bytes) {
		case 2: ctxt->dst.val = (s8)ctxt->dst.val; break;
		case 4: ctxt->dst.val = (s16)ctxt->dst.val; break;
		case 8: ctxt->dst.val = (s32)ctxt->dst.val; break;
		}
		break;
	case 0xcc:		/* int3 */
		rc = emulate_int(ctxt, 3);
		break;
	case 0xcd:		/* int n */
		rc = emulate_int(ctxt, ctxt->src.val);
		break;
	case 0xce:		/* into */
		if (ctxt->eflags & X86_EFLAGS_OF)
			rc = emulate_int(ctxt, 4);
		break;
	case 0xe9: /* jmp rel */
	case 0xeb: /* jmp rel short */
		rc = jmp_rel(ctxt, ctxt->src.val);
		ctxt->dst.type = OP_NONE; /* Disable writeback. */
		break;
	case 0xf4:              /* hlt */
		ctxt->ops->halt(ctxt);
		break;
	case 0xf5:	/* cmc */
		/* complement carry flag from eflags reg */
		ctxt->eflags ^= X86_EFLAGS_CF;
		break;
	case 0xf8: /* clc */
		ctxt->eflags &= ~X86_EFLAGS_CF;
		break;
	case 0xf9: /* stc */
		ctxt->eflags |= X86_EFLAGS_CF;
		break;
	case 0xfc: /* cld */
		ctxt->eflags &= ~X86_EFLAGS_DF;
		break;
	case 0xfd: /* std */
		ctxt->eflags |= X86_EFLAGS_DF;
		break;
	default:
		goto cannot_emulate;
	}

	if (rc != X86EMUL_CONTINUE)
		goto done;

writeback:
	if (ctxt->d & SrcWrite) {
		BUG_ON(ctxt->src.type == OP_MEM || ctxt->src.type == OP_MEM_STR);
		rc = writeback(ctxt, &ctxt->src);
		if (rc != X86EMUL_CONTINUE)
			goto done;
	}
	if (!(ctxt->d & NoWrite)) {
		rc = writeback(ctxt, &ctxt->dst);
		if (rc != X86EMUL_CONTINUE)
			goto done;
	}

	/*
	 * restore dst type in case the decoding will be reused
	 * (happens for string instruction )
	 */
	ctxt->dst.type = saved_dst_type;

	if ((ctxt->d & SrcMask) == SrcSI)
		string_addr_inc(ctxt, VCPU_REGS_RSI, &ctxt->src);

	if ((ctxt->d & DstMask) == DstDI)
		string_addr_inc(ctxt, VCPU_REGS_RDI, &ctxt->dst);

	if (ctxt->rep_prefix && (ctxt->d & String)) {
		unsigned int count;
		struct read_cache *r = &ctxt->io_read;
		if ((ctxt->d & SrcMask) == SrcSI)
			count = ctxt->src.count;
		else
			count = ctxt->dst.count;
		register_address_increment(ctxt, VCPU_REGS_RCX, -count);

		if (!string_insn_completed(ctxt)) {
			/*
			 * Re-enter guest when pio read ahead buffer is empty
			 * or, if it is not used, after each 1024 iteration.
			 */
			if ((r->end != 0 || reg_read(ctxt, VCPU_REGS_RCX) & 0x3ff) &&
			    (r->end == 0 || r->end != r->pos)) {
				/*
				 * Reset read cache. Usually happens before
				 * decode, but since instruction is restarted
				 * we have to do it here.
				 */
				ctxt->mem_read.end = 0;
				writeback_registers(ctxt);
				return EMULATION_RESTART;
			}
			goto done; /* skip rip writeback */
		}
		ctxt->eflags &= ~X86_EFLAGS_RF;
	}

	ctxt->eip = ctxt->_eip;
	if (ctxt->mode != X86EMUL_MODE_PROT64)
		ctxt->eip = (u32)ctxt->_eip;

done:
	if (rc == X86EMUL_PROPAGATE_FAULT) {
		if (KVM_EMULATOR_BUG_ON(ctxt->exception.vector > 0x1f, ctxt))
			return EMULATION_FAILED;
		ctxt->have_exception = true;
	}
	if (rc == X86EMUL_INTERCEPTED)
		return EMULATION_INTERCEPTED;

	if (rc == X86EMUL_CONTINUE)
		writeback_registers(ctxt);

	return (rc == X86EMUL_UNHANDLEABLE) ? EMULATION_FAILED : EMULATION_OK;

twobyte_insn:
	switch (ctxt->b) {
	case 0x09:		/* wbinvd */
		(ctxt->ops->wbinvd)(ctxt);
		break;
	case 0x08:		/* invd */
	case 0x0d:		/* GrpP (prefetch) */
	case 0x18:		/* Grp16 (prefetch/nop) */
	case 0x1f:		/* nop */
		break;
	case 0x20: /* mov cr, reg */
		ctxt->dst.val = ops->get_cr(ctxt, ctxt->modrm_reg);
		break;
	case 0x21: /* mov from dr to reg */
		ctxt->dst.val = ops->get_dr(ctxt, ctxt->modrm_reg);
		break;
	case 0x40 ... 0x4f:	/* cmov */
		if (test_cc(ctxt->b, ctxt->eflags))
			ctxt->dst.val = ctxt->src.val;
		else if (ctxt->op_bytes != 4)
			ctxt->dst.type = OP_NONE; /* no writeback */
		break;
	case 0x80 ... 0x8f: /* jnz rel, etc*/
		if (test_cc(ctxt->b, ctxt->eflags))
			rc = jmp_rel(ctxt, ctxt->src.val);
		break;
	case 0x90 ... 0x9f:     /* setcc r/m8 */
		ctxt->dst.val = test_cc(ctxt->b, ctxt->eflags);
		break;
	case 0xb6 ... 0xb7:	/* movzx */
		ctxt->dst.bytes = ctxt->op_bytes;
		ctxt->dst.val = (ctxt->src.bytes == 1) ? (u8) ctxt->src.val
						       : (u16) ctxt->src.val;
		break;
	case 0xbe ... 0xbf:	/* movsx */
		ctxt->dst.bytes = ctxt->op_bytes;
		ctxt->dst.val = (ctxt->src.bytes == 1) ? (s8) ctxt->src.val :
							(s16) ctxt->src.val;
		break;
	default:
		goto cannot_emulate;
	}

threebyte_insn:

	if (rc != X86EMUL_CONTINUE)
		goto done;

	goto writeback;

cannot_emulate:
	return EMULATION_FAILED;
}

void emulator_invalidate_register_cache(struct x86_emulate_ctxt *ctxt)
{
	invalidate_registers(ctxt);
}

void emulator_writeback_register_cache(struct x86_emulate_ctxt *ctxt)
{
	writeback_registers(ctxt);
}

bool emulator_can_use_gpa(struct x86_emulate_ctxt *ctxt)
{
	if (ctxt->rep_prefix && (ctxt->d & String))
		return false;

	if (ctxt->d & TwoMemOp)
		return false;

	return true;
}
