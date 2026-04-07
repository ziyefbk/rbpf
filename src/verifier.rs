#![allow(clippy::arithmetic_side_effects)]
// Derived from uBPF <https://github.com/iovisor/ubpf>
// Copyright 2015 Big Switch Networks, Inc
//      (uBPF: safety checks, originally in C)
// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>
//      (Translation to Rust)
// Copyright 2020 Solana Maintainers <maintainers@solana.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Verifies that the bytecode is valid for the given config.

use crate::{
    ebpf,
    program::{BuiltinFunction, FunctionRegistry, SBPFVersion},
    vm::{Config, ContextObject},
};
use thiserror::Error;

/// Error definitions
#[derive(Debug, Error, Eq, PartialEq)]
pub enum VerifierError {
    /// ProgramLengthNotMultiple
    #[error("program length must be a multiple of {} octets", ebpf::INSN_SIZE)]
    ProgramLengthNotMultiple,
    /// Deprecated
    #[error("Deprecated")]
    ProgramTooLarge(usize),
    /// NoProgram
    #[error("no program set, call prog_set() to load one")]
    NoProgram,
    /// Division by zero
    #[error("division by 0 (insn #{0})")]
    DivisionByZero(usize),
    /// UnsupportedLEBEArgument
    #[error("unsupported argument for LE/BE (insn #{0})")]
    UnsupportedLEBEArgument(usize),
    /// LDDWCannotBeLast
    #[error("LD_DW instruction cannot be last in program")]
    LDDWCannotBeLast,
    /// IncompleteLDDW
    #[error("incomplete LD_DW instruction (insn #{0})")]
    IncompleteLDDW(usize),
    /// InfiniteLoop
    #[error("infinite loop (insn #{0})")]
    InfiniteLoop(usize),
    /// JumpOutOfCode
    #[error("jump out of code to #{0} (insn #{1})")]
    JumpOutOfCode(usize, usize),
    /// JumpToMiddleOfLDDW
    #[error("jump to middle of LD_DW at #{0} (insn #{1})")]
    JumpToMiddleOfLDDW(usize, usize),
    /// InvalidSourceRegister
    #[error("invalid source register (insn #{0})")]
    InvalidSourceRegister(usize),
    /// CannotWriteR10
    #[error("cannot write into register r10 (insn #{0})")]
    CannotWriteR10(usize),
    /// InvalidDestinationRegister
    #[error("invalid destination register (insn #{0})")]
    InvalidDestinationRegister(usize),
    /// UnknownOpCode
    #[error("unknown eBPF opcode {0:#2x} (insn #{1:?})")]
    UnknownOpCode(u8, usize),
    /// Shift with overflow
    #[error("Shift with overflow of {0}-bit value by {1} (insn #{2:?})")]
    ShiftWithOverflow(u64, u64, usize),
    /// Invalid register specified
    #[error("Invalid register specified at instruction {0}")]
    InvalidRegister(usize),
    /// Invalid function
    #[error("Invalid function at instruction {0}")]
    InvalidFunction(usize),
    /// Invalid syscall
    #[error("Invalid syscall code {0}")]
    InvalidSyscall(u32),
    /// Unaligned immediate
    #[error("Unaligned immediate (insn #{0})")]
    UnalignedImmediate(usize),
}

/// eBPF Verifier
pub trait Verifier {
    /// eBPF verification function that returns an error if the program does not meet its requirements.
    ///
    /// Some examples of things the verifier may reject the program for:
    ///
    ///   - Program does not terminate.
    ///   - Unknown instructions.
    ///   - Bad formed instruction.
    ///   - Unknown eBPF syscall index.
    fn verify<C: ContextObject>(
        prog: &[u8],
        config: &Config,
        sbpf_version: SBPFVersion,
        function_registry: &FunctionRegistry<usize>,
        syscall_registry: &FunctionRegistry<BuiltinFunction<C>>,
    ) -> Result<(), VerifierError>;
}

fn check_prog_len(prog: &[u8]) -> Result<(), VerifierError> {
    if prog.len().checked_rem(ebpf::INSN_SIZE) != Some(0) {
        return Err(VerifierError::ProgramLengthNotMultiple);
    }
    if prog.is_empty() {
        return Err(VerifierError::NoProgram);
    }
    Ok(())
}

fn check_imm_nonzero(insn: &ebpf::Insn, insn_ptr: usize) -> Result<(), VerifierError> {
    if insn.imm == 0 {
        return Err(VerifierError::DivisionByZero(insn_ptr));
    }
    Ok(())
}

fn check_imm_endian(insn: &ebpf::Insn, insn_ptr: usize) -> Result<(), VerifierError> {
    match insn.imm {
        16 | 32 | 64 => Ok(()),
        _ => Err(VerifierError::UnsupportedLEBEArgument(insn_ptr)),
    }
}

fn check_imm_aligned(
    insn: &ebpf::Insn,
    insn_ptr: usize,
    alignment: i64,
) -> Result<(), VerifierError> {
    if (insn.imm & (alignment - 1)) == 0 {
        Ok(())
    } else {
        Err(VerifierError::UnalignedImmediate(insn_ptr))
    }
}

fn check_load_dw(prog: &[u8], insn_ptr: usize) -> Result<(), VerifierError> {
    if (insn_ptr + 1) * ebpf::INSN_SIZE >= prog.len() {
        // Last instruction cannot be LD_DW because there would be no 2nd DW
        return Err(VerifierError::LDDWCannotBeLast);
    }
    let next_insn = ebpf::get_insn(prog, insn_ptr + 1);
    if next_insn.opc != 0 {
        return Err(VerifierError::IncompleteLDDW(insn_ptr));
    }
    Ok(())
}

fn check_jmp_offset(
    prog: &[u8],
    insn_ptr: usize,
    program_range: &std::ops::Range<usize>,
) -> Result<(), VerifierError> {
    let insn = ebpf::get_insn(prog, insn_ptr);

    let dst_insn_ptr = insn_ptr as isize + 1 + insn.off as isize;
    if dst_insn_ptr < 0 || !program_range.contains(&(dst_insn_ptr as usize)) {
        return Err(VerifierError::JumpOutOfCode(
            dst_insn_ptr as usize,
            insn_ptr,
        ));
    }
    let dst_insn = ebpf::get_insn(prog, dst_insn_ptr as usize);
    if dst_insn.opc == 0 {
        return Err(VerifierError::JumpToMiddleOfLDDW(
            dst_insn_ptr as usize,
            insn_ptr,
        ));
    }
    Ok(())
}

fn check_registers(
    insn: &ebpf::Insn,
    store: bool,
    insn_ptr: usize,
    sbpf_version: SBPFVersion,
) -> Result<(), VerifierError> {
    if insn.src > 10 {
        return Err(VerifierError::InvalidSourceRegister(insn_ptr));
    }

    match (insn.dst, store) {
        (0..=9, _) | (10, true) => Ok(()),
        (10, false) if sbpf_version.manual_stack_frame_bump() && insn.opc == ebpf::ADD64_IMM => {
            Ok(())
        }
        (10, false) => Err(VerifierError::CannotWriteR10(insn_ptr)),
        (_, _) => Err(VerifierError::InvalidDestinationRegister(insn_ptr)),
    }
}

/// Check that the imm is a valid shift operand
fn check_imm_shift(insn: &ebpf::Insn, insn_ptr: usize, imm_bits: u64) -> Result<(), VerifierError> {
    let shift_by = insn.imm as u64;
    if insn.imm < 0 || shift_by >= imm_bits {
        return Err(VerifierError::ShiftWithOverflow(
            shift_by, imm_bits, insn_ptr,
        ));
    }
    Ok(())
}

/// Check that callx has a valid register number
fn check_callx_register(
    insn: &ebpf::Insn,
    insn_ptr: usize,
    sbpf_version: SBPFVersion,
) -> Result<(), VerifierError> {
    let reg = if sbpf_version.callx_uses_src_reg() {
        insn.src as i64
    } else if sbpf_version.callx_uses_dst_reg() {
        insn.dst as i64
    } else {
        insn.imm
    };
    if !(0..10).contains(&reg) {
        return Err(VerifierError::InvalidRegister(insn_ptr));
    }
    Ok(())
}

/// Mandatory verifier for solana programs to run on-chain
#[derive(Debug)]
pub struct RequisiteVerifier {}
impl Verifier for RequisiteVerifier {
    /// Check the program against the verifier's rules
    #[rustfmt::skip]
    fn verify<C: ContextObject>(prog: &[u8], _config: &Config, sbpf_version: SBPFVersion, _function_registry: &FunctionRegistry<usize>, _syscall_registry: &FunctionRegistry<BuiltinFunction<C>>) -> Result<(), VerifierError> {
        check_prog_len(prog)?;

        let program_range = 0..prog.len() / ebpf::INSN_SIZE;
        let mut insn_ptr: usize = 0;
        while (insn_ptr + 1) * ebpf::INSN_SIZE <= prog.len() {
            let insn = ebpf::get_insn(prog, insn_ptr);
            let mut store = false;

            match insn.opc {
                ebpf::LD_DW_IMM if !sbpf_version.disable_lddw() => {
                    check_load_dw(prog, insn_ptr)?;
                    insn_ptr += 1;
                },

                // BPF_LDX class
                ebpf::LD_B_REG  if !sbpf_version.move_memory_instruction_classes() => {},
                ebpf::LD_H_REG  if !sbpf_version.move_memory_instruction_classes() => {},
                ebpf::LD_W_REG  if !sbpf_version.move_memory_instruction_classes() => {},
                ebpf::LD_DW_REG if !sbpf_version.move_memory_instruction_classes() => {},

                // BPF_ST class
                ebpf::ST_B_IMM  if !sbpf_version.move_memory_instruction_classes() => store = true,
                ebpf::ST_H_IMM  if !sbpf_version.move_memory_instruction_classes() => store = true,
                ebpf::ST_W_IMM  if !sbpf_version.move_memory_instruction_classes() => store = true,
                ebpf::ST_DW_IMM if !sbpf_version.move_memory_instruction_classes() => store = true,

                // BPF_STX class
                ebpf::ST_B_REG  if !sbpf_version.move_memory_instruction_classes() => store = true,
                ebpf::ST_H_REG  if !sbpf_version.move_memory_instruction_classes() => store = true,
                ebpf::ST_W_REG  if !sbpf_version.move_memory_instruction_classes() => store = true,
                ebpf::ST_DW_REG if !sbpf_version.move_memory_instruction_classes() => store = true,

                // BPF_ALU32_LOAD class
                ebpf::ADD32_IMM  => {},
                ebpf::ADD32_REG  => {},
                ebpf::SUB32_IMM  => {},
                ebpf::SUB32_REG  => {},
                ebpf::MUL32_IMM  if !sbpf_version.enable_pqr() => {},
                ebpf::MUL32_REG  if !sbpf_version.enable_pqr() => {},
                ebpf::LD_1B_REG  if sbpf_version.move_memory_instruction_classes() => {},
                ebpf::DIV32_IMM  if !sbpf_version.enable_pqr() => { check_imm_nonzero(&insn, insn_ptr)?; },
                ebpf::DIV32_REG  if !sbpf_version.enable_pqr() => {},
                ebpf::LD_2B_REG  if sbpf_version.move_memory_instruction_classes() => {},
                ebpf::OR32_IMM   => {},
                ebpf::OR32_REG   => {},
                ebpf::AND32_IMM  => {},
                ebpf::AND32_REG  => {},
                ebpf::LSH32_IMM  => { check_imm_shift(&insn, insn_ptr, 32)?; },
                ebpf::LSH32_REG  => {},
                ebpf::RSH32_IMM  => { check_imm_shift(&insn, insn_ptr, 32)?; },
                ebpf::RSH32_REG  => {},
                ebpf::NEG32      if !sbpf_version.disable_neg() => {},
                ebpf::LD_4B_REG  if sbpf_version.move_memory_instruction_classes() => {},
                ebpf::MOD32_IMM  if !sbpf_version.enable_pqr() => { check_imm_nonzero(&insn, insn_ptr)?; },
                ebpf::MOD32_REG  if !sbpf_version.enable_pqr() => {},
                ebpf::LD_8B_REG  if sbpf_version.move_memory_instruction_classes() => {},
                ebpf::XOR32_IMM  => {},
                ebpf::XOR32_REG  => {},
                ebpf::MOV32_IMM  => {},
                ebpf::MOV32_REG  => {},
                ebpf::ARSH32_IMM => { check_imm_shift(&insn, insn_ptr, 32)?; },
                ebpf::ARSH32_REG => {},
                ebpf::LE         if !sbpf_version.disable_le() => { check_imm_endian(&insn, insn_ptr)?; },
                ebpf::BE         => { check_imm_endian(&insn, insn_ptr)?; },

                // BPF_ALU64_STORE class
                ebpf::ADD64_IMM  if insn.dst == ebpf::FRAME_PTR_REG as u8 && sbpf_version.manual_stack_frame_bump() => {
                    check_imm_aligned(&insn, insn_ptr, 64)?;
                },
                ebpf::ADD64_IMM  => {},
                ebpf::ADD64_REG  => {},
                ebpf::SUB64_IMM  => {},
                ebpf::SUB64_REG  => {},
                ebpf::MUL64_IMM  if !sbpf_version.enable_pqr() => {},
                ebpf::ST_1B_IMM  if sbpf_version.move_memory_instruction_classes() => store = true,
                ebpf::MUL64_REG  if !sbpf_version.enable_pqr() => {},
                ebpf::ST_1B_REG  if sbpf_version.move_memory_instruction_classes() => store = true,
                ebpf::DIV64_IMM  if !sbpf_version.enable_pqr() => { check_imm_nonzero(&insn, insn_ptr)?; },
                ebpf::ST_2B_IMM  if sbpf_version.move_memory_instruction_classes() => store = true,
                ebpf::DIV64_REG  if !sbpf_version.enable_pqr() => {},
                ebpf::ST_2B_REG  if sbpf_version.move_memory_instruction_classes() => store = true,
                ebpf::OR64_IMM   => {},
                ebpf::OR64_REG   => {},
                ebpf::AND64_IMM  => {},
                ebpf::AND64_REG  => {},
                ebpf::LSH64_IMM  => { check_imm_shift(&insn, insn_ptr, 64)?; },
                ebpf::LSH64_REG  => {},
                ebpf::RSH64_IMM  => { check_imm_shift(&insn, insn_ptr, 64)?; },
                ebpf::RSH64_REG  => {},
                ebpf::ST_4B_IMM  if sbpf_version.move_memory_instruction_classes() => store = true,
                ebpf::NEG64      if !sbpf_version.disable_neg() => {},
                ebpf::ST_4B_REG  if sbpf_version.move_memory_instruction_classes() => store = true,
                ebpf::MOD64_IMM  if !sbpf_version.enable_pqr() => { check_imm_nonzero(&insn, insn_ptr)?; },
                ebpf::ST_8B_IMM  if sbpf_version.move_memory_instruction_classes() => store = true,
                ebpf::MOD64_REG  if !sbpf_version.enable_pqr() => {},
                ebpf::ST_8B_REG  if sbpf_version.move_memory_instruction_classes() => store = true,
                ebpf::XOR64_IMM  => {},
                ebpf::XOR64_REG  => {},
                ebpf::MOV64_IMM  => {},
                ebpf::MOV64_REG  => {},
                ebpf::ARSH64_IMM => { check_imm_shift(&insn, insn_ptr, 64)?; },
                ebpf::ARSH64_REG => {},
                ebpf::HOR64_IMM  if sbpf_version.disable_lddw() => {},

                // BPF_PQR class
                ebpf::LMUL32_IMM if sbpf_version.enable_pqr() => {},
                ebpf::LMUL32_REG if sbpf_version.enable_pqr() => {},
                ebpf::LMUL64_IMM if sbpf_version.enable_pqr() => {},
                ebpf::LMUL64_REG if sbpf_version.enable_pqr() => {},
                ebpf::UHMUL64_IMM if sbpf_version.enable_pqr() => {},
                ebpf::UHMUL64_REG if sbpf_version.enable_pqr() => {},
                ebpf::SHMUL64_IMM if sbpf_version.enable_pqr() => {},
                ebpf::SHMUL64_REG if sbpf_version.enable_pqr() => {},
                ebpf::UDIV32_IMM if sbpf_version.enable_pqr() => { check_imm_nonzero(&insn, insn_ptr)?; },
                ebpf::UDIV32_REG if sbpf_version.enable_pqr() => {},
                ebpf::UDIV64_IMM if sbpf_version.enable_pqr() => { check_imm_nonzero(&insn, insn_ptr)?; },
                ebpf::UDIV64_REG if sbpf_version.enable_pqr() => {},
                ebpf::UREM32_IMM if sbpf_version.enable_pqr() => { check_imm_nonzero(&insn, insn_ptr)?; },
                ebpf::UREM32_REG if sbpf_version.enable_pqr() => {},
                ebpf::UREM64_IMM if sbpf_version.enable_pqr() => { check_imm_nonzero(&insn, insn_ptr)?; },
                ebpf::UREM64_REG if sbpf_version.enable_pqr() => {},
                ebpf::SDIV32_IMM if sbpf_version.enable_pqr() => { check_imm_nonzero(&insn, insn_ptr)?; },
                ebpf::SDIV32_REG if sbpf_version.enable_pqr() => {},
                ebpf::SDIV64_IMM if sbpf_version.enable_pqr() => { check_imm_nonzero(&insn, insn_ptr)?; },
                ebpf::SDIV64_REG if sbpf_version.enable_pqr() => {},
                ebpf::SREM32_IMM if sbpf_version.enable_pqr() => { check_imm_nonzero(&insn, insn_ptr)?; },
                ebpf::SREM32_REG if sbpf_version.enable_pqr() => {},
                ebpf::SREM64_IMM if sbpf_version.enable_pqr() => { check_imm_nonzero(&insn, insn_ptr)?; },
                ebpf::SREM64_REG if sbpf_version.enable_pqr() => {},

                // BPF_JMP32 class
                ebpf::JEQ32_IMM
                | ebpf::JEQ32_REG
                | ebpf::JGT32_IMM
                | ebpf::JGT32_REG
                | ebpf::JGE32_IMM
                | ebpf::JGE32_REG
                | ebpf::JLT32_IMM
                | ebpf::JLT32_REG
                | ebpf::JLE32_IMM
                | ebpf::JLE32_REG
                | ebpf::JSET32_IMM
                | ebpf::JSET32_REG
                | ebpf::JNE32_IMM
                | ebpf::JNE32_REG
                | ebpf::JSGT32_IMM
                | ebpf::JSGT32_REG
                | ebpf::JSGE32_IMM
                | ebpf::JSGE32_REG
                | ebpf::JSLT32_IMM
                | ebpf::JSLT32_REG
                | ebpf::JSLE32_IMM
                | ebpf::JSLE32_REG if sbpf_version.enable_jmp32() => { check_jmp_offset(prog, insn_ptr, &program_range)?; },

                // BPF_JMP64 class
                ebpf::JA
                | ebpf::JEQ64_IMM
                | ebpf::JEQ64_REG
                | ebpf::JGT64_IMM
                | ebpf::JGT64_REG
                | ebpf::JGE64_IMM
                | ebpf::JGE64_REG
                | ebpf::JLT64_IMM
                | ebpf::JLT64_REG
                | ebpf::JLE64_IMM
                | ebpf::JLE64_REG
                | ebpf::JSET64_IMM
                | ebpf::JSET64_REG
                | ebpf::JNE64_IMM
                | ebpf::JNE64_REG
                | ebpf::JSGT64_IMM
                | ebpf::JSGT64_REG
                | ebpf::JSGE64_IMM
                | ebpf::JSGE64_REG
                | ebpf::JSLT64_IMM
                | ebpf::JSLT64_REG
                | ebpf::JSLE64_IMM
                | ebpf::JSLE64_REG   => { check_jmp_offset(prog, insn_ptr, &program_range)?; },
                ebpf::CALL_IMM   => {},
                ebpf::CALL_REG   => { check_callx_register(&insn, insn_ptr, sbpf_version)?; },
                ebpf::EXIT       => {},

                _                => {
                    return Err(VerifierError::UnknownOpCode(insn.opc, insn_ptr));
                }
            }

            check_registers(&insn, store, insn_ptr, sbpf_version)?;

            insn_ptr += 1;
        }

        // insn_ptr should now be equal to number of instructions.
        if insn_ptr != prog.len() / ebpf::INSN_SIZE {
            return Err(VerifierError::JumpOutOfCode(insn_ptr, insn_ptr));
        }

        Ok(())
    }
}

use crate::{
    reduced_product::ReducedProduct,
    tnum::Tnum,
    wrapped_interval::WrappedRange,
};

/// Abstract register state
#[derive(Clone, Debug)]
pub struct RegState {
    pub domain: ReducedProduct,
    pub initialized: bool,
}

impl Default for RegState {
    fn default() -> Self {
        Self {
            domain: ReducedProduct::top(64),
            initialized: false,
        }
    }
}

impl RegState {
    /// Create a scalar register (unknown value)
    pub fn new_scalar() -> Self {
        Self {
            domain: ReducedProduct::top(64),
            initialized: true,
        }
    }

    /// Create a constant register
    pub fn new_constant(value: u64) -> Self {
        Self {
            domain: ReducedProduct::constant(value, 64),
            initialized: true,
        }
    }

    /// Synchronize Tnum and Range via reduction
    pub fn reduce(&mut self) {
        self.domain.reduce();
    }

    /// Get tnum representation
    pub fn tnum(&self) -> Tnum {
        *self.domain.tnum()
    }

    /// Get interval representation
    pub fn interval(&self) -> &WrappedRange {
        self.domain.interval()
    }

    /// Set new tnum and interval, then reduce
    pub fn set_tnum_interval(&mut self, tnum: Tnum, interval: WrappedRange) {
        *self.domain.tnum_mut() = tnum;
        *self.domain.interval_mut() = interval;
        self.reduce();
    }

    /// Set only tnum then reduce
    pub fn set_tnum(&mut self, tnum: Tnum) {
        *self.domain.tnum_mut() = tnum;
        self.reduce();
    }
}

/// Verifier state (all registers)
#[derive(Clone, Debug)]
pub struct VerifierState {
    pub regs: [RegState; 11],  // r0-r10
}

impl Default for VerifierState {
    fn default() -> Self {
        Self {
            regs: [
                RegState::default(),
                RegState::default(),
                RegState::default(),
                RegState::default(),
                RegState::default(),
                RegState::default(),
                RegState::default(),
                RegState::default(),
                RegState::default(),
                RegState::default(),
                RegState::default(),
            ],
        }
    }
}

impl VerifierState {
    fn new() -> Self {
        let mut state = Self::default();

        // r1 initialized as scalar (entry point argument)
        state.regs[1] = RegState::new_scalar();

        // r10 initialized as scalar (stack pointer)
        state.regs[10] = RegState::new_scalar();

        state
    }

    fn get_reg(&self, reg: u8) -> &RegState {
        &self.regs[reg as usize]
    }

    fn get_reg_mut(&mut self, reg: u8) -> &mut RegState {
        &mut self.regs[reg as usize]
    }

    fn set_reg_constant(&mut self, reg: u8, value: u64) {
        self.regs[reg as usize] = RegState::new_constant(value);
    }

    fn set_reg_scalar(&mut self, reg: u8) {
        self.regs[reg as usize] = RegState::new_scalar();
    }
}

/// Abstract interpretation Verifier
#[derive(Debug)]
pub struct AbstractVerifier {}

impl AbstractVerifier {
    /// Abstract interpretation main loop
    pub fn abstract_verify(
        prog: &[u8],
        _sbpf_version: SBPFVersion,
    ) -> Result<(), VerifierError> {
        let num_insns = prog.len() / ebpf::INSN_SIZE;
        let mut state = VerifierState::new();
        let mut insn_ptr = 0;

        while insn_ptr < num_insns {
            let insn = ebpf::get_insn(prog, insn_ptr);

            match insn.opc {
                // ===== BPF_ALU64_STORE class =====

                // MOV
                ebpf::MOV64_IMM => {
                    state.set_reg_constant(insn.dst, insn.imm as i64 as u64);
                }
                ebpf::MOV64_REG => {
                    if !state.get_reg(insn.src).initialized {
                        return Err(VerifierError::InvalidSourceRegister(insn_ptr));
                    }
                    state.regs[insn.dst as usize] = state.regs[insn.src as usize].clone();
                    state.regs[insn.dst as usize].reduce();
                }

                // ADD
                ebpf::ADD64_IMM => {
                    let imm_val = insn.imm as i64 as u64;
                    let dst = state.get_reg_mut(insn.dst);

                    let imm_tnum = Tnum::const_val(imm_val);
                    let new_tnum = dst.tnum().add(imm_tnum);

                    let imm_range = WrappedRange::new_constant(imm_val, 64);
                    let new_range = dst.interval().add(&imm_range);

                    dst.set_tnum_interval(new_tnum, new_range);
                }
                ebpf::ADD64_REG => {
                    if !state.get_reg(insn.src).initialized {
                        return Err(VerifierError::InvalidSourceRegister(insn_ptr));
                    }

                    let src_tnum = state.get_reg(insn.src).tnum();
                    let src_range = state.get_reg(insn.src).interval().clone();

                    let dst = state.get_reg_mut(insn.dst);
                    let new_tnum = dst.tnum().add(src_tnum);
                    let new_range = dst.interval().add(&src_range);
                    dst.set_tnum_interval(new_tnum, new_range);
                }

                // SUB
                ebpf::SUB64_IMM => {
                    let imm_val = insn.imm as i64 as u64;
                    let dst = state.get_reg_mut(insn.dst);

                    let imm_tnum = Tnum::const_val(imm_val);
                    let new_tnum = dst.tnum().sub(imm_tnum);

                    let imm_range = WrappedRange::new_constant(imm_val, 64);
                    let new_range = dst.interval().sub(&imm_range);

                    dst.set_tnum_interval(new_tnum, new_range);
                }
                ebpf::SUB64_REG => {
                    if !state.get_reg(insn.src).initialized {
                        return Err(VerifierError::InvalidSourceRegister(insn_ptr));
                    }

                    let src_tnum = state.get_reg(insn.src).tnum();
                    let src_range = state.get_reg(insn.src).interval().clone();
                    let dst = state.get_reg_mut(insn.dst);

                    let new_tnum = dst.tnum().sub(src_tnum);
                    let new_range = dst.interval().sub(&src_range);
                    dst.set_tnum_interval(new_tnum, new_range);
                }

                // MUL
                ebpf::MUL64_IMM if !_sbpf_version.enable_pqr() => {
                    let imm_val = insn.imm as i64 as u64;
                    let dst = state.get_reg_mut(insn.dst);

                    let imm_tnum = Tnum::const_val(imm_val);
                    let new_tnum = dst.tnum().mul(imm_tnum);

                    let imm_range = WrappedRange::new_constant(imm_val, 64);
                    let new_range = dst.interval().mul(&imm_range);

                    dst.set_tnum_interval(new_tnum, new_range);
                }
                ebpf::MUL64_REG if !_sbpf_version.enable_pqr() => {
                    if !state.get_reg(insn.src).initialized {
                        return Err(VerifierError::InvalidSourceRegister(insn_ptr));
                    }

                    let src_tnum = state.get_reg(insn.src).tnum();
                    let src_range = state.get_reg(insn.src).interval().clone();
                    let dst = state.get_reg_mut(insn.dst);

                    let new_tnum = dst.tnum().mul(src_tnum);
                    let new_range = dst.interval().mul(&src_range);
                    dst.set_tnum_interval(new_tnum, new_range);
                }

                // DIV
                ebpf::DIV64_IMM if !_sbpf_version.enable_pqr() => {
                    let imm_val = insn.imm as i64 as u64;
                    if imm_val == 0 {
                        return Err(VerifierError::DivisionByZero(insn_ptr));
                    }

                    let dst = state.get_reg_mut(insn.dst);
                    let imm_tnum = Tnum::const_val(imm_val);
                    let new_tnum = dst.tnum().udiv(imm_tnum);

                    let imm_range = WrappedRange::new_constant(imm_val, 64);
                    let new_range = dst.interval().udiv(&imm_range);

                    dst.set_tnum_interval(new_tnum, new_range);
                }
                ebpf::DIV64_REG if !_sbpf_version.enable_pqr() => {
                    if !state.get_reg(insn.src).initialized {
                        return Err(VerifierError::InvalidSourceRegister(insn_ptr));
                    }

                    let divisor = state.get_reg(insn.src);
                    let divisor_tnum = divisor.tnum();
                    let divisor_range = divisor.interval();

                    if !divisor_tnum.is_definitely_nonzero() || divisor_range.contains_zero() {
                        return Err(VerifierError::DivisionByZero(insn_ptr));
                    }

                    let src_tnum = state.get_reg(insn.src).tnum();
                    let src_range = state.get_reg(insn.src).interval().clone();
                    let dst = state.get_reg_mut(insn.dst);

                    let new_tnum = dst.tnum().udiv(src_tnum);
                    let new_range = dst.interval().udiv(&src_range);

                    dst.set_tnum_interval(new_tnum, new_range);
                }

                // MOD
                ebpf::MOD64_IMM if !_sbpf_version.enable_pqr() => {
                    let imm_val = insn.imm as i64 as u64;
                    if imm_val == 0 {
                        return Err(VerifierError::DivisionByZero(insn_ptr));
                    }

                    let dst = state.get_reg_mut(insn.dst);
                    let imm_tnum = Tnum::const_val(imm_val);
                    let new_tnum = dst.tnum().urem(imm_tnum);

                    let imm_range = WrappedRange::new_constant(imm_val, 64);
                    let new_range = dst.interval().urem(&imm_range);

                    dst.set_tnum_interval(new_tnum, new_range);
                }
                ebpf::MOD64_REG if !_sbpf_version.enable_pqr() => {
                    if !state.get_reg(insn.src).initialized {
                        return Err(VerifierError::InvalidSourceRegister(insn_ptr));
                    }

                    let divisor = state.get_reg(insn.src);
                    let divisor_tnum = divisor.tnum();
                    let divisor_range = divisor.interval();

                    if !divisor_tnum.is_definitely_nonzero() || divisor_range.contains_zero() {
                        return Err(VerifierError::DivisionByZero(insn_ptr));
                    }

                    let src_tnum = state.get_reg(insn.src).tnum();
                    let src_range = state.get_reg(insn.src).interval().clone();
                    let dst = state.get_reg_mut(insn.dst);

                    let new_tnum = dst.tnum().urem(src_tnum);
                    let new_range = dst.interval().urem(&src_range);

                    dst.set_tnum_interval(new_tnum, new_range);
                }

                // AND
                ebpf::AND64_IMM => {
                    let imm_val = insn.imm as i64 as u64;
                    let dst = state.get_reg_mut(insn.dst);

                    let imm_tnum = Tnum::const_val(imm_val);
                    let new_tnum = dst.tnum().and(&imm_tnum);

                    let imm_range = WrappedRange::new_constant(imm_val, 64);
                    let new_range = dst.interval().and(&imm_range);

                    dst.set_tnum_interval(new_tnum, new_range);
                }
                ebpf::AND64_REG => {
                    if !state.get_reg(insn.src).initialized {
                        return Err(VerifierError::InvalidSourceRegister(insn_ptr));
                    }

                    let src_tnum = state.get_reg(insn.src).tnum();
                    let src_range = state.get_reg(insn.src).interval().clone();
                    let dst = state.get_reg_mut(insn.dst);

                    let new_tnum = dst.tnum().and(&src_tnum);
                    let new_range = dst.interval().and(&src_range);
                    dst.set_tnum_interval(new_tnum, new_range);
                }

                // OR
                ebpf::OR64_IMM => {
                    let imm_val = insn.imm as i64 as u64;
                    let dst = state.get_reg_mut(insn.dst);

                    let imm_tnum = Tnum::const_val(imm_val);
                    let new_tnum = dst.tnum().or(&imm_tnum);

                    let imm_range = WrappedRange::new_constant(imm_val, 64);
                    let new_range = dst.interval().or(&imm_range);

                    dst.set_tnum_interval(new_tnum, new_range);
                }
                ebpf::OR64_REG => {
                    if !state.get_reg(insn.src).initialized {
                        return Err(VerifierError::InvalidSourceRegister(insn_ptr));
                    }

                    let src_tnum = state.get_reg(insn.src).tnum();
                    let src_range = state.get_reg(insn.src).interval().clone();
                    let dst = state.get_reg_mut(insn.dst);

                    let new_tnum = dst.tnum().or(&src_tnum);
                    let new_range = dst.interval().or(&src_range);
                    dst.set_tnum_interval(new_tnum, new_range);
                }

                // XOR
                ebpf::XOR64_IMM => {
                    let imm_val = insn.imm as i64 as u64;
                    let dst = state.get_reg_mut(insn.dst);

                    let imm_tnum = Tnum::const_val(imm_val);
                    let new_tnum = dst.tnum().xor(imm_tnum);
                    dst.set_tnum(new_tnum);
                }
                ebpf::XOR64_REG => {
                    if !state.get_reg(insn.src).initialized {
                        return Err(VerifierError::InvalidSourceRegister(insn_ptr));
                    }

                    let src_tnum = state.get_reg(insn.src).tnum();
                    let dst = state.get_reg_mut(insn.dst);

                    let new_tnum = dst.tnum().xor(src_tnum);
                    dst.set_tnum(new_tnum);
                }

                // SHIFT: LSH, RSH, ARSH
                ebpf::LSH64_IMM => {
                    let imm_val = insn.imm as u32;
                    let dst = state.get_reg_mut(insn.dst);

                    let dst_tnum = dst.tnum();
                    let imm_tnum = Tnum::const_val(imm_val as u64);
                    let new_tnum = dst_tnum.shl(&imm_tnum);

                    let dst_range = dst.interval();
                    let imm_range = WrappedRange::new_constant(imm_val as u64, 64);
                    let new_range = dst_range.shl(&imm_range);

                    dst.set_tnum_interval(new_tnum, new_range);
                }
                ebpf::LSH64_REG => {
                    if !state.get_reg(insn.src).initialized {
                        return Err(VerifierError::InvalidSourceRegister(insn_ptr));
                    }

                    let src_tnum = state.get_reg(insn.src).tnum();
                    let src_range = state.get_reg(insn.src).interval().clone();
                    let dst = state.get_reg_mut(insn.dst);

                    let new_tnum = dst.tnum().shl(&src_tnum);
                    let new_range = dst.interval().shl(&src_range);
                    dst.set_tnum_interval(new_tnum, new_range);
                }
                ebpf::RSH64_IMM => {
                    let imm_val = insn.imm as u32;
                    let dst = state.get_reg_mut(insn.dst);

                    let dst_tnum = dst.tnum();
                    let imm_tnum = Tnum::const_val(imm_val as u64);
                    let new_tnum = dst_tnum.lshr(&imm_tnum);

                    let dst_range = dst.interval();
                    let new_range = dst_range.lshr_const(imm_val as u64);

                    dst.set_tnum_interval(new_tnum, new_range);
                }
                ebpf::RSH64_REG => {
                    if !state.get_reg(insn.src).initialized {
                        return Err(VerifierError::InvalidSourceRegister(insn_ptr));
                    }

                    let src_tnum = state.get_reg(insn.src).tnum();
                    let dst = state.get_reg_mut(insn.dst);

                    let new_tnum = dst.tnum().lshr(&src_tnum);
                    // Variable shift is imprecise; conservatively use top
                    let new_range = WrappedRange::top(64);
                    dst.set_tnum_interval(new_tnum, new_range);
                }
                ebpf::ARSH64_IMM => {
                    let imm_val = insn.imm as u32;
                    let dst = state.get_reg_mut(insn.dst);

                    let dst_range = dst.interval();
                    let new_range = dst_range.ashr_const(imm_val as u64);

                    let dst_tnum = dst.tnum();
                    let new_tnum = dst_tnum.ashr_const(imm_val as u64);

                    dst.set_tnum_interval(new_tnum, new_range);
                }
                ebpf::ARSH64_REG => {
                    if !state.get_reg(insn.src).initialized {
                        return Err(VerifierError::InvalidSourceRegister(insn_ptr));
                    }

                    let src_range = state.get_reg(insn.src).interval().clone();
                    let dst = state.get_reg_mut(insn.dst);

                    let new_range = dst.interval().ashr(&src_range);
                    let new_tnum = dst.tnum();
                    dst.set_tnum_interval(new_tnum, new_range);
                }

                // NEG
                ebpf::NEG64 if !_sbpf_version.disable_neg() => {
                    let dst = state.get_reg_mut(insn.dst);

                    let dst_tnum = dst.tnum();
                    let new_tnum = dst_tnum.not().add(Tnum::const_val(1));

                    // Negation interval is imprecise; set conservatively to top
                    let new_range = WrappedRange::top(64);

                    dst.set_tnum_interval(new_tnum, new_range);
                }

                // ===== BPF_ALU32_LOAD class =====

                // ADD32
                ebpf::ADD32_IMM => {
                    let imm_val = (insn.imm as i32) as u32;
                    let dst = state.get_reg_mut(insn.dst);

                    let dst_tnum = dst.tnum().cast(4);
                    let imm_tnum = Tnum::const_val(imm_val as u64).cast(4);
                    let new_tnum = dst_tnum.add(imm_tnum);

                    let dst_range = dst.interval().trunc(32);
                    let imm_range = WrappedRange::new_constant(imm_val as u64, 32);
                    let new_range = dst_range.add(&imm_range);

                    dst.set_tnum_interval(new_tnum, new_range);
                }
                ebpf::ADD32_REG => {
                    if !state.get_reg(insn.src).initialized {
                        return Err(VerifierError::InvalidSourceRegister(insn_ptr));
                    }

                    let src_tnum = state.get_reg(insn.src).tnum().cast(4);
                    let src_range = state.get_reg(insn.src).interval().trunc(32);

                    let dst = state.get_reg_mut(insn.dst);
                    let dst_tnum = dst.tnum().cast(4);
                    let new_tnum = dst_tnum.add(src_tnum);

                    let dst_range = dst.interval().trunc(32);
                    let new_range = dst_range.add(&src_range);

                    dst.set_tnum_interval(new_tnum, new_range);
                }

                // SUB32
                ebpf::SUB32_IMM => {
                    let imm_val = (insn.imm as i32) as u32;
                    let dst = state.get_reg_mut(insn.dst);

                    let dst_tnum = dst.tnum().cast(4);
                    let imm_tnum = Tnum::const_val(imm_val as u64).cast(4);
                    let new_tnum = dst_tnum.sub(imm_tnum);

                    let dst_range = dst.interval().trunc(32);
                    let imm_range = WrappedRange::new_constant(imm_val as u64, 32);
                    let new_range = dst_range.sub(&imm_range);

                    dst.set_tnum_interval(new_tnum, new_range);
                }
                ebpf::SUB32_REG => {
                    if !state.get_reg(insn.src).initialized {
                        return Err(VerifierError::InvalidSourceRegister(insn_ptr));
                    }

                    let src_tnum = state.get_reg(insn.src).tnum().cast(4);
                    let src_range = state.get_reg(insn.src).interval().trunc(32);

                    let dst = state.get_reg_mut(insn.dst);
                    let dst_tnum = dst.tnum().cast(4);
                    let new_tnum = dst_tnum.sub(src_tnum);

                    let dst_range = dst.interval().trunc(32);
                    let new_range = dst_range.sub(&src_range);

                    dst.set_tnum_interval(new_tnum, new_range);
                }

                // MUL32
                ebpf::MUL32_IMM if !_sbpf_version.enable_pqr() => {
                    let imm_val = (insn.imm as i32) as u32;
                    let dst = state.get_reg_mut(insn.dst);

                    let dst_tnum = dst.tnum().cast(4);
                    let imm_tnum = Tnum::const_val(imm_val as u64).cast(4);
                    let new_tnum = dst_tnum.mul(imm_tnum);

                    let dst_range = dst.interval().trunc(32);
                    let imm_range = WrappedRange::new_constant(imm_val as u64, 32);
                    let new_range = dst_range.mul(&imm_range);

                    dst.set_tnum_interval(new_tnum, new_range);
                }
                ebpf::MUL32_REG if !_sbpf_version.enable_pqr() => {
                    if !state.get_reg(insn.src).initialized {
                        return Err(VerifierError::InvalidSourceRegister(insn_ptr));
                    }

                    let src_tnum = state.get_reg(insn.src).tnum().cast(4);
                    let src_range = state.get_reg(insn.src).interval().trunc(32);

                    let dst = state.get_reg_mut(insn.dst);
                    let dst_tnum = dst.tnum().cast(4);
                    let new_tnum = dst_tnum.mul(src_tnum);

                    let dst_range = dst.interval().trunc(32);
                    let new_range = dst_range.mul(&src_range);

                    dst.set_tnum_interval(new_tnum, new_range);
                }

                // DIV32
                ebpf::DIV32_IMM if !_sbpf_version.enable_pqr() => {
                    let imm_val = (insn.imm as i32) as u32;
                    if imm_val == 0 {
                        return Err(VerifierError::DivisionByZero(insn_ptr));
                    }

                    let dst = state.get_reg_mut(insn.dst);
                    let dst_tnum = dst.tnum().cast(4);
                    let imm_tnum = Tnum::const_val(imm_val as u64).cast(4);
                    let new_tnum = dst_tnum.udiv(imm_tnum);

                    let dst_range = dst.interval().trunc(32);
                    let imm_range = WrappedRange::new_constant(imm_val as u64, 32);
                    let new_range = dst_range.udiv(&imm_range);

                    dst.set_tnum_interval(new_tnum, new_range);
                }
                ebpf::DIV32_REG if !_sbpf_version.enable_pqr() => {
                    if !state.get_reg(insn.src).initialized {
                        return Err(VerifierError::InvalidSourceRegister(insn_ptr));
                    }

                    let divisor_tnum = state.get_reg(insn.src).tnum().cast(4);
                    let divisor_range = state.get_reg(insn.src).interval().trunc(32);

                    if !divisor_tnum.is_definitely_nonzero() || divisor_range.contains_zero() {
                        return Err(VerifierError::DivisionByZero(insn_ptr));
                    }

                    let src_tnum = state.get_reg(insn.src).tnum().cast(4);
                    let src_range = state.get_reg(insn.src).interval().trunc(32);
                    let dst = state.get_reg_mut(insn.dst);
                    let dst_tnum = dst.tnum().cast(4);
                    let new_tnum = dst_tnum.udiv(src_tnum);

                    let dst_range = dst.interval().trunc(32);
                    let new_range = dst_range.udiv(&src_range);

                    dst.set_tnum_interval(new_tnum, new_range);
                }

                // MOD32
                ebpf::MOD32_IMM if !_sbpf_version.enable_pqr() => {
                    let imm_val = (insn.imm as i32) as u32;
                    if imm_val == 0 {
                        return Err(VerifierError::DivisionByZero(insn_ptr));
                    }

                    let dst = state.get_reg_mut(insn.dst);
                    let dst_tnum = dst.tnum().cast(4);
                    let imm_tnum = Tnum::const_val(imm_val as u64).cast(4);
                    let new_tnum = dst_tnum.urem(imm_tnum);

                    let dst_range = dst.interval().trunc(32);
                    let imm_range = WrappedRange::new_constant(imm_val as u64, 32);
                    let new_range = dst_range.urem(&imm_range);

                    dst.set_tnum_interval(new_tnum, new_range);
                }
                ebpf::MOD32_REG if !_sbpf_version.enable_pqr() => {
                    if !state.get_reg(insn.src).initialized {
                        return Err(VerifierError::InvalidSourceRegister(insn_ptr));
                    }

                    let divisor_tnum = state.get_reg(insn.src).tnum().cast(4);
                    let divisor_range = state.get_reg(insn.src).interval().trunc(32);

                    if !divisor_tnum.is_definitely_nonzero() || divisor_range.contains_zero() {
                        return Err(VerifierError::DivisionByZero(insn_ptr));
                    }

                    let src_tnum = state.get_reg(insn.src).tnum().cast(4);
                    let src_range = state.get_reg(insn.src).interval().trunc(32);
                    let dst = state.get_reg_mut(insn.dst);
                    let dst_tnum = dst.tnum().cast(4);
                    let new_tnum = dst_tnum.urem(src_tnum);

                    let dst_range = dst.interval().trunc(32);
                    let new_range = dst_range.urem(&src_range);

                    dst.set_tnum_interval(new_tnum, new_range);
                }

                // AND32
                ebpf::AND32_IMM => {
                    let imm_val = (insn.imm as i32) as u32;
                    let dst = state.get_reg_mut(insn.dst);

                    let dst_tnum = dst.tnum().cast(4);
                    let imm_tnum = Tnum::const_val(imm_val as u64).cast(4);
                    let new_tnum = dst_tnum.and(&imm_tnum);

                    let dst_range = dst.interval().trunc(32);
                    let imm_range = WrappedRange::new_constant(imm_val as u64, 32);
                    let new_range = dst_range.and(&imm_range);

                    dst.set_tnum_interval(new_tnum, new_range);
                }
                ebpf::AND32_REG => {
                    if !state.get_reg(insn.src).initialized {
                        return Err(VerifierError::InvalidSourceRegister(insn_ptr));
                    }

                    let src_tnum = state.get_reg(insn.src).tnum().cast(4);
                    let src_range = state.get_reg(insn.src).interval().trunc(32);

                    let dst = state.get_reg_mut(insn.dst);
                    let dst_tnum = dst.tnum().cast(4);
                    let new_tnum = dst_tnum.and(&src_tnum);

                    let dst_range = dst.interval().trunc(32);
                    let new_range = dst_range.and(&src_range);

                    dst.set_tnum_interval(new_tnum, new_range);
                }

                // OR32
                ebpf::OR32_IMM => {
                    let imm_val = (insn.imm as i32) as u32;
                    let dst = state.get_reg_mut(insn.dst);

                    let dst_tnum = dst.tnum().cast(4);
                    let imm_tnum = Tnum::const_val(imm_val as u64).cast(4);
                    let new_tnum = dst_tnum.or(&imm_tnum);

                    let dst_range = dst.interval().trunc(32);
                    let imm_range = WrappedRange::new_constant(imm_val as u64, 32);
                    let new_range = dst_range.or(&imm_range);

                    dst.set_tnum_interval(new_tnum, new_range);
                }
                ebpf::OR32_REG => {
                    if !state.get_reg(insn.src).initialized {
                        return Err(VerifierError::InvalidSourceRegister(insn_ptr));
                    }

                    let src_tnum = state.get_reg(insn.src).tnum().cast(4);
                    let src_range = state.get_reg(insn.src).interval().trunc(32);

                    let dst = state.get_reg_mut(insn.dst);
                    let dst_tnum = dst.tnum().cast(4);
                    let new_tnum = dst_tnum.or(&src_tnum);

                    let dst_range = dst.interval().trunc(32);
                    let new_range = dst_range.or(&src_range);

                    dst.set_tnum_interval(new_tnum, new_range);
                }

                // XOR32
                ebpf::XOR32_IMM => {
                    let imm_val = (insn.imm as i32) as u32;
                    let dst = state.get_reg_mut(insn.dst);

                    let dst_tnum = dst.tnum().cast(4);
                    let imm_tnum = Tnum::const_val(imm_val as u64).cast(4);
                    let new_tnum = dst_tnum.xor(imm_tnum);

                    // XOR range is imprecise on WrappedRange; use top conservatively
                    let new_range = WrappedRange::top(32);

                    dst.set_tnum_interval(new_tnum, new_range);
                }
                ebpf::XOR32_REG => {
                    if !state.get_reg(insn.src).initialized {
                        return Err(VerifierError::InvalidSourceRegister(insn_ptr));
                    }

                    let src_tnum = state.get_reg(insn.src).tnum().cast(4);

                    let dst = state.get_reg_mut(insn.dst);
                    let dst_tnum = dst.tnum().cast(4);
                    let new_tnum = dst_tnum.xor(src_tnum);

                    // XOR range is imprecise on WrappedRange; use top conservatively
                    let new_range = WrappedRange::top(32);

                    dst.set_tnum_interval(new_tnum, new_range);
                }

                // MOV32
                ebpf::MOV32_IMM => {
                    let imm_val = (insn.imm as i32) as u32;
                    let dst = state.get_reg_mut(insn.dst);

                    let new_tnum = Tnum::const_val(imm_val as u64).cast(4);
                    let new_range = WrappedRange::new_constant(imm_val as u64, 32);

                    dst.set_tnum_interval(new_tnum, new_range);
                }
                ebpf::MOV32_REG => {
                    if !state.get_reg(insn.src).initialized {
                        return Err(VerifierError::InvalidSourceRegister(insn_ptr));
                    }

                    let src_tnum = state.get_reg(insn.src).tnum().cast(4);
                    let src_range = state.get_reg(insn.src).interval().trunc(32);

                    let dst = state.get_reg_mut(insn.dst);
                    dst.set_tnum_interval(src_tnum, src_range);
                }

                // SHIFT32: LSH, RSH, ARSH
                ebpf::LSH32_IMM => {
                    let imm_val = insn.imm as u32;
                    let dst = state.get_reg_mut(insn.dst);

                    let dst_tnum = dst.tnum().cast(4);
                    let imm_tnum = Tnum::const_val(imm_val as u64).cast(4);
                    let new_tnum = dst_tnum.shl(&imm_tnum);

                    let dst_range = dst.interval().trunc(32);
                    let new_range = dst_range.shl_const(imm_val as u64);

                    dst.set_tnum_interval(new_tnum, new_range);
                }
                ebpf::LSH32_REG => {
                    if !state.get_reg(insn.src).initialized {
                        return Err(VerifierError::InvalidSourceRegister(insn_ptr));
                    }

                    let src_tnum = state.get_reg(insn.src).tnum().cast(4);

                    let dst = state.get_reg_mut(insn.dst);
                    let dst_tnum = dst.tnum().cast(4);
                    let new_tnum = dst_tnum.shl(&src_tnum);

                    // Variable shift amount is imprecise; use top conservatively
                    let new_range = WrappedRange::top(32);

                    dst.set_tnum_interval(new_tnum, new_range);
                }
                ebpf::RSH32_IMM => {
                    let imm_val = insn.imm as u32;
                    let dst = state.get_reg_mut(insn.dst);

                    let dst_tnum = dst.tnum().cast(4);
                    let imm_tnum = Tnum::const_val(imm_val as u64).cast(4);
                    let new_tnum = dst_tnum.lshr(&imm_tnum);

                    let dst_range = dst.interval().trunc(32);
                    let new_range = dst_range.lshr_const(imm_val as u64);

                    dst.set_tnum_interval(new_tnum, new_range);
                }
                ebpf::RSH32_REG => {
                    if !state.get_reg(insn.src).initialized {
                        return Err(VerifierError::InvalidSourceRegister(insn_ptr));
                    }

                    let src_tnum = state.get_reg(insn.src).tnum().cast(4);

                    let dst = state.get_reg_mut(insn.dst);
                    let dst_tnum = dst.tnum().cast(4);
                    let new_tnum = dst_tnum.lshr(&src_tnum);

                    // Variable shift amount is imprecise; use top conservatively
                    let new_range = WrappedRange::top(32);

                    dst.set_tnum_interval(new_tnum, new_range);
                }
                ebpf::ARSH32_IMM => {
                    let imm_val = insn.imm as u32;
                    let dst = state.get_reg_mut(insn.dst);

                    let dst_tnum = dst.tnum().cast(4);
                    let new_tnum = dst_tnum.ashr_const(imm_val as u64);

                    let dst_range = dst.interval().trunc(32);
                    let new_range = dst_range.ashr_const(imm_val as u64);

                    dst.set_tnum_interval(new_tnum, new_range);
                }
                ebpf::ARSH32_REG => {
                    if !state.get_reg(insn.src).initialized {
                        return Err(VerifierError::InvalidSourceRegister(insn_ptr));
                    }

                    let dst = state.get_reg_mut(insn.dst);

                    let new_tnum = Tnum::top_with_width(32);
                    let new_range = WrappedRange::top(32);

                    dst.set_tnum_interval(new_tnum, new_range);
                }

                // NEG32
                ebpf::NEG32 if !_sbpf_version.disable_neg() => {
                    let dst = state.get_reg_mut(insn.dst);

                    let dst_tnum = dst.tnum().cast(4);
                    let new_tnum = dst_tnum.not().add(Tnum::const_val(1)).cast(4);

                    let new_range = WrappedRange::top(32);

                    dst.set_tnum_interval(new_tnum, new_range);
                }

                // ===== BPF_PQR class =====
                ebpf::LMUL32_IMM if _sbpf_version.enable_pqr() => {
                    let imm_val = (insn.imm as i32) as u32;
                    let dst = state.get_reg_mut(insn.dst);

                    let dst_tnum = dst.tnum().cast(4);
                    let imm_tnum = Tnum::const_val(imm_val as u64).cast(4);
                    let new_tnum = dst_tnum.mul(imm_tnum);

                    let dst_range = dst.interval().trunc(32);
                    let imm_range = WrappedRange::new_constant(imm_val as u64, 32);
                    let new_range = dst_range.mul(&imm_range);

                    dst.set_tnum_interval(new_tnum, new_range);
                }
                ebpf::LMUL32_REG if _sbpf_version.enable_pqr() => {
                    if !state.get_reg(insn.src).initialized {
                        return Err(VerifierError::InvalidSourceRegister(insn_ptr));
                    }
                    let src_tnum = state.get_reg(insn.src).tnum().cast(4);
                    let src_range = state.get_reg(insn.src).interval().trunc(32);
                    let dst = state.get_reg_mut(insn.dst);
                    let dst_tnum = dst.tnum().cast(4);
                    let new_tnum = dst_tnum.mul(src_tnum);
                    let dst_range = dst.interval().trunc(32);
                    let new_range = dst_range.mul(&src_range);
                    dst.set_tnum_interval(new_tnum, new_range);
                }
                ebpf::LMUL64_IMM if _sbpf_version.enable_pqr() => {
                    let imm_val = insn.imm as i64 as u64;
                    let dst = state.get_reg_mut(insn.dst);
                    let imm_tnum = Tnum::const_val(imm_val);
                    let new_tnum = dst.tnum().mul(imm_tnum);
                    let imm_range = WrappedRange::new_constant(imm_val, 64);
                    let new_range = dst.interval().mul(&imm_range);
                    dst.set_tnum_interval(new_tnum, new_range);
                }
                ebpf::LMUL64_REG if _sbpf_version.enable_pqr() => {
                    if !state.get_reg(insn.src).initialized {
                        return Err(VerifierError::InvalidSourceRegister(insn_ptr));
                    }
                    let src_tnum = state.get_reg(insn.src).tnum();
                    let src_range = state.get_reg(insn.src).interval().clone();
                    let dst = state.get_reg_mut(insn.dst);
                    let new_tnum = dst.tnum().mul(src_tnum);
                    let new_range = dst.interval().mul(&src_range);
                    dst.set_tnum_interval(new_tnum, new_range);
                }

                ebpf::EXIT => {
                    break;
                }

                _ => {
                    if insn.dst <= 9 {
                        state.set_reg_scalar(insn.dst);
                    }
                }
            }

            insn_ptr += 1;
        }

        Ok(())
    }
}
