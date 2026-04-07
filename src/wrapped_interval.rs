//! Wrapped interval implementation for Solana eBPF
//! Based on the paper "A Wrapped Interval Arithmetic" by Jorge A. Navas et al.

use std::cmp::{max, min};
use crate::tnum::Tnum;

/// Trait for checking most significant bit (MSB) status
trait MsbCheck {
    fn is_msb_one(self, width: u32) -> bool;
    fn is_msb_zero(self, width: u32) -> bool;
    fn wrapping_div_signed(self, rhs: Self, width: u32) -> Self;
    fn wrapping_div_unsigned(self, rhs: Self, width: u32) -> Self;
}

/// Represents a wrapped interval with bit width [lb, ub]
#[derive(Debug, Clone, PartialEq)]
pub struct WrappedRange {
    /// Base range
    base: BaseRange,
    /// Whether it's bottom
    is_bottom: bool,
    /// Widening counter
    counter_widening_cannot_doubling: u32,
}

/// Base range type
#[derive(Debug, Clone, PartialEq)]
pub struct BaseRange {
    /// Variable identifier (can be empty)
    var: Option<String>,
    /// State change counter
    num_of_changes: u32,
    /// Whether it's a lattice
    is_lattice: bool,
    /// Whether it's top
    is_top: bool,
    /// Whether it's bottom
    is_bottom: bool,
    /// Lower bound
    lb: u64,
    /// Upper bound
    ub: u64,
    /// Bit width
    width: u32,
    /// Whether it's signed
    is_signed: bool,
}

impl MsbCheck for u64 {
    fn is_msb_one(self, width: u32) -> bool {
        self & (1 << (width - 1)) != 0
    }

    fn is_msb_zero(self, width: u32) -> bool {
        self & (1 << (width - 1)) == 0
    }

    fn wrapping_div_signed(self, rhs: Self, width: u32) -> Self {
        let self_masked = self;
        let rhs_masked = rhs;

        // Check if divisor is zero
        if rhs_masked == 0 {
            panic!("wrapint: signed division by zero");
        }

        let dividend = get_signed_representation(self_masked, 64);
        let divisor = get_signed_representation(rhs_masked, 64);

        let result = dividend / divisor;

        result as u64
    }

    fn wrapping_div_unsigned(self, rhs: Self, width: u32) -> Self {
        let self_masked = self;
        let rhs_masked = rhs;

        // Check if divisor is zero
        if rhs_masked == 0 {
            panic!("wrapint: unsigned division by zero");
        }

        // Perform unsigned division directly
        self_masked / rhs_masked
    }
}

fn get_signed_representation(value: u64, width: u32) -> i64 {
    let masked_value = value;

    if masked_value & (1u64 << 63) != 0 {
        let sign_extended = masked_value | (!u64::MAX); // Set all high bits to 1
        sign_extended as i64
    } else {
        masked_value as i64
    }
}

impl BaseRange {
    fn new_constant(value: u64, width: u32, is_signed: bool) -> Self {
        Self {
            var: None,
            num_of_changes: 0,
            is_lattice: false,
            is_bottom: false,
            is_top: false,
            lb: value,
            ub: value,
            width,
            is_signed,
        }
    }

    fn new_bounds(lb: u64, ub: u64, width: u32, is_signed: bool) -> Self {
        Self {
            var: None,
            num_of_changes: 0,
            is_lattice: false,
            is_top: false,
            is_bottom: false,
            lb,
            ub,
            width,
            is_signed,
        }
    }
}

impl WrappedRange {
    /// Create bottom value
    pub fn bottom(width: u32) -> Self {
        Self {
            base: BaseRange {
                var: None,
                num_of_changes: 0,
                is_lattice: false,
                is_top: false,
                is_bottom: true,
                lb: 0,
                ub: 0,
                width: 64,
                is_signed: false,
            },
            is_bottom: true,
            counter_widening_cannot_doubling: 0,
        }
    }

    /// Check if range contains zero
    pub fn contains_zero(&self) -> bool {
        if self.is_bottom() {
            return false;
        }
        if self.is_top() {
            return true;
        }
        
        let lb = self.lb();
        let ub = self.ub();
        
        // For wrapped range (lb > ub), it contains zero
        if lb > ub {
            return true;
        }
        
        // Non-wrapped range: check if 0 is within [lb, ub]
        lb <= 0 && 0 <= ub
    }

    /// Get start value
    pub fn get_start(&self) -> u64 {
        self.base.lb
    }

    /// Get lower bound
    pub fn lb(&self) -> u64 {
        self.base.lb
    }

    /// Get upper bound
    pub fn ub(&self) -> u64 {
        self.base.ub
    }

    /// Get end value
    pub fn get_end(&self) -> u64 {
        self.base.ub
    }

    /// Create top value
    pub fn top(width: u32) -> Self {
        Self {
            base: BaseRange {
                var: None,
                num_of_changes: 0,
                is_lattice: true,
                is_top: true,
                is_bottom: false,
                lb: 0,
                ub: if width >= 64 {
                    u64::MAX
                } else {
                    (1u64 << width) - 1
                },
                width,
                is_signed: false,
            },
            is_bottom: false,
            counter_widening_cannot_doubling: 0,
        }
    }

    /// Create from constant
    pub fn new_constant(value: u64, width: u32) -> Self {
        Self {
            base: BaseRange::new_constant(value, width, false),
            is_bottom: false,
            counter_widening_cannot_doubling: 0,
        }
    }

    /// Create from bounds
    pub fn new_bounds(lb: u64, ub: u64, width: u32) -> Self {
        Self {
            base: BaseRange::new_bounds(lb, ub, width, false),
            is_bottom: false,
            counter_widening_cannot_doubling: 0,
        }
    }

    /// Create WrappedRange from Tnum
    pub fn from_tnum(tnum: &Tnum, width: u32) -> Self {
        // If tnum is bottom, return bottom
        if tnum.is_bottom() {
            return Self::bottom(width);
        }
        
        // If tnum is top, return top
        if tnum.is_top() {
            return Self::top(width);
        }
        
        // Calculate possible min and max values
        // For tnum, min is value, max is value | mask
        let min_val = tnum.value;
        let max_val = tnum.value | tnum.mask;
        
        // If min and max are equal, create constant
        if min_val == max_val {
            Self::new_constant(min_val, width)
        } else {
            Self::new_bounds(min_val, max_val, width)
        }
    }

    /// Get signed max value 0111...1 (corresponds to C++ get_signed_max)
    pub fn get_signed_max(width: u32) -> u64 {
        ((1u64 << (width - 1)) - 1)
    }

    /// Get signed min value 1000....0 (corresponds to C++ get_signed_min)
    pub fn get_signed_min(width: u32) -> u64 {
        1u64 << (width - 1)
    }

    /// Get unsigned max value 1111....1 (corresponds to C++ get_unsigned_max)
    pub fn get_unsigned_max(width: u32) -> u64 {
        match width {
            8 => 255,         // mod_8 - 1 = 256 - 1
            16 => 65535,      // mod_16 - 1 = 65536 - 1
            32 => 4294967295, // mod_32 - 1 = 4294967296 - 1
            64 => u64::MAX,
            _ => ((1u64 << width) - 1),
        }
    }

    /// Get unsigned min value 0000....0 (corresponds to C++ get_unsigned_min)
    pub fn get_unsigned_min(_width: u32) -> u64 {
        0
    }

    /// Check if bottom
    pub fn is_bottom(&self) -> bool {
        self.base.is_bottom
    }

    /// Check if top
    pub fn is_top(&self) -> bool {
        (!self.base.is_bottom
            && (self.base.ub.wrapping_sub(self.base.lb) == Self::get_unsigned_max(self.base.width)))
    }

    /// Get bit width
    pub fn width(&self) -> u32 {
        self.base.width
    }

    /// Check if singleton range
    pub fn is_singleton(&self) -> bool {
        if self.is_bottom() {
            return false;
        }
        if self.is_top() {
            return false;
        }
        self.base.lb == self.base.ub
    }

    /// Set to bottom
    pub fn make_bottom(&mut self) {
        self.is_bottom = true;
        self.base.is_top = false;
    }

    /// Set to top
    pub fn make_top(&mut self) {
        self.base.is_top = true;
        self.is_bottom = false;
    }

    /// Whether the value is non-negative (min value >= 0)
    pub fn is_nonnegative(&self) -> bool {
        if self.is_bottom() {
            return false;
        }
        self.base.lb >= 0
    }

    /// Whether the value is negative (max value < 0, interpreted as signed)
    pub fn is_negative(&self) -> bool {
        if self.is_bottom() {
            return false;
        }
        // Check if max value is negative (MSB is 1)
        let sign_bit = 1u64 << (self.base.width - 1);
        self.base.ub < sign_bit && self.base.lb >= sign_bit
    }

    /// Whether it is signed
    pub fn is_signed(&self) -> bool {
        self.base.is_signed
    }

    /// Get min value
    pub fn min_value(&self) -> u64 {
        self.base.lb
    }

    /// Get max value
    pub fn max_value(&self) -> u64 {
        self.base.ub
    }

    /// Get signed min value
    pub fn smin_value(&self) -> i64 {
        self.base.lb as i64
    }

    /// Get signed max value
    pub fn smax_value(&self) -> i64 {
        self.base.ub as i64
    }

    /// Get unsigned min value
    pub fn umin_value(&self) -> u64 {
        self.base.lb
    }

    /// Get unsigned max value
    pub fn umax_value(&self) -> u64 {
        self.base.ub
    }

    /// Check if contains a value
    pub fn contains(&self, value: u64) -> bool {
        if self.is_bottom() {
            return false;
        }
        if self.is_top() {
            return true;
        }
        
        // For wrapped interval, need to check if it crosses the boundary
        if self.base.lb <= self.base.ub {
            // Normal interval
            value >= self.base.lb && value <= self.base.ub
        } else {
            // Wrapped interval
            value >= self.base.lb || value <= self.base.ub
        }
    }

    /// Check if subset of another range
    pub fn is_subset_of(&self, other: &WrappedRange) -> bool {
        if self.is_bottom() {
            return true;
        }
        if other.is_bottom() {
            return false;
        }
        if other.is_top() {
            return true;
        }
        
        // Simplified implementation: check if bounds are within other's range
        other.contains(self.base.lb) && other.contains(self.base.ub)
    }

    /// Reset bottom flag
    pub fn reset_bottom_flag(&mut self) {
        self.is_bottom = false;
    }

    /// Reset top flag
    pub fn reset_top_flag(&mut self) {
        self.base.is_top = false;
    }

    /// Calculate cardinality (interval size)
    pub fn cardinality(&self) -> u64 {
        if self.is_bottom {
            return 0;
        }

        if self.base.is_top {
            return if self.base.width >= 64 {
                u64::MAX
            } else {
                1u64 << self.base.width
            };
        }

        // Handle wrapping case
        if self.base.lb <= self.base.ub {
            self.base.ub - self.base.lb + 1
        } else {
            let max_val = if self.base.width >= 64 {
                u64::MAX
            } else {
                (1u64 << self.base.width) - 1
            };

            max_val
                .wrapping_sub(self.base.lb)
                .wrapping_add(self.base.ub)
                .wrapping_add(1)
        }
    }

    pub fn at(&self, value: u64) -> bool {
        if self.is_bottom() {
            return false;
        } else if self.is_top() {
            return true;
        }
        (value.wrapping_sub(self.base.lb)) <= (self.base.ub.wrapping_sub(self.base.lb))
    }

    pub fn signed_split(&self, intervals: &mut Vec<WrappedRange>) {
        if self.is_bottom() {
            return;
        }

        let width = self.base.width;

        if self.is_top() {
            // Top case: split into two maximum half-ranges
            // [0, 2^(N-1)-1] and [2^(N-1), 2^N-1]
            let unsigned_min = Self::get_unsigned_min(width);
            let signed_max = Self::get_signed_max(width);
            let signed_min = Self::get_signed_min(width);
            let unsigned_max = Self::get_unsigned_max(width);

            // First interval: [0, positive max]
            intervals.push(WrappedRange::new_bounds(unsigned_min, signed_max, width));
            // Second interval: [negative min, unsigned max]
            intervals.push(WrappedRange::new_bounds(signed_min, unsigned_max, width));
        } else {
            // Check if crossing signed boundary
            let signed_limit = Self::new_bounds(
                Self::get_signed_max(width),
                Self::get_signed_min(width),
                width,
            );
            if signed_limit.less_or_equal(self) {
                let signed_max = Self::get_signed_max(width);
                let signed_min = Self::get_signed_min(width);

                // Split into two intervals
                // [start, positive max]
                intervals.push(WrappedRange::new_bounds(self.base.lb, signed_max, width));
                // [negative min, end]
                intervals.push(WrappedRange::new_bounds(signed_min, self.base.ub, width));
            } else {
                // Does not cross boundary, add self directly
                intervals.push(self.clone());
            }
        }
    }

    pub fn unsigned_split(&self, intervals: &mut Vec<WrappedRange>) {
        if self.is_bottom() {
            return;
        }

        let width = self.base.width;

        if self.is_top() {
            // For top case, split into two maximum intervals
            intervals.push(Self::new_bounds(
                i64::MIN as u64,
                Self::get_unsigned_max(width),
                width,
            ));
            intervals.push(Self::new_bounds(
                Self::get_unsigned_min(width),
                i64::MAX as u64,
                width,
            ));
        } else {
            // Check if crossing unsigned boundary (wraps from max to min)
            let unsigned_limit = Self::new_bounds(
                Self::get_unsigned_max(width),
                Self::get_unsigned_min(width),
                width,
            );
            if unsigned_limit.less_or_equal(self) {
                intervals.push(Self::new_bounds(
                    self.base.lb,
                    Self::get_unsigned_max(width),
                    width,
                ));
                intervals.push(Self::new_bounds(
                    Self::get_unsigned_min(width),
                    self.base.ub,
                    width,
                ));
            } else {
                intervals.push(self.clone());
            }
        }
    }

    pub fn signed_and_unsigned_split(&self, out: &mut Vec<WrappedRange>) {
        let mut ssplit = Vec::new();
        self.signed_split(&mut ssplit);

        for interval in ssplit {
            interval.unsigned_split(out);
        }
    }

    /// Remove zero from interval, splitting into sub-intervals not containing zero
    pub fn trim_zero(&self, out: &mut Vec<WrappedRange>) {
        let width = self.width();
        let zero = 0u64;

        if !self.is_bottom() && !self.is_singleton_zero() {
            if self.base.lb == zero {
                // If start is zero, return [1, end]
                out.push(WrappedRange::new_bounds(1, self.base.ub, width));
            } else if self.base.ub == zero {
                // If end is zero, return [start, -1] (i.e. [start, u64::MAX])
                let minus_one = Self::get_unsigned_max(width);
                out.push(WrappedRange::new_bounds(self.base.lb, minus_one, width));
            } else if self.at(zero) {
                // If zero is inside interval, split into two: [start, -1] and [1, end]
                let minus_one = Self::get_unsigned_max(width);
                out.push(WrappedRange::new_bounds(self.base.lb, minus_one, width));
                out.push(WrappedRange::new_bounds(1, self.base.ub, width));
            } else {
                // If zero is not in interval, return original interval
                out.push(self.clone());
            }
        }
    }

    /// Check if singleton range containing only zero
    fn is_singleton_zero(&self) -> bool {
        !self.is_bottom() && self.base.lb == 0 && self.base.ub == 0
    }

    /// Check if less than or equal
    pub fn less_or_equal(&self, x: &Self) -> bool {
        if x.is_top() || self.is_bottom() {
            return true;
        } else if x.is_bottom() || self.is_top() {
            return false;
        } else if self.base.lb == x.base.lb && self.base.ub == x.base.ub {
            return true;
        } else {
            return x.at(self.base.lb)
                && x.at(self.base.ub)
                && (!(self.at(x.base.lb)) || !(self.at(x.base.ub)));
        }
    }

    pub fn equal(&self, x: &Self) -> bool {
        self.less_or_equal(x) && x.less_or_equal(self)
    }

    // /// Calculate wrapped cardinality
    // fn w_card(x: u64, y: u64) -> u64 {
    //     if x <= y {
    //         y - x + 1
    //     } else {
    //         // Use wrapping_add to avoid overflow
    //         u64::MAX.wrapping_sub(x).wrapping_add(y).wrapping_add(1)
    //     }
    // }

    /// Wrapping addition
    pub fn add(&self, x: &Self) -> Self {
        // Check bottom case first
        if self.is_bottom() || x.is_bottom() {
            return Self::bottom(64);
        }

        // Check top case
        if self.is_top() || x.is_top() {
            return Self::top(64);
        }

        // [a,b] + [c,d] = [a+c,b+d] if no overflow
        // top           otherwise
        let x_sz = x.base.ub.wrapping_sub(x.base.lb);
        let sz = self.base.ub.wrapping_sub(self.base.lb);
        if x_sz.wrapping_add(sz).wrapping_add(1) <= x_sz {
            return Self::top(64);
        }
        Self::new_bounds(
            self.base.lb.wrapping_add(x.base.lb),
            self.base.ub.wrapping_add(x.base.ub),
            64,
        )
    }

    /// Wrapping subtraction
    pub fn sub(&self, x: &Self) -> Self {
        // Check bottom case first
        if self.is_bottom() || x.is_bottom() {
            return Self::bottom(64);
        }

        // Check top case
        if self.is_top() || x.is_top() {
            return Self::top(64);
        }
        // [a,b] - [c,d] = [a-d,b-c] if no overflow
        // top           otherwise
        let x_sz = x.base.ub.wrapping_sub(x.base.lb);
        let sz = self.base.ub.wrapping_sub(self.base.lb);
        if x_sz.wrapping_add(sz).wrapping_add(1) <= x_sz {
            return Self::top(64);
        }
        Self::new_bounds(
            self.base.lb.wrapping_sub(x.base.ub),
            self.base.ub.wrapping_sub(x.base.lb),
            64,
        )
    }

    /// And operation
    pub fn and(&self, x: &Self) -> Self {
        if self.less_or_equal(x) {
            return self.clone();
        } else if x.less_or_equal(self) {
            return x.clone();
        } else {
            let x_at_self_lb = x.at(self.base.lb);
            if x_at_self_lb {
                let self_at_x_lb = self.at(x.base.lb);
                if self_at_x_lb {
                    let span_a = self.base.ub.wrapping_sub(self.base.lb);
                    let span_b = x.base.ub.wrapping_sub(x.base.lb);
                    if (span_a < span_b) || (span_a == span_b && self.base.lb <= x.base.lb) {
                        return self.clone();
                    } else {
                        return x.clone();
                    }
                } else {
                    let x_at_self_ub = x.at(self.base.ub);
                    if x_at_self_ub {
                        return self.clone();
                    } else {
                        return Self::new_bounds(self.base.lb, x.base.ub, 64);
                    }
                }
            } else {
                let self_at_x_lb = self.at(x.base.lb);

                if self_at_x_lb {
                    let self_at_x_ub = self.at(x.base.ub);

                    if self_at_x_ub {
                        return x.clone();
                    } else {
                        return Self::new_bounds(x.base.lb, self.base.ub, 64);
                    }
                } else {
                    let result = Self::bottom(64);
                    return result;
                }
            }
        }
    }

    pub fn or(&self, x: &Self) -> Self {
        // If both are singletons (constants), compute exact OR result
        if self.is_singleton() && x.is_singleton() {
            let result = self.base.lb | x.base.lb;
            return Self::new_bounds(result, result, 64);
        }
        
        if self.less_or_equal(x) {
            return x.clone();
        } else if x.less_or_equal(self) {
            return self.clone();
        } else {
            if x.at(self.base.lb) && x.at(self.base.ub) && self.at(x.base.lb) && self.at(x.base.ub)
            {
                return Self::top(64);
            } else if x.at(self.base.ub) && self.at(x.base.lb) {
                return Self::new_bounds(self.base.lb, x.base.ub, 64);
            } else if self.at(x.base.ub) && x.at(self.base.lb) {
                return Self::new_bounds(x.base.lb, self.base.ub, 64);
            } else {
                let span_a = x.base.lb.wrapping_sub(self.base.ub);
                let span_b = self.base.lb.wrapping_sub(x.base.ub);
                if (span_a < span_b) || (span_a == span_b && self.base.lb <= x.base.lb) {
                    return Self::new_bounds(self.base.lb, x.base.ub, 64);
                } else {
                    return Self::new_bounds(x.base.lb, self.base.ub, 64);
                }
            }
        }
    }

    /// Unsigned multiplication
    pub fn unsigned_mul(&self, x: &Self) -> Self {
        assert!(!self.is_bottom() && !x.is_bottom());

        let width = self.base.width;
        let mut res = Self::top(width);

        // Check if multiplication will overflow
        let m_start_bignum = self.base.lb as u128;
        let m_end_bignum = self.base.ub as u128;
        let x_start_bignum = x.base.lb as u128;
        let x_end_bignum = x.base.ub as u128;
        let unsigned_max = Self::get_unsigned_max(width) as u128;

        let prod1 = m_end_bignum * x_end_bignum;
        let prod2 = m_start_bignum * x_start_bignum;
        let diff = if prod1 > prod2 {
            prod1 - prod2
        } else {
            prod2 - prod1
        };

        if diff < unsigned_max {
            res = Self::new_bounds(
                self.base.lb.wrapping_mul(x.base.lb),
                self.base.ub.wrapping_mul(x.base.ub),
                width,
            );
        }

        res
    }

    /// Exact meet (intersection) operation
    /// If out is empty, the intersection is empty
    pub fn exact_meet(&self, x: &Self, out: &mut Vec<WrappedRange>) {
        if self.is_bottom() || x.is_bottom() {
            // bottom
            return;
        } else if *self == *x || self.is_top() {
            out.push(x.clone());
        } else if x.is_top() {
            out.push(self.clone());
        } else if x.at(self.base.lb)
            && x.at(self.base.ub)
            && self.at(x.base.lb)
            && self.at(x.base.ub)
        {
            out.push(Self::new_bounds(self.base.lb, x.base.ub, self.base.width));
            out.push(Self::new_bounds(x.base.lb, self.base.ub, self.base.width));
        } else if x.at(self.base.lb) && x.at(self.base.ub) {
            out.push(self.clone());
        } else if self.at(x.base.lb) && self.at(x.base.ub) {
            out.push(x.clone());
        } else if x.at(self.base.lb)
            && x.at(self.base.ub)
            && !x.at(self.base.ub)
            && self.at(x.base.lb)
        {
            out.push(Self::new_bounds(self.base.lb, x.base.ub, self.base.width));
        } else if x.at(self.base.ub)
            && self.at(x.base.lb)
            && !x.at(self.base.lb)
            && self.at(x.base.ub)
        {
            out.push(Self::new_bounds(x.base.lb, self.base.ub, self.base.width));
        } else {
            // bottom - out remains empty
        }
    }

    pub fn reduced_signed_unsigned_mul(&self, x: &Self, out: &mut Vec<WrappedRange>) {
        if self.is_bottom() || x.is_bottom() {
            return;
        }

        let s = self.signed_mul(x);
        let u = self.unsigned_mul(x);
        s.exact_meet(&u, out);
    }

    /// Signed multiplication
    pub fn signed_mul(&self, x: &Self) -> Self {
        assert!(!self.is_bottom() && !x.is_bottom());

        let width = self.base.width;
        let msb_start = self.base.lb.is_msb_one(width);
        let msb_end = self.base.ub.is_msb_one(width);
        let msb_x_start = x.base.lb.is_msb_one(width);
        let msb_x_end = x.base.ub.is_msb_one(width);

        let mut res = Self::top(width);

        if msb_start == msb_end && msb_end == msb_x_start && msb_x_start == msb_x_end {
            // Both intervals are in the same hemisphere
            if !msb_start {
                return self.unsigned_mul(x);
            } else {
                // Check if multiplication will overflow
                let m_start_bignum = self.base.lb as u128;
                let m_end_bignum = self.base.ub as u128;
                let x_start_bignum = x.base.lb as u128;
                let x_end_bignum = x.base.ub as u128;
                let unsigned_max = Self::get_unsigned_max(width) as u128;

                let prod1 = m_start_bignum * x_start_bignum;
                let prod2 = m_end_bignum * x_end_bignum;
                let diff = if prod1 > prod2 {
                    prod1 - prod2
                } else {
                    prod2 - prod1
                };

                if diff < unsigned_max {
                    res = Self::new_bounds(
                        self.base.ub.wrapping_mul(x.base.ub),
                        self.base.lb.wrapping_mul(x.base.lb),
                        width,
                    );
                }
                return res;
            }
        }

        // Each interval cannot cross boundary: one interval is in different hemispheres
        if !(msb_start != msb_end || msb_x_start != msb_x_end) {
            if msb_start && !msb_x_start {
                // Check if multiplication will overflow
                let m_start_bignum = self.base.lb as u128;
                let m_end_bignum = self.base.ub as u128;
                let x_start_bignum = x.base.lb as u128;
                let x_end_bignum = x.base.ub as u128;
                let unsigned_max = Self::get_unsigned_max(width) as u128;

                let mul1 = m_end_bignum * x_start_bignum;
                let mul2 = m_start_bignum * x_end_bignum;
                if mul1 >= mul2 && mul1 - mul2 < unsigned_max {
                    res = Self::new_bounds(
                        self.base.lb.wrapping_mul(x.base.ub),
                        self.base.ub.wrapping_mul(x.base.lb),
                        width,
                    );
                }
            } else if !msb_start && msb_x_start {
                // Check if multiplication will overflow
                let m_start_bignum = self.base.lb as u128;
                let m_end_bignum = self.base.ub as u128;
                let x_start_bignum = x.base.lb as u128;
                let x_end_bignum = x.base.ub as u128;
                let unsigned_max = Self::get_unsigned_max(width) as u128;

                let mul1 = m_start_bignum * x_end_bignum;
                let mul2 = m_end_bignum * x_start_bignum;
                if mul1 >= mul2 && mul1 - mul2 < unsigned_max {
                    res = Self::new_bounds(
                        self.base.ub.wrapping_mul(x.base.lb),
                        self.base.lb.wrapping_mul(x.base.ub),
                        width,
                    );
                }
            }
        }

        res
    }

    /// Multiplication
    pub fn mul(&self, x: &Self) -> Self {
        if self.is_bottom() || x.is_bottom() {
            return Self::bottom(self.base.width);
        }
        if self.is_top() || x.is_top() {
            return Self::top(self.base.width);
        } else {
            let mut cuts = Vec::new();
            let mut x_cuts = Vec::new();

            self.signed_and_unsigned_split(&mut cuts);
            x.signed_and_unsigned_split(&mut x_cuts);

            assert!(!cuts.is_empty());
            assert!(!x_cuts.is_empty());

            let mut res = Self::bottom(self.base.width);
            for cut in &cuts {
                for x_cut in &x_cuts {
                    let mut exact_reduct = Vec::new();
                    cut.reduced_signed_unsigned_mul(x_cut, &mut exact_reduct);
                    for interval in exact_reduct {
                        res = res.or(&interval);
                    }
                }
            }

            res
        }
    }

    /// Signed division
    pub fn signed_div(&self, x: &Self) -> Self {
        assert!(!x.at(0));
        assert!(!self.is_bottom() && !x.is_bottom());

        let width = self.width();
        let msb_start = self.base.lb.is_msb_one(width);
        let msb_x_start = x.base.lb.is_msb_one(width);

        let smin = Self::get_signed_min(width);
        let minus_one = Self::get_unsigned_max(width); // -1 in two's complement

        let mut res = Self::top(width);

        if msb_start == msb_x_start {
            if msb_start {
                // Both are negative
                // Check if division will overflow
                if !((self.base.ub == smin && x.base.lb == minus_one)
                    || (self.base.lb == smin && x.base.ub == minus_one))
                {
                    res = Self::new_bounds(
                        self.base.ub.wrapping_div_signed(x.base.lb, width),
                        self.base.lb.wrapping_div_signed(x.base.ub, width),
                        width,
                    );
                }
            } else {
                // Both are positive
                // Check if division will overflow
                if !((self.base.lb == smin && x.base.ub == minus_one)
                    || (self.base.ub == smin && x.base.lb == minus_one))
                {
                    res = Self::new_bounds(
                        self.base.lb.wrapping_div_signed(x.base.ub, width),
                        self.base.ub.wrapping_div_signed(x.base.lb, width),
                        width,
                    );
                }
            }
        } else {
            if msb_start {
                // self is negative, x is positive
                // Check if division will overflow
                if !((self.base.lb == smin && x.base.lb == minus_one)
                    || (self.base.ub == smin && x.base.ub == minus_one))
                {
                    res = Self::new_bounds(
                        self.base.lb.wrapping_div_signed(x.base.lb, width),
                        self.base.ub.wrapping_div_signed(x.base.ub, width),
                        width,
                    );
                }
            } else {
                // self is positive, x is negative
                // Check if division will overflow
                if !((self.base.ub == smin && x.base.ub == minus_one)
                    || (self.base.lb == smin && x.base.lb == minus_one))
                {
                    res = Self::new_bounds(
                        self.base.ub.wrapping_div_signed(x.base.ub, width),
                        self.base.lb.wrapping_div_signed(x.base.lb, width),
                        width,
                    );
                }
            }
        }

        res
    }

    /// Signed division operation
    pub fn sdiv(&self, x: &Self) -> Self {
        if self.is_bottom() || x.is_bottom() {
            return Self::bottom(self.width());
        }
        if self.is_top() || x.is_top() {
            return Self::top(self.width());
        } else {
            let mut cuts = Vec::new();
            let mut x_cuts = Vec::new();

            self.signed_and_unsigned_split(&mut cuts);
            x.signed_and_unsigned_split(&mut x_cuts);

            assert!(!cuts.is_empty());
            assert!(!x_cuts.is_empty());

            let mut res = Self::bottom(self.width());
            for cut in &cuts {
                for x_cut in &x_cuts {
                    let mut trimmed_divisors = Vec::new();
                    x_cut.trim_zero(&mut trimmed_divisors);
                    for divisor in trimmed_divisors {
                        res = res.or(&cut.signed_div(&divisor));
                    }
                }
            }

            res
        }
    }

    pub fn unsigned_div(&self, x: &Self) -> Self {
        assert!(!x.at(0));
        assert!(!self.is_bottom() && !x.is_bottom());
        let res = Self::new_bounds(
            self.base.lb.wrapping_div_unsigned(x.base.ub, self.width()),
            self.base.ub.wrapping_div_unsigned(x.base.lb, self.width()),
            self.width(),
        );
        res
    }

    /// Unsigned division operation
    pub fn udiv(&self, x: &Self) -> Self {
        if self.is_bottom() || x.is_bottom() {
            return Self::bottom(self.width());
        }
        if self.is_top() || x.is_top() {
            return Self::top(self.width());
        } else {
            let mut cuts = Vec::new();
            let mut x_cuts = Vec::new();

            self.signed_split(&mut cuts);
            x.signed_split(&mut x_cuts);

            assert!(!cuts.is_empty());
            assert!(!x_cuts.is_empty());

            let mut res = Self::bottom(self.width());
            for cut in &cuts {
                for x_cut in &x_cuts {
                    let mut trimmed_divisors = Vec::new();
                    x_cut.trim_zero(&mut trimmed_divisors);
                    for divisor in trimmed_divisors {
                        res = res.or(&cut.unsigned_div(&divisor));
                    }
                }
            }

            res
        }
    }

    pub fn default_implementation(&self, x: &Self) -> Self {
        if self.is_bottom() || x.is_bottom() {
            return Self::bottom(self.width());
        } else {
            return Self::top(self.width());
        }
    }

    pub fn urem(&self, x: &Self) -> Self {
        self.default_implementation(x)
    }

    pub fn srem(&self, x: &Self) -> Self {
        self.default_implementation(x)
    }

    /// Truncate function - fully consistent with C++ implementation
    pub fn trunc(&self, bits_to_keep: u32) -> Self {
        if self.is_bottom() || self.is_top() {
            return self.clone();
        }

        let w = self.width();

        let start_high = self.lb() >> bits_to_keep;
        let end_high = self.ub() >> bits_to_keep;

        if start_high == end_high {
            let mask = (1u64 << bits_to_keep) - 1; // Standard low-bit mask
            let lower_start = self.lb() & mask;
            let lower_end = self.ub() & mask;

            if lower_start <= lower_end {
                return Self::new_bounds(lower_start, lower_end, w);
            }
        } else {
            let y = start_high.wrapping_add(1);
            if y == end_high {
                let mask = (1u64 << bits_to_keep) - 1;
                let lower_start = self.lb() & mask;
                let lower_end = self.ub() & mask;

                if !(lower_start <= lower_end) {
                    return Self::new_bounds(lower_start, lower_end, w);
                }
            }
        }

        // Return top for other cases
        Self::top(w)
    }

    // Constant left shift
    pub fn shl_const(&self, k: u64) -> Self {
        if self.is_bottom() {
            return self.clone();
        }

        if self.is_top() {
            return self.clone();
        }

        let b = self.width();
        let truncated = self.trunc(b - k as u32);

        if !truncated.is_top() {
            let start = self.lb() << k;
            let end = self.ub() << k;
            Self::new_bounds(start, end, b)
        } else {
            Self::top(b)
        }
    }

    // Interval left shift
    pub fn shl(&self, x: &Self) -> Self {
        if self.is_bottom() {
            return self.clone();
        }

        // Only execute when shift amount is singleton
        if x.is_singleton() {
            self.shl_const(x.lb())
        } else {
            Self::top(self.width())
        }
    }

    
    pub fn lshr_const(&self, k: u64) -> Self {
        if self.is_bottom() {
            return self.clone();
        }
        // Must check is_top first, then call cross_unsigned_limit
        if self.is_top() {
            return self.clone();
        }
        if !self.cross_unsigned_limit() {
            // b = bit width
            let b = self.width();
            // Logical right shift of interval endpoints
            let new_lb = self.lb() >> k;
            let new_ub = self.ub() >> k;
            Self::new_bounds(new_lb, new_ub, b)
        } else {
            Self::top(self.width())
        }
    }

    // Arithmetic right shift (constant)
    pub fn ashr_const(&self, k: u64) -> Self {
        if self.is_bottom() {
            return self.clone();
        }

        if self.is_top() {
            return self.clone();
        }

        if !self.cross_signed_limit() {
            let b = self.width();
            let start_result = self.lb() >> k;
            let end_result = self.ub() >> k;
            Self::new_bounds(start_result, end_result, b)
        } else {
            Self::top(self.width())
        }
    }

    // Arithmetic right shift (constant)
    pub fn ashr(&self, x: &Self) -> Self {
        if self.is_bottom() {
            return self.clone();
        }

        // Only execute when shift amount is singleton
        if x.is_singleton() {
            self.ashr_const(x.lb())
        } else {
            Self::top(self.width())
        }
    }

    // Check if crosses signed limit
    pub fn cross_signed_limit(&self) -> bool {
        if self.is_bottom() || self.is_top() {
            return false;
        }

        let signed_limit = self.signed_limit(self.width());
        self.contains_interval(&signed_limit)
    }

    // Check if crosses unsigned limit
    fn cross_unsigned_limit(&self) -> bool {
        if self.is_bottom() || self.is_top() {
            return false;
        }

        let unsigned_limit = self.unsigned_limit(self.width());
        self.contains_interval(&unsigned_limit)
    }

    // Check if current interval contains another interval
    fn contains_interval(&self, other: &Self) -> bool {
        if self.is_bottom() {
            return false;
        }
        if other.is_bottom() {
            return true;
        }
        if self.is_top() {
            return true;
        }
        if other.is_top() {
            return false;
        }

        // Wrapped intervals need special handling
        if self.base.lb <= self.base.ub {
            // Current interval is not wrapped
            if other.base.lb <= other.base.ub {
                // Other interval is also not wrapped
                self.base.lb <= other.base.lb && other.base.ub <= self.base.ub
            } else {
                // Other interval is wrapped, current interval cannot contain it
                false
            }
        } else {
            // Current interval is wrapped
            if other.base.lb <= other.base.ub {
                // Other interval is not wrapped
                other.base.lb >= self.base.lb || other.base.ub <= self.base.ub
            } else {
                // Both intervals are wrapped
                self.base.lb <= other.base.lb && other.base.ub <= self.base.ub
            }
        }
    }

    // Return signed limit interval [signed_max, signed_min]
    pub fn signed_limit(&self, width: u32) -> Self {
        let signed_max = Self::get_signed_max(width);
        let signed_min = Self::get_signed_min(width);
        Self::new_bounds(signed_max, signed_min, width)
    }

    // Return unsigned limit interval [unsigned_max, unsigned_min]
    fn unsigned_limit(&self, width: u32) -> Self {
        let unsigned_max = Self::get_unsigned_max(width);
        let unsigned_min = Self::get_unsigned_min(width);
        Self::new_bounds(unsigned_max, unsigned_min, width)
    }

    /// 16-bit byte swap (endianness conversion)
    /// Uses byte boundary analysis algorithm, O(1) complexity
    pub fn bswap16(&self) -> Self {
        // 1. Handle base cases
        if self.is_bottom() {
            return Self::bottom(self.width());
        }

        if self.is_top() {
            return Self::top(self.width());
        }

        // 2. Handle singleton intervals (constants)
        if self.is_singleton() {
            let swapped = self.base.lb.swap_bytes() >> 48; // Keep only low 16-bit swap result
            return Self::new_constant(swapped, self.width());
        }

        // 3. Determine candidate points
        let mut candidates = Vec::new();
        let lb = self.base.lb & 0xFFFF; // Only consider low 16 bits
        let ub = self.base.ub & 0xFFFF;

        // Add original boundaries
        candidates.push(lb);
        candidates.push(ub);

        // High byte equal case
        let upper = ub | 0x00FF;
        if upper >= lb && upper <= ub {
            candidates.push(upper);
        }

        // High byte of ub greater than high byte of lb
        let upper = (upper & 0xff00).wrapping_sub(0x0100) | 0x00ff;
        if upper > lb && upper <= ub && upper != 0 {
            candidates.push(upper);
        }

        // High byte equal case
        let lower = lb;
        if lower >= lb && lower <= ub {
            candidates.push(lower);
        }

        // High byte of ub greater than high byte of lb
        let lower = ((lb & 0xFF00).wrapping_add(0x0100)) & 0xFF00;
        if lower >= lb && lower <= ub {
            candidates.push(lower);
        }

        // 4. Compute swapped values
        let mut swapped_values: Vec<u64> = candidates
            .iter()
            .map(|&v| {
                let bytes = v.to_le_bytes();
                u16::from_be_bytes([bytes[0], bytes[1]]) as u64
            })
            .collect();

        // 5. Find new interval bounds
        if swapped_values.is_empty() {
            return Self::top(self.width());
        }

        let new_min = *swapped_values.iter().min().unwrap();
        let new_max = *swapped_values.iter().max().unwrap();

        // 6. Return result
        Self::new_bounds(new_min, new_max, self.width())
    }
    
    /// 32-bit byte swap (endianness conversion)
    /// Uses byte boundary analysis algorithm, O(1) complexity
    pub fn bswap32(&self) -> Self {
        // 1. Handle base cases
        if self.is_bottom() {
            return Self::bottom(self.width());
        }

        if self.is_top() {
            return Self::top(self.width());
        }

        // 2. Handle singleton intervals (constants)
        if self.is_singleton() {
            let swapped = (self.base.lb as u32).swap_bytes() as u64;
            return Self::new_constant(swapped, self.width());
        }

        // 3. Determine candidate points
        let mut candidates = Vec::new();
        let lb = self.base.lb & 0xFFFFFFFF; // Only consider low 32 bits
        let ub = self.base.ub & 0xFFFFFFFF;

        // Add original boundaries
        candidates.push(lb);
        candidates.push(ub);
        println!("bswap32: lb={:#x}, ub={:#x}", lb, ub);

        for i in (0..3).rev() {
            if ub & (0xFF << (i * 8)) != lb & (0xFF << (i * 8)) {
                let upper = (((ub & (!0u64 >> (i * 8)) << (i * 8))) - (0x01 << (i * 8))) | ((1 << (i * 8)) - 1);
                if upper >= lb && upper <= ub {
                    candidates.push(upper);
                    break;
                }
            }
        }

        for i in (0..3).rev() {
            if ub & (0xFF << (i * 8)) != lb & (0xFF << (i * 8)) {
                let lower = ((lb & (0xFF << (i * 8))) + (0x01 << (i * 8)));
                if lower >= lb && lower <= ub {
                    candidates.push(lower);
                    break;
                }
            }
        }

        // 4. Compute swapped values
        let mut swapped_values: Vec<u64> = candidates
            .iter()
            .map(|&v| (v as u32).swap_bytes() as u64)
            .collect();

        // 5. Find new interval bounds
        if swapped_values.is_empty() {
            return Self::top(self.width());
        }

        let new_min = *swapped_values.iter().min().unwrap();
        let new_max = *swapped_values.iter().max().unwrap();

        // 6. Return result
        Self::new_bounds(new_min, new_max, self.width())
    }
    
    /// 64-bit byte swap (endianness conversion)
    /// Uses byte boundary analysis algorithm, O(1) complexity
    pub fn bswap64(&self) -> Self {
        // 1. Handle base cases
        if self.is_bottom() {
            return Self::bottom(self.width());
        }

        if self.is_top() {
            return Self::top(self.width());
        }

        // 2. Handle singleton intervals (constants)
        if self.is_singleton() {
            let swapped = self.base.lb.swap_bytes();
            return Self::new_constant(swapped, self.width());
        }

        // 3. Determine candidate points
        let mut candidates = Vec::new();
        let lb = self.base.lb;
        let ub = self.base.ub;

        // Add original boundaries
        candidates.push(lb);
        candidates.push(ub);

        for i in (0..8).rev() {
            if ub & (0xFF << (i * 8)) != lb & (0xFF << (i * 8)) {
                // Compute value with current byte position decremented by 1, low bits all 0xFF
                // Use (1u64 << (i*8)) - 1 instead of right shift to avoid 64-bit shift overflow when i=0
                let mask_high = if i < 8 { !0u64 << (i * 8) } else { 0 };
                let mask_low = if i > 0 { (1u64 << (i * 8)) - 1 } else { 0 };
                let upper = ((ub & mask_high) - (0x01 << (i * 8))) | mask_low;
                println!("bswap64: i={}, upper={:#x}", i, upper);

                    candidates.push(upper);
                break;
            }
        }

        for i in (0..8).rev() {
            if ub & (0xFF << (i * 8)) != lb & (0xFF << (i * 8)) {
                let mask_high = if i < 8 { !0u64 << (i * 8) } else { 0 };
                let mask_low = if i > 0 { (1u64 << (i * 8)) - 1 } else { 0 };
                let lower = (lb & mask_high) + (0x01 << (i * 8));

                    candidates.push(lower);
                break;
            }
        }

        // 4. Compute swapped values
        let mut swapped_values: Vec<u64> = candidates
            .iter()
            .map(|&v| v.swap_bytes())
            .collect();

        // 5. Find new interval bounds
        if swapped_values.is_empty() {
            return Self::top(self.width());
        }

        let new_min = *swapped_values.iter().min().unwrap();
        let new_max = *swapped_values.iter().max().unwrap();

        // 6. Return result
        Self::new_bounds(new_min, new_max, self.width())
    }
    
    /// 64-bit byte swap - recursive version
    /// Uses recursive byte boundary analysis algorithm, O(1) complexity
    pub fn bswap64_recursive(&self) -> Self {
        // 1. Handle base cases
        if self.is_bottom() {
            return Self::bottom(self.width());
        }

        if self.is_top() {
            return Self::top(self.width());
        }

        // 2. Handle singleton intervals (constants)
        if self.is_singleton() {
            let swapped = self.base.lb.swap_bytes();
            return Self::new_constant(swapped, self.width());
        }

        let lb = self.base.lb;
        let ub = self.base.ub;

        // 3. Use recursive algorithm to compute max and min
        let max_result = self.find_max_recursive(lb, ub, 7, 0);
        let min_result = self.find_min_recursive(lb, ub, 7, 0);

        // 4. Return result
        Self::new_bounds(min_result, max_result, self.width())
    }

    /// Recursively find maximum value
    /// x: lower bound, y: upper bound, n: current byte index to check (7 to 0), m: number of matched bytes
    fn find_max_recursive(&self, x: u64, y: u64, n: i32, m: i32) -> u64 {
        if n < 0 {
            // All bytes are identical, return bswap(y) directly
            return y.swap_bytes();
        }

        let bi = n * 8; // Bit index of the n-th byte
        let byte_mask = 0xFFu64 << bi;

        // Check if the n-th byte is the same
        if (x & byte_mask) == (y & byte_mask) {
            // Bytes are the same, continue recursive check on next byte
            return self.find_max_recursive(x, y, n - 1, m + 1);
        } else {
            // Found first differing byte
            let low_mask = if bi > 0 { (1u64 << bi) - 1 } else { 0 };

            // Check if low bits of y are all 0xFF
            if (y & low_mask) == low_mask {
                // carry = 0: low bits already all FF, directly bswap
                return self.partial_bswap(y, n + m);
            } else {
                // carry = 1: need to decrement n-th byte by 1, low bits all set to FF
                let high_mask = !low_mask;
                let adjusted = ((y & high_mask) - (1u64 << bi)) | low_mask;
                return self.partial_bswap(adjusted, n + m);
            }
        }
    }

    /// Recursively find minimum value
    /// x: lower bound, y: upper bound, n: current byte index to check (7 to 0), m: number of matched bytes
    fn find_min_recursive(&self, x: u64, y: u64, n: i32, m: i32) -> u64 {
        if n < 0 {
            // All bytes are identical, return bswap(x) directly
            return x.swap_bytes();
        }

        let bi = n * 8; // Bit index of the n-th byte
        let byte_mask = 0xFFu64 << bi;

        // Check if the n-th byte is the same
        if (x & byte_mask) == (y & byte_mask) {
            // Bytes are the same, continue recursive check on next byte
            return self.find_min_recursive(x, y, n - 1, m + 1);
        } else {
            // Found first differing byte
            let low_mask = if bi > 0 { (1u64 << bi) - 1 } else { 0 };

            // Check if low bits of x are all 0
            if (x & low_mask) == 0 {
                // carry = 0: low bits already all 0, directly bswap
                return self.partial_bswap(x, n + m);
            } else {
                // carry = 1: need to increment n-th byte by 1, low bits all set to 0
                let high_mask = !low_mask;
                let adjusted = (x & high_mask) + (1u64 << bi);
                return self.partial_bswap(adjusted, n + m);
            }
        }
    }
    
    fn partial_bswap(&self, value: u64, k: i32) -> u64 {
        if k >= 7 {
            return value.swap_bytes();
        }
        value.swap_bytes()
    }
}
