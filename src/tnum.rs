//! This is a tnum implementation for Solana eBPF

use std::u64;

fn testbit(val: u64, bit: u8) -> bool {
    if bit >= 64 {
        return false;
    }
    (val & (1u64 << bit)) != 0
}

/// Bitwise operations trait
pub trait BitOps {
    /// Clear low bits (first n bits from LSB)
    fn clear_low_bits(&mut self, n: u32);
    /// Clear high bits (first n bits from MSB)
    fn clear_high_bits(&mut self, n: u32);
}

impl BitOps for u64 {
    fn clear_low_bits(&mut self, n: u32) {
        if n >= 64 {
            *self = 0;
        } else {
            *self &= (!0u64).wrapping_shl(n);
        }
    }

    fn clear_high_bits(&mut self, n: u32) {
        if n >= 64 {
            *self = 0;
        } else {
            *self &= (1u64 << (64 - n)) - 1;
        }
    }
}

// This is for bit-level abstraction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// tnum definition
pub struct Tnum {
    pub value: u64,
    pub mask: u64,
}

impl Tnum {
    /// Create a new instance
    pub fn new(value: u64, mask: u64) -> Self {
        Self { value, mask }
    }

    /// Create a bottom element
    pub fn bottom() -> Self {
        Self::new(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF)
    }

    /// Create a top element
    pub fn top() -> Self {
        Self::new(0, 0xFFFFFFFFFFFFFFFF)
    }

    /// Create a constant tnum instance
    pub fn const_val(value: u64) -> Self {
        Self::new(value, 0)
    }

    /// Check if Tnum is definitely non-zero
    pub fn is_definitely_nonzero(&self) -> bool {
        // If any known bit in value is 1, it's definitely non-zero
        (self.value & !self.mask) != 0
    }

    pub fn from_range(min: u64, max: u64) -> Self {
        let chi = min ^ max;
        // Highest unknown bit
        let bits = (64 - chi.leading_zeros()) as u64;
        // Completely unknown if out of range
        if bits > 63 {
            return Self::new(0, u64::MAX);
        }

        // Unknown bits within range
        let delta = (1u64 << bits) - 1;
        Self::new(min & !delta, delta)
    }

    /// Create Tnum from WrappedRange
    pub fn from_wrapped_range(range: &crate::wrapped_interval::WrappedRange) -> Self {
        // If range is bottom, return bottom
        if range.is_bottom() {
            return Self::bottom();
        }
        
        // If range is top, return top
        if range.is_top() {
            return Self::top();
        }
        
        // Use range bounds to create Tnum
        let min_val = range.lb();
        let max_val = range.ub();
        
        Self::from_range(min_val, max_val)
    }

    /// Get the value field
    pub fn value(&self) -> u64 {
        self.value
    }

    /// Get the mask field
    pub fn mask(&self) -> u64 {
        self.mask
    }

    pub fn is_zero(&self) -> bool {
        self.value == 0 && self.mask == 0
    }
    /// Check if it's bottom (impossible value)
    pub fn is_bottom(&self) -> bool {
        (self.value & self.mask) != 0
    }

    /// Check if it's top (completely unknown value)
    pub fn is_top(&self) -> bool {
        self.value == 0 && self.mask == u64::MAX
    }

    /// Check if it's a subset of another Tnum
    pub fn is_subset_of(&self, other: &Tnum) -> bool {
        // If self is bottom, always a subset
        if self.is_bottom() {
            return true;
        }
        // If other is bottom, only subset if self is also bottom
        if other.is_bottom() {
            return self.is_bottom();
        }
        // If other is top, always a subset
        if other.is_top() {
            return true;
        }
        
        // For tnum, check if all possible values of self are contained in other
        // This requires checking if (self.value | self.mask) is contained in other
        let self_min = self.value;
        let self_max = self.value | self.mask;
        let other_min = other.value;
        let other_max = other.value | other.mask;
        
        // Simplified check: if self's range is within other's range
        self_min >= other_min && self_max <= other_max
    }

    /// Check if it's a definite value (singleton)
    pub fn is_singleton(&self) -> bool {
        self.mask == 0
    }

    /// Check if it's non-negative (MSB is 0)
    pub fn is_nonnegative(&self) -> bool {
        (self.value & (1 << 63)) == 0 && (self.mask & (1 << 63)) == 0
    }

    /// Check if it's negative (MSB is 1)
    pub fn is_negative(&self) -> bool {
        (self.value & (1 << 63)) != 0 && (self.mask & (1 << 63)) == 0
    }

    /// Count leading consecutive zeros
    pub fn countl_zero(&self) -> u32 {
        self.value.leading_zeros()
    }

    /// Count trailing consecutive zeros
    pub fn countr_zero(&self) -> u32 {
        self.value.trailing_zeros()
    }

    /// Count minimum leading consecutive zeros
    pub fn count_min_leading_zeros(&self) -> u32 {
        let max = self.value.wrapping_add(self.mask);
        max.leading_zeros()
    }

    /// Count minimum trailing consecutive zeros
    pub fn count_min_trailing_zeros(&self) -> u32 {
        let max = self.value.wrapping_add(self.mask);
        max.trailing_zeros()
    }

    /// Count maximum leading consecutive zeros
    pub fn count_max_leading_zeros(&self) -> u32 {
        self.value.leading_zeros()
    }

    /// Count maximum trailing consecutive zeros
    pub fn count_max_trailing_zeros(&self) -> u32 {
        self.value.trailing_zeros()
    }

    /// Clear high bits
    pub fn clear_high_bits(&mut self, n: u32) {
        if n >= 64 {
            self.value = 0;
            self.mask = 0;
        } else {
            let mask = (1u64 << (64 - n)) - 1;
            self.value &= mask;
            self.mask &= mask;
        }
    }

    pub fn shl(&self, x: &Tnum) -> Tnum {
        if self.is_bottom() || x.is_bottom() {
            return Tnum::bottom();
        } else if self.is_top() || x.is_top() {
            return Tnum::top();
        }

        if x.is_singleton() {
            return self.shl_const(x.value);
        } else {
            let w = 64u8;
            let mut res = Tnum::top();
            let min_shift_amount = x.value;

            if self.mask == u64::MAX {
                res.value = res.value.wrapping_shl(min_shift_amount as u32);
                res.mask = res.mask.wrapping_shl(min_shift_amount as u32);
                return res;
            }

            let max_value = x.value.wrapping_add(x.mask);
            let len = (self.value | self.mask).leading_zeros() as u64;
            let mut max_res = Tnum::top();

            if len > max_value {
                max_res.mask.clear_high_bits((len - max_value) as u32);
            }

            let max_shift_amount = if max_value > w as u64 {
                w as u64
            } else {
                max_value
            };

            if min_shift_amount == 0 && max_shift_amount == w as u64 {
                println!("[Rust shl] Fast path: shift amount is unknown");
                let min_trailing_zeros = self.count_min_trailing_zeros();
                res.value.clear_low_bits(min_trailing_zeros);
                res.mask.clear_low_bits(min_trailing_zeros);
                return res;
            }

            res.mask = u64::MAX;
            res.value = u64::MAX;
            let mut join_count = 0;

            for i in min_shift_amount..=max_shift_amount {
                if x.value == ((!x.mask) & i) {
                    continue;
                }
                join_count += 1;
                let tmp = self.shl_const(i);
                res = res.or(&tmp);
                if join_count > 8 || res.is_top() {
                    return Tnum::top();
                }
            }

            if res.is_bottom() {
                Tnum::top()
            } else {
                res
            }
        }
    }

    pub fn lshr(&self, x: &Tnum) -> Tnum {
        if self.is_bottom() || x.is_bottom() {
            return Tnum::bottom();
        } else if self.is_top() || x.is_top() {
            return Tnum::top();
        }

        if x.is_singleton() {
            return self.lshr_const(x.value);
        } else {
            let w = 64u8; // Assuming 64-bit
            let mut res = Tnum::top();
            let min_shift_amount = x.value;
            let len = self.value.leading_zeros() as u64;
            let max_value = x.value.wrapping_add(x.mask);
            let max_shift_amount = if max_value > w as u64 {
                w as u64
            } else {
                max_value
            };
            let mut max_res = Tnum::top();
            if (len + x.value) >= w as u64 {
                return Tnum::new(0, 0);
            } else {
                max_res.clear_high_bits((len + x.value) as u32);
            }

            res = Tnum {
                value: u64::MAX,
                mask: u64::MAX,
            };
            let mut join_count = 0;
            for i in min_shift_amount..=max_shift_amount {
                res = res.or(&self.lshr_const(i));
                // join_count += 1;
                if join_count > 6 || res.is_top() {
                    return max_res;
                }
            }
            if res.is_bottom() {
                max_res
            } else {
                res
            }
        }
    }

    /// Tnum addition operation
    pub fn add(&self, other: Self) -> Self {
        // Calculate mask sum - represents mask combination of two unknown numbers
        let sm = self.mask.wrapping_add(other.mask);

        // Calculate sum of definite values
        let sv = self.value.wrapping_add(other.value);

        // sigma = (a.mask + b.mask) + (a.value + b.value)
        // Used to detect carry propagation
        let sigma = sm.wrapping_add(sv);

        // chi = carry propagation bitmask
        // Use XOR to find which bits had carry
        let chi = sigma ^ sv;

        // mu = final unknown bitmask
        // Includes:
        // 1. Uncertainty from carry (chi)
        // 2. Original input unknown bits (a.mask | b.mask)
        let mu = chi | self.mask | other.mask;

        // Return result:
        // value: sum of definite values, excluding all unknown bits (~mu)
        // mask: bitmask of all unknown bits
        Self::new(sv & !mu, mu)
    }

    /// Tnum subtraction operation
    pub fn sub(&self, other: Self) -> Self {
        if self.is_bottom() || other.is_bottom() {
            return Self::bottom();
        } else if self.is_top() || other.is_top() {
            return Self::top();
        }
        let dv = self.value.wrapping_sub(other.value);
        let alpha = dv.wrapping_add(self.mask);
        let beta = dv.wrapping_sub(other.mask);
        let chi = alpha ^ beta;
        let mu = chi | self.mask | other.mask;
        Self::new(dv & !mu, mu)
    }

    /// Tnum XOR operation
    pub fn xor(&self, other: Self) -> Self {
        if self.is_bottom() || other.is_bottom() {
            return Self::bottom();
        } else if self.is_top() || other.is_top() {
            return Self::top();
        }

        let v = self.value ^ other.value;
        let mu = self.mask | other.mask;

        Self::new(v & !mu, mu)
    }

    /// Tnum multiplication operation
    pub fn mul(&self, other: Self) -> Self {
        if self.is_bottom() || other.is_bottom() {
            return Self::bottom();
        } else if self.is_top() || other.is_top() {
            return Self::top();
        }
        let mut a = *self;
        let mut b = other;
        let acc_v = a.value.wrapping_mul(b.value);
        let mut acc_m: Self = Self::new(0, 0);
        while (a.value != 0) || (a.mask != 0) {
            // println!("acc_m.mask:{:?}, acc_m.value:{:?}", acc_m.mask, acc_m.value);
            if (a.value & 1) != 0 {
                acc_m = acc_m.add(Tnum::new(0, b.mask));
            } else if (a.mask & 1) != 0 {
                acc_m = acc_m.add(Tnum::new(0, b.value | b.mask));
            }
            a = a.lshr_const(1);
            b = b.shl_const(1);
        }
        Tnum::new(acc_v, 0).add(acc_m)
    }

    /// Tnum bitwise NOT operation
    pub fn not(&self) -> Self {
        if self.is_bottom() {
            return Self::bottom();
        } else if self.is_top() {
            return Self::top();
        }
        Self::new(!(self.value ^ self.mask), self.mask)
    }

    /// Constant optimization for tnum_mul
    pub fn mul_opt(&self, other: Self) -> Self {
        // If one is a constant
        if self.mask == 0 && self.value.count_ones() == 1 {
            // a.value = 2 ^ x
            other.shl_const(self.value.trailing_zeros() as u64)
        } else if other.mask == 0 && other.value.count_ones() == 1 {
            // a.value = 2 ^ x
            self.shl_const(other.value.trailing_zeros() as u64)
        } else if (self.value | self.mask).count_ones() <= (other.value | other.mask).count_ones() {
            self.mul(other)
        } else {
            other.mul(*self)
        }
    }

    ///computes the w of the tnum domain.
    pub fn join(&self, other: Self) -> Self {
        let v = self.value ^ other.value;
        let m = (self.mask | other.mask) | v;
        Self::new((self.value | other.value) & (!m), m)
    }

    /// [split_at_mu] splits a tnum at the first unknow.
    fn split_at_mu(&self) -> (Self, u32, Self) {
        let i = self.mask.leading_ones();
        let x1 = Self::new(self.value >> (i + 1), self.mask >> (i + 1));
        let x2 = Self::new(self.value & ((1 << i) - 1), self.mask & ((1 << i) - 1));
        (x1, i, x2)
    }

    /// [tnum_mul_const] multiplies a constant [c] by the tnum [x]
    /// which has [j] unknown bits and [n] is the fuel (Z.of_nat n = j).
    fn mul_const(&self, c: u64, n: u64) -> Self {
        if n == 0 {
            Self::new(c.wrapping_mul(self.value), 0)
        } else {
            let (y1, i1, y2) = self.split_at_mu();
            let p = y1.mul_const(c, n - 1);
            let mc = Self::new(c.wrapping_mul(y2.mask), 0);
            let mu0 = p.shl_const((i1 + 1) as u64).add(mc);
            let mu1 = mu0.add(Self::new(c.wrapping_shl(i1 as u32), 0));
            mu0.join(mu1)
        }
    }

    /// [xtnum_mul x i y j] computes the multiplication of
    /// [x]  which has [i] unknown bits by
    /// [y]  which has [j] unknown bits such (i <= j)
    fn xtnum_mul(x: Self, i: u64, y: Self, j: u64) -> Self {
        if i == 0 && j == 0 {
            Self::new(x.value * y.value, 0)
        } else {
            let (y1, i1, y2) = y.split_at_mu(); // y = y1.mu.y2
            let p = if i == j {
                Self::xtnum_mul(y1, j - 1, x, i)
            } else {
                Self::xtnum_mul(x, i, y1, j - 1)
            };
            let mc = x.mul_const(y2.value, i);
            let mu0 = p.shl_const((i1 + 1) as u64).add(mc);
            let mu1 = mu0.add(x.shl_const(i1 as u64));
            mu0.join(mu1)
        }
    }

    /// the top of the xtnum_mul
    pub fn xtnum_mul_top(&self, other: Self) -> Self {
        let i = 64 - self.mask.leading_zeros() as u64;
        let j = 64 - other.mask.leading_zeros() as u64;
        if i <= j {
            Self::xtnum_mul(*self, i, other, j)
        } else {
            Self::xtnum_mul(other, j, *self, i)
        }
    }

    /// clear bit of a tnum
    fn clear_bit(&self, pos: u8) -> Self {
        Self::new(self.value & !(1 << pos), self.mask & !(1 << pos))
    }

    /// bit size of a tnum
    fn size(&self) -> u8 {
        let a = 64 - self.value.leading_zeros();
        let b = 64 - self.mask.leading_zeros();
        if a < b {
            b as u8
        } else {
            a as u8
        }
    }

    /// max 64 of a tnum
    fn max_val(&self) -> u64 {
        self.value | self.mask
    }

    /// [xtnum_mul_high x y n] multiplies x by y
    /// where n is the number of bits that are set in either x or y.
    /// We also have that x <= y and 0 <= x and 0 <= y
    fn xtnum_mul_high(&self, y: Self, n: u8) -> Self {
        if self.mask == 0 && y.mask == 0 {
            //if both are constants, perform normal multiplication
            Self::new(self.value.wrapping_mul(y.value), 0)
        } else if n == 0 {
            //panic!("should not happen");
            Self::new(0, 0) //should not happen
        } else {
            let b = y.size();
            if b == 0 {
                return Self::new(0, 0);
            }
            let ym = testbit(y.mask, b - 1);
            let y_prime = y.clear_bit(b - 1); //clear the highest bit of y
            let p = if y_prime.max_val() <= self.max_val() {
                y_prime.xtnum_mul_high(*self, n - 1)
            } else {
                self.xtnum_mul_high(y_prime, n - 1)
            };
            if ym {
                p.add(self.shl_const((b - 1) as u64)).join(p)
            } else {
                p.add(self.shl_const((b - 1) as u64))
            }
        }
    }

    /// the top level of xtnum_mul_high
    pub fn xtnum_mul_high_top(&self, other: Self) -> Self {
        self.xtnum_mul_high(
            other,
            ((self.value | self.mask).count_ones() + (other.value | other.mask).count_ones()) as u8,
        )
    }

    /// aux function for tnum_mul_rec
    fn decompose(&self) -> (Self, Self) {
        (
            Self::new(self.value >> 1, self.mask >> 1),
            Self::new(self.value & 1, self.mask & 1),
        )
    }

    /// A new tnum_mul proposed by frederic
    pub fn mul_rec(&self, other: Self) -> Self {
        if self.mask == 0 && other.mask == 0 {
            // both are known
            Self::new(self.value * other.value, 0)
        } else if self.mask == u64::MAX && other.mask == u64::MAX {
            //both are unknown
            Self::new(0, u64::MAX)
        } else if (self.value == 0 && self.mask == 0) || (other.value == 0 && other.mask == 0) {
            // mult by 0
            Self::new(0, 0)
        } else if self.value == 1 && self.mask == 0 {
            // mult by 1
            other
        } else if other.value == 1 && other.mask == 0 {
            // mult by 1
            *self
        } else {
            let (a_up, _a_low) = self.decompose();
            let (b_up, _b_low) = other.decompose();
            a_up.mul_rec(b_up)
        }
    }

    /// Tnum intersection operation
    pub fn intersect(&self, other: Self) -> Self {
        let v = self.value | other.value;
        let mu = self.mask & other.mask;
        Self::new(v & !mu, mu)
    }

    /// Tnum truncation to specified byte size
    pub fn cast(&self, size: u8) -> Self {
        // Handle overflow
        let mut result = *self;
        result.value &= (1u64 << (size * 8)) - 1;
        result.mask &= (1u64 << (size * 8)) - 1;
        result
    }

    pub fn is_aligned(&self, size: u64) -> bool {
        (self.value | self.mask) & (size - 1) == (size - 1)
    }

    /// Checks if self contains other
    pub fn contains(&self, other: Self) -> bool {
        if self.is_bottom() {
            false
        } else if other.is_bottom() {
            true
        } else {
            (self.value & !other.mask) == (other.value & !other.mask)
                && (self.mask | other.mask) == self.mask
        }
    }

    /// Convert tnum to string
    pub fn to_sbin(&self, size: usize) -> String {
        let mut result = vec![0u8; size];
        let mut a = *self;

        // Process bits from MSB to LSB
        for n in (1..=64).rev() {
            if n < size {
                result[n - 1] = match (a.mask & 1, a.value & 1) {
                    (1, _) => b'x', // Unknown bit
                    (0, 1) => b'1', // Known bit 1
                    (0, 0) => b'0', // Known bit 0
                    _ => unreachable!(),
                };
            }
            // Right shift for next bit
            a.mask >>= 1;
            a.value >>= 1;
        }

        // Set string termination position
        let end = std::cmp::min(size - 1, 64);
        result[end] = 0;

        // Convert to string
        String::from_utf8(result[..end].to_vec()).unwrap_or_else(|_| String::new())
    }

    pub fn subreg(&self) -> Self {
        self.cast(4)
    }

    pub fn clear_subreg(&self) -> Self {
        self.lshr_const(32).shl_const(32)
    }

    pub fn with_subreg(&self, subreg: Self) -> Self {
        self.clear_subreg().or(&subreg.subreg())
    }

    pub fn with_const_subreg(&self, value: u32) -> Self {
        self.with_subreg(Self::const_val(value as u64))
    }

    /// Signed modulo operation (SRem)
    pub fn srem(&self, other: Self) -> Self {
        // Handle bottom and top cases
        if self.is_bottom() || other.is_bottom() {
            return Self::bottom();
        } else if self.is_top() || other.is_top() {
            return Self::top();
        }

        // Handle singleton case
        if self.is_singleton() && other.is_singleton() {
            let res_single = Tnum::new(
                (self.value as i64).wrapping_rem(other.value as i64) as u64,
                0,
            );
            return res_single;
        }

        // Handle divisor being zero
        if other.value == 0 {
            return Self::top(); // top
        } else {
            let mut res = rem_get_low_bits(self, &other);
            if other.mask == 0
                && (other.value) & 1 == 0
                && ((other.value.trailing_zeros() + other.value.leading_zeros() + 1) == 64)
            {
                let low_bits = other.value - 1;
                if self.is_nonnegative()
                    || (other.value.trailing_zeros() <= self.count_min_trailing_zeros())
                {
                    res.value = low_bits & res.value;
                    res.mask = low_bits & res.mask;
                }
                if self.is_negative() && !(self.value & low_bits) == 0 {
                    res.mask = low_bits & res.mask;
                    res.value = (!low_bits) | res.value;
                }
                return res;
            }
            let leadingz = self.count_min_leading_zeros();
            res.value.clear_high_bits(leadingz);
            res.mask.clear_high_bits(leadingz);
            return res;
        }
    }

    /// Unsigned modulo operation (URem)
    pub fn urem(&self, other: Self) -> Self {
        // Handle bottom and top cases
        if self.is_bottom() || other.is_bottom() {
            return Self::bottom();
        } else if self.is_top() || other.is_top() {
            return Self::top();
        }

        // Handle divisor being zero
        if other.value == 0 {
            return Self::top(); // Division by zero returns top
        }

        let mut res = rem_get_low_bits(self, &other);
        // Handle low bits
        // Check if divisor is a power of 2
        if other.mask == 0
            && !((other.value >> 63) & 1 == 1)
            && ((other.value.trailing_zeros() + other.value.leading_zeros() + 1) == 64)
        {
            // Divisor is power of 2, use bitmask to compute remainder
            let low_bits = other.value - 1; // e.g., 8-1=7(0b111), used as mask
            let res_value = low_bits & self.value;
            let res_mask = low_bits & self.mask;
            return Self::new(res_value, res_mask);
        }

        // General case: result precision is limited
        // Since result is less than or equal to either operand, leading zeros in operands also exist in result
        let leading_zeros = self
            .count_min_leading_zeros()
            .max(other.count_min_leading_zeros());
        res.clear_high_bits(leading_zeros);

        res
    }

    /// Signed division operation
    pub fn signed_div(&self, other: Self) -> Self {
        if self.is_bottom() || other.is_bottom() {
            return Self::bottom();
        }

        let w = 64;

        if self.is_singleton() && other.is_singleton() {
            return Tnum::new(self.value.wrapping_div(other.value), 0);
        }

        if self.is_nonnegative() && other.is_nonnegative() {
            return self.udiv(other);
        }

        let mut result = Self::top();
        let mut tmp: i64 = 0;

        if self.is_negative() && other.is_negative() {
            if self.value == i64::MIN as u64 && other.is_singleton() && other.value == u64::MAX {
                return Self::top();
            }

            let denom = other.get_signed_max_value();
            let num = self.get_signed_min_value();

            if !(num == i64::MIN as u64 && denom == i64::MAX as u64) {
                tmp = (num as i64).wrapping_div(denom as i64);
            } else {
                tmp = i64::MAX;
            }
        } else if self.is_negative() && other.is_nonnegative() {
            // Result is negative if -LHS u>= RHS
            let neg_lhs_max: i64 = (self.get_signed_max_value() as i64).wrapping_neg();
            if neg_lhs_max >= other.get_signed_max_value() as i64 {
                let denom = other.get_signed_min_value();
                let num = self.get_signed_min_value();
                tmp = (num as i64).wrapping_div(denom as i64);
            }
        } else if self.is_nonnegative() && other.is_negative() {
            // Result is negative if LHS u>= -RHS
            let neg_rhs_min = (other.get_signed_min_value() as i64).wrapping_neg();
            if self.get_signed_min_value() >= neg_rhs_min as u64 {
                let denom = other.get_signed_max_value();
                let num = self.get_signed_max_value();
                tmp = (num as i64).wrapping_div(denom as i64);
            }
        }

        if tmp != 0 {
            if (tmp >> 63) & 1 == 0 {
                let lead_zeros = tmp.leading_zeros();
                result.clear_high_bits(lead_zeros);
            } else {
                let lead_ones = (!tmp).leading_zeros();
                if lead_ones > 0 {
                    let high_mask = u64::MAX << (64 - lead_ones);
                    result.value |= high_mask;
                    result.mask &= !high_mask;
                }
            }
        }
        result
    }

    /// Signed division operation
    pub fn sdiv(&self, other: Self) -> Self {
        if self.is_bottom() || other.is_bottom() {
            return Self::bottom();
        }
        if self.is_top() || other.is_top() {
            return Self::top();
        }

        let w = 64;

        if other.value == 0 {
            return Self::top();
        } else if (self.mask == 0 && other.mask == 0) {
            return Self::new(self.value.wrapping_div(other.value), 0);
        }

        let t0 = self.get_zero_circle();
        let t1 = self.get_one_circle();
        let x0 = other.get_zero_circle();
        let x1 = other.get_one_circle();

        let res00 = t0.signed_div(x0);
        let res01 = t0.signed_div(x1);
        let res10 = t1.signed_div(x0);
        let res11 = t1.signed_div(x1);

        res00.or(&res01).or(&res10).or(&res11)
    }

    fn get_signed_min_value(&self) -> u64 {
        if (self.value >> 63) & 1 == 1 {
            self.value | self.mask
        } else {
            self.value
        }
    }

    fn get_signed_max_value(&self) -> u64 {
        if (self.value >> 63) & 1 == 1 {
            self.value
        } else {
            self.value | self.mask
        }
    }

    pub fn get_zero_circle(&self) -> Self {
        let width = 64;
        let sign_max = i64::MAX;
        let value = self.value as i64;
        let mask = self.mask as i64;
        if value & (1i64 << 63) != 0 {
            return Tnum::new(sign_max as u64, sign_max as u64);
        } else if mask & (1i64 << 63) != 0 {
            return Tnum::new(value as u64, (mask & sign_max) as u64);
        } else {
            return *self;
        }
    }

    pub fn get_one_circle(&self) -> Self {
        let value = self.value as i64;
        let mask = self.mask as i64;
        let width = 64;
        let sign_max = i64::MAX;
        let sign_min = i64::MIN;
        let unsign_max = u64::MAX;
        if value &(1i64 << 63) != 0 {
            return *self;
        }else if mask &(1i64 << 63) != 0 {
            let mut value = value;
            value |= (1i64<<63);
            let mut mask = mask;
            mask &= !(1i64<<63);
            return Tnum::new(value as u64,mask as u64);
        }else {
            return Tnum::new(unsign_max,unsign_max);
        }
    }

    /// Unsigned division operation
    pub fn udiv(&self, other: Self) -> Self {
        // Handle bottom and top cases
        if self.is_bottom() || other.is_bottom() {
            return Self::bottom();
        }
        if self.is_top() || other.is_top() {
            return Self::top();
        }

        let w = 64;
        let flag: bool = (other.value == 0);
        if flag {
            // Handle division by zero
            return Self::top();
        } else {
            let mut Res = Tnum::top();
            let MaxRes = match (self.value + self.mask).checked_div(other.value) {
                // If division succeeds, return new Tnum containing the result
                Some(result) => result,
                // If division by zero, checked_div returns None, we return top
                None => return Self::top(),
            };
            let leadz = MaxRes.leading_zeros();
            Res.value.clear_high_bits(leadz);
            Res.mask.clear_high_bits(leadz);
            if (leadz == 64) {
                return Res;
            }
            let result = self.div_compute_low_bit(Res, other);
            return result;
        }
    }

    fn div_compute_low_bit(&self, mut result: Self, other: Self) -> Self {
        // Odd / Odd -> Odd
        if (self.value & 1) != 0 && (self.mask & 1) != 0 {
            result.value |= 1; // Set LSB to 1
            result.mask &= !1;
        }

        let min_tz =
            self.count_min_trailing_zeros() as i32 - other.count_max_trailing_zeros() as i32;
        let max_tz =
            self.count_max_trailing_zeros() as i32 - other.count_min_trailing_zeros() as i32;

        if min_tz >= 0 {
            result.value.clear_low_bits(min_tz as u32);
            result.mask.clear_low_bits(min_tz as u32);

            if min_tz == max_tz {
                // Result has exactly min_tz trailing zeros
                result.value |= 1u64 << min_tz; // Set bit min_tz to 1
                result.mask &= !(1u64 << min_tz); // Clear mask for bit min_tz
            }
        }

        // Check if result is bottom
        if result.is_bottom() {
            return Self::top();
        }

        result
    }

    /// Create bottom element with specified bit width
    pub fn bottom_with_width(width: u32) -> Self {
        let mask = if width >= 64 {
            u64::MAX
        } else {
            (1u64 << width) - 1
        };
        Self::new(mask, mask)
    }

    /// Create top element with specified bit width
    pub fn top_with_width(width: u32) -> Self {
        let mask = if width >= 64 {
            u64::MAX
        } else {
            (1u64 << width) - 1
        };
        Self::new(0, mask)
    }

    pub fn shl_const(&self, k: u64) -> Self {
        // Handle special cases
        if self.is_bottom() {
            return *self;
        }
        if self.is_top() {
            return *self;
        }

        let width = 64; // Fixed bit width
        let shift = k % width as u64; // Ensure shift value is in range, simulate wrapint(k, w)

        Self::new(
            self.value.wrapping_shl(shift as u32),
            self.mask.wrapping_shl(shift as u32),
        )
    }

    pub fn lshr_const(&self, k: u64) -> Self {
        // Handle special cases
        if self.is_bottom() {
            return *self;
        }
        if self.is_top() {
            return *self;
        }

        let width = 64; // Fixed bit width
        let shift = k; // Ensure shift value is in range, simulate wrapint(k, w)

        Self::new(
            self.value.wrapping_shr(shift as u32),
            self.mask.wrapping_shr(shift as u32),
        )
    }

    pub fn ashr_const(&self, k: u64) -> Self {
        // Handle special cases
        if self.is_bottom() {
            return *self;
        }
        if self.is_top() {
            return *self;
        }

        let width = 64; // Fixed bit width
        let shift = k % width as u64; // Ensure shift value is in range, simulate wrapint(k, w)

        // Get sign bit
        let vsig = (self.value >> 63) & 1 == 1;
        let msig = (self.mask >> 63) & 1 == 1;

        // Choose shift strategy based on sign bits
        if !vsig && !msig {
            // Both are non-negative, use logical right shift
            Self::new(
                self.value.wrapping_shr(shift as u32),
                self.mask.wrapping_shr(shift as u32),
            )
        } else if vsig && !msig {
            // Value is negative but mask is non-negative
            Self::new(
                ((self.value as i64).wrapping_shr(shift as u32)) as u64,
                self.mask.wrapping_shr(shift as u32),
            )
        } else {
            // Other cases
            Self::new(
                self.value.wrapping_shr(shift as u32),
                ((self.mask as i64).wrapping_shr(shift as u32)) as u64,
            )
        }
    }

    pub fn le(&self, other: &Tnum) -> bool {
        if other.is_top() || self.is_bottom() {
            return true;
        } else if other.is_bottom() || self.is_top() {
            return false;
        } else if self.value == other.value && self.mask == other.mask {
            return true;
        } else if (self.mask & (!other.mask)) != 0 {
            // self[i] is unknown but other[i] is known
            return false;
        } else {
            return (self.value & (!other.mask)) == other.value;
        }
    }

    /// Equality check (==)
    pub fn eq(&self, other: &Tnum) -> bool {
        self.le(other) && other.le(self)
    }

    pub fn or(&self, other: &Tnum) -> Tnum {
        if self.is_bottom() || other.is_bottom() {
            return Tnum::bottom();
        } else if self.is_top() || other.is_top() {
            return Tnum::top();
        }
        let v = self.value | other.value;
        let mu = self.mask | other.mask;
        Tnum::new(v, mu & (!v))
    }

    pub fn and(&self, other: &Tnum) -> Tnum {
        if self.is_bottom() || other.is_bottom() {
            return Tnum::bottom();
        } else if self.is_top() || other.is_top() {
            return Tnum::top();
        }
        let alpha = self.value | self.mask;
        let beta = other.value | other.mask;
        let v = self.value & other.value;
        Tnum::new(v, (alpha & beta) & (!v))
    }

    /// 16-bit byte swap
    pub fn bswap16(&self) -> Tnum {
        if self.is_bottom() {
            return Tnum::bottom();
        } else if self.is_top() {
            return Tnum::top();
        }

        // Extract low 16 bits
        let low16_value = self.value & 0xFFFF;
        let low16_mask = self.mask & 0xFFFF;

        // Swap bytes: [b1 b0] -> [b0 b1]
        let swapped_value = ((low16_value & 0xFF) << 8) | ((low16_value >> 8) & 0xFF);
        let swapped_mask = ((low16_mask & 0xFF) << 8) | ((low16_mask >> 8) & 0xFF);

        Tnum::new(swapped_value, swapped_mask)
    }

    /// 32-bit byte swap
    pub fn bswap32(&self) -> Tnum {
        if self.is_bottom() {
            return Tnum::bottom();
        } else if self.is_top() {
            return Tnum::top();
        }

        // Extract low 32 bits
        let low32_value = self.value & 0xFFFFFFFF;
        let low32_mask = self.mask & 0xFFFFFFFF;

        // Swap bytes: [b3 b2 b1 b0] -> [b0 b1 b2 b3]
        let swapped_value = ((low32_value & 0xFF) << 24)
            | ((low32_value & 0xFF00) << 8)
            | ((low32_value >> 8) & 0xFF00)
            | ((low32_value >> 24) & 0xFF);

        let swapped_mask = ((low32_mask & 0xFF) << 24)
            | ((low32_mask & 0xFF00) << 8)
            | ((low32_mask >> 8) & 0xFF00)
            | ((low32_mask >> 24) & 0xFF);

        Tnum::new(swapped_value, swapped_mask)
    }

    /// 64-bit byte swap
    pub fn bswap64(&self) -> Tnum {
        if self.is_bottom() {
            return Tnum::bottom();
        } else if self.is_top() {
            return Tnum::top();
        }

        let swapped_value = self.value.swap_bytes();
        let swapped_mask = self.mask.swap_bytes();

        Tnum::new(swapped_value, swapped_mask)
    }

    /// Generic byte swap method
    /// size: 16, 32, or 64
    pub fn bswap(&self, size: u32) -> Tnum {
        match size {
            16 => self.bswap16(),
            32 => self.bswap32(),
            64 => self.bswap64(),
            _ => {
                // Unsupported size, return top
                Tnum::top()
            }
        }
    }
}

pub fn rem_get_low_bits(lhs: &Tnum, rhs: &Tnum) -> Tnum {
    let w = 64u8; // Fixed bit width is 64

    if !rhs.is_zero() && (rhs.value & 1) == 0 && (rhs.mask & 1) == 0 {
        let qzero = rhs.count_min_trailing_zeros();

        if qzero == 0 {
            return Tnum::top();
        }

        let mut mask = if qzero > 1 {
            (1u64 << (qzero - 1)) - 1
        } else {
            0u64
        };
        mask = 0xFFFFFFFFFFFFFFFF;

        let res_value = lhs.value & mask;
        let res_mask = lhs.mask & mask;
        let res = Tnum::new(res_value, res_mask);

        return res;
    }

    Tnum::top()
}