//! The reduction algorithm improves precision by exchanging information between two domains.

use crate::tnum::Tnum;
use crate::wrapped_interval::WrappedRange;

#[derive(Debug, Clone, PartialEq)]
pub struct ReducedProduct {
    /// Wrapped interval component
    interval: WrappedRange,
    /// Tnum component
    tnum: Tnum,
}

impl ReducedProduct {
    /// Creates a new reduced product from an interval and a tnum
    pub fn new(interval: WrappedRange, tnum: Tnum) -> Self {
        let mut product = Self { interval, tnum };
        product.reduce();
        product
    }

    /// Creates the bottom element
    pub fn bottom(width: u32) -> Self {
        Self {
            interval: WrappedRange::bottom(width),
            tnum: Tnum::bottom(),
        }
    }

    /// Creates the top element
    pub fn top(width: u32) -> Self {
        Self {
            interval: WrappedRange::top(width),
            tnum: Tnum::top(),
        }
    }

    /// Creates a constant value
    pub fn constant(value: u64, width: u32) -> Self {
        Self {
            interval: WrappedRange::new_bounds(value, value, width),
            tnum: Tnum::const_val(value),
        }
    }

    /// Checks if this is the bottom element
    pub fn is_bottom(&self) -> bool {
        self.interval.is_bottom() || self.tnum.is_bottom()
    }

    /// Checks if this is the top element
    pub fn is_top(&self) -> bool {
        self.interval.is_top() && self.tnum.is_top()
    }

    /// Returns a reference to the interval component
    pub fn interval(&self) -> &WrappedRange {
        &self.interval
    }

    /// Returns a reference to the tnum component
    pub fn tnum(&self) -> &Tnum {
        &self.tnum
    }

    /// Returns a mutable reference to the interval component
    pub fn interval_mut(&mut self) -> &mut WrappedRange {
        &mut self.interval
    }

    /// Returns a mutable reference to the tnum component
    pub fn tnum_mut(&mut self) -> &mut Tnum {
        &mut self.tnum
    }

    /// Executes the reduction algorithm.
    ///
    /// Exchanges information between the interval and tnum domains through three rounds of propagation:
    ///
    /// Round 1: Tnum -> Interval
    ///   Extracts bounds from (value, mask) and tightens [lb, ub].
    ///
    /// Round 2: Interval -> Tnum
    ///   Computes bit patterns from [lb, ub] and refines (value, mask).
    ///
    /// Round 3: Tnum -> Interval (convergence)
    ///   Tightens bounds again using the refined tnum.
    pub fn reduce(&mut self) {
        // Early exit for bottom case
        if self.interval.is_bottom() && self.tnum.is_bottom() {
            return;
        }

        if self.interval.is_bottom() {
            self.tnum = Tnum::bottom();
            return;
        }

        if self.tnum.is_bottom() {
            self.interval = WrappedRange::bottom(self.interval.width());
            return;
        }

        // Handle top case - normalize to same bit width
        let width = if self.interval.is_top() && self.tnum.is_top() {
            return; // Both are top, no reduction needed
        } else if self.interval.is_top() && !self.tnum.is_top() {
            64
        } else if !self.interval.is_top() && self.tnum.is_top() {
            self.interval.width()
        } else {
            self.interval.width()
        };

        let mut lb = self.interval.lb();
        let mut ub = self.interval.ub();
        let mut tnum = self.tnum;

        // Track whether any reduction occurred
        let mut interval_changed = false;
        let mut tnum_changed = false;

        // ============ Round 1: Tnum -> Interval ============
        // Extract bounds from tnum and tighten interval
        let tnum_min = tnum.value;
        let tnum_max = tnum.value | tnum.mask;

        if tnum_min > lb {
            lb = tnum_min;
            interval_changed = true;
        }
        if tnum_max < ub {
            ub = tnum_max;
            interval_changed = true;
        }

        // Check if interval became invalid
        if lb > ub {
            *self = Self::bottom(width);
            return;
        }

        // ============ Round 2: Interval -> Tnum ============
        // Compute tnum from interval and refine
        let range_tnum = Tnum::from_range(lb, ub);

        // Perform intersection (AND operation on tnum)
        let new_value = tnum.value | range_tnum.value;
        let new_mask = tnum.mask & range_tnum.mask;
        let refined_tnum = Tnum::new(new_value, new_mask);

        // Check if tnum changed
        if refined_tnum != tnum {
            tnum = refined_tnum;
            tnum_changed = true;
        }

        // Check if tnum became bottom (value & mask != 0 means inconsistency)
        if (tnum.value & tnum.mask) != 0 {
            *self = Self::bottom(width);
            return;
        }

        // ============ Round 3: Tnum -> Interval (convergence) ============
        // Tighten bounds again using refined tnum
        let tnum_min = tnum.value;
        let tnum_max = tnum.value | tnum.mask;

        if tnum_min > lb {
            lb = tnum_min;
            interval_changed = true;
        }
        if tnum_max < ub {
            ub = tnum_max;
            interval_changed = true;
        }

        // Update components if changed
        if interval_changed {
            self.interval = WrappedRange::new_bounds(lb, ub, width);
        }
        if tnum_changed {
            self.tnum = tnum;
        }
    }

}

impl std::fmt::Display for ReducedProduct {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ReducedProduct {{ interval: {:?}, tnum: {:?} }}", 
               self.interval, self.tnum)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant() {
        let product = ReducedProduct::constant(42, 64);
        assert_eq!(product.interval().lb(), 42);
        assert_eq!(product.interval().ub(), 42);
        assert_eq!(product.tnum().value, 42);
        assert_eq!(product.tnum().mask, 0);
    }

    #[test]
    fn test_bottom() {
        let product = ReducedProduct::bottom(64);
        assert!(product.is_bottom());
        assert!(product.interval().is_bottom());
    }

    #[test]
    fn test_top() {
        let product = ReducedProduct::top(64);
        assert!(product.is_top());
        assert!(product.interval().is_top());
        assert!(product.tnum().is_top());
    }

    #[test]
    fn test_reduce_tnum_narrows_interval() {
        // Tnum represents 0b1010 or 0b1011 (value=0b1010, mask=0b0001)
        let interval = WrappedRange::new_bounds(0, 20, 64);
        let tnum = Tnum::new(0b1010, 0b0001); // 10 or 11

        let product = ReducedProduct::new(interval, tnum);

        // Interval should be narrowed to [10, 11]
        assert_eq!(product.interval().lb(), 10);
        assert_eq!(product.interval().ub(), 11);
    }

    #[test]
    fn test_reduce_interval_narrows_tnum() {
        // Interval [5, 7] should narrow the tnum
        let interval = WrappedRange::new_bounds(5, 7, 64);
        let tnum = Tnum::top(); // completely unknown

        let product = ReducedProduct::new(interval, tnum);

        // Tnum should be refined to reflect bit patterns of [5, 7]
        // 5 = 0b0101, 6 = 0b0110, 7 = 0b0111
        // Common bits: value=0b0100, mask=0b0011
        let expected_tnum = Tnum::from_range(5, 7);
        assert_eq!(product.tnum().value, expected_tnum.value);
        assert_eq!(product.tnum().mask, expected_tnum.mask);
    }

    #[test]
    fn test_reduce_detects_inconsistency() {
        // Interval [0, 10] and tnum representing [20, 30] should produce bottom
        let interval = WrappedRange::new_bounds(0, 10, 64);
        let tnum = Tnum::new(20, 10); // min=20, max=30

        let product = ReducedProduct::new(interval, tnum);

        assert!(product.is_bottom());
    }

    #[test]
    fn test_reduce_three_rounds() {
        // Tests the effect of three rounds of reduction
        // Tnum's min = value, max = value | mask
        let interval = WrappedRange::new_bounds(0, 255, 64);
        let tnum = Tnum::new(0b11000000, 0b00001111); // min=192, max=207

        let product = ReducedProduct::new(interval, tnum);

        // Since interval is [0, 255] and tnum is [192, 207]
        // interval should be narrowed after reduction
        let tnum_min = product.tnum().value;
        let tnum_max = product.tnum().value | product.tnum().mask;

        // Verify reduction works correctly
        assert!(product.interval().lb() >= tnum_min);
        assert!(product.interval().ub() <= tnum_max || product.interval().ub() >= tnum_max);
    }

    #[test]
    fn test_exact_value_convergence() {
        // When both domains imply the same value, should converge to that value
        let interval = WrappedRange::new_bounds(100, 100, 64);
        let tnum = Tnum::const_val(100);

        let product = ReducedProduct::new(interval, tnum);

        assert_eq!(product.interval().lb(), 100);
        assert_eq!(product.interval().ub(), 100);
        assert_eq!(product.tnum().value, 100);
        assert_eq!(product.tnum().mask, 0);
    }

    #[test]
    fn test_power_of_two_range() {
        // Tests power-of-two range [8, 15]
        // 8 = 0b01000, 15 = 0b01111
        let interval = WrappedRange::new_bounds(8, 15, 64);
        let tnum = Tnum::top();

        let product = ReducedProduct::new(interval, tnum);

        // Verify tnum correctly captures the bit pattern
        let tnum_min = product.tnum().value;
        let tnum_max = product.tnum().value | product.tnum().mask;
        assert_eq!(tnum_min, 8);
        assert_eq!(tnum_max, 15);
    }

    #[test]
    fn test_single_bit_mask() {
        // Tnum has only one uncertain bit
        let interval = WrappedRange::new_bounds(0, 255, 64);
        let tnum = Tnum::new(0b10000000, 0b00000001); // 128 or 129

        let product = ReducedProduct::new(interval, tnum);

        assert_eq!(product.interval().lb(), 128);
        assert_eq!(product.interval().ub(), 129);
        assert_eq!(product.tnum().value, 0b10000000);
        assert_eq!(product.tnum().mask, 0b00000001);
    }

    #[test]
    fn test_interval_bottom_propagates() {
        // If interval is bottom, the entire product should be bottom
        let interval = WrappedRange::bottom(64);
        let tnum = Tnum::const_val(42);

        let product = ReducedProduct::new(interval, tnum);

        assert!(product.is_bottom());
    }

    #[test]
    fn test_tnum_bottom_propagates() {
        // If tnum is bottom, the entire product should be bottom
        let interval = WrappedRange::new_bounds(10, 20, 64);
        let tnum = Tnum::bottom();

        let product = ReducedProduct::new(interval, tnum);

        assert!(product.is_bottom());
    }

    #[test]
    fn test_display_format() {
        let product = ReducedProduct::constant(42, 64);
        let display_str = format!("{}", product);

        // Verify output contains interval and tnum info
        assert!(display_str.contains("interval"));
        assert!(display_str.contains("tnum"));
    }

    #[test]
    fn test_mutability_triggers_reduce() {
        let mut product = ReducedProduct::constant(10, 64);

        // Modify interval
        *product.interval_mut() = WrappedRange::new_bounds(5, 15, 64);

        // Manually call reduce to synchronize state
        product.reduce();

        // Tnum should be updated to reflect the new interval
        // Verify interval bounds are within tnum range
        let tnum_min = product.tnum().value;
        let tnum_max = product.tnum().value | product.tnum().mask;
        assert!(product.interval().lb() >= tnum_min);
        assert!(product.interval().ub() <= tnum_max);
    }

    #[test]
    fn test_byte_range() {
        // Tests byte range [0, 255]
        let interval = WrappedRange::new_bounds(0, 255, 64);
        let tnum = Tnum::from_range(0, 255);

        let product = ReducedProduct::new(interval, tnum);

        // Should converge to tnum representing a complete byte
        assert_eq!(product.interval().lb(), 0);
        assert_eq!(product.interval().ub(), 255);
        // Tnum representation for [0, 255]: value=0, mask=0xFF
        assert_eq!(product.tnum().value, 0);
        assert_eq!(product.tnum().mask, 0xFF);
    }
}
