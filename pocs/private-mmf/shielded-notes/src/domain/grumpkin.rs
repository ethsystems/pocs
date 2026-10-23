//! Grumpkin, the curve embedded in BN254: y^2 = x^3 - 17 over BN254's scalar
//! field, so its coordinates are native field elements. Only what the register
//! feed needs: affine addition and scalar multiplication. Matches Noir's
//! `std::embedded_curve_ops`, generator included.

use std::sync::LazyLock;

use ark_bn254::Fr;
use ark_ff::{
    AdditiveGroup,
    Field,
    Zero,
};
use num_bigint::BigUint;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Point {
    pub x: Fr,
    pub y: Fr,
    pub infinity: bool,
}

/// Noir's embedded-curve generator: (1, sqrt(-16)).
pub static GENERATOR: LazyLock<Point> = LazyLock::new(|| Point {
    x: Fr::from(1u64),
    y: Fr::from(
        BigUint::parse_bytes(
            b"17631683881184975370165255887551781615748388533673675138860",
            10,
        )
        .expect("valid decimal literal"),
    ),
    infinity: false,
});

impl Point {
    pub const INFINITY: Point = Point {
        x: Fr::ZERO,
        y: Fr::ZERO,
        infinity: true,
    };

    pub fn new(x: Fr, y: Fr) -> Self {
        Self {
            x,
            y,
            infinity: false,
        }
    }

    pub fn is_on_curve(&self) -> bool {
        self.infinity || self.y.square() == self.x.square() * self.x - Fr::from(17u64)
    }

    fn double(&self) -> Self {
        if self.infinity || self.y.is_zero() {
            return Self::INFINITY;
        }
        let lambda = (self.x.square() * Fr::from(3u64))
            * (self.y.double())
                .inverse()
                .expect("y = 0 returned the point at infinity above");
        let x3 = lambda.square() - self.x.double();
        let y3 = lambda * (self.x - x3) - self.y;
        Self::new(x3, y3)
    }

    pub fn add(&self, other: &Self) -> Self {
        if self.infinity {
            return *other;
        }
        if other.infinity {
            return *self;
        }
        if self.x == other.x {
            return if self.y == other.y {
                self.double()
            } else {
                Self::INFINITY
            };
        }
        let lambda = (other.y - self.y)
            * (other.x - self.x)
                .inverse()
                .expect("equal x returned above");
        let x3 = lambda.square() - self.x - other.x;
        let y3 = lambda * (self.x - x3) - self.y;
        Self::new(x3, y3)
    }

    /// Double-and-add over the scalar's bits, most significant first.
    pub fn mul(&self, scalar: &BigUint) -> Self {
        let mut acc = Self::INFINITY;
        for i in (0..scalar.bits()).rev() {
            acc = acc.double();
            if scalar.bit(i) {
                acc = acc.add(self);
            }
        }
        acc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_is_on_the_curve() {
        assert!(GENERATOR.is_on_curve());
    }

    #[test]
    fn multiplication_distributes_over_addition() {
        let a = GENERATOR.mul(&BigUint::from(5u8));
        let b = GENERATOR.mul(&BigUint::from(7u8));
        assert_eq!(a.add(&b), GENERATOR.mul(&BigUint::from(12u8)));
        assert!(a.is_on_curve());
    }
}
