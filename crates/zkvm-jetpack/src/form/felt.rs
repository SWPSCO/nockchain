use core::ops::{Add, Div, Mul, Neg, Sub};

use num_traits::{MulAdd, Pow};

use crate::form::base::*;
use crate::form::fext::*;
use crate::form::{Belt, Felt};

impl Felt {
    #[inline(always)]
    pub fn zero() -> Self {
        Felt(Default::default())
    }

    #[inline(always)]
    pub fn one() -> Self {
        Self::from([1, 0, 0])
    }

    #[inline(always)]
    pub fn constant(a: u64) -> Self {
        Felt([Belt(a), Belt::zero(), Belt::zero()])
    }

    #[inline(always)]
    pub fn lift(a: Belt) -> Self {
        Felt([a, Belt::zero(), Belt::zero()])
    }

    #[inline(always)]
    pub fn ordered_root(order: u64) -> Result<Self, FieldError> {
        Ok(Self::constant(Belt(order).ordered_root()?.into()))
    }

    #[inline(always)]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&e| e.is_zero())
    }

    #[inline(always)]
    pub fn degree(&self) -> u32 {
        match self.0.iter().rposition(|&x| x.is_zero()) {
            Some(i) => i as u32,
            // TODO: change return to an enum so this can be negative infty?
            None => 0,
        }
    }
    #[inline(always)]
    pub fn unpack(self) -> [u64; 3] {
        [self.0[0].0, self.0[1].0, self.0[2].0]
    }

    #[inline(always)]
    pub fn copy_from_slice(&mut self, src: &Felt) {
        self.0.copy_from_slice(&src.0)
    }

    // pub fn to_simd(&self) -> std::simd::Simd<[u64; 4]> {
    //     std::simd::Simd::load_or_default(&self.0)
    // }
}

impl core::ops::Index<usize> for Felt {
    type Output = Belt;

    #[inline(always)]
    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl core::ops::IndexMut<usize> for Felt {
    #[inline(always)]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

// impl AsRef<[u64]> for Felt {
//     fn as_ref(&self) -> &[u64] {
//         &self.0
//     }
// }

impl From<[Belt; 3]> for Felt {
    #[inline(always)]
    fn from(f: [Belt; 3]) -> Self {
        Felt(f)
    }
}

impl From<[u64; 3]> for Felt {
    #[inline(always)]
    fn from(f: [u64; 3]) -> Self {
        Felt(f.map(Belt::from))
    }
}

impl TryFrom<&[u64]> for Felt {
    type Error = ();

    #[inline(always)]
    fn try_from(f: &[u64]) -> Result<Self, Self::Error> {
        if f.len() != 3 {
            return Err(());
        }
        Ok(Felt([Belt::from(f[0]), Belt::from(f[1]), Belt::from(f[2])]))
    }
}

impl From<Felt> for [u64; 3] {
    #[inline(always)]
    fn from(f: Felt) -> Self {
        f.0.map(u64::from)
    }
}

impl From<Felt> for [Belt; 3] {
    #[inline(always)]
    fn from(f: Felt) -> Self {
        f.0
    }
}

impl<'a> From<&'a Felt> for &'a [Belt] {
    #[inline(always)]
    fn from(f: &'a Felt) -> &'a [Belt] {
        &f.0
    }
}

#[cfg(test)]
impl quickcheck::Arbitrary for Felt {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        Felt([Belt::arbitrary(g), Belt::arbitrary(g), Belt::arbitrary(g)])
    }
}

impl Add for Felt {
    type Output = Self;

    #[inline(always)]
    fn add(self, rhs: Self) -> Self::Output {
        let mut res: Felt = Felt::zero();
        fadd(&self, &rhs, &mut res);
        res
    }
}

impl Sub for Felt {
    type Output = Self;

    #[inline(always)]
    fn sub(self, rhs: Self) -> Self::Output {
        let mut res: Felt = Felt::zero();
        fsub(&self, &rhs, &mut res);
        res
    }
}

impl Mul for Felt {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: Self) -> Self::Output {
        let mut res: Felt = Felt::zero();
        fmul(&self, &rhs, &mut res);
        res
    }
}

impl Pow<usize> for Felt {
    type Output = Self;

    #[inline(always)]
    fn pow(self, rhs: usize) -> Self::Output {
        let mut res: Felt = Felt::zero();
        fpow(&self, rhs as u64, &mut res);
        res
    }
}

impl Neg for Felt {
    type Output = Self;

    #[inline(always)]
    fn neg(self) -> Self::Output {
        let mut res: Felt = Felt::zero();
        fneg(&self, &mut res);
        res
    }
}

impl Div for Felt {
    type Output = Self;

    #[inline(always)]
    fn div(self, rhs: Self) -> Self::Output {
        let mut res: Felt = Felt::zero();
        fdiv(&self, &rhs, &mut res);
        res
    }
}

impl MulAdd for Felt {
    type Output = Self;
    #[inline(always)]
    fn mul_add(self, a: Self, b: Self) -> Self {
        let mut res: Felt = Felt::zero();
        fmul(&self, &a, &mut res);
        fadd_self(&b, &mut res);
        res
    }
}
