// Base field arithmetic functions.

pub const PRIME: u64 = 18446744069414584321;
pub const PRIME_PRIME: u64 = PRIME - 2;
pub const PRIME_128: u128 = 18446744069414584321;
pub const H: u64 = 20033703337;
pub const ORDER: u64 = 2_u64.pow(32);

#[derive(Debug)]
pub enum FieldError {
    OrderedRootError,
}

pub fn based_check(a: u64) -> bool {
    a < PRIME
}

#[macro_export]
macro_rules! based {
    ( $( $x:expr ),* ) => {
      {
          $(
              debug_assert!($crate::form::math::base::based_check($x), "element must be inside the field\r");
          )*
      }
    };
}

#[inline(always)]
pub fn badd(a: u64, b: u64) -> u64 {
    based!(a);
    based!(b);
    (((a as u128) + (b as u128)) % PRIME_128) as u64
}

#[inline(always)]
pub fn bneg(a: u64) -> u64 {
    based!(a);
    if a != 0 {
        PRIME - a
    } else {
        0
    }
}

#[inline(always)]
pub fn bsub(a: u64, b: u64) -> u64 {
    based!(a);
    based!(b);

    if a >= b {
        a - b
    } else {
        (((a as u128) + PRIME_128) - (b as u128)) as u64
    }
}

/// Reduce a 128 bit number
#[inline(always)]
pub fn reduce(n: u128) -> u64 {
    (n % PRIME_128) as u64
}

#[inline(always)]
pub fn bmul(a: u64, b: u64) -> u64 {
    based!(a);
    based!(b);
    reduce((a as u128) * (b as u128))
}

#[inline(always)]
pub fn bpow(mut a: u64, mut b: u64) -> u64 {
    based!(a);
    based!(b);

    let mut c: u64 = 1;
    if b == 0 {
        return c;
    }

    while b > 1 {
        if b & 1 == 0 {
            a = reduce((a as u128) * (a as u128));
            b /= 2;
        } else {
            c = reduce((c as u128) * (a as u128));
            a = reduce((a as u128) * (a as u128));
            b = (b - 1) / 2;
        }
    }
    reduce((c as u128) * (a as u128))
}

#[inline(always)]
pub fn bdiv(a: u64, b: u64) -> u64 {
    bmul(a, binv(b))
}

#[inline(always)]
pub fn binv(a: u64) -> u64 {
    // Due to fermat's little theorem, a^(p-1) = 1 (mod p), so a^(p-2) = a^(-1) (mod p)
    // bpow already checks based, so we skip it here
    bpow(a, PRIME - 2)
}

#[test]
fn test_binv() {
    assert_eq!(bmul(binv(888), 888), 1);
}
