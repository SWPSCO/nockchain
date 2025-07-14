use either::{Left, Right};
use nockvm::jets::JetErr;
use nockvm::noun::{Atom, Cell, Error, Noun, Result, D};

use super::structs::HoonMapIter;
use crate::form::mary::*;
use crate::form::poly::*;
use crate::hand::structs::{HoonList, HoonMap};
use crate::jets::utils::jet_err;
use crate::noun::noun_ext::*;

impl AtomExt for Atom {
    fn as_u32(&self) -> Result<u32> {
        if let Ok(a) = self.as_direct() {
            if a.bit_size() > 32 {
                Err(Error::NotRepresentable)
            } else {
                Ok(a.data() as u32)
            }
        } else {
            Err(Error::NotRepresentable)
        }
    }

    fn as_belt(&self) -> Result<Belt> {
        if let Ok(x) = self.as_u64() {
            Ok(Belt(x))
        } else {
            Err(Error::NotRepresentable)
        }
    }

    fn as_felt<'a>(&self) -> Result<&'a Felt> {
        if let Ok(atom) = self.as_indirect() {
            if atom.size() == 4 {
                let buf_ptr = atom.data_pointer();
                unsafe {
                    assert!(*(buf_ptr.add(3)) == 0x1);
                }
                let felt_ref: &Felt = unsafe { &*(buf_ptr as *const Felt) };
                Ok(felt_ref)
            } else {
                Err(Error::NotRepresentable)
            }
        } else {
            Err(Error::NotRepresentable)
        }
    }

    fn as_mut_felt<'a>(&self) -> Result<&'a mut Felt> {
        if let Ok(mut atom) = self.as_indirect() {
            if atom.size() == 4 {
                let buf_ptr = atom.data_pointer_mut();
                unsafe {
                    assert!(*(buf_ptr.add(3)) == 0x1);
                }
                let felt_ref: &mut Felt = unsafe { &mut *(buf_ptr as *mut Felt) };
                Ok(felt_ref)
            } else {
                Err(Error::NotRepresentable)
            }
        } else {
            Err(Error::NotRepresentable)
        }
    }
}

impl NounExt for Noun {
    fn as_belt(&self) -> Result<Belt> {
        if let Ok(atom) = self.as_atom() {
            atom.as_belt()
        } else {
            Err(Error::NotRepresentable)
        }
    }

    fn as_felt<'a>(&self) -> Result<&'a Felt> {
        if let Ok(atom) = self.as_atom() {
            atom.as_felt()
        } else {
            Err(Error::NotRepresentable)
        }
    }

    fn as_mut_felt<'a>(&self) -> Result<&'a mut Felt> {
        if let Ok(atom) = self.as_atom() {
            atom.as_mut_felt()
        } else {
            Err(Error::NotRepresentable)
        }
    }

    fn uncell<const N: usize>(&self) -> Result<[Self; N]> {
        let mut inp = *self;
        let mut cnt = 0;
        let mut ret = [(); N].map(|_| {
            cnt += 1;
            if cnt == N {
                Ok(inp)
            } else {
                let c = inp.as_cell()?;
                inp = c.tail();
                Ok(c.head())
            }
        });
        if let Some(e) = ret.iter_mut().filter(|v| v.is_err()).next() {
            let n = core::mem::replace(e, Ok(D(0)));
            return Err(n.unwrap_err());
        }
        Ok(ret.map(|v| v.unwrap()))
    }
}

impl TryFrom<Noun> for MarySlice<'_> {
    type Error = ();

    fn try_from(n: Noun) -> std::result::Result<Self, Self::Error> {
        if n.is_atom() {
            Err(())
        } else {
            MarySlice::try_from(n.as_cell()?)
        }
    }
}

impl TryFrom<Cell> for MarySlice<'_> {
    type Error = ();

    #[inline(always)]
    fn try_from(c: Cell) -> std::result::Result<Self, Self::Error> {
        let step = c.head().as_atom()?.as_u32()?;
        let len = c.tail().as_cell()?.head().as_atom()?.as_u32()?;
        let cell: Cell = c.tail().as_cell()?;
        let dat_noun: Atom = c.tail().as_cell()?.tail().as_atom()?;
        let dat_slice: &[u64] = match dat_noun.as_either() {
            Left(_direct) => unsafe {
                let tail_ptr2 = &(*(cell.to_raw_pointer())).tail as *const Noun;
                std::slice::from_raw_parts(tail_ptr2 as *const u64, (len * step) as usize)
            },
            Right(indirect) => unsafe {
                std::slice::from_raw_parts(
                    indirect.data_pointer() as *mut u64,
                    (len * step) as usize,
                )
            },
        };
        Ok(MarySlice {
            step,
            len,
            dat: dat_slice,
        })
    }
}

impl TryFrom<Noun> for Table<'_> {
    type Error = ();

    fn try_from(n: Noun) -> std::result::Result<Self, Self::Error> {
        if n.is_atom() {
            Err(())
        } else {
            Table::try_from(n.as_cell()?)
        }
    }
}

impl TryFrom<Cell> for Table<'_> {
    type Error = ();

    #[inline(always)]
    fn try_from(c: Cell) -> std::result::Result<Self, Self::Error> {
        let full_width = c.head().as_atom()?.as_u32()?;
        let mary_cell = c.tail().as_cell()?;
        let mary = MarySlice::try_from(mary_cell)?;

        Ok(Table {
            num_cols: full_width,
            mary,
        })
    }
}

// TODO: use Ares::noun::Result or Error somehow for the methods that
// convert our structs from nouns
impl TryFrom<Noun> for BPolySlice<'_> {
    type Error = JetErr;

    #[inline(always)]
    fn try_from(n: Noun) -> std::result::Result<Self, Self::Error> {
        if n.is_atom() {
            jet_err()
        } else {
            BPolySlice::try_from(n.as_cell()?)
        }
    }
}

impl TryFrom<Noun> for FPolySlice<'_> {
    type Error = JetErr;

    #[inline(always)]
    fn try_from(n: Noun) -> std::result::Result<Self, Self::Error> {
        if n.is_atom() {
            jet_err()
        } else {
            FPolySlice::try_from(n.as_cell()?)
        }
    }
}

impl TryFrom<&Noun> for FPolySlice<'_> {
    type Error = JetErr;

    #[inline(always)]
    fn try_from(n: &Noun) -> std::result::Result<Self, Self::Error> {
        if n.is_atom() {
            jet_err()
        } else {
            FPolySlice::try_from(n.as_cell()?)
        }
    }
}

impl TryFrom<Cell> for BPolySlice<'_> {
    type Error = JetErr;

    #[inline(always)]
    fn try_from(c: Cell) -> std::result::Result<Self, Self::Error> {
        let head = c.head().as_atom();
        let tail = c.tail().as_atom();
        if let (Ok(head), Ok(tail)) = (head, tail) {
            let len32 = head.as_u32()?;
            let dat_slice: BPolySlice = unsafe {
                PolySlice(std::slice::from_raw_parts(
                    tail.data_pointer() as *const Belt,
                    len32 as usize,
                ))
            };
            Ok(dat_slice)
        } else {
            jet_err()
        }
    }
}

impl TryFrom<Cell> for FPolySlice<'_> {
    type Error = JetErr;

    #[inline(always)]
    fn try_from(c: Cell) -> std::result::Result<Self, Self::Error> {
        let head = c.head().as_atom();
        let tail = c.tail().as_atom();
        if let (Ok(head), Ok(tail)) = (head, tail) {
            let len32 = head.as_u32()?;
            let dat_slice: FPolySlice = unsafe {
                PolySlice(std::slice::from_raw_parts(
                    tail.data_pointer() as *const Felt,
                    len32 as usize,
                ))
            };
            Ok(dat_slice)
        } else {
            jet_err()
        }
    }
}

fn not_cell<T>() -> core::result::Result<T, nockvm::noun::Error> {
    Err(nockvm::noun::Error::NotCell)
}

impl TryFrom<Noun> for HoonList {
    type Error = nockvm::noun::Error;
    fn try_from(n: Noun) -> core::result::Result<Self, Self::Error> {
        if n.is_cell() {
            Ok(HoonList::from(n.as_cell().unwrap_or_else(|err| {
                panic!(
                    "Panicked with {err:?} at {}:{} (git sha: {:?})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA")
                )
            })))
        } else {
            Ok(HoonList { next: None })
        }
    }
}

impl From<Cell> for HoonList {
    fn from(c: Cell) -> Self {
        Self { next: Some(c) }
    }
}

impl TryFrom<Noun> for HoonMap {
    type Error = nockvm::noun::Error;

    fn try_from(n: Noun) -> std::result::Result<Self, Self::Error> {
        if n.is_cell() {
            HoonMap::try_from(n.as_cell().unwrap_or_else(|err| {
                panic!(
                    "Panicked with {err:?} at {}:{} (git sha: {:?})",
                    file!(),
                    line!(),
                    option_env!("GIT_SHA")
                )
            }))
        } else {
            not_cell()
        }
    }
}

impl TryFrom<Cell> for HoonMap {
    type Error = nockvm::noun::Error;

    fn try_from(c: Cell) -> std::result::Result<Self, Self::Error> {
        let tail: Noun = c.tail();
        if let Ok(cell_tail) = tail.as_cell() {
            let left = cell_tail.head();
            let right = cell_tail.tail();

            Ok(Self {
                node: c.head(),
                left: left.as_cell().ok(),
                right: right.as_cell().ok(),
            })
        } else {
            not_cell()
        }
    }
}

impl From<Noun> for HoonMapIter {
    fn from(n: Noun) -> Self {
        if let Ok(c) = n.as_cell() {
            Self {
                stack: vec![Some(c)],
            }
        } else {
            Self { stack: vec![None] }
        }
    }
}
