//! Cache native mint's complete inputs and its type/formula product.

use hatch::ast::hoon::Hoon;
use nockapp::noun::slab::NounSlab;
use nockvm::noun::{Noun, NounAllocator, T};

use crate::build_cache::{BuildCache, CacheObjectKind, CacheWrite};
use crate::errors::{CompilerError, Result};
use crate::nasm_bridge::{hydrate_pack_root, SlabToNockasm};
use crate::native::noun::noun_pair;
use crate::native::Dialect;

pub(super) fn key(
    slab: &mut NounSlab,
    subject: Noun,
    expr: &Hoon,
    vet: bool,
    cold: &[u8],
) -> blake3::Hash {
    let gene = hatch::utils::hoon_to_noun_for_dialect(Dialect::Urbit, slab, expr);
    let input = T(slab, &[subject, gene]);
    slab.set_root(input);
    let mut hash = blake3::Hasher::new();
    hash.update(b"honk-urbit-mint-v1\0");
    hash.update(env!("HONK_NATIVE_COMPILER_FINGERPRINT").as_bytes());
    hash.update(&[0, u8::from(vet)]);
    hash.update(&(cold.len() as u64).to_le_bytes());
    hash.update(cold);
    hash.update(&slab.jam());
    hash.finalize()
}

pub(super) fn read(
    cache: &mut BuildCache,
    key: blake3::Hash,
    slab: &mut NounSlab,
) -> Result<Option<Noun>> {
    let Some(cached) = cache
        .read(key, CacheObjectKind::MintProduct)
        .map_err(cache_error)?
    else {
        return Ok(None);
    };
    let decoded = cached
        .bundle
        .roots()
        .iter()
        .find(|root| root.name() == cached.root_name)
        .map(|root| {
            let mut values = vec![None; cached.bundle.nodes().len()];
            hydrate_pack_root(slab, cached.bundle.nodes(), root.id(), &mut values)
        })
        .filter(|&noun| noun_pair(noun, &slab.noun_space()).is_ok());
    if decoded.is_none() {
        cache.reject_loaded_payload(key);
    }
    Ok(decoded)
}

pub(super) fn write(
    cache: &mut BuildCache,
    key: blake3::Hash,
    slab: &NounSlab,
    product: Noun,
) -> Result<()> {
    let noun = SlabToNockasm::new().convert(product, &slab.noun_space())?;
    let bundle = nockasm::lift_bundle(&[nockasm::DagInput {
        name: "mint",
        noun: &noun,
        mode: nockasm::DagMode::Noun,
    }])
    .map_err(cache_error)?;
    let graph = bundle.to_bytes();
    cache
        .write_pack_prebuilt(
            &[CacheWrite {
                key,
                kind: CacheObjectKind::MintProduct,
                logical_source: "urbit/mint",
                dependency_keys: &[],
                root_name: "mint",
            }],
            std::rc::Rc::new(bundle),
            &graph,
        )
        .map_err(cache_error)
}

fn cache_error(error: impl std::fmt::Display) -> CompilerError {
    CompilerError::Io(std::io::Error::other(format!(
        "Hoon 135 mint cache: {error}"
    )))
}
