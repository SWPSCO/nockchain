//! Materialize callable Hoon 135 lazy resolvers at the noun boundary.

use super::*;

impl Ut<'_> {
    pub(super) fn export_noun(&mut self, noun: Noun) -> Result<Noun> {
        self.with_stack_guard(|ut| ut.export_noun_inner(noun))
    }

    fn export_noun_inner(&mut self, noun: Noun) -> Result<Noun> {
        if noun.as_direct().is_ok() {
            return Ok(noun);
        }
        let identity = NounIdentity::of(noun);
        if let Some(exported) = self.exported_nouns.get(&identity) {
            return Ok(*exported);
        }
        let exported = if let Some(id) = self.lazy_mask_ids.get(&identity).copied() {
            self.export_lazy_mask(id)?
        } else if self.export_fork_sets.contains(&identity) {
            self.export_fork_set(noun)?
        } else {
            let space = self.slab.noun_space();
            match noun.in_space(&space).as_cell() {
                Ok(cell) => {
                    let head = cell.head().noun();
                    let tail = cell.tail().noun();
                    let new_head = self.export_noun(head)?;
                    let new_tail = self.export_noun(tail)?;
                    if NounIdentity::of(new_head) == NounIdentity::of(head)
                        && NounIdentity::of(new_tail) == NounIdentity::of(tail)
                    {
                        noun
                    } else {
                        T(self.slab, &[new_head, new_tail])
                    }
                }
                Err(_) => noun,
            }
        };
        self.exported_nouns.insert(identity, exported);
        Ok(exported)
    }

    fn export_fork_set(&mut self, set: Noun) -> Result<Noun> {
        // Materializing a resolver changes its containing type's mug. Rebuild
        // compiler-owned fork sets with the exported keys so both search and
        // heap ordering use the nouns that cross the compiler boundary.
        // Ownership is explicit: a literal noun resembling a fork is data.
        let mut pending = vec![set];
        let mut keys = Vec::new();
        let mut changed = false;
        while let Some(tree) = pending.pop() {
            if noun_is_zero(tree) {
                continue;
            }
            let (key, left, right) = set_parts(tree, &self.slab.noun_space())?;
            let exported = self.export_noun(key)?;
            changed |= NounIdentity::of(key) != NounIdentity::of(exported);
            keys.push(exported);
            pending.push(right);
            pending.push(left);
        }
        if !changed {
            return Ok(set);
        }
        let mut exported = D(0);
        for key in keys {
            exported = set_put_mug(self.slab, exported, key)?;
        }
        Ok(exported)
    }

    fn export_lazy_mask(&mut self, id: LazyResolverId) -> Result<Noun> {
        if let Some(mask) = self.exported_lazy_masks.get(&id) {
            return Ok(*mask);
        }
        if !self.exporting_lazy.insert(id) {
            return Err(CompilerError::Noun("recursive lazy resolver export".into()));
        }
        let context = self
            .lazy_resolvers
            .get(&id)
            .ok_or_else(|| CompilerError::Noun("missing lazy resolver context".into()))?
            .clone();
        let core = context.core_type;
        let NTy::Core {
            payload,
            garb,
            rest,
            ..
        } = core.as_ref()
        else {
            return Err(CompilerError::Noun(
                "lazy resolver context is not a core".into(),
            ));
        };
        let (payload, garb, rest) = (*payload, garb.clone(), rest.clone());
        let sut = live_to_noun(&mut self.cx, &payload, self.slab);
        let sut = self.export_noun(sut)?;
        let rest = live_leaf_to_noun(&mut self.cx, &rest, self.slab);
        let space = self.slab.noun_space();
        let dom = rest
            .in_space(&space)
            .as_cell()
            .map_err(|error| CompilerError::Decode(error.to_string()))?
            .tail()
            .noun();
        let dom = self.export_noun(dom)?;
        let nym = match garb.nym {
            Some(name) => {
                let name = term_to_noun(self.slab, &name);
                T(self.slab, &[D(0), name])
            }
            None => D(0),
        };
        let poly = term_to_noun(
            self.slab,
            match garb.poly {
                Poly::Dry => "dry",
                Poly::Wet => "wet",
            },
        );
        let mut fan = D(0);
        for (inner, hoon) in context.fan {
            let inner = self.export_noun(inner)?;
            let hoon = self.export_noun(hoon)?;
            let entry = T(self.slab, &[inner, hoon]);
            fan = set_put_mug(self.slab, fan, entry)?;
        }
        let mut rib = D(0);
        for (sut, dox, hoon) in context.rib {
            let sut = live_to_noun(&mut self.cx, &sut, self.slab);
            let sut = self.export_noun(sut)?;
            let dox = live_to_noun(&mut self.cx, &dox, self.slab);
            let dox = self.export_noun(dox)?;
            let hoon = self.export_noun(hoon)?;
            let entry = T(self.slab, &[sut, dox, hoon]);
            rib = set_put_mug(self.slab, rib, entry)?;
        }
        let sample = T(
            self.slab,
            &[sut, nym, poly, dom, fan, rib, D(u64::from(!context.vet))],
        );
        let factory = match self.laze_factory {
            Some(factory) => factory,
            None => {
                let factory = self
                    .slab
                    .cue_into(bytes::Bytes::from_static(include_bytes!(
                        "../../../assets/laze-135.jam"
                    )))
                    .map_err(|error| {
                        CompilerError::Decode(format!("lazy resolver factory: {error:?}"))
                    })?;
                self.laze_factory = Some(factory);
                factory
            }
        };
        let semi = self.slam_resolver_gate(factory, sample)?;
        let space = self.slab.noun_space();
        let mask = semi
            .in_space(&space)
            .as_cell()
            .map_err(|error| CompilerError::Decode(error.to_string()))?
            .head()
            .noun();
        self.exported_lazy_masks.insert(id, mask);
        self.exporting_lazy.remove(&id);
        Ok(mask)
    }
    pub(super) fn slam_resolver_gate(&mut self, gate: Noun, sample: Noun) -> Result<Noun> {
        let space = self.slab.noun_space();
        let result = unsafe {
            self.musk.context.with_stack_frame(
                0,
                |context| -> std::result::Result<Noun, nockvm::interpreter::Error> {
                    let gate = context.stack.copy_into(gate, &space);
                    let sample = context.stack.copy_into(sample, &space);
                    let stack_space = context.stack.noun_space();
                    let gate = gate.in_space(&stack_space).as_cell()?;
                    let battery = gate.head().noun();
                    let tail = gate.tail().as_cell()?.tail().noun();
                    let subject = T(&mut context.stack, &[battery, sample, tail]);
                    let slot = T(&mut context.stack, &[D(0), D(1)]);
                    let call = T(&mut context.stack, &[D(9), D(2), slot]);
                    interpret(context, subject, call)
                },
            )
        }
        .map_err(|error| CompilerError::Noun(format!("lazy resolver export: {error:?}")))?;
        Ok(self
            .slab
            .copy_into(result, &self.musk.context.stack.noun_space()))
    }
}

#[cfg(test)]
mod tests {
    use hatch::ast::hoon::Dialect;

    use super::*;

    #[test]
    fn exported_fork_orders_materialized_members() {
        for value in 1..32 {
            let mut slab: NounSlab = NounSlab::new();
            let mut ut = Ut::new_for_dialect(&mut slab, Dialect::Urbit);
            let id = ut.lazy_resolver_new_id();
            let internal = T(ut.slab, &[D(SEMI_TAG_LAZY), D(1), D(id.0)]);
            let materialized = T(ut.slab, &[D(SEMI_TAG_LAZY), D(2), D(value)]);
            ut.lazy_mask_ids.insert(NounIdentity::of(internal), id);
            ut.exported_lazy_masks.insert(id, materialized);
            let hold = term_to_noun(ut.slab, "hold");
            let noun = ty_noun(ut.slab);
            let internal_hold = T(ut.slab, &[hold, noun, internal]);
            let materialized_hold = T(ut.slab, &[hold, noun, materialized]);
            let boolean = ty_bool(ut.slab);
            let fork = ut.fork_from_options(vec![boolean, internal_hold]).unwrap();
            let expected = ut
                .fork_from_options(vec![boolean, materialized_hold])
                .unwrap();
            let actual = ut.export_noun(fork).unwrap();
            assert!(
                noun_eq(actual, expected, &ut.slab.noun_space()).unwrap(),
                "member {value}"
            );
            let again = ut.export_noun(fork).unwrap();
            assert_eq!(NounIdentity::of(actual), NounIdentity::of(again));

            let mut members = type_fork_options(boolean, &ut.slab.noun_space()).unwrap();
            members.push(internal_hold);
            let unregistered = ty_fork(ut.slab, members);
            let burped = ut.burp_type(unregistered).unwrap();
            let actual = ut.export_noun(burped).unwrap();
            assert!(noun_eq(actual, expected, &ut.slab.noun_space()).unwrap());
        }
    }

    #[test]
    fn literal_fork_tuple_preserves_tree_shape() {
        let mut slab: NounSlab = NounSlab::new();
        let mut ut = Ut::new_for_dialect(&mut slab, Dialect::Urbit);
        let tag = term_to_noun(ut.slab, "fork");
        let branch = T(ut.slab, &[D(42), D(0), D(0)]);
        let tree = T(ut.slab, &[D(42), branch, D(0)]);
        let literal = T(ut.slab, &[tag, tree]);
        let actual = ut.export_noun(literal).unwrap();
        assert_eq!(NounIdentity::of(literal), NounIdentity::of(actual));
    }

    #[test]
    fn literal_lazy_tuple_is_not_an_internal_resolver() {
        let mut slab: NounSlab = NounSlab::new();
        let mut ut = Ut::new_for_dialect(&mut slab, Dialect::Urbit);
        let id = ut.lazy_resolver_new_id();
        let _internal = ut.semi_noun_lazy_root(id);
        let literal = T(ut.slab, &[D(SEMI_TAG_LAZY), D(1), D(id.0)]);
        let exported = ut.export_noun(literal).expect("literal export");
        assert_eq!(NounIdentity::of(literal), NounIdentity::of(exported));
    }

    #[test]
    fn serialized_lazy_resolver_remains_callable_in_a_new_compiler() {
        let mut slab: NounSlab = NounSlab::new();
        let formula = T(&mut slab, &[D(1), D(42)]);
        let answer = T(&mut slab, &[D(0), formula]);
        let battery = T(&mut slab, &[D(1), answer]);
        let gate = T(&mut slab, &[battery, D(0), D(0)]);
        let mask = T(&mut slab, &[D(SEMI_TAG_LAZY), D(2), gate]);
        let semi = T(&mut slab, &[mask, D(0)]);
        slab.set_root(semi);
        let serialized = slab.jam();
        drop(slab);

        let mut slab: NounSlab = NounSlab::new();
        let semi = slab.cue_into(serialized).expect("cue resolver");
        let mut ut = Ut::new_for_dialect(&mut slab, Dialect::Urbit);
        let semi = ut.semi_import_noun(semi).expect("import resolver");
        let complete = ut.semi_complete(semi).expect("call resolver");
        let value = ut.semi_complete_value_id(complete).expect("complete value");
        let formula = ut.value_arena.noun(value);
        let expected = T(ut.slab, &[D(1), D(42)]);
        assert!(noun_eq(formula, expected, &ut.slab.noun_space()).expect("formula equality"));
    }
}
