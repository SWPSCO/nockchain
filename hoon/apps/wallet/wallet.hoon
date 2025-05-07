::  /ker/wallet/wallet: nockchain wallet
/=  bip39  /common/bip39
/=  slip10  /common/slip10
/=  m  /common/markdown/types
/=  md  /common/markdown/markdown
/=  transact  /common/tx-engine
/=  z   /common/zeke
/=  zo  /common/zoon
/=  dumb  /apps/dumbnet/lib/types
/=  *   /common/zose
/=  *  /common/wrapper
::
=>
=|  bug=_&
|%
::    $key: public or private key
::
::  a public key is generated from a private key and +cc (chain code).
::  pub contains the base58 encoded version of the cheetah curve point
::
+$  key
  $~  [%pub p=*@ux]
  $%  [%pub p=@ux]
      [%prv p=@ux]
  ==
::    $coil: key and chaincode
::
::  a wallet consists of a collection of +coil (address and entropy pair). the
::  $cc (called a chain code elsewhere) allows for the deterministic
::  generation of child keys from a parent key without compromising other
::  branches of the hierarchy.
::
::  .key:  public or private key
::  .cc: associated entropy (chain code)
::
+$  coil  [%coil =key =cc]
::
::    $meta: stored metadata for a key
+$  meta
  $%  coil
      [%label @t]
      [%seed @t]
  ==
::
::    $keys: path indexed map for keys
::
::  path format for keys state:
::
::  /keys                                                        ::  root path (holds nothing in its fil)
::  /keys/[t/master]/[key-type]/m/[coil/key]                     ::  master key path
::  /keys/[t/master]/[key-type]/[ud/index]/[coil/key]            ::  derived key path
::  /keys/[t/master]/[key-type]/[ud/index]/[coil/key]            ::  specific key path
::  /keys/[t/master]/[key-type]/[ud/index]/label/[label/label]   ::  key label path for derived key
::  /keys/[t/master]/[key-type]/m/label/[label/label]            ::  key label path for master key
::  /keys/[t/master]/seed/[seed/seed-phrase]                     ::  seed-phrase path
::
::  Note the terminal entry of the path holds that value, this value is the
::  non-unit `fil` in the $axal definition
::
::  where:
::  - [t/master] is the base58 encoded master public key as @t
::  - m denotes the master key
::  - [ud/index] is the derivation index as @ud
::  - [key-type] is either %pub or %prv
::  - [coil/key] is the key and chaincode pair. key is in serialized
::               format as a @ux, NOT base58.
::  - [seed/seed-phrase] is the seed phrase as a tape
::  - [label/label] is a label value
::
::  master key is stored under 'm'.
::  derived keys use incrementing indices starting from 0 under their master-key and key-type
::  labels are stored as children of their associated keys.
::  seed is a seed phrase and is only stored as a child of [t/master]
::
+$  keys  $+(keys-axal (axal meta))
::
::    $draft-tree: structured tree of draft, input, and seed data
::
::  we use the axal structure to track the relationship between drafts,
::  inputs, and seeds. this allows us to navigate the tree and maintain
::  all the relationships without duplicating data.
::
::  paths in the draft-tree follow these conventions:
::
::  /draft/[draft-name]                    :: draft node
::  /draft/[draft-name]/input/[input-name] :: input in a draft
::  /input/[input-name]                    :: input node
::  /input/[input-name]/seed/[seed-name]   :: seed in an input
::  /seed/[seed-name]                      :: seed node
::
+$  draft-tree
  $+  wallet-draft-tree
  (axal draft-entity)
::    $draft-entity: entities stored in the draft tree
::
+$  draft-entity
  $%  [%draft =draft-name =draft]
      [%input =input-name =preinput]
      [%seed =seed-name =preseed]
  ==
::
::  +master: master key pair
++  master
  =<  form
  |%
    +$  form  (unit coil)
    ++  public
      |=  =form
      ?:  ?=(^ form)
        u.form
      ~|("master public key not found" !!)
    ::
    ++  to-b58
      |=  =form
      ^-  @t
      (crip (en:base58:wrap p.key:(public form)))
  --
::  $cc: chaincode
::
+$  cc  @ux
::  $balance: wallet balance
+$  balance
  $+  wallet-balance
  (z-map:zo nname:transact nnote:transact)
::  $state: wallet state
::
+$  state
  $:  %0
      =balance
      hash-to-name=(z-map:zo hash:transact nname:transact)  ::  hash of note -> name of note
      name-to-hash=(z-map:zo nname:transact hash:transact)  ::  name of note -> hash of note
      receive-address=lock:transact
      =master
      =keys
      transactions=$+(transactions (map * transaction))
      last-block=(unit block-id:transact)
      peek-requests=$+(peek-requests (map @ud ?(%balance %block)))
      active-draft=(unit draft-name)
      active-input=(unit input-name)
      active-seed=(unit seed-name)             ::  currently selected seed
      draft-tree=draft-tree                    ::  structured tree of drafts, inputs, and seeds
      pending-commands=(z-map:zo @ud [phase=?(%block %balance %ready) wrapped=cause])  ::  commands waiting for sync
  ==
+$  seed-name   $~('default-seed' @t)
::
+$  draft-name  $~('default-draft' @t)
::
+$  input-name  $~('default-input' @t)
::
::  $transaction: TODO
::
+$  transaction
  $:  recipient=@ux
      amount=@ud
      status=?(%unsigned %signed %sent)
  ==
::
+$  cause
  $%  [%keygen entropy=byts salt=byts]
      [%derive-child key-type=?(%pub %prv) i=@ label=(unit @t)]
      [%import-keys keys=(list (pair trek coil))]
      [%import-master-pubkey key=@t cc=@t]           ::  base58-encoded pubkey + chain code
      [%make-tx dat=draft]
      [%list-notes-by-pubkey pubkey=@t]                ::  base58-encoded pubkey
      $:  %simple-spend
          names=(list [first=@t last=@t])              ::  base58-encoded name hashes
          recipients=(list [m=@ pks=(list @t)])        ::  base58-encoded locks
          gifts=(list coins:transact)                  ::  number of coins to spend
          fee=coins:transact                           ::  fee
      ==
      [%sign-tx dat=draft index=(unit @ud) entropy=@]
      [%list-pubkeys ~]
      [%list-notes ~]
      [%show-balance block=@ux]
      [%show =path]
      [%gen-master-privkey seedphrase=@t]
      [%gen-master-pubkey master-privkey=keyc:slip10]
      [%update-balance ~]
      [%update-block ~]
      [%sync-run wrapped=cause]                         ::  run command after sync completes
      $:  %scan
          master-pubkey=@t              ::  base58 encoded master public key to scan for
          search-depth=$~(100 @ud)      ::  how many addresses to scan (default 100)
          include-timelocks=$~(%.n ?)   ::  include timelocked notes (default false)
          include-multisig=$~(%.n ?)    ::  include notes with multisigs (default false)
      ==
      [%advanced-spend advanced-spend]
      [%file %write path=@t contents=@t success=?]
      npc-cause
  ==
::
+$  advanced-spend
  $%  [%seed advanced-spend-seed]
      [%input advanced-spend-input]
      [%draft advanced-spend-draft]
  ==
::
+$  advanced-spend-seed
  $%  [%new name=@t]                          ::  new empty seed in draft
      $:  %set-name
          seed-name=@t
          new-name=@t
      ==
      $:  %set-source                                  ::  set .output-source
          seed-name=@t
          source=(unit [hash=@t is-coinbase=?])
      ==
      $:  %set-recipient                               ::  set .recipient
          seed-name=@t
          recipient=[m=@ pks=(list @t)]
      ==
      $:  %set-timelock                                ::  set .timelock-intent
          seed-name=@t
          absolute=timelock-range:transact
          relative=timelock-range:transact
      ==
      $:  %set-gift
          seed-name=@t
          gift=coins:transact
      ==
      $:  %set-parent-hash
          seed-name=@t
          parent-hash=@t
      ==
      $:  %set-parent-hash-from-name
          seed-name=@t
          name=[@t @t]
      ==
      $:  %print-status                                ::  do the needful
          seed-name=@t
      ==
  ==
::  $seed-mask: tracks which fields of a $seed:transact have been set
::
::    this might have been better as a "unitized seed" but would have been
::    much more annoying to read the code
+$  seed-mask
  $~  [%.n %.n %.n %.n %.n]
  $:  output-source=?
      recipient=?
      timelock-intent=?
      gift=?
      parent-hash=?
  ==
::  $preseed: a $seed:transact in process of being built
+$  preseed  [name=@t (pair seed:transact seed-mask)]
::
::  $spend-mask: tracks which field of a $spend:transact have been set
+$  spend-mask
  $~  [%.n %.n %.n]
  $:  signature=?
      seeds=?
      fee=?
  ==
::
+$  advanced-spend-input
  ::  there is only one right way to create an $input from a $spend, so we don't need
  ::  the mask or other commands.
  $%  [%new name=@t]                                   :: new empty input
      $:  %set-name
          input-name=@t
          new-name=@t
      ==
      $:  %add-seed
          input-name=@t
          seed-name=@t
      ==
      $:  %set-fee
          input-name=@t
          fee=coins:transact
      ==
      $:  %set-note-from-name                          ::  set .note using .name
          input-name=@t
          name=[@t @t]
      ==
      $:  %set-note-from-hash                          ::  set .note using hash
          input-name=@t
          hash=@t
      ==
      $:  %derive-note-from-seeds                      ::  derive note from seeds
          input-name=@t
      ==
      $:  %remove-seed
          input-name=@t
          seed-name=@t
      ==
      $:  %remove-seed-by-hash
          input-name=@t
          hash=@t
      ==
      $:  %print-status
          input-name=@t
      ==
  ==
::
+$  input-mask
  $~  [%.n *spend-mask]
  $:  note=?
      spend=spend-mask
  ==
::
+$  preinput  [name=@t (pair input:transact input-mask)]
::
+$  draft  [name=@t p=inputs:transact]
::
+$  advanced-spend-draft
  $%  [%new name=@t]                                    ::  new input draft
      $:  %set-name
          draft-name=@t
          new-name=@t
      ==
      $:  %add-input
          draft-name=@t
          input-name=@t
      ==
      $:  %remove-input
          draft-name=@t
          input-name=@t
      ==
      $:  %remove-input-by-name
          draft-name=@t
          name=[first=@t last=@t]
      ==
      [%print-status =draft-name]                            ::  print draft status
  ==
::
+$  npc-cause
  $%  [%npc-bind pid=@ result=*]
  ==
::
+$  effect
  $~  [%npc 0 %poke %fact *fact:dumb]
  $%  file-effect
      [%markdown @t]
      [%raw *]
      [%npc pid=@ npc-effect]
      [%exit code=@]
  ==
::
+$  file-effect
  $%
    [%file %read path=@t]
    [%file %write path=@t contents=@]
  ==
::
+$  npc-effect
  $%  [%poke $>(%fact cause:dumb)]
      [%peek path]
  ==
::
::TODO this probably shouldnt live in here
::
++  print
  |=  nodes=markdown:m
  ^-  (list effect)
  ~[(make-markdown-effect nodes)]
::
++  warn
  |*  meg=tape
  |*  *
  ?.  bug  +<
  ~>  %slog.[1 (crip "WARN: !! {meg} !!")]
  +<
::
++  debug
  |*  meg=tape
  |*  *
  ?.  bug  +<
  ~>  %slog.[0 (crip "wallet: {meg}")]
  +<
::
++  moat  (keep state)
::

::
::  +edit: modify inputs
++  edit
  |_  =state
  ::
  +*  inp
    ^-  preinput
    ?~  active-input.state
      %-  (debug "no active input set!")
      *preinput
    =/  input-result  (~(get-input plan draft-tree.state) u.active-input.state)
    ?~  input-result
      ~|("active input not found in draft-tree" !!)
    u.input-result
  ::    +add-seed: add a seed to the input
  ::
  ++  add-seed
    |=  =seed:transact
    ^-  [(list effect) ^state]
    ?:  (~(has z-in:zo seeds.spend.p.inp) seed)
      :_  state
      %-  print
      %-  need
      %-  de:md
      %-  crip
      """
      ##  add-seed

      **seed already exists in .spend**
      """
    =/  pre=preinput  inp
    =/  =preinput
      %=    pre
          seeds.spend.p
        %.  seed
        ~(put z-in:zo seeds.spend.p.pre)
        ::
        seeds.spend.q  %.y
      ==
    =.  active-input.state  (some name.pre)
    ::
    =/  input-name=input-name  (need active-input.state)
    =.  draft-tree.state
      (~(add-input plan draft-tree.state) input-name preinput)
    ::  if active-seed is set, link it to this input
    =.  draft-tree.state
      ?:  ?=(^ active-seed.state)
        (~(link-seed-to-input plan draft-tree.state) input-name u.active-seed.state)
      draft-tree.state
    `state
  ::
  ++  remove-seed
    |=  =seed:transact
    ^-  [(list effect) ^state]
    ?.  (~(has z-in:zo seeds.spend.p.inp) seed)
      :_  state
      %-  print
      %-  need
      %-  de:md
      %-  crip
      """
      ##  remove-seed

      **seed not found in .spend**
      """
    =/  pre=preinput  inp
    =.  seeds.spend.p.pre
      %.  seed
      ~(del z-in:zo seeds.spend.p.pre)
    =.  draft-tree.state
      =/  input-name=input-name  (need active-input.state)
      (~(add-input plan draft-tree.state) input-name pre)
    `state
  --
::
::  +draw: modify drafts
++  draw
  |_  =state
  +*  df
    ^-  draft
    ?>  ?=(^ active-draft.state)
    =/  draft-result  (~(get-draft plan draft-tree.state) u.active-draft.state)
    ?~  draft-result
      *draft
    u.draft-result
  ::    +add-input: add an input to the draft
  ::
  ++  add-input
    |=  =input:transact
    ^-  [(list effect) ^state]
    =/  =draft  df
    =/  =input-name
      =+  (to-b58:nname:transact name.note.input)
      %-  crip
      "{<first>}-{<last>}"
    ?:  (~(has z-by:zo p.df) name.note.input)
      :_  state
      %-  print
      %-  need
      %-  de:md
      %-  crip
      """
      ##  add-input

      **input already exists in .draft**

      draft already has input with note name: {<input-name>}
      """
    =/  active-draft=draft-name  (need active-draft.state)
    =.  p.draft
      %-  ~(put z-by:zo p.draft)
      :-  name.note.input
      input
    =.  draft-tree.state
      %.  [active-draft draft]
      ~(add-draft plan draft-tree.state)
    =.  draft-tree.state
      %.  [active-draft input-name]
      ~(link-input-to-draft plan draft-tree.state)
    write-draft
  ::
  ++  write-draft
    ^-  [(list effect) ^state]
    =?  active-draft.state  ?=(~ active-draft.state)  (some *draft-name)
    ?>  ?=(^ active-draft.state)
    =/  =draft  df
    =.  draft-tree.state  (~(add-draft plan draft-tree.state) u.active-draft.state draft)
    =/  dat-jam  (jam draft)
    =/  path=@t  (crip "drafts/{(trip u.active-draft.state)}.draft")
    =/  effect  [%file %write path dat-jam]
    :_  state
    ~[effect [%exit 0]]
  --
::
::  Convenience wrapper door for slip10 library
::  ** Never use slip10 directly in the wallet **
++  s10
  |_  bas=base:slip10
  ++  gen-master-key
    |=  [entropy=byts salt=byts]
    =/  argon-byts=byts
      :-  32
      %+  argon2-nockchain:argon2:crypto
        entropy
      salt
    =/  memo=tape  (from-entropy:bip39 argon-byts)
    %-  (debug "memo: {memo}")
    :-  (crip memo)
    (from-seed:slip10 [64 (to-seed:bip39 memo "")])
::
  ++  from-seed
    |=  =byts
    (from-seed:slip10 byts)
::
  ++  from-private
    |=  =keyc:slip10
    (from-private:slip10 keyc)
::
  ++  from-public
    |=  =keyc:slip10
    (from-public:slip10 keyc)
::
::  Derives public key from parent public key
::  index i is expected to be a bip32 style index
::  meaning that for the n-th child key, i=n.
::
  ++  derive-public
    |=  [parent=coil i=@u]
    ?>  &(?=(%pub -.key.parent) (lte i (dec (bex 31))))
    =>  [cor=(from-public [p.key cc]:parent) i=i]
    (derive-public:cor i)
::
::  Derives private key from parent private key
::  index i is expected to be a bip32 style index
::  meaning that for n-th child key: i = (n + 2^31)
::
  ++  derive-private
    |=  [parent=coil i=@u]
    ?>  &(?=(%prv -.key.parent) (gte i (bex 31)))
    =>  [cor=(from-private [p.key cc]:parent) i=i]
    (derive-private:cor i)
  --
::
++  vault
  |_  =state
  ++  base-path  ^-  trek
    ?~  master.state
      ~|("base path not accessible because master not set" !!)
    /keys/[t/(to-b58:master master.state)]
  ::
  ++  seed-path  ^-  trek
    (welp base-path /seed)
  ::
  ++  get
    |_  key-type=?(%pub %prv)
    ::
    ++  key-path  ^-  trek
      (welp base-path ~[key-type])
    ::
    ++  seed-path  ^-  trek
      (welp base-path /seed)
    ::
    ++  master
      ^-  coil
      =/  =trek  (welp key-path /m)
      =/  =meta  (~(got of keys.state) trek)
      ?>  ?=(%coil -.meta)
      meta
    ::
    ++  by-index
      |=  index=@ud
      ^-  coil
      =/  =trek  (welp key-path /[ud/index])
      =/  =meta  (~(got of keys.state) trek)
      ?>  ?=(%coil -.meta)
      meta
    ::
    ++  seed
      ^-  meta
      (~(got of keys.state) seed-path)
    ::
    ++  by-label
      |=  label=@t
      %+  murn  keys
      |=  [t=trek =meta]
      ?:(&(?=(%label -.meta) =(label +.meta)) `t ~)
    ::
    ++  keys
      ^-  (list [trek meta])
      =/  subtree
        %-  ~(kids of keys.state)
        key-path
      ~(tap by kid.subtree)
    ::
    ++  coils
      ^-  (list coil)
      %+  murn  keys
      |=  [t=trek =meta]
      ^-  (unit coil)
      ;;  (unit coil)
      ?:(=(%coil -.meta) `meta ~)
    --
  ::
  ++  put
    |%
    ::
    ++  seed
      |=  seed-phrase=@t
      ^-  (axal meta)
      %-  ~(put of keys.state)
      [seed-path [%seed seed-phrase]]
    ::
    ++  key
      |=  [=coil index=(unit @) label=(unit @t)]
      ^-  (axal meta)
      =/  key-type=@tas  -.key.coil
      =/  suffix=trek
        ?@  index
          /[key-type]/m
        /[key-type]/[ud/u.index]
      =/  key-path=trek  (welp base-path suffix)
      %-  (debug "adding key at {(en-tape:trek key-path)}")
      =.  keys.state  (~(put of keys.state) key-path coil)
      ?~  label
        keys.state
      %+  ~(put of keys.state)
        (welp key-path /label)
      label/u.label
    --
  ::
  ::  +derive-child: derives the i-th hardened/unhardened child
  ::
  ::    derives the i-th hardened or unhardened child from the master key.
  ::    this arm will convert i to fit the slip10/bip32 indexing schemes.
  ::    the i-th hardened corresponds to index i + 2^31 while the ith
  ::    unhardened child corresponds to index i.
  ::
  ++  derive-child
    |=  [parent=coil i=@u]
    ^-  coil
    ?:  (gte i (bex 31))
      ~|("Child index {<i>} out of range. Child indices are capped to values between [0, 2^31)" !!)
    ?~  master.state
      ~|("No master keys available for derivation" !!)
    ?:  ?=(%prv -.key.parent)
      ::
      ::  If the parent key is %prv, then the child is hardened
      ::  and we add 2^31 to the index
      =>  (derive-private:s10 parent (add i (bex 31)))
      [%coil [%prv private-key] chain-code]
    =>  (derive-public:s10 parent i)
    [%coil [%pub public-key] chain-code]
  ::
  ++  get-note
    |=  name=nname:transact
    ^-  nnote:transact
    ?:  (~(has z-by:zo balance.state) name)
      (~(got z-by:zo balance.state) name)
    ~|("note not found: {<name>}" !!)
  ::
  ++  get-note-from-hash
    |=  has=hash:transact
    ^-  nnote:transact
    =/  name=nname:transact
      (~(got z-by:zo hash-to-name.state) has)
    (get-note name)
  ::
  ++  generate-pid
    |=  peek-type=?(%balance %block)
    ^-  (unit @ud)
    =/  has-active-peek=?
      %-  ~(any by peek-requests.state)
      |=(t=?(%balance %block) =(t peek-type))
    ?:  has-active-peek  ~
    =/  used-pids=(list @ud)
      ~(tap in ~(key by peek-requests.state))
    =/  max-pid=@ud
      (roll used-pids max)
    =/  next-pid=@ud  +(max-pid)
    ?:  =(next-pid 0)  `1  :: handle wraparound
    `next-pid
  --
::    +plan: core for managing draft relationships
::
::  provides methods for adding, removing, and navigating the draft tree.
::  uses the axal structure to maintain relationships between drafts, inputs,
::  and seeds.
::
++  plan
  |_  tree=draft-tree
  ::
  ::  +get-draft: retrieve a draft by name
  ::
  ++  get-draft
    |=  name=draft-name
    ^-  (unit draft)
    =/  res  (~(get of tree) /draft/[name])
    ?~  res  ~
    ?.  ?=(%draft -.u.res)  ~
    `draft.u.res
  ::    +get-input: retrieve an input by name
  ::
  ++  get-input
    |=  name=input-name
    ^-  (unit preinput)
    =/  res  (~(get of tree) /input/[name])
    ?~  res  ~
    ?.  ?=(%input -.u.res)  ~
    `preinput.u.res
  ::    +get-seed: retrieve a seed by name
  ::
  ++  get-seed
    |=  name=seed-name
    ^-  (unit preseed)
    =/  res  (~(get of tree) /seed/[name])
    ?~  res  ~
    ?.  ?=(%seed -.u.res)  ~
    `preseed.u.res
  ::    +add-draft: add a new draft
  ::
  ++  add-draft
    |=  [name=draft-name =draft]
    ^-  draft-tree
    =/  entity  [%draft name draft]
    (~(put of tree) /draft/[name] entity)
  ::    +add-input: add a new input
  ::
  ++  add-input
    |=  [name=input-name =preinput]
    ^-  draft-tree
    =/  entity  [%input name preinput]
    (~(put of tree) /input/[name] entity)
  ::    +add-seed: add a new seed
  ::
  ++  add-seed
    |=  [name=seed-name =preseed]
    ^-  draft-tree
    =/  entity  [%seed name preseed]
    (~(put of tree) /seed/[name] entity)
  ::    +link-input-to-draft: link an input to a draft
  ::
  ++  link-input-to-draft
    |=  [draft-name=draft-name input-name=input-name]
    ^-  draft-tree
    =/  input-entity  (~(get of tree) /input/[input-name])
    ?~  input-entity  tree
    ?.  ?=(%input -.u.input-entity)  tree
    (~(put of tree) /draft/[draft-name]/input/[input-name] u.input-entity)
  ::    +link-seed-to-input: link a seed to an input
  ::
  ++  link-seed-to-input
    |=  [input-name=input-name seed-name=seed-name]
    ^-  draft-tree
    =/  seed-entity  (~(get of tree) /seed/[seed-name])
    ?~  seed-entity  tree
    ?.  ?=(%seed -.u.seed-entity)  tree
    (~(put of tree) /input/[input-name]/seed/[seed-name] u.seed-entity)
  ::    +unlink-input-from-draft: remove an input from a draft
  ::
  ++  unlink-input-from-draft
    |=  [draft-name=draft-name input-name=input-name]
    ^-  draft-tree
    (~(del of tree) /draft/[draft-name]/input/[input-name])
  ::    +unlink-seed-from-input: remove a seed from an input
  ::
  ++  unlink-seed-from-input
    |=  [input-name=input-name seed-name=seed-name]
    ^-  draft-tree
    (~(del of tree) /input/[input-name]/seed/[seed-name])
  ::    +list-draft-inputs: list all inputs in a draft
  ::
  ++  list-draft-inputs
    |=  name=draft-name
    ^-  (list input-name)
    =/  kids  (~(kid of tree) /draft/[name])
    %+  murn  ~(tap in ~(key by kids))
    |=  pax=pith
    ^-  (unit input-name)
    =/  pax=path  (pout pax)
    ?>  ?=([%input *] pax)
    ?>  ?=(^ t.pax)
    `i.t.pax
  ::    +list-input-seeds: list all seeds in an input
  ::
  ++  list-input-seeds
    |=  name=input-name
    ^-  (list seed-name)
    =/  kids  (~(kid of tree) /input/[name])
    %+  murn  ~(tap in ~(key by kids))
    |=  pax=pith
    ^-  (unit seed-name)
    =/  pax=path  (pout pax)
    ?:  &(?=([%seed *] pax) ?=(^ t.pax))
      `i.t.pax
    ~
  ::    +list-all-drafts: list all draft names
  ::
  ++  list-all-drafts
    ^-  (list draft-name)
    =/  kids  (~(kid of tree) /draft)
    %+  murn  ~(tap in ~(key by kids))
    |=  pax=pith
    ^-  (unit draft-name)
    =/  pax=path  (pout pax)
    ?:  ?=(^ pax)
      `i.pax
    ~
  ::    +list-all-inputs: list all input names
  ::
  ++  list-all-inputs
    ^-  (list input-name)
    =/  kids  (~(kid of tree) /input)
    %+  murn  ~(tap in ~(key by kids))
    |=  pax=pith
    ^-  (unit input-name)
    =/  pax=path  (pout pax)
    ?:  ?=(^ pax)
      `i.pax
    ~
  ::    +list-all-seeds: list all seed names
  ::
  ++  list-all-seeds
    ^-  (list seed-name)
    =/  kids  (~(kid of tree) /seed)
    %+  murn  ~(tap in ~(key by kids))
    |=  pax=pith
    ^-  (unit seed-name)
    =/  pax=path  (pout pax)
    ?:  &(?=([%seed *] pax) ?=(^ t.pax))
      `i.pax
    ~
  ::    +remove-draft: completely remove a draft and its associations
  ::
  ++  remove-draft
    |=  name=draft-name
    ^-  draft-tree
    (~(lop of tree) /draft/[name])
  ::    +remove-input: completely remove an input and its associations
  ::
  ++  remove-input
    |=  name=input-name
    ^-  draft-tree
    (~(lop of tree) /input/[name])
  ::    +remove-seed: completely remove a seed and its associations
  ::
  ++  remove-seed
    |=  name=seed-name
    ^-  draft-tree
    (~(lop of tree) /seed/[name])
  --
::
++  make-markdown-effect
  |=  nodes=markdown:m
  [%markdown (crip (en:md nodes))]
::
++  display-poke
  |=  =cause
  ^-  effect
  =/  nodes=markdown:m
  %-  need
  %-  de:md
  %-  crip
  """
  ## poke
  {<cause>}
  """
  (make-markdown-effect nodes)
::
++  display-note
  |=  note=nnote:transact
  ^-  markdown:m
  %-  need
  %-  de:md
  %-  crip
  """
  ## details

  - name: {<(to-b58:nname:transact name.note)>}
  - assets: {<assets.note>}
  - source: {<source.note>}

  ## lock

  - m: {<m.lock.note>}
  - signers: {<(to-b58:signers:lock:transact lock.note)>}

  """
::
++  show
  |=  [=state =path]
  ^-  [(list effect) ^state]
  |^
  ?+    path  !!
      [%balance ~]
    :-  ~[(display-balance balance.state)]
    state
  ::
      [%receive-address ~]
    :-  (display-receive-address receive-address.state)
    state
  ::
      [%state ~]
    :-  display-state
    state
  ==
  ++  display-balance
    |=  =balance
    ^-  effect
    =/  nodes=markdown:m
    %-  need
    %-  de:md
    %-  crip
    """
    ## balance
    {<balance>}
    """
    (make-markdown-effect nodes)
  ::
  ++  display-receive-address
    |=  address=lock:transact
    ^-  (list effect)
    =/  nodes=markdown:m
    %-  need
    %-  de:md
    %-  crip
    """
    ## receive address
    {<address>}
    """
    ~[(make-markdown-effect nodes)]
  ::
  ++  display-state
    ^-  (list effect)
    =/  nodes=markdown:m
    %-  need
    %-  de:md
    %-  crip
    """
    ## state
    - last block: {<last-block.state>}
    """
    ~[(make-markdown-effect nodes)]
  --
--
::
%-  (moat &)
^-  fort:moat
|_  =state
+*  v  ~(. vault state)
    d  ~(. draw state)
    e  ~(. edit state)
    p  ~(. plan draft-tree.state)
::
++  load
  |=  arg=^state
  ^-  ^state
  arg
::
++  peek
  |=  =path
  ^-  (unit (unit *))
  %-  (debug "peek: {<state>}")
  ?+    path  ~
    ::
      [%balance ~]
    ``balance.state
    ::
      [%receive-address ~]
    ``receive-address.state
    ::
      [%state ~]
    ``state
  ==
::
++  poke
  |=  =ovum:moat
  |^
  ^-  [(list effect) ^state]
  %-  (warn "debug printing may expose sensitive information")
  =/  =wire  wire.ovum
  =+  [@ src=@ta ver=@ rest=*]=wire.ovum
  %-  (debug "wire: {<[src ver `path`rest]>}")
  =/  cause=(unit cause)
    %-  (soft cause)
    cause.input.ovum
  =/  success  [%exit 0]
  =/  failure  [%exit 1]
  ?~  cause
    %-  (debug "input does not have a proper cause: {<cause.input.ovum>}")
    [~[failure] state]
  =/  cause  u.cause
  %-  (debug "cause: {<-.cause>}")
  =;  process
    =^  effs  state  process
    ::  check for pending balance commands and execute them
    =^  pending-effs  state  handle-pending-commands
    [(weld effs pending-effs) state]
  ?-  -.cause
      %npc-bind              (handle-npc cause)
      %show                  (show state path.cause)
      %keygen                (do-keygen cause)
      %derive-child          (do-derive-child cause)
      %sign-tx               (do-sign-tx cause)
      %scan                  (do-scan cause)
      %list-notes            (do-list-notes cause)
      %list-notes-by-pubkey  (do-list-notes-by-pubkey cause)
      %simple-spend          (do-simple-spend cause)
      %update-balance        (do-update-balance cause)
      %update-block          (do-update-block cause)
      %import-keys           (do-import-keys cause)
      %import-master-pubkey  (do-import-master-pubkey cause)
      %gen-master-privkey    (do-gen-master-privkey cause)
      %gen-master-pubkey     (do-gen-master-pubkey cause)
      %make-tx               (do-make-tx cause)
      %list-pubkeys          (do-list-pubkeys cause)
      %show-balance          (do-show-balance cause)
      %sync-run              (do-sync-run cause)
    ::
      %advanced-spend
    ?-  +<.cause
      %seed   (do-advanced-spend-seed +>.cause)
      %input  (do-advanced-spend-input +>.cause)
      %draft  (do-advanced-spend-draft +>.cause)
    ==
    ::
      %file
    ?>  ?=(%write +<.cause)
    ~&  >  "%file %write: {<cause>}"
    [[%exit 0]~ state]
  ==
  ::
  ++  handle-npc
    |=  =npc-cause
    ^-  [(list effect) ^state]
    %-  (debug "handle-npc: {<-.npc-cause>}")
    ?-    -.npc-cause
        %npc-bind
      =/  pid  pid.npc-cause
      =/  peek-type
        ?.  (~(has by peek-requests.state) pid)
          ~|("no peek request found for pid: {<pid>}" !!)
        (~(got by peek-requests.state) pid)
      =/  result  result.npc-cause
      ?-  peek-type
          %balance
        =/  softed=(unit (unit (unit (z-map:zo nname:transact nnote:transact))))
          %-  (soft (unit (unit (z-map:zo nname:transact nnote:transact))))
          result
        =.  peek-requests.state
          (~(del by peek-requests.state) pid)
        ?~  softed
          %-  (debug "handle-npc: %balance: could not soft result")
          `state
        =/  balance-result=(unit (unit _balance.state))  u.softed
        ?~  balance-result
          %-  (warn "%update-balance did not return a result: bad path")
          `state
        ?~  u.balance-result
          %-  (warn "%update-balance did not return a result: nothing")
          `state
        ?~  u.u.balance-result
          %-  (warn "%update-balance did not return a result: empty result")
          `state
        =.  balance.state  u.u.balance-result
        %-  (debug "balance state updated!")
        =.  name-to-hash.state
          %-  ~(run z-by:zo balance.state)
          |=  not=nnote:transact
          ^-  hash:transact
          (hash:nnote:transact not)
        =.  hash-to-name.state
          %-  ~(gas z-by:zo *(z-map:zo hash:transact nname:transact))
          %+  turn  ~(tap z-by:zo name-to-hash.state)
          |=  [name=nname:transact =hash:transact]
          [hash name]
        ::  move each command from balance phase to ready phase
        =/  balance-commands=(list [pid=@ud [phase=?(%block %balance %ready) wrapped=cause]])
          %+  skim  ~(tap z-by:zo pending-commands.state)
          |=  [pid=@ud [phase=?(%block %balance %ready) wrapped=cause]]
          =(phase %balance)
        =.  pending-commands.state
          %-  ~(gas z-by:zo pending-commands.state)
          %+  turn  balance-commands
          |=  [pid=@ud [phase=?(%block %balance %ready) wrapped=cause]]
          [pid [%ready wrapped]]
        ::
        ::  the top-level poke arm should check for pending commands
        ::  and execute them as appropriate
        %-  (debug "handle-npc: %balance: balance updated, pending commands ready for execution")
        [~ state]
        ::
          %block
        %-  (debug "handle-npc: %block")
        =/  softed=(unit (unit (unit (unit block-id:transact))))
          %-  (soft (unit (unit (unit block-id:transact))))
          result
        =.  peek-requests.state
          (~(del by peek-requests.state) pid)
        ?~  softed
          %-  (warn "handle-npc: %block: could not soft result")
          `state
        =/  block-result  u.softed
        %-  (debug "handle-npc: %block: {<block-result>}")
        %-  (debug "handle-npc: %block: {<peek-requests.state>}")
        ?~  block-result
          %-  (warn "handle-npc: %block: bad path")
          `state
        ?~  u.block-result
          %-  (warn "handle-npc: %block: nothing")
          `state
        ?~  u.u.block-result
          %-  (warn "handle-npc: %block: empty result")
          `state
        %-  (debug "handle-npc: %block: found block")
        %-  (debug "handle-npc: {<(to-b58:block-id:transact (need u.u.block-result))>}")
        %-  (debug "handle-npc: hash: {<(to-b58:hash:transact (need u.u.block-result))>}")
        =.  last-block.state  u.u.block-result
        ::  move each command from block phase to balance phase
        =/  block-commands=(list [pid=@ud [phase=?(%block %balance %ready) wrapped=cause]])
          %+  skim  ~(tap z-by:zo pending-commands.state)
          |=  [pid=@ud [phase=?(%block %balance %ready) wrapped=cause]]
          =(phase %block)
        ::
        %-  (debug "handle-npc: %block: preparing {<(lent block-commands)>} commands for balance update")
        ::  move each command to balance update phase
        =.  pending-commands.state
          %-  ~(gas z-by:zo pending-commands.state)
          %+  turn  block-commands
          |=  [pid=@ud [phase=?(%block %balance %ready) wrapped=cause]]
          [pid [%balance wrapped]]
        ::  check if we need to update balance (if there are commands waiting for it)
        =/  have-balance-cmds=?
          %-  ~(any z-by:zo pending-commands.state)
          |=  [phase=?(%block %balance %ready) wrapped=*]
          =(phase %balance)
        ::
        ?:  have-balance-cmds
          %-  (debug "handle-npc: %block: initiating balance update for pending commands")
          =^  balance-update-effs  state
            (do-update-balance [%update-balance ~])
          [balance-update-effs state]
        `state
        ::
      ==
    ==
  ::
  ++  handle-pending-commands
    ^-  [(list effect) ^state]
    =/  ready-commands=(list [pid=@ud =cause])
      %+  turn
        %+  skim  ~(tap z-by:zo pending-commands.state)
        |=  [pid=@ud [phase=?(%block %balance %ready) wrapped=cause]]
        =(phase %ready)
      |=  [pid=@ud [phase=?(%block %balance %ready) wrapped=cause]]
      [pid wrapped]
    ?~  ready-commands
      %-  (debug "no pending commands to execute")
      `state
    %-  (debug "executing {<(lent ready-commands)>} pending commands")
    ::  process each command
    =/  effs=(list effect)  ~
    =/  cmds=(list [pid=@ud =cause])  ready-commands
    |-
    ?~  cmds
      [effs state]
    =/  pid=@ud  pid.i.cmds
    =/  =cause  +.i.cmds
    =/  ov=^ovum
      %*  .  ovum
        cause.input  cause
      ==
    =.  pending-commands.state
      (~(del z-by:zo pending-commands.state) pid)
    ::
    =^  cmd-effs  state
      (poke ov)
    $(cmds t.cmds, effs (weld effs cmd-effs))
  ::
  ++  do-sync-run
    |=  =cause
    ?>  ?=(%sync-run -.cause)
    %-  (debug "sync-run: wrapped command {<-.wrapped.cause>}")
    ::  get a new pid for the command
    =/  pid=(unit @ud)  (generate-pid:v %block)
    ?~  pid
      ::  if we can't get a pid, run the command directly
      %-  (debug "sync-run: no pid available, running command directly")
      =/  ov=^ovum
        %*  .  ovum
          cause.input  wrapped.cause
        ==
      (poke ov)
    ::  store the command in pending-commands
    =.  pending-commands.state
      %+  ~(put z-by:zo pending-commands.state)
        u.pid
      [%block wrapped.cause]
    ::  initiate block update
    =^  block-update-effs  state
      (do-update-block [%update-block ~])
    ::  return block update effects
    [block-update-effs state]
  ::
  ++  do-update-balance
    |=  =cause
    ?>  ?=(%update-balance -.cause)
    %-  (debug "update-balance")
    %-  (debug "last balance size: {<(lent ~(tap z-by:zo balance.state))>}")
    =/  pid=(unit @ud)  (generate-pid:v %balance)
    ?~  pid  `state
    =/  bid=block-id:transact
      ?:  ?=(~ last-block.state)
        ~|("no last block found, not updating balance" !!)
      (need last-block.state)
    =/  =path  (snoc /balance (to-b58:block-id:transact bid))
    =/  =effect  [%npc u.pid %peek path]
    :-  ~[effect]
    state(peek-requests (~(put by peek-requests.state) u.pid %balance))
  ::
  ++  do-update-block
    |=  =cause
    ?>  ?=(%update-block -.cause)
    %-  (debug "update-block")
    %-  (debug "last block: {<last-block.state>}")
    =/  pid=(unit @ud)  (generate-pid:v %block)
    ?~  pid  `state
    =/  =path  /heavy
    =/  =effect  [%npc u.pid %peek path]
    :-  ~[effect]
    state(peek-requests (~(put by peek-requests.state) u.pid %block))
  ::
  ++  do-import-keys
    |=  =cause
    ?>  ?=(%import-keys -.cause)
    =/  new-keys=_keys.state
      %+  roll  keys.cause
      |=  [[=trek =coil] acc=_keys.state]
      (~(put of acc) trek coil)
    `state(keys new-keys)
  ::
  ::>)  TODO: update state.master as well
  ++  do-import-master-pubkey
    |=  =cause
    ?>  ?=(%import-master-pubkey -.cause)
    %-  (debug "import-master-pubkey: {<key.cause>}")
    =/  c=coil  [%coil [%pub (de:base58:wrap (trip key.cause))] (de:base58:wrap (trip cc.cause))]
    =/  cor  (from-public:s10 [p.key.c cc.c])
    =/  master-pubkey-coil=coil  [%coil [%pub public-key] chain-code]:cor
    =.  master.state  (some master-pubkey-coil)
    =/  label  `(crip "master-public-{<(end [3 4] public-key:cor)>}")
    %-  (debug "Imported master public key: {<public-key:cor>}")
    =.  keys.state  (key:put:v master-pubkey-coil ~ label)
    `state
  ::
  ++  do-gen-master-privkey
    |=  =cause
    ?>  ?=(%gen-master-privkey -.cause)
    ::  We do not need to reverse the endian-ness of the seedphrase
    ::  because the bip39 code expects a tape.
    =/  seed=byts  [64 (to-seed:bip39 (trip seedphrase.cause) "")]
    =/  cor  (from-seed:s10 seed)
    =/  master-pubkey-coil=coil  [%coil [%pub public-key] chain-code]:cor
    =/  master-privkey-coil=coil  [%coil [%prv private-key] chain-code]:cor
    =.  master.state  (some master-pubkey-coil)
    =/  public-label  `(crip "master-public-{<(end [3 4] public-key:cor)>}")
    =/  private-label  `(crip "master-private-{<(end [3 4] public-key:cor)>}")
    =.  keys.state  (key:put:v master-privkey-coil ~ private-label)
    =.  keys.state  (key:put:v master-pubkey-coil ~ public-label)
    =.  keys.state  (seed:put:v seedphrase.cause)
    %-  (debug "master.state: {<master.state>}")
    [[%exit 0]~ state]
  ::
  ++  do-gen-master-pubkey
    |=  =cause
    ?>  ?=(%gen-master-pubkey -.cause)
    =/  cor  (from-private:s10 master-privkey.cause)
    =/  master-pubkey-coil=coil  [%coil [%pub public-key] chain-code]:cor
    =/  master-privkey-coil=coil  [%coil [%prv private-key] chain-code]:cor
    %-  (debug "Generated master public key: {<public-key:cor>}")
    =/  public-label  `(crip "master-public-{<(end [3 4] public-key:cor)>}")
    =/  private-label  `(crip "master-private-{<(end [3 4] public-key:cor)>}")
    =.  master.state  (some master-pubkey-coil)
    =.  keys.state  (key:put:v master-privkey-coil ~ private-label)
    =.  keys.state  (key:put:v master-pubkey-coil ~ public-label)
    %-  (debug "master.state: {<master.state>}")
    `state
  ::
  ++  do-make-tx
    |=  =cause
    ?>  ?=(%make-tx -.cause)
    %-  (debug "make-tx: {<dat.cause>}")
    ::  note that new:raw-tx calls +validate already
    =/  raw=raw-tx:transact  (new:raw-tx:transact p.dat.cause)
    =/  tx-id  id.raw
    =/  nock-cause=$>(%fact cause:dumb)
      [%fact %heard-tx raw]
    %-  (debug "make-tx: new-tx {<tx-id>}")
    :_  state
    :~
      [%npc 0 %poke nock-cause]
      [%exit 0]
    ==
  ::
  ++  do-list-pubkeys
    |=  =cause
    ?>  ?=(%list-pubkeys -.cause)
    =/  pubkeys  ~(coils get:v %pub)
    =/  base58-keys=(list tape)
      %+  turn  pubkeys
      |=  =coil
      =/  pubkey=schnorr-pubkey:transact  pub:(from-public:s10 [p.key cc]:coil)
      %-  trip
      (to-b58:schnorr-pubkey:transact pubkey)
    %-  (debug "base58-keys: {<base58-keys>}")
    :-  [%exit 0]~
    state
  ::
  ++  do-show-balance
    |=  =cause
    ?>  ?=(%show-balance -.cause)
    %-  (debug "show-balance: {<block.cause>}")
    =/  =path  /balance/[(scot %ux block.cause)]
    =/  =effect  [%npc 0 %peek path]
    :-  ~[effect]
    state
  ::
  ++  do-scan
    |=  =cause
    ?>  ?=(%scan -.cause)
    %-  (debug "scan: scanning {<search-depth.cause>} addresses")
    ?>  ?=(^ master.state)
    ::  get all public keys up to search depth
    =/  index=@ud  search-depth.cause
    =/  coils=(list coil)
      =/  keys=(list coil)  [~(master get:v %pub)]~
      =|  done=_|
      |-  ^-  (list coil)
      ?:  done  keys
      =?  done  =(0 index)  &
      =/  base=trek  /keys/pub/[ux/p.key:(public:master master.state)]/[ud/index]
      =/  key=(unit coil)
        ;;  (unit coil)
        (~(get of keys.state) base)
      %=  $
        index  ?:(=(0 index) 0 (dec index))
        keys  ?^(key (snoc keys u.key) keys)
      ==
    ::  fail when no coils
    ?:  ?=(~ coils)
      ~|("no coils for master key" !!)
    ::  generate first names of notes owned by each pubkey
    =/  first-names=(list [hash:transact schnorr-pubkey:transact])
      %+  turn  coils
      |=  =coil
      ::  create lock from public key
      =/  pubkey=schnorr-pubkey:transact  pub:(from-public:s10 [p.key cc]:coil)
      =/  =lock:transact  (new:lock:transact pubkey)
      ::  generate name and take first name
      =/  match-name=nname:transact
        %-  new:nname:transact
        :*  lock
            [*hash:transact %.n]  ::  empty source, not a coinbase
            *timelock:transact    ::  no timelock
        ==
      [-.match-name pubkey]
    ::  find notes with matching first names in balance
    =/  notes=(list nnote:transact)
      %+  murn
        ~(tap z-by:zo balance.state)
      |=  [name=nname:transact note=nnote:transact]
      ^-  (unit nnote:transact)
      ::  check if first name matches any in our list
      =/  matches
        %+  lien  first-names
        |=  [first-name=hash:transact pubkey=schnorr-pubkey:transact]
        =/  =lock:transact  (new:lock:transact pubkey)
        ::  update lock if include-multisig is true and pubkey is in
        ::  the multisig set in the note's lock
        =?  lock
          ?&  include-multisig.cause
              (~(has z-in:zo pubkeys.lock.note) pubkey)
          ==
        lock.note
        ::  update match-name if include-timelocks is set
        =?  first-name  include-timelocks.cause
          =<  -
          %-  new:nname:transact
          :*  lock
              [*hash:transact %.n]  ::  empty source, not a coinbase
              timelock.note         ::  include timelock
          ==
        =(-.name first-name)
      ?:(matches `note ~)
    %-  (debug "found matches: {<notes>}")
    =/  nodes=markdown:m
      :~  :-  %leaf
          :-  %heading
          :*  %atx  1
              :~  [%text 'Scan Result']
              ==
          ==
          :-  %container
          :-  %ul
          :*  0  '*'
             (turn notes display-note)
          ==
      ==
    :_  state
    ~[(make-markdown-effect nodes)]
  ::
  ++  do-list-notes
    |=  =cause
    ?>  ?=(%list-notes -.cause)
    %-  (debug "list-notes")
    =/  notes=(list [name=nname:transact note=nnote:transact])
      %+  sort  ~(tap z-by:zo balance.state)
      |=  $:  a=[name=nname:transact note=nnote:transact]
              b=[name=nname:transact note=nnote:transact]
          ==
      (gth assets.note.a assets.note.b)
    =/  nodes=markdown:m
      %+  welp
      %-  need
      %-  de:md
      %-  crip
      """
      ## wallet notes

      """
      %-  zing
      %+  turn  notes
      |=  [* =nnote:transact]
      (display-note nnote)
    :_  state
    ~[(make-markdown-effect nodes) [%exit 0]]
  ::
  ++  do-list-notes-by-pubkey
    |=  =cause
    ~&  "list-notes-by-pubkey"
    ?>  ?=(%list-notes-by-pubkey -.cause)
    ~&  "list-notes-by-pubkey: {<pubkey.cause>}"
    =/  target-pubkey=schnorr-pubkey:transact
      (from-b58:schnorr-pubkey:transact pubkey.cause)
    =/  matching-notes=(list [name=nname:transact note=nnote:transact])
      %+  skim  ~(tap z-by:zo balance.state)
      |=  [name=nname:transact note=nnote:transact]
      (~(has z-in:zo pubkeys.lock.note) target-pubkey)
    =/  sorted-notes=(list [name=nname:transact note=nnote:transact])
      %+  sort  matching-notes
      |=  $:  a=[name=nname:transact note=nnote:transact]
              b=[name=nname:transact note=nnote:transact]
          ==
      (gth assets.note.a assets.note.b)
    =/  nodes=markdown:m
      %+  welp
      %-  need
      %-  de:md
      %-  crip
      """
      ## wallet notes for pubkey {<(to-b58:schnorr-pubkey:transact target-pubkey)>}

      """
      %-  zing
      %+  turn  sorted-notes
      |=  [* =nnote:transact]
      (display-note nnote)
    :_  state
    ~[(make-markdown-effect nodes) [%raw sorted-notes] [%exit 0]]
  ::
  ++  do-simple-spend
    |=  =cause
    ?>  ?=(%simple-spend -.cause)
    %-  (debug "simple-spend: {<names.cause>}")
    ::  for now, each input corresponds to a single name and recipient. all
    ::  assets associated with the name are transferred to the recipient.
    ::
    ::  thus there is one recipient per name, and one seed per recipient.
    ::
    =/  names=(list nname:transact)
      %+  turn  names.cause
      |=  [first=@t last=@t]
      (from-b58:nname:transact [first last])
    =/  recipients=(list lock:transact)
      %+  turn  recipients.cause
      |=  [m=@ pks=(list @t)]
      %+  m-of-n:new:lock:transact  m
      %-  ~(gas z-in:zo *(z-set:zo schnorr-pubkey:transact))
      %+  turn  pks
      |=  pk=@t
      (from-b58:schnorr-pubkey:transact pk)
    ::
    =/  gifts=(list coins:transact)  gifts.cause
    ::
    ?.  ?&  =((lent names) (lent recipients))
            =((lent names) (lent gifts))
        ==
      ~|("different number of names/recipients/gifts" !!)
    =|  ledger=(list [name=nname:transact recipient=lock:transact gifts=coins:transact])
    =.  ledger
      |-
      ?~  names  ledger
      ::  since we assert they are equal in length above, this is just to get
      ::  the i face
      ?~  gifts  ledger
      ?~  recipients  ledger
      %=  $
        ledger      [[i.names i.recipients i.gifts] ledger]
        names       t.names
        gifts       t.gifts
        recipients  t.recipients
      ==
    ::
    ::  the fee is subtracted from the first note that permits doing so without overspending
    =/  fee=coins:transact  fee.cause
    ::  use the first private key to construct the subsequent inputs
    =/  sender=coil
      =/  private-keys=(list coil)  ~(coils get:v %prv)
      ?~  private-keys
        ~|("No private keys available for signing" !!)
      (head private-keys)
    =/  sender-key=schnorr-seckey:transact
      (from-atom:schnorr-seckey:transact p.key.sender)
    ::  for each name, create an input from the corresponding note in sender's
    ::  balance at the current block. the fee will be subtracted entirely from
    ::  the first note that has sufficient assets for both the fee and the gift.
    ::  the refund is sent to receive-address.state
    =/  [ins=(list input:transact) spent-fee=?]
      %^  spin  ledger  `?`%.n
      |=  $:  $:  name=nname:transact
                  recipient=lock:transact
                  gift=coins:transact
              ==
            spent-fee=?
          ==
      =/  note=nnote:transact  (get-note:v name)
      ?:  (gth gift assets.note)
        ~|  "gift {<gift>} larger than assets {<assets.note>} for recipient {<recipient>}"
        !!
      ?:  ?&  !spent-fee
              (lte (add gift fee) assets.note)
          ==
        ::  we can subtract the fee from this note
        :_  %.y
        %-  with-choice:with-refund:simple-from-note:new:input:transact
        [recipient gift fee note sender-key receive-address.state]
      ::  ::  we cannot subtract the fee from this note, or we already have from a previous one
      :_  %.n
      %-  with-choice:with-refund:simple-from-note:new:input:transact
      [recipient gift 0 note sender-key receive-address.state]
    ::
    ?.  spent-fee
      ~|("no note suitable to subtract fee from, aborting operation" !!)
    =/  ins-draft=inputs:transact  (multi:new:inputs:transact ins)
    ?:  ?=(~ last-block.state)
      ~|("last-block unknown!" !!)
    ::  name is the b58-encoded name of the first input
    =/  draft-name=@t
      %-  head
      %+  turn  ~(tap z-by:zo (names:inputs:transact ins-draft))
      |=  =nname:transact
      =<  last
      (to-b58:nname:transact nname)
    ::  jam inputs and save as draft
    =/  =draft
      %*  .  *draft
        p  ins-draft
        name  draft-name
      ==
    =/  draft-jam  (jam draft)
    =/  path=@t
      %-  crip
      "./drafts/{(trip name.draft)}.draft"
    %-  (debug "saving draft to {<path>}")
    =/  =effect  [%file %write path draft-jam]
    :-  ~[effect [%exit 0]]
    state
  ::
  ++  do-keygen
    |=  =cause
    ?>  ?=(%keygen -.cause)
    =+  [seed-phrase=@t cor]=(gen-master-key:s10 entropy.cause salt.cause)
    =/  master-public-coil  [%coil [%pub public-key] chain-code]:cor
    =/  master-private-coil  [%coil [%prv private-key] chain-code]:cor
    =.  master.state  (some master-public-coil)
    %-  (debug "keygen: new public key {<public-key:cor>}")
    %-  (debug "keygen: public key: base58 {<(en:base58:wrap public-key:cor)>}")
    %-  (debug "keygen: new private key {<private-key:cor>}")
    %-  (debug "keygen: private key: base58 {<(en:base58:wrap private-key:cor)>}")
    =/  pub-label  `(crip "master-public-{<(end [3 4] public-key:cor)>}")
    =/  prv-label  `(crip "master-public-{<(end [3 4] public-key:cor)>}")
    =.  keys.state  (key:put:v master-public-coil ~ pub-label)
    =.  keys.state  (key:put:v master-private-coil ~ prv-label)
    =.  keys.state  (seed:put:v seed-phrase)
    :-  [%exit 0]~
    state
  ::
  ::  derives child %pub or %prv key of current master key
  ::  at index `i`. this will overwrite existing paths.
  ++  do-derive-child
    |=  =cause
    ?>  ?=(%derive-child -.cause)
    =/  par=coil  ~(master get:v key-type.cause)
    =/  child=coil  (derive-child:v par i.cause)
    =.  keys.state
      (key:put:v child `i.cause label.cause)
    :-  [%exit 0]~
    state
  ::
  ++  do-sign-tx
    |=  =cause
    ?>  ?=(%sign-tx -.cause)
    %-  (debug "sign-tx: {<dat.cause>}")
    ::  get private key at specified index, or first derived key if no index
    =/  private-keys=(list coil)  ~(coils get:v %prv)
    ?~  private-keys
      ~|("No private keys available for signing" !!)
    =/  sender=coil
      ?~  index.cause  i.private-keys
      =/  key-at-index=meta  (~(by-index get:v %prv) u.index.cause)
      ?>  ?=(%coil -.key-at-index)
      key-at-index
    =/  sender-key=schnorr-seckey:transact
      (from-atom:schnorr-seckey:transact p.key.sender)
    =/  signed-inputs=inputs:transact
      %-  ~(run z-by:zo p.dat.cause)
      |=  =input:transact
      %-  (debug "signing input: {<input>}")
      =.  spend.input
        %+  sign:spend:transact
          spend.input
        sender-key
      input
    =/  signed-draft=draft
      %=  dat.cause
        p  signed-inputs
      ==
    =/  draft-jam  (jam signed-draft)
    =/  path=@t
      %-  crip
      "./drafts/{(trip name.signed-draft)}.draft"
    %-  (debug "saving input draft to {<path>}")
    =/  =effect  [%file %write path draft-jam]
    :-  ~[effect [%exit 0]]
    state
  ::
  ++  do-advanced-spend-seed
    |=  cause=advanced-spend-seed
    ^-  [(list effect) ^state]
    |^
    =?  active-draft.state  ?=(~ active-draft.state)  `*draft-name
    =?  active-seed.state  ?=(~ active-seed.state)  `*seed-name
    ?-  -.cause
      %new  do-new
      %set-name  do-set-name
      %set-source  do-set-source
      %set-recipient  do-set-recipient
      %set-timelock  do-set-timelock
      %set-gift  do-set-gift
      %set-parent-hash  do-set-parent-hash
      %set-parent-hash-from-name  do-set-parent-hash-from-name
      %print-status  do-print-status
    ==
    ::
    ++  do-new
      ?>  ?=([%new *] cause)
      =/  sed=preseed
        %*  .  *preseed
          name  name.cause
        ==
      (write-seed sed)
    ::
    ++  do-set-name
      ?>  ?=([%set-name *] cause)
      =/  pre=(unit preseed)
        (get-seed:p seed-name.cause)
      ?>  ?=(^ pre)
      =.  name.u.pre  new-name.cause
      (write-seed u.pre)
    ::
    ++  do-set-source
      ?>  ?=([%set-source *] cause)
      =/  pre=(unit preseed)
        (get-seed:p seed-name.cause)
      ?>  ?=(^ pre)
      =/  sed=preseed
        ?~  source.cause
          %=  u.pre
            output-source.p  ~
            output-source.q  %.y
          ==
        %=  u.pre
          output-source.p  (some (from-b58:source:transact u.source.cause))
          output-source.q  %.y
        ==
      (write-seed sed)
    ::
    ++  do-set-recipient
      ?>  ?=([%set-recipient *] cause)
      =/  pre=(unit preseed)
        (get-seed:p seed-name.cause)
      ?>  ?=(^ pre)
      =/  recipient=lock:transact
        %+  m-of-n:new:lock:transact  m.recipient.cause
        %-  ~(gas z-in:zo *(z-set:zo schnorr-pubkey:transact))
        (turn pks.recipient.cause from-b58:schnorr-pubkey:transact)
      =/  sed=preseed
        %=  u.pre
          recipient.p  recipient
          recipient.q  %.y
        ==
      (write-seed sed)
    ::
    ++  do-set-timelock
      ?>  ?=([%set-timelock *] cause)
      ::TODO
      !!
    ::
    ++  do-set-gift
      ?>  ?=([%set-gift *] cause)
      =/  pre=(unit preseed)
        (get-seed:p seed-name.cause)
      ?>  ?=(^ pre)
      =/  sed=preseed
        %=  u.pre
          gift.p  gift.cause
          gift.q  %.y
        ==
      (write-seed sed)
    ::
    ++  do-set-parent-hash
      ?>  ?=([%set-parent-hash *] cause)
      =/  pre=(unit preseed)
        (get-seed:p seed-name.cause)
      ?>  ?=(^ pre)
      =/  sed=preseed
        %=  u.pre
          parent-hash.q  %.y
          parent-hash.p  (from-b58:hash:transact parent-hash.cause)
        ==
      (write-seed sed)
    ::
    ++  do-set-parent-hash-from-name
      ?>  ?=([%set-parent-hash-from-name *] cause)
      =/  pre=(unit preseed)
        (get-seed:p seed-name.cause)
      ?>  ?=(^ pre)
      =/  name=nname:transact  (from-b58:nname:transact name.cause)
      =/  not=nnote:transact  (get-note:v name)
      =/  sed=preseed
        %=  u.pre
          parent-hash.p  (hash:nnote:transact not)
          parent-hash.q  %.y
        ==
      (write-seed sed)
    ::
    ++  do-print-status
      ?>  ?=([%print-status *] cause)
      =/  pre=(unit preseed)
        (get-seed:p seed-name.cause)
      ?>  ?=(^ pre)
      =/  output-source-text=tape
        ?:  !output-source.q.u.pre
          "Unset (any output source is OK)"
        <output-source.p.u.pre>
      =/  recipient-text=tape
        ?:  !recipient.q.u.pre
          "Unset"
        <recipient.p.u.pre>
      =/  timelock-text=tape
        ?:  !timelock-intent.q.u.pre
          "Unset (no intent)"
        <timelock-intent.p.u.pre>
      =/  gift-text=tape
        ?:  !gift.q.u.pre
          "Gift: unset (gift must be nonzero)"
        ?:  =(0 gift.p.u.pre)
          """
          Gift: 0 (must be nonzero)
          """
        """
        Gift: {<gift.p.u.pre>}
        """
      =/  status-text=tape
        """
        ## Seed Status

        ### Output Source
        {output-source-text}

        ### Recipient
        {recipient-text}

        ### Timelock Intent
        {timelock-text}

        ### Gift
        {gift-text}
        """
      :_  state
      (print (need (de:md (crip status-text))))
    ::
    ++  write-seed
      |=  sed=preseed
      ^-  [(list effect) ^state]
      =.  active-seed.state  (some name.sed)
      =.  draft-tree.state  (~(add-seed plan draft-tree.state) name.sed sed)
      =^  writes  state  write-draft:d
      [writes state]
    --  ::+do-advanced-spend-seed
  ::
  ++  do-advanced-spend-input
    |=  cause=advanced-spend-input
    ^-  [(list effect) ^state]
    |^
    ?-  -.cause
      %new  do-new
      %set-name  do-set-name
      %add-seed  do-add-seed
      %set-fee   do-set-fee
      %set-note-from-name  do-set-note-from-name
      %set-note-from-hash  do-set-note-from-hash
      %derive-note-from-seeds  do-derive-note-from-seeds
      %remove-seed  do-remove-seed
      %remove-seed-by-hash  do-remove-seed-by-hash
      %print-status  do-print-status
    ==
    ::
    ++  do-new
      ?>  ?=([%new *] cause)
      =/  inp=preinput
        %*  .  *preinput
          name  name.cause
        ==
      =.  active-input.state  (some name.cause)
      (write-input inp)
    ::
    ++  do-set-name
      ?>  ?=([%set-name *] cause)
      =/  pre=(unit preinput)
        (get-input:p input-name.cause)
      ?>  ?=(^ pre)
      =.  name.u.pre  new-name.cause
      =.  active-input.state  (some new-name.cause)
      (write-input u.pre)
    ::
    ++  do-add-seed
      ?>  ?=([%add-seed *] cause)
      ::
      =/  pre=(unit preinput)
        (get-input:p input-name.cause)
      ?>  ?=(^ pre)
      =/  sed=(unit preseed)
        (get-seed:p seed-name.cause)
      ?>  ?=(^ sed)
      ?:  (~(has z-in:zo seeds.spend.p.u.pre) p.u.sed)
        :_  state
        =/  nodes=markdown:m
          :~  :-  %leaf
              :-  %paragraph
              :~  [%text (crip "seed already exists in .spend, doing nothing.")]
              ==
          ==
        (print nodes)
      =/  inp=preinput
        %=  u.pre
          seeds.spend.p  (~(put z-in:zo seeds.spend.p.u.pre) p.u.sed)
          seeds.spend.q  %.y
        ==
      (write-input inp)
    ::
    ++  do-set-fee
      ?>  ?=([%set-fee *] cause)
      =/  pre=(unit preinput)
        (get-input:p input-name.cause)
      ?>  ?=(^ pre)
      =.  fee.spend.p.u.pre  fee.cause
      =.  fee.spend.q.u.pre  %.y
      (write-input u.pre)
    ::
    ++  do-set-note-from-name
      ?>  ?=([%set-note-from-name *] cause)
      ::
      =/  pre=(unit preinput)
        (get-input:p input-name.cause)
      ?>  ?=(^ pre)
      =/  name=nname:transact  (from-b58:nname:transact name.cause)
      =/  not=nnote:transact  (get-note:v name)
      =/  inp=preinput
        %=  u.pre
          note.p  not
          note.q  %.y
        ==
      (write-input inp)
    ::
    ++  do-set-note-from-hash
      ?>  ?=([%set-note-from-hash *] cause)
      ::
      =/  pre=(unit preinput)
        (get-input:p input-name.cause)
      ?>  ?=(^ pre)
      =/  =hash:transact  (from-b58:hash:transact hash.cause)
      =/  note=nnote:transact  (get-note-from-hash:v hash)
      =/  inp=preinput
        %=  u.pre
          note.p  note
          note.q  %.y
        ==
      (write-input inp)
    ::
    ++  do-derive-note-from-seeds
      ?>  ?=([%derive-note-from-seeds *] cause)
      ::
      =/  pre=(unit preinput)
        (get-input:p input-name.cause)
      ?>  ?=(^ pre)
      =/  seeds-list=(list seed:transact)
        ~(tap z-in:zo seeds.spend.p.u.pre)
      ?~  seeds-list
        :_  state
        =/  nodes=markdown:m
          :~  :-  %leaf
              :-  %paragraph
              :~  [%text (crip "no seeds exist in .spend, so note cannot be set.")]
              ==
          ==
        (print nodes)
      =/  =hash:transact  parent-hash.i.seeds-list
      =/  note=nnote:transact  (get-note-from-hash:v hash)
      =/  inp=preinput
        %=  u.pre
          note.p  note
          note.q  %.y
        ==
      (write-input inp)
    ::
    ++  do-remove-seed
      ?>  ?=([%remove-seed *] cause)
      ::
      =/  pre=(unit preinput)
        (get-input:p input-name.cause)
      ?>  ?=(^ pre)
      =.  active-input.state  (some input-name.cause)
      =/  sed=(unit preseed)
        (get-seed:p seed-name.cause)
      ?>  ?=(^ sed)
      ?:  !(~(has z-in:zo seeds.spend.p.u.pre) p.u.sed)
        :_  state
        =/  nodes=markdown:m
          :~  :-  %leaf
              :-  %paragraph
              :~  [%text (crip "seed does not exist in .spend, doing nothing")]
              ==
          ==
        (print nodes)
      =/  inp=preinput
        %=  u.pre
          seeds.spend.p  (~(del z-in:zo seeds.spend.p.u.pre) p.u.sed)
          seeds.spend.q  !=(*seeds:transact seeds.spend.p.u.pre)
        ==
      (write-input inp)
    ::
    ++  do-remove-seed-by-hash
      ?>  ?=([%remove-seed-by-hash *] cause)
      :: find seed with hash
      =/  pre=(unit preinput)
        (get-input:p input-name.cause)
      ?>  ?=(^ pre)
      =.  active-input.state  (some input-name.cause)
      =/  seed-hashes=(z-map:zo hash:transact seed:transact)
        %-  ~(gas z-by:zo *(z-map:zo hash:transact seed:transact))
        %+  turn  ~(tap z-in:zo seeds.spend.p.u.pre)
        |=  sed=seed:transact
        [(hash:seed:transact sed) sed]
      =/  has=hash:transact  (from-b58:hash:transact hash.cause)
      ?.  (~(has z-by:zo seed-hashes) has)
        :_  state
        =/  nodes=markdown:m
          :~  :-  %leaf
              :-  %paragraph
              :~  [%text (crip "seed does not exist in .spend, doing nothing")]
              ==
          ==
        (print nodes)
      =/  remove-seed=seed:transact
        (~(got z-by:zo seed-hashes) has)
      ::
      =/  inp=preinput
        %=  u.pre
          seeds.spend.p  (~(del z-in:zo seeds.spend.p.u.pre) remove-seed)
          seeds.spend.q  !=(*seeds:transact seeds.spend.p.u.pre)
        ==
      (write-input inp)
    ::
    ++  do-print-status
      ?>  ?=([%print-status *] cause)
      =/  pre=(unit preinput)
        (get-input:p input-name.cause)
      ?>  ?=(^ pre)
      =|  status-nodes=markdown:m
      =.  status-nodes
        %+  snoc  status-nodes
        :-  %leaf
        :-  %paragraph
        ?:  !signature.spend.q.u.pre
          ::  TODO we removed the ability to sign in this control flow
          [%text (crip ".signature: unset")]~
        ::  check the signature
        ::
        ::  get a .parent-hash of a seed. they have to all be the same, so which
        ::  one doesn't matter; if they're not all the same validation will fail.
        =/  seeds-list=(list seed:transact)
          ~(tap z-in:zo seeds.spend.p.u.pre)
        ?~  seeds-list
          [%text (crip "no seeds exist, so signature cannot be checked")]~
        =/  parent-note-hash=hash:transact  parent-hash.i.seeds-list
        =/  parent-note-hash-b58=tape
          (trip (to-b58:hash:transact parent-note-hash))
        =/  parent-note-name=(unit nname:transact)
          (~(get z-by:zo hash-to-name.state) parent-note-hash)
        ?~  parent-note-name
          :~
            :-  %text
            %-  crip
            """
            note with hash {parent-note-hash-b58} present in .spend but
            has no matching .name in wallet
            """
            :-  %text
            ::  TODO better, more succint error message.
            '''
            this implies that it is not in the balance unless there is a hash collision.
            please report this as a bug if you are sure you have the $note, as this
            situation is very unlkely. the spend ought to still be valid in that case
            and you can broadcast it anyway.
            '''
          ==
        =/  parent-note-name-b58=tape
          =;  [first=@t last=@t]
            "<(trip first)> <(trip last)>"
          (to-b58:nname:transact u.parent-note-name)
        =/  parent-note=(unit nnote:transact)
          (~(get z-by:zo balance.state) u.parent-note-name)
        ?~  parent-note
          :~
            :-  %text
            %-  crip
            """
            note with name {parent-note-name-b58} and hash {parent-note-hash-b58}
            present in .spend but not in balance
            """
          ==
        ?:  (verify:spend:transact spend.p.u.pre u.parent-note)
          [%text (crip "signature(s) on spend are valid.")]~
        ::  missing or invalid sigs
        =/  have-sigs
          %+  turn
            %~  tap  z-in:zo
            ^-  (z-set:zo schnorr-pubkey:transact)
            %~  key  z-by:zo  (need signature.spend.p.u.pre)
          |=  pk=schnorr-pubkey:transact
          [%text (to-b58:schnorr-pubkey:transact pk)]
        ?~  have-sigs
          [%text 'no signatures found!']~
        =/  lock-b58=[m=@ pks=(list @t)]
          (to-b58:lock:transact recipient.i.seeds-list)
        =/  need-sigs
          (turn pks.lock-b58 (lead %text))
        ?~  need-sigs
          [%text 'no recipients found!']~
        ;:  welp
          :~  [%text (crip "signature on spend did not validate.")]
              [%text (crip "signatures on spend:")]
          ==
          ::TODO check if any particular signature did not validate
          have-sigs
          :~  [%text (crip ".lock on parent note:")]
              [%text (crip "number of sigs required: {(scow %ud m.lock-b58)}")]
              [%text (crip "pubkeys of possible signers:")]
          ==
          need-sigs
        ==
      ::TODO  check individual seeds? this would require some refactoring and
      ::the happy path does not involve adding unfinished seeds to an input.
      :_  state
      (print status-nodes)
    ::
    ++  write-input
      |=  inp=preinput
      ^-  [(list effect) ^state]
      =.  active-input.state  (some name.inp)
      =.  draft-tree.state  (~(add-input plan draft-tree.state) name.inp inp)
      =^  writes  state  write-draft:d
      [writes state]
    --  ::+do-advanced-spend-input
  ::
  ++  do-advanced-spend-draft
    |=  cause=advanced-spend-draft
    ^-  [(list effect) ^state]
    |^
    =?  active-draft.state  ?=(~ active-draft.state)  `*draft-name
    ?-  -.cause
      %new  do-new
      %set-name  do-set-name
      %add-input  do-add-input
      %remove-input  do-remove-input
      %remove-input-by-name  do-remove-input-by-name
      %print-status  do-print-status
    ==
    ::
    ++  do-new
      ?>  ?=([%new *] cause)
      =.  active-draft.state  (some name.cause)
      =/  dat=draft
        %*  .  *draft
          name  name.cause
        ==
      (write-draft dat)
    ::
    ++  do-set-name
      ?>  ?=([%set-name *] cause)
      =/  pre=(unit draft)
        (get-draft:p draft-name.cause)
      ?>  ?=(^ pre)
      =.  active-draft.state  (some new-name.cause)
      =.  name.u.pre  new-name.cause
      (write-draft u.pre)
    ::
    ++  do-add-input
      ?>  ?=([%add-input *] cause)
      =/  pre=(unit draft)
        (get-draft:p draft-name.cause)
      ?>  ?=(^ pre)
      =.  active-draft.state  (some draft-name.cause)
      =/  inp=(unit preinput)
        (get-input:p input-name.cause)
      ?>  ?=(^ inp)
      ?:  (~(has z-by:zo p.u.pre) name.note.p.u.inp)
        :_  state
        %-  print
        ^-  markdown:m
        :_  ~  :-  %leaf
        :-  %paragraph
        :_  ~  :-  %text
        %-  crip
        """
        draft already has input with note name
        {<(to-b58:nname:transact name.note.p.u.inp)>}, doing nothing.
        """
      =.  p.u.pre
        (~(put z-by:zo p.u.pre) [name.note.p.u.inp p.u.inp])
      (write-draft u.pre)
    ::
    ++  do-remove-input
      ?>  ?=([%remove-input *] cause)
      =/  pre=(unit draft)
        (get-draft:p draft-name.cause)
      ?>  ?=(^ pre)
      =.  active-draft.state  (some draft-name.cause)
      =/  inp=(unit preinput)
        (get-input:p input-name.cause)
      ?>  ?=(^ inp)
      ?.  (~(has z-by:zo p.u.pre) name.note.p.u.inp)
        :_  state
        %-  print
        :_  ~  :-  %leaf
        :-  %paragraph
        :_  ~  :-  %text
        %-  crip
        """
        draft does not have input with note name
        {<(to-b58:nname:transact name.note.p.u.inp)>}, doing nothing.
        """
      ?.  =(u.inp (~(got z-by:zo p.u.pre) name.note.p.u.inp))
        :_  state
        %-  print
        :_  ~  :-  %leaf
        :-  %paragraph
        :_  ~  :-  %text
        %-  crip
        """
        draft has input with note name
        {<(to-b58:nname:transact name.note.p.u.inp)>}, but it is
        a different input. to remove this input, use %remove-input-by-name
        instead.
        """
      =.  p.u.pre
        (~(del z-by:zo p.u.pre) name.note.p.u.inp)
      (write-draft u.pre)
    ::
    ++  do-remove-input-by-name
      ?>  ?=([%remove-input-by-name *] cause)
      =/  pre=(unit draft)
        (get-draft:p draft-name.cause)
      =.  active-draft.state  (some draft-name.cause)
      ?>  ?=(^ pre)
      =/  name=nname:transact  (from-b58:nname:transact name.cause)
      ?.  (~(has z-by:zo p.u.pre) name)
        :_  state
        %-  print
        :_  ~  :-  %leaf
        :-  %paragraph
        :_  ~  :-  %text
        %-  crip
        """
        draft does not have input with note name {(trip first.name.cause)}
        {(trip last.name.cause)}, doing nothing.
        """
      =.  p.u.pre  (~(del z-by:zo p.u.pre) name)
      (write-draft u.pre)
    ::
    ++  do-print-status
      ?>  ?=([%print-status *] cause)
      =/  pre=(unit draft)
        (get-draft:p draft-name.cause)
      =.  active-draft.state  (some draft-name.cause)
      ?>  ?=(^ pre)
      =/  inputs=(list [name=nname:transact =input:transact])
        ~(tap z-by:zo p.u.pre)
      =/  input-texts=(list tape)
        %+  turn  inputs
        |=  [name=nname:transact =input:transact]
        =/  signature-text=tape  ?~(signature.spend.input "unset" "set")
        =/  name-text=tape  <(to-b58:nname:transact name)>
        =/  note-text=tape  <(to-b58:hash:transact (hash:nnote:transact note.input))>
        =/  seeds-text=tape
          %-  zing
          %+  turn  ~(tap z-in:zo seeds.spend.input)
          |=  =seed:transact
          """
          - recipient: {<(to-b58:lock:transact recipient.seed)>}
          - gift: {<gift.seed>}
          - parent hash: {<(to-b58:hash:transact parent-hash.seed)>}
          """
        """
        #### Input {name-text}:

        - Note hash: {note-text}
        - Fee: {<fee.spend.input>}
        - Signature: {signature-text}

        ##### Seeds

        {seeds-text}

        """
      =/  status-text=tape
        """
        ## Draft Status

        Name: {(trip name.u.pre)}
        Number of inputs: {<(lent inputs)>}

        ### Inputs

        {(zing input-texts)}
        """
      :_  state
      (print (need (de:md (crip status-text))))
    ::
    ++  write-draft
      |=  dat=draft
      ^-  [(list effect) ^state]
      =.  active-draft.state  (some name.dat)
      write-draft:d
    --  ::+do-advanced-spend-draft
  --  ::+poke
--
