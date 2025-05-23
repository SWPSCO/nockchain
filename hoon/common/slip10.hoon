::  slip-10 implementation in hoon using the cheetah curve
::
::  to use, call one of the core initialization arms.
::  using the produced core, derive as needed and take out the data you want.
::
::  NOTE:  tested to be correct against the SLIP-10 spec
::   https://github.com/satoshilabs/slips/blob/master/slip-0010.md
::
/=  *  /common/zose
/=  *  /common/zeke
=,  hmac:crypto
=,  cheetah:zeke
=+  ecc=cheetah
::
::  prv:  private key
::  pub:  public key
::  cad:  chain code
::  dep:  depth in chain
::  ind:  index at depth
::  pif:  parent fingerprint (4 bytes)
=>  |%
    +$  base  [prv=@ pub=a-pt:curve cad=@ dep=@ud ind=@ud pif=@]
    --
|_  base
+$  base  ^base
::
+$  keyc  [key=@ cai=@]  ::  prv/pub key + chain code
::
::  elliptic curve operations and values
::
++  point  ch-scal:affine:curve
::
++  ser-p  ser-a-pt
::
++  n      g-order:curve
::
++  domain-separator  [14 'dees niahckcoN']
::
::
::  rendering
::
++  private-key     ?.(=(0 prv) prv ~|(%know-no-private-key !!))
++  public-key      (ser-p pub)
++  chain-code      cad
::
++  identity        (hash160 public-key)
++  fingerprint     (cut 3 [16 4] identity)
::
++  hash160
  |=  d=@
  (ripemd-160:ripemd:crypto 32 (sha-256:sha d))
::
::  core initialization
::
++  from-seed
  |=  byts
  ^+  +>
  =+  der=(hmac-sha512l domain-separator [wid dat])
  =/  [left=@ right=@]
    [(cut 3 [32 32] der) (cut 3 [0 32] der)]
  ::
  ::  In the case where the left is greater than or equal to the curve order,
  ::  We have an invalid key and will use the right digest to rehash until we
  ::  obtain a valid key. This prevents the distribution from being biased.
  |-
  ?:  (lth left n)
    +>.^$(prv left, pub (point left a-gen:curve), cad right)
  =/  der  (hmac-sha512l domain-separator 64^der)
  %=    $
    der  der
    left  (cut 3 [32 32] der)
    right  (cut 3 [0 32] der)
  ==
::
++  from-private
  |=  keyc
  +>(prv key, pub (point key a-gen:curve), cad cai)
::
++  from-public
  |=  keyc
  +>(pub (de-a-pt key), cad cai)
::
::  derivation arms: Only used for testing.
::
::    +derive-path
::
::  Given a bip32-style path, i.e "m/0'/25", derive the key associated
::  with that path.
::
++  derive-path
  |=  t=tape
  %-  derive-sequence
  (scan t derivation-path)
::
::    +derivation-path
::
::  Parses the bip32-style derivation path and return a list of indices
::
++  derivation-path
  ;~  pfix
    ;~(pose (jest 'm/') (easy ~))
  %+  most  fas
  ;~  pose
    %+  cook
      |=(i=@ (add i (bex 31)))
    ;~(sfix dem soq)
  ::
    dem
  ==  ==
::
::    +derive-sequence
::
::  Derives a key from a list of indices associated with a bip32-style path.
::
++  derive-sequence
  |=  j=(list @u)
  ?~  j  +>
  =.  +>  (derive i.j)
  $(j t.j)
::
::    +derive
::
::  Checks if prv has been set to 0, denoting a wallet which only
::  contains public keys. If prv=0, call derive-public otherwise
::  call derive-private.
::
++  derive
  ?:  =(0 prv)
    derive-public
  derive-private
::
::    +derive-private
::
::  derives the i-th child key from `prv`
::
++  derive-private
  |=  i=@u
  ^+  +>
  ::  we must have a private key to derive the next one
  ?:  =(0 prv)
    ~|  %know-no-private-key
    !!
  ::  derive child at i
  =/  [left=@ right=@]
    =-  [(cut 3 [32 32] -) (cut 3 [0 32] -)]
    %+  hmac-sha512l  [32 cad]
    ?:  (gte i (bex 31))
      ::  hardened child
      [37 (can 3 ~[4^i 32^prv 1^0])]
    ::  normal child
    [101 (can 3 ~[4^i 97^(ser-p (point prv a-gen:curve))])]
  =+  key=(mod (add left prv) n)
  ::
  ::  In the case where `left` is greater than or equal to the curve order,
  ::  or the key is the identity point, we have an invalid key and will
  ::  rehash `0x1 || right || i` to obtain a valid key. This prevents the
  ::  distribution from being biased.
  |-
  ?:  &(!=(0 key) (lth left n))
    %_  +>.^$
      prv   key
      pub   (point key a-gen:curve)
      cad   right
      dep   +(dep)
      ind   i
      pif   fingerprint
    ==
  =/  [left=@ right=@]
    =-  [(cut 3 [32 32] -) (cut 3 [0 32] -)]
    %+  hmac-sha512l  [32 cad]
    [37 (can 3 ~[4^i 32^right 1^0x1])]
  %=    $
    left   left
    right  right
    key    (mod (add left prv) n)
  ==
::
::    +derive-public
::
::  derives the i-th child key from `pub`
++  derive-public
  |=  i=@u
  ^+  +>
  ::  public keys can't be hardened
  ?:  (gte i (bex 31))
    ~|  %cant-derive-hardened-public-key
    !!
  ::  derive child at i
  =/  [left=@ right=@]
    =-  [(cut 3 [32 32] -) (cut 3 [0 32] -)]
    %+  hmac-sha512l  [32 cad]
    101^(can 3 ~[4^i 97^(ser-p pub)])
  =+  key=(ch-add:affine:curve (point left a-gen:curve) pub)
  ::
  ::  In the case where `left` is greater than or equal to the curve order,
  ::  or the key is the identity point, we have an invalid key and will
  ::  rehash `0x1 || right || i` to obtain a valid key. This prevents the
  ::  distribution from being biased.
  |-
  ?:  &((lth left n) !=(a-id:curve key))
    %_  +>.^$
      pub   key
      cad   right
      dep   +(dep)
      ind   i
      pif   fingerprint
    ==
  =/  [left=@ right=@]
    =-  [(cut 3 [32 32] -) (cut 3 [0 32] -)]
    %+  hmac-sha512l  [32 cad]
    [37 (can 3 ~[4^i 32^right 1^0x1])]
  %=    $
    left   left
    right  right
    key   (ch-add:affine:curve (point left a-gen:curve) pub)
  ==
--
