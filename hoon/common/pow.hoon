/=  sp  /common/stark/prover
/=  np  /common/nock-prover
/=  *  /common/zeke
|%
++  check-target
  |=  [proof-hash-atom=tip5-hash-atom target-bn=bignum:bignum]
  ^-  ?
  =/  target-atom=@  (merge:bignum target-bn)
  ?>  (lte proof-hash-atom max-tip5-atom:tip5)
  (lte proof-hash-atom target-atom)
::
++  prove-block  (cury prove-block-inner pow-len)
::
::  +prove-block-inner
++  prove-block-inner
  |=  [length=@ block-commitment=noun-digest:tip5 nonce=noun-digest:tip5]
  ^-  [proof:sp tip5-hash-atom]
  =/  =prove-result:sp
    (prove:np block-commitment nonce length ~)
  ?>  ?=(%& -.prove-result)
  =/  =proof:sp  p.prove-result
  =/  proof-hash=tip5-hash-atom  (proof-to-pow proof)
  [proof proof-hash]
--
