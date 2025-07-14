/=  sp  /common/stark/prover
/=  np  /common/nock-prover
/=  *  /common/zeke
|%
++  check-target
  |=  [proof-hash-atom=tip5-hash-atom target-bn=bignum:bignum]
  ^-  ?
  (check-target-atom proof-hash-atom (merge:bignum target-bn))
::
++  check-target-atom
  |=  [proof-hash-atom=tip5-hash-atom target-atom=tip5-hash-atom]
  ^-  ?
  ?>  (lte proof-hash-atom max-tip5-atom:tip5)
  (lte proof-hash-atom target-atom)
::
++  prove-block  (cury prove-block-inner pow-len)
::
::  +prove-block-inner
++  prove-block-inner
  |=  prover-input:sp
  ^-  [proof:sp tip5-hash-atom]
  =/  =prove-result:sp
    ?-  version
      %0  (prove:np version header nonce pow-len)
      %1  (prove:np version header nonce pow-len)
      %2  (prove:np version header nonce pow-len)
    ==
  ?>  ?=(%& -.prove-result)
  =/  =proof:sp  p.prove-result
  =/  proof-hash=tip5-hash-atom  (proof-to-pow proof)
  [proof proof-hash]
--
