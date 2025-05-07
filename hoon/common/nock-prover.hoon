/=  *  /common/zeke
/=  stark-prover  /common/stark/prover
/=  common  /common/nock-common
/#  sc=stark-config
::
|%
::
++  prover
  =|  in=stark-input
  ::  +<+< = stark-engine door sample wrt stark-verifier core
  %_    stark-prover
      +<+<
    %_  in
      stark-config        sc
      all-verifier-funcs  all-verifier-funcs:common
    ==
  ==
::
++  prove
  |=  [header=noun-digest:tip5 nonce=noun-digest:tip5 len=@ override=(unit (list term))]
  (prove:prover header nonce len override)
--
