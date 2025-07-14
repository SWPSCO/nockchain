/=  mine  /common/pow
/=  nv  /common/nock-verifier
/=  *  /common/zoon
/=  *  /common/zeke
/=  *  /common/wrapper
::
=<  ((moat |) inner)
=>
|%
+$  kernel-state  ~
::  $cause: possible pokes
::
::    %share:
::      .share: result from a miner
::      .target: target needed to be met for share to be valid
::      .pow-len: the length of the powork puzzle. always 64 on livenet.
+$  cause
  $%  $:  %share
          share=[eny=@ commit=noun-digest:tip5 prf=proof dig=tip5-hash-atom]
          target=@
          pow-len=@
  ==  ==
::
::  since we are only pulling one share at a time and responding about whether it
::  verified before pulling the next, we dont need to identify the share in the effect.
::  we might want to though for more robustness and visibility into what's going on, but
::  i'm going to skip it for now.
+$  effect
  $%  [%good-share ~]
      [%bad-share why=@tas]
  ==
--
::
|%
++  moat  (keep kernel-state)
++  inner
  |_  k=kernel-state
  ++  load  |=(=kernel-state kernel-state)
  ::
  ++  peek
    |=  arg=*
    =/  pax  ((soft path) arg)
    ?~  pax  ~|(not-a-path+arg !!)
    ~|(invalid-peek+pax !!)
  ::
  ++  poke
    |=  [wir=wire eny=@ our=@ux now=@da dat=*]
    ^-  [(list effect) k=kernel-state]
    ~&  "foo"
    ::
    ~&  dat+dat
    =/  cause  ((soft cause) dat)
    ?~  cause
      ~>  %slog.[0 [%leaf "error: bad cause"]]
      `k
    =/  cause  u.cause
    ?>  ?=([%share *] cause)
    =/  prf=proof  prf.share.cause
    ::
    ::  validate that the correct powork puzzle was solved
    =/  check-pow-puzzle=?
      ?:  =((lent objects.prf) 0)  %.n
      =/  puzzle  (snag 0 objects.prf)
      ?.  ?=([%puzzle *] puzzle)  %.n
      =(pow-len.cause len.puzzle)
    ?.  check-pow-puzzle
      :_  k
      [%bad-share %wrong-pow-length]~
    ::
    ::  validate the proof
    =/  valid=?
      (verify:nv prf ~ eny.share.cause)
    ?.  valid
      :_  k
      [%bad-share %bad-proof]~
    ::
    ?:  (check-target-atom:mine dig.share.cause target.cause)
      ::  they hit the target, credit the share
      :_  k
      [%good-share ~]~
    ::  they sent in a valid share that did not hit the target
    :_  k
    [%bad-share %below-target]~
  --
--
