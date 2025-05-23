/=  mine  /common/pow
/=  sp  /common/stark/prover
/=  *  /common/zoon
/=  *  /common/zeke
/=  *  /common/wrapper
=<  ((moat |) inner)  :: wrapped kernel
=>
  |%
  +$  effect  [%command %pow prf=proof:sp dig=tip5-hash-atom block-commitment=noun-digest:tip5 nonce=noun-digest:tip5]
  +$  kernel-state  [%state version=%1]
  +$  cause  [length=@ block-commitment=noun-digest:tip5 nonce=noun-digest:tip5]
  --
|%
++  moat  (keep kernel-state) :: no state
++  inner
  |_  k=kernel-state
  ::  do-nothing load
  ++  load
    |=  =kernel-state  kernel-state
  ::  crash-only peek
  ++  peek
    |=  arg=*
    =/  pax  ((soft path) arg)
    ?~  pax  ~|(not-a-path+arg !!)
    ~|(invalid-peek+pax !!)
  ::  poke: try to prove a block
  ++  poke
    |=  [wir=wire eny=@ our=@ux now=@da dat=*]
    ^-  [(list effect) k=kernel-state]
    =/  cause  ((soft cause) dat)
    ?~  cause
      ~>  %slog.[0 [%leaf "error: bad cause"]]
      `k
    =/  cause  u.cause
    :: XX TODO set up stark config, construct effect
    =/  [prf=proof:sp dig=tip5-hash-atom]  (prove-block-inner:mine cause)
    :_  k
    [%command %pow prf dig block-commitment.cause nonce.cause]~
  --
--
