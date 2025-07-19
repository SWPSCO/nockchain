/=  mine  /common/pow
/=  sp  /common/stark/prover
/=  t  /common/tx-engine
/=  *  /common/zoon
/=  *  /common/zeke
/=  *  /common/wrapper
=<  ((moat |) inner)  :: wrapped kernel
=>
  |%
  +$  kernel-state  [%state version=%1]
  ::
  +$  cause
    $%
      $:
        %template
        version=?(%0 %1 %2)
        commit=block-commitment:t
        nonce=noun-digest:tip5
        network-target=bignum:bignum
        pool-target=bignum:bignum
        pow-len=@        
      ==
    ==
  ::
  +$  effect  
    $%
      [%invalid ~]
      [%valid commit=block-commitment:t prf=proof:sp dig=tip5-hash-atom valid=?(%network %pool)]
    ==
  ::
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
    ::
    ~&  dat+dat
    =/  cause  ((soft cause) dat)
    ?~  cause
      ~>  %slog.[0 [%leaf "error: bad cause"]]
      `k
    ::
    =/  c  u.cause
    ::
    =/  input=prover-input:sp
      ?-  version.c
        %0  [%0 commit.c nonce.c pow-len.c]
        %1  [%1 commit.c nonce.c pow-len.c]
        %2  [%2 commit.c nonce.c pow-len.c]
      ==
    ::
    ~&  %generating-proof
    =/  [prf=proof:sp dig=tip5-hash-atom] 
      (prove-block-inner:mine input)
    =;  eff  
      :_  k  ~[eff]
    ?.  (check-target:mine dig network-target.c)
      ?.  (check-target:mine dig pool-target.c)
        [%invalid ~]
      [%valid commit.c prf dig %pool]
    [%valid commit.c prf dig %network]
  --
--
