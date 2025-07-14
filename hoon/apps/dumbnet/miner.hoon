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
  +$  pool-id    @tas
  +$  user-id-1  @tas
  +$  user-id-2  @tas
  ::
  +$  cause
    $:
      version=?(%0 %1)
      make-proof=?
      commit=block-commitment:t
      =pool-id
      =user-id-1
      =user-id-2
    ==
  ::
  +$  effect  
    $:
      %res
      eny=@
      commit=block-commitment:t
      prf=proof:sp
      dig=tip5-hash-atom
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
    =/  cause  u.cause
    ::
    =+  nonce-seed=[pool-id.cause user-id-1.cause user-id-2.cause eny]
    ::
    =/  nonce=noun-digest:tip5
      (hash-noun-varlen:tip5 nonce-seed)
    ::
    =/  commit  commit.cause
    ::
    =/  input=prover-input:sp
      ?-  version.cause
        %0  [%0 commit nonce pow-len]
        %1  [%1 commit nonce pow-len]
      ==
    ::
    ~&  %generating-proof
    =/  [prf=proof:sp dig=tip5-hash-atom] 
      ?:  make-proof.cause
        (prove-block-inner:mine input)
      [*proof:sp *tip5-hash-atom]
    ~&  proof-done+dig
    :_  k
    ~[[%res eny commit prf dig]]
  --
--
