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
<<<<<<< HEAD
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
=======
  +$  cause
    $%  [%0 header=noun-digest:tip5 nonce=noun-digest:tip5 target=bignum:bignum pow-len=@]
        [%1 header=noun-digest:tip5 nonce=noun-digest:tip5 target=bignum:bignum pow-len=@]
        [%2 header=noun-digest:tip5 nonce=noun-digest:tip5 target=bignum:bignum pow-len=@]
>>>>>>> upstream/master
    ==
  ::
  +$  success
    $:  
      commit=block-commitment:t
      dig=tip5-hash-atom
      prf=proof:sp
    ==
  +$  effect  
    $%
      [%miss hash=noun-digest:tip5]
      [%pool success]
      [%network success]
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
    =/  cause  ((soft cause) dat)
    ?~  cause
      ~>  %slog.[1 'poke: Bad cause']
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
<<<<<<< HEAD
    ::
    =/  [prf=proof:sp dig=tip5-hash-atom] 
=======
    :: XX TODO set up stark config, construct effect
    =/  [prf=proof:sp dig=tip5-hash-atom]
>>>>>>> upstream/master
      (prove-block-inner:mine input)
    =;  eff  
      :_  k  ~[eff]
    ?.  (check-target:mine dig network-target.c)
      ?.  (check-target:mine dig pool-target.c)
        [%miss (atom-to-digest:tip5 dig)]
      [%pool commit.c dig prf]
    [%network commit.c dig prf]
  --
--
