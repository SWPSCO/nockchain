/=  *    /common/zoon
/=  *    /common/zeke
/=  *    /common/wrapper
/=  t    /common/tx-engine
/=  t1   /common/tx-engine-1
/=  s10  /common/slip10
::
=<  ((moat |) inner)  :: wrapped kernel
::
=>
  |%
  +$  kernel-state  [%state version=%1]
  +$  effect
    $%  [%exit code=@]
        [%file %write path=@t contents=@]
    ==
  :: we want schnorr-seckey:t
  :: +$  cause         [%sign =raw-tx:t1 extended-key=@t]
  +$  cause
    $%  [%sign =raw-tx:t1 extended-key=@t save-file=@t]
    ==
  --
|%
++  moat  (keep kernel-state) :: no state
++  inner
  |_  k=kernel-state
  ::  do-nothing load
  ++  load
    |=  =kernel-state  kernel-state
  ::  crash on peek
  ++  peek
    |=  arg=path
    ~|  %peeks-not-allowed
    !!
  ::
  ++  poke
    |=  [wir=wire eny=@ our=@ux now=@da dat=*]
    ^-  [(list effect) k=kernel-state]
    =/  cause  ((soft cause) dat)
    ?~  cause
      ~>  %slog.[1 'poke: Bad cause']
      :_  k
      [%exit 1]~
    =+  c=u.cause
    ?-  -.c
      ::
        %sign
      ::  process extended key
      ~|  %bad-key
      =/  core  (from-extended-key:s10 extended-key.c)
      ~|  %not-private-key
      ?>  !=(0 prv:core)
      ::  get private key
      =/  sign-key=schnorr-seckey:t
        (from-atom:schnorr-seckey:t private-key:core)
      :: alias for raw-tx
      =/  rtx=raw-tx:t1  raw-tx.c
      ::  sign spends
      =/  signed-spends=spends:t1
        %-  ~(run z-by spends.rtx)
        |=  spend=spend:t1
        (sign:spend-v1:t spend sign-key)
      ::  rebuild rtx with signed spends
      =/  new-rtx=raw-tx:t1  [version.rtx *tx-id:t1 signed-spends]
      ::  compute and set the correct id
      =.  rtx  new-rtx(id (compute-id:raw-tx:t1 new-rtx))
      ::  validate the spends
      ?.  (validate:spends:t1 spends.rtx)
        ~&  'did not validate'
        :_  k  [%exit 1]~
      :_  k
      :~
        ::  write to file
        [%file %write save-file.c (jam rtx)]
        ::  exit the nockapp
        [%exit 0]
      ==
      ::
    ==
  --
--
