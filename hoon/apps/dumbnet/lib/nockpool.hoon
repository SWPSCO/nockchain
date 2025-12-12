/=  zeke  /common/zeke
/=  *  /common/zoon
/=  dcon  /apps/dumbnet/lib/consensus
/=  dumb-transact  /common/tx-engine
/=  dk  /apps/dumbnet/lib/types
/=  sp  /common/stark/prover
|%
++  peek
  |=  [arg=path k=kernel-state:dk]
  =/  =(pole)  arg
  ^-  (unit (unit *))
  =/  t  ~(. dumb-transact constants.k)
  =/  con  ~(. dcon c.k constants.k)
  ?+  pole  ~
    ::
      [%commitment-at height=@ ~]
    ^-  (unit (unit [noun-digest:tip5:zeke coins:t]))
    =/  num=(unit page-number:t)
      ((soft page-number:t) height.pole)
    ?~  num
      ~
    =/  id=(unit block-id:t)
      (~(get z-by heaviest-chain.d.k) u.num)
    ?~  id
      [~ ~]
    =/  pag
      (bind (~(get z-by blocks.c.k) u.id) to-page:local-page:t)
    ?~  pag
      [~ ~]
    =/  cb=coinbase-split:t  ~(coinbase get:page:t u.pag)
    ::  we only support page-v1 so if its a v0 page, we return a [~ ~]
    ?.  ?=([%1 *] cb)
      [~ ~]
    =/  reward=coins:t
      %-  ~(rep z-by +.cb)
      |=  [[=hash:t amt=coins:t] total=coins:t]
      (add amt total)
    =/  pow-data  ~(pow get:page:t u.pag)
    ?~  pow-data
      [~ ~]
    =/  prf  u.pow-data
    ?:  =((lent objects.prf) 0)
      [~ ~]
    =/  puzzle  (snag 0 objects.prf)
    ?.  ?=([%puzzle *] puzzle)
      [~ ~]
    ~&  commitment+commitment.puzzle
    ``[commitment.puzzle reward]
    ::
      [%template difficulty=@ ~]
    ^-  (unit (unit [?(%0 %1 %2) noun-digest:tip5:zeke bignum:bignum:zeke bignum:bignum:zeke @ @]))
    ::
    =/  commit=block-commitment:t
      (block-commitment:page:t candidate-block.m.k)
    ::
    =/  network-target
      (~(got z-by targets.c.k) ~(parent get:page:t candidate-block.m.k))
    ::
    =/  pool-target  (chunk:bignum:zeke (div max-tip5-atom:tip5:zeke (bex difficulty.pole)))
    ::
    =/  height  ~(height get:page:t candidate-block.m.k)
    ::
    =/  version=proof-version:sp
      (height-to-proof-version:con height)
    ::
    :+  ~  ~
    ?-  version
      %0  [%0 commit network-target pool-target height pow-len:t]
      %1  [%1 commit network-target pool-target height pow-len:t]
      %2  [%2 commit network-target pool-target height pow-len:t]
    ==
  ==
--
