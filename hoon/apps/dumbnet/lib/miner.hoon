/=  dk  /apps/dumbnet/lib/types
/=  sp  /common/stark/prover
/=  dumb-transact  /common/tx-engine
/=  *  /common/zoon
::
:: everything to do with mining and mining state
::
|_  [m=mining-state:dk =blockchain-constants:dumb-transact]
+*  t  ~(. dumb-transact blockchain-constants)
+|  %admin
::  +set-mining: set .mining
++  set-mining
  |=  mine=?
  ^-  mining-state:dk
  m(mining mine)
::
::  +set-pubkey: set .pubkey
++  set-pubkeys
  |=  pks=(list lock:t)
  ^-  mining-state:dk
  =.  pubkeys.m
    (~(gas z-in *(z-set lock:t)) pks)
  m
::
::  +set-shares validate and set .shares
++  set-shares
  |=  shr=(list [lock:t @])
  =/  s=shares:t  (~(gas z-by *(z-map lock:t @)) shr)
  ?.  (validate:shares:t s)
    ~|('invalid shares' !!)
  m(shares s)
::
+|  %candidate-block
++  set-pow
  |=  prf=proof:sp
  ^-  mining-state:dk
  m(pow.candidate-block (some prf))
::
++  set-digest
  ^-  mining-state:dk
  m(digest.candidate-block (compute-digest:page:t candidate-block.m))
::
::  +update-timestamp: updates timestamp on candidate block if needed
::
::    this should be run every time we get a poke.
++  update-timestamp
  |=  now=@da
  ^-  mining-state:dk
  ?:  |(=(*page:t candidate-block.m) !mining.m)
    ::  not mining or no candidate block is set so no need to update timestamp
    m
  ?:  %+  gte  timestamp.candidate-block.m
      (time-in-secs:page:t (sub now update-candidate-timestamp-interval:t))
    ::  has not been ~m2, so leave timestamp alone
    m
  =.  timestamp.candidate-block.m  (time-in-secs:page:t now)
  =/  print-var
    %-  trip
    ^-  @t
    %^  cat  3
      'candidate block timestamp updated: '
    (scot %$ timestamp.candidate-block.m)
  ~>  %slog.[0 [%leaf print-var]]
  m
::
::  +heard-new-tx: potentially changes candidate block in reaction to a raw-tx
++  heard-new-tx
  |=  raw=raw-tx:t
  ^-  mining-state:dk
  ~>  %slog.[3 'miner: heard-new-tx']
  ~>  %slog.[3 (cat 3 'miner: heard-new-tx: raw-tx: ' (to-b58:hash:t id.raw))]
  ::
  ::  if the mining pubkey is not set, do nothing
  ?:  =(*(z-set lock:t) pubkeys.m)  m
  ::  check to see if block is valid with tx - this checks whether the inputs
  ::  exist, whether the new size will exceed block size, and whether timelocks
  ::  are valid
  =/  tx=(unit tx:t)  (mole |.((new:tx:t raw height.candidate-block.m)))
  ?~  tx
    ::  invalid tx. we don't emit a %liar effect from this because it might
    ::  just not be valid for this particular block
    m
  =/  new-acc=(unit tx-acc:t)
    (process:tx-acc:t candidate-acc.m u.tx height.candidate-block.m)
  ?~  new-acc
    ::~&  >>>  """
    ::         tx {(trip (to-b58:hash:t id.raw))} cannot be added to candidate
    ::         block.
    ::         """
    m
  ::  we can add tx to candidate-block
  =.  tx-ids.candidate-block.m
    (~(put z-in tx-ids.candidate-block.m) id.raw)
  =/  old-fees=coins:t  fees.candidate-acc.m
  =.  candidate-acc.m  u.new-acc
  =/  new-fees=coins:t  fees.candidate-acc.m
  ::  check if new-fees != old-fees to determine if split should be recalculated.
  ::  since we don't have replace-by-fee
  ?:  =(new-fees old-fees)
    ::  fees are equal so no need to recalculate split
    m
  ::  fees are unequal. for this miner, fees are only ever monotonically
  ::  incremented and so this assertion should never fail.
  ?>  (gth new-fees old-fees)
  =/  fee-diff=coins:t  (sub new-fees old-fees)
  ::  compute old emission+fees
  =/  old-assets=coins:t
    %+  roll  ~(val z-by coinbase.candidate-block.m)
    |=  [c=coins:t sum=coins:t]
    (add c sum)
  =/  new-assets=coins:t  (add old-assets fee-diff)
  =.  coinbase.candidate-block.m
    (new:coinbase-split:t new-assets shares.m)
  m
::
::  +heard-new-block: refreshes the candidate block to be mined in reaction to a new block
::
::    when we hear a new heaviest block, we need to update the candidate we're attempting
::    to mine. that means we should update the parent and page number of the block, and carry
::    over any transactions we had previously been attempting to include that werent
::    included in the most recent block.
++  heard-new-block
  |=  [c=consensus-state:dk p=pending-state:dk now=@da]
  ^-  mining-state:dk
  ::
  ::  do a sanity check that we have a heaviest block, and that the heaviest block
  ::  is not the parent of our current candidate block
  ?~  heaviest-block.c
    ::  genesis block has its own codepath, which is why this conditional does not attempt
    ::  to generate the genesis block
    ~>  %slog.[0 leaf+"attempted to generate new candidate block when we have no genesis block"]
    m
  ?:  =(u.heaviest-block.c parent.candidate-block.m)
    ~>  %slog.[0 leaf+"heaviest block unchanged, do not generate new candidate block"]
    m
  ?:  =(*(z-set lock:t) pubkeys.m)
    ~>  %slog.[0 leaf+"no pubkey(s) set so no new candidate block will be generated"]
    m
  =/  print-var
    %-  trip
    ^-  @t
    %^  cat  3
      'generating new candidate block with parent: '
    (to-b58:hash:t u.heaviest-block.c)
  ~>  %slog.[0 [%leaf print-var]]
  =.  candidate-block.m
    %-  new-candidate:page:t
    :*  (to-page:local-page:t (~(got z-by blocks.c) u.heaviest-block.c))
        now
        (~(got z-by targets.c) u.heaviest-block.c)
        shares.m
    ==
  =.  candidate-acc.m
    (new:tx-acc:t (~(get z-by balance.c) u.heaviest-block.c))
  ::
  ::  roll over the pending txs and try to include them in the new candidate block
  %+  roll  ~(val z-by raw-txs.p)
  |=  [raw=raw-tx:t min=_m]
  (heard-new-tx raw)
--
