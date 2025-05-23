/=  dk  /apps/dumbnet/lib/types
/=  sp  /common/stark/prover
/=  mine  /common/pow
/=  dumb-transact  /common/tx-engine
/=  *  /common/zoon
::  this library is where _every_ update to the consensus state
::  occurs, no matter how minor.
|_  [c=consensus-state:dk =blockchain-constants:dumb-transact]
+*  t  ~(. dumb-transact blockchain-constants)
+|  %genesis
::
::  +set-genesis-seal: set .genesis-seal
++  set-genesis-seal
  |=  [height=page-number:t msg-hash=@t]
  ^-  consensus-state:dk
  ~>  %slog.[0 leaf+"setting genesis seal."]
  =/  seal  (new:genesis-seal:t height msg-hash)
  c(genesis-seal seal)
::
++  add-btc-data
  |=  btc-hash=(unit btc-hash:t)
  ^-  consensus-state:dk
  ?:  =(~ btc-hash)
    ~>  %slog.[0 leaf+"Not checking btc hash for genesis block"]
    c(btc-data `btc-hash)
  ~>  %slog.[0 leaf+"received btc block hash, waiting to hear nockchain genesis block!"]
  c(btc-data `btc-hash)
::
+|  %checks-and-computes
++  inputs-in-heaviest-balance
  |=  raw=raw-tx:t
  ^-  ?
  (inputs-in-balance raw get-cur-balance-names)
::
++  inputs-in-balance
  |=  [raw=raw-tx:t balance=(z-set nname:t)]
  ^-  ?
  ::  set of inputs required by tx that are not in balance
  =/  in-balance=(z-set nname:t)
    (~(dif z-in (inputs-names:raw-tx:t raw)) balance)
  ::  %.y: all inputs in .raw are in balance
  ::  %.n: input(s) in .raw not in balance
  =(*(z-set nname:t) in-balance)
::
++  get-cur-height
  ^-  page-number:t
  height:(~(got z-by blocks.c) (need heaviest-block.c))
::
++  get-cur-balance
  ^-  (z-map nname:t nnote:t)
  ?~  heaviest-block.c
    ::~&  >>  "no known blocks, balance is empty"
    *(z-map nname:t nnote:t)
  (~(got z-by balance.c) u.heaviest-block.c)
::
++  get-cur-balance-names
  ^-  (z-set nname:t)
  ~(key z-by get-cur-balance)
::
::
::  +compute-target: find the new target
::
::    this is supposed to be mathematically identical to
::    https://github.com/bitcoin/bitcoin/blob/master/src/pow.cpp
::
::    note that this works differently from what you might expect.
::    we/bitcoin compute "target" where the larger the number is,
::    the easier the block is to find. difficulty is just a human
::    friendly form to read target in. that's why this appears
::    backwards, where e.g. an epoch that takes 2x as long as the
::    desired duration results in doubling the target.
++  compute-target
  |=  [bid=block-id:t prev-target=bignum:bignum:t]
  ^-  bignum:bignum:t
  (compute-target-raw (compute-epoch-duration bid) prev-target)
::
::  +compute-target-raw: helper for +compute-target
::
::    makes it easier for unit tests. we currently do not use
::    bignum arithmetic due to lack of testing and it not yet
::    being necessary. once consensus logic starts being run
::    in the zkvm, we will need to change to bignum arithmetic.
++  compute-target-raw
  |=  [epoch-dur=@ prev-target-bn=bignum:bignum:t]
  ^-  bignum:bignum:t
  =/  prev-target-atom=@  (merge:bignum:t prev-target-bn)
  =/  capped-epoch-dur=@
    ?:  (lth epoch-dur quarter-ted:t)
      quarter-ted:t
    ?:  (gth epoch-dur quadruple-ted:t)
      quadruple-ted:t
    epoch-dur
  =/  next-target-atom=@
    %+  div
      (mul prev-target-atom capped-epoch-dur)
    target-epoch-duration:t
  =/  next-target-bn=bignum:bignum:t
    ?:  (gth next-target-atom max-target-atom:t)
      max-target:t
    (chunk:bignum:t next-target-atom)
  ?:  =(prev-target-atom next-target-atom)
    next-target-bn
  ~>  %slog.[0 (cat 3 'previous target: ' (scot %ud prev-target-atom))]
  ~>  %slog.[0 (cat 3 'new target: ' (scot %ud next-target-atom))]
  next-target-bn
::
::  +compute-epoch-duration: computes the duration of an epoch in seconds
::
::    to mitigate certain types of "time warp" attacks, the timestamp we mark
::    as the end of an epoch is the median time of the last 11 blocks in the
::    epoch. this also happens to be the min timestamp for the first block
::    in the following epoch, which is already kept track of in
::    .min-timestamps, where the value at a given block-id is the min
::    timestamp of block that has that block-id as its parent. thus
::    the duration of a given epoch is the difference between the minimum timestamp
::    of the first block of the next epoch and the first block of the current
::    epoch.
++  compute-epoch-duration
  |=  last-block=block-id:t
  ^-  @
  =/  prev-last-block=block-id:t
    (~(got z-by epoch-start.c) last-block)
  =/  epoch-start=@
    (~(got z-by min-timestamps.c) prev-last-block)
  =/  epoch-end=@
    (~(got z-by min-timestamps.c) last-block)
  ~|  "time warp attack: negative epoch duration"
  (sub epoch-end epoch-start)
::
::  +check-size: check on page size, requires all raw-tx
++  check-size
  |=  [p=pending-state:dk pag=page:t]
  ^-  ?
  (lte (compute-size:page:t pag raw-txs.p) max-block-size:t)
::
+|  %page-handling
++  add-page
  |=  [pag=page:t acc=tx-acc:t now=@da]
  ^-  consensus-state:dk
  ::  update balance
  ::
  =?  balance.c  !=(~ balance.acc)
    ::  if balance.acc is empty, this would still add the following to balance.c,
    ::  so we do it conditionally.
    (~(put z-by balance.c) digest.pag balance.acc)
  =/  coinbases=(list coinbase:t)
    %+  turn  ~(tap z-in ~(key z-by coinbase.pag))
    |=  =lock:t
    (new:coinbase:t pag lock)
  =.  balance.c
    %+  roll  coinbases
    |=  [=coinbase:t bal=_balance.c]
    (~(put z-bi bal) digest.pag name.coinbase coinbase)
  ::  update txs
  ::
  =.  txs.c
    %+  roll  ~(tap z-in txs.acc)
    |=  [=tx:t txs=_txs.c]
    (~(put z-bi txs) digest.pag id.tx tx)
  ::  update blocks
  ::
  =.  blocks.c
    (~(put z-by blocks.c) digest.pag (to-local-page:page:t pag))
  ::
  ::  update epoch map. the first block-id in an epoch maps to its parent,
  ::  and each subsequent block maps to the same block-id as the first. this is helpful
  ::  bookkeeping to avoid a length pointer chase of parent of parent of...
  ::  when reaching the end of an epoch and needing to compute its length.
  =.  epoch-start.c
    ?:  =(*page-number:t height.pag)
      ::  genesis block is also considered the last block of the "0th" epoch.
      (~(put z-by epoch-start.c) digest.pag digest.pag)
    ?:  =(0 epoch-counter.pag)
      (~(put z-by epoch-start.c) digest.pag parent.pag)
    %-  ~(put z-by epoch-start.c)
    :-  digest.pag
    (~(got z-by epoch-start.c) parent.pag)
  =.  min-timestamps.c  (update-min-timestamps now pag)
  ::
  =.  targets.c
    ?:  =(+(epoch-counter.pag) blocks-per-epoch:t)
      ::  last block of an epoch means update to target
      %-  ~(put z-by targets.c)
      :-  digest.pag
      (compute-target digest.pag target.pag)
    ?:  =(height.pag *page-number:t)  ::  genesis block
      %-  ~(put z-by targets.c)
      [digest.pag target.pag]
    ::  target remains the same throughout an epoch
    %-  ~(put z-by targets.c)
    :-  digest.pag
    (~(got z-by targets.c) parent.pag)
  ::  note we do not update heaviest-block here, since that is conditional
  ::  and the effects emitted depend on whether we do it.
  c
::
::  +validate-page-without-txs-da: helper for urbit time
++  validate-page-without-txs-da
  |=  [pag=page:t now=@da]
  (validate-page-without-txs pag (time-in-secs:page:t now))
::
::  +validate-page-without-txs: with parent, without raw-txs
::
::    performs every check that can be done on a page when you
::    know its parent, except for validating the powork or digest,
::    but don't have all of the raw-txs. not to be performed on
::    genesis block, which has its own check. this check should
::    be performed before adding a block to pending state.
++  validate-page-without-txs
  |=  [pag=page:t now-secs=@]
  ^-  (reason:dk ~)
  =/  par=page:t  (to-page:local-page:t (~(got z-by blocks.c) parent.pag))
  ::  this is already checked in +heard-block but is done here again
  ::  to avoid a footgun
  ?.  (check-digest:page:t pag)
    [%.n %page-digest-invalid-2]
  ::
  =/  check-epoch-counter=?
    ?&  (lth epoch-counter.pag blocks-per-epoch:t)
      ?|  ?&  =(0 epoch-counter.pag)
              ::  epoch-counter is zero-indexed so we decrement
              =(epoch-counter.par (dec blocks-per-epoch:t))
          ==  :: start of an epoch
          ::  counter is one greater than its parent's counter.
          =(epoch-counter.pag +(epoch-counter.par))
      ==
    ==
  ?.  check-epoch-counter
    [%.n %page-epoch-invalid]
  ::
  =/  check-pow-hash=?
    ?.  check-pow-flag:t
      ::  this case only happens during testing
      ::~&  "skipping pow hash check for {(trip (to-b58:hash:t digest.pag))}"
      %.y
    %-  check-target:mine
    :_  target.pag
    (proof-to-pow:t (need pow.pag))
  ?.  check-pow-hash
    [%.n %pow-target-check-failed]
  ::
  =/  check-timestamp=?
    ?&  %+  gte  timestamp.pag
        (~(got z-by min-timestamps.c) parent.pag)
      ::
        (lte timestamp.pag (add now-secs max-future-timestamp:t))
    ==
  ?.  check-timestamp
    [%.n %page-timestamp-invalid]
  ::
  ::  check target
  ?.  =(target.pag (~(got z-by targets.c) parent.pag))
    [%.n %page-target-invalid]
  ::
  ::  check height
  ?.  =(height.pag +(height.par))
    [%.n %page-height-invalid]
  ::
  =/  check-heaviness=?
    .=  accumulated-work.pag
    %-  chunk:bignum:t
    %+  add
      (merge:bignum:t accumulated-work.par)
    (merge:bignum:t (compute-work:page:t target.pag))
  ?.  check-heaviness
    [%.n %page-heaviness-invalid]
  ::
  =/  check-coinbase-split=?
    (based:coinbase-split:t coinbase.pag)
  ?.  check-coinbase-split
    [%.n %coinbase-split-not-based]
  =/  check-msg-length=?
    (lth (lent msg.pag) 20)
  ?.  check-msg-length
    [%.n %msg-too-large]
  =/  check-msg-valid=?
    (validate:page-msg:t msg.pag)
  ?.  check-msg-valid
    [%.n %msg-not-valid]
  ::
  [%.y ~]
::
::  +validate-page-with-txs: to be run after all txs gathered
::
::    note that this does _not_ repeat earlier validation steps,
::    namely that done by +validate-page-withouts-txs and checking
::    the powork. it returns ~ if any of the checks fail, and
::    a $tx-acc otherwise, which is the datum needed to add the
::    page to consensus state.
++  validate-page-with-txs
  |=  [p=pending-state:dk pag=page:t]
  ^-  (reason:dk tx-acc:t)
  =/  digest-b58=tape  (trip (to-b58:hash:t digest.pag))
  ?.  (check-size p pag)
    ::~&  >>>  "block {digest-b58} is too large"
    [%.n %block-too-large]
  =/  raw-tx-set=(set (unit raw-tx:t))
    (~(run z-in tx-ids.pag) |=(=tx-id:t (~(get z-by raw-txs.p) tx-id)))
  =/  raw-tx-list=(list (unit raw-tx:t))  ~(tap z-in raw-tx-set)
  =|  tx-list=(list tx:t)
  =.  tx-list
    |-
    ?~  raw-tx-list  tx-list
    ?~  i.raw-tx-list
      ~  :: exit early b/c raw-tx was not present in raw-tx-set
    =/  utx=(unit tx:t)  (mole |.((new:tx:t u.i.raw-tx-list height.pag)))
    ?~  utx  :: exit early b/c raw-tx failed to convert
      ~
    %=  $
      tx-list  [u.utx tx-list]
      raw-tx-list  t.raw-tx-list
    ==
  ?:  ?&(=(~ tx-list) !=(~ raw-tx-list))
    :: failed to build a raw-tx, so the page is invalid
    [%.n %raw-txs-failed-to-build]
  :: initialize balance transfer accumulator with parent block's balance
  =/  acc=tx-acc:t
    (new:tx-acc:t (~(get z-by balance.c) parent.pag))
  ::
  ::  test to see that the input notes for all transactions
  ::  exist in the parent block's balance, that they are not
  ::  over- or underspent, and that the resulting
  ::  output notes are valid as well. a lot is going
  ::  on here - this is a load-bearing chunk of code in the
  ::  transaction engine.
  ::
  =/  balance-transfer=(unit tx-acc:t)
    |-
    ?~  tx-list
      (some acc)
    =/  new-acc=(unit tx-acc:t)
      (process:tx-acc:t acc i.tx-list height.pag)
    ?~  new-acc  ~  :: tx failed to process
    $(acc u.new-acc, tx-list t.tx-list)
  ::
  ?~  balance-transfer
    ::  balance transfer failed
    ::~&  >>>  "block {digest-b58} invalid"
    [%.n %balance-transfer-failed]
  ::
  ::  check that the coinbase split adds up to emission+fees
  =/  total-split=coins:t
    %+  roll  ~(val z-by coinbase.pag)
    |=([c=coins:t s=coins:t] (add c s))
  =/  emission-and-fees=coins:t
    (add (emission-calc:coinbase:t height.pag) fees.u.balance-transfer)
  ?.  =(emission-and-fees total-split)
    [%.n %improper-split]
  ::~&  >  "block {digest-b58} txs validated"
  [%.y u.balance-transfer]
::
::  +update-heaviest: set new heaviest block if it is so
++  update-heaviest
  |=  pag=page:t
  ^-  consensus-state:dk
  =/  digest-b58=cord  (to-b58:hash:t digest.pag)
  ::~>   %slog.[0 leaf+"checking if block {digest-b58} is heaviest"]
  ?:  =(~ heaviest-block.c)
    :: if we have no heaviest block, this must be genesis block.
    ~|  "received non-genesis block before genesis block"
    ?>  =(*page-number:t height.pag)
    c(heaviest-block (some digest.pag))
  ::  > rather than >= since we take the first heaviest block we've heard
  ?:  %+  compare-heaviness:page:t  pag
      (~(got z-by blocks.c) (need heaviest-block.c))
    =/  print-var
      %-  trip
      ^-  @t
      %^  cat  3
        digest-b58
      ' is new heaviest block'
    ~>  %slog.[0 leaf+print-var]
    c(heaviest-block (some digest.pag))
  =/  print-var
    %-  trip
    ^-  @t
    %^  cat  3
      digest-b58
    ' is NOT new heaviest block'
  ~>  %slog.[0 leaf+print-var]
  c
::
::  +get-elders: get list of ancestor block IDs up to 24 deep
::  (ordered newest->oldest)
++  get-elders
  |=  [d=derived-state:dk bid=block-id:t]
  ^-  (unit [page-number:t (list block-id:t)])
  =/  block  (~(get z-by blocks.c) bid)
  ?~  block
    ~
  =/  pag=page:t  (to-page:local-page:t u.block)
  =/  height=page-number:t  height.pag
  =/  ids=(list block-id:t)  [bid ~]
  =/  count  1
  |-
  ?:  =(height *page-number:t)  `[height (flop ids)]
  ?:  =(24 count)  `[height (flop ids)]
  =/  prev-height=page-number:t  (dec height)
  =/  prev-id=(unit block-id:t)  (~(get z-by heaviest-chain.d) prev-height)
  ?~  prev-id
    ::  if prev-id is null, something is wrong
    ~
  $(height prev-height, ids [u.prev-id ids], count +(count))
::
+|  %timestamp
::  +update-min-timestamps: sets min timestamp of children of .id
::
++  update-min-timestamps
  |=  [now=@da pag=page:t]
  ^-  (z-map block-id:t @)
  =/  min-timestamp=@
    ::  get timestamps of up to N=min-past-blocks prior blocks.
    =|  prev-timestamps=(list @)
    =/  b=@  (dec min-past-blocks:t)  :: iteration counter
    =/  cur-block=page:t  pag
    |-
    =.  prev-timestamps  [timestamp.cur-block prev-timestamps]
    ?:  ?|  =(0 b)  :: we've looked back +min-past-blocks blocks
            ::
            :: we've reached genesis block
            =(*page-number:t height.cur-block)
        ==
      ::  return median of timestamps
      (median:t prev-timestamps)
    %=  $
      b          (dec b)
      cur-block  (to-page:local-page:t (~(got z-by blocks.c) parent.cur-block))
    ==
  ::
  (~(put z-by min-timestamps.c) digest.pag min-timestamp)
--
