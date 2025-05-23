/=  dk  /apps/dumbnet/lib/types
/=  sp  /common/stark/prover
/=  c-transact  /common/tx-engine
/=  dumb-miner  /apps/dumbnet/lib/miner
/=  dumb-pending  /apps/dumbnet/lib/pending
/=  dumb-derived  /apps/dumbnet/lib/derived
/=  dumb-consensus  /apps/dumbnet/lib/consensus
/=  mine  /common/pow
/=  nv  /common/nock-verifier
/=  zeke  /common/zeke
/=  *  /common/zoon
/=  *  /common/wrapper
::
::  Never use c-transact face, always use the lustar `t`
::  alias, otherwise the blockchain constants set in the kernel
::  will not be active.
::
|%
++  moat  (keep kernel-state:dk)
++  inner
  |_  k=kernel-state:dk
  +*  min      ~(. dumb-miner m.k constants.k)
      pen      ~(. dumb-pending p.k constants.k)
      der      ~(. dumb-derived d.k constants.k)
      con      ~(. dumb-consensus c.k constants.k)
      t        ~(. c-transact constants.k)
  ::
  ::  We should be calling the inner kernel load in case of update
  ++  load
    |=  arg=kernel-state:dk
    arg
  ::
  ::TODO make referentially transparent by requiring event number in the scry path
  ++  peek
    |=  arg=path
    ^-  (unit (unit *))
    =/  =(pole)  arg
    ?+  pole  ~
    ::
        [%blocks ~]
      ^-  (unit (unit (z-map block-id:t page:t)))
      ``(~(run z-by blocks.c.k) to-page:local-page:t)
    ::
        [%transactions ~]
      ^-  (unit (unit (z-mip block-id:t tx-id:t tx:t)))
      ``txs.c.k
    ::
        [%raw-transactions ~]
      ^-  (unit (unit (z-map tx-id:t raw-tx:t)))
      ``raw-txs.p.k
    ::
    ::  For %block, %transaction, %raw-transaction, and %balance scries, the ID is
    ::  passed as a base58 encoded string in the scry path.
        [%block bid=@ ~]
      ^-  (unit (unit page:t))
      :: scry for a validated block (this does not look at pending state)
      =/  block-id  (from-b58:hash:t bid.pole)
      `(bind (~(get z-by blocks.c.k) block-id) to-page:local-page:t)
    ::
        [%elders bid=@ peer-id=@ ~]
      ::  get ancestor block IDs up to 24 deep for a given block
      ^-  (unit (unit [page-number:t (list block-id:t)]))
      =/  block-id  (from-b58:hash:t bid.pole)
      =/  elders  (get-elders:con d.k block-id)
      ?~  elders
        [~ ~]
      ``u.elders
    ::
        [%transaction tid=@ ~]
      ::  scry for a tx that has been included in a validated block
      ^-  (unit (unit (z-map tx-id:t tx:t)))
      :-  ~
      %-  ~(get z-by txs.c.k)
      (from-b58:hash:t tid.pole)
    ::
        [%raw-transaction tid=@ ~]
      ::  scry for a raw-tx
      ^-  (unit (unit raw-tx:t))
      :-  ~
      %-  ~(get z-by raw-txs.p.k)
      (from-b58:hash:t tid.pole)
    ::
        [%heavy ~]
      ^-  (unit (unit (unit block-id:t)))
      ``heaviest-block.c.k
    ::
        [%heavy-n pag=@ ~]
      ^-  (unit (unit page:t))
      =/  num=(unit page-number:t)
        ((soft page-number:t) pag.pole)
      ?~  num
        ~
      =/  id=(unit block-id:t)
        (~(get z-by heaviest-chain.d.k) u.num)
      ?~  id
        [~ ~]
      `(bind (~(get z-by blocks.c.k) u.id) to-page:local-page:t)
    ::
        [%desk-hash ~]
      ^-  (unit (unit (unit @uvI)))
      ``desk-hash.a.k
    ::
        [%mining-pubkeys ~]
      ^-  (unit (unit (list [m=@ pks=(list @t)])))
      =/  locks=(list [m=@ pks=(list @t)])
        %+  turn  ~(tap z-in pubkeys.m.k)
        |=(=lock:t (to-b58:lock:t lock))
      ``locks
    ::
        [%balance bid=@ ~]
      ^-  (unit (unit (z-map nname:t nnote:t)))
      :-  ~
      %-  ~(get z-by balance.c.k)
      (from-b58:hash:t bid.pole)
    ::
        [%heaviest-block ~]
      ^-  (unit (unit page:t))
      ?~  heaviest-block.c.k
        [~ ~]
      =/  heaviest-block  (~(get z-by blocks.c.k) u.heaviest-block.c.k)
      ?~  heaviest-block  ~
      ``(to-page:local-page:t u.heaviest-block)
    ::
        [%heavy-summary ~]
      ^-  (unit (unit [(z-set lock:t) (unit page-summary:t)]))
      ?~  heaviest-block.c.k
        ``[pubkeys.m.k ~]
      =/  heaviest-block  (~(get z-by blocks.c.k) u.heaviest-block.c.k)
      :+  ~  ~
      :-  pubkeys.m.k
      ?~  heaviest-block
        ~
      `(to-page-summary:page:t (to-page:local-page:t u.heaviest-block))
    ==
  ::
  ++  poke
    |=  [wir=wire eny=@ our=@ux now=@da dat=*]
    ^-  [(list effect:dk) kernel-state:dk]
    |^
    =/  cause  ((soft cause:dk) dat)
    ?~  cause
      ~>  %slog.[0 [%leaf "error: badly formatted cause, should never occur."]]
      ~&  ;;([thing=@t ver=@ type=@t] [-.dat +<.dat +>-.dat])
      =/  peer-id  (get-peer-id wir)
      ?~  peer-id
        `k
      ~>  %slog.[0 [leaf+"peer-id found in wire of badly formatted cause, emitting %liar-peer"]]
      [[%liar-peer u.peer-id %invalid-fact]~ k]
    =/  cause  u.cause
    ::~&  "inner dumbnet cause: {<[-.cause -.+.cause]>}"
    =^  effs  k
      ?+    wir  ~|("unsupported wire: {<wir>}" !!)
          [%poke src=?(%nc %timer %sys %miner %npc) ver=@ *]
        ?-  -.cause
          %command  (handle-command now p.cause)
          %fact     (handle-fact wir eny our now p.cause)
        ==
      ::
         [%poke %libp2p ver=@ typ=?(%gossip %response) %peer-id =peer-id:dk *]
        ?>  ?=(%fact -.cause)
        (handle-fact wir eny our now p.cause)
      ==
    ::  possibly update timestamp on candidate block for mining
    =.  m.k  (update-timestamp:min now)
    effs^k
    ::
    ::  +heard-genesis-block: check if block is a genesis block and decide whether to keep it
    ++  heard-genesis-block
      |=  [wir=wire now=@da eny=@ pag=page:t]
      ^-  [(list effect:dk) kernel-state:dk]
      ?:  (check-duplicate-block digest.pag)
        :: do nothing (idempotency), we already have block
        `k
      ::
      ?~  btc-data.c.k
        ~>  %slog.[0 leaf+"btc-data not set, crashing"]
        !!
      ?.  (check-genesis pag u.btc-data.c.k genesis-seal.c.k)
        ::  is not a genesis block, throw it out and inform the king. note this
        ::  must be a %liar effect since genesis blocks have no powork and are
        ::  thus cheap to make, so we cannot trust their block-id.
        [[(liar-effect wir %not-a-genesis-block)]~ k]
      ::  heard valid genesis block
      ~>  %slog.[0 leaf+"validated genesis block!"]
      (new-block now eny pag *tx-acc:t)
    ::
    ++  heard-block
      |=  [wir=wire now=@da pag=page:t eny=@]
      ^-  [(list effect:dk) kernel-state:dk]
      ?:  =(*page-number:t height.pag)
        ::  heard genesis block
        ~>  %slog.[0 leaf+"heard genesis block"]
        (heard-genesis-block wir now eny pag)
      ?~  heaviest-block.c.k
        =/  peer-id=(unit @)  (get-peer-id wir)
        ?~  peer-id
          ::  received block before genesis from source other than libp2p
          `k
        ~>  %slog.[0 [%leaf "no genesis block yet, requesting elders"]]
        :_  k
        [%request %block %elders digest.pag u.peer-id]~
      ::  if we don't have parent and block claims to be heaviest
      ::  request ancestors to catch up or handle reorg
      ?.  (~(has z-by blocks.c.k) parent.pag)
        ?:  %+  compare-heaviness:page:t  pag
            (~(got z-by blocks.c.k) u.heaviest-block.c.k)
          =/  peer-id=(unit @)  (get-peer-id wir)
          ?~  peer-id
            ~|("unsupported wire: {<wir>}" !!)
          =/  print-var
            %-  trip
            ^-  @t
            %^  cat  3
              'potential reorg: requesting elders for heavier block: '
            (to-b58:hash:t digest.pag)
          ~>  %slog.[0 [%leaf print-var]]
          :_  k
          [%request %block %elders digest.pag u.peer-id]~
        ::  received block, don't have parent, isn't heaviest, ignore.
        `k
      ::  yes, we have its parent
      ::
      ::  do we already have this block?
      ?:  (check-duplicate-block digest.pag)
        :: do nothing (idempotency), we already have block
        `k
      ::
      ::  check to see if the .digest is valid. if it is not, we
      ::  emit a %liar-peer. if it is, then any further %liar effects
      ::  should be %liar-block-id. this tells the runtime that
      ::  anybody who sends us this block id is a liar
      ?.  (check-digest:page:t pag)
        ~>  %slog.[0 leaf+"digest is not valid"]
        :_  k
        [(liar-effect wir %page-digest-invalid)]~
      ::
      ::  since we know the digest is valid, we want to tell the runtime
      ::  to start tracking that block-id.
      =/  block-effs=(list effect:dk)
        =/  =(pole)  wir
        ?.  ?=([%poke %libp2p ver=@ typ=?(%gossip %response) %peer-id =peer-id:dk *] pole)
          ~
        [%track %add digest.pag peer-id.pole]~
      ::
      ::  %liar-block-id only says that anybody who sends us this
      ::  block-id is a liar, but it doesn't (and can't) include the
      ::  peer id. so it gets cross-referenced with the blocks being
      ::  tracked to know who to ban.
      ::
      ::  the crash case is when we get a bad block from the npc driver or
      ::  from the kernel itself.
      =/  check-page-without-txs=(reason:dk ~)
        (validate-page-without-txs-da:con pag now)
      ?:  ?=(%.n -.check-page-without-txs)
        ::  block has bad data
        :_  k
        ::  the order here matters since we want to add the block to tracking
        ::  and then ban the peer who sent it. we do this instead of %liar-peer
        ::  since its possible for another poke to be processed after %track %add
        ::  but before %liar-block-id, so more peers may be added to tracking
        ::  before %liar-block-id is processed.
        %+  snoc  block-effs
        [%liar-block-id digest.pag +.check-page-without-txs]
      ::
      ?.  (check-pow pag)
        :_  k
        %+  snoc  block-effs
        [%liar-block-id digest.pag %failed-pow-check]
      ::
      ::  tell driver we have seen this block so don't send it back to the kernel again
      =.  block-effs
        [[%seen %block digest.pag] block-effs]
      ::  stop tracking block id as soon as we verify pow
      =.  block-effs
        %+  snoc  block-effs
        ^-  effect:dk
        [%track %remove digest.pag]
      =^  missing-txs=(list tx-id:t)  p.k
        (add-pending-block:pen pag)
      ?:  !=(missing-txs *(list tx-id:t))
        ~>  %slog.[0 leaf+"missing txs"]
        ::  block has missing txs
        =.  block-effs
          %+  weld  block-effs
          %+  turn  missing-txs
          |=  =tx-id:t
          ^-  effect:dk
          [%request %raw-tx %by-id tx-id]
        :_  k
        ?:  %+  compare-heaviness:page:t  pag
            (~(got z-by blocks.c.k) (need heaviest-block.c.k))
          ~>  %slog.[0 %leaf^"gossip new heaviest block, have not validated txs yet"]
          :-  [%gossip %0 %heard-block pag]
          block-effs
        block-effs
      ::
      ::  block has no missing transactions, so we check that its transactions
      ::  are valid
      (process-block-with-txs now eny pag block-effs)
    ::
    ::  +heard-elders: handle response to parent hashes request
    ++  heard-elders
      |=  [wir=wire now=@da oldest=page-number:t ids=(list block-id:t)]
      ^-  [(list effect:dk) kernel-state:dk]
      ::  extract peer ID from wire
      =/  peer-id=(unit @)  (get-peer-id wir)
      ?~  peer-id
        ~|("unsupported wire: {<wir>}" !!)
      =/  ids-lent  (lent ids)
      ?:  (gth ids-lent 24)
        :_  k
        [[%liar-peer u.peer-id %more-than-24-parent-hashes]~]
      ?.  ?|  =(oldest *page-number:t)
              =(ids-lent 24)
          ==
        ~>  %slog.[0 %leaf^"bad elders: either oldest should be genesis or need 24 elders"]
        ::  either oldest is genesis OR we must have received exactly 24 ids
        :_  k
        [[%liar-peer u.peer-id %less-than-24-parent-hashes]~]
      ::  find highest block we have in the ancestor list
      =/  latest-known=(unit [=block-id:t =page-number:t])
        =/  height  (dec (add oldest ids-lent))
        |-
        ?~  ids  ~
        ?:  =(height 0)  ~
        ?:  (~(has z-by blocks.c.k) i.ids)
          `[i.ids height]
        $(ids t.ids, height (dec height))
      ?~  latest-known
        ?:  =(oldest *page-number:t)
          ?:  =(~ heaviest-block.c.k)
            ::  request genesis block because we don't have it yet
            :_  k
            [%request %block %by-height *page-number:t]~
          ::  if we have differing genesis blocks, liar
          ~>  %slog.[0 %leaf^"bad elders: differing genesis blocks"]
          :_  k
          [[%liar-peer u.peer-id %differing-genesis]~]
        ::  request elders of oldest ancestor to catch up faster
        ::  hashes are ordered newest>oldest
        =/  print-var
          "processed elders and asking for oldest: requesting elders"
        ~>  %slog.[0 %leaf^print-var]
        :_  k
        [%request %block %elders (rear ids) u.peer-id]~
      =/  print-var
        %-  trip
        %^  cat  3
          'processed elders and found intersection: requesting next block '
        (scot %ud +(page-number.u.latest-known))
      ~>  %slog.[0 %leaf^print-var]
      ::  request next block after our highest known block
      ::  this will trigger either catchup or reorg from this point
      :_  k
      [%request %block %by-height +(page-number.u.latest-known)]~
    ::
    ++  check-duplicate-block
      |=  digest=block-id:t
      ?|  (~(has z-by blocks.c.k) digest)
          (~(has z-by pending-blocks.p.k) digest)
      ==
    ::
    ++  check-genesis
     |=  [pag=page:t btc-hash=(unit btc-hash:t) =genesis-seal:t]
     ^-  ?
     =/  check-digest  (check-digest:page:t pag)
     =/  check-pow-hash=?
      ?.  check-pow-flag:t
         ::  this case only happens during testing
         ::~&  "skipping pow hash check for {(trip (to-b58:hash:t digest.pag))}"
         %.y
       %-  check-target:mine
       :_  target.pag
       (proof-to-pow:zeke (need pow.pag))
     =/  check-pow-valid=?  (check-pow pag)
     ::
     ::  check if timestamp is in base field, this will anchor subsequent timestamp checks
     ::  since child block timestamps have to be within a certain range of the most recent
     ::  N blocks.
     =/  check-timestamp=?  (based:zeke timestamp.pag)
     =/  check-txs=?  =(tx-ids.pag *(z-set tx-id:t))
     =/  check-epoch=?  =(epoch-counter.pag *@)
     =/  check-target=?  =(target.pag genesis-target:t)
     =/  check-work=?  =(accumulated-work.pag (compute-work:page:t genesis-target:t))
     =/  check-coinbase=?  =(coinbase.pag *(z-map lock:t @))
     =/  check-height=?  =(height.pag *page-number:t)
     =/  check-btc-hash=?
       ?~  btc-hash  ~>  %slog.[0 leaf+"Not checking btc hash when validating genesis block"]  %.y
       =(parent.pag (hash:btc-hash:t u.btc-hash))
     ::
     ::  check that the message matches what's in the seal
     =/  check-msg=?
       ?~  genesis-seal  %.y
       =((hash:page-msg:t msg.pag) msg-hash.u.genesis-seal)
     ~&  :*  check-digest+check-digest
             check-pow-hash+check-pow-hash
             check-pow-valid+check-pow-valid
             check-timestamp+check-timestamp
             check-txs+check-txs
             check-epoch+check-epoch
             check-target+check-target
             check-work+check-work
             check-coinbase+check-coinbase
             check-height+check-height
             check-msg+check-msg
             check-btc-hash+check-btc-hash
         ==
     ?&  check-digest
         check-pow-hash
         check-pow-valid
         check-timestamp
         check-txs
         check-epoch
         check-target
         check-work
         check-coinbase
         check-height
         check-msg
         check-btc-hash
     ==
    ++  check-pow
      |=  pag=page:t
      ^-  ?
      ?.  check-pow-flag:t
        ~>  %slog.[0 leaf+"WARNING: check-pow-flag is off, skipping pow check"]
        ::  this case only happens during testing
        %.y
      ?~  pow.pag
        %.n
      ::
      ::  validate that powork puzzle in the proof is correct.
      ?&  (check-pow-puzzle u.pow.pag pag)
          ::
          ::  validate the powork. this is done separately since the
          ::  other checks are much cheaper.
          (verify:nv u.pow.pag ~ eny)
      ==
    ::
    ++  check-pow-puzzle
      |=  [pow=proof:sp pag=page:t]
      ^-  ?
      ?:  =((lent objects.pow) 0)
        %.n
      =/  puzzle  (snag 0 objects.pow)
      ?.  ?=(%puzzle -.puzzle)
        %.n
      ?&  =((block-commitment:page:t pag) commitment.puzzle)
          =(pow-len.zeke len.puzzle)
      ==
    ::
    ++  heard-tx
      |=  [wir=wire now=@da raw=raw-tx:t eny=@]
      ^-  [(list effect:dk) kernel-state:dk]
      ~>  %slog.[3 leaf+"heard-tx"]
      =/  id-b58  (to-b58:hash:t id.raw)
      ~>  %slog.[3 leaf+(trip (cat 3 'raw-tx: ' id-b58))]
      ::
      ::  check tx-id. this is the fastest check to do, so we try it first before
      ::  calling validate:raw-tx (which also checks the id)
      ?.  =((compute-id:raw-tx:t raw) id.raw)
        ~>  %slog.[3 leaf+"tx-id-invalid"]
        :_  k
        [(liar-effect wir %tx-id-invalid)]~
      ::
      ::  do we already have raw-tx?
      ?:  (~(has z-by raw-txs.p.k) id.raw)
        :: do nothing (idempotency), we already have it
        ~>  %slog.[3 leaf+"tx-id-already-seen"]
        `k
      ?:  (based:raw-tx:t raw)
        :_  k
        [(liar-effect wir %raw-tx-not-based)]~
      ::
      ::  check if raw-tx is part of a pending block
      ::
      =/  tx-pending-blocks=(list block-id:t)
        ~(tap z-in (~(get z-ju tx-block.p.k) id.raw))
      ?:  !=(*(list block-id:t) tx-pending-blocks)
        ::  pending blocks are waiting on tx
        ?.  (validate:raw-tx:t raw)
          ::  raw-tx doesn't validate.
          ::  remove blocks containing bad tx from pending state. note that since
          ::  we already checked that the id of the transaction was valid, we
          ::  won't accidentally throw out a block that contained a valid tx-id
          ::  just because we received a tx that claimed the same id as the valid
          ::  one.
          =.  p.k
            %+  roll  tx-pending-blocks
            |=  [id=block-id:t pend=_p.k]
            (remove-pending-block:pen id)
          ::
          ~>  %slog.[3 leaf+"page-pending-raw-tx-invalid"]
          :_  k
          [(liar-effect wir %page-pending-raw-tx-invalid) ~]
        ::  add to raw-txs map, remove from tx-block jug, remove from
        ::  block-tx jug
        =.  p.k  (add-tx-in-pending-block:pen raw)
        ~>  %slog.[3 leaf+"process-ready-blocks"]
        (process-ready-blocks now eny raw)
      ::  no pending blocks waiting on tx
      ::
      ::  check if any inputs are absent in heaviest balance
      ?.  (inputs-in-heaviest-balance:con raw)
        ::  input(s) in tx not in balance, discard tx
        ~>  %slog.[3 leaf+"inputs-in-heaviest-balance"]
        `k
      ::  all inputs in balance
      ::
      ::  check if any inputs are in spent-by
      ?:  (inputs-in-spent-by:pen raw)
        ::  inputs present in spent-by, discard tx
        ~>  %slog.[3 leaf+"inputs-in-spent-by"]
        `k
      ::  inputs not present in spent-by
      ?.  (validate:raw-tx:t raw)
        ::  raw-tx doesn't validate.
        ~>  %slog.[3 leaf+"raw-tx-invalid"]
        :_  k
        [(liar-effect wir %tx-inputs-not-in-spent-by-and-invalid)]~
      ::
      =.  p.k
        (add-tx-not-in-pending-block:pen raw get-cur-height:con)
      ::
      ::  next we would process blocks made ready by tx but we already
      ::  determined that no pending blocks were waiting on this this,
      ::  so we just tell the miner.
      =.  m.k  (heard-new-tx:min raw)
      ~>  %slog.[3 leaf+"heard-new-tx"]
      :-  ~[[%seen %tx id.raw] [%gossip %0 %heard-tx raw]]
      k
    ::
    ::  +process-ready-blocks: process blocks no longer waitings on txs
    ++  process-ready-blocks
      |=  [now=@da eny=@ raw=raw-tx:t]
      ^-  [(list effect:dk) kernel-state:dk]
      ::  .work contains block-ids for blocks that no longer have any
      ::  missing transactions
      =/  work=(z-set block-id:t)  find-ready-blocks:pen
      =^  eff  k
        %+  roll  ~(tap z-in work)
        |=  [bid=block-id:t effs=(list effect:dk) k=_k]
        ::  process the block, skipping the steps that we know its already
        ::  done by the fact that it was in pending-blocks.p.k
        =^  new-effs  k
          %:  process-block-with-txs
            now  eny
            (to-page:local-page:t (~(got z-by pending-blocks.p.k) bid))
            :: if the block is bad, then tell the driver never to send it
            :: to us again
            ~[[%seen %block bid]]
          ==
        ::  remove the block from pending blocks. at this point, its either
        ::  been discarded by the kernel or lives in the consensus state
        =.  p.k  (remove-pending-block:pen bid)
        ::  add the effects onto the list and return the updated kernel state
        [(weld new-effs effs) k]
      ::
      ::  tell the miner about the new transaction. this might look strange
      ::  informing it here, potentially after new blocks have been made ready
      ::  by it, but this tx may be part of a reorg, so the processed blocks
      ::  might not be the heaviest.
      =.  m.k  (heard-new-tx:min raw)
      ::
      eff^k
    ::
    ::
    ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
    ::  the remaining arms are used by both %heard-tx and %heard-block
    ::
    ::  +process-block-with-txs: process a block that we have all txs for
    ::
    ::    this is called along the codepath for both %heard-block and +heard-tx,
    ::    since once we hear the last transaction we're waiting for in a given
    ::    block, we immediately try to validate it. the genesis block does _not_
    ::    go through here.
    ::
    ::    bad-block-effs are effects which are passed through and emitted
    ::    only if the block is bad. If the block is good then ++new-block
    ::    emits effects and bad-block-effs is ignored.
    ++  process-block-with-txs
      |=  [now=@da eny=@ pag=page:t bad-block-effs=(list effect:dk)]
      ^-  [(list effect:dk) kernel-state:dk]
      =/  digest-b58  (to-b58:hash:t digest.pag)
      ::
      ::  if we do have all raw-txs, check if pag validates
      ::  (i.e. transactions are valid and size isnt too big)
      =/  new-transfers=(reason:dk tx-acc:t)
        (validate-page-with-txs:con p.k pag)
      ?-    -.new-transfers
          %.y
        (new-block now eny pag +.new-transfers)
        ::
          %.n
        ::  did not validate, so we throw the block out and stop
        ::  tracking it
        [bad-block-effs k]
      ==
    ::
    ::  +new-block: update kernel state with new valid block.
    ++  new-block
      |=  [now=@da eny=@ pag=page:t acc=tx-acc:t]
      ^-  [(list effect:dk) kernel-state:dk]
      ::
      ::  page is validated, update consensus and derived state
      =.  c.k  (add-page:con pag acc now)
      =/  print-var
        %-  trip
        ^-  @t
        %+  rap  3
        :~  'block '  (to-b58:hash:t digest.pag)
            ' added to validated blocks at '  (scot %u height.pag)
        ==
      ~>  %slog.[0 %leaf^print-var]
      ::
      =/  effs=(list effect:dk)
        ::  request block N+1 on each peer's heaviest chain
        :+  [%request %block %by-height +(height.pag)]
          ::  tell driver we've seen this block so don't process it again
          [%seen %block digest.pag]
        ~
      ::
      =/  old-heavy  heaviest-block.c.k
      =.  c.k  (update-heaviest:con pag)
      ::  if block is the new heaviest block, gossip it to peers
      =?  effs  !=(old-heavy heaviest-block.c.k)
        ~>  %slog.[0 %leaf^"dumbnet: new heaviest block!"]
        =/  span=span-effect:dk
          :+  %span  %new-heaviest-chain
          ~['block_height'^n+height.pag 'heaviest_block_digest'^s+(to-b58:hash:t digest.pag)]
        :*  [%gossip %0 %heard-block pag]
            span
            effs
        ==
      ::  refresh pending state
      =.  p.k  (refresh-after-new-block:pen c.k retain.a.k)
      ::
      ::  tell the miner about the new block
      =.  m.k  (heard-new-block:min c.k p.k now)
      ::
      ::  update derived state
      =.  d.k  (update:der c.k pag)
      ?.  =(old-heavy heaviest-block.c.k)
        =^  mining-effs  k  (do-mine (hash-noun-varlen:tip5:zeke [%nonce eny]))
        =.  effs  (weld mining-effs effs)
        effs^k
      ::
      effs^k
    ::
    ::  +liar-effect: produce the appropriate liar effect
    ::
    ::    this only produces the `%liar-peer` effect. the other possibilities
    ::    are receiving a bad block or tx via the npc driver or from within
    ::    the miner module or +do-genesis. in this case we just emit a
    ::    warning and crash, since that means there's a bug.
    ++  liar-effect
      |=  [wir=wire r=term]
      ^-  effect:dk
      ?+    wir  ~|("bad wire for liar effect! {<wir>}" !!)
          [%poke %libp2p ver=@ typ=?(%gossip %response) %peer-id id=@ *]
        [%liar-peer (need (get-peer-id wir)) r]
      ::
          [%poke %npc ver=@ *]
        ~|  'ATTN: received a bad block or tx via npc driver'
        !!
      ::
          [%poke %miner *]
        ::  this indicates that the mining module built a bad block and then
        ::  told the kernel about it. alternatively, +do-genesis produced
        ::  a bad genesis block. this should never happen, it indicates
        ::  a serious bug otherwise.
        ~|  'ATTN: miner or +do-genesis produced a bad block!'
        !!
      ==
    ::
    ++  get-peer-id
      |=  wir=wire
      ^-  (unit @)
      =/  =(pole)  wir
      ?.  ?=([%poke %libp2p ver=@ typ=?(%gossip %response) %peer-id id=@ *] pole)
        ~
      (some id.pole)
    ::
    ++  handle-command
      |=  [now=@da =command:dk]
      ^-  [(list effect:dk) kernel-state:dk]
      ~>  %slog.[0 (cat 3 'command: ' -.command)]
      ::  ~&  "handling command: {<-.command>}"
      ?:  &(?=(init-command:dk -.command) !init.a.k)
        ::  kernel no longer in init phase, can't do init command
        ~>  %slog.[0 leaf+"kernel no longer in init phase, can't do init command"]
        `k
      ?:  &(?=(non-init-command:dk -.command) init.a.k)
        ::  kernel in init phase, can't perform command
        ~>  %slog.[0 leaf+"kernel is in init phase, can't do non-init command"]
        `k
      |^
      ?-  -.command
          %born
        do-born
      ::
          %pow
        do-pow
      ::
          %set-mining-key
        do-set-mining-key
      ::
          %set-mining-key-advanced
        do-set-mining-key-advanced
      ::
          %enable-mining
        do-enable-mining
      ::
          %timer
        do-timer
      ::
          %set-genesis-seal
        =.  c.k  (set-genesis-seal:con p.command)
        `k
      ::
          %genesis
        do-genesis
      ::
          %btc-data
        do-btc-data
      ::
          %set-constants
        `k(constants p.command)
      ==
      ::
      ++  do-born
        ^-  [(list effect:dk) kernel-state:dk]
        ?>  ?=([%born *] command)
        ::  once born command is registered, the init phase is over
        ::  note state update won't be registered unless poke is successful.
        =.  k  k(init.a %.n)
        :: do we have any blocks?
        ?~  heaviest-block.c.k
          ::  no, request genesis block
          ?~  btc-data.c.k
            ~>  %slog.[0 leaf+"No genesis parent btc block hash set, crashing"]
            !!
          ::  requesting any genesis block, keeping first one we see.
          ::  we do not request blocks by id so we can only request height 0
          ::  blocks and throw out ones we aren't expecting
          ~>  %slog.[0 leaf+"Requesting genesis block"]
          :_  k
          [%request %block %by-height *page-number:t]~
        :: yes, so get height N of heaviest block and request the block
        :: of height N+1
        =/  height=page-number:t
          +(height:(~(got z-by blocks.c.k) u.heaviest-block.c.k))
        ~>  %slog.[0 leaf+"dumbnet born"]
        :_  k
        [%request %block %by-height height]~
      ::
      ++  do-pow
        ^-  [(list effect:dk) kernel-state:dk]
        ?>  ?=([%pow *] command)
        =/  commit=block-commitment:t
          (block-commitment:page:t candidate-block.m.k)
        ?.  =(bc.command commit)
          ~&  "mined for wrong (old) block commitment"  `k
        ?.  =(nonce.command next-nonce.m.k)
          ~&  "mined wrong (old) nonce"  `k
        ?:  %+  check-target:mine  dig.command
            (~(got z-by targets.c.k) parent.candidate-block.m.k)
          =.  m.k  (set-pow:min prf.command)
          =.  m.k  set-digest:min
          (heard-block /poke/miner now candidate-block.m.k eny)
        :: mine the next nonce
        (do-mine (atom-to-digest:tip5:zeke dig.command))
      ::
      ++  do-set-mining-key
        ^-  [(list effect:dk) kernel-state:dk]
        ?>  ?=([%set-mining-key *] command)
        =/  pk=(unit schnorr-pubkey:t)
          (mole |.((from-b58:schnorr-pubkey:t p.command)))
        ?~  pk
          ~>  %slog.[0 leaf+"invalid mining pubkey, exiting"]
          [[%exit 1]~ k]
        =/  =lock:t  (new:lock:t u.pk)
        =.  m.k  (set-pubkeys:min [lock]~)
        =.  m.k  (set-shares:min [lock 100]~)
        ::  ~&  >  "pubkeys.m set to {<pubkeys.m.k>}"
        ::  ~&  >  "shares.m set to {<shares.m.k>}"
        `k
      ::
      ++  do-set-mining-key-advanced
        ^-  [(list effect:dk) kernel-state:dk]
        ?>  ?=([%set-mining-key-advanced *] command)
        ?:  (gth (lent p.command) 2)
        ~>  %slog.[0 [%leaf "coinbase split for more than two locks not yet supported, exiting"]]
          [[%exit 1]~ k]
        ?~  p.command
        ~>  %slog.[0 [%leaf "empty list of locks, exiting."]]
          [[%exit 1]~ k]
        ::
        =/  [keys=(list lock:t) shares=(list [lock:t @]) crash=?]
          %+  roll  `(list [@ @ (list @t)])`p.command
          |=  $:  [s=@ m=@ ks=(list @t)]
                  locks=(list lock:t)
                  shares=(list [lock:t @])
                  crash=_`?`%|
              ==
          =+  r=(mole |.((from-b58:lock:t m ks)))
          ?~  r
            [~ ~ %&]
          [[u.r locks] [[u.r s] shares] crash]
        ?:  crash
          ~>  %slog.[0 leaf+"invalid public keys provided, exiting"]
          [[%exit 1]~ k]
        =.  m.k  (set-pubkeys:min keys)
        =.  m.k  (set-shares:min shares)
        ::  ~&  >  "pubkeys.m set to {<pubkeys.m.k>}"
        ::  ~&  >  "shares.m set to {<shares.m.k>}"
        `k
      ::
      ++  do-enable-mining
        ^-  [(list effect:dk) kernel-state:dk]
        ?>  ?=([%enable-mining *] command)
        ?.  p.command
          ::~&  >  'generation of candidate blocks disabled'
          =.  m.k  (set-mining:min p.command)
          `k
        ?:  =(*(z-set lock:t) pubkeys.m.k)
          ::  ~&  >
          ::      """
          ::      generation of candidate blocks has not been enabled because mining pubkey
          ::      is empty. set it with %set-mining-key then run %enable-mining again
          ::      """
          `k
        ?:  =(~ heaviest-block.c.k)
          ::~&  >
          ::    """
          ::    generation of candidate blocks enabled. candidate block will be generated
          ::    once a genesis block has been received.
          ::    """
          =.  m.k  (set-mining:min p.command)
          `k
        ::~&  >  'generation of candidate blocks enabled.'
        =.  m.k  (set-mining:min p.command)
        =.  m.k  (heard-new-block:min c.k p.k now)
        `k
      ::
      ++  do-timer
        ::TODO post-dumbnet: only rerequest transactions a max of once/twice (maybe an admin param)
        ^-  [(list effect:dk) kernel-state:dk]
        ?>  ?=([%timer *] command)
        ?:  init.a.k
          ::  kernel in init phase, command ignored
          `k
        =/  tx-req-effs=(list effect:dk)
          %+  turn  ~(tap z-by find-pending-tx-ids:pen)
          |=  =tx-id:t
          ^-  effect:dk
          [%request %raw-tx %by-id tx-id]
        ::
        ::  we always request the next heaviest block with each %timer event
        =/  heavy-height=page-number:t
          ?~  heaviest-block.c.k
            *page-number:t  ::  rerequest genesis block
          +(height:(~(got z-by blocks.c.k) u.heaviest-block.c.k))
        =/  effs=(list effect:dk)
          :-  [%request %block %by-height heavy-height]
          tx-req-effs
        effs^k
      ::
      ++  do-genesis
        ::  generate genesis block and sets it as candidate block
        ^-  [(list effect:dk) kernel-state:dk]
        ?>  ?=([%genesis *] command)
        ::  creating genesis block with template
        ~>  %slog.[0 leaf+"create genesis block with template"]
        =/  =genesis-template:t
          (new:genesis-template:t p.command)
        =/  genesis-page=page:t
          (new-genesis:page:t genesis-template now)
        =.  candidate-block.m.k  genesis-page
        =.  c.k  (add-btc-data:con `btc-hash.p.command)
        `k
      ::
      ++  do-btc-data
        ^-  [(list effect:dk) kernel-state:dk]
        ?>  ?=([%btc-data *] command)
        =.  c.k  (add-btc-data:con p.command)
        `k
      --::+handle-command
    ::
    ++  handle-fact
      |=  [wir=wire eny=@ our=@ux now=@da =fact:dk]
      ^-  [(list effect:dk) kernel-state:dk]
      ~>  %slog.[0 (cat 3 'fact: ' +<.fact)]
      ?:  init.a.k
        ::  kernel in init phase, fact ignored
        `k
      ?-    -.data.fact
          %heard-block
        (heard-block wir now p.data.fact eny)
      ::
          %heard-tx
        (heard-tx wir now p.data.fact eny)
      ::
          %heard-elders
        (heard-elders wir now p.data.fact)
      ==
      ::
      ++  do-mine
        |=  nonce=noun-digest:tip5:zeke
        ^-  [(list effect:dk) kernel-state:dk]
        ?.  mining.m.k
          `k
        ?:  =(*(z-set lock:t) pubkeys.m.k)
          ::~&  "cannot mine without first setting pubkey with %set-mining-key"
          `k
        =/  commit=block-commitment:t
          (block-commitment:page:t candidate-block.m.k)
        =.  next-nonce.m.k  nonce
        ~&  mining-on+nonce
        :_  k
        [%mine pow-len:zeke commit nonce]~
    --::  +poke
  --::  +kernel
--
:: churny churn 1
