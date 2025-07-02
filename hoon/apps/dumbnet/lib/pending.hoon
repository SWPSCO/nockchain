/=  dcon  /apps/dumbnet/lib/consensus
/=  dk  /apps/dumbnet/lib/types
/=  dumb-transact  /common/tx-engine
/=  *  /common/zoon
::
|_  [p=pending-state:dk c=consensus-state:dk bc=blockchain-constants:dumb-transact]
+*  t  ~(. dumb-transact bc)
+|  %logic
::  +find-ready-blocks: blocks for which .id was the last missing tx
++  has-raw-tx
  |=  tid=tx-id:t
  ^-  ?
  |((~(has z-by raw-txs.p) tid) (~(has z-by raw-txs.c) tid))
++  get-raw-tx
  |=  tid=tx-id:t
  ^-  (unit raw-tx:t)
  =/  p-raw-tx  (~(get z-by raw-txs.p) tid)
  ?~  p-raw-tx
    (~(get z-by raw-txs.c) tid)
  p-raw-tx
++  got-raw-tx
  |=  tid=tx-id:t
  ^-  raw-tx:t
  (need (get-raw-tx tid))
++  find-ready-blocks
  ^-  (z-set block-id:t)
  ::  set of all pending blocks
  =/  p-bids=(z-set block-id:t)  ~(key z-by pending-blocks.p)
  ::  set of pending blocks still waiting on txs
  =/  w-bids=(z-set block-id:t)  ~(key z-by block-tx.p)
  (~(dif z-in p-bids) w-bids)
::
++  inputs-in-spent-by
  |=  raw=raw-tx:t
  ^-  ?
  =/  inputs-names=(z-set nname:t)  (inputs-names:raw-tx:t raw)
  =/  spent-by-names=(z-set nname:t)  ~(key z-by spent-by.p)
  =/  common-names=(z-set nname:t)  (~(int z-in spent-by-names) inputs-names)
  ::  %.y: inputs are present in spent-by
  ::  %.n: inputs are not present in spent-by
  !=(*(z-set nname:t) common-names)
::
++  refresh-after-new-block
  |=  retain=(unit @)
  ^-  pending-state:dk
  ?~  retain
    ::  never drop transactions
    p
  ?:  =(0 u.retain)
    ::  never retain anything
    %_  p
      spent-by  *(z-map nname:t tx-id:t)
      heard-at  *(z-map tx-id:t page-number:t)
      raw-txs   *(z-map tx-id:t raw-tx:t)
    ==
  ::
  ::  enumerate last N block heights inclusive of current block height
  =/  cur-height=page-number:t
    ~(get-cur-height dcon c p bc)
  =/  min-height=page-number:t
    ?:  (lth cur-height u.retain)  0
    ::  add 1 b/c range is inclusive of cur-height
    ::  so retain=1 means min-height=cur-height
    +((sub cur-height u.retain))
  =/  heard-kvs=(list [tx-id:t page-number:t])
    ~(tap z-by heard-at.p)
  ::
  =/  keep-drop=[k=(list [tx-id:t page-number:t]) d=(list raw-tx:t)]
    %+  roll  heard-kvs
    |=  $:  [tid=tx-id:t num=page-number:t]
            [keep=(list [tx-id:t page-number:t]) drop=(list raw-tx:t)]
        ==
    =/  raw=raw-tx:t  (got-raw-tx tid)
    ?:  (lth num min-height)
      ::  tx is old, drop it
      [keep [raw drop]]
    ?.  (~(inputs-in-heaviest-balance dcon c p bc) raw)
      ::  input(s) in tx not in balance, discard
      [keep [raw drop]]
    ::  tx should stay in heard-at
    [[[tid num] keep] drop]
  ::
  ::  new heard-at map from k.keep-drop
  =.  heard-at.p
    (~(gas z-by *(z-map tx-id:t page-number:t)) k.keep-drop)
  ::
  ::  remove d.keep-drop from spent-by map
  =.  p
    %+  roll  d.keep-drop
    |=  [raw=raw-tx:t pen=_p]
    (remove-inputs-from-spent-by raw)
  ::
  ::  remove d.keep-drop from raw-txs map. we cannot just
  ::  make a new map with k.keep-drop since raw-txs also includes
  ::  txs for pending blocks
  =.  p
    %+  roll  d.keep-drop
    |=  [raw=raw-tx:t pen=_p]
    (remove-raw-tx id.raw)
  ::
  p
+|  %getters-and-setters
::
::  +add-tx-not-in-pending-block:
::
::    these transactions are treated differently from transactions
::    that are in a pending block. we track their inputs and when
::    we heard them. if we hear another transaction using some
::    of the same inputs, we discard it. if we heard the transaction
::    sufficiently long ago, we drop it from pending state.
++  add-tx-not-in-pending-block
  |=  [raw=raw-tx:t cur-height=page-number:t]
  ^-  pending-state:dk
  =.  p  (add-raw-tx raw)
  =.  p  (add-inputs-to-spent-by raw)
  =.  p  (tx-heard-at id.raw cur-height)
  p
::
::  +add-tx-in-pending-block:
::
::    when a tx is in a pending block, we ignore whether it uses
::    inputs that have been spent in the heaviest balance, or
::    when we heard it.
++  add-tx-in-pending-block
  |=  raw=raw-tx:t
  ^-  pending-state:dk
  =.  p  (add-raw-tx raw)
  ::  this one needs to go before remove-tx-from-tx-block because
  ::  the keys it needs to inspect are gotten from .tx-block.
  =.  p  (remove-tx-from-block-tx id.raw)
  =.  p  (remove-tx-from-tx-block id.raw)
  p
::
++  tx-heard-at
  |=  [id=tx-id:t height=page-number:t]
  ^-  pending-state:dk
  p(heard-at (~(put z-by heard-at.p) id height))
::
++  add-inputs-to-spent-by
  |=  raw=raw-tx:t
  ^-  pending-state:dk
  =/  inputs-names=(list nname:t)
    ~(tap z-in (inputs-names:raw-tx:t raw))
  =/  new-entries=(list [nname:t tx-id:t])
    (turn inputs-names |=(n=nname:t n^id.raw))
  p(spent-by (~(gas z-by spent-by.p) new-entries))
::
++  remove-inputs-from-spent-by
  |=  raw=raw-tx:t
  ^-  pending-state:dk
  =/  inputs-names=(list nname:t)
    ~(tap z-in (inputs-names:raw-tx:t raw))
  =.  spent-by.p
    %+  roll  inputs-names
    |=  [nom=nname:t spb=_spent-by.p]
    (~(del z-by spb) nom)
  p
::
::  +find-pending-tx-ids: pending tx-ids for pending blocks
++  find-pending-tx-ids
  ^-  (z-set tx-id:t)
  %+  roll  ~(val z-by block-tx.p)
  |=  [tx-ids=(z-set tx-id:t) all-tx-ids=(z-set tx-id:t)]
  (~(uni z-in all-tx-ids) tx-ids)
::
++  remove-tx-from-tx-block
  |=  id=tx-id:t
  ^-  pending-state:dk
  p(tx-block (~(del z-by tx-block.p) id))
::
++  remove-tx-from-block-tx
  |=  tid=tx-id:t
  ^-  pending-state:dk
  =/  block-vals=(unit (z-set block-id:t))
    (~(get z-by tx-block.p) tid)
  ?~  block-vals
    ::  no blocks waiting on this tx, so do nothing
    p
  =/  block-list=(list block-id:t)
    ~(tap z-in u.block-vals)
  =.  block-tx.p
    %+  roll  block-list
    |=  [bid=block-id:t blt=_block-tx.p]
    (~(del z-ju blt) bid tid)
  p
::
++  add-pending-block
  |=  pag=page:t
  ^-  [(list tx-id:t) pending-state:dk]
  ::  find missing txs
  =/  missing-txs=(list tx-id:t)
    :: linear in the number of transactions in a block which is much smaller than
    :: the number of transactions in the state, which key:z-by must traverse
    %-  ~(rep z-in tx-ids.pag)
    |=  [tid=tx-id:t missing=(list tx-id:t)]
    ?.  (has-raw-tx tid)
      [tid missing]
    missing
  ::  return missing txs and new pending state
  :-  missing-txs
  =;  pen=pending-state:dk
    ::  add to list of pending blocks if there are missing txs
    =?  pending-blocks.pen
      !=(~ missing-txs)
    (~(put z-by pending-blocks.pen) digest.pag (to-local-page:page:t pag))
    pen
  %+  roll  missing-txs
  |=  [tid=tx-id:t pen=_p]
  ::  block requires these txs to be complete
  =.  block-tx.pen
    (~(put z-ju block-tx.pen) digest.pag tid)
  ::  add block to set of blocks that require this tx
  =.  tx-block.pen
    (~(put z-ju tx-block.pen) tid digest.pag)
  pen
::
++  remove-pending-block
  |=  bid=block-id:t
  ^-  pending-state:dk
  =.  pending-blocks.p  (~(del z-by pending-blocks.p) bid)
  ::  get the txs that were needed for this block. if it was a valid
  ::  block, this will be empty already, but if it was invalid we
  ::  want to clean up the state.
  =/  tx-vals=(unit (z-set tx-id:t))
                        (~(get z-by block-tx.p) bid)
  ?~  tx-vals
    ::  no txs needed by block so just delete from block-tx
    =.  block-tx.p      (~(del z-by block-tx.p) bid)
    p
  =/  tx-list=(list tx-id:t)
    ~(tap z-in u.tx-vals)
  =.  block-tx.p        (~(del z-by block-tx.p) bid)
  ::  remove the block-id from this map.
  =.  tx-block.p
    %+  roll  tx-list
    |=  [tid=tx-id:t txb=_tx-block.p]
    (~(del z-ju txb) tid bid)
  p
::
++  add-raw-tx
  |=  raw=raw-tx:t
  ^-  pending-state:dk
  p(raw-txs (~(put z-by raw-txs.p) id.raw raw))
::
++  remove-raw-tx
  |=  tid=tx-id:t
  ^-  pending-state:dk
  p(raw-txs (~(del z-by raw-txs.p) tid))
--
