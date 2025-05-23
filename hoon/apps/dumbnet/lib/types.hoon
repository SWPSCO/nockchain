/=  *   /common/zoon
/=  zeke  /common/zeke
/=  w   /common/wrapper
/=  dt  /common/tx-engine
/=  sp  /common/stark/prover
/=  miner-kernel  /apps/dumbnet/miner
|%
+|  %state
+$  kernel-state
  $+  kernel-state
  $%  $:  %0
          c=consensus-state
          p=pending-state
          a=admin-state
          m=mining-state
        ::
          d=derived-state
          constants=blockchain-constants:dt
  ==  ==
::
+$  consensus-state
  $+  consensus-state
  $:  balance=(z-mip block-id:dt nname:dt nnote:dt)
      txs=(z-mip block-id:dt tx-id:dt tx:dt) ::  fully validated transactions
      blocks=(z-map block-id:dt local-page:dt)  ::  fully validated blocks
    ::
      heaviest-block=(unit block-id:dt) ::  most recent heaviest block
    ::
    ::  min timestamp of block that is a child of this block
      min-timestamps=(z-map block-id:dt @)
    ::  this map is used to calculate epoch duration. it is a map of each
    ::  block-id to the first block-id in that epoch.
      epoch-start=(z-map block-id:dt block-id:dt)
    ::  this map contains the expected target for the child
    ::  of a given block-id.
      targets=(z-map block-id:dt bignum:bignum:dt)
    ::
    ::  Bitcoin block hash for genesis block
    ::>)  TODO: change face to btc-hash?
      btc-data=(unit (unit btc-hash:dt))
      =genesis-seal:dt  ::  desired seal for genesis block
  ==
::
::  you will not have lost any chain state if you lost pending state, you'd just have to
::  request data again from peers
+$  pending-state
  $+  pending-state
  $:  pending-blocks=(z-map block-id:dt local-page:dt)  ::  blocks for which we are waiting on txs
    ::  data we need
      block-tx=(z-jug block-id:dt tx-id:dt)  ::  tx-id's needed before pending block-id can be validated
      tx-block=(z-jug tx-id:dt block-id:dt)  ::  pending block-id's that include tx-id
    ::  data we have
      raw-txs=(z-map tx-id:dt raw-tx:dt)
      spent-by=(z-map nname:dt tx-id:dt)        ::  names of notes and the pending tx trying to spend it
      heard-at=(z-map tx-id:dt page-number:dt)  :: block height which a tx-id was first heard
  ==
::
+$  admin-state
  $+  admin-state
  $:  desk-hash=(unit @uvI)               ::  hash of zkvm desk
      init=init-phase                     ::  boolean flag denoting whether kernel is in the init phase.
      retain=$~([~ 20] (unit @))          ::  how long to retain transactions before dropping
                                          ::  value of ~ indicates never drop transactions,
                                          ::  value of [~ 0] indicates drop everything every new block
  ==
::
+$  derived-state
  $+  derived-state
  $:  heaviest-chain=(z-map page-number:dt block-id:dt)
  ==
::
+$  mining-state
  $+  mining-state
  $:  mining=?                        ::  build candidate blocks?
      pubkeys=(z-set lock:dt)          ::  locks for coinbase in mined blocks
      shares=(z-map lock:dt @)         ::  shares of coinbase+fees among locks
      candidate-block=page:dt            ::  the next block we will attempt to mine.
      candidate-acc=tx-acc:dt           ::  accumulator for txs in candidate block
      next-nonce=noun-digest:tip5:zeke  :: nonce being mined
  ==
::
+$  init-phase  $~(%.y ?)
::
+|  %io
+$  peer-id  @id  ::  libp2p PeerId in base58 format converted to a bytestring
+$  cause
  $+  cause
  $%  [%fact p=fact]  ::  wire format; message from king, kernel must validate these
      [%command p=command]  ::  originate locally
  ==
::
+$  command
  $+  command
  $%  [%pow prf=proof:sp dig=tip5-hash-atom:zeke bc=digest:tip5:zeke nonce=noun-digest:tip5:zeke] :: check if a proof of work is good for the next block, issue a block if so
      [%set-mining-key p=@t]  ::  set $lock for coinbase in mined blocks
      [%set-mining-key-advanced p=(list [share=@ m=@ keys=(list @t)])]  :: multisig and/or split coinbases
      [%enable-mining p=?]  ::  switch for generating candidate blocks for mining
      [%timer p=~] ::  ask for heaviest block and any pending transactions
      [%born p=~]  ::  initial event the king sends on boot
      [%genesis p=[=btc-hash:dt block-height=@ message=cord]]  ::  emit genesis block with this template
      :: set expected btc height and msg hash of genesis block
      [%set-genesis-seal p=[height=page-number:dt msg-hash=@t]]
      [%btc-data p=(unit btc-hash:dt)]  ::  data from BTC RPC node
      test-command
  ==
::
::  commands only used during testing
+$  test-command
  $+  test-command
  $%  [%set-constants p=blockchain-constants:dt]
  ==
::
::  commands that can only be performed if init-phase is %.y
+$  init-command
  $?  %set-constants
      %set-genesis-seal
      %btc-data
      %genesis
      %born
  ==
::  commands that can only be performed if init-phase is %.n
+$  non-init-command  ?(%timer %pow)
::
+$  fact
  $+  fact
  $:  version=%0
    $=  data
    $%  [%heard-block p=page:dt]
        [%heard-tx p=raw-tx:dt]
        [%heard-elders p=[oldest=page-number:dt ids=(list block-id:dt)]]
    ==
  ==
::
+$  effect
  $+  effect
  $%  [%gossip p=fact]  :: broadcast tx or block to network
      [%request p=request]  :: request specific tx or block
      [%track p=track]  :: runtime tracking of blocks for %liar-block-id effect
      [%seen p=seen]    ::  seen so don't reprocess
      [%mine length=@ block-commitment=noun-digest:tip5:zeke nonce=noun-digest:tip5:zeke]
      lie
      span-effect
      [%exit code=@]
  ==
::
+$  seen
  $+  seen
  $%  [%block p=block-id:dt]  ::  block has been seen, don't reprocess
      [%tx p=tx-id:dt]       ::  tx has been seen, don't reprocess
  ==
::
+$  span-field
  $%  [%n p=@ud]
      [%s p=@t]
  ==
+$  span-effect  [%span name=cord fields=(list (pair cord span-field))]
::
+$  request
  $+  request
  $%  [%block request-block]
      [%raw-tx request-tx]
  ==
::
++  request-block
  $%  [%by-height p=page-number:dt] ::  request block at height .p on each peer's heaviest chain
      [%elders p=block-id:dt q=peer-id] ::  request ancestor block IDs up to 24 deep from specific peer
  ==
::
++  request-tx
  $%  [%by-id p=tx-id:dt] ::  request raw-tx with id .p from peers
  ==
::
::  Records reason for failure if %.n
::  Returns `object` if %.y
::  Used to surface cause to liar effect.
++  reason
  |$  object
  (each object term)
::
::  the runtime tracks who sent us which blocks to determine which peers to
::  ban for a bad block. an %add effect is emitted when a block has a valid
::  digest. this tells the runtime to add that block-id and peer-id to
::  MessageTracker and means %liar-block-id is now
::  possible for that block-id (see the libp2p driver for further
::  information). %remove means that that block-id has valid txs as well, so
::  it is no longer necessary for the driver to track that block-id.
+$  track
  $+  track
  $%  [%add p=block-id:dt q=peer-id]  ::  everything but txs checked, add to tracking
      [%remove p=block-id:dt] ::  txs also valid, remove from tracking
  ==
::
+$  lie
  $%  ::  block has bad non-tx data, or raw-tx did not validate. this is only
      ::  ever returned as an effect in response to a particular tx or block
      ::  poke.
      [%liar-peer p=peer-id cause=term]  ::  block-id is wrong, or raw-tx did not validate
      ::
      ::  block-id is correct, block did not validate. this is only returned once
      ::  a block's fields are all checked as having been valid - so we know
      ::  the block-id and powork are valid in particular. so only bad tx data
      ::  can cause this to be emitted - and the libp2p driver will ban all nodes
      ::  that sent us this block-id as a result.
      [%liar-block-id p=block-id:dt cause=term]
  ==
::
::  $goof: kernel error type
::
+$  goof    [mote=term =tang]
+$  ovum    [[%poke ~] =pok]                                 ::  internal poke
::  $crud: kernel error wrapper
::
+$  crud    [=goof =pok]
::  $pok: kernel poke type
::
+$  pok     [eny=@ our=@ux now=@da =cause]
--
