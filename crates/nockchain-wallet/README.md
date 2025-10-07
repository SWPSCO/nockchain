# Nockchain Wallet

## Setup

### Generate New Key Pair

```bash
# Generate a new key pair with random entropy
nockchain-wallet keygen
```

### Importing and Exporting Keys

The wallet supports importing and exporting keys:

```bash
# Export all wallet keys to a file (default: keys.export)
nockchain-wallet export-keys

# Import keys from the exported file
nockchain-wallet import-keys --file keys.export

# Import an extended key string
nockchain-wallet import-keys --key "zprv..."

# Generate master private key from seed phrase
nockchain-wallet import-keys --seedphrase "your seed phrase here"

# Generate master public key from private key and chain code
nockchain-wallet import-keys --master-privkey <private-key> --chain-code <chain-code>

# Import a watch-only public key
nockchain-wallet import-keys --watch-only <public-key-base58>

# Import a master public key from exported file
nockchain-wallet import-master-pubkey keys.export
```

The exported keys file contains all wallet keys as a `jam` file that can be imported on another instance.

Can be used for:
- Backing up your wallet
- Migrating to a new device
- Sharing public keys with other users

### Connecting to a Nockchain API server

The wallet talks to the gRPC APIs exposed by a running nockchain instance. You can target either the **public** API (default) or the **private** API that is typically bound to `localhost`. You must run a nockchain instance to connect to the private API. Zorp runs its own public Nockchain API server at `https://nockchain-api.zorp.io`, and the wallet connects to it by default.

#### Public API (default)

```bash
# Use the default public endpoint (https://nockchain-api.zorp.io)
nockchain-wallet list-notes

# Or point at a different remote public listener
nockchain-wallet \
  --client public \
  --public-grpc-server-addr https://public-node.example.com \
  list-notes
```
- The wallet syncs its balance based on the pubkeys that are stored in it. Make sure your wallet is loaded with your keys before running sync-heavy commands such as `list-notes`, `list-notes-by-pubkey`, `create-tx`, and `send-tx`. If you do not have pubkeys, import them with `import-keys` (see [Importing and Exporting Keys](#importing-and-exporting-keys)).
- `--public-grpc-server-addr` accepts a bare `host:port` or a full URI (e.g. `http://host:port`).
- If you omit the port, the wallet assumes **80** for `http://` and **443** for `https://` URLs.
- By default, we do not sync notes attached to watch-only pubkeys. Pair sync-heavy commands with `--include-watch-only` when you want watch-only pubkeys included in balance updates.

#### Private API

```bash
# Talk to a private listener running on localhost:5555 (default)
nockchain-wallet --client private list-notes

# Override the private port if your setup uses a different port forward
nockchain-wallet \
  --client private \
  --private-grpc-server-port 6000 \
  list-notes
```

When `--client private` is selected, the wallet spins up the private listener driver so subsequent operations (balance sync and transaction submission) use the private interface automatically. You must have a
nockchain instance running locally to use the private client.

> **Tip:** Ensure the corresponding NockApp gRPC server is running and reachable before issuing wallet commands; otherwise the wallet will fail when attempting to synchronize state.



# Advanced Options

### Derive Child Key

```bash
# Derive child key with index as positional argument
nockchain-wallet derive-child <0-2147483647> --hardened --label <label>

# Examples:
nockchain-wallet derive-child 42
nockchain-wallet derive-child 42 --hardened
nockchain-wallet derive-child 42 --hardened --label "my-key"
```

Derives a child public or private key at the given index from the current master key.




## Listing Notes

### List All Notes

```bash
nockchain-wallet list-notes
```

Displays all notes (UTXOs) currently managed by the wallet, sorted by assets.

### List Notes by Public Key

```bash
nockchain-wallet list-notes-by-pubkey <public-key>
```

Shows only the notes associated with the specified public key. Useful for filtering wallet contents by address or for multisig scenarios.

### List Arbitrary Notes by Public Key (Watch-Only)

```bash
nockchain-wallet import-keys --watch-only <public-key>
nockchain-wallet list-notes-by-pubkey <public-key> --include-watch-only
```

Shows only the notes associated with the specified public key. Useful for filtering wallet contents by address or for multisig scenarios.

You must add the watch-only pubkey to the wallet before it will be recognized.

### List Notes by Public Key (CSV format)

```bash
nockchain-wallet list-notes-by-pubkey-csv <public-key>
```

Outputs matching notes in CSV format suitable for analysis or reporting. The output csv has the format: `notes-<public-key>.csv`.

## Transaction Creation

#### Components of transaction creation

1. **Seeds**: Define where funds are going and how much
2. **Inputs**: Specify which notes (UTXOs) to spend
3. **Transaction**: Combine inputs into a complete transaction
4. **Sign**: Authorize the transaction with private keys
5. **Send Transaction**: Send the final transaction for broadcasting

### Create a Transaction

The create-tx command supports two modes: single recipient and multiple recipients.

#### Single Recipient Transaction

```bash
# Send to a single recipient
nockchain-wallet create-tx \
  --names "[first1 last1]" \
  --recipients "[1 pk1]" \
  --gifts 100 \
  --fee 10
```

Gifts and fees are denominated in nicks (65536 nicks = 1 nock).

For single recipient transactions:
- `--recipients` specifies one recipient as `[<num-of-signatures> <public-key-1>,<public-key-2>,...]`
- `--gifts` specifies the amount to send to that recipient
- Multiple names can still be provided to use funds from multiple notes

#### Multiple Recipients Transaction

```bash
# Send to multiple recipients
nockchain-wallet create-tx \
  --names "[first1 last1],[first2 last2]" \
  --recipients "[1 pk1],[2 pk2,pk3]" \
  --gifts "100,200" \
  --fee 10
```

Gifts and fees are denominated in nicks (65536 nicks = 1 nock).

For multiple recipient transactions:
- `--recipients` specifies a list of recipients, each as `[<num-of-signatures> <public-key-1>,<public-key-2>,...]`
- `--gifts` specifies a list of amounts, one for each recipient (must match the number of recipients)

#### Common Parameters

- The number of signatures required is specified as the first number in each recipient specification
- The `names` argument is a list of `[first-name last-name]` pairs specifying funding notes
- The `fee` argument is the transaction fee to pay (in nicks, 65536 nicks to 1 nock)
- For multisig recipients, list multiple public keys after the signature count
- Optional timelock constraints are specified with a single flag: `--timelock <SPEC>`, where `SPEC` is a comma-separated list of `absolute=<range>` and/or `relative=<range>`.
  - Ranges use the `min..max` syntax. (`10..`, `..500`, `0..1`).
  - Providing only a range (without `absolute=`) is shorthand for `absolute=<range>`.
  - Supplying both components gives a combined intent.
  - Any finite upper bound prompts for confirmation—type `YES` to acknowledge the note becomes unspendable after the upper bound.

### Make Transaction from Transaction File

```bash
# Sign the transaction
nockchain-wallet sign-tx txs/transaction.tx

# Optionally specify a key index for signing
nockchain-wallet sign-tx txs/transaction.tx --index 5

# Display transaction contents
nockchain-wallet show-tx txs/transaction.tx

# Make and broadcast the signed transaction
nockchain-wallet send-tx txs/transaction.tx
```

Note: The transaction file will be saved in `./txs/` directory with a `.tx` extension.

### Check whether a transaction was accepted (public API only)

```bash
# Query the public API for acceptance status
nockchain-wallet \
  --client public \
  tx-accepted <base58-tx-id>
```

- The wallet asks the Nockchain node whether it has validated the transaction (consistency check). A `true` response means the node accepted the transaction, not that it currently resides in the mempool. You can use this command to check whether a transaction was accepted by the network; it is necessary for inclusion in a block but not sufficient when timelocks are present.
- Currently, the private API cannot be queried with this request
- The command is lightweight and does not perform a full balance sync.


## Message Signing and Verification

### Sign Message

Signs arbitrary bytes with the wallet's key. By default, the signature is written to `message.sig`.

Short flags:

```bash
nockchain-wallet sign-message -m "hello"
nockchain-wallet sign-message -m "hello" --index 5 --hardened
```

Positional message (equivalent to `-m/--message`):

```bash
nockchain-wallet sign-message "hello"
```

From file:

```bash
nockchain-wallet sign-message --message-file ./payload.bin
```

### Verify Message

Verifies a signature against a message and a base58-encoded schnorr public key.

Short flags:

```bash
nockchain-wallet verify-message -m "hello" -s message.sig -p <BASE58_PUBKEY>
```

Positional-only form (message, signature file, pubkey):

```bash
nockchain-wallet verify-message "hello" message.sig <BASE58_PUBKEY>
```

Named/positional mixed examples:

```bash
nockchain-wallet verify-message --message-file ./payload.bin message.sig <BASE58_PUBKEY>
nockchain-wallet verify-message "hello" -s message.sig -p <BASE58_PUBKEY>
```

Notes:
- The positional forms are equivalent to the named flags (`--message`, `--signature`, `--pubkey`).

### Sign Hash

Signs a precomputed tip5 hash (base58 string). Writes signature to `hash.sig`.

```bash
nockchain-wallet sign-hash <BASE58_TIP5_HASH>
nockchain-wallet sign-hash <BASE58_TIP5_HASH> --index 5 --hardened
```

### Verify Hash

Verifies a signature against a precomputed tip5 hash (base58 string) and pubkey.

```bash
nockchain-wallet verify-hash <BASE58_TIP5_HASH> hash.sig <BASE58_PUBKEY>
nockchain-wallet verify-hash <BASE58_TIP5_HASH> -s hash.sig -p <BASE58_PUBKEY>
```
