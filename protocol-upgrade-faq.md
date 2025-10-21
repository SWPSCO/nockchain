#  V1 Protocol Upgrade FAQ

## For Miners
### How do I generate a mining PKH for the automatic cutover?

Run `nockchain-wallet generate-mining-pkh` and record the PKH address the command prints (see the “Setup Keys” section above for details on wiring it into `.env`). If you are not using the bash scripts we provide to run the miner, you need to pass the newly generated PKH address to the `--mining-pkh` arg and your current pubkey address to the `--mining-pubkey` arg when starting the miner.

## General

### What will change after the v1 protocol cutoff at block 39000?
At block 39000 v0 keys will only be able to spend to v1 addresses. This means that v0 keys will no longer be able to spend funds to v0 addresses. We will not support upgrading v0 keys to v1. You will need to generate a new v1 keypair and transfer your funds to it. There is no deadline for doing this, but we recommend doing it as soon as possible.

We are working on tools in the wallet to allow you to easily transfer your funds from a v0 key to a v1 key.

### Is there a deadline to transferring v0 notes to v1?
No, there is no deadline to transferring v0 notes to v1. You can transfer your funds at any time.

### How do I generate keys if I want to transact or receive funds now?

Run `nockchain-wallet keygen`. That command will emit a v0 master key until the wallet has been upgraded to create v1 transactions.

### How do I generate v1 keys?
If you are not a miner, there is no need to create v1 keys at this time, since you will not be able to receive funds using those keys until block height 39000. v1 keys will be supported at block height 39000. Generate new v0 keys using `nockchain-wallet keygen`.

### Should I use the `generate-mining-pkh` command?
If you are not a miner, there is currently no need to generate a set of v1 keys since you will not be able to receive funds using those keys until block height 39000. Use `nockchain-wallet keygen` instead.

### Can I import my v0 keys as v1 keys?

Do not do this. We will provide tools in the wallet to allow you to generate a new v1 key and transfer your funds from your old v0 key to a v1 key.

### I have a seed phrase. I have some v0 notes I want to spend. How do I import it?

If your seed phrase predates the release of the v1 protocol upgrade (October 15, 2025), it most likely maps to a version 0 master key. Import it with the version flag: `nockchain-wallet import-keys --seedphrase "<your words>" --version 0`. It should be set to the active master key after importing, so you should be able to create transactions with it without running further commands.

### I have a `keys.export` file from `nockchain-wallet export-keys`. How do I recover my v0 key?

Run `nockchain-wallet import-keys --file <PATH_TO_KEYS_EXPORT>`. The import process preserves the key version. When the import completes, set the restored master active with `nockchain-wallet set-active-master-address <IMPORTED_V0_ADDRESS>`.

### The wallet says "Active address corresponds to v1 key" when I try to spend v0 notes. What should I do?

1. If you still need a v0 master key, import it first using either `nockchain-wallet import-keys --file <PATH_TO_KEYS_EXPORT>` or `nockchain-wallet import-keys --seedphrase "<your words>" --version 0`.
2. Make the v0 master active:
   - List known masters: `nockchain-wallet list-master-addresses`
   - Set the active one: `nockchain-wallet set-active-master-address <V0_ADDRESS>`
   - (Optional) confirm: `nockchain-wallet list-active-addresses`

Once a v0 master is active, retry the spend and it will sign successfully.
