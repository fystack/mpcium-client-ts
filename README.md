# Mpcium TypeScript Client

A TypeScript client for interacting with Mpcium Multi-Party Computation (MPC) service to generate and manage wallets and sign transactions across multiple blockchains.

### Client sign

![alt text](./images/sign-solana.png)

### MPCIUM nodes coordinate to sign transaction

![alt text](./images/mpc-nodes.png)

## Prerequisites

Important: Before using this TypeScript client, you need to set up the Mpcium MPC nodes. The nodes provide the underlying MPC infrastructure that this client connects to.
Please follow the installation and setup instructions at [mpcium](https://github.com/fystack/mpcium) to deploy the required MPC nodes. Typically, you'll need to run multiple nodes (e.g., 3 nodes in a 2-of-3 threshold setup) before using this client.

```sh
# Example of starting MPC nodes (after installing from the repository)
mpcium start -n node0
mpcium start -n node1
mpcium start -n node2
```

## Overview

Mpcium is a service that provides secure key management and transaction signing using Multi-Party Computation. This client library allows you to:

- Generate cryptographic keys without exposing private key material
- Sign transactions for multiple blockchain networks
- Receive cryptographic operation results through event subscriptions

## Supported Key Types and Blockchains

- **ECDSA**: Bitcoin, Ethereum, and other EVM-compatible chains
- **EdDSA**: Solana, Polkadot, Cardano, and other EdDSA-based chains

## Installation

```bash
npm install @fystack/mpcium-ts
```

## Creating a client

- User need to generate `event_initiator.key` through [mpcium-cli](https://github.com/fystack/mpcium/blob/master/INSTALLATION.md) before using this client

```ts
import { connect } from "nats";
import { MpciumClient } from "@fystack/mpcium-ts";

async function setupClient() {
  // First, establish NATS connection
  const nc = await connect({ servers: "nats://localhost:4222" });

  // Create client with key path
  const mpcClient = await MpciumClient.create({
    nc: nc,
    keyPath: "./event_initiator.key",
  });

  return mpcClient;
}
```

### Encrypted client (Recommended for production usage)

```ts
const mpcClient = await MpciumClient.create({
  nc: nc,
  keyPath: "./event_initiator.key.age",
  password: "your-secure-password", // Stored and load secure vault like KMS, Hashicorp vault
});
```

### Generating a Wallet

```ts
import { connect } from "nats";
import { MpciumClient } from "@fystack/mpcium-ts";
import fs from "fs";

async function generateWallet() {
  const nc = await connect({ servers: "nats://localhost:4222" });
  const mpcClient = await MpciumClient.create({
    nc: nc,
    keyPath: "./event_initiator.key",
  });

  // Store wallets in a file (for testing only)
  const walletsFile = "./examples/wallets.json";
  const wallets = fs.existsSync(walletsFile)
    ? JSON.parse(fs.readFileSync(walletsFile, "utf8"))
    : {};

  // Subscribe to wallet creation results
  mpcClient.onWalletCreationResult((event) => {
    console.log("Received wallet creation result:", event);

    // Store wallet info with wallet_id as key
    wallets[event.wallet_id] = {
      wallet_id: event.wallet_id,
      ecdsa_pub_key: event.ecdsa_pub_key,
      eddsa_pub_key: event.eddsa_pub_key,
    };

    // Save to file (in production, use a database)
    fs.writeFileSync(walletsFile, JSON.stringify(wallets, null, 2));
    console.log(`Wallet ${event.wallet_id} saved to wallets.json`);
    console.log(
      "NOTE: File storage is for testing only. Use a database in production."
    );
  });

  // Create the wallet
  const walletID = await mpcClient.createWallet();
  console.log(`CreateWallet request sent, wallet ID: ${walletID}`);

  // Wait for result and handle cleanup
  process.on("SIGINT", async () => {
    await mpcClient.cleanup();
    await nc.drain();
    process.exit(0);
  });
}
```

### Signing a Solana Transaction

```ts
import { connect } from "nats";
import { MpciumClient, KeyType } from "@fystack/mpcium-ts";
import {
  Connection,
  Transaction,
  SystemProgram,
  PublicKey,
  LAMPORTS_PER_SOL,
} from "@solana/web3.js";
import fs from "fs";

async function signSolanaTransaction(walletId) {
  const nc = await connect({ servers: "nats://localhost:4222" });
  const mpcClient = await MpciumClient.create({
    nc: nc,
    keyPath: "./event_initiator.key",
  });

  // Get wallet information from wallets.json
  const walletsFile = "./examples/wallets.json";
  const wallets = JSON.parse(fs.readFileSync(walletsFile, "utf8"));
  const wallet = wallets[walletId];

  if (!wallet) {
    throw new Error(`Wallet ${walletId} not found`);
  }

  // Connect to Solana devnet
  const connection = new Connection(
    "https://api.devnet.solana.com",
    "confirmed"
  );

  // Create public key from wallet data
  const publicKeyBuffer = Buffer.from(wallet.eddsa_pub_key, "base64");
  const fromPublicKey = new PublicKey(publicKeyBuffer);

  // Create transaction
  const transaction = new Transaction().add(
    SystemProgram.transfer({
      fromPubkey: fromPublicKey,
      toPubkey: new PublicKey("4LKprD1XvTuBupHqWXoS42XsEBHp7qALo3giDBRCNhAV"),
      lamports: LAMPORTS_PER_SOL * 0.01,
    })
  );

  // Get recent blockhash
  const { blockhash } = await connection.getLatestBlockhash();
  transaction.recentBlockhash = blockhash;
  transaction.feePayer = fromPublicKey;

  // Serialize transaction message
  const serializedTx = transaction.serializeMessage();

  // Listen for signing results
  mpcClient.onSignResult((event) => {
    if (event.result_type === 1) {
      // Success
      const signature = Buffer.from(event.signature, "base64");
      transaction.addSignature(fromPublicKey, signature);

      if (transaction.verifySignatures()) {
        connection
          .sendRawTransaction(transaction.serialize())
          .then((txId) => console.log(`Transaction sent: ${txId}`));
      }
    }
  });

  // Send signing request
  await mpcClient.signTransaction({
    walletId: walletId,
    keyType: KeyType.Ed25519,
    networkInternalCode: "solana:devnet",
    tx: Buffer.from(serializedTx).toString("base64"),
  });
}
```

[Full example: sign-solana.ts](./examples/sign-solana.ts)

### HD Wallet Derivation (`derivation_path`)

Instead of running DKG for every user, you can generate **one master wallet** and derive unlimited child addresses using BIP-32 non-hardened child key derivation (CKD). The `derivation_path` is passed at signing time — the MPC nodes derive the same child key server-side during the signing ceremony.

**Architecture:**
- One DKG (`createWallet`) produces a master public key + chain code
- Child addresses are derived client-side via `deriveEthereumAddress()` / `deriveSecp256k1ChildCompressed()` / `deriveEd25519ChildCompressed()`
- At signing time, pass `derivationPath` so MPC nodes sign with the matching child key
- A single backup at init time is enough to restore all wallets

```ts
import { connect } from "nats";
import {
  MpciumClient,
  KeyType,
  deriveEthereumAddress,
  compressPublicKey,
} from "@fystack/mpcium-ts";
import fs from "fs";

async function signWithDerivedKey(walletId: string, userIndex: number) {
  const nc = await connect({ servers: "nats://localhost:4222" });
  const mpcClient = await MpciumClient.create({
    nc,
    keyPath: "./event_initiator.key",
  });

  // Load wallet generated via createWallet() — must include
  // ecdsa_pub_key and chain_code from the DKG result
  const wallets = JSON.parse(fs.readFileSync("./wallets.json", "utf8"));
  const wallet = wallets[walletId];

  // Compress the master public key (DKG may return 64/65-byte uncompressed)
  const masterPubKey = new Uint8Array(
    Buffer.from(wallet.ecdsa_pub_key, "base64")
  );
  const compressed =
    masterPubKey.length === 33
      ? masterPubKey
      : compressPublicKey(masterPubKey);

  // Derive child address locally — same result the MPC nodes will compute
  const derivationPath = [44, 60, 0, 0, userIndex];
  const childAddress = deriveEthereumAddress(
    compressed,
    wallet.chain_code, // hex string from DKG result
    derivationPath
  );

  console.log(`User #${userIndex} address: ${childAddress}`);

  // Build your transaction using childAddress as the sender,
  // then base64-encode the tx hash for signing:
  const txHash = "..."; // unsigned transaction hash (hex, no 0x prefix)
  const txPayload = Buffer.from(txHash, "hex").toString("base64");

  // Sign with derivation_path — MPC nodes derive the same child key
  const txId = await mpcClient.signTransaction({
    walletId: walletId,
    keyType: KeyType.Secp256k1,
    networkInternalCode: "ethereum:sepolia",
    tx: txPayload,
    derivationPath: derivationPath, // ← enables HD child signing
  });
}
```

The same approach works for Ed25519 chains (Solana, Polkadot) using `deriveEd25519ChildCompressed()`.

[Full example: sign-eth-derived.ts](./examples/sign-eth-derived.ts)

### Signing a Polkadot Transaction (Native Token Transfer)

```ts
import { connect } from "nats";
import {
  MpciumClient,
  KeyType,
  buildNativeTransferPayload,
  submitSignedExtrinsic,
  ed25519PubKeyToSubstrateAddress,
  getNetworkCode,
  POLKADOT_NETWORKS,
} from "@fystack/mpcium-ts";
import { SigningResultType } from "@fystack/mpcium-ts";
import { u8aToHex } from "@polkadot/util";
import fs from "fs";

async function signPolkadotTransaction(walletId: string) {
  const nc = await connect({ servers: "nats://localhost:4222" });
  const mpcClient = await MpciumClient.create({
    nc: nc,
    keyPath: "./event_initiator.key",
  });

  // Load wallet from wallets.json
  const wallets = JSON.parse(fs.readFileSync("./wallets.json", "utf8"));
  const wallet = wallets[walletId];

  if (!wallet?.eddsa_pub_key) {
    throw new Error(`Wallet ${walletId} not found or missing EdDSA key`);
  }

  // Convert EdDSA public key to Substrate address
  const senderAddress = ed25519PubKeyToSubstrateAddress(
    wallet.eddsa_pub_key,
    POLKADOT_NETWORKS.westend.ss58Prefix // Use Westend testnet
  );

  // Build signing payload for native token transfer
  const payloadResult = await buildNativeTransferPayload({
    mpcAddress: senderAddress,
    destinationAddress: "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
    amount: BigInt(100_000_000_000), // 0.1 WND
    network: "westend",
    keepAlive: true,
  });

  // Listen for signing results
  mpcClient.onSignResult(async (event) => {
    if (event.result_type === SigningResultType.Success) {
      const sigBytes = Buffer.from(event.signature, "base64");
      const signatureHex = u8aToHex(sigBytes);

      // Submit signed extrinsic
      const result = await submitSignedExtrinsic({
        api: payloadResult.api,
        extrinsic: payloadResult.extrinsic,
        signatureHex: signatureHex,
        mpcAddress: senderAddress,
      });

      console.log(`Transaction submitted: ${result.txHash}`);
    }
  });

  // Send signing request
  await mpcClient.signTransaction({
    walletId: walletId,
    keyType: KeyType.Ed25519,
    networkInternalCode: getNetworkCode("westend"),
    tx: Buffer.from(payloadResult.payloadBytes).toString("base64"),
  });
}
```

[Full example: sign-polkadot.ts](./examples/sign-polkadot.ts)

### Signing an Asset Hub Transaction (Asset Transfer)

```ts
import { connect } from "nats";
import {
  MpciumClient,
  KeyType,
  buildAssetTransferPayload,
  submitSignedExtrinsic,
  ed25519PubKeyToSubstrateAddress,
  getNetworkCode,
  POLKADOT_NETWORKS,
} from "@fystack/mpcium-ts";
import { SigningResultType } from "@fystack/mpcium-ts";
import { u8aToHex } from "@polkadot/util";
import fs from "fs";

async function signAssetHubTransaction(walletId: string, assetId: number) {
  const nc = await connect({ servers: "nats://localhost:4222" });
  const mpcClient = await MpciumClient.create({
    nc: nc,
    keyPath: "./event_initiator.key",
  });

  // Load wallet from wallets.json
  const wallets = JSON.parse(fs.readFileSync("./wallets.json", "utf8"));
  const wallet = wallets[walletId];

  if (!wallet?.eddsa_pub_key) {
    throw new Error(`Wallet ${walletId} not found or missing EdDSA key`);
  }

  // Convert EdDSA public key to Substrate address
  const senderAddress = ed25519PubKeyToSubstrateAddress(
    wallet.eddsa_pub_key,
    POLKADOT_NETWORKS["asset-hub-westend"].ss58Prefix
  );

  // Build signing payload for asset transfer
  const payloadResult = await buildAssetTransferPayload({
    mpcAddress: senderAddress,
    assetId: assetId,
    destinationAddress: "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
    amount: BigInt(1_000_000),
    network: "asset-hub-westend",
  });

  // Listen for signing results
  mpcClient.onSignResult(async (event) => {
    if (event.result_type === SigningResultType.Success) {
      const sigBytes = Buffer.from(event.signature, "base64");
      const signatureHex = u8aToHex(sigBytes);

      // Submit signed extrinsic
      const result = await submitSignedExtrinsic({
        api: payloadResult.api,
        extrinsic: payloadResult.extrinsic,
        signatureHex: signatureHex,
        mpcAddress: senderAddress,
      });

      console.log(`Transaction submitted: ${result.txHash}`);
    }
  });

  // Send signing request
  await mpcClient.signTransaction({
    walletId: walletId,
    keyType: KeyType.Ed25519,
    networkInternalCode: getNetworkCode("asset-hub-westend"),
    tx: Buffer.from(payloadResult.payloadBytes).toString("base64"),
  });
}
```

[Full example: sign-polkadot-asset-hub.ts](./examples/sign-polkadot-asset-hub.ts)

### Resharing MPC Keys

Resharing allows you to change the threshold and/or participants in an MPC wallet without exposing the private key. This is useful for:

- Adding or removing participants from a wallet
- Changing the threshold (e.g., from 2-of-3 to 3-of-5)
- Key rotation for security purposes

#### Resharing an Ethereum Wallet

```ts
import { connect } from "nats";
import { MpciumClient, KeyType } from "@fystack/mpcium-ts";
import fs from "fs";

async function reshareEthereumWallet(walletId: string) {
  const nc = await connect({ servers: "nats://localhost:4222" });
  const mpcClient = await MpciumClient.create({
    nc: nc,
    keyPath: "./event_initiator.key",
  });

  // Listen for resharing results
  mpcClient.onResharingResult((event) => {
    console.log("Resharing result:", event);

    if (event.result_type === "success") {
      // Update wallet with new public key
      const wallets = JSON.parse(fs.readFileSync("./wallets.json", "utf8"));
      wallets[walletId].ecdsa_pub_key = event.pub_key;
      wallets[walletId].reshared = true;
      wallets[walletId].new_threshold = event.new_threshold;

      fs.writeFileSync("./wallets.json", JSON.stringify(wallets, null, 2));
      console.log("Wallet updated with new reshared key");
    }
  });

  // Initiate resharing with new node configuration
  const sessionId = await mpcClient.reshareKeys({
    walletId: walletId,
    nodeIds: ["node0", "node1", "node2", "node3"], // Add new node
    newThreshold: 3, // Change from 2-of-3 to 3-of-4
    keyType: KeyType.Secp256k1,
  });

  console.log(`Resharing initiated with session ID: ${sessionId}`);
}
```

#### Resharing a Solana Wallet

```ts
// Similar to Ethereum but using Ed25519 keys
const sessionId = await mpcClient.reshareKeys({
  walletId: walletId,
  nodeIds: ["node0", "node1", "node2"],
  newThreshold: 2,
  keyType: KeyType.Ed25519,
});
```

[Full examples: reshare-eth.ts](./examples/reshare-eth.ts) | [reshare-solana.ts](./examples/reshare-solana.ts)

## Tests

### 1. Generate an MPC wallet

```
npx ts-node ./examples/generate-wallet.ts
```

```
Connected to NATS at localhost:4222
Subscribed to wallet creation results
CreateWallet request sent for wallet: a99900b2-0ef8-4d7e-8c3f-2ef85abbae4c
CreateWallet sent, awaiting result... walletID: a99900b2-0ef8-4d7e-8c3f-2ef85abbae4c
Received wallet creation result: {
  wallet_id: 'a99900b2-0ef8-4d7e-8c3f-2ef85abbae4c',
  ecdsa_pub_key: '1ftOqTd9z540F7J6bSLJJ8gqn85HlyQKetWB4mACDFBhaodgiNr9ILL5wZ95yWpaqQc77f02rQklUeDSZhLVVA==',
  eddsa_pub_key: 'm0qUKZlxmzgYA9sRh1Q7cQJHT8jEdUQjbic8hQNHG2o='
}
Solana wallet address: BTC9kvDchPvu84iMzLbhYBg5bWma4QHDAFumpF41ErjT
Ethereum wallet address: 0x309bdE4d218e44E4a391f4c43Bf6226156D3255b
Wallet saved to wallets.json with ID: a99900b2-0ef8-4d7e-8c3f-2ef85abbae4c

```

### 2. Transfer Solana to the wallet

- Use Phantom to transfer SOL from devnet to the wallet

###

### 3. Sign a Solana transaction

```
npx ts-node ./examples/sign-solana.ts a99900b2-0ef8-4d7e-8c3f-2ef85abbae4c
```

### 4. Sign an Ethereum transaction

```
npx ts-node ./examples/sign-eth.ts a99900b2-0ef8-4d7e-8c3f-2ef85abbae4c
```

### 5. Sign a Polkadot transaction (Native Token Transfer)

```
npx ts-node ./examples/sign-polkadot.ts a99900b2-0ef8-4d7e-8c3f-2ef85abbae4c
```

### 6. Sign an Asset Hub transaction (Asset Transfer)

```
npx ts-node ./examples/sign-polkadot-asset-hub.ts a99900b2-0ef8-4d7e-8c3f-2ef85abbae4c 1984
```
