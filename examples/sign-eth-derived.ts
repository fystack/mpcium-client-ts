/**
 * Example: HD Wallet Signing with derivation_path
 *
 * Usage:
 *   npx ts-node examples/sign-eth-derived.ts <wallet-id> [child-index]
 */

import { connect } from "nats";
import {
  MpciumClient,
  KeyType,
  SigningResultEvent,
  deriveEthereumAddress,
  compressPublicKey,
} from "../src";
import { SigningResultType } from "../src/types";
import { ethers } from "ethers";
import * as fs from "fs";
import * as path from "path";

const walletId = process.argv[2];
const childIndex = parseInt(process.argv[3] || "0", 10);

if (!walletId) {
  console.error(
    "Usage: npx ts-node examples/sign-eth-derived.ts <wallet-id> [child-index]"
  );
  process.exit(1);
}

// Non-hardened BIP-44 path: m/44/60/0/0/<childIndex>
const DERIVATION_PATH = [44, 60, 0, 0, childIndex];

const DESTINATION_WALLET = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e";
const AMOUNT_TO_SEND = "0.0001"; // ETH

function loadWallet(walletId: string) {
  const walletsPath = path.resolve("./wallets.json");
  try {
    if (fs.existsSync(walletsPath)) {
      const wallets = JSON.parse(fs.readFileSync(walletsPath, "utf8"));
      if (wallets[walletId]) {
        return wallets[walletId];
      }
      throw new Error(`Wallet with ID ${walletId} not found in wallets.json`);
    } else {
      throw new Error("wallets.json file not found");
    }
  } catch (error) {
    console.error(`Failed to load wallet: ${error.message}`);
    process.exit(1);
  }
}

async function main() {
  console.log(`Using wallet ID: ${walletId}`);

  const wallet = loadWallet(walletId);

  if (!wallet.ecdsa_pub_key) {
    throw new Error("Wallet has no ECDSA public key");
  }

  if (!wallet.chain_code) {
    throw new Error(
      "Wallet has no chain_code. Make sure your MPC nodes support CKD " +
        "and that wallets.json includes the chain_code field from DKG."
    );
  }

  // Compress master public key if needed (DKG may return 64/65-byte uncompressed)
  const masterPubRaw = new Uint8Array(
    Buffer.from(wallet.ecdsa_pub_key, "base64")
  );
  const masterPubCompressed =
    masterPubRaw.length === 33
      ? masterPubRaw
      : compressPublicKey(masterPubRaw);

  // Derive child address locally — MPC nodes will derive the same child key
  const childAddress = deriveEthereumAddress(
    masterPubCompressed,
    wallet.chain_code,
    DERIVATION_PATH
  );

  console.log(`Derivation path  : m/${DERIVATION_PATH.join("/")}`);
  console.log(`Child address    : ${childAddress}`);

  const nc = await connect({ servers: "nats://localhost:4222" }).catch(
    (err) => {
      console.error(`Failed to connect to NATS: ${err.message}`);
      process.exit(1);
    }
  );
  console.log(`Connected to NATS at ${nc.getServer()}`);

  const mpcClient = await MpciumClient.create({
    nc,
    keyPath: "./event_initiator.key",
    // password: "your-password-here", // Required for .age encrypted keys
  });

  try {
    const provider = new ethers.JsonRpcProvider(
      "https://eth-sepolia.public.blastapi.io"
    );
    console.log("Connected to Ethereum Sepolia testnet");

    console.log(`Sender (derived): ${childAddress}`);
    console.log(`Destination: ${DESTINATION_WALLET}`);
    console.log(`Amount: ${AMOUNT_TO_SEND} ETH`);

    const nonce = await provider.getTransactionCount(childAddress);
    const feeData = await provider.getFeeData();

    const transaction = {
      to: DESTINATION_WALLET,
      value: ethers.parseEther(AMOUNT_TO_SEND),
      gasLimit: 21000,
      maxFeePerGas: feeData.maxFeePerGas,
      maxPriorityFeePerGas: feeData.maxPriorityFeePerGas,
      nonce,
      type: 2, // EIP-1559
      chainId: 11155111, // Sepolia
    };

    const unsignedTx = ethers.Transaction.from(transaction);
    const txHash = unsignedTx.unsignedHash;
    const txHashHex = txHash.substring(2);

    console.log(`Transaction hash: ${txHash}`);

    // Subscribe to signing results
    let signatureReceived = false;

    mpcClient.onSignResult((event: SigningResultEvent) => {
      console.log("Received signing result:", event);
      signatureReceived = true;

      if (event.result_type !== SigningResultType.Success) {
        console.error(`Signing failed: ${event.error_reason}`);
        return;
      }

      try {
        const r = "0x" + Buffer.from(event.r, "base64").toString("hex");
        const s = "0x" + Buffer.from(event.s, "base64").toString("hex");
        const v = Buffer.from(event.signature_recovery, "base64")[0];

        const signedTx = ethers.Transaction.from({
          ...transaction,
          signature: { r, s, v },
        });

        // Verify recovered signer matches the derived child address
        const recoveredAddress = signedTx.from;
        console.log(`Recovered signer: ${recoveredAddress}`);

        if (
          recoveredAddress?.toLowerCase() !== childAddress.toLowerCase()
        ) {
          console.error("Signature verification failed! Addresses don't match.");
          return;
        }

        console.log("Signature verification successful!");

        provider
          .broadcastTransaction(signedTx.serialized)
          .then((tx) => {
            console.log(`Transaction sent! Transaction hash: ${tx.hash}`);
            console.log(
              `View transaction: https://sepolia.etherscan.io/tx/${tx.hash}`
            );
          })
          .catch((err) => console.error("Error broadcasting transaction:", err));
      } catch (error) {
        console.error("Error processing signature:", error);
      }
    });

    // Send signing request with derivationPath for HD child key signing
    const txId = await mpcClient.signTransaction({
      walletId: walletId,
      keyType: KeyType.Secp256k1,
      networkInternalCode: "ethereum:sepolia",
      tx: Buffer.from(txHashHex, "hex").toString("base64"),
      derivationPath: DERIVATION_PATH,
    });

    console.log(`Signing request sent with txID: ${txId}`);

    // Wait for the result
    await new Promise<void>((resolve) => {
      const checkInterval = setInterval(() => {
        if (signatureReceived) {
          clearInterval(checkInterval);
          resolve();
        }
      }, 1000);
    });

    // Keep the process running to allow time for transaction confirmation
    await new Promise((r) => setTimeout(r, 5000));

    console.log("Cleaning up...");
    await mpcClient.cleanup();
    await nc.drain();
  } catch (error) {
    console.error("Error:", error);
    await mpcClient.cleanup();
    await nc.drain();
    process.exit(1);
  }
}

main().catch(console.error);
