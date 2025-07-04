import { connect } from "nats";
import { KeygenSuccessEvent, MpciumClient } from "../src";
import { computeAddress, hexlify } from "ethers";
import base58 from "bs58";
import * as fs from "fs";
import * as path from "path";

async function main() {
  // First, establish NATS connection separately
  const nc = await connect({ servers: "nats://localhost:4222" }).catch(
    (err) => {
      console.error(`Failed to connect to NATS: ${err.message}`);
      process.exit(1);
    }
  );
  console.log(`Connected to NATS at ${nc.getServer()}`);

  // Create client with key path
  const mpcClient = await MpciumClient.create({
    nc: nc,
    keyPath: "./event_initiator.key",
    // password: "your-password-here", // Required for .age encrypted keys
  });

  try {
    // Subscribe to wallet creation results
    mpcClient.onWalletCreationResult((event: KeygenSuccessEvent) => {
      console.log("Received wallet creation result:", event);

      if (event.eddsa_pub_key) {
        const pubKeyBytes = Buffer.from(event.eddsa_pub_key, "base64");
        const solanaAddress = base58.encode(pubKeyBytes);
        console.log(`Solana wallet address: ${solanaAddress}`);
      }

      if (event.ecdsa_pub_key) {
        const pubKeyBytes = Buffer.from(event.ecdsa_pub_key, "base64");

        const uncompressedKey =
          pubKeyBytes.length === 65
            ? pubKeyBytes
            : Buffer.concat([Buffer.from([0x04]), pubKeyBytes]);

        const pubKeyHex = hexlify(uncompressedKey);
        const ethAddress = computeAddress(pubKeyHex);

        console.log(`Ethereum wallet address: ${ethAddress}`);
      }
      
      // Save the event to wallets.json with wallet_id as the key
      const walletsPath = path.resolve("./wallets.json");
      let wallets: Record<string, KeygenSuccessEvent> = {};
      
      // Read existing wallets file if it exists
      try {
        if (fs.existsSync(walletsPath)) {
          wallets = JSON.parse(fs.readFileSync(walletsPath, "utf8"));
        }
      } catch (error) {
        console.warn(`Could not read wallets file: ${error.message}`);
      }
      
      // Add the new wallet
      wallets[event.wallet_id] = event;
      
      // Write back to file
      fs.writeFileSync(walletsPath, JSON.stringify(wallets, null, 2));
      console.log(`Wallet saved to wallets.json with ID: ${event.wallet_id}`);
    });

    // Create a new wallet
    const walletID = await mpcClient.createWallet();
    console.log(`CreateWallet sent, awaiting result... walletID: ${walletID}`);

    // Keep the process running to receive the result
    process.on("SIGINT", async () => {
      console.log("Shutting down...");
      await mpcClient.cleanup();
      await nc.drain();
      process.exit(0);
    });
  } catch (error) {
    console.error("Error:", error);
    await mpcClient.cleanup();
    await nc.drain();
    process.exit(1);
  }
}

// Run the example
main().catch(console.error);
