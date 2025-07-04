import { NatsConnection } from "nats";

export enum KeyType {
  Secp256k1 = "secp256k1",
  Ed25519 = "ed25519",
}

export interface MpciumOptions {
  nc: NatsConnection;
  keyPath: string;
  password?: string; // Optional password for encrypted keys
  encrypted?: boolean; // Explicitly specify if key is encrypted
}

export interface GenerateKeyMessage {
  wallet_id: string;
  signature?: string;
}

export interface SignTxMessage {
  key_type: KeyType;
  wallet_id: string;
  network_internal_code: string;
  tx_id: string;
  tx: string;
  signature?: string;
}

export interface KeygenSuccessEvent {
  wallet_id: string;
  ecdsa_pub_key?: string;
  eddsa_pub_key?: string;
}

export enum SigningResultType {
  Unknown = 0,
  Success = 1,
  Error = 2,
}

export interface SigningResultEvent {
  wallet_id: string;
  tx_id: string;
  network_internal_code: string;
  r: string;
  s: string;
  signature_recovery: string;
  signature: string;
  result_type: SigningResultType;
  error_message?: string;
}
