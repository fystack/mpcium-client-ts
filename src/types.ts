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
  clientID?: string;
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

export interface KeygenResultEvent {
  wallet_id: string;
  ecdsa_pub_key?: string;
  eddsa_pub_key?: string;
  result_type?: string;
  error_reason?:string;
  error_code?:string;
}

export enum SigningResultType {
  Unknown = 0,
  Success = "success",
  Error = "error",
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
  error_reason?: string;
}

export interface ResharingMessage {
  session_id: string;
  node_ids: string[];
  new_threshold: number;
  key_type: KeyType;
  wallet_id: string;
  signature?: string;
}

export interface ResharingResultEvent {
  result_type: "success" | "error";
  wallet_id: string;
  session_id?: string;
  pub_key?: string;
  new_threshold: number;
  key_type: KeyType;
  error_code?: string;
  error_reason?: string;
}
