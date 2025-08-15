/**
 * SIWS Plugin Type Definitions
 */

export interface WalletAddress {
  id: string;
  userId: string;
  address: string;
  isPrimary: boolean;
  createdAt: Date;
}

export interface SIWSVerifyMessageArgs {
  message: string;
  signature: string;
  address: string;
  /**
   * The server-issued nonce that must be present in the signed message.
   * Passing it allows the verifier to strictly compare against stored value.
   */
  nonce: string;
  /**
   * The relying party domain this login is for. Should be bound in the message to
   * prevent origin/audience confusion.
   */
  domain: string;
  /**
   * Solana cluster context used for the signature (e.g., "mainnet-beta", "devnet", "testnet").
   * Helps prevent cross-environment replay.
   */
  cluster?: string;
}

export interface SNSLookupArgs {
  walletAddress: string;
}

export interface SNSLookupResult {
  name: string;
}
