/**
 * SIWS Plugin Type Definitions
 */

export interface WalletAddress {
  id: string;
  userId: string;
  address: string;
  type: "svm" | "evm";
  chainId: number | null;
  isPrimary: boolean;
  createdAt: Date;
}

interface CacaoHeader {
  t: "caip122";
}

// Signed Cacao (CAIP-74)
interface CacaoPayload {
  domain: string;
  aud: string;
  nonce: string;
  iss: string;
  version?: string;
  iat?: string;
  nbf?: string;
  exp?: string;
  statement?: string;
  requestId?: string;
  resources?: string[];
  type?: string;
}

interface Cacao {
  h: CacaoHeader;
  p: CacaoPayload;
  s: {
    t: "eip191" | "eip1271";
    s: string;
    m?: string;
  };
}

export interface EVMVerifyMessageArgs {
  message: string;
  signature: string;
  address: string;
  chainId: number;
  cacao?: Cacao;
}

export interface SVMVerifyMessageArgs {
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

export interface ENSLookupArgs {
  walletAddress: string;
}

export interface ENSLookupResult {
  name: string;
  avatar: string;
}

export interface SNSLookupArgs {
  walletAddress: string;
}

export interface SNSLookupResult {
  name: string;
}
