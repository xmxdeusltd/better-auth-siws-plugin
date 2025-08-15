# better-auth-web3

Web3 (EVM + Solana) plugin for Better Auth. Provides a secure, nonce-based wallet login flow that integrates with Better Auth sessions and cookies.

- Server plugin: `better-auth-web3`
- Client plugin: `better-auth-web3/client`
- Requires `better-auth >= 1.3.5`

## Features

- Nonce-based SIWE/SIWS-style verification
- Server-side wallet ownership checks (EVM and Solana)
- Sign-in/up on verify; link additional wallets with dedicated endpoints
- Optional ENS/SNS lookups to derive default name/email
- Sets Better Auth session and cookies on success

## Installation

```bash
# npm
npm install better-auth-web3 better-auth

# pnpm
pnpm add better-auth-web3 better-auth

# yarn
yarn add better-auth-web3 better-auth
```

## Endpoints

- POST `/web3/nonce`

  - Body: `{ walletAddress: string, type: "svm" | "evm", value: number | "mainnet-beta" | "devnet" | "testnet" }`
  - For `evm`, set `value` = `chainId` (number). For `svm`, set `value` = `cluster` (string).
  - Response: `{ nonce: string }`
  - Stores a short‑lived nonce bound to `type`, `walletAddress`, and `value`.

- POST `/web3/svm/verify`

  - Headers: must include `Origin` whose domain matches `options.domain`.
  - Body: `{ message: string, signature: string, walletAddress: string, cluster?: "mainnet-beta" | "devnet" | "testnet", email?: string }`
  - Verifies signature; signs in existing user or creates a new one. Issues session and sets cookies. Does not link to an already signed-in user.
  - Response: `{ token: string, success: boolean, user: { id: string, walletAddress: string } }`
  - Errors: `400` invalid domain or missing email when `anonymous=false`; `401` invalid/expired nonce or signature; `500` internal error.

- POST `/web3/svm/link`

  - Requires active session; `Origin` domain must match.
  - Body: `{ message: string, signature: string, walletAddress: string, cluster?: "mainnet-beta" | "devnet" | "testnet" }`
  - Links the Solana wallet to the current user. When `allowMultipleWalletsPerChain=false` (default), only one Solana wallet total is allowed; first linked is primary.
  - Response: `{ success: true }`
  - Errors: `400` already linked, linked to another user, or multiple wallets not allowed; `401` invalid/expired nonce.

- POST `/web3/evm/verify`

  - Headers: must include `Origin` whose domain matches `options.domain`.
  - Body: `{ message: string, signature: string, walletAddress: string, chainId?: number, email?: string }` (default `chainId=1`)
  - Verifies signature (checksummed address); signs in existing user or creates a new one. Issues session and sets cookies.
  - Response: `{ token: string, success: boolean, user: { id: string, walletAddress: string, chainId: number } }`
  - Rules: if `allowMultipleWalletsPerChain=false`, a user cannot have different EVM addresses on the same `chainId`; the same address across different chains is allowed.
  - Errors: `400` invalid domain or missing email when `anonymous=false`; `401` invalid/expired nonce or signature; `500` internal error.

- POST `/web3/evm/link`
  - Requires active session; `Origin` domain must match.
  - Body: `{ message: string, signature: string, walletAddress: string, chainId?: number }` (default `chainId=1`)
  - Links the EVM address on the specified `chainId` to the current user; primary is the first address on that chain.
  - Response: `{ success: true }`
  - Errors: `400` already linked, linked to another user, or different address on same chain not allowed; `401` invalid/expired nonce.

## Options

```ts
export interface Web3PluginOptions {
  domain: string;
  emailDomainName?: string; // default: domain - will be used to form an email if no email is provided and anonymous=false and no ens/sns lookup is provided
  anonymous?: boolean; // default: true
  allowMultipleWalletsPerChain?: boolean; // default: false

  getNonce: () => Promise<string>;
  verifyEVMMessage?: (args: {
    message: string;
    signature: string;
    address: string; // checksummed
    chainId: number;
    cacao?: {
      h: { t: "caip122" };
      p: {
        domain: string;
        aud: string;
        nonce: string;
        iss: string;
        version?: string;
      };
      s: { t: "eip191" | "eip1271"; s: string; m?: string };
    };
  }) => Promise<boolean>;
  ensLookup?: (args: {
    walletAddress: string;
  }) => Promise<{ name: string; avatar: string }>;

  verifySVMMessage?: (args: {
    message: string;
    signature: string;
    address: string;
    nonce: string;
    domain: string;
    cluster?: "mainnet-beta" | "devnet" | "testnet";
  }) => Promise<boolean>;
  snsLookup?: (args: { walletAddress: string }) => Promise<{ name: string }>;
}
```

Behavior rules:

- If `anonymous=true` (default), new users may be created without email; `emailDomainName ?? domain` is used with ENS/SNS or a shortened address to form an email.
- If `anonymous=false` and there is no active session, `email` is required in `verify` bodies.
- Always call `/web3/nonce` first; the returned nonce must be reflected in the signed message. Nonces are bound to `type`, `walletAddress`, and `value` (chainId/cluster) and expire in ~15 minutes.

## Data model (schema)

Creates a `walletAddress` model with fields:

- `userId` (ref `user.id`), `accountId` (ref `account.id`), `type` ("svm" | "evm"), `address`, `chainId` (number | null), `isPrimary` (boolean), `createdAt` (date)

## License

MIT
