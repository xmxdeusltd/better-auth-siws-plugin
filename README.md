# better-auth-siws-plugin

Sign in With Solana (SIWS) plugin for Better Auth. It adds a simple, secure wallet-based login flow that integrates seamlessly with Better Auth’s session and cookie system.

- Server plugin: `better-auth-siws-plugin`
- Client plugin: `better-auth-siws-plugin/client`
- Requires `better-auth >= 1.3.5`

## Features

- Nonce-based message signing flow
- Verifies wallet ownership server-side
- Signs in existing users or creates new users on first verification; linking additional wallets is handled via `POST /siws/link`
- Optional SNS reverse lookup to derive a friendly default email/name
- Supports linking multiple wallets per user (opt-in)
- Sets Better Auth session and cookies on success

## Installation

```bash
# npm
npm install better-auth-siws-plugin better-auth

# pnpm
pnpm add better-auth-siws-plugin better-auth

# yarn
yarn add better-auth-siws-plugin better-auth
```

## Quickstart

### 1) Server: register the plugin

```ts
// auth.ts (or your Better Auth init file)
import { auth } from "better-auth";
import { siws } from "better-auth-siws-plugin";

export const { handleRequest } = auth({
  baseURL: "https://example.com",
  plugins: [
    siws({
      domain: "example.com",
      anonymous: true,
      allowMultipleWallets: false,
      getNonce: async () => crypto.randomUUID(),
      verifyMessage: async ({
        message,
        signature,
        address,
        nonce,
        domain,
        cluster,
      }) => {
        // Verify SIWS signature (example using TweetNaCl + base58)
        // This should be your actual verification logic
        try {
          const nacl = await import("tweetnacl");
          const bs58 = (await import("bs58")).default;
          const sigBytes = bs58.decode(signature);
          const pubKeyBytes = bs58.decode(address);
          const msgBytes = new TextEncoder().encode(message);
          return nacl.sign.detached.verify(msgBytes, sigBytes, pubKeyBytes);
        } catch {
          return false;
        }
      },
      snsLookup: async ({ walletAddress }) => {
        // Optional: resolve SNS name (return { name: string } or omit)
        return { name: undefined as unknown as string };
      },
    }),
  ],
});
```

### 2) Client: register the plugin

```ts
// client.ts
import { createAuthClient } from "better-auth/react";
import { siwsClient } from "better-auth-siws-plugin/client";

export const authClient = createAuthClient({
  baseURL: "/api/auth",
  plugins: [siwsClient()],
});
```

### 3) Client flow: sign-in/sign-up (does NOT link wallets)

```ts
// Example usage on client
import bs58 from "bs58";
import { authClient } from "./client";

export const handleSiwsLogin = async (wallet: {
  // Use whatever wallet interface you rely on (e.g. wallet adapter)
  publicKey: { toBase58(): string };
  signMessage: (message: Uint8Array) => Promise<Uint8Array>;
}) => {
  const walletAddress = wallet.publicKey.toBase58();

  // 1) Get nonce (optionally pass a cluster, defaults to "mainnet-beta")
  const { nonce } = await authClient.call("/siws/nonce", {
    method: "POST",
    body: { walletAddress, cluster: "mainnet-beta" },
  });

  // 2) Compose message & sign
  const message = `Sign in with Solana\n\nNonce: ${nonce}`;
  const encoded = new TextEncoder().encode(message);
  const signature = await wallet.signMessage(encoded);

  // 3) Verify (signs in if user exists, or creates user otherwise). Does NOT link wallets.
  const { success, user, token } = await authClient.call("/siws/verify", {
    method: "POST",
    body: {
      message,
      signature: bs58.encode(signature),
      walletAddress,
      cluster: "mainnet-beta",
      // email: optional, required if anonymous=false and user not signed-in
    },
  });

  return { success, user, token };
};
```

### 4) Client flow: link wallet for a signed-in user

```ts
// Example usage on client (user must already be signed-in)
import bs58 from "bs58";
import { authClient } from "./client";

export const handleLinkWallet = async (wallet: {
  publicKey: { toBase58(): string };
  signMessage: (message: Uint8Array) => Promise<Uint8Array>;
}) => {
  const walletAddress = wallet.publicKey.toBase58();

  // 1) Get nonce (bound to wallet + cluster)
  const { nonce } = await authClient.call("/siws/nonce", {
    method: "POST",
    body: { walletAddress, cluster: "mainnet-beta" },
  });

  // 2) Compose message & sign
  const message = `Link Solana wallet\n\nNonce: ${nonce}`;
  const encoded = new TextEncoder().encode(message);
  const signature = await wallet.signMessage(encoded);

  // 3) Link wallet to the currently signed-in user
  const { success } = await authClient.call("/siws/link", {
    method: "POST",
    body: {
      message,
      signature: bs58.encode(signature),
      walletAddress,
      cluster: "mainnet-beta",
    },
  });

  return { success };
};
```

## Endpoints

- POST `/siws/nonce`

  - Body: `{ walletAddress: string, cluster?: "mainnet-beta" | "devnet" | "testnet" }`
  - Response: `{ nonce: string }`
  - Stores a short-lived nonce bound to the wallet address and cluster

- POST `/siws/verify`

  - Body: `{ message: string, signature: string, walletAddress: string, cluster?: "mainnet-beta" | "devnet" | "testnet", email?: string }`
  - Verifies signature; signs in existing user by wallet, or creates a new user if wallet is unknown. Issues session and sets cookies.
  - Does NOT link wallets to the currently signed-in user. Use `POST /siws/link` for linking.
  - Response: `{ token: string, success: boolean, user: { id: string, walletAddress: string } }`
  - Errors:
    - 400: missing required fields (e.g., `email` when `anonymous=false`)
    - 401: invalid/expired nonce, invalid signature, generic unauthorized
    - 500: internal server error

- POST `/siws/link`
  - Requires active session
  - Body: `{ message: string, signature: string, walletAddress: string, cluster?: "mainnet-beta" | "devnet" | "testnet" }`
  - Verifies signature and links the wallet to the currently signed-in user (subject to `allowMultipleWallets`).
  - Response: `{ success: boolean }`
  - Errors:
    - 400: wallet already linked to this user, wallet belongs to another user, or multiple wallets not allowed
    - 401: invalid/expired nonce, invalid signature

## Options

```ts
export interface SIWSPluginOptions {
  domain: string; // Used for default email domain when anonymous=true
  emailDomainName?: string; // Override domain used in generated email
  anonymous?: boolean; // Allow creating users without email (default: true)
  allowMultipleWallets?: boolean; // Allow linking multiple wallets to a signed-in user (default: false)

  getNonce: () => Promise<string>; // Generate a nonce (unique per request)
  verifyMessage: (args: {
    message: string;
    signature: string;
    address: string;
    nonce: string;
    domain: string;
    cluster?: "mainnet-beta" | "devnet" | "testnet";
  }) => Promise<boolean>; // Implement signature verification

  snsLookup?: (args: { walletAddress: string }) => Promise<{ name: string }>;
}
```

Behavior details:

- If `anonymous` is true (default), the plugin can create a new user without an email. It will use SNS name or wallet address to construct a default email like `name@domain` or `wallet@domain`.
- If `anonymous` is false and there is no active session, `email` is required in `/siws/verify` body.
- `/siws/verify` is for sign-in/sign-up only. It does not link wallets to the currently signed-in user.
- Linking additional wallets for a signed-in user is done via `/siws/link` and is subject to `allowMultipleWallets`.
- If the wallet is already linked to a different user, `/siws/link` returns 400.

## Data model (schema)

The plugin brings its own schema definition for a `walletAddressSol` model/table:

- `userId`: string (reference to Better Auth `user.id`)
- `address`: string (wallet address)
- `isPrimary`: boolean (first address becomes primary)
- `createdAt`: date

If you manage your own DB migrations, add a table/model. Example Prisma:

```prisma
model WalletAddressSol {
  id         String   @id @default(cuid())
  userId     String
  user       User     @relation(fields: [userId], references: [id], onDelete: Cascade)
  address    String   @unique
  isPrimary  Boolean  @default(false)
  createdAt  DateTime @default(now())

  @@map("walletAddressSol")
}
```

## License

MIT
