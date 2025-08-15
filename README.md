# better-auth-siws-plugin

Sign in With Solana (SIWS) plugin for Better Auth. It adds a simple, secure wallet-based login flow that integrates seamlessly with Better Auth’s session and cookie system.

- Server plugin: `better-auth-siws-plugin`
- Client plugin: `better-auth-siws-plugin/client`
- Requires `better-auth >= 1.3.7-beta.1`

## Features

- Nonce-based message signing flow
- Verifies wallet ownership server-side
- Creates/links user accounts to Solana wallet addresses
- Optional SNS reverse lookup to derive a friendly default email/name
- Supports linking multiple wallets per user (opt-in)
- Sets Better Auth session and cookies on success

## Installation

```bash
# npm
npm install better-auth-siws-plugin better-auth zod

# pnpm
pnpm add better-auth-siws-plugin better-auth zod

# yarn
yarn add better-auth-siws-plugin better-auth zod
```

Peer deps:

- better-auth: >= 1.3.7-beta.1
- zod: ^3.25.0 || ^4.0.0

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
      verifyMessage: async ({ message, signature, address }) => {
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

### 3) Client flow: get nonce → sign → verify

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

  // 1) Get nonce
  const { nonce } = await authClient.call("/siws/nonce", {
    method: "POST",
    body: { walletAddress },
  });

  // 2) Compose message & sign
  const message = `Sign in with Solana\n\nNonce: ${nonce}`;
  const encoded = new TextEncoder().encode(message);
  const signature = await wallet.signMessage(encoded);

  // 3) Verify (creates/links user and sets session cookie on success)
  const { success, user, token } = await authClient.call("/siws/verify", {
    method: "POST",
    body: {
      message,
      signature: bs58.encode(signature),
      walletAddress,
      // email: optional, required if anonymous=false and user not signed-in
    },
  });

  return { success, user, token };
};
```

## Endpoints

- POST `/siws/nonce`

  - Body: `{ walletAddress: string }`
  - Response: `{ nonce: string }`
  - Stores a short-lived nonce bound to the wallet address

- POST `/siws/verify`
  - Body: `{ message: string, signature: string, walletAddress: string, email?: string }`
  - Verifies signature, creates or links user, issues session, sets cookies
  - Response: `{ token: string, success: boolean, user: { id: string, walletAddress: string } }`
  - Errors:
    - 400: missing required fields, wallet linked to another user, or multiple wallets disallowed
    - 401: invalid/expired nonce, invalid signature, generic unauthorized
    - 500: internal server error

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
  }) => Promise<boolean>; // Implement signature verification

  snsLookup?: (args: { walletAddress: string }) => Promise<{ name: string }>;
}
```

Behavior details:

- If `anonymous` is true (default), the plugin can create a new user without an email. It will use SNS name or wallet address to construct a default email like `name@domain` or `wallet@domain`.
- If `anonymous` is false and there is no active session, `email` is required in `/siws/verify` body.
- If a signed-in user verifies a new wallet and `allowMultipleWallets` is false, it raises 400.
- If the wallet is already linked to a different user, it raises 400.

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
}
```

Example Drizzle (Postgres):

```ts
import { pgTable, text, boolean, timestamp } from "drizzle-orm/pg-core";

export const walletAddressSol = pgTable("wallet_address_sol", {
  id: text("id").primaryKey().defaultRandom(), // or your ID strategy
  userId: text("user_id").notNull(),
  address: text("address").notNull().unique(),
  isPrimary: boolean("is_primary").notNull().default(false),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});
```

Note: Better Auth’s adapter can create/manage the schema dynamically, but if you also consume the DB directly you will want a matching model for type-safety and migrations.

## Security considerations

- Always bind nonces to a specific wallet address and expire them quickly (≤15 minutes).
- Do not reuse nonces; delete them after a successful verification.
- Verify signatures using robust, well-reviewed libraries (`tweetnacl`, `@solana/web3.js`, etc.).
- Prefer base58 for signatures and addresses to match Solana ecosystem norms.
- Consider rate-limiting the `/siws/nonce` and `/siws/verify` endpoints.

## Error codes

- `UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE`
- `UNAUTHORIZED` (invalid signature, generic unauthorized)
- `BAD_REQUEST` (wallet linked to another user, multiple wallets not allowed)
- `INTERNAL_SERVER_ERROR`

## Framework notes

- Next.js: Place Better Auth’s handler under `/api/auth` and use `baseURL: "/api/auth"` on the client.
- Hono/Express/Fastify: Mount Better Auth at a path (e.g. `/auth`) and point client `baseURL` accordingly.
- SSR: The plugin sets session cookies; standard Better Auth session retrieval still applies.

## Type references

- Server plugin returns `BetterAuthPlugin`-compatible object with `id: "siws"`.
- Client plugin uses `BetterAuthClientPlugin` and `$InferServerPlugin` to wire types for endpoint calls.

## Contributing

PRs and issues are welcome. If you’re adding verification helpers or new wallet-linking strategies, include tests and docs.

## License

MIT
