import {
  APIError,
  createAuthEndpoint,
  createAuthMiddleware,
  getSessionFromCtx,
} from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import { z } from "zod";
import type { BetterAuthPlugin } from "better-auth/types";
import type {
  SNSLookupArgs,
  SNSLookupResult,
  SIWSVerifyMessageArgs,
  WalletAddress,
} from "./types";
import type { User } from "better-auth/types";
import { schema } from "./schema";
import { getDomain } from "./util";

export interface SIWSPluginOptions {
  domain: string;
  emailDomainName?: string;
  anonymous?: boolean;
  allowMultipleWallets?: boolean; // false by default
  getNonce: () => Promise<string>;
  verifyMessage: (args: SIWSVerifyMessageArgs) => Promise<boolean>;
  snsLookup?: (args: SNSLookupArgs) => Promise<SNSLookupResult>;
}

const walletAddressRegex = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

export const siws = (options: SIWSPluginOptions) => {
  const siwsMiddleware = createAuthMiddleware(async (ctx) => {
    const session = await getSessionFromCtx(ctx);
    if (!session) {
      throw new APIError("UNAUTHORIZED");
    }
    return {
      session,
    };
  });

  return {
    id: "siws",
    schema,
    endpoints: {
      getSiwsNonce: createAuthEndpoint(
        "/siws/nonce",
        {
          method: "POST",
          body: z.object({
            walletAddress: z.string().regex(walletAddressRegex),
            // Bind nonce to cluster to avoid cross-environment replay
            cluster: z
              .enum(["mainnet-beta", "devnet", "testnet"]) // common Solana clusters
              .optional()
              .default("mainnet-beta"),
          }),
        },
        async (ctx) => {
          const { walletAddress, cluster } = ctx.body;
          const nonce = await options.getNonce();

          // Store nonce with wallet address and cluster context
          await ctx.context.internalAdapter.createVerificationValue({
            identifier: `siws:${walletAddress}:${cluster}`,
            value: nonce,
            expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
          });

          return ctx.json({ nonce });
        }
      ),
      verifySiwsMessage: createAuthEndpoint(
        "/siws/verify",
        {
          method: "POST",
          body: z
            .object({
              message: z.string().min(1),
              signature: z.string().min(1),
              walletAddress: z
                .string()
                .regex(walletAddressRegex)
                .min(32)
                .max(44),
              cluster: z
                .enum(["mainnet-beta", "devnet", "testnet"]) // match issuance
                .optional()
                .default("mainnet-beta"),
              email: z.string().email().optional(),
            })
            .refine((data) => options.anonymous !== false || !!data.email, {
              message:
                "Email is required when the anonymous plugin option is disabled.",
              path: ["email"],
            }),
          requireHeaders: true,
          requireRequest: true,
        },
        async (ctx) => {
          const { message, signature, walletAddress, cluster, email } =
            ctx.body;
          const domain = getDomain(ctx.headers.get("origin") ?? "");
          const isAnon = options.anonymous ?? true;

          if (!domain || domain !== options.domain) {
            throw new APIError("BAD_REQUEST", {
              message: "Domain is required.",
              status: 400,
            });
          }

          if (!isAnon && !email) {
            throw new APIError("BAD_REQUEST", {
              message: "Email is required when anonymous is disabled.",
              status: 400,
            });
          }

          try {
            // Find stored nonce bound to wallet address and cluster
            const verification =
              await ctx.context.internalAdapter.findVerificationValue(
                `siws:${walletAddress}:${cluster}`
              );

            // Ensure nonce is valid and not expired
            if (!verification || new Date() > verification.expiresAt) {
              throw new APIError("UNAUTHORIZED", {
                message: "Unauthorized: Invalid or expired nonce",
                status: 401,
                code: "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE",
              });
            }

            // Verify SIWS message against stored nonce and domain
            const { value: nonce } = verification;
            const verified = await options.verifyMessage({
              message,
              signature,
              address: walletAddress,
              nonce,
              domain,
              cluster,
            });

            if (!verified) {
              throw new APIError("UNAUTHORIZED", {
                message: "Unauthorized: Invalid SIWS signature",
                status: 401,
              });
            }

            // Clean up used nonce
            await ctx.context.internalAdapter.deleteVerificationValue(
              verification.id
            );

            // Look for existing user by their wallet addresses
            let user: User | null = null;

            // Check if there's a wallet address record for this exact address
            const existingWalletAddress: WalletAddress | null =
              await ctx.context.adapter.findOne({
                model: "walletAddressSol",
                where: [
                  { field: "address", operator: "eq", value: walletAddress },
                ],
              });

            if (existingWalletAddress) {
              // Get the user associated with this wallet address
              user = await ctx.context.adapter.findOne({
                model: "user",
                where: [
                  {
                    field: "id",
                    operator: "eq",
                    value: existingWalletAddress.userId,
                  },
                ],
              });
            }

            // Create new user if wallet is not linked to any user
            if (!user) {
              const emailDomain = options.emailDomainName ?? domain;

              // use sns lookup for email
              const { name } =
                (await options.snsLookup?.({
                  walletAddress,
                })) ?? {};
              const walletName = `${walletAddress.slice(
                3
              )}...${walletAddress.slice(-3)}`;
              const userEmail =
                !isAnon && email
                  ? email
                  : name
                  ? `${name}@${emailDomain}`
                  : `${walletName}@${emailDomain}`;

              user = await ctx.context.internalAdapter.createUser({
                name: name ?? walletName,
                email: userEmail,
              });

              // Create wallet address record
              await ctx.context.adapter.create({
                model: "walletAddressSol",
                data: {
                  userId: user.id,
                  address: walletAddress,
                  isPrimary: true, // First address is primary
                  createdAt: new Date(),
                },
              });

              // Create account record for wallet authentication
              await ctx.context.internalAdapter.createAccount({
                userId: user.id,
                providerId: "siws",
                accountId: walletAddress,
                createdAt: new Date(),
                updatedAt: new Date(),
              });
            }

            const session = await ctx.context.internalAdapter.createSession(
              user.id,
              ctx
            );

            if (!session) {
              throw new APIError("INTERNAL_SERVER_ERROR", {
                message: "Internal Server Error",
                status: 500,
              });
            }

            await setSessionCookie(ctx, { session, user });

            return ctx.json({
              token: session.token,
              success: true,
              user: {
                id: user.id,
                walletAddress,
              },
            });
          } catch (error: unknown) {
            if (error instanceof APIError) throw error;
            throw new APIError("UNAUTHORIZED", {
              message: "Something went wrong. Please try again later.",
              error: error instanceof Error ? error.message : "Unknown error",
              status: 401,
            });
          }
        }
      ),
      verifyLinkWallet: createAuthEndpoint(
        "/siws/link",
        {
          method: "POST",
          body: z.object({
            message: z.string().min(1),
            signature: z.string().min(1),
            walletAddress: z.string().regex(walletAddressRegex).min(32).max(44),
            cluster: z
              .enum(["mainnet-beta", "devnet", "testnet"]) // match issuance
              .optional()
              .default("mainnet-beta"),
          }),
          requireRequest: true,
          use: [siwsMiddleware],
        },
        async (ctx) => {
          const { message, signature, walletAddress, cluster } = ctx.body;
          const sessionUser = ctx.context.session?.user;
          if (!sessionUser) {
            throw new APIError("UNAUTHORIZED", {
              message: "Unauthorized: User is not logged in.",
              status: 401,
            });
          }

          try {
            // Find stored nonce bound to wallet address and cluster
            const verification =
              await ctx.context.internalAdapter.findVerificationValue(
                `siws:${walletAddress}:${cluster}`
              );

            // Ensure nonce is valid and not expired
            if (!verification || new Date() > verification.expiresAt) {
              throw new APIError("UNAUTHORIZED", {
                message: "Unauthorized: Invalid or expired nonce",
                status: 401,
                code: "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE",
              });
            }

            // Verify SIWS message against stored nonce and domain
            const { value: nonce } = verification;
            const verified = await options.verifyMessage({
              message,
              signature,
              address: walletAddress,
              nonce,
              domain: options.domain,
              cluster,
            });

            if (!verified) {
              throw new APIError("UNAUTHORIZED", {
                message: "Unauthorized: Invalid SIWS signature",
                status: 401,
              });
            }

            // Clean up used nonce
            await ctx.context.internalAdapter.deleteVerificationValue(
              verification.id
            );

            // Check if there's a wallet address record for this exact address
            const currentUserWalletAddresses =
              await ctx.context.adapter.findMany<WalletAddress>({
                model: "walletAddressSol",
                where: [
                  { field: "userId", operator: "eq", value: sessionUser.id },
                ],
              });

            const walletAddressExists = currentUserWalletAddresses.some(
              (w) => w.address === walletAddress
            );

            // check if this address is already linked to this user
            if (walletAddressExists) {
              throw new APIError("BAD_REQUEST", {
                message: "Wallet already linked to this user.",
                status: 400,
              });
            }

            // Prevent linking a wallet that belongs to another user
            const walletLinkedElsewhere: WalletAddress | null =
              await ctx.context.adapter.findOne({
                model: "walletAddressSol",
                where: [
                  { field: "address", operator: "eq", value: walletAddress },
                ],
              });
            if (
              walletLinkedElsewhere &&
              walletLinkedElsewhere.userId !== sessionUser.id
            ) {
              throw new APIError("BAD_REQUEST", {
                message: "Wallet already linked to another user.",
                status: 400,
              });
            }

            const isPrimary = currentUserWalletAddresses.length === 0;
            // check if multiple wallets are allowed
            if (!options.allowMultipleWallets && !isPrimary) {
              throw new APIError("BAD_REQUEST", {
                message: "Linking multiple Solana wallets is not allowed.",
                status: 400,
              });
            }

            // Create wallet address record
            await ctx.context.adapter.create({
              model: "walletAddressSol",
              data: {
                userId: sessionUser.id,
                address: walletAddress,
                isPrimary,
                createdAt: new Date(),
              },
            });

            // Create account record for wallet authentication
            await ctx.context.internalAdapter.createAccount({
              userId: sessionUser.id,
              providerId: "siws",
              accountId: walletAddress,
              createdAt: new Date(),
              updatedAt: new Date(),
            });

            return ctx.json({
              success: true,
            });
          } catch (error: unknown) {
            if (error instanceof APIError) throw error;
            throw new APIError("BAD_REQUEST", {
              message: "Something went wrong. Please try again later.",
              error: error instanceof Error ? error.message : "Unknown error",
              status: 400,
            });
          }
        }
      ),
    },
  } satisfies BetterAuthPlugin;
};
