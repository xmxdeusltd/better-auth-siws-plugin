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
import { getOrigin } from "./util/url";

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

export const siws = (options: SIWSPluginOptions): BetterAuthPlugin => {
  const siwsMiddleware = createAuthMiddleware(async (ctx) => {
    const session = await getSessionFromCtx(ctx);
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
          }),
        },
        async (ctx) => {
          const { walletAddress } = ctx.body;
          const nonce = await options.getNonce();

          // Store nonce with wallet address and cluster context
          await ctx.context.internalAdapter.createVerificationValue({
            identifier: `siws:${walletAddress}`,
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
          body: z.object({
            message: z.string().min(1),
            signature: z.string().min(1),
            walletAddress: z.string().regex(walletAddressRegex),
            email: z.string().email().optional(),
          }),
          requireRequest: true,
          requireHeaders: true,
          use: [siwsMiddleware],
        },
        async (ctx) => {
          const { message, signature, walletAddress, email } = ctx.body;
          const sessionUser = ctx.context.session?.user;
          const isAnon = options.anonymous ?? true;

          if (!isAnon && !email && !sessionUser) {
            throw new APIError("BAD_REQUEST", {
              message:
                "Email is required when anonymous is disabled or user is not logged in.",
              status: 400,
            });
          }

          try {
            // Find stored nonce with wallet address
            const verification =
              await ctx.context.internalAdapter.findVerificationValue(
                `siws:${walletAddress}`
              );

            // Ensure nonce is valid and not expired
            if (!verification || new Date() > verification.expiresAt) {
              throw new APIError("UNAUTHORIZED", {
                message: "Unauthorized: Invalid or expired nonce",
                status: 401,
                code: "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE",
              });
            }

            // Verify SIWS message
            const verified = await options.verifyMessage({
              message,
              signature,
              address: walletAddress,
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

            if (sessionUser && user && user.id !== sessionUser.id) {
              // wallet belongs to another user
              throw new APIError("BAD_REQUEST", {
                message: "Wallet linked to another user.",
                status: 400,
              });
            }

            // Create new user if not logged in and not linked to any user
            if (!user && !sessionUser) {
              const domain =
                options.emailDomainName ?? getOrigin(ctx.context.baseURL);

              // use sns lookup for email
              const { name } =
                (await options.snsLookup?.({ walletAddress })) ?? {};
              const userEmail =
                !isAnon && email
                  ? email
                  : name
                  ? `${name}@${domain}`
                  : `${walletAddress}@${domain}`;

              user = await ctx.context.internalAdapter.createUser({
                name: name ?? walletAddress,
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
            } else if (sessionUser && !user) {
              // user is logged in but wallet is not linked to them
              if (!options.allowMultipleWallets) {
                throw new APIError("BAD_REQUEST", {
                  message: "Linking multiple wallets is not allowed.",
                  status: 400,
                });
              }
              // check if this specific address exists
              if (!existingWalletAddress) {
                // add this new address to existing user's addresses
                await ctx.context.adapter.create({
                  model: "walletAddressSol",
                  data: {
                    userId: sessionUser.id,
                    address: walletAddress,
                    isPrimary: false, // Additional addresses are not primary by default
                    createdAt: new Date(),
                  },
                });

                // create account record for this new wallet
                await ctx.context.internalAdapter.createAccount({
                  userId: sessionUser.id,
                  providerId: "siws",
                  accountId: walletAddress,
                  createdAt: new Date(),
                  updatedAt: new Date(),
                });
              }
              user = sessionUser;
            }
            // else
            // user is not logged in but wallet is linked to them: do nothing
            // user is logged in and wallet is linked to them: do nothing

            if (!user) {
              // this should never happen
              throw new APIError("INTERNAL_SERVER_ERROR", {
                message: "Internal Server Error",
                status: 500,
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
    },
  } satisfies BetterAuthPlugin;
};
