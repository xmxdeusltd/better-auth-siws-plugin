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
  ENSLookupArgs,
  ENSLookupResult,
  SNSLookupArgs,
  SNSLookupResult,
  SVMVerifyMessageArgs,
  EVMVerifyMessageArgs,
  WalletAddress,
} from "./types";
import type { User } from "better-auth/types";
import { schema } from "./schema";
import { getDomain, toChecksumAddress } from "./util";

export interface Web3PluginOptions {
  domain: string;
  emailDomainName?: string;
  anonymous?: boolean;
  allowMultipleWalletsPerChain?: boolean; // false by default
  getNonce: () => Promise<string>;
  verifyEVMMessage?: (args: EVMVerifyMessageArgs) => Promise<boolean>;
  ensLookup?: (args: ENSLookupArgs) => Promise<ENSLookupResult>;
  verifySVMMessage?: (args: SVMVerifyMessageArgs) => Promise<boolean>;
  snsLookup?: (args: SNSLookupArgs) => Promise<SNSLookupResult>;
}

const SVMValletAddressRegex = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const EVMValletAddressRegex = /^0[xX][a-fA-F0-9]{40}$/i;

export const web3 = (options: Web3PluginOptions) => {
  const web3Middleware = createAuthMiddleware(async (ctx) => {
    const session = await getSessionFromCtx(ctx);
    if (!session) {
      throw new APIError("UNAUTHORIZED");
    }
    return {
      session,
    };
  });

  return {
    id: "web3",
    schema,
    endpoints: {
      getNonce: createAuthEndpoint(
        "/web3/nonce",
        {
          method: "POST",
          body: z.object({
            walletAddress: z.union([
              z.string().regex(SVMValletAddressRegex),
              z.string().regex(EVMValletAddressRegex),
            ]),
            type: z.enum(["svm", "evm"]),
            // Bind nonce to chainId or cluster to avoid cross-environment replay
            value: z.union([z.number(), z.string()]),
          }),
        },
        async (ctx) => {
          const { walletAddress, type, value } = ctx.body;
          const nonce = await options.getNonce();

          // Store nonce with wallet address and cluster context
          await ctx.context.internalAdapter.createVerificationValue({
            identifier: `${type}:${walletAddress}:${value}`,
            value: nonce,
            expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
          });

          return ctx.json({ nonce });
        }
      ),

      verifySVMMessage: createAuthEndpoint(
        "/web3/svm/verify",
        {
          method: "POST",
          body: z
            .object({
              message: z.string().min(1),
              signature: z.string().min(1),
              walletAddress: z
                .string()
                .regex(SVMValletAddressRegex)
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
              message: "Domain is not allowed.",
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
                `svm:${walletAddress}:${cluster}`
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
            if (!options.verifySVMMessage) {
              throw new APIError("UNAUTHORIZED", {
                message: "Unauthorized: No verification function provided",
                status: 401,
              });
            }
            const verified = await options.verifySVMMessage({
              message,
              signature,
              address: walletAddress,
              nonce,
              domain,
              cluster,
            });

            if (!verified) {
              throw new APIError("UNAUTHORIZED", {
                message: "Unauthorized: Invalid SVM signature",
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
                model: "walletAddress",
                where: [
                  { field: "address", operator: "eq", value: walletAddress },
                  { field: "type", operator: "eq", value: "svm" },
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
                0,
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

              // Create account record for wallet authentication
              const account = await ctx.context.internalAdapter.createAccount({
                userId: user.id,
                providerId: "svm",
                accountId: walletAddress,
                createdAt: new Date(),
                updatedAt: new Date(),
              });

              // Create wallet address record
              await ctx.context.adapter.create({
                model: "walletAddress",
                data: {
                  userId: user.id,
                  address: walletAddress,
                  accountId: account.id,
                  type: "svm",
                  isPrimary: true, // First address is primary
                  createdAt: new Date(),
                },
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
      linkSVMWallet: createAuthEndpoint(
        "/web3/svm/link",
        {
          method: "POST",
          body: z.object({
            message: z.string().min(1),
            signature: z.string().min(1),
            walletAddress: z
              .string()
              .regex(SVMValletAddressRegex)
              .min(32)
              .max(44),
            cluster: z
              .enum(["mainnet-beta", "devnet", "testnet"]) // match issuance
              .optional()
              .default("mainnet-beta"),
          }),
          requireRequest: true,
          requireHeaders: true,
          use: [web3Middleware],
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
          const domain = getDomain(ctx.headers.get("origin") ?? "");
          if (!domain || domain !== options.domain) {
            throw new APIError("BAD_REQUEST", {
              message: "Domain is not allowed.",
              status: 400,
            });
          }

          try {
            // Find stored nonce bound to wallet address and cluster
            const verification =
              await ctx.context.internalAdapter.findVerificationValue(
                `svm:${walletAddress}:${cluster}`
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
            if (!options.verifySVMMessage) {
              throw new APIError("UNAUTHORIZED", {
                message: "Unauthorized: No verification function provided",
                status: 401,
              });
            }
            const verified = await options.verifySVMMessage({
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

            // Check if there's a wallet address record for this exact address
            const currentUserWalletAddresses =
              await ctx.context.adapter.findMany<WalletAddress>({
                model: "walletAddress",
                where: [
                  { field: "userId", operator: "eq", value: sessionUser.id },
                  { field: "type", operator: "eq", value: "svm" },
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
                model: "walletAddress",
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

            const isPrimary = currentUserWalletAddresses.length === 0; // first wallet on solana is primary
            // check if multiple wallets are allowed (for Solana, this applies across all SVM wallets)
            if (!options.allowMultipleWalletsPerChain && !isPrimary) {
              throw new APIError("BAD_REQUEST", {
                message: "Linking multiple Solana wallets is not allowed.",
                status: 400,
              });
            }
            // Create account record for wallet authentication
            const account = await ctx.context.internalAdapter.createAccount({
              userId: sessionUser.id,
              providerId: "svm",
              accountId: walletAddress,
              createdAt: new Date(),
              updatedAt: new Date(),
            });

            // Create wallet address record
            await ctx.context.adapter.create({
              model: "walletAddress",
              data: {
                userId: sessionUser.id,
                address: walletAddress,
                accountId: account.id,
                type: "svm",
                isPrimary,
                createdAt: new Date(),
              },
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

      verifyEVMMessage: createAuthEndpoint(
        "/web3/evm/verify",
        {
          method: "POST",
          body: z
            .object({
              message: z.string().min(1),
              signature: z.string().min(1),
              walletAddress: z.string().regex(EVMValletAddressRegex).length(42),
              chainId: z
                .number()
                .int()
                .positive()
                .max(2147483647)
                .optional()
                .default(1),
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
          const {
            message,
            signature,
            walletAddress: rawWalletAddress,
            chainId,
            email,
          } = ctx.body;
          const walletAddress = toChecksumAddress(rawWalletAddress);
          const isAnon = options.anonymous ?? true;
          const domain = getDomain(ctx.headers.get("origin") ?? "");

          if (!domain || domain !== options.domain) {
            throw new APIError("BAD_REQUEST", {
              message: "Domain is not allowed.",
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
            // Find stored nonce with wallet address and chain ID context
            const verification =
              await ctx.context.internalAdapter.findVerificationValue(
                `evm:${walletAddress}:${chainId}`
              );

            // Ensure nonce is valid and not expired
            if (!verification || new Date() > verification.expiresAt) {
              throw new APIError("UNAUTHORIZED", {
                message: "Unauthorized: Invalid or expired nonce",
                status: 401,
                code: "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE",
              });
            }

            // Verify EVM message with enhanced parameters
            const { value: nonce } = verification;
            if (!options.verifyEVMMessage) {
              throw new APIError("UNAUTHORIZED", {
                message: "Unauthorized: No verification function provided",
                status: 401,
              });
            }
            const verified = await options.verifyEVMMessage({
              message,
              signature,
              address: walletAddress,
              chainId,
              cacao: {
                h: { t: "caip122" },
                p: {
                  domain: options.domain,
                  aud: options.domain,
                  nonce,
                  iss: options.domain,
                  version: "1",
                },
                s: { t: "eip191", s: signature },
              },
            });

            if (!verified) {
              throw new APIError("UNAUTHORIZED", {
                message: "Unauthorized: Invalid EVM signature",
                status: 401,
              });
            }

            // Clean up used nonce
            await ctx.context.internalAdapter.deleteVerificationValue(
              verification.id
            );

            // Look for existing user by their wallet addresses
            let user: User | null = null;

            // Check if there's a wallet address record for this exact address+chainId combination
            const existingWalletAddress: WalletAddress | null =
              await ctx.context.adapter.findOne({
                model: "walletAddress",
                where: [
                  { field: "address", operator: "eq", value: walletAddress },
                  { field: "chainId", operator: "eq", value: chainId },
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
            } else {
              // No exact match found, check if this address exists on any other chain
              const anyWalletAddress: WalletAddress | null =
                await ctx.context.adapter.findOne({
                  model: "walletAddress",
                  where: [
                    { field: "address", operator: "eq", value: walletAddress },
                  ],
                });

              if (anyWalletAddress) {
                // Same address exists on different chain, get that user
                user = await ctx.context.adapter.findOne({
                  model: "user",
                  where: [
                    {
                      field: "id",
                      operator: "eq",
                      value: anyWalletAddress.userId,
                    },
                  ],
                });
              }
            }

            // Create new user if none exists
            if (!user) {
              const emailDomain = options.emailDomainName ?? domain;
              const { name, avatar } =
                (await options.ensLookup?.({ walletAddress })) ?? {};
              // Use checksummed address for email generation
              const walletName = `${walletAddress.slice(
                0,
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
                image: avatar ?? "",
              });

              // Create account record for wallet authentication
              const account = await ctx.context.internalAdapter.createAccount({
                userId: user.id,
                providerId: `evm:${chainId}`,
                accountId: walletAddress,
                createdAt: new Date(),
                updatedAt: new Date(),
              });

              // Create wallet address record
              await ctx.context.adapter.create({
                model: "walletAddress",
                data: {
                  userId: user.id,
                  address: walletAddress,
                  accountId: account.id,
                  chainId,
                  type: "evm",
                  isPrimary: true, // First address is primary
                  createdAt: new Date(),
                },
              });
            } else {
              // User exists, but check if this specific address/chain combo exists
              if (!existingWalletAddress) {
                // Respect allowMultipleWalletsPerChain: block linking a different address on the same chain
                const userWalletAddresses =
                  await ctx.context.adapter.findMany<WalletAddress>({
                    model: "walletAddress",
                    where: [
                      { field: "userId", operator: "eq", value: user.id },
                      { field: "type", operator: "eq", value: "evm" },
                    ],
                  });

                const chainWalletsForUser = userWalletAddresses.filter(
                  (w) => w.chainId === chainId
                );

                if (!options.allowMultipleWalletsPerChain) {
                  const hasDifferentAddressOnSameChain =
                    chainWalletsForUser.some(
                      (w) => w.address !== walletAddress
                    );
                  if (hasDifferentAddressOnSameChain) {
                    throw new APIError("BAD_REQUEST", {
                      message:
                        "Linking a different EVM address on the same chain is not allowed.",
                      status: 400,
                    });
                  }
                }

                // Determine primary status: first wallet on this chain is primary
                const isPrimary = chainWalletsForUser.length === 0;

                // Create account record for this new wallet+chain combination
                const account = await ctx.context.internalAdapter.createAccount(
                  {
                    userId: user.id,
                    providerId: `evm:${chainId}`,
                    accountId: walletAddress,
                    createdAt: new Date(),
                    updatedAt: new Date(),
                  }
                );

                // Add this new chainId to existing user's addresses
                await ctx.context.adapter.create({
                  model: "walletAddress",
                  data: {
                    userId: user.id,
                    address: walletAddress,
                    accountId: account.id,
                    chainId,
                    type: "evm",
                    isPrimary,
                    createdAt: new Date(),
                  },
                });
              }
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
                chainId,
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
      linkEVMWallet: createAuthEndpoint(
        "/web3/evm/link",
        {
          method: "POST",
          body: z.object({
            message: z.string().min(1),
            signature: z.string().min(1),
            walletAddress: z.string().regex(EVMValletAddressRegex).length(42),
            chainId: z
              .number()
              .int()
              .positive()
              .max(2147483647)
              .optional()
              .default(1),
          }),
          requireRequest: true,
          requireHeaders: true,
          use: [web3Middleware],
        },
        async (ctx) => {
          const {
            message,
            signature,
            walletAddress: rawWalletAddress,
            chainId,
          } = ctx.body;
          const sessionUser = ctx.context.session?.user;
          if (!sessionUser) {
            throw new APIError("UNAUTHORIZED", {
              message: "Unauthorized: User is not logged in.",
              status: 401,
            });
          }

          const domain = getDomain(ctx.headers.get("origin") ?? "");
          if (!domain || domain !== options.domain) {
            throw new APIError("BAD_REQUEST", {
              message: "Domain is not allowed.",
              status: 400,
            });
          }

          const walletAddress = toChecksumAddress(rawWalletAddress);

          try {
            // Find stored nonce bound to wallet address and chainId
            const verification =
              await ctx.context.internalAdapter.findVerificationValue(
                `evm:${walletAddress}:${chainId}`
              );

            // Ensure nonce is valid and not expired
            if (!verification || new Date() > verification.expiresAt) {
              throw new APIError("UNAUTHORIZED", {
                message: "Unauthorized: Invalid or expired nonce",
                status: 401,
                code: "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE",
              });
            }

            // Verify EVM message against stored nonce and domain
            const { value: nonce } = verification;
            if (!options.verifyEVMMessage) {
              throw new APIError("UNAUTHORIZED", {
                message: "Unauthorized: No verification function provided",
                status: 401,
              });
            }
            const verified = await options.verifyEVMMessage({
              message,
              signature,
              address: walletAddress,
              chainId,
              cacao: {
                h: { t: "caip122" },
                p: {
                  domain: options.domain,
                  aud: options.domain,
                  nonce,
                  iss: options.domain,
                  version: "1",
                },
                s: { t: "eip191", s: signature },
              },
            });

            if (!verified) {
              throw new APIError("UNAUTHORIZED", {
                message: "Unauthorized: Invalid EVM signature",
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
                model: "walletAddress",
                where: [
                  { field: "userId", operator: "eq", value: sessionUser.id },
                ],
              });

            // check if this address is already linked to this user on this chain
            const walletAddressExists = currentUserWalletAddresses.some(
              (w) => w.address === walletAddress && w.chainId === chainId
            );

            // check if this address is already linked to this user on this chain
            if (walletAddressExists) {
              throw new APIError("BAD_REQUEST", {
                message: "Wallet already linked to this user.",
                status: 400,
              });
            }

            // Prevent linking a wallet that belongs to another user (any chain)
            const walletLinkedElsewhere: WalletAddress | null =
              await ctx.context.adapter.findOne({
                model: "walletAddress",
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

            const isPrimary =
              currentUserWalletAddresses.filter((w) => w.chainId === chainId)
                .length === 0; // first wallet on this chain is primary
            if (!options.allowMultipleWalletsPerChain) {
              const hasDifferentAddressOnSameChain =
                currentUserWalletAddresses.some(
                  (w) => w.chainId === chainId && w.address !== walletAddress
                );
              if (hasDifferentAddressOnSameChain) {
                throw new APIError("BAD_REQUEST", {
                  message:
                    "Linking a different EVM address on the same chain is not allowed.",
                  status: 400,
                });
              }
            }

            // Create account record for wallet authentication
            const account = await ctx.context.internalAdapter.createAccount({
              userId: sessionUser.id,
              providerId: `evm:${chainId}`,
              accountId: walletAddress,
              createdAt: new Date(),
              updatedAt: new Date(),
            });

            // Create wallet address record
            await ctx.context.adapter.create({
              model: "walletAddress",
              data: {
                userId: sessionUser.id,
                address: walletAddress,
                accountId: account.id,
                chainId,
                type: "evm",
                isPrimary,
                createdAt: new Date(),
              },
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
