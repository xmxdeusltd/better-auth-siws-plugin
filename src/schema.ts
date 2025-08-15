import type { AuthPluginSchema } from "better-auth/types";

export const schema = {
  walletAddress: {
    fields: {
      userId: {
        type: "string",
        references: {
          model: "user",
          field: "id",
        },
        required: true,
      },
      accountId: {
        type: "string",
        references: {
          model: "account",
          field: "id",
        },
        required: true,
      },
      type: {
        type: "string",
        required: true,
      },
      address: {
        type: "string",
        required: true,
      },
      chainId: {
        type: "number",
        required: false,
      },
      isPrimary: {
        type: "boolean",
        defaultValue: false,
      },
      createdAt: {
        type: "date",
        required: true,
      },
    },
  },
} satisfies AuthPluginSchema;
