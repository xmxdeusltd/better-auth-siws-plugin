import type { AuthPluginSchema } from "better-auth/types";

export const schema = {
  walletAddressSol: {
    fields: {
      userId: {
        type: "string",
        references: {
          model: "user",
          field: "id",
        },
        required: true,
      },
      address: {
        type: "string",
        required: true,
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
