import type { web3 } from ".";
import type { BetterAuthClientPlugin } from "better-auth/client";

export const web3Client = () => {
  return {
    id: "web3",
    $InferServerPlugin: {} as ReturnType<typeof web3>,
  } satisfies BetterAuthClientPlugin;
};
