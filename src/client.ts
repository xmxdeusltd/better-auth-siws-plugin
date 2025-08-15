import type { siws } from ".";
import type { BetterAuthClientPlugin } from "better-auth/client";

export const siwsClient = () => {
  return {
    id: "siws",
    $InferServerPlugin: {} as ReturnType<typeof siws>,
  } satisfies BetterAuthClientPlugin;
};
