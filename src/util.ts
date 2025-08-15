export function getDomain(url: string) {
  try {
    const parsedUrl = new URL(url);
    return parsedUrl.hostname;
  } catch (error) {
    return null;
  }
}

export function createMessage(
  domain: string,
  nonce: string,
  customMessage?: string
) {
  return `${
    customMessage ||
    "By signing this message you confirm you're the owner of this wallet."
  }\n\nDomain: ${domain}\nNonce: ${nonce}`;
}
