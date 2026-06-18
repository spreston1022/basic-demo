import {
  CustomRateLimitDetails,
  ZuploContext,
  ZuploRequest,
} from "@zuplo/runtime";

// Returns undefined to skip rate limiting when the bypass param is present.
export function rateLimitKey(
  request: ZuploRequest,
  context: ZuploContext,
  policyName: string,
): CustomRateLimitDetails | undefined {
  const url = new URL(request.url);
  if (url.searchParams.get("bypass") === "true") {
    context.log.info(`[${policyName}] rate limit bypassed via ?bypass`);
    return undefined;
  }

  return {
    key: "auth-rl:global",
    requestsAllowed: 5,
    timeWindowMinutes: 1,
  };
}
