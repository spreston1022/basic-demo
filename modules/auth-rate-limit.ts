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
  if (url.searchParams.has("bypass")) {
    context.log.info(`[${policyName}] rate limit bypassed via ?bypass`);
    return undefined;
  }

  const ip =
    request.headers.get("cf-connecting-ip") ??
    request.headers.get("x-forwarded-for")?.split(",")[0].trim() ??
    "unknown";

  return {
    key: `auth-rl:${ip}`,
    requestsAllowed: 60,
    timeWindowMinutes: 1,
  };
}
