import {
  HttpProblems,
  ZoneCache,
  ZuploContext,
  ZuploRequest,
} from "@zuplo/runtime";

interface PolicyOptions {
  maxSessions: number;
  sessionTtlSeconds?: number;
}

export default async function sessionCapPolicy(
  request: ZuploRequest,
  context: ZuploContext,
  options: PolicyOptions,
  policyName: string,
) {
  const maxSessions = options.maxSessions ?? 5000;
  const ttl = options.sessionTtlSeconds ?? 3600;

  // jwt-auth runs first and populates request.user — sid comes from the verified claims
  const sid = (request.user?.data as Record<string, unknown>)?.sid as
    | string
    | undefined;

  if (!sid) {
    return HttpProblems.unauthorized(request, context, {
      detail: "Token is missing required 'sid' claim",
    });
  }

  const cache = new ZoneCache<string[]>("active-sessions", context);
  const activeSessions = (await cache.get("sessions")) ?? [];

  if (!activeSessions.includes(sid)) {
    if (activeSessions.length >= maxSessions) {
      context.log.warn(
        `[${policyName}] cap reached: ${activeSessions.length}/${maxSessions}, rejected sid=${sid}`,
      );
      return HttpProblems.forbidden(request, context, {
        detail: `Maximum concurrent sessions (${maxSessions}) reached.`,
      });
    }
    activeSessions.push(sid);
    await cache.put("sessions", activeSessions, ttl);
    context.log.info(
      `[${policyName}] registered sid=${sid} (${activeSessions.length}/${maxSessions})`,
    );
  }

  return request;
}
