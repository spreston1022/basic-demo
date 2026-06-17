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

// Decodes JWT payload without verifying signature — edge inspection only.
function decodeJwtPayload(token: string): Record<string, unknown> | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const padded = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(atob(padded)) as Record<string, unknown>;
  } catch {
    return null;
  }
}

export default async function sessionCapPolicy(
  request: ZuploRequest,
  context: ZuploContext,
  options: PolicyOptions,
  policyName: string,
) {
  const maxSessions = options.maxSessions ?? 5000;
  const ttl = options.sessionTtlSeconds ?? 3600;

  const authHeader = request.headers.get("authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return HttpProblems.unauthorized(request, context, {
      detail: "Bearer token required",
    });
  }

  const payload = decodeJwtPayload(authHeader.slice(7));
  if (!payload) {
    return HttpProblems.unauthorized(request, context, {
      detail: "Invalid token format",
    });
  }

  const sid = payload.sid as string | undefined;
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
