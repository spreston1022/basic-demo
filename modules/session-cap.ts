import { HttpProblems, ZuploContext, ZuploRequest, environment } from "@zuplo/runtime";
import { Redis } from "@upstash/redis";

interface PolicyOptions {
  maxSessions: number;
  idleTimeoutSeconds?: number;
}

let redis: Redis | undefined;

function getRedis(): Redis {
  if (!redis) {
    redis = new Redis({
      url: environment.UPSTASH_REDIS_REST_URL,
      token: environment.UPSTASH_REDIS_REST_TOKEN,
    });
  }
  return redis;
}

const SESSION_KEY = "active-sessions";

export default async function sessionCapPolicy(
  request: ZuploRequest,
  context: ZuploContext,
  options: PolicyOptions,
  policyName: string,
) {
  const maxSessions = options.maxSessions ?? 3;
  const idleTimeout = (options.idleTimeoutSeconds ?? 10) * 1000;
  const now = Date.now();
  const cutoff = now - idleTimeout;

  const sid = (request.user?.data as Record<string, unknown>)?.sid as
    | string
    | undefined;

  if (!sid) {
    return HttpProblems.unauthorized(request, context, {
      detail: "Token is missing required 'sid' claim",
    });
  }

  const r = getRedis();

  // Prune sessions idle for longer than idleTimeout
  await r.zremrangebyscore(SESSION_KEY, 0, cutoff);

  // Check if this SID is already active
  const existingScore = await r.zscore(SESSION_KEY, sid);
  if (existingScore !== null) {
    // Refresh last-seen timestamp
    await r.zadd(SESSION_KEY, { score: now, member: sid });
    return request;
  }

  // New SID — check cap
  const activeCount = await r.zcard(SESSION_KEY);
  if (activeCount >= maxSessions) {
    context.log.warn(
      `[${policyName}] cap reached: ${activeCount}/${maxSessions}, rejected sid=${sid}`,
    );
    return HttpProblems.forbidden(request, context, {
      detail: `Maximum concurrent sessions (${maxSessions}) reached.`,
    });
  }

  // Register new session
  await r.zadd(SESSION_KEY, { score: now, member: sid });
  context.log.info(
    `[${policyName}] registered sid=${sid} (${activeCount + 1}/${maxSessions})`,
  );

  return request;
}
