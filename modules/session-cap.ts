import { HttpProblems, ZuploContext, ZuploRequest } from "@zuplo/runtime";

interface PolicyOptions {
  maxSessions: number;
  idleTimeoutSeconds?: number;
  redisUrl: string;
  redisToken: string;
}

const SESSION_KEY = "active-sessions";

async function upstash(url: string, token: string, command: unknown[]): Promise<unknown> {
  const res = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(command),
  });
  const json = await res.json() as { result?: unknown; error?: string };
  if (json.error) throw new Error(json.error);
  return json.result;
}

export default async function sessionCapPolicy(
  request: ZuploRequest,
  context: ZuploContext,
  options: PolicyOptions,
  policyName: string,
) {
  const maxSessions = options.maxSessions ?? 3;
  const idleTimeout = (options.idleTimeoutSeconds ?? 60) * 1000;
  const { redisUrl, redisToken } = options;
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

  const r = (cmd: unknown[]) => upstash(redisUrl, redisToken, cmd);

  await r(["ZREMRANGEBYSCORE", SESSION_KEY, 0, cutoff]);

  const existingScore = await r(["ZSCORE", SESSION_KEY, sid]);
  if (existingScore !== null) {
    await r(["ZADD", SESSION_KEY, now, sid]);
    return request;
  }

  const activeCount = await r(["ZCARD", SESSION_KEY]) as number;
  if (activeCount >= maxSessions) {
    context.log.warn(
      `[${policyName}] cap reached: ${activeCount}/${maxSessions}, rejected sid=${sid}`,
    );
    return HttpProblems.forbidden(request, context, {
      detail: `Maximum concurrent sessions (${maxSessions}) reached.`,
    });
  }

  await r(["ZADD", SESSION_KEY, now, sid]);
  context.log.info(
    `[${policyName}] registered sid=${sid} (${activeCount + 1}/${maxSessions})`,
  );

  return request;
}
