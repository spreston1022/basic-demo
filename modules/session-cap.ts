import { HttpProblems, ZuploContext, ZuploRequest } from "@zuplo/runtime";

interface PolicyOptions {
  maxSessions: number;
  idleTimeoutSeconds?: number;
  redisUrl: string;
  redisToken: string;
}

const SESSION_KEY = "active-sessions";

async function pipeline(
  url: string,
  token: string,
  commands: unknown[][],
): Promise<unknown[]> {
  const res = await fetch(`${url}/pipeline`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(commands),
  });
  const text = await res.text();
  if (!text.startsWith("[")) {
    throw new Error(`Upstash response: ${text.slice(0, 200)}`);
  }
  const rows = JSON.parse(text) as Array<{ result?: unknown; error?: string }>;
  for (const row of rows) {
    if (row.error) throw new Error(row.error);
  }
  return rows.map((r) => (r.result !== undefined ? r.result : null));
}

export default async function sessionCapPolicy(
  request: ZuploRequest,
  context: ZuploContext,
  options: PolicyOptions,
  policyName: string,
) {
  const maxSessions = options.maxSessions ?? 3;
  const idleTimeout = (options.idleTimeoutSeconds ?? 60) * 1000;
  const redisUrl = options.redisUrl?.trim();
  const redisToken = options.redisToken?.trim();
  throw new Error(`DBG2 tok=${btoa(redisToken ?? "")} url=${btoa(redisUrl ?? "")}`);
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

  // Prune stale + check existing + get count in one round-trip
  const [, existingScore, activeCount] = await pipeline(redisUrl, redisToken, [
    ["ZREMRANGEBYSCORE", SESSION_KEY, 0, cutoff],
    ["ZSCORE", SESSION_KEY, sid],
    ["ZCARD", SESSION_KEY],
  ]);

  if (existingScore !== null) {
    // Known session — refresh timestamp
    await pipeline(redisUrl, redisToken, [
      ["ZADD", SESSION_KEY, now, sid],
    ]);
    return request;
  }

  const count = activeCount as number;
  if (count >= maxSessions) {
    context.log.warn(
      `[${policyName}] cap reached: ${count}/${maxSessions}, rejected sid=${sid}`,
    );
    return HttpProblems.forbidden(request, context, {
      detail: `Maximum concurrent sessions (${maxSessions}) reached.`,
    });
  }

  await pipeline(redisUrl, redisToken, [
    ["ZADD", SESSION_KEY, now, sid],
  ]);
  context.log.info(
    `[${policyName}] registered sid=${sid} (${count + 1}/${maxSessions})`,
  );

  return request;
}
