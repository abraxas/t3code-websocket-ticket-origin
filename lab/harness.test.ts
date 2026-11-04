import * as NodeFS from "node:fs";

import * as NodePlatformCrypto from "@effect/platform-node/NodeCrypto";
import * as NodeServices from "@effect/platform-node/NodeServices";
import { expect, it } from "@effect/vitest";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Redacted from "effect/Redacted";

import * as ServerConfig from "../config.ts";
import * as ServerEnvironment from "../environment/ServerEnvironment.ts";
import * as SqlitePersistence from "../persistence/Sqlite.ts";
import * as ManagedPolicy from "../policy/ManagedPolicy.ts";
import * as EnvironmentAuth from "./EnvironmentAuth.ts";
import * as ServerSecretStore from "./ServerSecretStore.ts";
import * as SessionStore from "./SessionStore.ts";

const TEST_SERVER_PORT = 13_773;
const HOST = "192.168.1.50:3773";
const TRUSTED_ORIGIN = "http://192.168.1.50:3773";
const HOSTILE_ORIGIN = "https://evil.example";
const COOKIE_HOSTILE_ORIGIN = "http://192.168.1.50:8080";

const layerServerConfig = (overrides?: Partial<ServerConfig.ServerConfig["Service"]>) =>
  Layer.effect(
    ServerConfig.ServerConfig,
    Effect.gen(function* () {
      const config = yield* ServerConfig.ServerConfig;
      return {
        ...config,
        ...overrides,
        port: TEST_SERVER_PORT,
      } satisfies ServerConfig.ServerConfig["Service"];
    }),
  ).pipe(Layer.provide(ServerConfig.layerTest(process.cwd(), { prefix: "t3-f04-wsorigin-test-" })));

const layerEnvironmentAuth = (overrides?: Partial<ServerConfig.ServerConfig["Service"]>) =>
  EnvironmentAuth.layer.pipe(
    Layer.provide(ManagedPolicy.layerTest()),
    Layer.provideMerge(SqlitePersistence.layerMemory),
    Layer.provide(ServerSecretStore.layer),
    Layer.provide(ServerEnvironment.layerIdentity),
    Layer.provide(layerServerConfig(overrides)),
  );

const requestMetadata = {
  deviceType: "desktop" as const,
  os: "macOS",
  browser: "Chrome",
  ipAddress: "192.168.1.23",
};

type AuthOutcome = "accepted" | "rejected" | "skipped";

type LabResult = {
  witness: string;
  pin: string;
  executed: boolean;
  cookieMissingOrigin: AuthOutcome;
  cookieHostileOrigin: AuthOutcome;
  cookieTrustedOrigin: AuthOutcome;
  ticketHostileOrigin: AuthOutcome;
  bearerHostileOrigin: AuthOutcome;
  cookieMissingTag: string;
  cookieHostileTag: string;
  cookieTrustedTag: string;
  ticketHostileTag: string;
  bearerHostileTag: string;
  samesite: string;
  cookieHttpOnly: boolean;
  cookieSecureFlagPresent: boolean;
};

const requiredEnv = (name: string): string => {
  const value = process.env[name];
  if (!value) throw new Error(`missing ${name}`);
  return value;
};

const writeResult = (result: LabResult): void => {
  const resultPath = requiredEnv("LAB_RESULT_PATH");
  NodeFS.writeFileSync(resultPath, `${JSON.stringify(result, null, 2)}\n`);
};

const sessionCookieFlags = (): { samesite: string; httpOnly: boolean; securePresent: boolean } => {
  const httpTs = NodeFS.readFileSync(new URL("./http.ts", import.meta.url), "utf8");
  const sameSite = httpTs.match(/sameSite:\s*"([^"]+)"/);
  return {
    samesite: sameSite?.[1] ?? "unknown",
    httpOnly: /httpOnly:\s*true/.test(httpTs),
    securePresent: /secure:\s*true/.test(httpTs),
  };
};

const classify = (
  result: { readonly _tag: "Success"; readonly success: { readonly sessionId: string } } | {
    readonly _tag: "Failure";
    readonly failure: { readonly _tag: string };
  },
): { outcome: AuthOutcome; tag: string } => {
  if (result._tag === "Success") {
    return { outcome: "accepted", tag: result.success.sessionId ? "ok" : "empty-session" };
  }
  return { outcome: "rejected", tag: result.failure._tag };
};

it.layer(Layer.mergeAll(NodeServices.layer, NodePlatformCrypto.layer))("T3-F04-WSORIGIN", (it) => {
  it.effect("records authenticateWebSocketUpgrade origin matrix", () =>
    Effect.gen(function* () {
      const witness = requiredEnv("LAB_WITNESS");
      const pin = requiredEnv("LAB_PIN");
      const flags = sessionCookieFlags();
      const result: LabResult = {
        witness,
        pin,
        executed: false,
        cookieMissingOrigin: "skipped",
        cookieHostileOrigin: "skipped",
        cookieTrustedOrigin: "skipped",
        ticketHostileOrigin: "skipped",
        bearerHostileOrigin: "skipped",
        cookieMissingTag: "",
        cookieHostileTag: "",
        cookieTrustedTag: "",
        ticketHostileTag: "",
        bearerHostileTag: "",
        samesite: flags.samesite,
        cookieHttpOnly: flags.httpOnly,
        cookieSecureFlagPresent: flags.securePresent,
      };

      const serverAuth = yield* EnvironmentAuth.EnvironmentAuth;
      const sessions = yield* SessionStore.SessionStore;
      const pairing = yield* serverAuth.issuePairingCredential();
      const exchanged = yield* serverAuth.createBrowserSession(
        pairing.credential,
        requestMetadata,
      );
      const cookieUpgrade = (headers: Record<string, string>) =>
        serverAuth.authenticateWebSocketUpgrade(
          {
            url: "/ws",
            cookies: { [sessions.cookieName]: exchanged.sessionToken },
            headers: { host: HOST, ...headers },
          } as never,
          "rpc",
        );

      const missing = classify(yield* Effect.result(cookieUpgrade({})));
      result.cookieMissingOrigin = missing.outcome;
      result.cookieMissingTag = missing.tag;
      result.executed = true;

      const hostile = classify(
        yield* Effect.result(cookieUpgrade({ origin: COOKIE_HOSTILE_ORIGIN })),
      );
      result.cookieHostileOrigin = hostile.outcome;
      result.cookieHostileTag = hostile.tag;

      const trusted = classify(yield* Effect.result(cookieUpgrade({ origin: TRUSTED_ORIGIN })));
      result.cookieTrustedOrigin = trusted.outcome;
      result.cookieTrustedTag = trusted.tag;

      const verified = yield* Effect.result(sessions.verify(exchanged.sessionToken));
      if (verified._tag === "Success") {
        const minted = yield* Effect.result(
          serverAuth.issueWebSocketTicket(verified.success, { use: "rpc" }),
        );
        if (minted._tag === "Failure") {
          result.ticketHostileOrigin = "skipped";
          result.ticketHostileTag = minted.failure._tag;
        } else {
          const ticket = Redacted.value(minted.success.ticket);
          const ticketAuth = classify(
            yield* Effect.result(
              serverAuth.authenticateWebSocketUpgrade(
                {
                  method: "GET",
                  url: `/ws?wsTicket=${ticket}`,
                  cookies: {},
                  headers: { host: HOST, origin: HOSTILE_ORIGIN },
                } as never,
                "rpc",
              ),
            ),
          );
          result.ticketHostileOrigin = ticketAuth.outcome;
          result.ticketHostileTag = ticketAuth.tag;
        }
      } else {
        result.ticketHostileOrigin = "skipped";
        result.ticketHostileTag = verified.failure._tag;
      }

      const bearer = yield* serverAuth.issueSession();
      const bearerAuth = classify(
        yield* Effect.result(
          serverAuth.authenticateWebSocketUpgrade(
            {
              url: "/ws",
              cookies: {},
              headers: {
                host: HOST,
                origin: HOSTILE_ORIGIN,
                authorization: `Bearer ${bearer.token}`,
              },
            } as never,
            "rpc",
          ),
        ),
      );
      result.bearerHostileOrigin = bearerAuth.outcome;
      result.bearerHostileTag = bearerAuth.tag;

      writeResult(result);
      expect(result.witness).toBe(witness);
      expect(result.executed).toBe(true);
      expect(result.cookieTrustedOrigin).toBe("accepted");
      expect(result.bearerHostileOrigin).toBe("accepted");
      expect(
        result.cookieMissingOrigin === "accepted" || result.ticketHostileOrigin === "accepted",
      ).toBe(true);
    }).pipe(
      Effect.provide(
        layerEnvironmentAuth({
          mode: "web",
          host: "192.168.1.50",
          devUrl: new URL("http://localhost:5733"),
        }),
      ),
    ),
  );
});
