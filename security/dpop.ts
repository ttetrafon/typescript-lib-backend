import { decodeProtectedHeader, importJWK, jwtVerify, calculateJwkThumbprint } from "jose";
import { DPOP_IAT_TOLERANCE_S } from "../constants";
import { sha256 } from "./conversions";

export type DpopProof = {
  /** SHA-256 thumbprint (RFC 7638) of the public key that signed the proof */
  jkt: string;
  /** Unique id of the proof; feed it to the session's replay check on sensitive endpoints */
  jti: string;
};

/** Parses `Authorization: DPoP <token>`. A DPoP-bound token is never accepted under the Bearer scheme. */
export function getDpopToken(header: string | undefined): string | null {
  if (!header) return null;
  const parts = header.split(" ");
  if (parts.length !== 2 || parts[0]!.toLowerCase() !== "dpop" || !parts[1]) return null;
  return parts[1];
}

/**
 * Verify the `DPoP` header of a request (RFC 9449).
 * Returns the key thumbprint and jti, or null if the proof is missing or invalid.
 *
 * @param publicBase Public origin of the API (e.g. https://api.example.com), from configuration.
 *                   Never derive it from the Host header.
 * @param accessToken When the request carries an access token, pass it so the proof's `ath` is checked.
 *
 * Callers still have to (1) compare `jkt` with the token's/session's bound key and (2) check `jti` for replays.
 */
export async function verifyDpopProof(
  req: Request,
  publicBase: string,
  accessToken?: string
): Promise<DpopProof | null> {
  const proof = req.headers.get("DPoP");
  if (!proof) return null;

  try {
    const header = decodeProtectedHeader(proof);
    const jwk = header.jwk;
    if (header.typ !== "dpop+jwt" || header.alg !== "ES256" || !jwk) return null;
    // Only public P-256 keys are accepted; a proof carrying a private key is rejected outright.
    if (jwk.kty !== "EC" || jwk.crv !== "P-256" || "d" in jwk) return null;

    const key = await importJWK(jwk, "ES256");
    const { payload } = await jwtVerify(proof, key, { typ: "dpop+jwt", algorithms: ["ES256"] });

    const url = new URL(req.url);
    const expectedHtu = publicBase.replace(/\/+$/, "") + url.pathname; // htu excludes query and fragment
    if (payload.htm !== req.method || payload.htu !== expectedHtu) return null;

    if (typeof payload.iat !== "number") return null;
    if (Math.abs(Date.now() / 1000 - payload.iat) > DPOP_IAT_TOLERANCE_S) return null;

    if (typeof payload.jti !== "string" || payload.jti.length === 0) return null;

    if (accessToken !== undefined && payload.ath !== await sha256(accessToken)) return null;

    return { jkt: await calculateJwkThumbprint(jwk), jti: payload.jti };
  } catch {
    // malformed proof, bad signature, unsupported key, etc.
    return null;
  }
}
