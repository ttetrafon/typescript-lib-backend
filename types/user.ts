export type MiddlewareAuthData = {
  userId: number;
  username: string;
  sid: string;
  jkt: string;
  jti: string;
}

export type ParsedRefreshToken = { userId: number; sid: string; secret: string };
