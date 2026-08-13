import { createRemoteJWKSet, jwtVerify, JWTVerifyResult } from 'jose';

export interface JWKSClientOptions {
  jwksUri: string;
  issuer?: string;
  audience?: string;
  cacheTTLMs?: number;
}

export class JWKSVerifier {
  private remoteJWKSet: ReturnType<typeof createRemoteJWKSet>;
  private issuer?: string;
  private audience?: string;

  constructor(options: JWKSClientOptions) {
    this.issuer = options.issuer;
    this.audience = options.audience;
    this.remoteJWKSet = createRemoteJWKSet(new URL(options.jwksUri), {
      cacheMaxAge: options.cacheTTLMs || 600000 // 10 minutes default cache
    });
  }

  public async verifyToken(token: string): Promise<JWTVerifyResult> {
    const verifyOptions: { issuer?: string; audience?: string } = {};
    if (this.issuer) verifyOptions.issuer = this.issuer;
    if (this.audience) verifyOptions.audience = this.audience;

    return await jwtVerify(token, this.remoteJWKSet, verifyOptions);
  }
}
