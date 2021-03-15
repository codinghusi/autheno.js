import * as express from "express";
import { promises as fs } from "fs";
import * as jwt from "jsonwebtoken";
import { BadRequestError } from "./error-handlers/bad-request";
import { AuthenoError } from "./error-handlers/error-handler";
import { PermissionDeniedError } from "./error-handlers/permission-denied";
import { idGenerator } from "./id-generator";


type Key = string;
type KeyAlgorithm = "HS256" | "RS256";
type ExpiresIn = string;
type TokenNamespace = string;
type Token = string;
type RefreshTokenId = string;

interface AccessTokenPayload {
    username: string;
    role: string;
    extra?: any;
}

interface RefreshTokenPayload extends AccessTokenPayload {
    tokenId: RefreshTokenId;
    isRefreshToken: boolean;
}

type JWTPayload = any;

type AuthorizationCallback = (username: string, password: string) => Promise<AccessTokenPayload | false>;
type RevokeRefreshTokenCallback = (id: RefreshTokenId, payload: AccessTokenPayload) => Promise<void>;
type AddRefreshTokenCallback = (id: RefreshTokenId, payload: AccessTokenPayload) => Promise<void>;
type CheckRefreshTokenCallback = (id: RefreshTokenId, payload: AccessTokenPayload) => Promise<boolean>;

interface KeysParams {
    privateKey: Key;
    publicKey: Key;
    algorithm: KeyAlgorithm;
}

interface TokenExpirationParams {
    accessToken: Token;
    refreshToken: Token;
}

export class Autheno {
    private privateKey: Promise<Key>;
    public publicKey: Promise<Key>;
    private keyAlgorithm: KeyAlgorithm;

    private accessTokenExpiresIn: ExpiresIn;
    private refreshTokenExpiresIn: ExpiresIn;
    private jwtNamespace: TokenNamespace;

    private authorizeFn: AuthorizationCallback;
    private addRefreshTokenFn: AddRefreshTokenCallback;
    private revokeRefreshTokenFn: RevokeRefreshTokenCallback;
    private checkRefreshTokenFn: CheckRefreshTokenCallback;

    private refreshTokenIdStream = idGenerator();

    constructor() {}

    // Config
    keys({ privateKey, publicKey, algorithm }: KeysParams) {
        this.privateKey = fs.readFile(privateKey, { encoding: "utf-8" });
        this.publicKey = fs.readFile(publicKey, { encoding: "utf-8" });
        this.keyAlgorithm = algorithm;
        return this;
    }

    tokenExpiration({ accessToken, refreshToken }: TokenExpirationParams) {
        this.accessTokenExpiresIn = accessToken;
        this.refreshTokenExpiresIn = refreshToken;
        return this;
    }

    tokenNamespace(namespace: TokenNamespace) {
        this.jwtNamespace = namespace;
        return this;
    }

    authorize(callback: AuthorizationCallback) {
        this.authorizeFn = callback;
        return this;
    }

    addRefreshToken(callback: AddRefreshTokenCallback) {
        this.addRefreshTokenFn = callback;
        return this;
    }

    revokeRefreshToken(callback: RevokeRefreshTokenCallback) {
        this.revokeRefreshTokenFn = callback;
        return this;
    }

    checkRefreshToken(callback: CheckRefreshTokenCallback) {
        this.checkRefreshTokenFn = callback;
        return this;
    }

    // Express Middlewares
    expressLogin(): express.RequestHandler {
        this.assertAllPropertiesGiven();
        return async (request, response, next) => {
            const { username, password } = this.extractLoginCredentials(request);
            const payload = await this.authorizeFn(username, password);
            if (!payload) {
                this.sendError(response, new PermissionDeniedError("Either username or password is incorrect"));
                return;
            }
            const tokens = await this.createTokens(payload);
            this.sendData(response, tokens);
            next();
        };
    }

    expressRefreshToken(): express.RequestHandler {
        this.assertAllPropertiesGiven();
        return async (request, response, next) => {
            const refreshToken = this.extractRefreshToken(request) as string;
            this.verifyRefreshToken(refreshToken)
                .then(async (payload: any) => {
                    // Generate the new payload
                    // TODO: Maybe do a cleanup, update some values
                    const oldPayload = payload;
                    const newPayload = oldPayload;
                    const newRefreshTokenId = this.nextRefreshTokenId();
                    const newTokens = await this.createTokens(newPayload, newRefreshTokenId);

                    const oldRefreshTokenId = oldPayload.tokenId;
                    this.revokeRefreshTokenFn(oldRefreshTokenId, oldPayload);
                    this.addRefreshTokenFn(newRefreshTokenId, newPayload);

                    this.sendData(response, newTokens);
                    next();
                })
                .catch((e: AuthenoError) => this.sendError(response, e));
        };
    }

    expressRevokeRefreshToken(): express.RequestHandler {
        this.assertAllPropertiesGiven();
        return async (request, response, next) => {
            return this.verifyRefreshToken(this.extractRefreshToken(request))
                .then(async decoded => {
                    const id = decoded.tokenId;
                    const payload = this.extractAccessTokenPayload(decoded)
                    await this.revokeRefreshTokenFn(id, payload);
                    this.sendData(response, {});
                    next();
                })
                .catch(e => this.sendError(response, e));
        };
    }

    protected sendError(response: express.Response, error: AuthenoError): void {
        if (!(error instanceof AuthenoError)) {
            throw error;
        }
        response.status(error.httpStatus).json({
            status: "failed",
            error: error.message
        });
    }

    protected sendData(response: express.Response, data: any) {
        response.json({
            status: "success",
            data
        });
    }

    // JWT
    protected async createToken(payload: JWTPayload, expiresIn: ExpiresIn) {
        const privateKey = await this.privateKey;
        const token = jwt.sign(
            {
                payload,
                namespace: this.jwtNamespace,
            }, 
            privateKey,
            {
                algorithm: this.keyAlgorithm,
                expiresIn
            }
        );
        return token;
    }

    protected async createAccessToken(payload: AccessTokenPayload): Promise<Token> {
        return await this.createToken(payload, this.accessTokenExpiresIn);
    }

    protected nextRefreshTokenId(): RefreshTokenId {
        return this.refreshTokenIdStream.next().value as string;
    }

    protected async createRefreshToken(payload: AccessTokenPayload, refreshTokenId?: RefreshTokenId): Promise<Token> {
        const token = await this.createToken({
            ...payload,
            tokenId: refreshTokenId ?? this.nextRefreshTokenId(),
            isRefreshToken: true
        }, this.accessTokenExpiresIn);
        return token;
    }

    protected async createTokens(payload: AccessTokenPayload, refreshTokenId?: RefreshTokenId) {
        const accessToken = await this.createAccessToken(payload);
        const refreshToken = await this.createRefreshToken(payload, refreshTokenId);
        return { accessToken, refreshToken };
    }

    protected async verifyAccessToken(token: Token): Promise<any> {
        return jwt.verify(token, await this.publicKey, { algorithms: [this.keyAlgorithm] });
    }

    protected async verifyRefreshToken(token: Token): Promise<any> {
        try { 
            const decoded: any = jwt.verify(token, await this.publicKey, { algorithms: [this.keyAlgorithm] });
            const payload = this.extractRefreshTokenPayload(decoded);
            if (payload) {
                // Check if it is a refresh token
                const isRefreshToken = payload.isRefreshToken as boolean;
                const refreshTokenId = payload.tokenId as RefreshTokenId;
                if (!isRefreshToken || !refreshTokenId) {
                    throw new BadRequestError("Please provide a refresh token");
                }

                // Check if it got revoked
                if (!await this.checkRefreshTokenFn(refreshTokenId, payload)) {
                    throw new PermissionDeniedError("Provided refresh token got revoked");
                }      
                return payload;
            }
            throw new BadRequestError("Provided token in incorrect format");
        } catch(e) {
            if (e instanceof AuthenoError) {
                throw e;
            }
            throw new PermissionDeniedError("Token couldn't be verified");
        }
    }

    // Extraction
    protected extractLoginCredentials(request: express.Request) {
        const { username, password } = request.query as { username: string, password: string };
        return { username, password };
    }

    protected extractRefreshToken(request: express.Request): Token {
        const refreshToken = request.query.token as string;
        return refreshToken;
    }

    protected extractAccessTokenPayload(data: JWTPayload): AccessTokenPayload {
        const payload = data.payload as AccessTokenPayload;
        if (!payload) {
            return null;
        }
        return {
            username: payload.username,
            role: payload.role,
            extra: payload.extra ?? null
        };
    }

    protected extractRefreshTokenPayload(data: JWTPayload): RefreshTokenPayload {
        const payload = data.payload as RefreshTokenPayload;
        if (!payload) {
            return null;
        }
        return {
            username: payload.username,
            role: payload.role,
            extra: payload.extra ?? null,
            tokenId: payload.tokenId,
            isRefreshToken: true
        };
    }

    // Checker
    private assertAllPropertiesGiven() {
        if (this.privateKey && this.publicKey && this.keyAlgorithm &&
            this.accessTokenExpiresIn && this.refreshTokenExpiresIn && this.jwtNamespace &&
            this.addRefreshTokenFn && this.authorizeFn && this.revokeRefreshTokenFn &&
            this.checkRefreshTokenFn) {
                return;
        }
        // TODO: give examples, what's missing
        throw "Autheno needs all properties set";
    }
}