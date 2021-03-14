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

type Payload = { [key: string]: string | number | boolean }

type AuthorizationCallback = (username: string, password: string) => Promise<Payload | false>;
type RevokeRefreshTokenCallback = (id: RefreshTokenId) => Promise<void>;
type AddRefreshTokenCallback = (id: RefreshTokenId) => Promise<void>;
type CheckRefreshTokenCallback = (token: Token) => Promise<boolean>;

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
    private publicKey: Promise<Key>;
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
    expressTokens(): express.RequestHandler {
        this.assertAllPropertiesGiven();
        return async (request, response, next) => {
            const { username, password } = this.extractLoginCredentials(request);
            const payload = await this.authorizeFn(username, password);
            if (!payload) {
                // TODO: Add better error handling
                this.sendError(response, new PermissionDeniedError("username or password wrong"));
                return;
            }
            response.json(await this.createTokens(payload));
            next();
        };
    }

    expressRefreshToken(): express.RequestHandler {
        this.assertAllPropertiesGiven();
        return async (request, response, next) => {
            const refreshToken = this.extractRefreshToken(request) as string;
            this.verifyRefreshToken(refreshToken)
                .then(async (decoded: any) => {
                    const id = decoded.tokenId;
                    if (!await this.checkRefreshTokenFn(id)) {
                        this.sendError(response, new PermissionDeniedError("Provided refresh token got revoked"));
                        return;
                    }

                    // Generate the payload
                    // TODO: Maybe do a cleanup, update some values
                    const newPayload = Object.assign({}, decoded);
                    delete newPayload.tokenId;
                    delete newPayload.isRefreshToken;

                    const newTokens = await this.createTokens(newPayload);
                    response.json(newTokens);
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
                    await this.revokeRefreshTokenFn(id);
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
            errors: [ error.message ]
        });
    }

    // JWT
    protected async createToken(payload: Payload, expiresIn: ExpiresIn) {
        const privateKey = await this.privateKey;
        const token = jwt.sign(payload, privateKey, {
            algorithm: this.keyAlgorithm,
            expiresIn
        });
        return token;
    }

    protected async createAccessToken(payload: Payload): Promise<Token> {
        return await this.createToken(payload, this.accessTokenExpiresIn);
    }

    protected async createRefreshToken(payload: Payload): Promise<Token> {
        const refreshTokenId = this.refreshTokenIdStream.next().value as string;
        const token = await this.createToken({
            ...payload,
            tokenId: refreshTokenId,
            isRefreshToken: true
        }, this.accessTokenExpiresIn);
        return token;
    }

    protected async createTokens(payload: Payload) {
        const accessToken = await this.createAccessToken(payload);
        const refreshToken = await this.createRefreshToken(payload);
        return { accessToken, refreshToken };
    }

    protected async verifyAccessToken(token: Token): Promise<any> {
        return jwt.verify(token, await this.publicKey, { algorithms: [this.keyAlgorithm] });
    }

    protected async verifyRefreshToken(token: Token): Promise<any> {
        try { 
            const decoded: any = jwt.verify(token, await this.publicKey, { algorithms: [this.keyAlgorithm] });
            const id = decoded.tokenId as RefreshTokenId;
            if (!id) {
                throw new BadRequestError("Please provide a refresh token");
            }
            return decoded;
        } catch(e) {
            throw new PermissionDeniedError("Token couldn't be verified");
        }
    }

    // Extraction
    protected extractLoginCredentials(request: express.Request) {
        const { username, password } = request.query as { username: string, password: string };
        return { username, password };
    }

    protected extractRefreshToken(request: express.Request): Token {
        const { refresh_token: requestToken } = request.query;
        return requestToken as string;
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