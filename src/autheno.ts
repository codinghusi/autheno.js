import express = require("express");

type Key = string;
type KeyAlgorithm = "HS256" | "RS256";
type ExpiresIn = string;
type TokenNamespace = string;
type Token = string;

type Payload = { [key: string]: string | number }

type AuthorizationCallback = (username: string, password: string) => Promise<Payload>;
type RevokeRefreshTokenCallback = (token: Token) => Promise<void>;
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
    private privateKey: Key;
    private publicKey: Key;
    private keyAlgorithm: KeyAlgorithm;

    private accessTokenExpiresIn: ExpiresIn;
    private refreshTokenExpiresIn: ExpiresIn;
    private jwtNamespace: TokenNamespace;

    private authorizeFn: AuthorizationCallback;
    private revokeRefreshTokenFn: RevokeRefreshTokenCallback;
    private checkRefreshTokenFn: CheckRefreshTokenCallback;

    constructor() {}

    // Config
    keys({ privateKey, publicKey, algorithm }: KeysParams) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
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

    revokeRefreshToken(callback: RevokeRefreshTokenCallback) {
        this.revokeRefreshTokenFn = callback;
        return this;
    }

    checkRefreshToken(callback: CheckRefreshTokenCallback) {
        this.checkRefreshTokenFn = callback;
        return this;
    }

    // Express Middlewares
    expressAccessToken(): express.RequestHandler {
        this.assertAllPropertiesGiven();
        return (request, response, next) => {

        };
    }

    expressRefreshToken(): express.RequestHandler {
        this.assertAllPropertiesGiven();
        return (request, response, next) => {

        };
    }

    expressRevokeRefreshToken(): express.RequestHandler {
        this.assertAllPropertiesGiven();
        return (request, response, next) => {

        };
    }

    // Checker
    private assertAllPropertiesGiven() {
        if (this.privateKey && this.publicKey && this.keyAlgorithm &&
            this.accessTokenExpiresIn && this.refreshTokenExpiresIn && this.jwtNamespace &&
            this.authorizeFn && this.revokeRefreshTokenFn && this.checkRefreshTokenFn) {
                return;
        }
        // TODO: give examples, what's missing
        throw "Autheno needs all properties set";
    }
}