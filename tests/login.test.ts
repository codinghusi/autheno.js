import { expect } from 'chai';
import request = require('supertest');
import { authenoSetup } from './setup';
import jwt = require('jsonwebtoken');

const { app, auth } = authenoSetup();
const endpoint = request(app);

const username = "Joe";
const password = "1234";

async function verify(token: string) {
    return jwt.verify(token, await auth.publicKey, { algorithms: ["RS256"] });
}

async function getTokens(username: string, password: string) {
    const { body: { data, status, error }, status: httpStatus } = await endpoint.get(`/login?username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`);
    return {
        error,
        status,
        httpStatus,
        accessToken: data?.accessToken,
        refreshToken: data?.refreshToken
    };
}

async function revokeToken(token: string) {
    const { body: { status, error }, status: httpStatus } = await endpoint.get(`/revoke_token?token=${token}`);
    return { status, error, httpStatus };
}

async function refreshTokens(token: string) {
    const { body: { status, error, accessToken, refreshToken }, status: httpStatus } = await endpoint.get(`/revoke_token?token=${token}`);
    return { status, error, httpStatus, accessToken, refreshToken };
}



describe("/login - getting access and refresh token", () => {
    it("GET /login - success", async () => {
        const { accessToken, refreshToken } = await getTokens(username, password);
        expect(accessToken, "access token verification").satisfies(verify);
        expect(refreshToken, "refresh token verification (no payload check)").satisfies(verify);
    });

    it("GET /login - unauthorized", async () => {
        const { httpStatus, status } = await getTokens("Nope", "Nope");
        expect(httpStatus, "http status").equals(403);
        expect(status).equals("failed");
    });
});


describe('/revoke_token - invalidating refresh_token', () => {
    it("GET /revoke_token - success", async () => {
        // get tokens
        const { refreshToken } = await getTokens(username, password);
        // get new tokens
        const { status, httpStatus } = await revokeToken(refreshToken);
        // prove success (missing verification of correctness)
        expect(httpStatus, "http status").equals(200);
        expect(status, "status").equals("success");
    });
    
    it("GET /revoke_token - unauthorized (already revoked)", async () => {
        // get tokens
        const { refreshToken } = await getTokens(username, password);
        // make token invalid
        await revokeToken(refreshToken); 
        // retry revoking -> error
        const { status, httpStatus } = await revokeToken(refreshToken);
        // prove error
        expect(httpStatus, "http-status").equals(403);
        expect(status, "status").equals("failed");
    });
    
    it("GET /revoke_token - bad request", async () => {
        const { accessToken } = await getTokens(username, password);
        const { status, httpStatus } = await revokeToken(accessToken);
        expect(httpStatus, "http status").equals(400);
        expect(status, "status").equals("failed");
    });
});

describe("/refresh_token - renewing access and refresh token", () => {
    it("GET /refresh_token - success", async () => {
        // get first tokens
        const {  accessToken, refreshToken } = await getTokens(username, password);
        // get second tokens
        const { accessToken: accessToken2, refreshToken: refreshToken2, httpStatus, status } = await refreshTokens(refreshToken);
        // check response status
        expect(httpStatus, "http status").equals(200);
        expect(status, "status").equals("success");
        // check difference
        expect(accessToken2, "accessToken difference").to.not.equal(accessToken);
        expect(refreshToken2, "refreshToken difference").to.not.equal(refreshToken);
    });

    it("GET /refresh_token - unauthorized (revoked)", async () => {
        // get first tokens
        const { refreshToken } = await getTokens(username, password);
        // make token invalid
        await revokeToken(refreshToken);
        // get new tokens -> error
        const { status, httpStatus } = await refreshTokens(refreshToken);
        // prove errors
        expect(httpStatus, "http-status").equals(403);
        expect(status, "status").equals("failed");
    });
    
    it("GET /refresh_token - bad request", async () => {
        // get tokens
        const { accessToken } = await getTokens(username, password);
        // get new tokens -> error
        const { status, httpStatus } = await refreshTokens(accessToken);
        // prove errors
        expect(httpStatus, "http status").equals(400);
        expect(status, "status").equals("failed");
    });
})