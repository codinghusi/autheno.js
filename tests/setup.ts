import express = require("express");
import { Autheno } from "../src";
import path = require('path');
import { UserStorage } from "../src/user-storage/user-storage";
import { User } from "../src/user-storage/user";

export function authenoSetup() {
    const app = express();
    const auth = new Autheno();

    const users = new UserStorage();
    users.addUser(new User("Gerrit", "1234", "admin"));
    users.addUser(new User("Joe",    "1234", "user"));

    auth.keys({
        algorithm: "RS256",
        privateKey: path.join(__dirname, "./keys/jwtRS256.key"),
        publicKey:  path.join(__dirname, "./keys/jwtRS256.key.pub")
    });

    auth.tokenExpiration({
        accessToken: "15m",
        refreshToken: "15d"
    });

    auth.tokenNamespace("http://joe.com/jwt/claims");

    auth.authorize(async (username: string, password: string) => {
        const user = users.loginUser(username, password);
        if (!user) {
            return false;
        }
        return {
            username: user.username,
            role: user.role
        }
    });

    auth.addRefreshToken(async (id, payload) => {
        // handle refresh token added
    });

    auth.revokeRefreshToken(async (id, payload) => {
        users.revokeTokenId(id);
    });

    auth.checkRefreshToken(async (id, payload) => {
        return !users.isTokenIdBlacklisted(id);
    });

    app.use("/login", auth.expressLogin());
    app.use("/refresh_token", auth.expressRefreshToken());
    app.use("/revoke_token", auth.expressRevokeRefreshToken());

    return { auth, app };
}
