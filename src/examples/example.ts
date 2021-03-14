import * as express from 'express';
import { Autheno } from '..';

const app = express();

const auth = new Autheno();


auth.keys({
    algorithm: "RS256",
    privateKey: "",
    publicKey: ""
});

auth.tokenExpiration({
    accessToken: "15m",
    refreshToken: "15d"
});

auth.tokenNamespace("http://joe.com/jwt/claims");

auth.authorize(async (username: string, password: string) => {
    if (username === "Joe" && password === "1234") {
        return {
            username,
            role: "user"
        }
    }
    return false;
});

auth.addRefreshToken(token => {

});

auth.revokeRefreshToken(token => {
    // push to blacklist
})

auth.checkRefreshToken(token => {
    // check blacklist
    return true;
});

app.use("/login", auth.expressTokens());
app.use("/refresh_token", auth.expressRefreshToken());
app.use("/revoke_token", auth.expressRevokeRefreshToken());

