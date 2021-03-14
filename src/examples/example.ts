import * as express from 'express';
import path = require('path');
import { Autheno } from '..';

const app = express();

const auth = new Autheno();


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
    if (username === "Joe" && password === "1234") {
        return {
            username,
            role: "user"
        }
    }
    return false;
});

auth.addRefreshToken(async token => {
    // handle refresh token added
    // TODO: A connection to the user is needed
});

auth.revokeRefreshToken(async token => {
    // push to blacklist
})

auth.checkRefreshToken(async token => {
    // check blacklist
    return true;
});

app.use("/login", auth.expressTokens());
app.use("/refresh_token", auth.expressRefreshToken());
app.use("/revoke_token", auth.expressRevokeRefreshToken());

app.listen(8080, () => console.log("listening on port 8080"));

