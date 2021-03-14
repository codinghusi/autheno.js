import * as express from 'express';
const Autheno: any = null;

const app = express();

const auth = new Autheno();

app.use()

auth.keys({
    algorithm: "RSA256",
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

auth.revokeRefreshToken((token: string) => {
    // push to blacklist
})

auth.checkRefreshToken((token: string) => {
    // check blacklist
    return true;
});

app.use("/access_token", auth.expressAccessToken());
app.use("/refresh_token", auth.expressRefreshToken());
app.use("/revoke_token", auth.expressRevokeRefreshToken());

