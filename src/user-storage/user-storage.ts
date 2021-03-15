import { User } from "./user";


export class UserStorage {
    constructor(public users: User[] = [],
                public revokedTokenIds: string[] = []) { }

    addUser(user: User) {
        this.users.push(user);
        return this;
    }

    getUser(username: string) {
        return this.users.find(user => user.username === username);
    }

    loginUser(username: string, password: string) {
        const user = this.getUser(username);
        if (!user) {
            return null;
        }
        if (!user.checkPassword(password)) {
            return null;
        }
        return user;
    }

    isTokenIdBlacklisted(id: string) {
        return this.revokedTokenIds.includes(id);
    }

    revokeTokenId(id: string) {
        this.revokedTokenIds.push(id);
        return this;
    }
}