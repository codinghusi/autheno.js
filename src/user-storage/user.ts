

export class User {
    constructor(public username: string,
                protected password: string,
                public role: string) { }
    
    checkPassword(password: string) {
        return this.password === password;
    }
}