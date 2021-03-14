

export class AuthenoError extends Error {
    constructor(public httpStatus: number,
                public message: string) {
        super(message);
    }
}