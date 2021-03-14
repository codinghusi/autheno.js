import { AuthenoError } from "./error-handler";


export class BadRequestError extends AuthenoError {
    constructor(message: string) {
        super(400, message);
    }
}