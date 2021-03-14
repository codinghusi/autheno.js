import { AuthenoError } from "./error-handler";


export class PermissionDeniedError extends AuthenoError {
    constructor(message: string) {
        super(403, message)
    }
}