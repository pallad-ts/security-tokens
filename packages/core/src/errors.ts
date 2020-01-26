import {ErrorsDomain, generators} from 'alpha-errors';
import {SecurityTokenError} from "./SecurityTokenError";

export const errors = ErrorsDomain.create({
    errorClass: SecurityTokenError,
    codeGenerator: generators.formatCode('E_SC_%d')
}).createErrors(create => {
    return {
        UNSUPPORTED_TOKEN: create('Security token is not supported'),
        UNSUPPORTED_PARTICIPANT: create('Participant is not supported')
    }
});