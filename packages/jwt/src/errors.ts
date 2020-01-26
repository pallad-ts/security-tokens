import {ErrorsDomain, generators} from "alpha-errors";
import {SecurityTokenError} from "@pallad/security-tokens";

export const errors = ErrorsDomain.create({
    errorClass: SecurityTokenError,
    codeGenerator: generators.formatCode("E_JWT_%d")
})
    .createErrors(create => {
        return {
            EXPIRED: create('Token expired'),
            NOT_VALID_BEFORE: create('Token is not valid yet'),
            MALFORMED: create('Malformed'),
            INVALID_SUBJECT: create('Invalid subject'),
            INVALID_KEY_ID: create('Invalid key id')
        }
    });