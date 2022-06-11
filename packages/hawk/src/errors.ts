import {SecurityTokenError} from "@pallad/security-tokens";
import {Domain, generators} from "alpha-errors";

export const errors = Domain.create({
	errorClass: SecurityTokenError,
	codeGenerator: generators.formatCode("E_JWT_%d")
}).createErrors(create => {
	return {
		USER_ALREADY_ALREADY_REGISTERED: create('User "%s" is already registered'),
		CREDENTIAL_WITH_ID_ALREADY_REGISTERED: create('Credential with id "%s" is already registered'),
		NO_CREDENTIALS_FOUND: create('Credential for ID: %s not found')
	}
})
