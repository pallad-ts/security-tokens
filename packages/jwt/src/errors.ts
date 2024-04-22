import { Domain, ErrorDescriptor, formatCodeFactory } from "@pallad/errors";
import { SecurityTokenError } from "@pallad/security-tokens";

const code = formatCodeFactory("E_JWT_%c");
export const errors = new Domain().addErrorsDescriptorsMap({
	EXPIRED: ErrorDescriptor.useDefaultMessage(code(1), "Token expired", SecurityTokenError),
	NOT_VALID_BEFORE: ErrorDescriptor.useDefaultMessage(code(2), "Token is not valid yet", SecurityTokenError),
	MALFORMED: ErrorDescriptor.useDefaultMessage(code(3), "Malformed", SecurityTokenError),
	INVALID_SUBJECT: ErrorDescriptor.useDefaultMessage(code(4), "Invalid subject", SecurityTokenError),
	INVALID_KEY_ID: ErrorDescriptor.useDefaultMessage(code(5), "Invalid key id", SecurityTokenError),
});
