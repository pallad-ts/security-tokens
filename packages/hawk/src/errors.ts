import {SecurityTokenError} from "@pallad/security-tokens";
import {Domain, ErrorDescriptor, formatCodeFactory} from "@pallad/errors";

const code = formatCodeFactory("E_HAWK_%c");
export const errors = new Domain().addErrorsDescriptorsMap({
	NO_CREDENTIALS_FOUND: ErrorDescriptor.useMessageFormatter(
		code(1),
		(credentialId: string) => `Credential for ID: ${credentialId} not found`,
		SecurityTokenError
	)
})
