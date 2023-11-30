import {Domain, formatCodeFactory, ErrorDescriptor} from '@pallad/errors';
import {SecurityTokenError} from "./SecurityTokenError";

const code = formatCodeFactory("E_SC_%c");
export const errors = new Domain().addErrorsDescriptorsMap({
	UNSUPPORTED_TOKEN: ErrorDescriptor.useDefaultMessage(code(1), 'Security token is not supported', SecurityTokenError),
	UNSUPPORTED_PARTICIPANT: ErrorDescriptor.useDefaultMessage(code(2), 'Participant is not supported', SecurityTokenError)
});
