import {Domain, formatCodeFactory, ErrorDescriptor} from '@pallad/errors';
import {SecurityTokenError} from "./SecurityTokenError";

const code = formatCodeFactory("E_SC_%c");
export const errorsDomain = new Domain();
export const errors = errorsDomain.addErrorsDescriptorsMap({
	UNSUPPORTED_TOKEN: ErrorDescriptor.useDefaultMessage(code(1), 'Security token is not supported', SecurityTokenError),
});
