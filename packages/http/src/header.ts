import { Token } from "@pallad/security-tokens";

import { TokenFactory } from "./TokenFactory";

export function header(factory: (x: string | string[]) => Token, headerName: string): TokenFactory.Rule {
	return request => {
		const header = request.headers[headerName.toLowerCase()];
		if (header) {
			return factory(header);
		}
	};
}
