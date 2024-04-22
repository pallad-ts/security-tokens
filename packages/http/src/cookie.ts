import { Token } from "@pallad/security-tokens";

import { TokenFactory } from "./TokenFactory";

export function cookie(factory: (x: string) => Token, cookieName: string): TokenFactory.Rule {
	return (request: TokenFactory.Request & { cookies?: any }) => {
		if (!("cookies" in request)) {
			// eslint-disable-next-line no-console
			console.warn(
				'Request contains no "cookies" property. Make sure you have used a cookie-parser middleware first.'
			);
			return;
		}

		const cookie = request.cookies[cookieName];
		if (cookie) {
			return factory(cookie);
		}
	};
}
