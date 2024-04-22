import { TokenFactory } from "@pallad/security-tokens-http";

import { HAWKServerEngine } from "./HAWKServerEngine";

export function hawkVerification(engine: HAWKServerEngine, options: hawkVerification.Options.Arg): TokenFactory.Rule {
	return async request => {
		const { payload, ...restOptions } = options instanceof Function ? await options(request) : options;
		if (payload) {
			return engine.verifyWithPayload(request, { ...restOptions, payload });
		}
		return engine.verifyWithoutPayload(request, restOptions);
	};
}

export namespace hawkVerification {
	export interface Options extends HAWKServerEngine.Options {
		payload?: Buffer;
	}

	export namespace Options {
		export type Arg = ((req: TokenFactory.Request) => Options | Promise<Options>) | Options;
	}
}
