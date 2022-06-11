import {TokenFactory} from "@pallad/security-tokens-http";
import {HAWKServerEngine} from "./HAWKServerEngine";

export function hawkVerification(engine: HAWKServerEngine, {withPayload, ...options}: hawkVerification.Options): TokenFactory.Rule {
	return request => {
		if (withPayload) {
			return engine.verifyWithPayload(request, options);
		}
		return engine.verifyWithoutPayload(request, options);
	}
}

export namespace hawkVerification {
	export interface Options extends HAWKServerEngine.Options {
		withPayload: boolean
	}
}
