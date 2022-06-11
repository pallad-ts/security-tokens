import {TokenFactory} from "@pallad/security-tokens-http";
import {HAWKServerEngine} from "./HAWKServerEngine";

export function hawkVerification(engine: HAWKServerEngine, {withPayload, payloadProvider, ...options}: hawkVerification.Options): TokenFactory.Rule {
	return async request => {
		if (withPayload) {
			const payload = payloadProvider ? await payloadProvider(request) : undefined;
			return engine.verifyWithPayload(request, {...options, payload});
		}
		return engine.verifyWithoutPayload(request, options);
	}
}

export namespace hawkVerification {
	export interface Options extends HAWKServerEngine.Options {
		withPayload: boolean,
		payloadProvider?: (req: TokenFactory.Request) => Promise<Buffer> | Buffer;
	}
}
