import * as http from "http";
import {server} from 'hawk';
import {CredentialsStorage} from "./CredentialsStorage";
import {TokenHAWK} from "./TokenHAWK";
import getRawBody = require("raw-body");

export class HAWKServerEngine {
	constructor(private credentialsStorage: CredentialsStorage) {
	}

	async verifyWithoutPayload(request: HAWKServerEngine.Request, options?: HAWKServerEngine.Options) {
		const result = await this.internalVerify(request, options);
		return new TokenHAWK(result.credentials.user);
	}

	private internalVerify(request: http.IncomingMessage, options?: HAWKServerEngine.Options & { payload?: Buffer }) {
		const {overrideHostHeader: hostHeaderName, payload} = options || {};
		return server.authenticate(request,
			this.credentialsStorage.retrieveCredentials.bind(this.credentialsStorage),
			{
				hostHeaderName,
				payload: payload as any
			}
		);
	}

	async verifyWithPayload(request: HAWKServerEngine.Request, options?: HAWKServerEngine.Options.WithPayload) {
		const payload = options?.payload ?? await this.getPayloadFromRequest(request);
		const result = await this.internalVerify(request, {
			...options,
			payload
		});

		return new TokenHAWK(result.credentials.user);
	}

	private async getPayloadFromRequest(request: HAWKServerEngine.Request) {
		if (request.method === 'GET' || request.method === 'HEAD') {
			return Buffer.from('', 'utf-8');
		}

		return getRawBody(request);
	}
}

export namespace HAWKServerEngine {
	export interface Options {
		overrideHostHeader?: string;
	}

	export namespace Options {
		export interface WithPayload extends Options {
			payload?: Buffer;
		}
	}

	export type Request = http.IncomingMessage;
}

