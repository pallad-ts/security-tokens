import { server } from "hawk";
import * as http from "http";

import { CredentialsLoader } from "./CredentialsLoader";
import { TokenHAWK } from "./TokenHAWK";
import { errors } from "./errors";

import getRawBody from "raw-body";

export class HAWKServerEngine {
	private finalCredentialsLoader = async (id: string) => {
		const credentials = await this.credentialsLoader(id);
		if (credentials === undefined) {
			throw errors.NO_CREDENTIALS_FOUND.create(id);
		}
		return credentials;
	};

	constructor(private credentialsLoader: CredentialsLoader) {}

	async verifyWithoutPayload(request: HAWKServerEngine.Request, options?: HAWKServerEngine.Options) {
		const result = await this.internalVerify(request, options);
		return new TokenHAWK(result.user);
	}

	private async internalVerify(
		request: http.IncomingMessage,
		options?: HAWKServerEngine.Options & { payload?: Buffer }
	) {
		const { payload, contentType, ...restOptions } = options || {};
		const { credentials, artifacts } = await server.authenticate(request, this.finalCredentialsLoader, restOptions);

		if (payload) {
			server.authenticatePayload(
				payload as any,
				credentials,
				artifacts,
				contentType ?? request.headers["content-type"]!
			);
		}

		return credentials;
	}

	async verifyWithPayload(request: HAWKServerEngine.Request, options?: HAWKServerEngine.Options.WithPayload) {
		const payload = options?.payload ?? (await this.getPayloadFromRequest(request));
		const result = await this.internalVerify(request, {
			...options,
			payload,
		});

		return new TokenHAWK(result.user);
	}

	private async getPayloadFromRequest(request: HAWKServerEngine.Request) {
		if (request.method === "GET" || request.method === "HEAD") {
			return Buffer.from("", "utf-8");
		}

		return getRawBody(request);
	}
}

export namespace HAWKServerEngine {
	export interface Options {
		hostHeaderName?: string;
		host?: string;
		port?: number;
		contentType?: string;
	}

	export namespace Options {
		export interface WithPayload extends Options {
			payload?: Buffer;
		}
	}

	export type Request = http.IncomingMessage;
}
