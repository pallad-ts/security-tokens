import { TokenFactory } from "@src/TokenFactory";
import { bearerHeader } from "@src/bearerHeader";
import { cookie } from "@src/cookie";
import { createRequest } from "node-mocks-http";

import { Token } from "@pallad/security-tokens";

import { SimpleToken } from "./SimpleToken";

describe("TokenFactory", () => {
	let factory: TokenFactory;
	const VALUE = "tokenValue";
	beforeEach(() => {
		factory = TokenFactory.create(bearerHeader(SimpleToken.factory), cookie(SimpleToken.factory, "test"));
	});

	it("returns token from first matching rule", () => {
		const request = createRequest({
			headers: {
				authorization: `Bearer ${VALUE}`,
			},
		});

		return expect(factory.fromHTTPRequest(request)).resolves.toStrictEqual(new SimpleToken(VALUE));
	});

	it("returns default token if none matches", () => {
		const request = createRequest();

		return expect(factory.fromHTTPRequest(request)).resolves.toStrictEqual(Token.NONE);
	});
});
