import { HAWKServerEngine } from "@src/HAWKServerEngine";
import { TokenHAWK } from "@src/TokenHAWK";
import { createStaticCredentialsLoader } from "@src/createStaticCredentialsLoader";
import { Either, right, left } from "@sweet-monads/either";
import { json } from "body-parser";
import { client } from "hawk";
import * as http from "http";
import * as sinon from "sinon";
import { request } from "undici";

import { secret } from "@pallad/secret";

describe("HAWKServerEngine", () => {
	let server: http.Server;
	let handler: sinon.SinonStub;
	let engine: HAWKServerEngine;
	const URL = `http://localhost:10000/some-path`;

	const credentialsLoader = createStaticCredentialsLoader("sha256", {
		c1: {
			key: secret("k1"),
			user: "u1",
		},
		c2: {
			key: secret("k2"),
			user: "u2",
		},
	});

	beforeEach(() => {
		handler = sinon.stub();
		server = http.createServer((req, res) => {
			json()(req, res, () => {
				handler(req, res);
			});
		});
		server.listen(10000);
		engine = new HAWKServerEngine(credentialsLoader);
	});

	afterEach(() => {
		server.close();
	});

	describe("verification with payload", () => {
		it("simple", async () => {
			let result: Promise<TokenHAWK> | undefined;
			handler.callsFake((req, res) => {
				result = engine.verifyWithPayload(req);
				res.end();
			});

			const payload = Buffer.from("somepayloaddata", "utf-8");

			const { header } = client.header(URL, "POST", {
				contentType: "application/octet-stream",
				payload: payload as any,
				credentials: { id: "c1", ...(await credentialsLoader("c1"))! },
			});

			await request(URL, {
				method: "POST",
				// eslint-disable-next-line @typescript-eslint/naming-convention
				headers: { Authorization: header, "content-type": "application/octet-stream" },
				body: payload,
			});

			const resolvedResult = await result;
			expect(resolvedResult).toBeInstanceOf(TokenHAWK);

			expect(resolvedResult).toHaveProperty("user", "u1");
		});

		it("simple that fails", async () => {
			let result: Promise<Either<unknown, unknown>> | undefined;
			handler.callsFake((req, res) => {
				res.end();
				result = engine.verifyWithPayload(req).then(right).catch(left);
			});

			const { header } = client.header(URL, "POST", {
				contentType: "application/octet-stream",
				payload: Buffer.from("somepayloaddata", "utf-8") as any,
				credentials: { id: "c1", ...(await credentialsLoader("c1"))! },
			});

			await request(URL, {
				method: "POST",
				// eslint-disable-next-line @typescript-eslint/naming-convention
				headers: { Authorization: header, "content-type": "application/octet-stream" },
				body: Buffer.from("completely different payload"),
			});

			const resolvedResult = await result;

			expect(resolvedResult).toMatchSnapshot();
		});
	});
});
