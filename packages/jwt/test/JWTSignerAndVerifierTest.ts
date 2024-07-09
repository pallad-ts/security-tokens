import { CommonOptions } from "@src/CommonOptions";
import { JWTSigner } from "@src/JWTSigner";
import { JWTVerifier } from "@src/JWTVerifier";
import { createSecretProviderForKeyRing } from "@src/SecretProvider";
import { errors } from "@src/errors";
import { fromPromise } from "@sweet-monads/either";
import { decode, sign as _sign } from "jsonwebtoken";
import { Duration } from "luxon";
import * as sinon from "sinon";

import { KeyRing } from "@pallad/keyring";
import { secret } from "@pallad/secret";

import { JWT_DATA } from "./fixtures/jwtData";
import { KEY_RING } from "./fixtures/keyRing";

describe("JWTSignerAndVerifier", () => {
	let signer: JWTSigner;
	let verifier: JWTVerifier;
	let timer: sinon.SinonFakeTimers;

	beforeEach(() => {
		signer = new JWTSigner({
			secretProvider: createSecretProviderForKeyRing(KEY_RING),
		});
		verifier = new JWTVerifier({
			secretProvider: createSecretProviderForKeyRing(KEY_RING),
		});
		timer = sinon.useFakeTimers(5000);
	});

	afterEach(() => {
		timer.restore();
	});

	it("signing", async () => {
		const token = await signer.sign(JWT_DATA, {
			subject: "access-token",
			jwtid: "100",
			keyId: "k1",
			expiresIn: Duration.fromDurationLike({ seconds: 2 }),
		});

		const decoded = decode(token, { complete: true });

		expect(decoded).toMatchObject({
			header: {
				alg: CommonOptions.DEFAULT.algorithm,
				typ: "JWT",
				kid: "k1",
			},
			payload: {
				...JWT_DATA,
				iat: 5,
				exp: 7,
				sub: "access-token",
				jti: "100",
			},
			signature: expect.toBeString(),
		});
	});

	it("sanity check", async () => {
		const verifier = new JWTVerifier({
			secretProvider: createSecretProviderForKeyRing(KEY_RING),
		});
		const token = await signer.sign(JWT_DATA, {
			keyId: "k2",
		});
		const newData = await verifier.verify(token);

		expect(newData.payload).toEqual({
			...JWT_DATA,
			iat: 5,
		});
	});

	it("expiration", async () => {
		const duration = Duration.fromObject({ minutes: 10 });
		const token = await signer.sign(JWT_DATA, {
			expiresIn: duration,
			keyId: "k1",
		});

		expect(await verifier.verify(token)).toHaveProperty("payload", {
			...JWT_DATA,
			iat: 5,
			exp: 605,
		});

		timer.tick(duration.as("milliseconds"));

		const invalidResult = await fromPromise(verifier.verify(token));
		expect(invalidResult.isLeft()).toBe(true);
		expect(invalidResult.value).toBeErrorWithCode(errors.EXPIRED);
	});

	it("not before", async () => {
		const duration = Duration.fromObject({ minutes: 10 });
		const token = await signer.sign(JWT_DATA, {
			notBefore: duration,
			keyId: "k2",
		});

		const invalidResult = await fromPromise(verifier.verify(token));
		timer.tick(duration.as("milliseconds"));
		const validResult = await verifier.verify(token);

		expect(invalidResult.isLeft()).toBe(true);
		expect(invalidResult.value).toBeErrorWithCode(errors.NOT_VALID_BEFORE);

		expect(validResult.payload).toEqual({
			...JWT_DATA,
			iat: 5,
			nbf: 605,
		});
	});

	it("malformed token", async () => {
		const result = await fromPromise(verifier.verify("malformedtoken"));
		expect(result.isLeft()).toBe(true);
		expect(result.value).toBeErrorWithCode(errors.MALFORMED);
	});

	it("invalid subject", async () => {
		const token = await signer.sign(JWT_DATA, {
			subject: "foo",
			keyId: "k1",
		});

		const validResult = await verifier.verify(token, {
			subject: "foo",
		});

		const invalidResult = await fromPromise(
			verifier.verify(token, {
				subject: "bar",
			})
		);

		expect(validResult.payload).toEqual({
			...JWT_DATA,
			sub: "foo",
			iat: 5,
		});

		expect(invalidResult.isLeft()).toBe(true);
		expect(invalidResult.value).toBeErrorWithCode(errors.INVALID_SUBJECT);
	});

	describe("invalid key", () => {
		it("missing key", async () => {
			const token = _sign(JWT_DATA, "private-key", {
				expiresIn: 1000,
			});

			const invalidResult = await fromPromise(verifier.verify(token));
			expect(invalidResult.isLeft()).toBe(true);
			expect(invalidResult.value).toBeErrorWithCode(errors.INVALID_KEY_ID);
		});

		it("key that does not exist", async () => {
			const token = await signer.sign(JWT_DATA, {
				expiresIn: Duration.fromObject({ seconds: 10 }),
				keyId: "k1",
			});

			const newKeyRing = new KeyRing().addKey("k3", secret("some-secret"));
			const newVerifier = new JWTVerifier({
				secretProvider: createSecretProviderForKeyRing(newKeyRing),
			});

			const result = await fromPromise(newVerifier.verify(token));
			expect(result.isLeft()).toBe(true);
			expect(result.value).toBeErrorWithCode(errors.INVALID_KEY_ID);
		});
	});
});
