import { CachedVerifier } from "@src/CachedVerifier";
import { JWT } from "@src/JWT";
import { JWTVerifier } from "@src/JWTVerifier";
import { errors } from "@src/errors";
import { Either, fromPromise } from "@sweet-monads/either";
import { LRUCache } from "lru-cache";
import { Duration } from "luxon";
import * as sinon from "sinon";

import { SecurityTokenError } from "@pallad/security-tokens";

const VERIFY_OPTIONS = {
	subject: "any",
};
const CURRENT_TIMESTAMP = 60;
const DURATION = Duration.fromObject({ seconds: 100 });

const TOKEN = "some-random-jwt-token";
describe("CachedVerifier", () => {
	let verifier: CachedVerifier<any>;
	let rawVerifier: sinon.SinonStubbedInstance<JWTVerifier>;
	let cache: LRUCache<string, Either<SecurityTokenError, any>>;

	let timer: sinon.SinonFakeTimers;

	function createVerifier(options?: Partial<CachedVerifier.Options>) {
		return new CachedVerifier(rawVerifier, cache, {
			verifyOptions: VERIFY_OPTIONS,
			...options,
		});
	}

	beforeEach(() => {
		rawVerifier = sinon.createStubInstance(JWTVerifier);

		cache = new LRUCache({
			max: 10000,
			allowStale: false,
		});

		verifier = createVerifier();
		timer = sinon.useFakeTimers(1000 * CURRENT_TIMESTAMP);
	});

	afterEach(() => {
		timer.restore();
	});

	it("success result", async () => {
		const RESULT: JWT<any> = {
			header: {
				alg: "HS256",
				typ: "JWT",
			},
			payload: {
				exp: CURRENT_TIMESTAMP + DURATION.as("seconds"),
				sub: "any",
			},
			signature: "signature",
		};
		rawVerifier.verify.withArgs(TOKEN, VERIFY_OPTIONS).resolves(RESULT);
		const result = await verifier.verify(TOKEN);
		expect(result).toBeDefined();
		sinon.assert.calledOnce(rawVerifier.verify);

		timer.tick(DURATION.as("milliseconds") - 100);
		const result2 = await verifier.verify(TOKEN);
		expect(result2).toBeDefined();
		sinon.assert.calledOnce(rawVerifier.verify);
	});

	describe("error result", () => {
		it("by default not cached", async () => {
			rawVerifier.verify.rejects(errors.EXPIRED.create());

			const verifyResult1 = await fromPromise(verifier.verify(TOKEN));
			expect(verifyResult1.isLeft()).toBe(true);
			expect(verifyResult1.value).toBeErrorWithCode(errors.EXPIRED);

			const verifyResult2 = await fromPromise(verifier.verify(TOKEN));
			expect(verifyResult2.isLeft()).toBe(true);
			expect(verifyResult2.value).toBeErrorWithCode(errors.EXPIRED);

			sinon.assert.calledTwice(rawVerifier.verify);
		});

		it("error cache enabled", async () => {
			rawVerifier.verify.rejects(errors.EXPIRED.create());
			const verifier = createVerifier({ cacheError: true });

			const verifyResult1 = await fromPromise(verifier.verify(TOKEN));
			expect(verifyResult1.isLeft()).toBe(true);
			expect(verifyResult1.value).toBeErrorWithCode(errors.EXPIRED);

			const verifyResult2 = await fromPromise(verifier.verify(TOKEN));
			expect(verifyResult2.isLeft()).toBe(true);
			expect(verifyResult2.value).toBeErrorWithCode(errors.EXPIRED);

			sinon.assert.calledOnce(rawVerifier.verify);
		});

		it("error cache disabled", async () => {
			rawVerifier.verify.rejects(errors.EXPIRED.create());
			const verifier = createVerifier({ cacheError: false });

			const verifyResult1 = await fromPromise(verifier.verify(TOKEN));
			expect(verifyResult1.isLeft()).toBe(true);
			expect(verifyResult1.value).toBeErrorWithCode(errors.EXPIRED);

			const verifyResult2 = await fromPromise(verifier.verify(TOKEN));
			expect(verifyResult2.isLeft()).toBe(true);
			expect(verifyResult2.value).toBeErrorWithCode(errors.EXPIRED);

			sinon.assert.calledTwice(rawVerifier.verify);
		});
	});
});
