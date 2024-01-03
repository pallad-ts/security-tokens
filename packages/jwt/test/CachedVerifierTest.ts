import {CachedVerifier} from "@src/CachedVerifier";
import * as sinon from 'sinon';
import {JWTHelper} from "@src/JWTHelper";
import LRUCache = require("lru-cache");
import {SecurityTokenError} from "@pallad/security-tokens";
import {errors} from "@src/errors";
import {secret} from "@pallad/secret";
import {Either, fromPromise} from "@sweet-monads/either";
import {Duration} from "luxon";
import {KeyRing} from "@pallad/keyring";

describe('CachedVerifier', () => {
	let verifier: CachedVerifier;
	let helper: JWTHelper;
	let cache: LRUCache<string, Either<any, SecurityTokenError>>;

	let timer: sinon.SinonFakeTimers;

	const VERIFY_OPTIONS = {
		subject: 'any'
	};
	const CURRENT_TIMESTAMP = 60;
	const DURATION = Duration.fromObject({seconds: 100});

	function createVerifier(options?: CachedVerifier.Options<any>['options']) {
		return new CachedVerifier({
			helper: helper as any,
			cache: cache as any,
			verifyOptions: VERIFY_OPTIONS,
			options
		});
	}

	function createData(exp: number) {
		return {
			exp,
			foo: 'bar'
		};
	}

	function createToken(expiresIn: Duration) {
		return helper.sign({foo: 'bar'}, {
			subject: 'any',
			expiresIn
		});
	}

	beforeEach(() => {
		const keyRing = new KeyRing()
			.addKey('k1', secret('testPrivateKey'));

		helper = new JWTHelper('HS512', keyRing);
		cache = new LRUCache({
			max: 10000,
			ttl: 10000,
			allowStale: false
		});

		verifier = createVerifier();
		timer = sinon.useFakeTimers(1000 * CURRENT_TIMESTAMP);
	});

	afterEach(() => {
		timer.restore();
	});

	describe('error result', () => {
		it('by default not cached', async () => {
			const spy = sinon.spy(helper, 'verify');
			const token = await createToken(Duration.fromObject({seconds: 100}));

			timer.tick(DURATION.as('milliseconds'));


			const verifyResult1 = await fromPromise(verifier.verify(token));
			expect(verifyResult1.isLeft()).toBe(true);
			expect(verifyResult1.value).toBeErrorWithCode(errors.EXPIRED);

			const verifyResult2 = await fromPromise(verifier.verify(token));
			expect(verifyResult2.isLeft()).toBe(true);
			expect(verifyResult2.value).toBeErrorWithCode(errors.EXPIRED);

			sinon.assert.calledTwice(spy);
		});

		it('error cache enabled', async () => {
			const verifier = createVerifier({cacheError: true});
			const spy = sinon.spy(helper, 'verify');
			const token = await createToken(Duration.fromObject({seconds: 100}));

			timer.tick(DURATION.as('milliseconds'));

			const verifyResult1 = await fromPromise(verifier.verify(token));
			expect(verifyResult1.isLeft()).toBe(true);
			expect(verifyResult1.value).toBeErrorWithCode(errors.EXPIRED)

			const verifyResult2 = await fromPromise(verifier.verify(token));
			expect(verifyResult2.isLeft()).toBe(true);
			expect(verifyResult2.value).toBeErrorWithCode(errors.EXPIRED)

			sinon.assert.calledOnce(spy);
		})
		;

		it('error cache disabled', async () => {
			const verifier = createVerifier({cacheError: false});
			const spy = sinon.spy(helper, 'verify');
			const token = await createToken(Duration.fromObject({seconds: 100}));

			timer.tick(DURATION.as('milliseconds'));

			const verifyResult1 = await fromPromise(verifier.verify(token));
			expect(verifyResult1.isLeft()).toBe(true);
			expect(verifyResult1.value).toBeErrorWithCode(errors.EXPIRED);

			const verifyResult2 = await fromPromise(verifier.verify(token));
			expect(verifyResult2.isLeft()).toBe(true);
			expect(verifyResult2.value).toBeErrorWithCode(errors.EXPIRED);

			sinon.assert.calledTwice(spy);
		});
	});
});
