import * as sinon from 'sinon';
import {decode as _decode, sign as _sign} from 'jsonwebtoken';
import {errors} from '@src/errors';
import {secret} from "@pallad/secret";
import {JWTHelper} from "@src/JWTHelper";

import {fromPromise} from '@sweet-monads/either';
import {Duration} from 'luxon';
import {KeyRing} from "@pallad/keyring";

describe('JWTHelper', () => {
	let tool: JWTHelper;

	let timer: sinon.SinonFakeTimers;
	let keyRing: KeyRing;

	const ALGORITHM = 'HS512';
	const DATA = {
		some: 'data',
		to: 'sign'
	};

	function decode(token: string): any {
		return _decode(token, {complete: true});
	}

	beforeEach(() => {
		keyRing = new KeyRing()
			.addKey('k1', secret('rrJLFNm7FvelkhYrqWP7P08cJMX0IvcMLgkINt9wAEJZnMnGwt3sP6ZozotO'))
			.addKey('k2', secret('uphSbURwF2Xqtfa3OWwIX9b34NCz3jWc9CTDKZaomewnTotYswoVe1Ci5pyL'))
		tool = new JWTHelper(ALGORITHM, keyRing);

		timer = sinon.useFakeTimers(5000);
	});

	afterEach(() => {
		timer.restore();
	});

	it('sanity check', async () => {
		const token = await tool.sign(DATA);
		const newData = await tool.verify(token);

		expect(newData)
			.toEqual({
				...DATA,
				iat: 5
			});
	});

	it('signing', async () => {
		const token = await tool.sign(DATA, {
			subject: 'access-token',
			jwtid: '100',
			expiresIn: Duration.fromDurationLike({seconds: 2})
		});

		const decoded = decode(token);

		expect(decoded)
			.toMatchObject({
				header: {
					alg: ALGORITHM,
					typ: 'JWT',
					kid: expect.toBeOneOf(['k1', 'k2'])
				},
				payload: {
					...DATA,
					iat: 5,
					exp: 7,
					sub: 'access-token',
					jti: '100'
				},
				signature: expect.toBeString()
			});
	});

	it('expiration', async () => {
		const duration = Duration.fromObject({minutes: 10});
		const token = await tool.sign(DATA, {
			expiresIn: duration
		});

		expect(await tool.verify(token))
			.toEqual({
				...DATA,
				iat: 5,
				exp: 605
			});

		timer.tick(duration.as('milliseconds'));

		const invalidResult = await fromPromise(tool.verify(token));
		expect(invalidResult.isLeft()).toBe(true);
		expect(invalidResult.value).toBeErrorWithCode(errors.EXPIRED);
	});

	it('not before', async () => {
		const duration = Duration.fromObject({minutes: 10});
		const token = await tool.sign(DATA, {
			notBefore: duration
		});

		const invalidResult = await fromPromise(tool.verify(token));
		timer.tick(duration.as('milliseconds'));
		const validResult = await tool.verify(token);

		expect(invalidResult.isLeft()).toBe(true);
		expect(invalidResult.value)
			.toBeErrorWithCode(errors.NOT_VALID_BEFORE);

		expect(validResult)
			.toEqual({
				...DATA,
				iat: 5,
				nbf: 605
			});
	});

	it('malformed token', async () => {
		const result = await fromPromise(tool.verify('malformedtoken'));
		expect(result.isLeft()).toBe(true);
		expect(result.value).toBeErrorWithCode(errors.MALFORMED);
	});

	it('invalid subject', async () => {
		const token = await tool.sign(DATA, {
			subject: 'foo'
		});

		const validResult = await tool.verify(token, {
			subject: 'foo'
		});

		const invalidResult = await fromPromise(tool.verify(token, {
			subject: 'bar'
		}));

		expect(validResult)
			.toEqual({
				...DATA,
				sub: 'foo',
				iat: 5
			});

		expect(invalidResult.isLeft()).toBe(true);
		expect(invalidResult.value).toBeErrorWithCode(errors.INVALID_SUBJECT);
	});

	describe('invalid key', () => {
		it('missing key', async () => {
			const token = _sign(DATA, 'private-key', {
				expiresIn: 1000
			});

			const invalidResult = await fromPromise(tool.verify(token));
			expect(invalidResult.isLeft()).toBe(true);
			expect(invalidResult.value).toBeErrorWithCode(
				errors.INVALID_KEY_ID
			);
		});

		it('key that does not exist', async () => {
			const token = await tool.sign(DATA, {
				expiresIn: Duration.fromObject({seconds: 10})
			});

			const newKeyRing = new KeyRing()
				.addKey('k3', secret('some-secret'))
			const newTool = new JWTHelper(ALGORITHM, newKeyRing);

			const result = await fromPromise(newTool.verify(token));
			expect(result.isLeft()).toBe(true);
			expect(result.value).toBeErrorWithCode(
				errors.INVALID_KEY_ID
			);
		});
	});
});
