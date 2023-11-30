import * as sinon from 'sinon';
import {decode as _decode, sign as _sign} from 'jsonwebtoken';
import moment = require("moment");
import {errors} from '@src/errors';
import {secret} from "@pallad/secret";
import {JWTHelper} from "@src/JWTHelper";
import {left, right, fromPromise} from '@sweet-monads/either';

describe('JWTHelper', () => {
	let tool: JWTHelper;

	let timer: sinon.SinonFakeTimers;

	const ALGORITHM = 'HS512';
	const DATA = {
		some: 'data',
		to: 'sign'
	};

	function decode(token: string): any {
		return _decode(token, {complete: true});
	}

	beforeEach(() => {
		tool = new JWTHelper(ALGORITHM, {
			k1: secret('rrJLFNm7FvelkhYrqWP7P08cJMX0IvcMLgkINt9wAEJZnMnGwt3sP6ZozotO'),
			k2: secret('uphSbURwF2Xqtfa3OWwIX9b34NCz3jWc9CTDKZaomewnTotYswoVe1Ci5pyL')
		});

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
			id: '100',
			expires: moment.duration(2, 'seconds')
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
		const duration = moment.duration(10, 'minutes');
		const token = await tool.sign(DATA, {
			expires: duration
		});

		expect(await tool.verify(token))
			.toEqual({
				...DATA,
				iat: 5,
				exp: 605
			});

		timer.tick(duration.asMilliseconds());

		const invalidResult = await fromPromise(tool.verify(token));
		expect(invalidResult.isLeft()).toBe(true);
		expect(invalidResult.value).toBeErrorWithCode(errors.EXPIRED);
	});

	it('not before', async () => {
		const duration = moment.duration(10, 'minutes');
		const token = await tool.sign(DATA, {
			notBefore: duration
		});

		const invalidResult = await fromPromise(tool.verify(token));
		timer.tick(duration.asMilliseconds());
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
				expires: moment.duration(10, 'seconds')
			});

			const newTool = new JWTHelper(ALGORITHM, {
				k3: secret('some-secret')
			});

			const result = await fromPromise(newTool.verify(token));
			expect(result.isLeft()).toBe(true);
			expect(result.value).toBeErrorWithCode(
				errors.INVALID_KEY_ID
			);
		});
	});
});
