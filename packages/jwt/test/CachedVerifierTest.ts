import {CachedVerifier} from "@src/CachedVerifier";
import * as sinon from 'sinon';
import {JWTHelper} from "@src/JWTHelper";
import LRUCache = require("lru-cache");
import {Either} from "monet";
import {SecurityTokenError} from "@pallad/security-tokens";
import {errors} from "@src/errors";
import {secret, Secret} from "@pallad/secret";
import * as moment from 'moment';

describe('CachedVerifier', () => {
    let verifier: CachedVerifier;
    let helper: JWTHelper;
    let cache: LRUCache<string, Either<any, SecurityTokenError>>;

    let timer: sinon.SinonFakeTimers;

    const VERIFY_OPTIONS = {
        subject: 'any'
    };
    const CURRENT_TIMESTAMP = 60;
    const DURATION = moment.duration(100, 'seconds');

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

    function createToken(expires: moment.Duration) {
        return helper.sign({foo: 'bar'}, {
            subject: 'any',
            expires
        });
    }

    beforeEach(() => {
        helper = new JWTHelper('HS512', {k1: secret('testPrivateKey')});
        cache = new LRUCache({
            max: 10000,
            maxAge: 10000
        });

        verifier = createVerifier();
        timer = sinon.useFakeTimers(1000 * CURRENT_TIMESTAMP);
    });

    afterEach(() => {
        timer.restore();
    });

    describe('success result', () => {
        it('token that still a lot of time to expire', async () => {
            const token = await createToken(DURATION);

            const data = {
                iat: CURRENT_TIMESTAMP,
                exp: CURRENT_TIMESTAMP + 100,
                foo: 'bar',
                sub: 'any'
            };

            expect(await verifier.verify(token))
                .toEqual(data);

            const stub = sinon.stub(helper, 'verify')
                .throws(new Error('should not be called'));

            // still returns old data since result is cached
            expect(await verifier.verify(token))
                .toEqual(data);

            timer.tick(DURATION.asMilliseconds());

            stub.restore();
            await expect(verifier.verify(token))
                .rejects
                .toThrowError(errors.EXPIRED.defaultMessage);
        });
    });

    describe('error result', () => {
        it('by default not cached', async () => {
            const spy = sinon.spy(helper, 'verify');
            const token = await createToken(moment.duration(100, 'seconds'));

            timer.tick(DURATION.asMilliseconds());

            expect(await Either.fromPromise(verifier.verify(token)))
                .toEqual(Either.Left(errors.EXPIRED()));

            expect(await Either.fromPromise(verifier.verify(token)))
                .toEqual(Either.Left(errors.EXPIRED()));

            sinon.assert.calledTwice(spy);
        });

        it('error cache enabled', async () => {
            const verifier = createVerifier({cacheError: true});
            const spy = sinon.spy(helper, 'verify');
            const token = await createToken(moment.duration(100, 'seconds'));

            timer.tick(DURATION.asMilliseconds());

            expect(await Either.fromPromise(verifier.verify(token)))
                .toEqual(Either.Left(errors.EXPIRED()));

            expect(await Either.fromPromise(verifier.verify(token)))
                .toEqual(Either.Left(errors.EXPIRED()));

            sinon.assert.calledOnce(spy);
        });

        it('error cache disabled', async () => {
            const verifier = createVerifier({cacheError: false});
            const spy = sinon.spy(helper, 'verify');
            const token = await createToken(moment.duration(100, 'seconds'));

            timer.tick(DURATION.asMilliseconds());

            expect(await Either.fromPromise(verifier.verify(token)))
                .toEqual(Either.Left(errors.EXPIRED()));

            expect(await Either.fromPromise(verifier.verify(token)))
                .toEqual(Either.Left(errors.EXPIRED()));

            sinon.assert.calledTwice(spy);
        });
    });
});