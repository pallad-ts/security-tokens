import {createRequest} from 'node-mocks-http';
import {bearerHeader} from "@src/bearerHeader";
import {SimpleToken} from "./SimpleToken";

describe('bearerHeader', () => {
    const VALUE = 'SomePayload';

    describe('prefix', () => {
        it('be default uses "Bearer"', () => {
            const request = createRequest({
                headers: {
                    authorization: `Bearer ${VALUE}`
                }
            });

            expect(bearerHeader(SimpleToken.factory)(request))
                .toStrictEqual(
                    new SimpleToken(VALUE)
                );
        });

        it('ignores value is does not start with given prefix', () => {
            const request = createRequest({
                headers: {
                    authorization: `test ${VALUE}`
                }
            });

            expect(bearerHeader(SimpleToken.factory)(request))
                .toBeUndefined()
        })
    });

    it('returns nothing if header does not exist', () => {
        const request = createRequest();

        expect(bearerHeader(SimpleToken.factory)(request))
            .toBeUndefined();
    });

    it('returns nothing if header contains multiple values', () => {
        const request = createRequest({
            headers: {
                test: [VALUE, 'foo']
            }
        });

        expect(bearerHeader(SimpleToken.factory, {header: 'test'})(request))
            .toBeUndefined();
    });
});