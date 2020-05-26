import {createRequest} from 'node-mocks-http';
import {SimpleToken} from "./SimpleToken";
import {header} from "@src/header";

describe('header', () => {
    const NAME = 'headerName';

    const VALUE = 'value';


    it('uses factory if header present', () => {
        const request = createRequest({
            headers: {
                headername: VALUE
            }
        });

        expect(header(SimpleToken.factory, 'headerName')(request))
            .toStrictEqual(
                new SimpleToken(VALUE)
            );
    });

    it('returns undefined if header not available', () => {
        const request = createRequest({});
        expect(header(SimpleToken.factory, 'headerName')(request))
            .toBeUndefined();
    });
});