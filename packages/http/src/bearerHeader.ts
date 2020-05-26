import {TokenFactory} from "./TokenFactory";
import {Token} from "@pallad/security-tokens";

export function bearerHeader(factory: (x: string) => Token, userOpts: bearerHeader.Options.FromUser = {}): TokenFactory.Rule {
    const options = {
        ...bearerHeader.Options.DEFAULT,
        ...userOpts
    };

    return (request) => {
        const header = request.headers[options.header.toLowerCase()];
        if (!header) {
            return;
        }

        if (Array.isArray(header)) {
            return;
        }

        if (header.startsWith(options.prefix)) {
            const value = header.slice(options.prefix.length);
            return factory(value);
        }
    }
}

export namespace bearerHeader {
    export interface Options {
        prefix: string,
        header: string;
    }

    export namespace Options {
        export type FromUser = Partial<Options>;

        export const DEFAULT = {
            prefix: 'Bearer ',
            header: 'authorization'
        };
    }
}
