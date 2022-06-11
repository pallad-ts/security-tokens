import {Secret} from "@pallad/secret";
import {Algorithm, sign, SignOptions, verify, VerifyOptions} from "jsonwebtoken";
import {promisify} from "util";
import * as moment from "moment";
import {errors} from "./errors";

export class JWTHelper {
    constructor(private algorithm: Algorithm,
                private privateKeys: Record<string, Secret<string>>) {

    }

    sign<T>(data: T, options: JWTHelper.SignOptions = {}): Promise<string> {
        const [keyId, privateKey] = this.getRandomKey();
        const signOptions: SignOptions = {
            algorithm: this.algorithm,
            keyid: keyId,
        };

        if (options.id) {
            signOptions.jwtid = options.id;
        }

        if (options.subject) {
            signOptions.subject = options.subject;
        }

        if (options.expires) {
            signOptions.expiresIn = options.expires.asSeconds()
        }

        if (options.notBefore) {
            signOptions.notBefore = options.notBefore.asSeconds()
        }

        return promisify<any, string, SignOptions, string>(sign)({
            ...data,
        }, privateKey, signOptions);
    }

    private getRandomKey(): [string, string] {
        const keys = Object.keys(this.privateKeys);
        const key = keys[Math.floor(Math.random() * keys.length)];

        return [key, this.privateKeys[key].getValue()];
    }

    async verify<T>(token: string, options: JWTHelper.VerifyOptions = {}): Promise<T> {
        try {
            const result = await promisify<string, any, VerifyOptions, T>(verify)(
                token,
                this.getPrivateKeyForHeader.bind(this),
                {
                    algorithms: [this.algorithm],
                    subject: options.subject
                }
            );

            return result;
        } catch (e: any) {
            switch (true) {
                case e.name === 'TokenExpiredError':
                    throw errors.EXPIRED();

                case e.name === 'NotBeforeError':
                    throw errors.NOT_VALID_BEFORE();

                case /secret or public key callback/.test(e.message):
                    throw errors.INVALID_KEY_ID();

                case /malformed/.test(e.message):
                    throw errors.MALFORMED();

                case /subject invalid/.test(e.message):
                    throw errors.INVALID_SUBJECT();
            }
            throw e;
        }
    }

    private getPrivateKeyForHeader(header: any, callback: (error?: Error, key?: string) => void) {
        if (!header.kid) {
            callback(errors.INVALID_KEY_ID());
            return;
        }

        const privateKey = this.privateKeys[header.kid];
        if (!privateKey) {
            callback(errors.INVALID_KEY_ID());
            return;
        }

        callback(undefined, privateKey.getValue());
    }
}

export namespace JWTHelper {
    export interface SignOptions {
        expires?: moment.Duration;
        notBefore?: moment.Duration;
        id?: string;
        subject?: string;
    }

    export interface VerifyOptions {
        subject?: string;
    }
}
