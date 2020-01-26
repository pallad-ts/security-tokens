export abstract class Token {};

export namespace Token {
    export class None extends Token {

    }

    export const NONE = new None();
}