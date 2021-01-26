import { Token } from '@pallad/security-tokens';

export class TokenSimple<TValue = string, TPurpose extends string = string> extends Token {
  constructor(readonly value: TValue, readonly purpose?: TPurpose) {
    super();
    Object.freeze(this);
  }
}
