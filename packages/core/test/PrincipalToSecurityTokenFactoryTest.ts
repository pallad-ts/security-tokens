import { PrincipalToSecurityTokenFactory } from "@src/PrincipalToSecurityTokenFactory";
import { TokenSimple } from "@src/TokenSimple";
import { just, none } from "@sweet-monads/maybe";
import * as sinon from "sinon";

const PRINCIPAL = { some: "principal" };

describe("PrincipalToSecurityTokenFactory", () => {
	let factory: PrincipalToSecurityTokenFactory;
	beforeEach(() => {
		factory = new PrincipalToSecurityTokenFactory();
	});

	it("uses result of first mapper that returns Just", async () => {
		const result = new TokenSimple("token", "test");

		const mapper1 = sinon.stub().returns(none());
		const mapper2 = sinon.stub().returns(just(result));
		const mapper3 = sinon.stub().returns(none());

		factory.addMapper(mapper1).addMapper(mapper2).addMapper(mapper3);

		await expect(factory.toToken(PRINCIPAL)).resolves.toBe(result);

		sinon.assert.calledWith(mapper1, PRINCIPAL);
		sinon.assert.calledWith(mapper2, PRINCIPAL);
		sinon.assert.notCalled(mapper3);
	});
});
