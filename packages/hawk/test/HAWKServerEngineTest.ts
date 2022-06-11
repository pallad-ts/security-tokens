import * as http from "http";
import {json} from 'body-parser';
import * as sinon from 'sinon';
import {CredentialsStorage} from "@src/CredentialsStorage";
import {secret} from "@pallad/secret";
import {HAWKServerEngine} from "@src/HAWKServerEngine";
import {TokenHAWK} from "@src/TokenHAWK";
import {request} from 'undici';
import {client} from 'hawk';
import {Either} from "monet";


describe('HAWKServerEngine', () => {
	let server: http.Server;
	let handler: sinon.SinonStub;
	let engine: HAWKServerEngine;
	const URL = `http://localhost:10000/some-path`;

	const credentialsStorage = new CredentialsStorage('sha256');
	credentialsStorage.registerCredential('1', secret('k1'), 'u1');
	credentialsStorage.registerCredential('2', secret('k2'), 'u2');

	beforeEach(() => {
		handler = sinon.stub();
		server = http.createServer((req, res) => {
			json()(req, res, () => {
				handler(req, res);
			});
		});
		server.listen(10000);
		engine = new HAWKServerEngine(credentialsStorage);
	});

	afterEach((done) => {
		server.close(done);
	});

	describe('verification with payload', () => {
		it('simple', async () => {
			let result: Promise<TokenHAWK> | undefined;
			handler.callsFake(async (req, res) => {
				result = engine.verifyWithPayload(req);
				res.end();
			});

			const payload = Buffer.from('somepayloaddata', 'utf-8');

			const {header} = client.header(URL, 'POST', {
				contentType: 'application/octet-stream',
				payload: payload as any,
				credentials: {id: '1', ...credentialsStorage.retrieveCredentials('1')}
			});

			await request(URL, {
				method: 'POST',
				headers: {Authorization: header, 'content-type': 'application/octet-stream'},
				body: payload
			});

			const resolvedResult = await result;
			expect(resolvedResult)
				.toBeInstanceOf(TokenHAWK);

			expect(resolvedResult)
				.toHaveProperty('user', 'u1');
		});

		it('simple that fails', async () => {
			let result: Promise<Either<unknown, unknown>> | undefined;
			handler.callsFake(async (req, res) => {
				res.end();
				result = Either.fromPromise(engine.verifyWithPayload(req));
			});

			const {header} = client.header(URL, 'POST', {
				contentType: 'application/octet-stream',
				payload: Buffer.from('somepayloaddata', 'utf-8') as any,
				credentials: {id: '1', ...credentialsStorage.retrieveCredentials('1')}
			});

			await request(URL, {
				method: 'POST',
				headers: {Authorization: header, 'content-type': 'application/octet-stream'},
				body: Buffer.from('completely different payload')
			});

			const resolvedResult = await result;

			expect(resolvedResult)
				.toMatchSnapshot();
		});
	});
});
