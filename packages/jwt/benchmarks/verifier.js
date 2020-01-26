const Benchmark = require('benchmark');
const {CachedVerifier, JWTHelper} = require('../compiled');
const {randomBytes} = require('crypto');
const {secret} = require('@pallad/secret');
const LRUCache = require("lru-cache");
const moment = require("moment");

const helper = new JWTHelper('HS384', {key1: secret(randomBytes(60).toString('utf8'))})
const cached = new CachedVerifier({
    helper,
    cache: new LRUCache({
        maxAge: 100000,
        max: 1000000,

    }),
    verifyOptions: {subject: 'none'},
    options: {}
});

(async () => {
    const token = await helper.sign({some: 'data'}, {
        expires: moment.duration(1, 'hour'),
        subject: 'none'
    });

    (new Benchmark.Suite())
        .add('cached', async () => {
            await cached.verify(token);
        })
        .add('regular', async () => {
            await helper.verify(token);
        })
        .on('complete', function () {
            for (let i = 0; i < this.length; i++) {
                const test = this[i];
                console.log(test.toString());
            }
            console.log('Fastest is ' + this.filter('fastest').map('name'));
        })
        .run({async: true});
})();
