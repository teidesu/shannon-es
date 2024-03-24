import { describe, it, expect } from 'vitest'

import { Shannon } from './index.js'

const key = new Uint8Array([0x65, 0x87, 0xd8, 0x8f, 0x6c, 0x32, 0x9d, 0x8a, 0xe4, 0x6b]);

describe('Test Shannon', function() {
    it('Test Shannon Encrypt', function () {
        let plaintext = new TextEncoder().encode('Hello World');

        let s = new Shannon(key);
        let encryptedtext = s.encrypt(plaintext);
        let mac = s.finish(new Uint8Array(16));

        expect(encryptedtext).to.deep.equal(new Uint8Array([0x94, 0x81, 0xe5, 0xa9, 0x5f, 0x93, 0x5e, 0xcb, 0x6c, 0xb5, 0x24]));
        expect(mac).to.deep.equal(new Uint8Array([0x43, 0x23, 0x86, 0x24, 0xf3, 0xc9, 0x0c, 0x58, 0x79, 0xf4, 0xd3, 0xef, 0x83, 0x98, 0x2e, 0x4e]));
    });

    it('Test Shannon (from librespot)', function () {
        let data = Buffer.from('ab0072520e5203313233a00100f201033132339203495000e00302d2051a6c6962726573706f742d346433356335662d4652773755634838a2062430653163653938352d373332612d346335642d613338372d303731333964653739343065b204136c6962726573706f7420302e352e302d646576', 'hex')
        let key = Buffer.from('1625a18398e0b5ae1fcd71eaeda23008e4446c38a0865de6251cade7192383cc', 'hex')
        
        let s = new Shannon(key);
        s.nonce32(0)
        s.encrypt(data);
        let mac = s.finish(4);

        expect(data.toString('hex')).to.deep.equal('e9eb002d485b299ea13d434cd1debeee16180967e0722aa308914f3deffda865ac106cb77ca21b5345c7656fb0617351ace5c95d4880eaeae3b885ffe4c037ba2a925ab48ed997dd8a32effc491b1c2fc761f937825c19f35180b31ddda77fa7323d7de6154671971f4daf544edb160094e7cadd44');
        expect(mac).to.deep.equal(new Uint8Array([0xb5, 0x11, 0xbc, 0x3a]));
    });

    it('Test Shannon Decrypt', function () {
    	let encryptedtext = new Uint8Array([0x94, 0x81, 0xe5, 0xa9, 0x5f, 0x93, 0x5e, 0xcb, 0x6c, 0xb5, 0x24]);
    	let mac = new Uint8Array([0x43, 0x23, 0x86, 0x24, 0xf3, 0xc9, 0x0c, 0x58, 0x79, 0xf4, 0xd3, 0xef, 0x83, 0x98, 0x2e, 0x4e]);

        let s = new Shannon(key);
        let buf = s.decrypt(encryptedtext);
        let expectedMac = s.finish(new Uint8Array(16));

        expect(new TextDecoder().decode(buf)).to.deep.equal('Hello World');
        expect(mac).to.deep.equal(expectedMac);
    });
});
