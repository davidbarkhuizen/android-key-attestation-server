import { pki, asn1 } from 'node-forge';
//import * as asn1js from 'asn1js';

export const attestHardwareKey = async (
    challenge: String,
    certChainDER: Array<string>
) => {

    const certs = certChainDER.map(it => {

        const buffer = Buffer.from(it, 'hex');
        const cert = pki.certificateFromAsn1(asn1.fromDer(buffer.toString('binary')));
        console.log(cert);
    })

};