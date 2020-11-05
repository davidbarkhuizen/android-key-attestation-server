import { pki, asn1 } from 'node-forge';
import { pemFromDer } from './crypto';
import { IX509CertFromPKICert } from './x509';

export const attestHardwareKey = async (
    challenge: String,
    certChainDER: Array<string>,
    validGoogleRootCertsDER: Array<string>,
) => {

    console.log('HW key attestation');

    const certChain = certChainDER
        .map(der => ({
            der,
            pki: pki.certificateFromAsn1(asn1.fromDer(Buffer.from(der, 'hex').toString('binary'))),
            pem: pemFromDer(der)
        }))
        .map(it => ({ ...it,
            ix509: IX509CertFromPKICert(it.pki)
        }));

    console.log(`${certChainDER.length} certs in chain`);

    const rootCert = certChain.find(it => it.ix509.issuerDN == it.ix509.subjectDN);
    console.log(`root cert: ${rootCert.ix509.subjectDN}`);

    // verify self-signature of root cert
    //
    let rootSigVerified = false;
    try {
        const caStore = pki.createCaStore([ rootCert.pem ]);
        rootSigVerified = pki.verifyCertificateChain(caStore, [ rootCert.pki ]);
    } catch (e) {
        console.log(`error during verification of self-signature of ${rootCert.ix509.subjectDN}: ${e}`)
    }
    console.log(`${rootSigVerified ? 'verified' : 'failed to verify'} self-signature of ${rootCert.ix509.subjectDN} root cert`)
    
    if (!rootSigVerified) {
        return false;
    }

    // confirm root cert as known
    //
    const isKnownValidRootCert = validGoogleRootCertsDER.includes(rootCert.der);
    console.log(`root cert ${isKnownValidRootCert ? "is": "is not"} a known valid Google root HW attestation cert`);
    
    if (!isKnownValidRootCert) {
        return false;
    }

    const sorted = [rootCert];
    let remainder = certChain.filter(it => it != rootCert);

    // sort chain, verifying signatures
    //
    while (sorted.length < certChain.length) {
        const parent = sorted[sorted.length - 1];
        const child = remainder.find(it => it.ix509.issuerDN == parent.ix509.subjectDN);
        if (child === undefined) {
            console.log(`break in chain: ${parent.ix509.subjectDN} has no child, yet ${remainder.length} unprocessed certs remain`);
            return false;
        }
        sorted.push(child);
        remainder = remainder.filter(it => it != child);

        // verify signature
        //
        let sigVerified = false;
        try {
            const caStore = pki.createCaStore([ parent.pem ]);
            sigVerified = pki.verifyCertificateChain(caStore, [ child.pki ]);
        } catch (e) {
            console.log(`error during verification of signature of cert ${child.ix509.subjectDN}: ${e}`)
            return false;
        }

        console.log(`${sigVerified ? 'verified' : 'failed to verify'} ${child.ix509.subjectDN} signed by ${parent.ix509.subjectDN}`)
    }

    // check temporal validity of certs
    //
    const now = new Date();
    console.log(`checking temporal validity`);
    for(const cert of sorted) {

        let invalidBecauseOfDate = false;

        const notBefore = cert.pki.validity.notBefore;
        if (notBefore > now) {
            invalidBecauseOfDate = true;
            console.log(`cert is not yet valid as of ${now} - notBefore = ${notBefore})`);      
        }

        const notAfter = cert.pki.validity.notAfter;
        if (notAfter < now) {
            invalidBecauseOfDate = true;
            console.log(`cert has expired (notAfter: ${notAfter})`);
        }

        if (invalidBecauseOfDate) {
            console.log(`cert ${cert.ix509.subjectDN} is not yet valid as of ${now}`)
            return false;
        }
    }
    console.log(`all certs are valid as of ${now}`);

    console.log('HW key attestation cert chain:');
    sorted.forEach((it, index) => {
        console.log(`${index}: ${it.ix509.subjectDN}`);
        console.log(it.ix509);
    })

    return null;
};