import { pki, asn1 } from 'node-forge';
import { pemFromDer } from './crypto';
import { IX509CertFromPKICert } from './x509';

export const attestHardwareKey = async (
    challenge: String,
    certChainDER: Array<string>,
    validGoogleRootCertsDER: Array<string>,
): Promise<string> => {

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

    console.log(`${
        certChainDER.length} certs in chain: ${
        certChain.map(it => it.ix509.subjectDN).join(', ')}`);

    const rootCerts = certChain.filter(it => it.ix509.issuerDN == it.ix509.subjectDN);
    console.log(`${
        rootCerts.length} root certs(s): ${
        rootCerts.map(it => it.ix509.subjectDN).join(', ')}`);

    if (rootCerts.length == 0) {
        return 'no self-signed root cert';
    } else if (rootCerts.length > 1) {
        return 'too many root certs';
    }

    const rootCert = rootCerts[0];
    console.log(`root cert: ${rootCert.ix509.subjectDN}`);

    // verify self-signature of root cert
    //
    let rootSigVerified = false;
    try {
        const caStore = pki.createCaStore([ rootCert.pem ]);
        rootSigVerified = pki.verifyCertificateChain(caStore, [ rootCert.pki ]);
    } catch (e) {
        console.log(`error during verification of self-signature of root cert: ${e}`);
        return e.toString(e);
    }
    console.log(`${rootSigVerified ? 'verified' : 'failed to verify'} self-signature of 0 ${rootCert.ix509.subjectDN} root cert`)
    
    if (!rootSigVerified) {
        return `failed to verify self-signature of root cert ${rootCert.ix509.subjectDN}`;
    }

    // confirm root cert as known
    //
    const isKnownValidRootCert = validGoogleRootCertsDER.includes(rootCert.der);
    console.log(`root cert ${isKnownValidRootCert ? "is": "is not"} a known valid Google root HW attestation cert`);
    
    if (!isKnownValidRootCert) {
        return `root cert ${rootCert.ix509.subjectDN} is not a known valid Google root`;
    }

    const sortedChain = [rootCert];
    let nonRootCerts = certChain.filter(it => it != rootCert);

    // sort chain, verifying signatures
    //
    let childChainIndex = 0;
    while (sortedChain.length < certChain.length) {
        const parent = sortedChain[sortedChain.length - 1];
        const child = nonRootCerts.find(it => it.ix509.issuerDN == parent.ix509.subjectDN);
        childChainIndex = childChainIndex + 1;
        if (child === undefined) {
            const error = `break in chain: ${parent.ix509.subjectDN
                } has no child, yet ${nonRootCerts.length
                } unprocessed certs remain`;
            
            console.log(error);
            return error;
        }
        sortedChain.push(child);
        nonRootCerts = nonRootCerts.filter(it => it != child);

        // verify signature
        //
        let sigVerified = false;
        try {
            const caStore = pki.createCaStore([ parent.pem ]);
            sigVerified = pki.verifyCertificateChain(caStore, [ child.pki ]);
        } catch (e) {
            const error = `error during verification of signature of cert ${child.ix509.subjectDN} by ${parent.ix509.subjectDN}: ${e}`;
            console.log(error);
            return error;
        }

        console.log(`${sigVerified ? 'verified' : 'failed to verify'} ${childChainIndex} ${child.ix509.subjectDN} signed by ${childChainIndex - 1} ${parent.ix509.subjectDN}`)
    }

    // check temporal validity of certs
    //
    const now = new Date();
    console.log(`checking temporal validity`);
    for(const cert of sortedChain) {

        const notBefore = cert.pki.validity.notBefore;
        if (notBefore > now) {
            const error = `cert ${cert.ix509.subjectDN} is not yet valid as of ${now} - notBefore = ${notBefore})`;
            console.log(error);      
            return error;
        }

        const notAfter = cert.pki.validity.notAfter;
        if (notAfter < now) {
            const error = `cert ${cert.ix509.subjectDN} has already expired (notAfter: ${notAfter})`;
            console.log(error);
            return error;
        }
    }
    console.log(`all certs are temporally valid as of ${now}`);
    
    console.log('validated cert chain:');
    sortedChain.forEach((it, index) => {

        const usages = [];
        if (it.ix509.keyUsage.cRLSign) {
            usages.push('Sign CRL');
        }
        if (it.ix509.keyUsage.dataEncipherment) {
            usages.push('Enc Data');
        }
        if (it.ix509.keyUsage.decipherOnly) {
            usages.push('Only Dec Data');
        }
        if (it.ix509.keyUsage.digitalSignature) {
            usages.push('Sign Data');
        }
        if (it.ix509.keyUsage.encipherOnly) {
            usages.push('Only Enc Data');
        }
        if (it.ix509.keyUsage.keyAgreement) {
            usages.push('Key Agreement');
        }
        if (it.ix509.keyUsage.keyCertSign) {
            usages.push('Sign Key Cert');
        }
        if (it.ix509.keyUsage.nonRepudiation) {
            usages.push('Non Repudiation');
        }

        const remainingLifetimeMinutes = 
            Math.floor(
                (it.ix509.validity.notAfter.getTime() - (new Date()).getTime()) / 1000 / 60
            );

        console.log(`${index
        } ${it.ix509.isCA ? "(CA)": "    "
        } ${it.ix509.subjectDN.padEnd(25, ' ')
        } ${remainingLifetimeMinutes} mins - ${usages.join(', ')}, `);
        // console.log(it.ix509);
    })

    const hwCert = sortedChain[sortedChain.length - 1];

    console.log(hwCert.ix509);

    return null;
};