import { pki, asn1 } from 'node-forge';
import { pemFromDer } from './crypto';

interface IX509Cert {
    version: Number,
    serialNumber: string,
    signature: string,
    // siginfo: { algorithmOid: '1.2.840.113549.1.1.11', parameters: {} },
    sigAlgoOID: string
    validity: {
        notBefore: Date,
        notAfter: Date
      },
    issuerDN: string,
    subjectDN: string,
    CA: boolean,
    keyUsage: {
        digitalSignature: boolean,
        nonRepudiation: boolean,
        keyEncipherment: boolean,
        dataEncipherment: boolean,
        keyAgreement: boolean,
        keyCertSign: boolean,
        cRLSign: boolean,
        encipherOnly: boolean,
        decipherOnly: boolean
    }

    /*
     extensions: [
    {
      id: '2.5.29.15',
      critical: true,
      value: '\x03\x02\x01\x86',
      name: 'keyUsage',
      digitalSignature: true,
      nonRepudiation: false,
      keyEncipherment: false,
      dataEncipherment: false,
      keyAgreement: false,
      keyCertSign: true,
      cRLSign: true,
      encipherOnly: false,
      decipherOnly: false
    },
    {
      id: '2.5.29.31',
      critical: false,
      value: '0705 3 1\x86/https://android.googleapis.com/attestation/crl/',
      name: 'cRLDistributionPoints'
    }
  ],
  */
}

export const IX509CertFromPKICert = (cert: pki.Certificate): IX509Cert => {

    const basicConstraintsExt = cert.extensions.filter(it => it.name == 'basicConstraints')
    const ca = basicConstraintsExt.length > 0 && basicConstraintsExt[0].cA == true

    const keyUsageExt = cert.extensions.filter(it => it.name == 'keyUsage')[0]

    return {
        version: cert.version,
        serialNumber: cert.serialNumber,
        signature: Buffer.from(cert.signature).toString('hex').substring(0, 20) + '...',
        validity: {
            notBefore: cert.validity.notBefore,
            notAfter: cert.validity.notAfter
        },
        issuerDN: cert.issuer.attributes
            .map(attr => [attr.shortName, attr.value].filter(it => it != null).join('='))
            .join(', '),
        subjectDN: cert.subject.attributes
            .map(attr => [attr.shortName, attr.value].filter(it => it != null).join('='))
            .join(', '),
        sigAlgoOID: cert.siginfo.algorithmOid,
        CA: ca,
        keyUsage: {
            digitalSignature: keyUsageExt.digitalSignature,
            nonRepudiation: keyUsageExt.nonRepudiation,
            keyEncipherment: keyUsageExt.keyEncipherment,
            dataEncipherment: keyUsageExt.dataEncipherment,
            keyAgreement: keyUsageExt.keyAgreement,
            keyCertSign: keyUsageExt.keyCertSign,
            cRLSign: keyUsageExt.cRLSign,
            encipherOnly: keyUsageExt.encipherOnly,
            decipherOnly: keyUsageExt.decipherOnly,
        }
    }
}

export const attestHardwareKey = async (
    challenge: String,
    certChainDER: Array<string>
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

    // verify signature
    //
    let rootSigVerified = false;
    try {
        const caStore = pki.createCaStore([ rootCert.pem ]);
        rootSigVerified = pki.verifyCertificateChain(caStore, [ rootCert.pki ]);
    } catch (e) {
        console.log(`error during verification of self-signature of ${rootCert.ix509.subjectDN}: ${e}`)
    }
    console.log(`self-signature of ${rootCert.ix509.subjectDN} root verified ${rootSigVerified}`)

    // TODO check against stored list of acceptable google certs

    const sorted = [rootCert];
    let remainder = certChain.filter(it => it != rootCert);

    // TODO verify self-signature

    while (sorted.length < certChain.length) {
        const parent = sorted[sorted.length - 1];
        const child = remainder.find(it => it.ix509.issuerDN == parent.ix509.subjectDN);
        if (child === undefined) {
            throw `break in chain: non-leaf cert ${parent.ix509.subjectDN} has no child`
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
        }

        console.log(`signature of ${child.ix509.subjectDN} by ${parent.ix509.subjectDN}: verified ${sigVerified}`)
    }

    console.log('HW key attestation cert chain:');
    sorted.forEach((it, index) => {
        console.log(`${index}: ${it.ix509.subjectDN}`);
    })

    return null;
};