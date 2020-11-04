import { pki, asn1 } from 'node-forge';

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

    /*
     extensions: [
    {
      id: '2.5.29.14',
      critical: false,
      value: '\x04\x146aá\x00|\x88\x05\tQ\x8BDlGÿ\x1ALÉêO\x12',
      name: 'subjectKeyIdentifier',
      subjectKeyIdentifier: '3661e1007c880509518b446c47ff1a4cc9ea4f12'
    },
    {
      id: '2.5.29.35',
      critical: false,
      value: '0\x16\x80\x146aá\x00|\x88\x05\tQ\x8BDlGÿ\x1ALÉêO\x12',
      name: 'authorityKeyIdentifier'
    },
    {
      id: '2.5.29.19',
      critical: true,
      value: '0\x03\x01\x01ÿ',
      name: 'basicConstraints',
      cA: true
    },
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

    console.log(typeof cert.signature)

    return {
        version: cert.version,
        serialNumber: cert.serialNumber,
        signature: Buffer.from(cert.signature).toString('hex'),
        validity: {
            notBefore: cert.validity.notBefore,
            notAfter: cert.validity.notAfter
        },
        issuerDN: cert.issuer.attributes
            .map(attr => [attr.shortName, attr.value].join('='))
            .join(', '),
        subjectDN: cert.subject.attributes
            .map(attr => [attr.shortName, attr.value].join('='))
            .join(', '),
        sigAlgoOID: cert.siginfo.algorithmOid
    }
}

export const attestHardwareKey = async (
    challenge: String,
    certChainDER: Array<string>
) => {

    const certChainPKI = certChainDER.map(it => pki
        .certificateFromAsn1(asn1.fromDer(Buffer.from(it, 'hex').toString('binary')))
    );

    for(const z of certChainPKI) {
        console.log(IX509CertFromPKICert(z));
    }
};