import { pki, asn1 } from "node-forge";
import { pemFromDer, IX509CertFromPKICert, derFromPem } from "../crypto/x509";
import { getGoogleKeyAttestationRootCertsPEM } from "../dal/dal";
import { fetchGoogleAttestationCRL } from "./crl";
import { IKeyAttestationChainValidationResult } from "./model/IKeyAttestationChainValidationResult";
import { KeyAttestationFailureReason } from "./model/KeyAttestationFailureReason";

export const validateHWAttestationTrustChain = async (
    trustChainDER: Array<string>
): Promise<IKeyAttestationChainValidationResult> => {

    const googleRootCertsPEM = await getGoogleKeyAttestationRootCertsPEM();
    const googleRootCertsDER = googleRootCertsPEM.map(pem => derFromPem(pem));

    const certChain = trustChainDER
    .map(der => ({
        der,
        pki: pki.certificateFromAsn1(asn1.fromDer(Buffer.from(der, 'hex').toString('binary'))),
        pem: pemFromDer(der)
    }))
    .map(it => ({ ...it,
        ix509: IX509CertFromPKICert(it.pki)
    }));

    console.log(`${trustChainDER.length} certs in chain: ${
        certChain.map(it => it.ix509.subjectDN).join(', ')}`);

    const rootCerts = certChain.filter(it => it.ix509.issuerDN == it.ix509.subjectDN);
    console.log(`${
        rootCerts.length} root certs(s): ${
        rootCerts.map(it => it.ix509.subjectDN).join(', ')}`);

    if (rootCerts.length == 0) {
        return {
            succeeded: false,
            failureReason: KeyAttestationFailureReason.TrustChainDoesNotContainARoot,
            keyCert: null
        }
    } else if (rootCerts.length > 1) {
        return {
            succeeded: false,
            failureReason: KeyAttestationFailureReason.TrustChainContainsMultipleRoots,
            keyCert: null
        }
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
        return {
            succeeded: false,
            failureReason: KeyAttestationFailureReason.TrustChainSignatureError,
            keyCert: null
        }
    }
    console.log(`${rootSigVerified ? 'verified' : 'failed to verify'} self-signature of 0 ${rootCert.ix509.subjectDN} root cert`)

    if (!rootSigVerified) {
        return {
            succeeded: false,
            failureReason: KeyAttestationFailureReason.TrustChainSignatureError,
            keyCert: null
        }
    }

    // confirm root cert as known
    //
    const isKnownValidRootCert = googleRootCertsDER.includes(rootCert.der);
    console.log(`root cert ${isKnownValidRootCert ? "is": "is not"} a known valid Google root HW attestation cert`);

    if (!isKnownValidRootCert) {
        return {
            succeeded: false,
            failureReason: KeyAttestationFailureReason.TrustChainDoesNotContainAValidKnownRoot,
            keyCert: null
        }
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
            
            return {
                succeeded: false,
                failureReason: KeyAttestationFailureReason.TrustChainIsMissingALink,
                keyCert: null
            }
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
            console.error(e);
            const error = `error during verification of signature of cert ${child.ix509.subjectDN} by ${parent.ix509.subjectDN}: ${e.toString()}`;
            console.log(error);
            
            return {
                succeeded: false,
                failureReason: KeyAttestationFailureReason.TrustChainSignatureError,
                keyCert: null
            }
        }

        console.log(`${sigVerified ? 'verified' : 'failed to verify'} ${childChainIndex} ${child.ix509.subjectDN} signed by ${childChainIndex - 1} ${parent.ix509.subjectDN}`)
    }

    // (double) check temporal validity of certs
    //
    const now = new Date();
    console.log(`checking temporal validity`);
    for(const cert of sortedChain) {

        const notBefore = cert.pki.validity.notBefore;
        if (notBefore > now) {
            const error = `cert ${cert.ix509.subjectDN} is not yet valid as of ${now} (not before ${notBefore})`;
            console.log(error);      
            
            return {
                succeeded: false,
                failureReason: KeyAttestationFailureReason.TrustChainNodeNotYetValid,
                keyCert: null
            };
        }

        const notAfter = cert.pki.validity.notAfter;
        if (notAfter < now) {
            const error = `cert ${cert.ix509.subjectDN} has already expired (not after ${notAfter})`;
            console.log(error);
            
            return {
                succeeded: false,
                failureReason: KeyAttestationFailureReason.TrustChainNodeExpired,
                keyCert: null
            };
        }
    }
    console.log(`all certs are temporally valid as of ${now}`);

    // check against CRL

    const crl = await fetchGoogleAttestationCRL();
    console.log('checking against official Google CRL...');

    const revoked = sortedChain.filter(cert => 
        crl.includes(cert.ix509.subjectDN.toUpperCase())
    );

    if (revoked.length > 0) {
        
        const revokedSubjects = revoked
            .map(it => it.ix509.subjectDN)
            .join(', ');

        const error = `chain is invalid - it contains ${revoked.length} revoked cert(s): ${revokedSubjects}`;
        console.log(error);
        
        return {
            succeeded: false,
            failureReason: KeyAttestationFailureReason.TrustChainContainsARevokedElement,
            keyCert: null
        };
    }

    console.log('chain contains no known revoked certs');

    console.log('cert chain:');
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
    })

    const nonLeafCerts = sortedChain.slice(0, sortedChain.length - 1);

    console.log('confirming that all non-leaf certs have the right to sign either data or key certs');
    const unauthorizedToSign = nonLeafCerts
        .filter(it => 
            it.ix509.keyUsage.digitalSignature == false
            &&
            it.ix509.keyUsage.keyCertSign == false
            );
    if (unauthorizedToSign.length > 0) {
        console.log(`a certificate(s) internal to the chain was found to not possess signing rights: ${
            unauthorizedToSign.map(it => it.ix509.subjectDN).join(', ')
        }`);

        return {
            succeeded: false,
            failureReason: KeyAttestationFailureReason.TrustChainContainsAnInternalNodeWithoutSigningRights,
            keyCert: null
        };
    }

    const keyCert = sortedChain[sortedChain.length - 1];

    return {
        succeeded: true,
        failureReason: null,
        keyCert
    };
};