import { Asn1Node } from "@indrajala/asn1der"

enum SecurityLevel {
    Software = 0,
    TrustedEnvironment = 1,
    StrongBox = 2,
}

enum KeyPurpose {
    Encrypt = 0,
    Decrypt = 1,
    Sign = 2,
    Verify = 3,
    DericeKey = 4,
    Wrapkey = 5,
};

enum Algorithm {
    RSA = 1,
    EC = 3,
    AES = 32,
    HMAC = 128,
};

enum Digest {
    None = 0,
    MD5 = 1,
    SHA1 = 2,
    SHA_2_224 = 3,
    SHA_2_256 = 4,
    SHA_2_384 = 5,
    SHA_2_512 = 6,
}

enum Padding {
    None = 1,
    RSA_OAEP = 2,
    RSA_PSS = 3,
    RSA_PKCS1_1_5_ENCRYPT = 4,
    RSA_PKCS1_1_5_SIGN = 5,
    PKCS7 = 64,
}

enum ECCurve {
    P_224 = 0,
    P_256 = 1,
    P_384 = 2,
    P_521 = 3,
};

enum VerifiedBootState {
    Verified = 0,
    SelfSigned = 1,
    Unverified = 2,
    Failed = 3,
}

export interface IAttestationPackageInfo {
    packageName: string;
    version: number;
}

export const IAttestationPackageInfoFromAsn1Node = (node: Asn1Node): IAttestationPackageInfo => {
       
    return (node)
    ? {
        packageName: node.get('0')?.getUTF8String(),
        version: node.get('1')?.getInteger(),
    }
    : undefined
};

export interface IAttestationApplicationId {
    packageInfos: Array<IAttestationPackageInfo>;
    signatureDigests: Array<string>;
}

// OCTET STRING - 3042311c301a04157a61...
//     SEQUENCE(OF) - 311c301a04157a612e63...
//         SET(OF) - 301a04157a612e636f2e...
//             SEQUENCE(OF) - 04157a612e636f2e696e...
//                 OCTET STRING - 7a612e636f2e696e6472...
//                 INTEGER - 1
//         SET(OF) - 04207b6d3688d13ef0b6...
//             OCTET STRING - 7b6d3688d13ef0b62146...



export const IAttestationApplicationIdFromAsn1Node = (node: Asn1Node): IAttestationApplicationId => {
    
    if (node) {
        console.log('---------------------');
        node.summary(4, null).map(line => console.log(line));
        console.log('---------------------');
        node.get('0.0').summary(4, null).map(line => console.log(line));
        console.log('---------------------');
        node.get('0.0')?.getSetElements().map(it => console.log(it.toString()));
    }
    
    return (node)
    ? {
        packageInfos: node.get('0.0')?.getSetElements().map(it => IAttestationPackageInfoFromAsn1Node(it)),
        signatureDigests: node.get('1')?.getSetElements().map(it => it.getContentAsHex())
    }
    : undefined
};

export interface IRootOfTrust {
    verifiedBootKey: string,
    deviceLocked: boolean,
    verifiedBootState: VerifiedBootState,
    verifiedBootHash: string,
}

export const IRootOfTrustFromAsn1Node = (node: Asn1Node): IRootOfTrust => (
    (node)
    ? {
        verifiedBootKey: node.get('0')?.getContentAsHex(),
        deviceLocked: node.get('1')?.getBoolean(),
        verifiedBootState: node.get('2')?.getInteger(),
        verifiedBootHash: node.get('3')?.getContentAsHex(),
    }
    : undefined
);

export interface IAuthorizationList {
    purpose: Array<KeyPurpose>;
    algorithm: Algorithm;
    keySize: number;
    digest: Array<Digest>;
    padding: Array<Padding>;
    ecCurve: ECCurve;
    rsaPublicExponent: number;
    rollbackResistance: boolean;
    activeDateTime: number;
    originationExpireDateTime: number;
    usageExpireDateTime: number;
    noAuthRequired: boolean;
    userAuthType: number;
    authTimeout: number;
    allowWhileOnBody: boolean;
    trustedUserPresenceRequired: boolean;
    trustedConfirmationRequired: boolean;
    unlockedDeviceRequired: boolean;
    allApplications: boolean;
    applicationId: string;
    creationDateTime: number;
    origin: number;
    rootOfTrust: any;
    osVersion: number;
    osPatchLevel: number;
    attestationApplicationId: IAttestationApplicationId;
    attestationIdBrand: string;
    attestationIdDevice: string;
    attestationIdProduct: string;
    attestationIdSerial: string;
    attestationIdImei: string;
    attestationIdMeid: string;
    attestationIdManufacturer: string;
    attestationIdModel: string;
    vendorPatchLevel: number;
    bootPatchLevel: number;
}

export const IAuthorizationListFromAsn1Node = (node: Asn1Node): IAuthorizationList => {
 
    return {
        purpose: node.get('#1.0')?.getSetElementsAsIntegers(),
        algorithm: node.get('#2.0')?.getInteger(),
        keySize: node.get('#3.0')?.getInteger(),
        digest: node.get('#5.0')?.getSetElementsAsIntegers(),
        padding: node.get('#6.0')?.getSetElementsAsIntegers(),
        ecCurve: node.get('#10.0')?.getInteger(),
        rsaPublicExponent: node.get('#200.0')?.getInteger(),
        rollbackResistance: node.get('#303.0')?.getNull() == true,
        activeDateTime: node.get('#400.0')?.getInteger(),
        originationExpireDateTime: node.get('#401.0')?.getInteger(),
        usageExpireDateTime: node.get('#402.0')?.getInteger(),
        noAuthRequired: node.get('#503.0')?.getNull() == true,
        userAuthType: node.get('#504.0')?.getInteger(),
        authTimeout: node.get('#505.0')?.getInteger(),
        allowWhileOnBody: node.get('#506.0')?.getNull() == true,
        trustedUserPresenceRequired: node.get('#507.0')?.getNull() == true,
        trustedConfirmationRequired: node.get('#508.0')?.getNull() == true,
        unlockedDeviceRequired: node.get('#509.0')?.getNull() == true,
        allApplications: node.get('#600.0')?.getNull() == true,
        applicationId: node.get('#601.0')?.getContentAsHex(),
        creationDateTime: node.get('#701.0')?.getInteger(),
        origin: node.get('#702.0')?.getInteger(),
        rootOfTrust: IRootOfTrustFromAsn1Node(node.get('#704.0')),
        osVersion: node.get('#705.0')?.getInteger(),
        osPatchLevel: node.get('#706.0')?.getInteger(),
        attestationApplicationId: IAttestationApplicationIdFromAsn1Node(node.get('#709.0')),
        attestationIdBrand: node.get('#710.0')?.getContentAsHex(),
        attestationIdDevice: node.get('#711.0')?.getContentAsHex(),
        attestationIdProduct: node.get('#712.0')?.getContentAsHex(),
        attestationIdSerial: node.get('#713.0')?.getContentAsHex(),
        attestationIdImei: node.get('#714.0')?.getContentAsHex(),
        attestationIdMeid: node.get('#715.0')?.getContentAsHex(),
        attestationIdManufacturer: node.get('#716.0')?.getContentAsHex(),
        attestationIdModel: node.get('#717.0')?.getContentAsHex(),
        vendorPatchLevel: node.get('#718.0')?.getInteger(),
        bootPatchLevel: node.get('#719.0')?.getInteger(),
    };
}

export interface IKeyDescription {
    attestationVersion: number;
    attestationSecurityLevel: SecurityLevel,
    keymasterVersion: number,
    keymasterSecurityLevel: SecurityLevel,
    attestationChallenge: string,
    uniqueId: string,
    softwareEnforced: IAuthorizationList,
    teeEnforced: IAuthorizationList,
}

export const IKeyDescriptionFromAsn1Node = (node: Asn1Node): IKeyDescription => ({
    attestationVersion: node.get('0').getInteger(),
    attestationSecurityLevel: node.get('1').getInteger(),
    keymasterVersion: node.get('2').getInteger(),
    keymasterSecurityLevel: node.get('3').getInteger(),
    attestationChallenge: node.get('4').getContentAsHex(),
    uniqueId: node.get('5').getContentAsHex(),
    softwareEnforced: IAuthorizationListFromAsn1Node(node.get('6')),
    teeEnforced: IAuthorizationListFromAsn1Node(node.get('7')),
});
