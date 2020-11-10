import { Asn1Node } from "@indrajala/asn1der"

enum SecurityLevel {
    Software = 0,
    TrustedEnvironment = 1,
    StrongBox = 2,
}

enum VerifiedBootState {
    Verified = 0,
    SelfSigned = 1,
    Unverified = 2,
    Failed = 3,
}

export interface IRootOfTrust {
    verifiedBootKey: Buffer,
    deviceLocked: boolean,
    verifiedBootState: VerifiedBootState,
    verifiedBootHash: Buffer,
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

export interface IAuthorizationList {
    purpose: Array<KeyPurpose>;
    algorithm: Algorithm;
    keySize: number;
    digest: Array<Digest>;
    padding: Array<Padding>;
    ecCurve: ECCurve;
    rsaPublicExponent: number;
}

export const IAuthorizationListFromAsn1Node = (node: Asn1Node): IAuthorizationList => {
 
    console.log('x', node.toString());
 
    const y = node.get('#1.0');

    console.log('y', (y != null) ? y.toString() : '');

    //console.log('y', node.get('#1.0'));

    return {
        purpose: node.get('#1.0')?.getSetElementsAsIntegers(),
        algorithm: node.get('#2.0')?.getInteger(),
        keySize: node.get('#3.0')?.getInteger(),
        digest: node.get('#5.0')?.getSetElementsAsIntegers(),
        padding: node.get('#6.0')?.getSetElementsAsIntegers(),
        ecCurve: node.get('#10.0')?.getInteger(),
        rsaPublicExponent: node.get('#200.0')?.getInteger(),
    };
}

    // rollbackResistance  [303] EXPLICIT NULL OPTIONAL,
    // activeDateTime  [400] EXPLICIT INTEGER OPTIONAL,
    // originationExpireDateTime  [401] EXPLICIT INTEGER OPTIONAL,
    // usageExpireDateTime  [402] EXPLICIT INTEGER OPTIONAL,
    // noAuthRequired  [503] EXPLICIT NULL OPTIONAL,
    // userAuthType  [504] EXPLICIT INTEGER OPTIONAL,
    // authTimeout  [505] EXPLICIT INTEGER OPTIONAL,
    // allowWhileOnBody  [506] EXPLICIT NULL OPTIONAL,
    // trustedUserPresenceRequired  [507] EXPLICIT NULL OPTIONAL,
    // trustedConfirmationRequired  [508] EXPLICIT NULL OPTIONAL,
    // unlockedDeviceRequired  [509] EXPLICIT NULL OPTIONAL,
    // allApplications  [600] EXPLICIT NULL OPTIONAL,
    // applicationId  [601] EXPLICIT OCTET_STRING OPTIONAL,
    // creationDateTime  [701] EXPLICIT INTEGER OPTIONAL,
    // origin  [702] EXPLICIT INTEGER OPTIONAL,
    // rootOfTrust  [704] EXPLICIT RootOfTrust OPTIONAL,
    // osVersion  [705] EXPLICIT INTEGER OPTIONAL,
    // osPatchLevel  [706] EXPLICIT INTEGER OPTIONAL,
    // attestationApplicationId  [709] EXPLICIT OCTET_STRING OPTIONAL,
    // attestationIdBrand  [710] EXPLICIT OCTET_STRING OPTIONAL,
    // attestationIdDevice  [711] EXPLICIT OCTET_STRING OPTIONAL,
    // attestationIdProduct  [712] EXPLICIT OCTET_STRING OPTIONAL,
    // attestationIdSerial  [713] EXPLICIT OCTET_STRING OPTIONAL,
    // attestationIdImei  [714] EXPLICIT OCTET_STRING OPTIONAL,
    // attestationIdMeid  [715] EXPLICIT OCTET_STRING OPTIONAL,
    // attestationIdManufacturer  [716] EXPLICIT OCTET_STRING OPTIONAL,
    // attestationIdModel  [717] EXPLICIT OCTET_STRING OPTIONAL,
    // vendorPatchLevel  [718] EXPLICIT INTEGER OPTIONAL,
    // bootPatchLevel  [719] EXPLICIT INTEGER OPTIONAL,


export interface IKeyDescription {
    attestationVersion: number;
    attestationSecurityLevel: SecurityLevel,
    keymasterVersion: number,
    keymasterSecurityLevel: SecurityLevel,
    attestationChallenge: Buffer,
    uniqueId: Buffer,
    softwareEnforced: IAuthorizationList,
    teeEnforced: IAuthorizationList,
}

export const IKeyDescriptionFromAsn1Node = (node: Asn1Node): IKeyDescription => ({
    attestationVersion: node.get('0').getInteger(),
    attestationSecurityLevel: node.get('1').getInteger(),
    keymasterVersion: node.get('2').getInteger(),
    keymasterSecurityLevel: node.get('3').getInteger(),
    attestationChallenge: node.get('4').content,
    uniqueId: node.get('5').content,
    softwareEnforced: IAuthorizationListFromAsn1Node(node.get('6')),
    teeEnforced: IAuthorizationListFromAsn1Node(node.get('7')),
});
