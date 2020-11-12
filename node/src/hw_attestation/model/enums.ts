export enum SecurityLevel {
    Software = 0,
    TrustedEnvironment = 1,
    StrongBox = 2,
}

export enum KeyPurpose {
    Encrypt = 0,
    Decrypt = 1,
    Sign = 2,
    Verify = 3,
    DericeKey = 4,
    Wrapkey = 5,
};

export enum Algorithm {
    RSA = 1,
    EC = 3,
    AES = 32,
    HMAC = 128,
};

export enum Digest {
    None = 0,
    MD5 = 1,
    SHA1 = 2,
    SHA_2_224 = 3,
    SHA_2_256 = 4,
    SHA_2_384 = 5,
    SHA_2_512 = 6,
}

export enum Padding {
    None = 1,
    RSA_OAEP = 2,
    RSA_PSS = 3,
    RSA_PKCS1_1_5_ENCRYPT = 4,
    RSA_PKCS1_1_5_SIGN = 5,
    PKCS7 = 64,
}

export enum ECCurve {
    P_224 = 0,
    P_256 = 1,
    P_384 = 2,
    P_521 = 3,
};

export enum VerifiedBootState {
    Verified = 0,
    SelfSigned = 1,
    Unverified = 2,
    Failed = 3,
}

export enum HardwareAuthenticatorType {
    NONE = 0,
    PASSWORD = 1 << 0,
    FINGERPRINT = 1 << 1,
    ANY = 4294967295,
}

export enum KeyOrigin {
    GENERATED = 0,
    DERIVED = 1,
    IMPORTED = 2,
    UNKNOWN = 3,
};