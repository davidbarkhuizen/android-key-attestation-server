import { Integer } from "asn1js"

export interface IDeviceFingerprint {
    apiLevel: Number,
    androidID: String
}

export interface IDeviceRegistrationIntent {
    deviceFingerprint: IDeviceFingerprint
}

export interface IDeviceRegistrationPermission {
    registrationID: string,
    keyAttestationChallenge: string
    keyLifeTimeMinutes: Number,
    keySizeBits: Number,
    keySN: Number
}

export interface IDeviceRegistrationRq {
    registrationID: string,
    hwAttestationKeyChain: Array<string>
}

export interface IDevRegistrationRsp {
    registered: Boolean
}

export interface IMinimumDeviceRequirements {
    apiLevel: Number
}