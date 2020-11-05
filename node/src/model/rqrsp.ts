import { IDeviceFingerprint } from "./device";

export interface IDeviceRegPermissionRq {
    deviceFingerprint: IDeviceFingerprint
}

export interface IDeviceRegPermissionRsp {
    registrationID: string,
    keyAttestationChallenge: string
    keyLifeTimeMinutes: Number,
    keySizeBits: Number,
    keySN: Number
}

export interface IDeviceRegRq {
    registrationID: string,
    hwAttestationKeyChain: Array<string>
}

export interface IDeviceRegRsp {
    registered: Boolean
}