import { Integer } from "asn1js"

export interface IDeviceFingerprint {
    apiLevel: Number,
    androidID: String
}

export interface IMinimumDeviceRequirements {
    apiLevel: Number
}