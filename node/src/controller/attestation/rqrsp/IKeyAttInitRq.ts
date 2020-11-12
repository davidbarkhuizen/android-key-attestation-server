import { IDeviceFingerprint } from "../../../hw_attestation/model/IDeviceFingerprint";

export interface IKeyAttInitRq {
    deviceFingerprint: IDeviceFingerprint
}