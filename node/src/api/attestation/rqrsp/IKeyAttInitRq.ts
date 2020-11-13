import { IDeviceFingerprint } from "../../../key_attestation/model/IDeviceFingerprint";

export interface IKeyAttInitRq {
    deviceFingerprint: IDeviceFingerprint;
}