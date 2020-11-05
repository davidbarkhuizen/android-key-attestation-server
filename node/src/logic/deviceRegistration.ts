import { promisify } from 'util';

import { IDeviceFingerprint, IMinimumDeviceRequirements } from "../model/device";
import { randomBytes } from 'crypto';
import { attestHardwareKey } from './attestation';
import { IDeviceRegPermissionRsp } from '../model/rqrsp';
const randomBytesAsync = promisify(randomBytes);

let registrationID = 0; 
let hwAttestationChallenge = null;
const keySizeBits = 2048;
const keyLifeTimeMinutes = 24 * 60;

export const requestPermissionToRegisterDevice = async (
    minDeviceReqs: IMinimumDeviceRequirements,
    deviceFingerprint: IDeviceFingerprint
): Promise<IDeviceRegPermissionRsp> => {

    // check min requirements (e.g. OS level) based on fingerprint
    //
    if (deviceFingerprint.apiLevel < minDeviceReqs.apiLevel) {
        console.log(`device os api level (${deviceFingerprint.apiLevel}) is not sufficient (${minDeviceReqs.apiLevel})`)
        return null
    }

    registrationID = registrationID + 1;

    // create random challenge for hw key attestation
    //
    hwAttestationChallenge = await randomBytesAsync(8);
  
    // persist request with nonces, returning reg ID (not DB id)

    return {
        registrationID: registrationID.toString(),
        keyAttestationChallenge: hwAttestationChallenge.toString('hex'),
        keyLifeTimeMinutes: 60*24,
        keySizeBits: 2048,
        keySN: 1
    }
};

export const registerDevice = async (
    minDeviceReqs: IMinimumDeviceRequirements,
    registrationID: string,
    hwAttestationKeyChain: Array<string>
) => {

    const keyAttestation = await attestHardwareKey(
        hwAttestationChallenge, 
        hwAttestationKeyChain
    );

    return {
        registered: false
    };
};