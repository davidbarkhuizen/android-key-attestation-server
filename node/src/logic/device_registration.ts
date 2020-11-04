import { promisify } from 'util';

import { IDeviceFingerprint, IDeviceRegistrationIntent, IDeviceRegistrationPermission, IMinimumDeviceRequirements } from "../model/device";
import { randomBytes } from 'crypto';
const randomBytesAsync = promisify(randomBytes);

let registrationID = 0; 

export const processIntentToRegisterDevice = async (
    deviceFingerprint: IDeviceFingerprint,
    minDeviceReqs: IMinimumDeviceRequirements
): Promise<IDeviceRegistrationPermission> => {

    // check min requirements (e.g. OS level) based on fingerprint
    //
    if (deviceFingerprint.apiLevel < minDeviceReqs.apiLevel) {
        console.log(`device os api level (${deviceFingerprint.apiLevel}) is not sufficient (${minDeviceReqs.apiLevel})`)
        return null
    }

    registrationID = registrationID + 1;

    // create random challenge for hw key attestation
    //
    const hwAttestationChallenge = await randomBytesAsync(8);
  
    // persist request with nonces, returning reg ID (not DB id)

    return {
        registrationID: registrationID.toString(),
        keyAttestationChallenge: hwAttestationChallenge.toString('hex'),
        keyLifeTimeMinutes: 60*24,
        keySizeBits: 2048,
        keySN: 1
    }
};

export const processDeviceRegistration = async (
    registrationID: string,
    hwAttestationKeyChain: Array<string>
) => {

    return {
        registered: false
    };
};