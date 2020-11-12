import { Asn1Node } from "@indrajala/asn1der";
import { safeDateFromMS } from "../general/util";
import { Algorithm } from './model/google/enums';
import { IAttestationApplicationId } from "./model/google/IAttestationApplicationId";
import { IAttestationPackageInfo } from "./model/google/IAttestationPackageInfo";
import { IAuthorizationList } from "./model/google/IAuthorizationList";
import { IKeyDescription } from "./model/google/IKeyDescription";
import { IRootOfTrust } from "./model/google/IRootOfTrust";

export const IAttestationPackageInfoFromAsn1Node = (node: Asn1Node): IAttestationPackageInfo => {
       
    return (node)
    ? {
        packageName: node.get('0')?.getUTF8String(),
        version: node.get('1')?.getInteger(),
    }
    : undefined
};

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

export const IAttestationApplicationIdFromAsn1Node = (node: Asn1Node): IAttestationApplicationId => {

    return (node)
    ? {
        packageInfos: node.get('0.0')?.getSetElements().map(it => IAttestationPackageInfoFromAsn1Node(it)),
        signatureDigests: node.get('0.1')?.getSetElements().map(it => it.getContentAsHex())
    }
    : undefined
};

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

export const IAuthorizationListFromAsn1Node = (node: Asn1Node): IAuthorizationList => {
 
    return {
        purpose: node.get('#1.0')?.getSetElementsAsIntegers(),
        algorithm: node.get('#2.0')?.getInteger() as Algorithm,
        keySize: node.get('#3.0')?.getInteger(),
        digest: node.get('#5.0')?.getSetElementsAsIntegers(),
        padding: node.get('#6.0')?.getSetElementsAsIntegers(),
        ecCurve: node.get('#10.0')?.getInteger(),
        rsaPublicExponent: node.get('#200.0')?.getInteger(),
        rollbackResistance: node.get('#303.0')?.getNull() == true,
        activeDateTime: safeDateFromMS(node.get('#400.0')?.getInteger()),
        originationExpireDateTime: safeDateFromMS(node.get('#401.0')?.getInteger()),
        usageExpireDateTime: safeDateFromMS(node.get('#402.0')?.getInteger()),
        noAuthRequired: node.get('#503.0')?.getNull() == true,
        userAuthType: node.get('#504.0')?.getInteger(),
        authTimeout: node.get('#505.0')?.getInteger(),
        allowWhileOnBody: node.get('#506.0')?.getNull() == true,
        trustedUserPresenceRequired: node.get('#507.0')?.getNull() == true,
        trustedConfirmationRequired: node.get('#508.0')?.getNull() == true,
        unlockedDeviceRequired: node.get('#509.0')?.getNull() == true,
        allApplications: node.get('#600.0')?.getNull() == true,
        applicationId: node.get('#601.0')?.getContentAsHex(),
        creationDateTime: safeDateFromMS(node.get('#701.0')?.getInteger()),
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
};