import { IAttestationPackageInfo } from "./IAttestationPackageInfo";

export interface IAttestationApplicationId {
    packageInfos: Array<IAttestationPackageInfo>;
    signatureDigests: Array<string>;
}