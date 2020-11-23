export enum KeyAttestationFailureReason {
    InsufficientApiLevel,
    BannedAndroidID,
    TrustChainDoesNotContainARoot,
    TrustChainContainsMultipleRoots,
    TrustChainDoesNotContainAValidKnownRoot,
    TrustChainSignatureError,
    TrustChainIsMissingALink,
    TrustChainNodeNotYetValid,
    TrustChainNodeExpired,
    TrustChainContainsARevokedElement,
    TrustChainContainsAnInternalNodeWithoutSigningRights,
    KeyAttestationCertHasNoAttestationExtension,
    ChallengeFailed
}