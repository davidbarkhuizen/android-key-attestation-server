import { default as asn1js } from 'asn1.js';
 
const SecurityLevel = Object.freeze({ 
  0: 'Software',
  1: 'TrustedEnvironment',
  2: 'StrongBox', 
});

export const AuthorizationList = asn1js.define('AuthorizationList', function() {
  this.seq().obj(
    this.key('purpose').set().int().optional(),
    this.key('algorithm').set().int().optional(),
    this.key('keySize').set().int().optional()
  )
});

export const KeyDescription = asn1js.define('KeyDescription', function() {
  this.seq().obj(
    this.key('attestationVersion').int(),
    this.key('attestationSecurityLevel').enum(SecurityLevel),
    this.key('keymasterVersion').int(),
    this.key('keymasterSecurityLevel').enum(SecurityLevel),
    this.key('attestationChallenge').octstr(),
    this.key('uniqueId').octstr(),
    this.key('softwareEnforced').seq().obj(AuthorizationList),
    this.key('teeEnforced').seq().obj(AuthorizationList)
  );
});