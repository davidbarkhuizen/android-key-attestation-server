import { default as asn1js } from 'asn1.js';
 
export const KeyDescription = asn1js.define('Human', function() {
  this.seq().obj(
    this.key('attestationVersion').int(),
    this.key('attestationSecurityLevel').enum({ 
      0: 'Software',
      1: 'TrustedEnvironment',
      2: 'StrongBox', 
    })
  );
});