// console.log('indrajala-fluid-server');

// const MODULE_PATH = '/home/david/code/SoftHSMv2/src/lib/.libs/libsofthsm2.so';
 
// import { default as graphene } from "graphene-pk11";
// const Module = graphene.Module;
 
// const mod = Module.load(MODULE_PATH, "SoftHSM");
// mod.initialize();
 
// const slot = mod.getSlots(0);
// if (slot.flags & graphene.SlotFlag.TOKEN_PRESENT) {
//     const session = slot.open();
//     session.login("1234");
    
//     // generate RSA key pair
//     const keys = session.generateKeyPair(graphene.KeyGenMechanism.RSA, {
//         keyType: graphene.KeyType.RSA,
//         modulusBits: 1024,
//         publicExponent: Buffer.from([3]),
//         token: false,
//         verify: true,
//         encrypt: true,
//         wrap: true,
//         label: 'dog'
//     }, {
//         keyType: graphene.KeyType.RSA,
//         token: false,
//         sign: true,
//         decrypt: true,
//         unwrap: true
//     });
    
//     // get public key attributes
//     const pubKey = keys.publicKey.getAttribute({
//         modulus: null,
//         publicExponent: null
//     });
    
//     // convert values to base64
//     pubKey.modulus = pubKey.modulus.toString("base64");
//     pubKey.publicExponent = pubKey.publicExponent.toString("base64");
    
//     console.log(JSON.stringify(pubKey, null, 4));

//     // -----------

//     const objects = session.find({class: graphene.ObjectClass.PUBLICKEY});
//     for (let i=0; i<objects.length; i++) {
//         const cert = objects.items(i).toType();

//         console.log('CERT: ', cert.value.toString("hex"));
//     }

//     session.logout();
//     session.close();
// }
// else {
//     console.error("Slot is not initialized");
// }
 
// mod.finalize();
 