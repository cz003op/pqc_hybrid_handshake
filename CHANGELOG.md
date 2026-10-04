## 0.1.0

* Initial extraction from Cryptaverse: transcript builder, hybrid root key
  derivation, X25519 shared secret, ML-KEM-768 wrappers.
* `example/encrypt_demo.dart`: step-by-step demo from key generation to
  an encrypted, decrypted, and tamper-checked message.
* `example/file_demo.dart`: keygen / encrypt / decrypt for files, with
  Ed25519 sender signatures.
* Root key function named `deriveHybridRoot` (`_derivePqxdhRoot` in the app).
