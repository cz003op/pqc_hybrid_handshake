import 'dart:typed_data';

import 'package:mlkem_native/mlkem768.dart';

/// Generates a fresh ML-KEM-768 (FIPS 203) key pair.
/// Public key: 1184 bytes. Secret key: 2400 bytes.
///
/// Uses the system random number generator.
({Uint8List publicKey, Uint8List secretKey}) mlkemGenerateKeyPair() {
  final mlkem   = MLKEM768();
  final keyPair = mlkem.generateKeyPair();
  return (
    publicKey: Uint8List.fromList(keyPair.publicKey),
    secretKey: Uint8List.fromList(keyPair.secretKey),
  );
}

/// Encapsulate to a recipient's ML-KEM-768 public key.
/// Returns (sharedSecret, ciphertext) as raw bytes: 32-byte shared secret,
/// 1088-byte ciphertext. The ciphertext is sent to the recipient.
({Uint8List sharedSecret, Uint8List ciphertext}) mlkemEncapsulate(
    Uint8List recipientPublicKey) {
  final mlkem  = MLKEM768();
  final result = mlkem.encapsulate(recipientPublicKey);
  return (
    sharedSecret: Uint8List.fromList(result.sharedSecret),
    ciphertext:   Uint8List.fromList(result.ciphertext),
  );
}

/// Decapsulate a ciphertext with our ML-KEM-768 secret key.
/// Returns the 32-byte shared secret. On a wrong key or tampered
/// ciphertext ML-KEM does not throw; it returns a different
/// (pseudorandom) secret, so the derived root keys will not match.
Uint8List mlkemDecapsulate(Uint8List ciphertext, Uint8List secretKey) {
  final mlkem = MLKEM768();
  return Uint8List.fromList(
      mlkem.decapsulate(ciphertext, secretKey));
}
