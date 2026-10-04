import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

/// Computes the raw 32-byte X25519 shared secret.
///
/// [ourPub] must be the public key belonging to [ourPriv]; it is carried in
/// the key pair object exactly as the app does.
Future<List<int>> x25519SharedSecret(
    List<int> ourPriv, List<int> ourPub, List<int> theirPub) async {
  final x25519 = X25519();
  final ourKP = SimpleKeyPairData(
    ourPriv,
    publicKey: SimplePublicKey(ourPub, type: KeyPairType.x25519),
    type: KeyPairType.x25519,
  );
  final shared = await x25519.sharedSecretKey(
    keyPair:         ourKP,
    remotePublicKey: SimplePublicKey(theirPub, type: KeyPairType.x25519),
  );
  return shared.extractBytes();
}

/// Generates a fresh X25519 key pair as raw bytes.
Future<({Uint8List privateKey, Uint8List publicKey})>
    x25519GenerateKeyPair() async {
  final x25519  = X25519();
  final kp      = await x25519.newKeyPair();
  final priv    = await kp.extractPrivateKeyBytes();
  final pub     = (await kp.extractPublicKey()).bytes;
  return (
    privateKey: Uint8List.fromList(priv),
    publicKey:  Uint8List.fromList(pub),
  );
}
