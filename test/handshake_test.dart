// End-to-end tests with real, freshly generated X25519 and ML-KEM-768 keys.

import 'dart:typed_data';

import 'package:pqc_hybrid_handshake/pqc_hybrid_handshake.dart';
import 'package:test/test.dart';

String hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

class Party {
  Party(this.fingerprint, this.x25519Priv, this.x25519Pub, this.mlkemPub,
      this.mlkemSec);

  final String fingerprint;
  final Uint8List x25519Priv;
  final Uint8List x25519Pub;
  final Uint8List mlkemPub;
  final Uint8List mlkemSec;

  static Future<Party> create(String fingerprint) async {
    final x = await x25519GenerateKeyPair();
    final k = mlkemGenerateKeyPair();
    return Party(
        fingerprint, x.privateKey, x.publicKey, k.publicKey, k.secretKey);
  }
}

/// Encapsulator side. Returns its root key and the ciphertext it sends.
Future<({List<int> root, String kemCtB64})> encapsulatorSide(
    Party me, Party them) async {
  final kem = mlkemEncapsulate(them.mlkemPub);
  final kemCtB64 = encodeB64url(kem.ciphertext);
  final transcript = buildTranscript(
    encapsulatorFp: me.fingerprint,
    decapsulatorFp: them.fingerprint,
    encapsulatorX25519Pub: encodeB64url(me.x25519Pub),
    decapsulatorX25519Pub: encodeB64url(them.x25519Pub),
    encapsulatorMlkemPub: encodeB64url(me.mlkemPub),
    decapsulatorMlkemPub: encodeB64url(them.mlkemPub),
    kemCt: kemCtB64,
  );
  final ssDH = await x25519SharedSecret(me.x25519Priv, me.x25519Pub, them.x25519Pub);
  final root = await deriveHybridRoot(
      ssDH: ssDH, ssKEM: kem.sharedSecret, transcript: transcript);
  return (root: root, kemCtB64: kemCtB64);
}

/// Decapsulator side. [them] is what it believes the encapsulator's public
/// material is.
Future<List<int>> decapsulatorSide(
  Party me,
  Party them,
  String kemCtB64, {
  Uint8List? overrideMlkemSecret,
  ({Uint8List privateKey, Uint8List publicKey})? overrideX25519ForDh,
}) async {
  final kemSecret = mlkemDecapsulate(
      decodeB64url(kemCtB64), overrideMlkemSecret ?? me.mlkemSec);
  final transcript = buildTranscript(
    encapsulatorFp: them.fingerprint,
    decapsulatorFp: me.fingerprint,
    encapsulatorX25519Pub: encodeB64url(them.x25519Pub),
    decapsulatorX25519Pub: encodeB64url(me.x25519Pub),
    encapsulatorMlkemPub: encodeB64url(them.mlkemPub),
    decapsulatorMlkemPub: encodeB64url(me.mlkemPub),
    kemCt: kemCtB64,
  );
  // The override changes only the X25519 secret, not the transcript.
  final ssDH = overrideX25519ForDh == null
      ? await x25519SharedSecret(me.x25519Priv, me.x25519Pub, them.x25519Pub)
      : await x25519SharedSecret(overrideX25519ForDh.privateKey,
          overrideX25519ForDh.publicKey, them.x25519Pub);
  return deriveHybridRoot(ssDH: ssDH, ssKEM: kemSecret, transcript: transcript);
}

void main() {
  late Party alice; // encapsulator
  late Party bob; // decapsulator

  setUp(() async {
    alice = await Party.create('1111aaaa2222bbbb');
    bob = await Party.create('9999cccc8888dddd');
  });

  test('ML-KEM-768 sizes are as specified by FIPS 203', () {
    expect(alice.mlkemPub.length, 1184);
    expect(alice.mlkemSec.length, 2400);
    final kem = mlkemEncapsulate(bob.mlkemPub);
    expect(kem.ciphertext.length, 1088);
    expect(kem.sharedSecret.length, 32);
    expect(mlkemDecapsulate(kem.ciphertext, bob.mlkemSec), kem.sharedSecret);
  });

  test('(1) both parties derive the same 32-byte root key', () async {
    final enc = await encapsulatorSide(alice, bob);
    final decRoot = await decapsulatorSide(bob, alice, enc.kemCtB64);
    expect(enc.root.length, 32);
    expect(hex(decRoot), hex(enc.root));
  });

  test('(2) tampered transcript: modified ciphertext gives a different key',
      () async {
    final enc = await encapsulatorSide(alice, bob);
    final ct = decodeB64url(enc.kemCtB64);
    ct[0] ^= 0x01;
    final decRoot = await decapsulatorSide(bob, alice, encodeB64url(ct));
    expect(hex(decRoot), isNot(hex(enc.root)));
  });

  test('(2) tampered transcript: substituted ML-KEM public key gives a '
      'different key', () async {
    final enc = await encapsulatorSide(alice, bob);
    final mallory = await Party.create('1111aaaa2222bbbb');
    // Bob believes Alice's ML-KEM public key is Mallory's (only that field
    // differs; Alice's X25519 key and fingerprint are kept).
    final fakeAlice = Party(alice.fingerprint, alice.x25519Priv,
        alice.x25519Pub, mallory.mlkemPub, mallory.mlkemSec);
    final decRoot = await decapsulatorSide(bob, fakeAlice, enc.kemCtB64);
    expect(hex(decRoot), isNot(hex(enc.root)));
  });

  test('(2) tampered transcript: wrong peer fingerprint gives a different key',
      () async {
    final enc = await encapsulatorSide(alice, bob);
    final renamedAlice = Party('1111aaaa2222bbbc', alice.x25519Priv,
        alice.x25519Pub, alice.mlkemPub, alice.mlkemSec);
    final decRoot = await decapsulatorSide(bob, renamedAlice, enc.kemCtB64);
    expect(hex(decRoot), isNot(hex(enc.root)));
  });

  test('(3) a different ML-KEM secret gives a different key', () async {
    final enc = await encapsulatorSide(alice, bob);
    final otherKem = mlkemGenerateKeyPair();
    // Decapsulating with the wrong secret key does not throw (ML-KEM
    // implicit rejection); it yields an unrelated secret.
    final decRoot = await decapsulatorSide(bob, alice, enc.kemCtB64,
        overrideMlkemSecret: otherKem.secretKey);
    expect(hex(decRoot), isNot(hex(enc.root)));
  });

  test('(3) a different X25519 secret gives a different key', () async {
    final enc = await encapsulatorSide(alice, bob);
    final otherX = await x25519GenerateKeyPair();
    // Bob computes the X25519 shared secret with a different key pair;
    // the transcript and ML-KEM secret are unchanged.
    final decRoot = await decapsulatorSide(bob, alice, enc.kemCtB64,
        overrideX25519ForDh: otherX);
    expect(hex(decRoot), isNot(hex(enc.root)));
  });

  test('two independent handshakes produce different root keys', () async {
    final a = await encapsulatorSide(alice, bob);
    final b = await encapsulatorSide(alice, bob);
    expect(hex(a.root), isNot(hex(b.root)));
  });
}
