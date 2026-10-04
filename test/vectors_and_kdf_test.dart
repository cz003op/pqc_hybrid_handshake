// Fixed-input tests: transcript layout, root-key derivation and X25519.
// The expected hex values were computed with an independent reference
// implementation (Python stdlib hmac/hashlib + pyca/cryptography) written
// from the original Cryptaverse functions. If any byte of the protocol
// changes, these fail.

import 'dart:typed_data';

import 'package:pqc_hybrid_handshake/pqc_hybrid_handshake.dart';
import 'package:test/test.dart';

String hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

Uint8List unhex(String s) => Uint8List.fromList([
      for (var i = 0; i < s.length; i += 2)
        int.parse(s.substring(i, i + 2), radix: 16),
    ]);

// RFC 7748 section 6.1 test vector.
final rfcAlicePriv =
    unhex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
final rfcAlicePub =
    unhex('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a');
final rfcBobPub =
    unhex('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f');
const rfcShared =
    '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742';

Uint8List katTranscript({
  String encapsulatorFp = 'a1b2c3d4e5f60718',
  String decapsulatorFp = 'f0e1d2c3b4a59687',
  String? encapsulatorX25519Pub,
  String? decapsulatorX25519Pub,
  String encapsulatorMlkemPub = 'ENC_MLKEM_PUB',
  String decapsulatorMlkemPub = 'DEC_MLKEM_PUB',
  String kemCt = 'KEM_CT',
}) =>
    buildTranscript(
      encapsulatorFp: encapsulatorFp,
      decapsulatorFp: decapsulatorFp,
      encapsulatorX25519Pub:
          encapsulatorX25519Pub ?? encodeB64url(rfcAlicePub),
      decapsulatorX25519Pub:
          decapsulatorX25519Pub ?? encodeB64url(rfcBobPub),
      encapsulatorMlkemPub: encapsulatorMlkemPub,
      decapsulatorMlkemPub: decapsulatorMlkemPub,
      kemCt: kemCt,
    );

final katSsKem = Uint8List.fromList(List<int>.generate(32, (i) => i));

const katTranscriptHex =
    '0000001463727970746176657273652d70717864682d763100000010613162326333'
    '6434653566363037313800000010663065316432633362346135393638370000002b'
    '6853447743596b777031523069333363744437335767325f4f67306d4f4272303636'
    '53706a717162546d6f0000002b33703762665874397762545457324843374f51314e'
    '7a2d44513868626547644e7266782d46472d494b30380000000d454e435f4d4c4b45'
    '4d5f5055420000000d4445435f4d4c4b454d5f505542000000064b454d5f4354';

const katRootHex =
    '0f21a4ddc225b9ede7b65be903f11e63dc36fcc5e5148cf75c7c25793bf05fa8';

void main() {
  group('known-answer vectors (byte-for-byte protocol check)', () {
    test('X25519 matches RFC 7748', () async {
      final ss = await x25519SharedSecret(rfcAlicePriv, rfcAlicePub, rfcBobPub);
      expect(hex(ss), rfcShared);
    });

    test('base64url encoding is unpadded', () {
      expect(encodeB64url(rfcAlicePub),
          'hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo');
      expect(decodeB64url(encodeB64url(rfcAlicePub)), rfcAlicePub);
    });

    test('transcript bytes match reference', () {
      final t = katTranscript();
      expect(t.length, 202);
      expect(hex(t), katTranscriptHex);
    });

    test('root key matches reference', () async {
      final root = await deriveHybridRoot(
        ssDH: unhex(rfcShared),
        ssKEM: katSsKem,
        transcript: katTranscript(),
      );
      expect(root.length, 32);
      expect(hex(root), katRootHex);
    });
  });

  group('transcript binding', () {
    Future<String> rootFor(Uint8List transcript) async => hex(
        await deriveHybridRoot(
            ssDH: unhex(rfcShared), ssKEM: katSsKem, transcript: transcript));

    test('changing any single field changes the root key', () async {
      final baseline = await rootFor(katTranscript());
      final tampered = <String, Uint8List>{
        'encapsulatorFp': katTranscript(encapsulatorFp: 'a1b2c3d4e5f60719'),
        'decapsulatorFp': katTranscript(decapsulatorFp: 'f0e1d2c3b4a59688'),
        'encapsulatorX25519Pub':
            katTranscript(encapsulatorX25519Pub: encodeB64url(rfcBobPub)),
        'decapsulatorX25519Pub':
            katTranscript(decapsulatorX25519Pub: encodeB64url(rfcAlicePub)),
        'encapsulatorMlkemPub':
            katTranscript(encapsulatorMlkemPub: 'ENC_MLKEM_PUX'),
        'decapsulatorMlkemPub':
            katTranscript(decapsulatorMlkemPub: 'DEC_MLKEM_PUX'),
        'kemCt': katTranscript(kemCt: 'KEM_CU'),
      };
      for (final entry in tampered.entries) {
        expect(await rootFor(entry.value), isNot(baseline),
            reason: 'tampering ${entry.key} must change the root key');
      }
    });

    test('swapping encapsulator/decapsulator roles changes the root key',
        () async {
      final baseline = await rootFor(katTranscript());
      final swapped = await rootFor(katTranscript(
        encapsulatorFp: 'f0e1d2c3b4a59687',
        decapsulatorFp: 'a1b2c3d4e5f60718',
        encapsulatorX25519Pub: encodeB64url(rfcBobPub),
        decapsulatorX25519Pub: encodeB64url(rfcAlicePub),
        encapsulatorMlkemPub: 'DEC_MLKEM_PUB',
        decapsulatorMlkemPub: 'ENC_MLKEM_PUB',
      ));
      expect(swapped, isNot(baseline));
    });

    test('flipping one bit anywhere in the transcript changes the root key',
        () async {
      final t = katTranscript();
      final baseline = await rootFor(t);
      for (final i in [0, 4, 50, t.length - 1]) {
        final copy = Uint8List.fromList(t);
        copy[i] ^= 0x01;
        expect(await rootFor(copy), isNot(baseline), reason: 'byte $i');
      }
    });

    test('length prefixes prevent field-boundary ambiguity', () {
      // Without length prefixes, ("ab", "c") and ("a", "bc") would
      // concatenate to the same bytes.
      final t1 = katTranscript(encapsulatorFp: 'ab', decapsulatorFp: 'c');
      final t2 = katTranscript(encapsulatorFp: 'a', decapsulatorFp: 'bc');
      expect(hex(t1), isNot(hex(t2)));
    });
  });

  group('secret sensitivity (fixed inputs)', () {
    test('a different ML-KEM secret produces a different root key', () async {
      final base = await deriveHybridRoot(
          ssDH: unhex(rfcShared), ssKEM: katSsKem, transcript: katTranscript());
      final otherKem = Uint8List.fromList(katSsKem)..[31] ^= 0x01;
      final changed = await deriveHybridRoot(
          ssDH: unhex(rfcShared), ssKEM: otherKem, transcript: katTranscript());
      expect(hex(changed), isNot(hex(base)));
    });

    test('a different X25519 secret produces a different root key', () async {
      final base = await deriveHybridRoot(
          ssDH: unhex(rfcShared), ssKEM: katSsKem, transcript: katTranscript());
      final otherDh = unhex(rfcShared)..[0] ^= 0x01;
      final changed = await deriveHybridRoot(
          ssDH: otherDh, ssKEM: katSsKem, transcript: katTranscript());
      expect(hex(changed), isNot(hex(base)));
    });

    test('swapping the X25519 and ML-KEM secrets changes the root key',
        () async {
      final ssDh = unhex(rfcShared);
      final a = await deriveHybridRoot(
          ssDH: ssDh, ssKEM: katSsKem, transcript: katTranscript());
      final b = await deriveHybridRoot(
          ssDH: katSsKem, ssKEM: ssDh, transcript: katTranscript());
      expect(hex(a), isNot(hex(b)));
    });
  });
}
