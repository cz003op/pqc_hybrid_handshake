import 'dart:convert';
import 'dart:typed_data';

/// Unpadded base64url. This is the canonical string form the transcript
/// uses for X25519 public keys, ML-KEM public keys and the KEM ciphertext.
/// Both parties must encode identically or their transcripts will differ.
String encodeB64url(List<int> b) =>
    base64Url.encode(b).replaceAll('=', '');

/// Decodes base64url (padded or unpadded).
Uint8List decodeB64url(String s) => base64.decode(_b64urlToB64(s));

String _b64urlToB64(String s) {
  final std = s.replaceAll('-', '+').replaceAll('_', '/');
  final mod = std.length % 4;
  return mod == 0 ? std : std + '=' * (4 - mod);
}
