import 'dart:convert';
import 'package:cryptography/cryptography.dart';

class SecurityManager {
  late final SecretKey _secretKey;
  final _algorithm = AesGcm.with256bits();

  void initialize(String sharedSecretHex) {
    if (sharedSecretHex.isEmpty) {
      throw Exception('SECRET_KEY cannot be empty!');
    }
    // --- VULN-011 FIX: Use HKDF for key derivation ---
    // Derive the AES key from the raw hex using HKDF with SHA-256.
    // This matches the Python side: HKDF(SHA256, length=32, salt=None, info=b'clipsync-e2ee')
    final rawKey = _hexDecode(sharedSecretHex);
    _secretKey = SecretKey(rawKey);
    _initDerivedKey(rawKey);
  }

  Future<void> _initDerivedKey(List<int> rawKey) async {
    final hkdf = Hkdf(hmac: Hmac(Sha256()), outputLength: 32);
    final derivedKey = await hkdf.deriveKey(
      secretKey: SecretKey(rawKey),
      nonce: <int>[], // No salt (equivalent to Python salt=None)
      info: utf8.encode('clipsync-e2ee'),
    );
    _secretKey = derivedKey;
  }

  /// Must be called after initialize() and awaited before encrypt/decrypt.
  Future<void> ensureReady(String sharedSecretHex) async {
    final rawKey = _hexDecode(sharedSecretHex);
    await _initDerivedKey(rawKey);
  }

  List<int> _hexDecode(String hexStr) {
    final result = <int>[];
    for (int i = 0; i < hexStr.length; i += 2) {
      result.add(int.parse(hexStr.substring(i, i + 2), radix: 16));
    }
    return result;
  }

  Future<String> encryptMessage(Map<String, dynamic> messageDict) async {
    final plaintext = utf8.encode(jsonEncode(messageDict));

    // --- VULN-009 FIX: Add AAD (message type) to AES-GCM ---
    final msgType = messageDict['type'] ?? 'unknown';
    final aad = utf8.encode(msgType.toString());

    final secretBox = await _algorithm.encrypt(
      plaintext,
      secretKey: _secretKey,
      aad: aad,
    );

    // To interoperate with python's cryptography AESGCM:
    // Python returns ciphertext + mac as a single bytes object.
    final dataBytes = <int>[...secretBox.cipherText, ...secretBox.mac.bytes];

    final payload = {
      'iv': base64Encode(secretBox.nonce),
      'data': base64Encode(dataBytes),
      'aad': msgType.toString(),
    };

    return jsonEncode(payload);
  }

  Future<Map<String, dynamic>?> decryptMessage(String payloadStr) async {
    try {
      final payload = jsonDecode(payloadStr);
      if (payload['iv'] == null || payload['data'] == null) return null;

      final nonce = base64Decode(payload['iv']);
      final dataBytes = base64Decode(payload['data']);

      if (dataBytes.length < 16) return null; // Needs at least the 16 byte MAC

      final cipherText = dataBytes.sublist(0, dataBytes.length - 16);
      final macBytes = dataBytes.sublist(dataBytes.length - 16);

      // --- VULN-009 FIX: Verify AAD ---
      final aadStr = payload['aad'] ?? 'unknown';
      final aad = utf8.encode(aadStr.toString());

      final secretBox = SecretBox(
        cipherText,
        nonce: nonce,
        mac: Mac(macBytes),
      );

      final clearTextBytes = await _algorithm.decrypt(
        secretBox,
        secretKey: _secretKey,
        aad: aad,
      );

      return jsonDecode(utf8.decode(clearTextBytes));
    } catch (e) {
      print('Decryption failed: $e');
      return null;
    }
  }
}
