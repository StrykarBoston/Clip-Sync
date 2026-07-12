import 'dart:async';
import 'dart:io';

import 'package:nsd/nsd.dart';
import 'package:uuid/uuid.dart';
import 'package:clip_sync/sync/security_manager.dart';
import 'dart:convert';
import 'package:flutter/services.dart' show rootBundle;
import 'package:clip_sync/sync/file_transfer_manager.dart';
import 'package:cryptography/cryptography.dart';
import 'dart:math';

class SyncManager {
  static final SyncManager _instance = SyncManager._internal();
  factory SyncManager() => _instance;
  SyncManager._internal() {
    _fileManager = FileTransferManager();
    _fileManager.onFileSaved = (path) {
      _fileStreamController.add(path);
    };
  }

  final String deviceId = const Uuid().v4();

  Registration? _registration;
  Discovery? _discovery;

  HttpServer? _server;
  final List<WebSocket> _clients = [];

  final _clipboardStreamController = StreamController<String>.broadcast();
  Stream<String> get onClipboardReceived => _clipboardStreamController.stream;

  final _imageStreamController = StreamController<Map<String, dynamic>>.broadcast();
  Stream<Map<String, dynamic>> get onImageReceived => _imageStreamController.stream;

  final _fileStreamController = StreamController<String>.broadcast();
  Stream<String> get onFileReceived => _fileStreamController.stream;

  final Set<String> _connectedPeers = {};
  final Map<String, int> _seenNonces = {}; // {nonce: epoch_seconds} for TTL-based eviction
  final SecurityManager _securityManager = SecurityManager();
  
  // File Transfer
  late final FileTransferManager _fileManager;

  // --- VULN-004 FIX: Per-IP connection tracking ---
  final Map<String, int> _connectionsPerIp = {};
  static const int _maxConnectionsPerIp = 5;

  int get port => 52300;
  bool get syncSensitiveData => false;

  String _secretKey = '';
  String get secretKey => _secretKey;

  // --- VULN-008 FIX: HMAC-based time-window challenge instead of static fingerprint ---
  Future<String> _computeNetworkChallenge() async {
    if (secretKey.isEmpty) return "";
    final timeWindow = DateTime.now().millisecondsSinceEpoch ~/ 1000 ~/ 300; // 5-minute windows
    final msg = utf8.encode('clipsync-challenge:$timeWindow');
    final hmac = Hmac(Sha256());
    final mac = await hmac.calculateMac(msg, secretKey: SecretKey(utf8.encode(secretKey)));
    return mac.bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join().substring(0, 16);
  }

  Future<bool> _verifyNetworkChallenge(String challenge) async {
    final current = await _computeNetworkChallenge();
    if (_constantTimeEquals(challenge, current)) return true;

    // Check previous window for clock skew tolerance
    final prevWindow = (DateTime.now().millisecondsSinceEpoch ~/ 1000 ~/ 300) - 1;
    final prevMsg = utf8.encode('clipsync-challenge:$prevWindow');
    final hmac = Hmac(Sha256());
    final prevMac = await hmac.calculateMac(prevMsg, secretKey: SecretKey(utf8.encode(secretKey)));
    final prevChallenge = prevMac.bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join().substring(0, 16);
    return _constantTimeEquals(challenge, prevChallenge);
  }

  bool _constantTimeEquals(String a, String b) {
    if (a.length != b.length) return false;
    int result = 0;
    for (int i = 0; i < a.length; i++) {
      result |= a.codeUnitAt(i) ^ b.codeUnitAt(i);
    }
    return result == 0;
  }

  // --- VULN-019 FIX: Expanded sensitive data filter ---
  bool isSensitive(String text) {
    if (syncSensitiveData) return false;
    // Credit card numbers
    if (RegExp(r'\b(?:\d[ -]*?){13,19}\b').hasMatch(text)) return true;
    // Private key headers
    if (text.contains('-----BEGIN') && text.contains('PRIVATE KEY-----')) return true;
    // Social Security Numbers (SSN)
    if (RegExp(r'\b\d{3}-\d{2}-\d{4}\b').hasMatch(text)) return true;
    // AWS Access Key IDs
    if (RegExp(r'AKIA[0-9A-Z]{16}').hasMatch(text)) return true;
    // AWS Secret Access Keys
    if (RegExp(r'(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*\S{40}').hasMatch(text)) return true;
    // Generic API keys / tokens
    if (RegExp(r'(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token)\s*[:=]\s*\S{16,}', caseSensitive: false).hasMatch(text)) return true;
    // JSON Web Tokens (JWT)
    if (RegExp(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}').hasMatch(text)) return true;
    // Password patterns
    if (RegExp(r'(?:password|passwd|pwd)\s*[:=]\s*\S+', caseSensitive: false).hasMatch(text)) return true;
    return false;
  }

  Future<void> initialize(String key) async {
    _secretKey = key;
    _securityManager.initialize(key);
    // --- VULN-011 FIX: Await HKDF key derivation ---
    await _securityManager.ensureReady(key);

    // Start local WebSocket server
    await _startServer();

    // Register mDNS service
    await _registerService();

    // Start discovering peers
    await _startDiscovery();
  }

  Future<void> _startServer() async {
    try {
      final certBytes = await rootBundle.load('assets/certs/tls_cert.pem');
      final keyBytes = await rootBundle.load('assets/certs/tls_key.pem');

      SecurityContext securityContext = SecurityContext()
        ..useCertificateChainBytes(certBytes.buffer.asUint8List())
        ..usePrivateKeyBytes(keyBytes.buffer.asUint8List());

      _server = await HttpServer.bindSecure(InternetAddress.anyIPv4, port, securityContext);
      print('Secure WSS Server started on port ${_server!.port}');

      _server!.listen((HttpRequest request) {
        if (WebSocketTransformer.isUpgradeRequest(request)) {
          // --- VULN-004 FIX: Per-IP connection limiting ---
          final remoteIp = request.connectionInfo?.remoteAddress.address ?? 'unknown';
          final currentCount = _connectionsPerIp[remoteIp] ?? 0;
          if (currentCount >= _maxConnectionsPerIp) {
            print('Connection limit exceeded for IP $remoteIp. Rejecting.');
            request.response.statusCode = 429;
            request.response.close();
            return;
          }

          WebSocketTransformer.upgrade(request).then((WebSocket ws) {
            _connectionsPerIp[remoteIp] = currentCount + 1;
            _handleConnection(ws, remoteIp);
          });
        }
      });
    } catch (e) {
      print('Failed to start server: $e');
    }
  }

  /// Remove nonces older than 60 seconds from the cache.
  void _evictExpiredNonces() {
    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    _seenNonces.removeWhere((_, ts) => now - ts > 60);
  }

  void _handleConnection(WebSocket ws, [String remoteIp = 'unknown']) async {
    // NOTE: ws is NOT added to _clients until auth passes
    bool isAuthenticated = false;
    Timer? authTimeout;

    authTimeout = Timer(const Duration(seconds: 2), () {
      if (!isAuthenticated) {
        print('Peer auth handshake timed out');
        ws.close();
      }
    });

    ws.listen(
      (data) async {
        try {
          final message = await _securityManager.decryptMessage(data as String);
          if (message == null) {
            // Decryption failed or invalid payload, ignore to prevent attacks
            return;
          }

          if (message['type'] == 'hello') {
            // Replay Protection: Timestamp check (30 seconds)
            final int ts = message['timestamp'] ?? 0;
            final int currentTs = DateTime.now().millisecondsSinceEpoch ~/ 1000;
            if ((currentTs - ts).abs() > 30) {
              print('Peer $remoteIp failed auth handshake: Timestamp expired');
              // --- VULN-015 FIX: Close silently instead of sending plaintext rejection ---
              ws.close();
              return;
            }

            // Replay Protection: Nonce cache with TTL-based eviction
            _evictExpiredNonces();
            final String? nonce = message['nonce'];
            if (nonce == null || _seenNonces.containsKey(nonce)) {
              print('Peer $remoteIp failed auth handshake: Nonce reused');
              ws.close();
              return;
            }
            _seenNonces[nonce] = currentTs;

            // --- VULN-008 FIX: HMAC-based challenge verification ---
            final challenge = message['fingerprint'] ?? '';
            if (!await _verifyNetworkChallenge(challenge)) {
              print('Peer $remoteIp failed auth handshake: Invalid challenge');
              ws.close();
              return;
            }

            // === AUTH PASSED — only NOW add to broadcast pool ===
            isAuthenticated = true;
            _clients.add(ws);
            authTimeout?.cancel();
            final peerId = message['deviceId'];
            _connectedPeers.add(peerId);
            print('Securely connected to peer: $peerId');
          } else if (message['type'] == 'clipboard') {
            if (!isAuthenticated) return;
            final text = message['text'];
            _clipboardStreamController.add(text);
          } else if (message['type'] == 'clipboard_image') {
            if (!isAuthenticated) return;
            _imageStreamController.add({
              'data': base64Decode(message['data']),
              'format': message['format'],
            });
          } else if (message['type'] == 'file_start') {
            if (!isAuthenticated) return;
            await _fileManager.handleFileStart(message);
          } else if (message['type'] == 'file_chunk') {
            if (!isAuthenticated) return;
            await _fileManager.handleFileChunk(message);
          } else if (message['type'] == 'file_complete') {
            if (!isAuthenticated) return;
            await _fileManager.handleFileComplete(message);
          }
        } catch (e) {
          print('Invalid message: $e');
        }
      },
      onDone: () {
        if (isAuthenticated) _clients.remove(ws);
        // --- VULN-004 FIX: Decrement per-IP counter ---
        _connectionsPerIp[remoteIp] = max(0, (_connectionsPerIp[remoteIp] ?? 1) - 1);
        if (_connectionsPerIp[remoteIp] == 0) _connectionsPerIp.remove(remoteIp);
      },
      onError: (e) {
        if (isAuthenticated) _clients.remove(ws);
        _connectionsPerIp[remoteIp] = max(0, (_connectionsPerIp[remoteIp] ?? 1) - 1);
        if (_connectionsPerIp[remoteIp] == 0) _connectionsPerIp.remove(remoteIp);
      },
    );

    // Say hello
    final helloPayload = {
      'type': 'hello',
      'deviceId': deviceId,
      'timestamp': DateTime.now().millisecondsSinceEpoch ~/ 1000,
      'nonce': const Uuid().v4(),
      'fingerprint': await _computeNetworkChallenge()
    };
    final helloMessage = await _securityManager.encryptMessage(helloPayload);
    ws.add(helloMessage);
  }

  Future<void> _registerService() async {
    if (_server == null) return;

    try {
      // --- VULN-007 FIX: Generic service name without platform identifier ---
      // --- VULN-008 FIX: No fingerprint in mDNS TXT records ---
      _registration = await register(
        Service(
          name: 'ClipSync-${deviceId.substring(0, 4)}',
          type: '_clipsync._tcp',
          host: '',
          port: _server!.port,
          txt: {}, // No fingerprint broadcast
        ),
      );
    } catch (e) {
      print('Register failed: $e');
    }
  }

  Future<void> _startDiscovery() async {
    try {
      _discovery = await startDiscovery('_clipsync._tcp');
      _discovery!.addListener(() {
        for (final service in _discovery!.services) {
          _connectToService(service);
        }
      });
    } catch (e) {
      print('Discovery failed: $e');
    }
  }

  Future<void> _connectToService(Service service) async {
    if (service.host == null || service.port == null) return;

    final host = service.host!;
    final port = service.port!;

    try {
      final ws = await WebSocket.connect('wss://$host:$port');
      _handleConnection(ws, host);
    } catch (e) {
      print('Could not connect to service $host:$port: $e');
    }
  }

  Future<void> broadcastClipboard(String text) async {
    if (isSensitive(text)) {
      print('Sensitive data detected in clipboard. Sync paused for this item.');
      return;
    }
    final message = await _securityManager.encryptMessage({'type': 'clipboard', 'text': text});
    for (final ws in _clients) {
      ws.add(message);
    }
  }

  void dispose() {
    if (_registration != null) unregister(_registration!);
    if (_discovery != null) stopDiscovery(_discovery!);
    _server?.close();
  }
}
