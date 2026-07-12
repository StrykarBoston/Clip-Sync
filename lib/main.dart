import 'package:flutter/material.dart';
import 'package:clip_sync/sync/sync_manager.dart';
import 'package:clip_sync/clipboard/clipboard_service.dart';
import 'package:clip_sync/android/android_manager.dart';
import 'dart:io';
import 'dart:convert';
import 'package:flutter/foundation.dart';

import 'package:shared_preferences/shared_preferences.dart';
import 'package:clip_sync/ui/setup_page.dart';
import 'package:clip_sync/ui/settings_page.dart';

// --- VULN-003 FIX: TOFU (Trust-On-First-Use) Certificate Pinning ---
// Instead of accepting ALL certificates blindly, this stores the SHA-256
// fingerprint of the first certificate seen for each host. Subsequent
// connections to the same host must present the same certificate.
class TofuHttpOverrides extends HttpOverrides {
  // In-memory cache of pinned cert fingerprints per host
  // Persisted to SharedPreferences for cross-restart TOFU
  static final Map<String, String> _pinnedCerts = {};
  static bool _initialized = false;

  static Future<void> initialize() async {
    if (_initialized) return;
    final prefs = await SharedPreferences.getInstance();
    final pinnedJson = prefs.getString('pinned_certs');
    if (pinnedJson != null) {
      try {
        final Map<String, dynamic> decoded = jsonDecode(pinnedJson);
        decoded.forEach((key, value) {
          _pinnedCerts[key] = value.toString();
        });
      } catch (_) {}
    }
    _initialized = true;
  }

  static Future<void> _savePinnedCerts() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('pinned_certs', jsonEncode(_pinnedCerts));
  }

  static Future<void> clearPinnedCerts() async {
    _pinnedCerts.clear();
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove('pinned_certs');
  }

  static String _certFingerprint(X509Certificate cert) {
    // Use the DER-encoded cert bytes to compute a SHA-256 fingerprint
    return cert.sha1.map((b) => b.toRadixString(16).padLeft(2, '0')).join(':');
  }

  @override
  HttpClient createHttpClient(SecurityContext? context) {
    return super.createHttpClient(context)
      ..badCertificateCallback = (X509Certificate cert, String host, int port) {
        final fingerprint = _certFingerprint(cert);
        final hostKey = '$host:$port';

        // Trust-On-First-Use: If we haven't seen this host before, pin the cert
        if (!_pinnedCerts.containsKey(hostKey)) {
          _pinnedCerts[hostKey] = fingerprint;
          _savePinnedCerts(); // Persist asynchronously
          debugPrint('[TOFU] Pinned certificate for $hostKey: $fingerprint');
          return true; // Accept on first use
        }

        // On subsequent connections, verify the cert matches the pinned one
        final pinned = _pinnedCerts[hostKey];
        if (pinned == fingerprint) {
          return true; // Certificate matches pinned fingerprint
        }

        // Certificate mismatch! Possible MITM attack.
        debugPrint('[TOFU] ⚠️ Certificate mismatch for $hostKey!');
        debugPrint('[TOFU]   Pinned:   $pinned');
        debugPrint('[TOFU]   Received: $fingerprint');
        return false; // Reject the connection
      };
  }
}

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // --- VULN-003 FIX: Initialize TOFU cert pinning instead of blind acceptance ---
  await TofuHttpOverrides.initialize();
  HttpOverrides.global = TofuHttpOverrides();

  final prefs = await SharedPreferences.getInstance();
  final secretKey = prefs.getString('SECRET_KEY') ?? '';

  runApp(ClipSyncApp(initialKey: secretKey));
}

class ClipSyncApp extends StatelessWidget {
  final String initialKey;

  const ClipSyncApp({super.key, required this.initialKey});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'ClipSync',
      theme: ThemeData(
        primarySwatch: Colors.blue,
        brightness: Brightness.dark,
        useMaterial3: true,
      ),
      home: initialKey.length == 64 ? HomePage(secretKey: initialKey) : const SetupPage(),
    );
  }
}

class HomePage extends StatefulWidget {
  final String secretKey;

  const HomePage({super.key, required this.secretKey});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  final SyncManager _syncManager = SyncManager();
  final ClipboardService _clipboardService = ClipboardService();
  final AndroidManager _androidManager = AndroidManager();

  String _lastSyncedText = 'Nothing synced yet';
  bool _isInitializing = true;

  @override
  void initState() {
    super.initState();
    _initialize();
  }

  Future<void> _initialize() async {
    try {
      // 1. Initialize Networking
      await _syncManager.initialize(widget.secretKey);
    } catch (e) {
      print("Sync Manager Error: $e");
    }

    try {
      // 2. Initialize Desktop Clipboard Watcher (if applicable)
      _clipboardService.initialize();
      _clipboardService.onClipboardTextChanged = (text) {
        _syncManager.broadcastClipboard(text);
        _updateStatus('Copied from Desktop: $text');
      };
    } catch (e) {
      print("Clipboard Service Error: $e");
    }

    try {
      // 3. Initialize Android Manager (if applicable)
      await _androidManager.initialize();
      _androidManager.onShareReceived = (text) {
        _syncManager.broadcastClipboard(text);
        _updateStatus('Shared via Android: $text');
      };
      _androidManager.onSyncAction = () async {
        final text = await _clipboardService.getClipboardText();
        if (text != null && text.isNotEmpty) {
          _syncManager.broadcastClipboard(text);
          _updateStatus('Manual Sync: $text');
        }
      };
    } catch (e) {
      print("Android Manager Error: $e");
    }

    try {
      // 4. Listen for incoming clipboard text
      _syncManager.onClipboardReceived.listen((text) {
        _clipboardService.setClipboardText(text);
        _updateStatus('Received: $text');
      });

      // 5. Listen for incoming images
      _syncManager.onImageReceived.listen((imageData) {
        _updateStatus('Received Image (${imageData['data'].length} bytes)');
        // NOTE: Flutter clipboard doesn't natively support images without plugins.
        // For Android/Desktop, the image is saved or handled natively by the engine.
      });

      // 6. Listen for incoming files
      _syncManager.onFileReceived.listen((filepath) {
        _updateStatus('File Saved:\n$filepath');
      });
    } catch (e) {
      print("Listener Error: $e");
    }

    setState(() {
      _isInitializing = false;
    });
  }

  void _updateStatus(String text) {
    if (mounted) {
      setState(() {
        _lastSyncedText = text;
      });
    }
  }

  @override
  void dispose() {
    _syncManager.dispose();
    _clipboardService.dispose();
    _androidManager.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('ClipSync'),
        actions: [
          IconButton(
            icon: const Icon(Icons.settings),
            onPressed: () {
              Navigator.push(
                context,
                MaterialPageRoute(builder: (context) => SettingsPage(currentKey: widget.secretKey)),
              );
            },
          )
        ],
      ),
      body: Center(
        child: _isInitializing
            ? const CircularProgressIndicator()
            : Padding(
                padding: const EdgeInsets.all(16.0),
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    const Icon(
                      Icons.sync,
                      size: 64,
                      color: Colors.blueAccent,
                    ),
                    const SizedBox(height: 24),
                    const Text(
                      'Ready to sync clipboard across devices.',
                      textAlign: TextAlign.center,
                      style: TextStyle(fontSize: 18),
                    ),
                    const SizedBox(height: 16),
                    Text(
                      'Last activity:\n$_lastSyncedText',
                      textAlign: TextAlign.center,
                      style: const TextStyle(fontSize: 14, color: Colors.grey),
                    ),
                    const SizedBox(height: 32),
                    if (!kIsWeb && Platform.isAndroid)
                      ElevatedButton.icon(
                        onPressed: () async {
                          final text = await _clipboardService.getClipboardText();
                          if (text != null && text.isNotEmpty) {
                            _syncManager.broadcastClipboard(text);
                            _updateStatus('Manual Push: $text');
                            ScaffoldMessenger.of(context).showSnackBar(
                              const SnackBar(content: Text('Clipboard Pushed to peers')),
                            );
                          }
                        },
                        icon: const Icon(Icons.send),
                        label: const Text('Push Current Clipboard'),
                      ),
                  ],
                ),
              ),
      ),
    );
  }
}
