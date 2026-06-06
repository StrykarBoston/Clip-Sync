import 'package:flutter/material.dart';
import 'package:clip_sync/sync/sync_manager.dart';
import 'package:clip_sync/clipboard/clipboard_service.dart';
import 'package:clip_sync/android/android_manager.dart';
import 'dart:io';
import 'package:flutter/foundation.dart';

import 'package:shared_preferences/shared_preferences.dart';
import 'package:clip_sync/ui/setup_page.dart';
import 'package:clip_sync/ui/settings_page.dart';
class MyHttpOverrides extends HttpOverrides {
  @override
  HttpClient createHttpClient(SecurityContext? context) {
    return super.createHttpClient(context)
      ..badCertificateCallback = (X509Certificate cert, String host, int port) => true;
  }
}

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = MyHttpOverrides();
  
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
