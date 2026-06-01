import 'dart:io';
import 'package:flutter/services.dart';
import 'package:clipboard_watcher/clipboard_watcher.dart';
import 'package:flutter/foundation.dart';

class ClipboardService with ClipboardListener {
  static final ClipboardService _instance = ClipboardService._internal();
  factory ClipboardService() => _instance;
  ClipboardService._internal();

  Function(String text)? onClipboardTextChanged;

  void initialize() {
    if (!kIsWeb && (Platform.isWindows || Platform.isLinux || Platform.isMacOS)) {
      clipboardWatcher.addListener(this);
      clipboardWatcher.start();
    }
  }

  void dispose() {
    if (!kIsWeb && (Platform.isWindows || Platform.isLinux || Platform.isMacOS)) {
      clipboardWatcher.removeListener(this);
      clipboardWatcher.stop();
    }
  }

  @override
  void onClipboardChanged() async {
    final text = await getClipboardText();
    if (text != null && onClipboardTextChanged != null) {
      onClipboardTextChanged!(text);
    }
  }

  Future<void> setClipboardText(String text) async {
    // Check if it's already the same to avoid feedback loops
    final currentText = await getClipboardText();
    if (currentText != text) {
      await Clipboard.setData(ClipboardData(text: text));
    }
  }

  Future<String?> getClipboardText() async {
    final data = await Clipboard.getData('text/plain');
    return data?.text;
  }
}
