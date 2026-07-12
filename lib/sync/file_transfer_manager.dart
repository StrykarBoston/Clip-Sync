import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:path_provider/path_provider.dart';

class FileTransferManager {
  // Transfer ID -> map of transfer info
  final Map<String, _ActiveTransfer> _activeTransfers = {};

  // File saved callback
  Function(String filepath)? onFileSaved;
  Function(String transferId, double progress)? onProgress;

  Future<void> handleFileStart(Map<String, dynamic> data) async {
    final transferId = data['transfer_id'];
    final filename = data['filename'];
    final size = data['size'];

    // Determine save path
    Directory? dir;
    if (Platform.isAndroid) {
      // Use internal storage / custom folder
      dir = Directory('/storage/emulated/0/ClipSync');
      if (!await dir.exists()) {
        try {
          await dir.create(recursive: true);
        } catch (e) {
          // fallback
          dir = await getApplicationDocumentsDirectory();
          dir = Directory('${dir.path}/ClipSync');
          if (!await dir.exists()) {
            await dir.create(recursive: true);
          }
        }
      }
    } else {
      dir = await getApplicationDocumentsDirectory();
      dir = Directory('${dir.path}/ClipSync');
      if (!await dir.exists()) {
        await dir.create(recursive: true);
      }
    }

    final safeFilename = filename.replaceAll(RegExp(r'[^a-zA-Z0-9.\-_]'), '_');
    final savePath = '${dir.path}/$safeFilename';
    final tempPath = '$savePath.part';

    final file = File(tempPath);
    if (await file.exists()) {
      await file.delete();
    }

    _activeTransfers[transferId] = _ActiveTransfer(
      transferId: transferId,
      filename: safeFilename,
      savePath: savePath,
      tempPath: tempPath,
      totalSize: size,
      totalChunks: data['total_chunks'],
      file: file.openWrite(),
    );
  }

  Future<void> handleFileChunk(Map<String, dynamic> data) async {
    final transferId = data['transfer_id'];
    final transfer = _activeTransfers[transferId];
    if (transfer == null) return;

    final chunkData = base64Decode(data['data']);
    transfer.file.add(chunkData);
    transfer.receivedBytes += chunkData.length;

    if (onProgress != null && transfer.totalSize > 0) {
      final pct = (transfer.receivedBytes / transfer.totalSize) * 100;
      onProgress!(transferId, pct);
    }
  }

  Future<void> handleFileComplete(Map<String, dynamic> data) async {
    final transferId = data['transfer_id'];
    final expectedHash = data['hash'];
    final transfer = _activeTransfers[transferId];
    if (transfer == null) return;

    await transfer.file.close();

    // Verify hash
    final file = File(transfer.tempPath);
    final bytes = await file.readAsBytes();
    final actualHash = sha256.convert(bytes).toString();

    if (actualHash == expectedHash) {
      // Move to final path
      await file.rename(transfer.savePath);
      if (onFileSaved != null) {
        onFileSaved!(transfer.savePath);
      }
    } else {
      print('File hash mismatch for ${transfer.filename}');
      await file.delete();
    }

    _activeTransfers.remove(transferId);
  }
}

class _ActiveTransfer {
  final String transferId;
  final String filename;
  final String savePath;
  final String tempPath;
  final int totalSize;
  final int totalChunks;
  final IOSink file;
  int receivedBytes = 0;

  _ActiveTransfer({
    required this.transferId,
    required this.filename,
    required this.savePath,
    required this.tempPath,
    required this.totalSize,
    required this.totalChunks,
    required this.file,
  });
}
