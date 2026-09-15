# ClipSync

ClipSync securely synchronizes clipboard text between trusted devices on the same LAN. It does not synchronize images, files, media, or binary data.

## Architecture

- `clip_sync_desktop/`: unified Python desktop application for Windows and Linux
- `lib/`: Flutter Android client
- mDNS/Zeroconf: local peer discovery
- Secure WebSockets: peer transport
- AES-256-GCM with HKDF: message confidentiality and integrity
- HMAC challenge, timestamps, nonce cache, and certificate fingerprints: peer authentication and replay resistance

Only encrypted messages with type `clipboard` are accepted after authentication. Other message types are rejected.

## Desktop setup

```text
cd clip_sync_desktop
python -m venv .venv
.venv\\Scripts\\activate       # Windows
source .venv/bin/activate       # Linux
pip install -r requirements.txt
```

Copy `.env.example` to `.env` and set a shared 64-character hexadecimal `SECRET_KEY`. Start the dashboard with:

```text
python app.py
```

Open `http://127.0.0.1:5000`.

## Android setup

Build the Flutter application, enter the same 64-character key in the setup screen, and grant clipboard/share permissions as requested. Android share handling accepts text only.

## Security notes

The shared key must be kept private and must be different from keys used elsewhere. Clipboard contents can contain secrets; sensitive-data filtering is enabled by default, but filtering is heuristic and cannot replace user judgment.
