# ClipSync Security Architecture

ClipSync is a LAN-only, text-only clipboard synchronization system. Images, files, media, uploads, downloads, and binary transfer protocols are outside the product scope.

## Data flow

1. The local clipboard monitor reads text.
2. Sensitive-data filters may block the text locally.
3. The text is encoded as a `clipboard` JSON message.
4. AES-256-GCM encrypts the message using an HKDF-derived key.
5. The authenticated message travels over a secure WebSocket.
6. An authenticated peer decrypts the text and writes it to its clipboard.

## Peer authentication

- Devices discover peers with mDNS/Zeroconf on the local network.
- A shared 256-bit hexadecimal secret derives the AES key and HMAC challenge key.
- Handshakes require an encrypted hello message, a recent timestamp, a fresh nonce, and a five-minute HMAC challenge.
- Nonces are cached with TTL eviction to prevent handshake replay.
- Certificate fingerprints are pinned per peer where supported.
- Unauthenticated sockets are never added to the broadcast pool.
- Unsupported message types are rejected.

## Boundaries

The Flask dashboard binds to localhost. The peer WebSocket service uses the configured LAN port. The LAN and the shared secret are trust boundaries; a compromised trusted device or exposed key can read synchronized text.

## Residual risks

Sensitive-data detection is pattern-based and can miss unknown secrets. Users should avoid copying secrets when synchronization is enabled and rotate the shared key if a device or configuration file is exposed.
