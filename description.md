# Nsec Bunker

Nsec Bunker is a Nostr key vault and signing oracle for LNbits. It keeps private keys encrypted with the LNbits server secret and lets wallet administrators grant narrowly scoped signing permissions to installed extensions.

## Features

- Store and label multiple Nostr identities per wallet.
- Sign events with explicit per-key, per-extension, and per-kind permissions.
- Apply positive, paired rate limits with atomic database enforcement.
- Encrypt and decrypt messages with NIP-04 and NIP-44.
- Discover signing requirements declared by other LNbits extensions.
- Review a wallet-scoped signing audit log.
- Export keys using an admin wallet key for backup or migration.

REST operations that sign, encrypt, decrypt, manage permissions, or expose private keys require the wallet admin key. Invoice keys can only retrieve public keys.
