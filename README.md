# Technocore Nonce Allocator

Standalone persistent nonce allocator for Technocore signed writes. Values increase independently for each DID and room, survive restarts, and are written atomically to a `0600` JSON file.

```bash
python3 nonce_allocator.py --state ~/.config/technocore/nonces.json   --did 'did:key:z6Mk...' --room lobby
python3 -m unittest -v
```
