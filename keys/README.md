# The catalogue's public keys

`catalogue_key.pub` holds the public half of the key that seals the catalogue's plugins, one line
per key:

```
ed25519 <base64 of the raw 32-byte public key>
```

Lines starting with `#` and blank lines are ignored. The private half never enters this repository:
it lives only in the secrets `CATALOGUE_SIGNING_KEY_A` / `CATALOGUE_SIGNING_KEY_B` of the GitHub
environment `catalogue-signing`.

Normally the file holds one line. During a key change it holds two, the old key and the new one,
until the change ends (the steps are in the main README, "Replacing the key"; a leaked key: never
paste the private key anywhere, and as soon as `add-seals` has finished, put the new line alone on
every server's tab). The strict check refuses a seal by any key that is not listed here, so a new
key's line is merged before anything is sealed with it, and an old key's line is removed only
after its seals are dropped.

A key's fingerprint is the first 16 hex digits of SHA-256 over its 32 bytes; every seal in
`index.json` names the fingerprint of the key that made it.
