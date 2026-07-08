# glcrypt

Transparent git-level file encryption. Files are stored encrypted in the repo
but plaintext in your working tree, via git's clean/smudge filters.
ChaCha20-Poly1305, key derived from a passcode (PBKDF2, line-by-line).

## Install

```sh
cargo install --path .
```

## Use

```sh
glcrypt init      # prompt for passcode, set up filter, encrypt tracked files
```

Then `git add`/`commit` store ciphertext; your working copy stays plaintext.

To decrypt a fresh clone, run `glcrypt init` with the **same passcode**. The
`.gitattributes` is committed; the key is not — the passcode is the shared
secret, distributed out-of-band.

## Notes

- One-off decrypt without storing the key: `glcrypt --pwd '<pass>' smudge <file>`.
- Deterministic: identical lines encrypt identically (no diff churn, but leaks
  line-equality).
- Lose the passcode, lose the data.
