# ssh-sk-rk-patcher

A tiny utility to fix FIDO flags in OpenSSH `sk-ssh-ed25519@openssh.com` private keys.

After restoring resident credentials with `ssh-keygen -K`, the User Verification (UV) and User Presence (UP)
flags are not restored at all. The result: the key won’t authenticate until those flags are set back.
Consider this a friendly little patcher that returns the flags to their rightful place.

## What it does
- Parses an OpenSSH `OPENSSH PRIVATE KEY` of type `sk-ssh-ed25519@openssh.com`.
- Toggles flags inside the file:
    - `+uv` / `-uv` — enable/disable User Verification
    - `+up` / `-up` — enable/disable User Presence
- Outputs the patched key to stdout or atomically overwrites the file with `-i`.

Notes:
- Only unencrypted private keys are supported.
- This updates flags in the local private key file; it does not recreate credentials on the security key.

## Install

```bash
go install github.com/savely-krasovsky/ssh-sk-rk-patcher@master
```

### Usage

```bash
ssh-sk-rk-patcher +uv ~/.ssh/id_ed25519_sk # Outputs patched key to stdout
ssh-sk-rk-patcher -i +uv ~/.ssh/id_ed25519_sk # Overwrites the file with patched key
```

With any luck, one day this tool will become delightfully unnecessary.