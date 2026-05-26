# Vault Transit Signing Setup

HashiCorp Vault Transit secrets engine integration for `VaultTransitSigner`.

## Quick verification

After setup, run:

```sh
aevum vault-check
```

Exits 0 on success, 1 on failure. Reads `VAULT_ADDR`, `VAULT_TOKEN`, and
`AEVUM_VAULT_KEY_NAME` from the environment.

---

## Windows (PowerShell)

```powershell
# Install Vault
winget install HashiCorp.Vault

# Start a dev server (NOT for production — in-memory, unsealed, single-node)
vault server -dev

# In a second terminal, configure
$env:VAULT_ADDR  = "http://127.0.0.1:8200"
$env:VAULT_TOKEN = "root"   # printed by vault server -dev

vault secrets enable transit
vault write transit/keys/aevum-signing      type=ed25519
vault write transit/keys/aevum-signing-test type=ed25519

# Verify
$env:AEVUM_VAULT_KEY_NAME = "aevum-signing-test"
aevum vault-check
```

---

## Linux / macOS

```sh
# Install (choose one)
# Debian/Ubuntu:
wget -O - https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install vault
# macOS:
brew tap hashicorp/tap && brew install hashicorp/tap/vault

# Dev server
vault server -dev &

export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN="root"

vault secrets enable transit
vault write transit/keys/aevum-signing      type=ed25519
vault write transit/keys/aevum-signing-test type=ed25519

export AEVUM_VAULT_KEY_NAME=aevum-signing-test
aevum vault-check
```

---

## Key naming convention

| Key name              | Purpose                               |
|-----------------------|---------------------------------------|
| `aevum-signing`       | Production signing key                |
| `aevum-signing-test`  | Integration test key (isolated)       |

Never use `aevum-signing` in integration tests. The `aevum vault-check` command
defaults to `AEVUM_VAULT_KEY_NAME`; set it to `aevum-signing-test` for tests.

---

## Production: AppRole authentication

Dev-root tokens are not suitable for production. Use AppRole:

```sh
# Enable AppRole auth
vault auth enable approle

# Write a policy granting Transit sign/verify on the production key
vault policy write aevum-signer - <<EOF
path "transit/sign/aevum-signing" {
  capabilities = ["create", "update"]
}
path "transit/verify/aevum-signing" {
  capabilities = ["create", "update"]
}
path "transit/keys/aevum-signing" {
  capabilities = ["read"]
}
EOF

# Create an AppRole bound to that policy
vault write auth/approle/role/aevum-signer \
  token_policies="aevum-signer" \
  token_ttl=1h \
  token_max_ttl=4h \
  secret_id_ttl=24h

# Retrieve credentials
vault read -format=json auth/approle/role/aevum-signer/role-id \
  | jq -r .data.role_id

vault write -format=json -f auth/approle/role/aevum-signer/secret-id \
  | jq -r .data.secret_id

# Exchange for a token (do this in your deploy pipeline, not hardcoded)
vault write -format=json auth/approle/login \
  role_id="<role_id>" secret_id="<secret_id>" \
  | jq -r .auth.client_token
```

Set `VAULT_TOKEN` to the resulting token in your service's environment.

---

## Minimum Vault policy

```hcl
# Minimum policy for VaultTransitSigner (production key)
path "transit/sign/aevum-signing" {
  capabilities = ["create", "update"]
}
path "transit/verify/aevum-signing" {
  capabilities = ["create", "update"]
}
path "transit/keys/aevum-signing" {
  capabilities = ["read"]
}
```

---

## Environment variables

| Variable               | Default                     | Description                        |
|------------------------|-----------------------------|------------------------------------|
| `VAULT_ADDR`           | `http://127.0.0.1:8200`     | Vault server URL                   |
| `VAULT_TOKEN`          | _(required)_                | Vault token for authentication     |
| `AEVUM_VAULT_KEY_NAME` | `aevum-signing`             | Transit key name for `vault-check` |

`VaultTransitSigner` constructor also accepts `vault_addr=` and `token=` directly.

---

## Important notes

- Vault dev mode (`-dev`) is **in-memory only** — all data is lost on restart.
- The `prehashed` parameter must be `false` for ed25519 keys in Vault Transit
  (Vault 2.x requires Pure Ed25519; prehashed mode is not supported for ed25519).
- Key rotation is handled by Vault automatically; `key_id` in Aevum remains stable
  across rotations (it encodes the key name, not the version).
- See [key-rotation.md](key-rotation.md) for key rotation procedures.
