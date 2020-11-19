# Crypto contribox-proto Server

## Start server

```bash
  python server.py
```

## Call JsonRPC method

```bash
export SSM_ENDPOINT="http://localhost:5500/api/v1"
export MASTER_ENTROPY="1b278d56ad8701d810362a18ee1a7b560cc4a0982ee1858be4dda1eca84bea7f"
export CHAIN="elements-regtest"

curl -i -X POST -H "Content-Type: application/json" -d '{
        "jsonrpc": "2.0",
        "method": "new_master",
        "params": ["'"$CHAIN"'", "'"$MASTER_ENTROPY"'", true],
        "id": "42"
    }' $SSM_ENDPOINT
```

```bash
export SSM_ENDPOINT="http://localhost:5500/api/v1"
export KEY_FINGERPRINT="ce9e7a9b"

curl -i -X POST -H "Content-Type: application/json" -d '{
        "jsonrpc": "2.0",
        "method": "get_xpub",
        "params": ["'"$CHAIN"'", "'"$KEY_FINGERPRINT"'"],
        "id": "42"
    }' $SSM_ENDPOINT
```

```bash
export SSM_ENDPOINT="http://localhost:5500/api/v1"
export KEY_FINGERPRINT="ce9e7a9b"

curl -i -X POST -H "Content-Type: application/json" -d '{
        "jsonrpc": "2.0",
        "method": "get_xprv",
        "params": ["bitcoin-main", "'"$KEY_FINGERPRINT"'"],
        "id": "42"
    }' $SSM_ENDPOINT
```

```bash
export SSM_ENDPOINT="http://localhost:5500/api/v1"
export HD_PATH="84/0/1"
export XPUB="tpubD6NzVbkrYhZ4WbScGMjFV1RFPh7W6xUZZDzx1Zt5YZyVem4Zoqws3kB79PVhCrmWhdTzPYxfPadN7oSsHt1a4kwrSzVpm1ExqcuhYBX9En1"

curl -i -X POST -H "Content-Type: application/json" -d '{
        "jsonrpc": "2.0",
        "method": "new_address",
        "params": ["'"$CHAIN"'", "'"$XPUB"'", "'"$HD_PATH"'"],
        "id": "42"
    }' $SSM_ENDPOINT
```
```bash
export SSM_ENDPOINT="http://localhost:5500/api/v1"
export XPUB="tpubD6NzVbkrYhZ4WbScGMjFV1RFPh7W6xUZZDzx1Zt5YZyVem4Zoqws3kB79PVhCrmWhdTzPYxfPadN7oSsHt1a4kwrSzVpm1ExqcuhYBX9En1 tpubD6NzVbkrYhZ4WaSZUxTVKpF7YW81RvRHBmHb2maejAQUC2qSqWqZebTeyA8U58xB15BpCNNYpMr1VuTaqafoeuyRaCqn3EyQeMqgaiYDXaZ"
export HD_PATH="84/0/1 84/0/1"

curl -i -X POST -H "Content-Type: application/json" -d '{
        "jsonrpc": "2.0",
        "method": "new_multisig_address",
        "params": ["'"$CHAIN"'", 2, 2, "'"$XPUB"'", "'"$HD_PATH"'"],
        "id": "42"
    }' $SSM_ENDPOINT
```

```bash
export SSM_ENDPOINT="http://localhost:5500/api/v1"
export ADDRESS="ert1q9swn8f76jgadhkxv05wjr4seaz7zt2xaxx50wjta8pk7rh4m9khq2lxsa7"
export MASTER_BKEY="6cf649af895c88e68774d2f86f390f6e4df278cdf35636983bac81be07138575224e36271e4b5342aedc605d01f62ac5b5c48d8a4f0e7f71c2b4c3394bfaecd6"

curl -i -X POST -H "Content-Type: application/json" -d '{
        "jsonrpc": "2.0",
        "method": "new_confidential_address",
        "params": ["'"$CHAIN"'", "'"$ADDRESS"'", "'"$MASTER_BKEY"'"],
        "id": "42"
    }' $SSM_ENDPOINT
```

```bash
export SSM_ENDPOINT="http://localhost:5500/api/v1"
export CONTRACT="this is a commited contract"

curl -i -X POST -H "Content-Type: application/json" -d '{
        "jsonrpc": "2.0",
        "method": "hash_contract",
        "params": ["'"$CHAIN"'", "'"$CONTRACT"'"],
        "id": "42"
    }' $SSM_ENDPOINT
```
```bash
export SSM_ENDPOINT="http://localhost:5500/api/v1"
export CONTRACT="this is a commited contract"
export TXID="dcc50b5563a8a6b62195aca3e3bc6923c6773ac54e658e3e22653547b88b9b27"
export VOUT=0
export ASSET_ID="53931710d5747cd2cce06e7cf607eeb3f389e008b007864e92471391c556e710"

curl -i -X POST -H "Content-Type: application/json" -d '{
        "jsonrpc": "2.0",
        "method": "verify_contract_commitment",
        "params": ["'"$CHAIN"'", "'"$TXID"'", "'"$VOUT"'", "'"$CONTRACT"'", "'"$ASSET_ID"'"],
        "id": "42"
    }' $SSM_ENDPOINT
```

```bash
export SSM_ENDPOINT="http://localhost:5500/api/v1"
export PRIVKEY="d03fbdbaa95b76525da2078bbbeb9821c70cbe95e0c4d2ddcd2683a16e0a6de7"
export PUBKEY="038ed1e7fd9014e47c6c005472cf88185ed8b64c291e9eb0ee09e057297dddc143"

curl -i -X POST -H "Content-Type: application/json" -d '{
        "jsonrpc": "2.0",
        "method": "start_aes_session",
        "params": ["'"$PUBKEY"'"],
        "id": "42"
    }' $SSM_ENDPOINT
```
```bash
export SSM_ENDPOINT="http://localhost:5500/api/v1"
export MSG="this is a clear message"

curl -i -X POST -H "Content-Type: application/json" -d '{
        "jsonrpc": "2.0",
        "method": "encrypt_msg_for_session",
        "params": ["'"$MSG"'", "'"$SESSION_ID"'"],
        "id": "42"
    }' $SSM_ENDPOINT
```

```bash
export SSM_ENDPOINT="http://localhost:5500/api/v1"

curl -i -X POST -H "Content-Type: application/json" -d '{
        "jsonrpc": "2.0",
        "method": "decrypt_msg_for_session",
        "params": ["'"$MSG"'", "'"$SESSION_ID"'", "'"$IV"'"],
        "id": "42"
    }' $SSM_ENDPOINT
```

```bash
export SSM_ENDPOINT="http://localhost:5500/api/v1"
export KEY_FINGERPRINTS="ce9e7a9b ce9e7a9b"
export HD_PATHS="84'/0'/42' 84'/0'/1337'"
export PREV_TX="0200000002d12f2f94516b39ab1b34ddb7fd6908829bdeabb79527330a40f2be7da4b0c96e0000000000ffffffff20a553ed13610836fe66731baae865090a2922bdf7fc0e14d9e6bde7a696f0b60000000000ffffffff01c041c8170000000016001458f5399fb6f22cf28ab1294de806f6fc607a900800000000"
export SPEND_VALUES="1.50000000 2.50000000"

curl -i -X POST -H "Content-Type: application/json" -d '{
        "jsonrpc": "2.0",
        "method": "sign_tx",
        "params": ["bitcoin-main", "'"$PREV_TX"'", "'"$KEY_FINGERPRINTS"'", "'"$HD_PATHS"'", "'"$SPEND_VALUES"'"],
        "id": "42"
    }' $SSM_ENDPOINT
```
