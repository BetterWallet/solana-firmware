# better-wallet-solana

Air-gapped Solana hardware wallet firmware for Raspberry Pi.

The device never connects to the internet. It exchanges requests and signatures
with browser wallets over animated QR codes only.

## Compatibility

- Solflare extension: supported via Keystone Solana UR flow.
- Phantom: firmware speaks Keystone Solana UR; Phantom support depends on Phantom
  exposing Keystone Solana integration in the extension.

## Flow

1. Wallet shows animated `ur:sol-sign-request` QR.
2. Pi camera scans and decodes UR fragments.
3. Pi renders human-readable transaction/message details.
4. User confirms on hardware buttons.
5. Pi signs offline with Ed25519 at `m/44'/501'/{i}'/0'`.
6. Pi shows animated `ur:sol-signature` QR.
7. Wallet scans signature QR and submits.

## Hardware

- Raspberry Pi 4 (recommended no-wireless SKU for production)
- 3.5" SPI display
- Raspberry Pi camera module
- Confirm/reject GPIO buttons

Disable wireless in `/boot/firmware/config.txt`:

```ini
dtoverlay=disable-wifi
dtoverlay=disable-bt
```

## Project layout

```
solana-firmware/
├── main.py
├── config.py
├── wallet/
│   ├── keygen.py
│   ├── keystore.py
│   ├── derive.py
│   └── sol.py
├── ur/
│   ├── types.py
│   ├── decoder.py
│   └── encoder.py
├── solana/
│   └── parser.py
├── state/
│   ├── states.py
│   └── machine.py
├── camera/
├── display/
├── gpio/
└── tests/
```

## Dev setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest tests/ -v
```

## Security model

- Mnemonic encrypted at rest with PIN-derived scrypt key + AES-GCM
- Signing key material only exists in memory during signing
- `state/machine.py` is the only module importing `wallet/`
- No network transport path in firmware

## State machine

```
SETUP -> LOCKED -> IDLE -> SCANNING -> PARSED -> AWAIT_CONFIRM
                                       |             |
                                       | CONFIRM     | REJECT
                                       v             v
                                     SIGNING       IDLE
                                       |
                                       v
                                  DISPLAY_RESULT -> IDLE
```
