# Recon — safety overlay hook points & command map

Source: `js/ble-protocol.js`, `js/ui-controller.js`, `templates/*.html` of the upstream fork.

## Write (hook) points
`writeValueWithoutResponse` call sites:
- `sendCommand(commandType, commandName, payload)` → write @ `ble-protocol.js:1001`
- `sendCommandWithRetry(commandType, commandName, payload, opts)` → write @ `:938`
- `sendMeterIPCommand(...)` → write @ `:1059` (alt protocol; same command-level path)
- OTA / special `txCharacteristic.writeValueWithoutResponse(...)` @ `:1797, :1808, :1883, :1954, :2012, :2099, :2595`

**Decision:** hook the **command-level** functions `sendCommand` and `sendCommandWithRetry`. These carry every *decision* command, including the dangerous **triggers** `0x06` (factory reset), `0x1D` (system restart), `0x1F` (FW upgrade), `0x0C` (system reset). The `txCharacteristic` writes at `:1797–2595` are **OTA bulk-transfer frames sent *after* an already-confirmed trigger** — they are not individually gated (gating the trigger is sufficient and avoids prompting on every data chunk). `sendMeterIPCommand` (`0x21` write) also gets the hook in a follow-up if needed.

## Device name accessor
`js/ble-protocol.js:50` declares module-scoped `let device` (the Web-Bluetooth device); `device.name` (e.g. `MST_ACCP_1234`) is set at connect (`:420,447`). It is **not** exposed on `window`, so the overlay cannot read it cross-file. **The hook passes `device?.name`** into `beforeSend(... , deviceName)` — the send functions share scope with `device`.

## Command → risk tier map (from `sendCommand(0xNN, '...')` call sites)
| Code | Name(s) | Tier |
|---|---|---|
| 0x03 | Runtime Info (also stray 'Local API' label — treated as read) | READ |
| 0x04 | Device Info | READ |
| 0x08 | WiFi Info | READ |
| 0x0A | Settings Info | READ |
| 0x0D | Developer Mode Info | READ |
| 0x10 | Read Configuration | READ |
| 0x13 | BLE Event Log | READ |
| 0x14 | BMS Data | READ |
| 0x1A | HM Summary | READ |
| 0x1C | HM Event Log | READ |
| 0x24 | Network Info | READ |
| 0x51 | Read GID/VID/XID Info | READ |
| 0x02 | Set Server Type | CONFIG |
| 0x09 | Set Work Mode | CONFIG |
| 0x0B | Set Date/Time | CONFIG |
| 0x0E | Auto Mode Change | CONFIG |
| 0x0F | Backup Power | CONFIG |
| 0x15 | Set Power Mode (800/2500W) | CONFIG |
| 0x16 | Set AC Power | CONFIG |
| 0x17 | Set Total Power | CONFIG |
| 0x19 | Set Battery Mode | CONFIG |
| 0x20 | Parallel Machine | CONFIG |
| 0x21 | P1 Meter IP / Write Test IP | CONFIG |
| 0x22 | CT Timing Profile | CONFIG |
| 0x23 | Generator enable/disable | CONFIG |
| 0x27 | Power Array | CONFIG |
| 0x28 | Enable/Disable Local API (Port 30000) | CONFIG |
| 0x05 | URL Broker Config (cloud/broker redirect) | SENSITIVE |
| 0x53 | BLE Lock enable/disable/status | SENSITIVE |
| 0x06 | Factory Reset (Full/WiFi) | DANGEROUS |
| 0x0C | Dev Mode toggle / **System Reset** (overloaded code) | DANGEROUS |
| 0x1D | System Restart | DANGEROUS |
| 0x1F | Trigger FW Upgrade / Upgrade Mode | DANGEROUS |

Any code not in this table → DANGEROUS (fail-safe). `0x0C` is overloaded (dev-mode vs system-reset by payload) → classified DANGEROUS to be safe.
