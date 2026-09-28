- Parse NL80211_CMD_EXTERNAL_AUTH event details: action, SSID,
  BSSID, AKM suite(s), and MLD address when present
- Parse NL80211_ATTR_TIMED_OUT and NL80211_ATTR_TIMEOUT_REASON on
  ConnectResult failures
- Add captured-event tests for CONNECT success/failure with IEs
- Add captured-event tests for EXTERNAL_AUTH start and abort
- Add a pmkid builder method to Nl80211ExternalAuth for SAE PMKSA
  caching
- Verify Nl80211Connect covers FullMAC PSK / 1X / OWE attributes
  (WPA versions, ciphers, AKMs, control port, socket owner)
- Add builder tests for FullMAC CONNECT attribute emission
- Update CHANGELOG when the CONNECT event / external auth API lands

## Parsed layer (`Nl80211XxxParsed`)

Rework the high-level API after `nl-wireguard`
(`/home/fge/Source/netlink/nl-wireguard`): per-object parsed types
round-tripping between kernel messages and a user-facing config,
instead of read-side-only accessors or stream-consuming finders.

- Prerequisite: an error model with `ErrorKind` and secret redaction.
  `Nl80211Error::UnexpectedMessage` and `Nl80211Error::NetlinkError`
  currently render raw messages / the kernel's echoed request header,
  which can carry `Nl80211Attr::Key`, `AuthData`, `Pmk` and `Pmkid`.
  Mirror `nl-wireguard/src/redact.rs`: zero the secrets, drop the raw
  echo, keep the structured request.
- Parsed type shape, mirroring `WireguardParsed`:
  - `#[non_exhaustive]` + `Default` + public fields.
  - `From<&[Nl80211Attr]>` / `From<Vec<...>>` to parse replies and
    `build()` / `build_messages()` to emit requests, so a config read
    back from the kernel can be applied again.
  - Centralize the kernel rules: `IFNAMSIZ` and NUL checks, WPA3
    implies MFP, AKM/cipher consistency, control-port attributes,
    64 KiB NLA splitting, split wiphy dump coalescing, scan SSID caps.
- Candidate objects, in priority order:
  - `Nl80211ConnectParsed`: build `CONNECT` / `AUTHENTICATE` /
    `ASSOCIATE`, the biggest win for shuli's hand-built attributes.
  - `Nl80211IfaceParsed`: `get_by_name()` + `set()` for interface
    type, MAC, tx power, 4addr; closest analog to the wireguard
    device config.
  - `Nl80211BssParsed`: typed BSS read model from scan results (SSID,
    RSN/security, signal, frequency, IEs), building on the
    `Nl80211BssInfo` accessors.
  - `Nl80211WiphyParsed`: capabilities (supported commands, bands,
    features, max scan SSIDs) for the SoftMAC/FullMAC switch.
  - `Nl80211ScanParsed`, `Nl80211KeyParsed`: build-only configs.
- Handle verbs for the common flows, e.g.
  `Nl80211ConnectionHandle::connect_parsed()` and
  `Nl80211InterfaceHandle::get_by_name()`.
- Unit tests per parsed type with captured nlmon messages, plus
  kernel integration tests (`mac80211_hwsim`) gated and `#[ignore]`d
  like `nl-wireguard/tests/wireguard_kernel.rs`.
- A high-level helper must have both a parse and a build side;
  read-only "find the attribute" helpers stay in the caller.
