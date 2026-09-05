- Parse NL80211_ATTR_REQ_IE and NL80211_ATTR_RESP_IE into
  Nl80211Attr variants
- Expose request and response IEs on Nl80211Event::ConnectResult
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
