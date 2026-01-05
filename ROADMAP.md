# SecurePeer Roadmap - 2026 & Beyond

## 🎯 Vision

Create the **most secure P2P communication platform** combining:
- Signal Protocol (Double Ratchet) for E2EE
- Post-Quantum Cryptography (SPQR) for future-proofing
- Tor Hidden Services for anonymity
- Sealed Sender for metadata protection
- Native desktop/mobile apps for better OS integration

**Ultimate Goal:** Make surveillance-resistant communication accessible to journalists, activists, and privacy-conscious users.

---

## 📅 Timeline

### ✅ Phase 1: Double Ratchet Implementation (COMPLETED - Jan 5, 2026)

**What was built:**
- [x] HKDF-SHA256 (RFC 5869)
- [x] KDF_RK and KDF_CK primitives
- [x] Double Ratchet state management
- [x] Per-peer encryption/decryption
- [x] Header encryption
- [x] Skipped keys buffer for out-of-order messages
- [x] Unit tests (9 test cases)
- [x] Full documentation (DOUBLE_RATCHET.md)

**Current Code:**
```
public/app.js (lines 645-1270): Core Double Ratchet (~625 lines)
public/double-ratchet-tests.js: Unit tests (~300 lines)
DOUBLE_RATCHET.md: Specification (60 pages)
DOUBLE_RATCHET_USAGE.md: Usage guide (40 pages)
```

**Status:** ✅ **Production Ready** (No Professional Audit)

---

### 🔄 Phase 2: Integration & Testing (Jan 15 - Feb 15, 2026)

**Objectives:**
- Hook Double Ratchet into WebRTC DataChannels
- Integrate with chat messaging system
- Add SAS (Short Authentication String) fingerprint verification
- End-to-end testing across peers

**Tasks:**
- [ ] Create `WebRTCRatchetedChannel` wrapper class
  - Intercept all peer.send() calls
  - Apply Double Ratchet encryption
  - Decrypt received messages
  - Handle reconnection scenarios

- [ ] Modify chat message handling
  - Encrypt message with Double Ratchet before sending
  - Decrypt received messages
  - Display encryption status (🔓/🔒)

- [ ] Implement SAS verification UI
  - Generate 4 emoji SAS from fingerprint
  - Display on both sides
  - Manual verification button
  - Store verified fingerprints locally

- [ ] Test scenarios
  - Send 100+ messages and verify ratcheting
  - Out-of-order messages (WebRTC jitter)
  - Fast message sending (>10/sec)
  - Peer reconnection scenarios
  - Browser tab refresh (state loss)

- [ ] Performance benchmarking
  - Measure latency (target: < 50ms per message)
  - Memory growth test (target: stable at ~5KB/peer)
  - CPU usage (target: < 5% per message encrypt)

**Expected Output:**
- Fully integrated encrypted chat
- Fingerprint verification working
- Performance baseline established

---

### 🔐 Phase 3: X3DH Implementation (Feb 15 - Mar 31, 2026)

**What is X3DH:**
Extended Triple Diffie-Hellman - more robust initial key agreement than current simple ECDH.

**Objectives:**
- Replace simple ECDH with X3DH
- Support offline messaging (via pre-keys)
- Add identity key signatures
- Implement key rotation schedule

**Tasks:**
- [ ] Generate and manage pre-keys
  - Signed pre-keys (rotate weekly)
  - One-time pre-keys (use once, rotate as needed)
  - Identity keys (long-term, backed up)

- [ ] X3DH key agreement protocol
  ```
  Initial:
  - Alice: IK_A (identity), EK_A (ephemeral)
  - Bob: IK_B (identity), SPK_B (signed pre-key), OPK_B (one-time)
  
  Key derivation:
  DH1 = ECDH(IK_A, SPK_B)
  DH2 = ECDH(EK_A, IK_B)
  DH3 = ECDH(EK_A, SPK_B)
  DH4 = ECDH(EK_A, OPK_B)
  
  Shared secret = HKDF(DH1 || DH2 || DH3 || DH4)
  ```

- [ ] Pre-key upload/management
  - Batch upload to server on startup
  - Server marks used OPKs
  - Automatic re-upload when low

- [ ] Session initialization
  - Skip ECDH if X3DH available
  - Fall back to X3DH if peer offline
  - Handle key compromise

- [ ] Tests
  - X3DH key agreement verification vectors
  - Pre-key rotation schedule tests
  - Offline message queuing tests

**Expected Output:**
- X3DH replaces simple ECDH
- Offline messaging capability
- Better defense against compromise

---

### 🌌 Phase 4: Post-Quantum Readiness (Apr 1 - Jun 30, 2026)

**Threat:** Quantum computers (estimated 2030+) can break current ECC

**What is SPQR:**
Signal Post-Quantum Ratchet - combines classical DH with post-quantum KEX

**Tasks:**
- [ ] ML-KEM-768 (Kyber) integration
  - Compile libpqcrystals to WASM
  - Wrapper for JavaScript
  - ~1KB ciphertext overhead

- [ ] Triple Ratchet architecture
  ```
  Old approach (current):
  DHRatchet: ECDH(cur_dh, their_dh) → new_rootKey
  
  New approach (SPQR):
  DHRatchet: DH(ECDH, ML-KEM) → new_rootKey
  - Run both algorithms
  - Mix results: HKDF(DH_result || PQ_result)
  - Resistant to quantum computers
  ```

- [ ] Implementation
  - Generate PQ keypairs on startup
  - Exchange in X3DH or periodic ratchet
  - Use SPQR ratchet every 50 messages (heavier)
  - Keep classical ratchet for everyday

- [ ] Performance optimization
  - Cache PQ keypairs
  - Lazy load ML-KEM
  - Batch PQ operations

- [ ] Testing
  - Interop with classical Double Ratchet
  - Performance benchmarks
  - Recovery from PQ compromise

**Expected Output:**
- Post-quantum resistant encryption
- Ready for era of quantum computers

---

### 📱 Phase 5: Native Desktop App (Jul 1 - Dec 31, 2026)

**Why native app:**
- Better security (isolated process)
- No browser extensions
- Constant-time crypto (C++)
- Better UI/UX
- Offline capability

**Framework: Tauri**
```
Frontend: React (reuse current code)
Backend: Rust (libsignal bindings)
Crypto: rust-crypto (constant-time)
Size: ~5MB (vs Electron 100MB+)
```

**Tasks:**
- [ ] Setup Tauri project
  - Scaffold React + Rust
  - Configure build system
  - Code signing certificates

- [ ] Migrate crypto to Rust
  - Benchmark vs JavaScript
  - Implement libsignal wrapper
  - Add post-quantum support

- [ ] Implement local database
  - SQLite for message history
  - Encrypted at rest with user password
  - Vacuum & purge old messages

- [ ] Native features
  - System notifications
  - Tray icon
  - Keyboard shortcuts
  - Auto-update mechanism

- [ ] Distribution
  - Windows .exe, macOS .dmg, Linux .AppImage
  - Code signing (Windows + macOS)
  - Auto-updater channel

**Expected Output:**
- Desktop app with better security
- 50x faster crypto
- Professional look & feel

---

### 🧅 Phase 6: Tor Integration (Q1 2027)

**Objectives:**
- Hide IP address
- Resist censorship
- Add Sealed Sender

**Tasks:**
- [ ] Migrate server to Tor hidden service
  - Change VPS to Tor-capable (Debian)
  - Generate .onion address
  - Map WebSocket to hidden service
  - Keep current IP for backward compatibility

- [ ] Force Tor for clients
  - Detect if using Tor Browser
  - Refuse connections not via Tor
  - Implement onion routing via Nym

- [ ] Sealed Sender implementation
  - Hide sender identity in messages
  - Use certificat rotation
  - Prevent metadata leaks

- [ ] Cover traffic
  - Automatic dummy messages
  - Padding to constant size
  - Timing obfuscation

- [ ] Testing
  - Tor Browser compatibility
  - Censorship resistance (GFW, UAE)
  - Timing analysis resistance

**Expected Output:**
- Complete Tor integration
- Maximum anonymity
- Censorship-resistant

---

### 📱 Phase 7: Mobile Apps (Q2-Q4 2027)

**Platforms:**
- iOS (Swift + SwiftUI)
- Android (Kotlin + Jetpack Compose)

**Shared Core:**
- libsignal mobile bindings
- SQLite for message DB
- biometric auth (Face ID, fingerprint)

**Timeline:**
- 6 months iOS
- 6 months Android
- Parallel development

**Expected Output:**
- Feature parity with desktop
- App Store + Play Store release
- 100k+ installations

---

## 🗺️ Feature Matrix

| Feature | Phase | Browser | Desktop | iOS | Android |
|---------|-------|---------|---------|-----|---------|
| Double Ratchet | 1 | ✅ | ✅ | ✅ | ✅ |
| X3DH | 3 | ✅ | ✅ | ✅ | ✅ |
| Post-Quantum | 4 | ✅ | ✅ | ✅ | ✅ |
| Sealed Sender | 6 | ✅ | ✅ | ✅ | ✅ |
| Tor Hidden Service | 6 | 🟡 | ✅ | 🟡 | 🟡 |
| Offline Messages | 3 | ✅ | ✅ | ✅ | ✅ |
| Message History | 5 | 🟡 | ✅ | ✅ | ✅ |
| File Sharing | 2 | ✅ | ✅ | 🟡 | 🟡 |
| Voice Calls | 5 | 🟡 | ✅ | 🟡 | 🟡 |
| Disappearing Messages | 3 | ✅ | ✅ | ✅ | ✅ |

Legend: ✅ Full support | 🟡 Partial | ❌ No support

---

## 💰 Resource Requirements

### Development Team
```
Core Team (3-4 people):
- 1 Cryptography Engineer (C++ / Rust)
- 1 Backend Engineer (Node.js / Rust)
- 1 Frontend Engineer (React / React Native)
- 1 Security Auditor (part-time)
```

### Infrastructure
```
Development:
- GitHub: Free (public repo)
- CI/CD: GitHub Actions (free)

Production:
- VPS Tor: 1984.is ~$50/month
- CDN: None (P2P direct)
- Database: None (server is stateless)

Total: ~$600/year
```

### Timeline & Effort
```
Phase 1: 40 hours (DONE)
Phase 2: 80 hours
Phase 3: 120 hours
Phase 4: 160 hours
Phase 5: 200 hours (desktop)
Phase 6: 100 hours (Tor)
Phase 7: 500 hours (mobile 2x)

Total: ~1200 hours ≈ 6 months (full-time 1 person)
```

---

## 🎓 Educational Value

This project teaches:
1. **Cryptography fundamentals** - HKDF, HMAC, AES-GCM
2. **Forward secrecy** - Why ratcheting matters
3. **Key derivation** - One-way functions
4. **Post-quantum crypto** - Future of security
5. **P2P networking** - WebRTC, signaling, NAT traversal
6. **Browser security** - CSP, SRI, extensions
7. **Tor anonymity** - Hidden services, metadata leaks
8. **Code security** - Zeroization, timing attacks, side-channels

**Great for:**
- University coursework
- Security certifications
- Interview preparation
- Portfolio projects

---

## ⚠️ Important Notes

### Security Disclaimer
```
🚨 THIS IS AN EDUCATIONAL IMPLEMENTATION

DO NOT USE FOR REAL SECRETS OR COMMUNICATIONS
USE SIGNAL INSTEAD

This project is:
✅ Educational
✅ Learning resource
✅ Portfolio piece

This project is NOT:
❌ Production-ready (no audit)
❌ For protecting against state actors
❌ Better than Signal
```

### Why Not Just Use Signal?
```
Signal IS better for real use. BUT:

1. Learning: Building crypto teaches you deeply
2. Understanding: See how it all works
3. Customization: Add features Signal doesn't have
4. Innovation: Test new ideas (SPQR, cover traffic)
5. Portfolio: Impressive engineering work
```

### Responsible Disclosure
If you find a security vulnerability:
1. Do NOT post publicly
2. Email: corentin80@protonmail.com
3. Allow 90 days for patch
4. You'll be credited in SECURITY.md

---

## 📞 Get Involved

### Ways to Contribute
- 🐛 Report bugs (GitHub Issues)
- 📝 Write documentation
- 🧪 Add tests
- 🎨 UI/UX improvements
- 🔐 Security review (limited scope)

### Code of Conduct
- Be respectful
- No harassment
- Focus on code quality
- Educational mindset

---

## 📚 References & Resources

### Cryptography Standards
- [RFC 5869 - HKDF](https://tools.ietf.org/html/rfc5869)
- [Signal Double Ratchet](https://signal.org/docs/specifications/doubleratchet/)
- [Signal X3DH](https://signal.org/docs/specifications/x3dh/)
- [Signal SPQR](https://github.com/signalapp/SparsePostQuantumRatchet)

### Post-Quantum Crypto
- [NIST FIPS 203 - ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [libpqcrystals](https://github.com/pqclean/PQClean)
- [Open Quantum Safe](https://openquantumsafe.org/)

### Privacy & Anonymity
- [Tor Project](https://www.torproject.org/)
- [EFF - Surveillance](https://www.eff.org/)
- [Electronic Frontier Foundation](https://www.eff.org/)

### Development
- [Tauri Docs](https://tauri.app/)
- [libsignal-client](https://github.com/signalapp/libsignal)
- [WebRTC Best Practices](https://web.dev/webrtc/)

---

## 🎉 Success Metrics

### By Phase
| Phase | Metric | Target | Current |
|-------|--------|--------|---------|
| 1 | Unit tests pass | 100% | ✅ 100% |
| 2 | E2E messaging | Works | 🔄 In progress |
| 3 | X3DH interop | Verified | ⏳ TBD |
| 4 | PQ resistance | Proven | ⏳ TBD |
| 5 | Desktop app | Released | ⏳ TBD |
| 6 | Tor integration | Live | ⏳ TBD |
| 7 | Mobile apps | Published | ⏳ TBD |

### Long-term Vision
```
Year 1 (2026):
  - Fully encrypted chat
  - Desktop app
  - 1000+ users

Year 2 (2027):
  - Mobile apps
  - Tor integration
  - 10k+ users

Year 3 (2028):
  - Post-quantum hardened
  - GDPR-compliant
  - 100k+ users
```

---

**Last Updated:** January 5, 2026  
**Next Review:** February 15, 2026 (After Phase 2)  
**Maintained By:** SecurePeer Development Team
