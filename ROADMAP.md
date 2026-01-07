# SecurePeer Roadmap - MVP Monétisable (6 semaines)

## 🎯 Vision Recentrée

**Hybride P2P + Stockage:** Le seul service de transfert fichiers où même nous ne pouvons pas lire vos données.

**Positionnement:**
- P2P direct (gratuit, 100 MB) → **impossible à subpoena**
- Stockage temporaire chiffré E2E (payant) → **recurring revenue**
- Pas de concurrence frontale avec Dropbox → **niche privacy-first**

**Business Model:**
- Free: P2P direct, 100 MB max, liens 24h
- Pro (10€/mois): 5 GB, stockage 30j, analytics
- Business (25€/user/mois): Illimité, API, domaines custom, compliance

---

## ✅ Phase 1: Double Ratchet (TERMINÉ - 7 Jan 2026)

**Implémentation complète:**
- [x] HKDF, KDF_RK, KDF_CK (RFC 5869)
- [x] DH Ratchet (rotation 100 msg + 30min timer)
- [x] Symmetric Ratchet (chaînes send/recv séparées)
- [x] Skipped keys buffer (Map avec expiry 1h)
- [x] Header encryption (metadata protection)
- [x] Tests unitaires 9/9 PASS
- [x] Intégration P2P temps réel
  - [x] Init automatique après auth par mot de passe
  - [x] Handshake DH via messages `double-ratchet-init`
  - [x] `broadcastToAllPeers()` chiffre automatiquement
  - [x] `handleDoubleRatchetMessage()` déchiffre et dispatch
  - [x] Compatibilité backward (ancien format AES-GCM)
- [x] Documentation technique (4 fichiers: spec, usage, roadmap, changelog)

**Fichiers modifiés:**
- `public/app.js` (lines 645-1361): Core Double Ratchet + intégration (~700 lines)
- `public/double-ratchet-tests.js`: Tests unitaires (315 lines)
- Docs: DOUBLE_RATCHET.md, DOUBLE_RATCHET_USAGE.md, IMPLEMENTATION_SUMMARY.md

**Commits clés:**
- `e4ffe04`: Fix chainKey avant avancement pour header encryption
- `dfed902`: Intégration P2P communications
- `fedbc0a`: Roadmap refocus MVP monétisable

**Status:** ✅ **PRODUCTION** - Chat chiffré Signal Protocol actif sur https://securepeer.eu

**Note:** X3DH non implémenté (pas nécessaire pour P2P temps réel)

---

## 🚀 Phase 2: Sécurité & Trust (Semaines 1-2, ~40h)

**Objectif:** Permettre aux utilisateurs de vérifier qu'ils ne sont pas MITM.

### 2.1 Safety Numbers (Fingerprint Verification)
- [ ] 🔴 Générer fingerprint SHA-256 depuis clé publique ECDH ⏱️ 2h
- [ ] 🔴 Afficher fingerprint dans UI (format lisible 12 groupes) ⏱️ 3h
- [ ] 🔴 QR code du fingerprint pour scan mobile ⏱️ 2h
- [ ] 🔴 Bouton "Vérifier identité" → compare côte à côte ⏱️ 2h
- [ ] 🟡 Warning si fingerprint change (détection MITM) ⏱️ 2h
- [ ] 🟡 Guide utilisateur: vérifier par appel vocal ⏱️ 2h

### 2.2 TURN-Only Forcé (Masquage IP)
- [ ] 🔴 Checkbox UI "Masquer mon IP (forcer relay)" ⏱️ 1h
- [ ] 🔴 iceTransportPolicy: "relay" côté SimplePeer ⏱️ 2h
- [ ] 🔴 Filtrer host/srflx candidates avant envoi SDP ⏱️ 3h
- [ ] 🔴 Tests: vérifier aucun direct candidate ⏱️ 2h

### 2.3 Messages Éphémères Améliorés
- [ ] 🟡 Activer par défaut (30s) avec opt-out ⏱️ 1h
- [ ] 🟡 Indicateur countdown visuel sur messages ⏱️ 2h
- [ ] 🟡 Warning si désactivé ⏱️ 1h

### 2.4 Tests Sécurité
- [ ] 🔴 Tests de fuite IP (ipleak.net, browserleaks) ⏱️ 4h
- [ ] 🟡 ESLint security + Semgrep (SAST) ⏱️ 4h
- [ ] 🟡 OWASP ZAP sur endpoints (DAST) ⏱️ 6h
- [ ] 🟡 Fuzzing inputs messages/SDP ⏱️ 4h

**Livrable:** Application avec vérification fingerprint + option IP masquée + tests sécu passés

---

## 🏗️ Phase 3: Infrastructure Résiliente (Semaines 3-4, ~38h)

**Objectif:** Ne pas avoir un single point of failure.

### 3.1 Multi-Provider Offshore
- [ ] 🔴 Déployer signaling sur 2+ VPS (Islande + Suisse) ⏱️ 8h
- [ ] 🔴 Déployer TURN sur 2+ providers indépendants ⏱️ 8h
- [ ] 🟡 GeoDNS ou load balancing DNS round-robin ⏱️ 4h
- [ ] 🔴 Terraform pour IaC reproductible ⏱️ 12h
- [ ] 🟡 Tests failover: couper un provider → continuité ⏱️ 4h

### 3.2 RAM-Only & Ephemeral
- [ ] 🟡 Sessions en Redis (persistence=off, RAM uniquement) ⏱️ 4h
- [ ] 🟡 Coturn no-log, RAM allocations ⏱️ 2h
- [ ] 🟢 Désactiver swap ou chiffrer swap ⏱️ 1h

### 3.3 Monitoring Privacy-Preserving
- [ ] 🟡 Prometheus: uptime, error rate, latency (agrégés) ⏱️ 6h
- [ ] 🟡 Alerting email/Signal bot (downtime, error spike) ⏱️ 3h
- [ ] 🟢 Pas de logs individuels, seulement métriques ⏱️ 1h
- [ ] 🟡 Dashboard privé (auth HTTPS) pour ops ⏱️ 4h

### 3.4 CI/CD
- [ ] 🟡 GitHub Actions: tests auto sur PR ⏱️ 4h
- [ ] 🟡 Deploy auto staging (push main) ⏱️ 4h
- [ ] 🟡 Deploy production (tag release) ⏱️ 3h
- [ ] 🟡 Rollback auto si healthcheck fail ⏱️ 2h

**Livrable:** Infrastructure multi-region avec failover + monitoring + CI/CD

---

## 💰 Phase 4: Monétisation (Semaines 5-6, ~48h)

**Objectif:** Lancer en beta payante avec recurring revenue.

### 4.1 Système Comptes
- [ ] 🔴 Backend comptes (email hash uniquement) ⏱️ 12h
- [ ] 🔴 Auth simple (email + code OTP, pas de password) ⏱️ 8h
- [ ] 🟡 Page profil basique ⏱️ 4h

### 4.2 Paiement Stripe
- [ ] 🔴 Intégration Stripe Checkout ⏱️ 8h
- [ ] 🔴 Webhooks Stripe (subscription created/cancelled) ⏱️ 4h
- [ ] 🟡 Gestion abonnements (upgrade/downgrade) ⏱️ 6h

### 4.3 Plans & Quotas
- [ ] 🔴 Limite gratuit: 100 MB, liens 24h ⏱️ 2h
- [ ] 🔴 Plan Pro: 5 GB, stockage 30j, analytics ⏱️ 4h
- [ ] 🔴 Plan Business: illimité, API, domaines custom ⏱️ 4h
- [ ] 🟡 Enforcement quotas (taille, durée) ⏱️ 6h

### 4.4 Dashboard Utilisateur
- [ ] 🟡 Sessions actives + usage bandwidth ⏱️ 8h
- [ ] 🟡 Historique transferts (30 derniers jours) ⏱️ 4h
- [ ] 🟡 Facturation & invoices ⏱️ 4h

### 4.5 Landing & Pricing
- [ ] 🟡 Page /pricing avec comparaison plans ⏱️ 4h
- [ ] 🟡 CTA "Essai gratuit 7j" ⏱️ 2h
- [ ] 🟡 Témoignages utilisateurs (fake it till you make it) ⏱️ 2h

**Livrable:** App avec comptes + paiements Stripe + plans Free/Pro/Business

---

## 📚 Phase 5: Documentation & Legal (Semaine 7, ~20h)

**Objectif:** Conformité RGPD + transparence.

### 5.1 Documentation Utilisateur
- [ ] 🟢 Guide démarrage rapide (1 page EN/FR) ⏱️ 2h
- [ ] 🟡 FAQ sécurité (que loggue-t-on, limites) ⏱️ 4h
- [ ] 🟡 Best practices (vérifier fingerprints) ⏱️ 3h

### 5.2 Documentation Technique
- [ ] 🟡 Architecture (diagrammes infra + crypto) ⏱️ 4h
- [ ] 🟡 Threat model (adversaires, mitigations) ⏱️ 4h

### 5.3 Legal & Compliance
- [ ] 🔴 Privacy Policy détaillée (/privacy) ⏱️ 4h
- [ ] 🔴 ToS/CGU (disclaimers, limitations) ⏱️ 3h
- [ ] 🟡 Page /security (architecture, ce qu'on logue pas) ⏱️ 3h
- [ ] 🟢 Licence MIT open-source ⏱️ 30min

**Livrable:** Site complet avec legal compliance RGPD

---

## 🎯 Phase 6: Launch Beta (Semaine 8)

### 6.1 Pre-Launch
- [ ] 🔴 Audit sécu externe (pentest basique) ⏱️ Budget 2-5k€
- [ ] 🟡 Beta privée: 50 early adopters (Product Hunt, HN) ⏱️ -
- [ ] 🟡 Feedback loop: ajustements UX/pricing ⏱️ -

### 6.2 Launch
- [ ] 🔴 Product Hunt launch ⏱️ -
- [ ] 🟡 Post Hacker News "Show HN: SecurePeer" ⏱️ -
- [ ] 🟡 Twitter/X campaign (privacy advocates) ⏱️ -
- [ ] 🟡 Email journalistes tech (TechCrunch, Wired) ⏱️ -

### 6.3 Metrics
- [ ] Objectif: 100 signups semaine 1
- [ ] Objectif: 10 paying customers mois 1 (100€ MRR)
- [ ] Objectif: 50 paying customers mois 3 (500€ MRR)

---

## ❌ Roadmap Items SUPPRIMÉS (Overkill/Prématuré)

**Trop niche/complexe:**
- ❌ X3DH (pas besoin pour P2P temps réel)
- ❌ TURN en .onion (Tor) - 99% users ne l'utiliseront jamais
- ❌ Sealed sender - complexité énorme, gain marginal
- ❌ Padding messages / timing obfuscation
- ❌ Kill switch automatique / dead man's switch

**Trop tôt (faire après traction):**
- ❌ App mobile native (40h+) - rester web jusqu'à 10k users
- ❌ PWA offline - pas utile pour P2P temps réel
- ❌ i18n 5 langues - garder juste EN/FR pour MVP
- ❌ API REST / SDK - pas de clients API encore
- ❌ Intégrations Zapier
- ❌ Kubernetes autoscaling

**Distraction:**
- ❌ Vidéos tutoriels
- ❌ Warrant canary (faire après avoir du trafic)
- ❌ Workshops / conférences
- ❌ Hacktoberfest

---

## 📊 Estimation Totale MVP

**Temps:** 6-8 semaines (146h dev)  
**Budget:** 2-5k€ (audit sécu)  
**Launch:** Mi-Mars 2026

**Success Metrics:**
- 100€ MRR mois 1
- 500€ MRR mois 3
- 2000€ MRR mois 6 → rentabilité (VPS + temps dev)

**Pivot si échec:** Si < 50 paying customers après 6 mois → pivoter vers B2B compliance (santé/legal) ou abandonner.
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
