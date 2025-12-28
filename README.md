# 🔒 P2P File Transfer

Transfert de fichiers **chiffré de bout en bout** via WebRTC, sans stockage sur serveur.

## ✨ Fonctionnalités

- 🔐 **Chiffrement AES-256-GCM** côté client
- 🔑 **Mode mot de passe (PBKDF2)** : clé dérivée localement, jamais envoyée
- 🌐 **Transfert P2P direct** via WebRTC
- 📦 **Aucune limite de taille** (découpage en chunks de 64 Ko)
- 🔗 **Partage par lien** (clé de chiffrement dans l'URL, après le #)
- ✅ **Vérification d'intégrité** SHA-256
- 🚫 **Zéro stockage serveur** - le serveur ne fait que relayer les signaux

## 🏗️ Architecture

```
┌─────────────────┐                         ┌─────────────────┐
│   Expéditeur    │                         │   Destinataire  │
│    (Alice)      │                         │     (Bob)       │
├─────────────────┤                         ├─────────────────┤
│ 1. Sélectionne  │                         │ 4. Ouvre le     │
│    fichier      │                         │    lien         │
│ 2. Génère clé   │                         │ 5. Extrait clé  │
│    AES-256      │                         │    du lien      │
│ 3. Crée lien    │──── Lien partagé ────▶ │                 │
└────────┬────────┘                         └────────┬────────┘
         │                                           │
         │ WebSocket (signalisation)                 │
         ▼                                           ▼
    ┌─────────────────────────────────────────────────────┐
    │                  Serveur Node.js                     │
    │  - Gestion des rooms                                 │
    │  - Relais des signaux SDP/ICE                       │
    │  - NE STOCKE RIEN                                   │
    └─────────────────────────────────────────────────────┘
         │                                           │
         │ WebRTC (connexion P2P directe)           │
         ▼                                           ▼
    ┌─────────────────────────────────────────────────────┐
    │              Transfert P2P chiffré                   │
    │  - Chunks de 64 Ko                                  │
    │  - Chiffrement AES-GCM par chunk                   │
    │  - Hash SHA-256 pour intégrité                     │
    └─────────────────────────────────────────────────────┘
```

## 🚀 Installation

```bash
# Cloner ou accéder au projet
cd Projet

# Installer les dépendances
npm install

# Démarrer le serveur
npm start
```

Le serveur démarre sur `http://localhost:3000`

## 🌍 Déploiement sur un serveur (prod)

Pour que le chiffrement fonctionne partout (Web Crypto API), le site doit être servi dans un **contexte sécurisé** :
- ✅ **HTTPS** sur un nom de domaine (recommandé)
- ✅ ou `http://localhost` (dev)

### Option recommandée : Node en local + Nginx en reverse-proxy + Let’s Encrypt

1) Sur le serveur, installe Node.js (LTS) et lance l’app sur un port local (ex: 3000)

2) Installe Nginx et configure un reverse proxy (important : WebSocket)

Exemple de config Nginx :

```nginx
server {
    listen 80;
    server_name ton-domaine.tld;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

3) Active HTTPS via Certbot (Let’s Encrypt)

Sur Ubuntu/Debian (exemple) :

```bash
sudo apt update
sudo apt install -y nginx certbot python3-certbot-nginx
sudo certbot --nginx -d ton-domaine.tld
```

4) Accède ensuite à : `https://ton-domaine.tld`

### Notes importantes (réseau / WebRTC)

- Le serveur Node ne stocke pas de fichiers : il sert l’UI + fait la signalisation WebSocket.
- WebRTC P2P peut échouer derrière certains NAT/firewalls. Pour une fiabilité “prod”, l’ajout d’un serveur **TURN** est souvent nécessaire.

## 📖 Utilisation

### Expéditeur (Alice)
1. Ouvrir `http://localhost:3000`
2. Glisser-déposer ou sélectionner un fichier
3. (Optionnel) Saisir un mot de passe avant de copier le lien
4. Un lien est généré automatiquement
4. Partager ce lien avec le destinataire
5. Partager le mot de passe séparément (il n'est pas dans le lien)
6. Attendre que le destinataire se connecte
7. Le transfert démarre automatiquement (challenge AES avant envoi)

### Destinataire (Bob)
1. Ouvrir le lien reçu
2. Si le lien est protégé par mot de passe, saisir le mot de passe
3. La connexion s'établit automatiquement après validation du challenge
4. Le fichier est téléchargé après réception complète
5. L'intégrité est vérifiée via SHA-256

## 🔧 Stack Technique

- **Backend**: Node.js + WebSocket (ws)
- **Frontend**: HTML/CSS/JavaScript vanilla
- **P2P**: WebRTC via simple-peer
- **Crypto**: Web Crypto API (AES-256-GCM, SHA-256)
- **KDF**: PBKDF2 SHA-256 (200k itérations) pour le mode mot de passe
- **STUN**: Google STUN servers

## 📁 Structure du projet

```
Projet/
├── server.js           # Serveur WebSocket + HTTP
├── package.json        # Dépendances Node.js
├── README.md           # Documentation
└── public/
    ├── index.html      # Interface utilisateur
    ├── style.css       # Styles
    └── app.js          # Logique client (crypto, WebRTC, transfert)
```

## 🔒 Sécurité

- La clé de chiffrement est générée côté client
- En mode mot de passe, la clé est dérivée localement (PBKDF2) à partir d'un salt dans l'URL
- La clé est transmise dans le fragment d'URL (après #) - jamais envoyée au serveur
- Chaque chunk est chiffré avec un IV unique
- Le hash SHA-256 garantit l'intégrité du fichier
- Le serveur ne voit que les métadonnées WebRTC (pas le contenu)

## ⚠️ Limitations

- Les deux parties doivent rester connectées pendant le transfert
- Nécessite une connexion WebRTC possible (peut échouer derrière certains firewalls stricts)
- Pas de reprise de transfert en cas de déconnexion

## 📄 Licence

MIT
