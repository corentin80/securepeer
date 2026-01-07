/**
 * P2P File Transfer - Application principale
 * Transfert de fichiers chiffré E2E via WebRTC
 */

// ===== CONFIGURATION =====
const CHUNK_SIZE = 64 * 1024; // 64 Ko par morceau


const STUN_SERVERS = [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' },
    { urls: 'stun:stun2.l.google.com:19302' }
];
const KDF_ITERATIONS = 200000; // itérations PBKDF2 pour le mot de passe
const PASSWORD_SALT_BYTES = 16;

// ===== ÉTAT GLOBAL =====
let ws = null;
let peers = new Map(); // Map<odId, SimplePeer> - un peer par participant
let myOdId = null; // Mon identifiant unique dans la room
let participants = new Map(); // Map<odId, {pseudo, isCreator}> - liste des participants
let isCreator = false; // Suis-je le créateur de la room ?
let selectedFile = null;
let selectedFileNameOverride = null;
let cryptoKey = null;
let cryptoIV = null;
let roomId = null;
let isReceiver = false;
let receivedChunks = [];
let totalReceived = 0;
let fileInfo = null;
let transferStartTime = null;
let senderFileHash = null;
let usePassword = false;
let passwordSaltB64 = null;
let passwordIterations = KDF_ITERATIONS;
let pendingChallenge = null;
let expectedChallengeB64 = null;
let authVerified = false;
let passwordRequired = false;
let connectedCount = 0;
let receiverReady = false;
let sessionMode = null; // 'file', 'chat', 'both'
let chatMessages = [];
let userPseudo = ''; // Pseudo de l'utilisateur actuel
let remoteUserPseudo = ''; // Pseudo de l'autre utilisateur (legacy, pour 1:1)

// Chat UI state
let replyToMessageId = null; // message cible pour une réponse/quote
let editingMessageId = null; // message en cours d'édition
let typingSignalTimeout = null; // debounce pour signaux "typing"
let typingIndicatorTimer = null; // timer d'effacement du statut "X écrit..."

// Chat search and pinned messages
let chatSearchQuery = '';
let chatSearchUserFilter = '';
let pinnedMessageIds = new Set(); // IDs des messages épinglés

// Messages éphémères
let ephemeralMode = false;
let ephemeralDuration = 30; // secondes par défaut

// Session security options
let sessionOptions = {
    expirationMinutes: 0,      // 0 = illimité
    maxParticipants: 20,       // 1-20
    requireApproval: false,    // Approbation manuelle des participants
    autoLock: false,           // Verrouiller après 1er participant
    isLocked: false            // État actuel du verrouillage
};
let pendingApprovals = new Map(); // Map<odId, {pseudo, timestamp}> - participants en attente d'approbation

// ===== ECDH (Diffie-Hellman) État =====
let ecdhKeyPair = null; // Ma paire de clés ECDH {privateKey, publicKey}
let ecdhPublicKeyB64 = null; // Ma clé publique en base64 pour partage
let pendingKeyExchanges = new Map(); // Map<odId, {publicKeyB64, resolved}> - échanges en attente
let keyExchangeResolvers = new Map(); // Map<odId, {resolve, reject}> - promesses d'échange

// ===== ÉLÉMENTS DOM =====
const elements = {
    // Landing page
    landingPage: document.getElementById('landing-page'),
    startSessionBtn: document.getElementById('start-session-btn'),
    
    // Pseudo
    pseudoSection: document.getElementById('pseudo-section'),
    pseudoInputMain: document.getElementById('pseudo-input-main'),
    pseudoConfirmBtn: document.getElementById('pseudo-confirm-btn'),
    
    // Mode Selection
    modeSelection: document.getElementById('mode-selection'),
    
    // Sender
    senderSection: document.getElementById('sender-section'),
    dropZone: document.getElementById('drop-zone'),
    fileInput: document.getElementById('file-input'),
    fileInfoDiv: document.getElementById('file-info'),
    fileName: document.getElementById('file-name'),
    fileSize: document.getElementById('file-size'),
    clearFile: document.getElementById('clear-file'),
    passwordBlock: document.getElementById('password-block'),
    passwordInput: document.getElementById('password-input'),
    sendFileBtn: document.getElementById('send-file-btn'),
    
    // Security options
    sessionExpiration: document.getElementById('session-expiration'),
    maxParticipants: document.getElementById('max-participants'),
    requireApproval: document.getElementById('require-approval'),
    autoLock: document.getElementById('auto-lock'),
    
    linkSection: document.getElementById('link-section'),
    shareLink: document.getElementById('share-link'),
    copyLink: document.getElementById('copy-link'),
    linkStatus: document.getElementById('link-status'),
    connectedUsersSection: document.getElementById('connected-users-section'),
    connectedUsersDropdown: document.getElementById('connected-users-dropdown'),
    receiverConnectedUsersSection: document.getElementById('receiver-connected-users-section'),
    receiverConnectedUsersDropdown: document.getElementById('receiver-connected-users-dropdown'),
    
    // Chat (sender side)
    chatSection: document.getElementById('chat-section'),
    chatMessages: document.getElementById('chat-messages'),
    chatInput: document.getElementById('chat-input'),
    chatSend: document.getElementById('chat-send'),
    chatStatus: document.getElementById('chat-status'),
    
    // Receiver
    receiverSection: document.getElementById('receiver-section'),
    receiverPasswordBlock: document.getElementById('receiver-password-block'),
    receiverPassword: document.getElementById('receiver-password'),
    receiverPasswordApply: document.getElementById('receiver-password-apply'),
    incomingFileName: document.getElementById('incoming-file-name'),
    incomingFileSize: document.getElementById('incoming-file-size'),
    receiverStatus: document.getElementById('receiver-status'),
    receiveFileBtn: document.getElementById('receive-file-btn'),
    
    // Chat (receiver side)
    receiverChatSection: document.getElementById('receiver-chat-section'),
    receiverChatMessages: document.getElementById('receiver-chat-messages'),
    receiverChatInput: document.getElementById('receiver-chat-input'),
    receiverChatSend: document.getElementById('receiver-chat-send'),
    receiverChatStatus: document.getElementById('receiver-chat-status'),
    
    // Both mode - file sections
    bothFileSection: document.getElementById('both-file-section'),
    bothFileList: document.getElementById('both-file-list'),
    bothFileInput: document.getElementById('both-file-input'),
    bothFileSend: document.getElementById('both-file-send'),
    receiverBothFileSection: document.getElementById('receiver-both-file-section'),
    receiverBothFileList: document.getElementById('receiver-both-file-list'),
    receiverBothFileInput: document.getElementById('receiver-both-file-input'),
    receiverBothFileSend: document.getElementById('receiver-both-file-send'),
    receiverTitle: document.getElementById('receiver-title'),
    
    // Progress
    progressSection: document.getElementById('progress-section'),
    progressTitle: document.getElementById('progress-title'),
    progressFill: document.getElementById('progress-fill'),
    progressPercent: document.getElementById('progress-percent'),
    progressSpeed: document.getElementById('progress-speed'),
    progressTransferred: document.getElementById('progress-transferred'),
    
    // Complete
    completeSection: document.getElementById('complete-section'),
    completeMessage: document.getElementById('complete-message'),
    integrityCheck: document.getElementById('integrity-check'),
    newTransfer: document.getElementById('new-transfer'),
    
    // Error
    errorSection: document.getElementById('error-section'),
    errorMessage: document.getElementById('error-message'),
    retryTransfer: document.getElementById('retry-transfer'),
    
    // Close session buttons
    closeSession: document.getElementById('close-session'),
    closeChatSession: document.getElementById('close-chat-session'),
    closeReceiverSession: document.getElementById('close-receiver-session'),
    lockSessionBtn: document.getElementById('lock-session-btn')
};

// ===== UTILITAIRES =====

function formatFileSize(bytes) {
    if (bytes === 0) return '0 octets';
    const k = 1024;
    const sizes = ['octets', 'Ko', 'Mo', 'Go', 'To'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function showToast(message) {
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 2000);
}

function hideAllSections() {
    elements.modeSelection.classList.add('hidden');
    elements.senderSection.classList.add('hidden');
    elements.receiverSection.classList.add('hidden');
    elements.progressSection.classList.add('hidden');
    elements.completeSection.classList.add('hidden');
    elements.errorSection.classList.add('hidden');
}

function showError(message) {
    hideAllSections();
    elements.errorMessage.textContent = message;
    elements.errorSection.classList.remove('hidden');
}

// ===== SYSTÈME D'APPROBATION ET VERROUILLAGE =====

function showApprovalRequest(odId, pseudo) {
    // Créer une popup pour approuver/refuser
    const existing = document.querySelector('.approval-popup');
    if (existing) existing.remove();
    
    const popup = document.createElement('div');
    popup.className = 'approval-popup';
    popup.innerHTML = `
        <div class="approval-content">
            <h3>✋ Demande d'accès</h3>
            <p><strong>${escapeHtml(pseudo)}</strong> souhaite rejoindre la session</p>
            <div class="approval-actions">
                <button class="btn btn-success approve-btn" data-odid="${odId}">✓ Accepter</button>
                <button class="btn btn-danger reject-btn" data-odid="${odId}">✕ Refuser</button>
            </div>
            <p class="approval-hint">En attente: ${pendingApprovals.size} demande(s)</p>
        </div>
    `;
    
    document.body.appendChild(popup);
    
    // Event listeners
    popup.querySelector('.approve-btn').addEventListener('click', () => {
        approveParticipant(odId);
        popup.remove();
    });
    
    popup.querySelector('.reject-btn').addEventListener('click', () => {
        rejectParticipant(odId);
        popup.remove();
    });
}

function approveParticipant(odId) {
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
            type: 'approve-participant',
            odId: odId
        }));
        pendingApprovals.delete(odId);
        showToast('✅ Participant accepté');
        
        // Afficher la prochaine demande s'il y en a
        if (pendingApprovals.size > 0) {
            const next = pendingApprovals.entries().next().value;
            if (next) {
                showApprovalRequest(next[0], next[1].pseudo);
            }
        }
    }
}

function rejectParticipant(odId) {
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
            type: 'reject-participant',
            odId: odId
        }));
        pendingApprovals.delete(odId);
        showToast('❌ Participant refusé');
        
        // Afficher la prochaine demande s'il y en a
        if (pendingApprovals.size > 0) {
            const next = pendingApprovals.entries().next().value;
            if (next) {
                showApprovalRequest(next[0], next[1].pseudo);
            }
        }
    }
}

function updatePendingBadge(count) {
    let badge = document.querySelector('.pending-badge');
    if (count > 0) {
        if (!badge) {
            badge = document.createElement('span');
            badge.className = 'pending-badge';
            const lockBtn = document.querySelector('.lock-session-btn');
            if (lockBtn) {
                lockBtn.parentElement.appendChild(badge);
            }
        }
        badge.textContent = count;
    } else if (badge) {
        badge.remove();
    }
}

function updateLockButton() {
    const lockBtn = document.querySelector('.lock-session-btn');
    if (lockBtn) {
        lockBtn.textContent = sessionOptions.isLocked ? '🔓 Déverrouiller' : '🔒 Verrouiller';
        lockBtn.title = sessionOptions.isLocked ? 'Permettre de nouveaux participants' : 'Bloquer les nouveaux participants';
    }
}

function toggleSessionLock() {
    if (ws && ws.readyState === WebSocket.OPEN) {
        const newLockState = !sessionOptions.isLocked;
        ws.send(JSON.stringify({
            type: 'lock-session',
            locked: newLockState
        }));
    }
}

// ===== SÉCURITÉ - Échappement HTML pour prévenir XSS =====
function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function toBase64(u8arr) {
    return btoa(String.fromCharCode(...u8arr));
}

function fromBase64(b64) {
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

// ===== CRYPTOGRAPHIE =====

async function deriveKeyFromPassword(password, saltB64, iterations = KDF_ITERATIONS) {
    if (!window.crypto || !window.crypto.subtle) {
        throw new Error('La Web Crypto API n\'est pas disponible dans ce navigateur. Utilisez Chrome, Firefox, Edge ou Safari récent.');
    }
    const enc = new TextEncoder();
    const salt = fromBase64(saltB64);
    const pwKey = await window.crypto.subtle.importKey(
        'raw',
        enc.encode(password),
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );

    return window.crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            hash: 'SHA-256',
            salt,
            iterations
        },
        pwKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

function generatePasswordSalt() {
    const salt = window.crypto.getRandomValues(new Uint8Array(PASSWORD_SALT_BYTES));
    return toBase64(salt);
}

async function generateCryptoKey() {
    // Générer une clé AES-GCM 256 bits
    cryptoKey = await window.crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true, // extractable
        ['encrypt', 'decrypt']
    );
    
    // Générer un IV (Initialization Vector) de 12 octets
    cryptoIV = window.crypto.getRandomValues(new Uint8Array(12));
    
    console.log('🔐 Clé de chiffrement générée');
}

async function exportKeyToBase64() {
    const exported = await window.crypto.subtle.exportKey('raw', cryptoKey);
    const keyArray = new Uint8Array(exported);
    const combined = new Uint8Array(keyArray.length + cryptoIV.length);
    combined.set(keyArray);
    combined.set(cryptoIV, keyArray.length);
    return btoa(String.fromCharCode(...combined));
}

async function importKeyFromBase64(base64String) {
    const combined = Uint8Array.from(atob(base64String), c => c.charCodeAt(0));
    const keyData = combined.slice(0, 32); // 256 bits = 32 octets
    cryptoIV = combined.slice(32); // Les 12 derniers octets = IV
    
    cryptoKey = await window.crypto.subtle.importKey(
        'raw',
        keyData,
        { name: 'AES-GCM', length: 256 },
        true, // extractable = true pour pouvoir ré-exporter la clé
        ['encrypt', 'decrypt']
    );
    
    console.log('🔐 Clé de chiffrement importée');
}

async function encryptChunk(data) {
    // Générer un IV unique pour chaque chunk
    const chunkIV = window.crypto.getRandomValues(new Uint8Array(12));
    
    const encrypted = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: chunkIV },
        cryptoKey,
        data
    );
    
    // Combiner IV + données chiffrées
    const result = new Uint8Array(chunkIV.length + encrypted.byteLength);
    result.set(chunkIV);
    result.set(new Uint8Array(encrypted), chunkIV.length);
    
    return result;
}

async function decryptChunk(data) {
    const dataArray = new Uint8Array(data);
    const chunkIV = dataArray.slice(0, 12);
    const encryptedData = dataArray.slice(12);
    
    const decrypted = await window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: chunkIV },
        cryptoKey,
        encryptedData
    );
    
    return new Uint8Array(decrypted);
}

async function calculateHash(data) {
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// ===== ECDH (Diffie-Hellman Elliptic Curve) =====

/**
 * Génère une paire de clés ECDH (Elliptic Curve Diffie-Hellman)
 * Utilise la courbe P-256 (secp256r1) recommandée par le NIST
 */
async function generateECDHKeyPair() {
    ecdhKeyPair = await window.crypto.subtle.generateKey(
        {
            name: 'ECDH',
            namedCurve: 'P-256'
        },
        true, // extractable
        ['deriveKey', 'deriveBits']
    );
    
    // Exporter la clé publique en format raw pour partage
    const publicKeyRaw = await window.crypto.subtle.exportKey('raw', ecdhKeyPair.publicKey);
    ecdhPublicKeyB64 = btoa(String.fromCharCode(...new Uint8Array(publicKeyRaw)));
    
    console.log('🔐 Paire de clés ECDH générée');
    return ecdhPublicKeyB64;
}

/**
 * Exporte la paire ECDH pour stockage en localStorage
 */
async function exportECDHKeyPair() {
    if (!ecdhKeyPair) return null;
    
    const privateKeyJwk = await window.crypto.subtle.exportKey('jwk', ecdhKeyPair.privateKey);
    const publicKeyRaw = await window.crypto.subtle.exportKey('raw', ecdhKeyPair.publicKey);
    
    return {
        privateKeyJwk: privateKeyJwk,
        publicKeyB64: btoa(String.fromCharCode(...new Uint8Array(publicKeyRaw)))
    };
}

/**
 * Importe une paire ECDH depuis localStorage
 */
async function importECDHKeyPair(exported) {
    if (!exported || !exported.privateKeyJwk || !exported.publicKeyB64) return false;
    
    try {
        const privateKey = await window.crypto.subtle.importKey(
            'jwk',
            exported.privateKeyJwk,
            { name: 'ECDH', namedCurve: 'P-256' },
            true,
            ['deriveKey', 'deriveBits']
        );
        
        // Reconstruire la clé publique depuis le JWK (la clé publique est incluse dans le JWK privé)
        const publicKey = await window.crypto.subtle.importKey(
            'jwk',
            { ...exported.privateKeyJwk, d: undefined }, // Retirer la partie privée
            { name: 'ECDH', namedCurve: 'P-256' },
            true,
            []
        );
        
        ecdhKeyPair = { privateKey, publicKey };
        ecdhPublicKeyB64 = exported.publicKeyB64;
        
        console.log('🔐 Paire ECDH restaurée depuis localStorage');
        return true;
    } catch (err) {
        console.error('❌ Erreur import ECDH:', err);
        return false;
    }
}

/**
 * Dérive une clé AES-256-GCM depuis le secret partagé ECDH
 * @param {string} theirPublicKeyB64 - Clé publique de l'autre partie en base64
 */
async function deriveSharedKey(theirPublicKeyB64) {
    if (!ecdhKeyPair) {
        throw new Error('Paire ECDH non initialisée');
    }
    
    // Importer la clé publique de l'autre partie
    const theirPublicKeyRaw = Uint8Array.from(atob(theirPublicKeyB64), c => c.charCodeAt(0));
    const theirPublicKey = await window.crypto.subtle.importKey(
        'raw',
        theirPublicKeyRaw,
        { name: 'ECDH', namedCurve: 'P-256' },
        false,
        []
    );
    
    // Dériver les bits partagés
    const sharedBits = await window.crypto.subtle.deriveBits(
        {
            name: 'ECDH',
            public: theirPublicKey
        },
        ecdhKeyPair.privateKey,
        256 // 256 bits
    );
    
    // Utiliser HKDF pour dériver une clé AES robuste
    const sharedKeyMaterial = await window.crypto.subtle.importKey(
        'raw',
        sharedBits,
        { name: 'HKDF' },
        false,
        ['deriveKey']
    );
    
    cryptoKey = await window.crypto.subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: new TextEncoder().encode('SecurePeer-ECDH-Salt-v1'),
            info: new TextEncoder().encode('SecurePeer-AES-Key')
        },
        sharedKeyMaterial,
        { name: 'AES-GCM', length: 256 },
        true, // extractable pour pouvoir stocker
        ['encrypt', 'decrypt']
    );
    
    // Générer un IV déterministe basé sur le secret partagé (pour la compatibilité)
    const ivMaterial = await window.crypto.subtle.digest('SHA-256', 
        new TextEncoder().encode(btoa(String.fromCharCode(...new Uint8Array(sharedBits))) + '-IV')
    );
    cryptoIV = new Uint8Array(ivMaterial).slice(0, 12);
    
    // Clé AES dérivée
    return true;
}

/**
 * Envoie ma clé publique ECDH à un participant via WebSocket
 */
function sendECDHPublicKey(targetOdId) {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    
    ws.send(JSON.stringify({
        type: 'ecdh-public-key',
        targetOdId: targetOdId,
        publicKeyB64: ecdhPublicKeyB64
    }));
    
    console.log('📤 Clé publique ECDH envoyée à:', targetOdId);
}

/**
 * Attend la réception de la clé publique d'un participant
 * @returns {Promise<string>} La clé publique reçue
 */
function waitForECDHPublicKey(fromOdId, timeoutMs = 30000) {
    return new Promise((resolve, reject) => {
        // Vérifier si on a déjà reçu la clé
        if (pendingKeyExchanges.has(fromOdId)) {
            const exchange = pendingKeyExchanges.get(fromOdId);
            if (exchange.publicKeyB64) {
                resolve(exchange.publicKeyB64);
                return;
            }
        }
        
        // Attendre la réception
        keyExchangeResolvers.set(fromOdId, { resolve, reject });
        
        // Timeout
        setTimeout(() => {
            if (keyExchangeResolvers.has(fromOdId)) {
                keyExchangeResolvers.delete(fromOdId);
                reject(new Error('Timeout ECDH key exchange'));
            }
        }, timeoutMs);
    });
}

/**
 * Handler pour la réception d'une clé publique ECDH
 */
function handleECDHPublicKey(fromOdId, publicKeyB64) {
    console.log('📥 Clé publique ECDH reçue de:', fromOdId);
    
    pendingKeyExchanges.set(fromOdId, { publicKeyB64, resolved: true });
    
    // Résoudre la promesse en attente si elle existe
    if (keyExchangeResolvers.has(fromOdId)) {
        const { resolve } = keyExchangeResolvers.get(fromOdId);
        keyExchangeResolvers.delete(fromOdId);
        resolve(publicKeyB64);
    }
}

// ===== DOUBLE RATCHET (Signal Protocol Post-Quantum) =====

/**
 * État du Double Ratchet par paire de peers
 * Chaque conversation peer↔peer a son propre ratchet
 */
let doubleRatchetState = new Map(); // Map<odId, {rootKey, sendChain, recvChain, dhRatchet, skippedKeys}>

/**
 * Buffer pour les messages double-ratchet-init reçus avant l'initialisation
 */
let pendingDoubleRatchetInits = new Map(); // Map<odId, {dhPublicKey}>

/**
 * Timestamp du dernier envoi de double-ratchet-init (anti-boucle)
 */
let lastDoubleRatchetInitSent = new Map(); // Map<odId, timestamp>

/**
 * Structure du ratchet pour une paire de peers:
 * {
 *   rootKey: Uint8Array(32), // Root key dérivée d'ECDH initial
 *   sendChain: { chainKey: Uint8Array(32), messageNumber: number },
 *   recvChain: { chainKey: Uint8Array(32), messageNumber: number },
 *   dhRatchet: { 
 *     keyPair: { privateKey, publicKey },
 *     publicKeyB64: string,
 *     theirPublicKeyB64: string,
 *     numberUsed: number
 *   },
 *   skippedKeys: Map<string, {key: Uint8Array(32), timestamp}>  // Map<"odId:msgNum", ...>
 * }
 */

/**
 * HKDF-SHA256 selon RFC 5869
 * Expanded du rootKey en chaînes de ratcheting
 */
async function hkdfExpand(prk, info, length) {
    const hash = 'SHA-256';
    const hashLen = 32; // SHA-256 = 32 bytes
    
    // Nombre d'itérations N = ceil(L / HashLen)
    const N = Math.ceil(length / hashLen);
    let okm = new Uint8Array();
    let t = new Uint8Array();
    
    for (let i = 1; i <= N; i++) {
        // T(i) = HMAC-Hash(PRK, T(i-1) | info | i)
        const concat = new Uint8Array(t.length + info.length + 1);
        concat.set(t);
        concat.set(info, t.length);
        concat[concat.length - 1] = i;
        
        t = new Uint8Array(await window.crypto.subtle.sign(
            { name: 'HMAC', hash },
            await window.crypto.subtle.importKey('raw', prk, { name: 'HMAC', hash }, false, ['sign']),
            concat
        ));
        
        okm = new Uint8Array([...okm, ...t]);
    }
    
    // Retourner les L premiers bytes
    return okm.slice(0, length);
}

/**
 * HKDF Extract selon RFC 5869
 * Dérive un PRK depuis le secret partagé
 */
async function hkdfExtract(salt, ikm) {
    const hash = 'SHA-256';
    
    if (!salt || salt.length === 0) {
        salt = new Uint8Array(32); // Zeros
    }
    
    return new Uint8Array(await window.crypto.subtle.sign(
        { name: 'HMAC', hash },
        await window.crypto.subtle.importKey('raw', salt, { name: 'HMAC', hash }, false, ['sign']),
        ikm
    ));
}

/**
 * KDF_RK: Dérive une nouvelle rootKey et une chainKey initiale
 * Utilisé quand le DH ratchet tourne (nouveau ECDH)
 */
async function kdfRK(rootKey, dhSecret) {
    const salt = new TextEncoder().encode('KDF_RK');
    const info = new TextEncoder().encode('Double Ratchet Root Key');
    
    const prk = await hkdfExtract(rootKey, dhSecret);
    const expanded = await hkdfExpand(prk, info, 64); // 64 bytes = 32 pour RK + 32 pour CK
    
    return {
        rootKey: expanded.slice(0, 32),
        chainKey: expanded.slice(32, 64)
    };
}

/**
 * KDF_CK: Avance la chaîne (symmetric ratchet)
 * Utilisé à chaque message envoyé/reçu
 */
async function kdfCK(chainKey) {
    const hmacKey = await window.crypto.subtle.importKey(
        'raw',
        chainKey,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    
    // Nouvelle chainKey = HMAC-SHA256(chainKey, 0x01)
    const newCK = new Uint8Array(await window.crypto.subtle.sign(
        'HMAC',
        hmacKey,
        new Uint8Array([0x01])
    ));
    
    // MessageKey = HMAC-SHA256(chainKey, 0x02)
    const messageKey = new Uint8Array(await window.crypto.subtle.sign(
        'HMAC',
        hmacKey,
        new Uint8Array([0x02])
    ));
    
    return { newCK, messageKey };
}

/**
 * Initialise le Double Ratchet avec X3DH complet
 * @param {string} odId - ID du peer
 * @param {Uint8Array} sharedSecret - Secret d'ECDH initial (256 bits)
 * @param {boolean} isInitiator - True si tu es l'initiateur (détermine qui envoie en premier)
 */
async function initializeDoubleRatchet(odId, sharedSecret, isInitiator) {
    try {
        // Dériver rootKey initial depuis le secret partagé ECDH
        const salt = new TextEncoder().encode('SecurePeer-X3DH-Salt');
        const info = new TextEncoder().encode('SecurePeer-Double-Ratchet-Initialization');
        
        const prk = await hkdfExtract(salt, sharedSecret);
        const expanded = await hkdfExpand(prk, info, 96); // 96 bytes = 32 RK + 32 CK + 32 reserved
        
        const rootKey = expanded.slice(0, 32);
        const initialChainKey = expanded.slice(32, 64);
        
        // Générer une nouvelle paire DH pour le ratchet
        const dhKeyPair = await window.crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' },
            true,
            ['deriveKey', 'deriveBits']
        );
        
        const dhPublicKeyRaw = await window.crypto.subtle.exportKey('raw', dhKeyPair.publicKey);
        const dhPublicKeyB64 = btoa(String.fromCharCode(...new Uint8Array(dhPublicKeyRaw)));
        
        // Initialiser le ratchet selon si tu es initiateur ou non
        let state;
        if (isInitiator) {
            // Initiateur : sendChain actif, recvChain inactif (attend clé publique du pair)
            state = {
                rootKey,
                sendChain: {
                    chainKey: initialChainKey,
                    messageNumber: 0,
                    active: true // Initiateur: sendChain actif
                },
                recvChain: {
                    chainKey: initialChainKey,
                    messageNumber: 0,
                    active: false // N'activera que quand on reçoit la clé DH du pair
                },
                dhRatchet: {
                    keyPair: dhKeyPair,
                    publicKeyB64: dhPublicKeyB64,
                    theirPublicKeyB64: null, // À remplir quand on reçoit leur clé
                    numberUsed: 0,
                    lastRatchetTime: Date.now() // Timer pour rotation 30min
                },
                skippedKeys: new Map(), // Map<"odId:msgNum", {key: Uint8Array(32), timestamp, expiry}>
                skippedKeysMaxAge: 1000 * 60 * 60, // 1 heure
                dhRatchetMaxAge: 1000 * 60 * 30 // 30 minutes
            };
        } else {
            // Non-initiateur : recvChain actif, sendChain inactif (attend clé publique du pair)
            state = {
                rootKey,
                sendChain: {
                    chainKey: initialChainKey,
                    messageNumber: 0,
                    active: false // N'activera que quand on reçoit la clé DH du pair
                },
                recvChain: {
                    chainKey: initialChainKey,
                    messageNumber: 0,
                    active: true // Non-initiator reçoit en premier
                },
                dhRatchet: {
                    keyPair: dhKeyPair,
                    publicKeyB64: dhPublicKeyB64,
                    theirPublicKeyB64: null,
                    numberUsed: 0,
                    lastRatchetTime: Date.now() // Timer pour rotation 30min
                },
                skippedKeys: new Map(),
                skippedKeysMaxAge: 1000 * 60 * 60,
                dhRatchetMaxAge: 1000 * 60 * 30 // 30 minutes
            };
        }
        
        doubleRatchetState.set(odId, state);
        
        // Retourner la clé publique DH en Uint8Array
        return new Uint8Array(dhPublicKeyRaw);
        
    } catch (err) {
        console.error('❌ Erreur initialisation Double Ratchet:', err);
        throw err;
    }
}

/**
 * Complète l'initialisation du DH Ratchet quand on reçoit la clé publique du pair
 */
async function completeDoubleRatchetHandshake(odId, theirPublicKey) {
    try {
        const state = doubleRatchetState.get(odId);
        if (!state) {
            throw new Error('Double Ratchet non initialisé pour ' + odId);
        }
        
        // Convertir en Uint8Array si c'est un Array
        let theirPublicKeyRaw;
        if (Array.isArray(theirPublicKey)) {
            theirPublicKeyRaw = new Uint8Array(theirPublicKey);
            state.dhRatchet.theirPublicKeyB64 = btoa(String.fromCharCode(...theirPublicKeyRaw));
        } else {
            // C'est une string base64
            theirPublicKeyRaw = Uint8Array.from(atob(theirPublicKey), c => c.charCodeAt(0));
            state.dhRatchet.theirPublicKeyB64 = theirPublicKey;
        }
        
        const theirPublicKeyCrypto = await window.crypto.subtle.importKey(
            'raw',
            theirPublicKeyRaw,
            { name: 'ECDH', namedCurve: 'P-256' },
            false,
            []
        );
        
        const sharedBits = await window.crypto.subtle.deriveBits(
            { name: 'ECDH', public: theirPublicKeyCrypto },
            state.dhRatchet.keyPair.privateKey,
            256
        );
        
        // Dériver nouvelle rootKey + chainKey depuis le DH
        const result = await kdfRK(state.rootKey, new Uint8Array(sharedBits));
        state.rootKey = result.rootKey;
        
        // Mettre à jour la chainKey de la chaîne ACTIVE (pas les deux!)
        // L'initiator met à jour sendChain, le non-initiator met à jour recvChain
        if (state.sendChain.active) {
            // Initiator: update sendChain
            state.sendChain.chainKey = result.chainKey;
        } else {
            // Non-initiator: update recvChain
            state.recvChain.chainKey = result.chainKey;
        }
        
        // Activer les chaînes si elles ne sont pas encore actives
        if (!state.sendChain.active && state.sendChain.messageNumber === 0) {
            state.sendChain.active = true;
        }
        if (!state.recvChain.active && state.recvChain.messageNumber === 0) {
            state.recvChain.active = true;
        }
        
        // Réinitialiser le timer DH ratchet après handshake
        state.dhRatchet.lastRatchetTime = Date.now();
        
    } catch (err) {
        console.error('❌ Erreur handshake Double Ratchet:', err);
        throw err;
    }
}

/**
 * Encode un message avec header chiffré
 * Header = encryptedHeader(messageNumber || dhPublicKey)
 */
async function encryptMessageHeader(state, plaintext, chainKey, messageNumber) {
    try {
        // Dériver une clé de header depuis la chainKey fournie (non avancée)
        const headerHmac = await window.crypto.subtle.importKey(
            'raw',
            chainKey,
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
        );
        
        const headerKey = new Uint8Array(await window.crypto.subtle.sign(
            'HMAC',
            headerHmac,
            new TextEncoder().encode('header')
        ));
        
        // Header = messageNumber (4 bytes) || dhPublicKey (65 bytes) || padding
        const msgNumBytes = new Uint8Array(4);
        new DataView(msgNumBytes.buffer).setUint32(0, messageNumber, false);
        
        const dhPublicKeyRaw = Uint8Array.from(atob(state.dhRatchet.publicKeyB64), c => c.charCodeAt(0));
        const headerPlain = new Uint8Array([...msgNumBytes, ...dhPublicKeyRaw]);
        
        // Chiffrer le header avec AES-GCM
        const headerIV = window.crypto.getRandomValues(new Uint8Array(12));
        const headerKey_imported = await window.crypto.subtle.importKey(
            'raw',
            headerKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt']
        );
        
        const headerEncrypted = new Uint8Array(await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: headerIV },
            headerKey_imported,
            headerPlain
        ));
        
        // Format final : IV(12) || encryptedHeader || plaintext
        const result = new Uint8Array(headerIV.length + headerEncrypted.length + plaintext.length);
        result.set(headerIV);
        result.set(headerEncrypted, headerIV.length);
        result.set(plaintext, headerIV.length + headerEncrypted.length);
        
        return result;
        
    } catch (err) {
        console.error('❌ Erreur chiffrement header:', err);
        throw err;
    }
}

/**
 * Envoie un message avec Double Ratchet
 * Effectue le ratcheting symétrique et DH automatiquement
 */
async function sendMessageWithDoubleRatchet(odId, plaintext) {
    try {
        const state = doubleRatchetState.get(odId);
        if (!state) {
            throw new Error('Double Ratchet non initialisé pour ' + odId);
        }
        
        if (!state.sendChain.active) {
            throw new Error('Send chain pas encore active (handshake incomplet)');
        }
        
        // Sauvegarder la chainKey AVANT de l'avancer (pour le header)
        const currentChainKey = state.sendChain.chainKey;
        const currentMessageNumber = state.sendChain.messageNumber;
        
        // Avancer la chaîne symétrique
        const { newCK, messageKey } = await kdfCK(state.sendChain.chainKey);
        state.sendChain.chainKey = newCK;
        
        // Chiffrer le plaintext avec le messageKey
        const messageKeyImported = await window.crypto.subtle.importKey(
            'raw',
            messageKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt']
        );
        
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const ciphertext = new Uint8Array(await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            messageKeyImported,
            plaintext
        ));
        
        // Combiner IV + ciphertext
        const encryptedMessage = new Uint8Array(iv.length + ciphertext.length);
        encryptedMessage.set(iv);
        encryptedMessage.set(ciphertext, iv.length);
        
        // Encoder header avec la chainKey et messageNumber AVANT l'avancement
        const headerEncrypted = await encryptMessageHeader(state, encryptedMessage, currentChainKey, currentMessageNumber);
        
        // DH Ratchet: tous les 100 messages OU après 30 minutes
        state.sendChain.messageNumber++;
        const timeSinceLastRatchet = Date.now() - state.dhRatchet.lastRatchetTime;
        if (state.sendChain.messageNumber % 100 === 0 || timeSinceLastRatchet > state.dhRatchetMaxAge) {
            await performDHRatchet(state);
            console.log(`🔄 DH Ratchet déclenché (${timeSinceLastRatchet > state.dhRatchetMaxAge ? 'timer 30min' : '100 messages'})`);
        }
        
        // Résultat : Buffer contenant le message chiffré complet
        return {
            type: 'double-ratchet-message',
            odId: odId,
            data: btoa(String.fromCharCode(...headerEncrypted)),
            messageNumber: state.sendChain.messageNumber - 1, // Pour reference
            dhPublicKey: state.dhRatchet.publicKeyB64
        };
        
    } catch (err) {
        console.error('❌ Erreur send Double Ratchet:', err);
        throw err;
    }
}

/**
 * Reçoit et déchiffre un message avec Double Ratchet
 */
async function receiveMessageWithDoubleRatchet(odId, headerEncryptedB64, senderDHPublicKeyB64) {
    try {
        const state = doubleRatchetState.get(odId);
        if (!state) {
            throw new Error('Double Ratchet non initialisé pour ' + odId);
        }
        
        const headerEncrypted = Uint8Array.from(atob(headerEncryptedB64), c => c.charCodeAt(0));
        
        // Extraire IV et messages
        const headerIV = headerEncrypted.slice(0, 12);
        const rest = headerEncrypted.slice(12);
        
        // Essayer de déchiffrer le header avec la recvChain courante
        let plaintext = null;
        let headerDecrypted = null;
        
        try {
            // Dériver la clé de header depuis la recvChain
            const chainKey = state.recvChain.chainKey;
            const headerHmac = await window.crypto.subtle.importKey(
                'raw',
                chainKey,
                { name: 'HMAC', hash: 'SHA-256' },
                false,
                ['sign']
            );
            
            const headerKey = new Uint8Array(await window.crypto.subtle.sign(
                'HMAC',
                headerHmac,
                new TextEncoder().encode('header')
            ));
            
            const headerKeyImported = await window.crypto.subtle.importKey(
                'raw',
                headerKey,
                { name: 'AES-GCM', length: 256 },
                false,
                ['decrypt']
            );
            
            // Chiffré = 69 bytes (4 msg num + 65 DH public)
            const headerCiphertext = rest.slice(0, 85); // 69 + GCM tag (16)
            const messageCiphertext = rest.slice(85);
            
            headerDecrypted = new Uint8Array(await window.crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: headerIV },
                headerKeyImported,
                headerCiphertext
            ));
            
            // Extraire messageNumber et leur DH public key
            const messageNumber = new DataView(headerDecrypted.buffer).getUint32(0, false);
            const theirPublicKeyRaw = headerDecrypted.slice(4, 69);
            const theirPublicKeyB64 = btoa(String.fromCharCode(...theirPublicKeyRaw));
            
            // Si leur clé DH a changé, effectuer DH ratchet
            if (state.dhRatchet.theirPublicKeyB64 && theirPublicKeyB64 !== state.dhRatchet.theirPublicKeyB64) {
                console.log('🔄 DH Ratchet détecté (leur clé a changé)');
                
                // Calculer skipped keys pour les messages entre ancien et nouveau numéro
                const oldRecvNum = state.recvChain.messageNumber;
                const newRecvNum = messageNumber;
                
                // Stocker les clés sautées (max 100)
                for (let i = oldRecvNum; i < newRecvNum && i < oldRecvNum + 100; i++) {
                    const { newCK, messageKey } = await kdfCK(state.recvChain.chainKey);
                    state.recvChain.chainKey = newCK;
                    const keyId = odId + ':' + i;
                    state.skippedKeys.set(keyId, {
                        key: messageKey,
                        timestamp: Date.now(),
                        expiry: Date.now() + state.skippedKeysMaxAge
                    });
                }
                
                // Effectuer le DH ratchet
                state.dhRatchet.theirPublicKeyB64 = theirPublicKeyB64;
                const theirPublicKey = await window.crypto.subtle.importKey(
                    'raw',
                    theirPublicKeyRaw,
                    { name: 'ECDH', namedCurve: 'P-256' },
                    false,
                    []
                );
                
                const sharedBits = await window.crypto.subtle.deriveBits(
                    { name: 'ECDH', public: theirPublicKey },
                    state.dhRatchet.keyPair.privateKey,
                    256
                );
                
                // Dériver new rootKey
                const kdfResult = await kdfRK(state.rootKey, new Uint8Array(sharedBits));
                state.rootKey = kdfResult.rootKey;
                state.recvChain.chainKey = kdfResult.chainKey;
                state.recvChain.messageNumber = 0;
            }
            
            // Avancer recvChain jusqu'au numéro du message
            for (let i = state.recvChain.messageNumber; i < messageNumber; i++) {
                const { newCK, messageKey } = await kdfCK(state.recvChain.chainKey);
                state.recvChain.chainKey = newCK;
                const keyId = odId + ':' + i;
                state.skippedKeys.set(keyId, {
                    key: messageKey,
                    timestamp: Date.now(),
                    expiry: Date.now() + state.skippedKeysMaxAge
                });
            }
            
            // Avancer un dernier coup pour le message courant
            const { newCK, messageKey } = await kdfCK(state.recvChain.chainKey);
            state.recvChain.chainKey = newCK;
            state.recvChain.messageNumber = messageNumber + 1;
            
            // Déchiffrer le message avec le messageKey
            const messageIV = messageCiphertext.slice(0, 12);
            const messageCipherOnly = messageCiphertext.slice(12);
            
            const messageKeyImported = await window.crypto.subtle.importKey(
                'raw',
                messageKey,
                { name: 'AES-GCM', length: 256 },
                false,
                ['decrypt']
            );
            
            plaintext = new Uint8Array(await window.crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: messageIV },
                messageKeyImported,
                messageCipherOnly
            ));
            
        } catch (err) {
            console.warn('⚠️ Impossible déchiffrer avec chaîne actuelle, essai skipped keys buffer...');
            
            // Essayer avec les skipped keys
            // Extraire messageNumber du header
            const headerCiphertext = rest.slice(0, 85);
            let headerDecryptedForNum;
            
            try {
                const chainKey = state.recvChain.chainKey;
                const headerHmac = await window.crypto.subtle.importKey(
                    'raw',
                    chainKey,
                    { name: 'HMAC', hash: 'SHA-256' },
                    false,
                    ['sign']
                );
                
                const headerKey = new Uint8Array(await window.crypto.subtle.sign(
                    'HMAC',
                    headerHmac,
                    new TextEncoder().encode('header')
                ));
                
                const headerKeyImported = await window.crypto.subtle.importKey(
                    'raw',
                    headerKey,
                    { name: 'AES-GCM', length: 256 },
                    false,
                    ['decrypt']
                );
                
                headerDecryptedForNum = new Uint8Array(await window.crypto.subtle.decrypt(
                    { name: 'AES-GCM', iv: headerIV },
                    headerKeyImported,
                    headerCiphertext
                ));
                
                const messageNumber = new DataView(headerDecryptedForNum.buffer).getUint32(0, false);
                const keyId = odId + ':' + messageNumber;
                
                // Chercher dans skipped keys
                if (state.skippedKeys.has(keyId)) {
                    const skippedKeyEntry = state.skippedKeys.get(keyId);
                    const skippedMessageKey = skippedKeyEntry.key;
                    
                    const messageIV = messageCiphertext.slice(0, 12);
                    const messageCipherOnly = messageCiphertext.slice(12);
                    
                    const messageKeyImported = await window.crypto.subtle.importKey(
                        'raw',
                        skippedMessageKey,
                        { name: 'AES-GCM', length: 256 },
                        false,
                        ['decrypt']
                    );
                    
                    plaintext = new Uint8Array(await window.crypto.subtle.decrypt(
                        { name: 'AES-GCM', iv: messageIV },
                        messageKeyImported,
                        messageCipherOnly
                    ));
                    
                    // Zeroize et delete la clé utilisée
                    skippedKeyEntry.key.fill(0);
                    state.skippedKeys.delete(keyId);
                    
                    console.log('✅ Message déchiffré avec skipped key:', messageNumber);
                } else {
                    throw new Error('Clé sautée non trouvée dans le buffer');
                }
            } catch (innerErr) {
                console.error('❌ Erreur avec skipped keys:', innerErr.message, innerErr);
                throw err; // Throw original error
            }
        }
        
        // Nettoyer les clés expirées
        cleanupSkippedKeys(state);
        
        return plaintext;
        
    } catch (err) {
        console.error('❌ Erreur receive Double Ratchet:', err);
        throw err;
    }
}

/**
 * Effectue le DH Ratchet: renouvelle la paire ECDH
 */
async function performDHRatchet(state) {
    try {
        // Générer une nouvelle paire ECDH
        const newKeyPair = await window.crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' },
            true,
            ['deriveKey', 'deriveBits']
        );
        
        const newPublicKeyRaw = await window.crypto.subtle.exportKey('raw', newKeyPair.publicKey);
        const newPublicKeyB64 = btoa(String.fromCharCode(...new Uint8Array(newPublicKeyRaw)));
        
        // Dériver le secret avec leur dernière clé publique
        if (state.dhRatchet.theirPublicKeyB64) {
            const theirPublicKeyRaw = Uint8Array.from(atob(state.dhRatchet.theirPublicKeyB64), c => c.charCodeAt(0));
            const theirPublicKey = await window.crypto.subtle.importKey(
                'raw',
                theirPublicKeyRaw,
                { name: 'ECDH', namedCurve: 'P-256' },
                false,
                []
            );
            
            const sharedBits = await window.crypto.subtle.deriveBits(
                { name: 'ECDH', public: theirPublicKey },
                state.dhRatchet.keyPair.privateKey,
                256
            );
            
            // Dériver new rootKey + initChainKey
            const result = await kdfRK(state.rootKey, new Uint8Array(sharedBits));
            state.rootKey = result.rootKey;
            state.sendChain.chainKey = result.chainKey;
            state.sendChain.messageNumber = 0;
        }
        
        // Mettre à jour la paire ECDH
        state.dhRatchet.keyPair = newKeyPair;
        state.dhRatchet.publicKeyB64 = newPublicKeyB64;
        state.dhRatchet.numberUsed = state.sendChain.messageNumber;
        state.dhRatchet.lastRatchetTime = Date.now(); // Réinitialiser le timer
        
        console.log('🔄 DH Ratchet effectué | Nouvelle clé DH:', newPublicKeyB64.substring(0, 10) + '...');
        
    } catch (err) {
        console.error('❌ Erreur DH Ratchet:', err);
        throw err;
    }
}

/**
 * Nettoie les clés sautées expirées
 */
function cleanupSkippedKeys(state) {
    const now = Date.now();
    for (const [keyId, entry] of state.skippedKeys.entries()) {
        if (entry.expiry < now) {
            // Zeroize la clé avant suppression
            entry.key.fill(0);
            state.skippedKeys.delete(keyId);
        }
    }
}

/**
 * Zeroize complète l'état du ratchet (logout)
 */
function zeroizeDoubleRatchet(odId) {
    const state = doubleRatchetState.get(odId);
    if (!state) return;
    
    // Zeroize toutes les clés
    if (state.rootKey) state.rootKey.fill(0);
    if (state.sendChain.chainKey) state.sendChain.chainKey.fill(0);
    if (state.recvChain.chainKey) state.recvChain.chainKey.fill(0);
    
    // Zeroize les clés sautées
    for (const [_, entry] of state.skippedKeys.entries()) {
        entry.key.fill(0);
    }
    
    doubleRatchetState.delete(odId);
    console.log('🔐 Double Ratchet zéroisé pour', odId);
}

// ===== WEBSOCKET =====

function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}`;
    
    ws = new WebSocket(wsUrl);
    
    ws.onopen = () => {
        console.log('🌐 WebSocket connecté');
        
        // Récupérer le pseudo (déjà défini avant connectWebSocket)
        // userPseudo est défini dans setupPseudoSection()
        
        // Vérifier si on a une session sauvegardée (reconnexion)
        const savedSession = localStorage.getItem('securepeer_session');
        const isReconnection = savedSession !== null;
        const savedOdId = localStorage.getItem('securepeer_odid');

        if (isReceiver && !isReconnection) {
            // Mode destinataire pour la première fois : rejoindre la room
            console.log('📥 Première connexion destinataire');
            ws.send(JSON.stringify({
                type: 'join-room',
                roomId: roomId,
                pseudo: userPseudo,
                odId: savedOdId || undefined
            }));
        } else if (isReceiver && isReconnection) {
            // Destinataire qui se reconnecte
            console.log('🔄 Reconnexion destinataire');
            ws.send(JSON.stringify({
                type: 'join-room',
                roomId: roomId,
                pseudo: userPseudo,
                odId: savedOdId || undefined
            }));
        } else if (roomId && isReconnection) {
            // Mode expéditeur qui se reconnecte
            console.log('🔄 [WS] Reconnexion expéditeur détectée');
            console.log('   📦 roomId:', roomId);
            console.log('   👤 pseudo:', userPseudo);
            console.log('   🔑 odId:', savedOdId);
            const rejoinMsg = {
                type: 'rejoin-room',
                roomId: roomId,
                pseudo: userPseudo,
                role: 'sender',
                odId: savedOdId || undefined
            };
            console.log('📤 [WS] Envoi rejoin-room:', rejoinMsg);
            ws.send(JSON.stringify(rejoinMsg));
        } else {
            // Mode expéditeur : créer une nouvelle room
            // Récupérer les options de sécurité depuis l'UI
            if (elements.sessionExpiration) {
                sessionOptions.expirationMinutes = parseInt(elements.sessionExpiration.value) || 0;
            }
            if (elements.maxParticipants) {
                sessionOptions.maxParticipants = parseInt(elements.maxParticipants.value) || 20;
            }
            if (elements.requireApproval) {
                sessionOptions.requireApproval = elements.requireApproval.checked;
            }
            if (elements.autoLock) {
                sessionOptions.autoLock = elements.autoLock.checked;
            }
            
            console.log('📤 Création nouvelle room avec options:', sessionOptions);
            ws.send(JSON.stringify({
                type: 'create-room',
                fileInfo: fileInfo,
                pseudo: userPseudo,
                options: {
                    expirationMinutes: sessionOptions.expirationMinutes,
                    maxParticipants: sessionOptions.maxParticipants,
                    requireApproval: sessionOptions.requireApproval,
                    autoLock: sessionOptions.autoLock
                }
            }));
        }
    };
    
    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        handleWebSocketMessage(data);
    };
    
    ws.onclose = () => {
        console.log('🔌 WebSocket déconnecté');
    };
    
    ws.onerror = (error) => {
        console.error('❌ Erreur WebSocket:', error);
        showError('Erreur de connexion au serveur');
    };
}

function handleWebSocketMessage(data) {
    switch (data.type) {
        case 'room-created':
            roomId = data.roomId;
            myOdId = data.odId;
            // Sauvegarder l'odId pour reconnexion future
            localStorage.setItem('securepeer_odid', myOdId);
            isCreator = true;
            saveSessionToStorage();
            generateShareLink();
            break;
            
        case 'room-rejoined':
            console.log('✅ [WS] room-rejoined reçu !');
            console.log('   📦 roomId:', data.roomId);
            console.log('   🔑 odId:', data.odId);
            console.log('   👥 participants:', data.participants);
            console.log('   📄 fileInfo:', data.fileInfo);
            console.log('   🔗 hasReceiver:', data.hasReceiver);
            roomId = data.roomId;
            myOdId = data.odId;
            isCreator = true;
            // Sauvegarder l'odId pour reconnexion future
            localStorage.setItem('securepeer_odid', myOdId);
            // Restaurer les participants existants
            participants.clear();
            if (data.participants && Array.isArray(data.participants)) {
                data.participants.forEach(p => {
                    if (p.odId !== myOdId) {
                        participants.set(p.odId, { pseudo: p.pseudo, isCreator: p.isCreator || false });
                    }
                });
                connectedCount = participants.size;
                console.log(`👥 ${connectedCount} participant(s) déjà dans la room`);
            }
            updateConnectedUsersDropdown();
            generateShareLink();
            saveSessionToStorage();
            // Si un receiver est déjà là, mettre à jour le statut
            if (data.hasReceiver || connectedCount > 0) {
                elements.linkStatus.innerHTML = `<span class="pulse"></span> 👥 ${connectedCount} utilisateur(s) connecté(s)`;
                elements.linkStatus.className = 'status status-connected';
            }
            break;
            
        case 'room-joined':
            console.log('✅ Room rejointe');
            console.log('📦 FileInfo reçue:', data.fileInfo);
            myOdId = data.odId;
            // Sauvegarder l'odId pour reconnexion future
            localStorage.setItem('securepeer_odid', myOdId);
            fileInfo = data.fileInfo;
            if (fileInfo) {
                elements.incomingFileName.textContent = fileInfo.name;
                elements.incomingFileSize.textContent = formatFileSize(fileInfo.size);
            }
            
            // Nettoyer et stocker les participants existants
            participants.clear(); // Reset pour éviter doublons si reconnexion
            if (data.participants && Array.isArray(data.participants)) {
                data.participants.forEach(p => {
                    // Ne pas s'ajouter soi-même
                    if (p.odId !== myOdId) {
                        participants.set(p.odId, { pseudo: p.pseudo, isCreator: p.isCreator || false });
                    }
                });
                connectedCount = participants.size;
                console.log(`👥 ${connectedCount} participant(s) déjà dans la room`);
                
                // Si on recharge (doubleRatchetState vide), réinit complète
                if (cryptoKey && connectedCount > 0 && doubleRatchetState.size === 0) {
                    console.log('🔄 Réinitialisation Double Ratchet après reload...');
                    (async () => {
                        try {
                            const keyMaterial = await window.crypto.subtle.exportKey('raw', cryptoKey);
                            const sharedSecret = new Uint8Array(keyMaterial);
                            
                            for (const [odId, info] of participants.entries()) {
                                // Réinitialiser localement
                                const amInitiator = isCreator || !info.isCreator;
                                const dhPublicKey = await initializeDoubleRatchet(odId, sharedSecret, amInitiator);
                                console.log('🔐 Double Ratchet réinitialisé pour', odId);
                                
                                // Envoyer la clé publique DH
                                ws.send(JSON.stringify({
                                    type: 'double-ratchet-init',
                                    to: odId,
                                    publicKey: Array.from(dhPublicKey)
                                }));
                            }
                        } catch (err) {
                            console.error('❌ Erreur réinit Double Ratchet:', err);
                        }
                    })();
                } else {
                    console.log('⏭️ Skip réinit Double Ratchet:', { hasCryptoKey: !!cryptoKey, connectedCount, doubleRatchetStateSize: doubleRatchetState.size });
                }
            }
            // Toujours mettre à jour le dropdown (même si vide)
            updateConnectedUsersDropdown();
            
            // Vérifier si un mot de passe est requis
            if (fileInfo && fileInfo.passwordRequired) {
                console.log('🔐 Mot de passe requis! Salt:', fileInfo.passwordSalt);
                passwordSaltB64 = fileInfo.passwordSalt;
                passwordIterations = fileInfo.passwordIterations || KDF_ITERATIONS;
                usePassword = true;
                elements.receiverStatus.textContent = 'Mot de passe requis pour déchiffrer';
                elements.receiverPasswordBlock.classList.remove('hidden');
                console.log('🔓 receiverPasswordBlock rendu visible');
                elements.receiverPasswordApply.onclick = applyReceiverPassword;
            } else if (ecdhKeyPair && ecdhPublicKeyB64) {
                // Mode ECDH : envoyer ma clé publique au créateur pour dériver la clé partagée
                console.log('🔐 [ECDH] Envoi de ma clé publique au créateur...');
                elements.receiverStatus.textContent = 'Échange de clés sécurisé...';
                
                // Trouver le créateur dans les participants
                const creatorOdId = Array.from(participants.entries())
                    .find(([id, p]) => p.isCreator)?.[0];
                
                if (creatorOdId) {
                    sendECDHPublicKey(creatorOdId);
                    // La dérivation se fera quand on recevra la clé publique du créateur
                } else {
                    console.error('❌ [ECDH] Créateur non trouvé dans les participants');
                    showError('Erreur: créateur de la session introuvable.');
                }
                saveSessionToStorage();
            } else {
                console.log('✅ Pas de mot de passe requis');
                elements.receiverStatus.textContent = 'Connexion P2P en cours...';
                saveSessionToStorage();
                // Initier les connexions P2P avec tous les participants existants
                initPeersWithExistingParticipants();
            }
            break;
            
        case 'peer-joined':
            console.log('👋 [PEER] Nouveau participant détecté !');
            console.log('   👤 pseudo:', data.pseudo);
            console.log('   🔑 odId:', data.odId);
            console.log('   👑 isCreator:', data.isCreator);
            
            // Éviter les doublons (même odId déjà connu)
            if (participants.has(data.odId)) {
                console.log(`⚠️ [PEER] Participant déjà connu, ignoré: ${data.pseudo}`);
                break;
            }
            
            console.log(`✅ [PEER] Ajout du participant: ${data.pseudo}`);
            participants.set(data.odId, { pseudo: data.pseudo, isCreator: data.isCreator || false });
            connectedCount = participants.size;
            console.log('   👥 Total participants maintenant:', connectedCount);
            
            // Mettre à jour le statut (selon si on est creator ou receiver)
            if (!isReceiver && elements.linkStatus) {
                elements.linkStatus.innerHTML = `<span class="pulse"></span> 👥 ${connectedCount} participant(s) connecté(s)`;
                elements.linkStatus.className = 'status status-connected';
            }
            
            // Mettre à jour le dropdown des utilisateurs connectés
            updateConnectedUsersDropdown();
            
            // Créer une connexion P2P avec ce nouveau participant (je suis l'initiateur)
            if (!usePassword) {
                console.log(`🚀 Création connexion P2P avec ${data.pseudo}`);
                initPeerWith(data.odId, true);
            }
            break;
            
        case 'peer-left':
            console.log(`👋 Participant parti: ${data.pseudo} (${data.odId})`);
            participants.delete(data.odId);
            connectedCount = participants.size;
            
            // Détruire le peer correspondant
            const leavingPeer = peers.get(data.odId);
            if (leavingPeer) {
                leavingPeer.destroy();
                peers.delete(data.odId);
            }
            
            // Mettre à jour le statut (selon si on est creator ou receiver)
            if (!isReceiver && elements.linkStatus) {
                if (connectedCount > 0) {
                    elements.linkStatus.innerHTML = `<span class="pulse"></span> 👥 ${connectedCount} participant(s) connecté(s)`;
                } else {
                    elements.linkStatus.innerHTML = '<span class="pulse"></span> En attente de participants...';
                    elements.linkStatus.className = 'status status-waiting';
                }
            }
            
            updateConnectedUsersDropdown();
            break;
            
        case 'receiver-ready':
            console.log(`🔓 Participant prêt: ${data.pseudo} (${data.odId})`);
            elements.linkStatus.innerHTML = '<span class="pulse"></span> Établissement P2P...';
            // Créer une connexion P2P avec ce participant (je suis l'initiateur)
            if (!peers.has(data.odId)) {
                initPeerWith(data.odId, true);
            }
            break;
            
        case 'signal':
            // Signal WebRTC d'un participant spécifique
            const fromId = data.fromId;
            let existingPeer = peers.get(fromId);
            
            if (!existingPeer) {
                // Créer le peer s'il n'existe pas (je suis le répondeur)
                console.log(`📡 Signal reçu de ${data.fromPseudo || fromId}, création du peer...`);
                initPeerWith(fromId, false);
                existingPeer = peers.get(fromId);
            }
            
            if (existingPeer) {
                existingPeer.signal(data.signal);
            }
            break;
            
        case 'session-closed':
            // La session a été fermée
            console.log('🔴 Session fermée par:', data.closedBy);
            clearSessionStorage();
            
            // Fermer les connexions P2P
            peers.forEach(p => p.destroy());
            peers.clear();
            
            const closeMessage = data.isCreatorClose 
                ? `La session a été fermée par le créateur (${data.closedBy}).`
                : `${data.closedBy} a quitté la session.`;
            
            showError(closeMessage + '\n\nRetour à l\'accueil...');
            setTimeout(() => {
                window.location.href = window.location.origin + window.location.pathname;
            }, 2000);
            break;
        
        case 'approval-pending':
            // Je suis en attente d'approbation
            console.log('✋ En attente d\'approbation...');
            showToast('⏳ ' + data.message);
            if (elements.receiverStatus) {
                elements.receiverStatus.textContent = '⏳ ' + data.message;
            }
            break;
        
        case 'approval-request':
            // Un participant demande à rejoindre (je suis le créateur)
            console.log('✋ Demande d\'approbation de:', data.pseudo);
            pendingApprovals.set(data.odId, { pseudo: data.pseudo, timestamp: Date.now() });
            showApprovalRequest(data.odId, data.pseudo);
            break;
        
        case 'approval-rejected':
            // Ma demande a été refusée
            console.log('❌ Demande refusée');
            showError(data.message);
            setTimeout(() => {
                clearSessionStorage();
                window.location.href = window.location.origin + window.location.pathname;
            }, 3000);
            break;
        
        case 'approval-update':
            // Mise à jour du nombre de demandes en attente
            console.log('📊 Demandes en attente:', data.pendingCount);
            updatePendingBadge(data.pendingCount);
            break;
        
        case 'session-locked':
            // La session est verrouillée
            console.log('🔒 Session verrouillée');
            sessionOptions.isLocked = true;
            showToast('🔒 ' + data.message);
            updateLockButton();
            break;
        
        case 'session-unlocked':
            // La session est déverrouillée
            console.log('🔓 Session déverrouillée');
            sessionOptions.isLocked = false;
            showToast('🔓 ' + data.message);
            updateLockButton();
            break;
            
        case 'error':
            console.log('❌ Erreur serveur:', data.message);
            // Si l'erreur indique une session/room expirée, effacer et revenir à l'accueil
            const expiredErrors = ['expiré', 'invalide', 'expired', 'invalid', 'not found', 'introuvable'];
            const isSessionExpired = expiredErrors.some(e => 
                data.message && data.message.toLowerCase().includes(e)
            );
            
            if (isSessionExpired) {
                console.log('🗑️ Session expirée détectée, nettoyage...');
                clearSessionStorage();
                showError(data.message + '\n\nRetour à l\'accueil dans 3 secondes...');
                setTimeout(() => {
                    location.reload();
                }, 3000);
            } else {
                showError(data.message);
            }
            break;
            
        case 'ecdh-public-key':
            // Réception de la clé publique ECDH d'un autre participant
            console.log('🔐 [ECDH] Clé publique reçue de:', data.fromId);
            handleECDHPublicKey(data.fromId, data.publicKeyB64);
            
            // Si je suis le créateur, dériver la clé et envoyer ma clé publique en retour
            if (isCreator && ecdhKeyPair && !cryptoKey) {
                (async () => {
                    try {
                        // Dériver la clé AES partagée
                        await deriveSharedKey(data.publicKeyB64);
                        console.log('🔐 [ECDH] Clé AES dérivée avec succès (créateur)');
                        
                        // Initialiser le Double Ratchet (créateur = initiateur)
                        if (cryptoKey) {
                            const keyMaterial = await window.crypto.subtle.exportKey('raw', cryptoKey);
                            const sharedSecret = new Uint8Array(keyMaterial);
                            const dhPublicKey = await initializeDoubleRatchet(data.fromId, sharedSecret, true);
                            
                            // Traiter les double-ratchet-init en attente
                            if (pendingDoubleRatchetInits.has(data.fromId)) {
                                const pending = pendingDoubleRatchetInits.get(data.fromId);
                                await completeDoubleRatchetHandshake(data.fromId, pending.dhPublicKey);
                                pendingDoubleRatchetInits.delete(data.fromId);
                            }
                            
                            // Envoyer la clé publique DH via signaling
                            ws.send(JSON.stringify({
                                type: 'double-ratchet-init',
                                to: data.fromId,
                                publicKey: Array.from(dhPublicKey)
                            }));
                        }
                        
                        // Envoyer ma clé publique en retour
                        sendECDHPublicKey(data.fromId);
                        
                        // Sauvegarder la session avec la nouvelle clé
                        saveSessionToStorage();
                    } catch (err) {
                        console.error('❌ [ECDH] Erreur dérivation clé:', err);
                        showError('Erreur lors de l\'échange de clés sécurisé.');
                    }
                })();
            }
            // Si je suis receiver et que j'attends une clé
            else if (isReceiver && ecdhKeyPair && !cryptoKey) {
                (async () => {
                    try {
                        // Dériver la clé AES partagée
                        await deriveSharedKey(data.publicKeyB64);
                        console.log('🔐 [ECDH] Clé AES dérivée avec succès (receiver)');
                        
                        // Initialiser le Double Ratchet (receiver = non-initiateur)
                        if (cryptoKey) {
                            const keyMaterial = await window.crypto.subtle.exportKey('raw', cryptoKey);
                            const sharedSecret = new Uint8Array(keyMaterial);
                            const dhPublicKey = await initializeDoubleRatchet(data.fromId, sharedSecret, false);
                            
                            // Traiter les double-ratchet-init en attente
                            if (pendingDoubleRatchetInits.has(data.fromId)) {
                                const pending = pendingDoubleRatchetInits.get(data.fromId);
                                await completeDoubleRatchetHandshake(data.fromId, pending.dhPublicKey);
                                pendingDoubleRatchetInits.delete(data.fromId);
                            }
                            
                            // Envoyer la clé publique DH via signaling
                            ws.send(JSON.stringify({
                                type: 'double-ratchet-init',
                                to: data.fromId,
                                publicKey: Array.from(dhPublicKey)
                            }));
                        }
                        
                        // Sauvegarder la session
                        saveSessionToStorage();
                        
                        // Maintenant on peut initier les connexions P2P
                        elements.receiverStatus.textContent = 'Clé sécurisée établie, connexion P2P...';
                        initPeersWithExistingParticipants();
                    } catch (err) {
                        console.error('❌ [ECDH] Erreur dérivation clé:', err);
                        showError('Erreur lors de l\'échange de clés sécurisé.');
                    }
                })();
            }
            break;
        
        case 'double-ratchet-init':
            // Réception de la clé publique DH pour compléter le handshake
            handleDoubleRatchetInit(data, data.fromOdId);
            break;
    }
}

// ===== WEBRTC / SIMPLE-PEER =====

// Initialiser les connexions P2P avec tous les participants existants (quand on rejoint une room)
function initPeersWithExistingParticipants() {
    console.log('🔗 initPeersWithExistingParticipants: participants.size =', participants.size);
    
    // Toujours envoyer receiver-ready pour signaler qu'on est prêt
    // Le créateur recevra ce signal et initiera la connexion P2P
    if (ws && ws.readyState === WebSocket.OPEN) {
        console.log('📤 Envoi de receiver-ready');
        ws.send(JSON.stringify({ type: 'receiver-ready' }));
    }
    
    // Si on a déjà des participants, créer les connexions P2P avec eux
    participants.forEach((info, odId) => {
        if (!peers.has(odId)) {
            console.log(`🚀 Connexion P2P avec ${info.pseudo} (${odId})`);
        }
    });
}

// Créer une connexion P2P avec un participant spécifique
function initPeerWith(targetOdId, initiator) {
    if (peers.has(targetOdId)) {
        console.log(`⚠️ Peer déjà existant pour ${targetOdId}`);
        return;
    }
    
    const newPeer = new SimplePeer({
        initiator: initiator,
        trickle: true,
        config: {
            iceServers: STUN_SERVERS
        }
    });
    
    peers.set(targetOdId, newPeer);
    
    newPeer.on('signal', (signal) => {
        // Envoyer le signal SDP/ICE via WebSocket vers ce participant spécifique
        ws.send(JSON.stringify({
            type: 'signal',
            signal: signal,
            targetId: targetOdId
        }));
    });
    
    newPeer.on('connect', () => {
        console.log(`🤝 Connexion P2P établie avec ${targetOdId} !`);
        
        // Mettre à jour le statut du chat
        updateChatStatus(true);
        
        // Afficher le chat si le mode l'inclut
        if (sessionMode === 'chat' || sessionMode === 'both') {
            if (isCreator) {
                elements.chatSection.classList.remove('hidden');
            } else {
                elements.receiverChatSection.classList.remove('hidden');
            }
        }
        
        // Afficher la zone fichiers si mode both
        if (sessionMode === 'both') {
            if (isCreator) {
                elements.bothFileSection.classList.remove('hidden');
            } else {
                elements.receiverBothFileSection.classList.remove('hidden');
            }
        }
        
        if (isCreator) {
            // Côté créateur : démarrer le flux d'auth puis transfert (si mode fichier uniquement)
            if (sessionMode === 'file' && peers.size === 1) {
                startTransferFlow();
            }
            // En mode both, pas de transfert automatique - les fichiers sont envoyés via la zone latérale
        } else {
            if (sessionMode === 'chat') {
                elements.receiverStatus.textContent = 'Connecté ! Vous pouvez discuter.';
                document.querySelector('.receiver-info').style.display = 'none';
            } else if (sessionMode === 'both') {
                elements.receiverStatus.textContent = 'Connecté ! Vous pouvez discuter et échanger des fichiers.';
                document.querySelector('.receiver-info').style.display = 'none';
            } else {
                elements.receiverStatus.textContent = 'Connexion établie ! Transfert en cours...';
            }
        }
    });
    
    newPeer.on('data', (data) => {
        handlePeerData(data, targetOdId);
    });
    
    newPeer.on('close', () => {
        console.log(`🔌 Connexion P2P fermée avec ${targetOdId}`);
        peers.delete(targetOdId);
    });
    
    newPeer.on('error', (err) => {
        // Ignorer les erreurs d'annulation volontaire
        if (err.message && (err.message.includes('User-Initiated Abort') || err.message.includes('Close called'))) {
            console.log(`ℹ️ Connexion P2P fermée proprement avec ${targetOdId}`);
            return;
        }
        
        // Si le peer est déjà connecté, ne pas afficher d'erreur
        if (newPeer && newPeer.connected) {
            console.log(`ℹ️ Erreur P2P ignorée (peer ${targetOdId} déjà connecté):`, err.message);
            return;
        }
        
        console.error(`❌ Erreur P2P avec ${targetOdId}:`, err);
    });
}

// Fonction legacy pour compatibilité (utilisée dans quelques endroits)
function initPeer(initiator) {
    // Si on a des participants, se connecter au premier
    if (participants.size > 0) {
        const firstOdId = participants.keys().next().value;
        initPeerWith(firstOdId, initiator);
    }
}

// Obtenir un peer connecté (pour envoyer des messages)
function getConnectedPeer() {
    for (const [odId, p] of peers) {
        if (p.connected) return p;
    }
    return null;
}

// Envoyer des données à tous les peers connectés
async function broadcastToAllPeers(data) {
    const dataStr = typeof data === 'string' ? data : JSON.stringify(data);
    
    for (const [odId, p] of peers.entries()) {
        if (p.connected) {
            try {
                // Si Double Ratchet est initialisé pour ce peer, chiffrer
                if (doubleRatchetState.has(odId)) {
                    const plaintext = new TextEncoder().encode(dataStr);
                    const encrypted = await sendMessageWithDoubleRatchet(odId, plaintext);
                    p.send(JSON.stringify(encrypted));
                    // Message chiffré
                } else {
                    // Fallback: envoi en clair (pour compatibilité temporaire)
                    p.send(dataStr);
                    console.warn('⚠️ Envoi non chiffré vers', odId, '(Double Ratchet non initialisé)');
                }
            } catch (err) {
                console.error(`❌ Erreur envoi vers ${odId}:`, err);
            }
        }
    }
}

// ===== TRANSFERT DE FICHIER =====

function startTransferFlow() {
    if (usePassword) {
        sendAuthChallenge();
    } else {
        startFileTransfer();
    }
}

async function sendAuthChallenge() {
    const peer = getConnectedPeer();
    if (!peer || !cryptoKey) return;
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const challenge = window.crypto.getRandomValues(new Uint8Array(16));

    const cipherBuf = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        cryptoKey,
        challenge
    );

    expectedChallengeB64 = toBase64(challenge);

    const payload = {
        type: 'auth-challenge',
        iv: toBase64(iv),
        cipher: toBase64(new Uint8Array(cipherBuf))
    };

    peer.send(JSON.stringify(payload));
}

async function handleAuthChallenge(data, fromOdId) {
    // Côté destinataire
    const peer = fromOdId ? peers.get(fromOdId) : getConnectedPeer();
    console.log('🔑 handleAuthChallenge appelé, cryptoKey existe?', !!cryptoKey, 'peer existe?', !!peer);
    
    if (!cryptoKey) {
        // Pas encore de mot de passe saisi : on met en attente
        console.log('⏳ Pas de clé, mise en attente');
        pendingChallenge = data;
        return;
    }

    if (!peer) {
        console.error('❌ ERREUR: peer inexistant dans handleAuthChallenge!');
        pendingChallenge = data;
        return;
    }

    try {
        console.log('🔓 Déchiffrement du challenge...');
        const iv = fromBase64(data.iv);
        const cipher = fromBase64(data.cipher);
        const plainBuf = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            cryptoKey,
            cipher
        );

        const plainB64 = toBase64(new Uint8Array(plainBuf));
        console.log('✅ Challenge déchiffré avec succès, envoi de auth-response ok');
        peer.send(JSON.stringify({
            type: 'auth-response',
            ok: true,
            value: plainB64
        }));

        authVerified = true;
        elements.receiverStatus.textContent = 'Mot de passe validé. Connexion sécurisée.';
        
        // Initialiser Double Ratchet côté destinataire (non-initiator)
        if (fromOdId && cryptoKey) {
            try {
                const keyMaterial = await window.crypto.subtle.exportKey('raw', cryptoKey);
                const sharedSecret = new Uint8Array(keyMaterial);
                const dhPublicKey = await initializeDoubleRatchet(fromOdId, sharedSecret, false);
                
                // Envoyer notre clé DH publique
                peer.send(JSON.stringify({
                    type: 'double-ratchet-init',
                    dhPublicKey: dhPublicKey
                }));
                console.log('🔐 Double Ratchet initialisé côté destinataire pour', fromOdId);
            } catch (err) {
                console.error('❌ Erreur init Double Ratchet destinataire:', err);
            }
        }
    } catch (err) {
        console.error('❌ ERREUR déchiffrement - mot de passe incorrect ou données corrompu', err);
        if (peer) peer.send(JSON.stringify({ type: 'auth-response', ok: false, reason: 'bad-password' }));
        showError('Mot de passe incorrect.');
        peers.forEach(p => p.destroy());
        peers.clear();
    }
}

async function handleAuthResponse(data) {
    // Côté expéditeur
    console.log('🔏 handleAuthResponse reçue:', data);
    
    if (!usePassword) {
        console.log('✅ Pas de mot de passe, ignorant auth-response');
        return;
    }

    if (!data.ok) {
        console.error('❌ Mot de passe incorrect côté destinataire');
        showError('Mot de passe incorrect côté destinataire.');
        // Détruire tous les peers
        peers.forEach(p => p.destroy());
        peers.clear();
        return;
    }

    if (expectedChallengeB64 && data.value === expectedChallengeB64) {
        console.log('✅ Mot de passe vérifié! Démarrage du transfert...');
        authVerified = true;
        
        // Initialiser Double Ratchet côté expéditeur (initiator)
        const peer = getConnectedPeer();
        if (peer && peer._id && cryptoKey) {
            try {
                const keyMaterial = await window.crypto.subtle.exportKey('raw', cryptoKey);
                const sharedSecret = new Uint8Array(keyMaterial);
                const dhPublicKey = await initializeDoubleRatchet(peer._id, sharedSecret, true);
                
                // Envoyer notre clé DH publique
                peer.send(JSON.stringify({
                    type: 'double-ratchet-init',
                    dhPublicKey: dhPublicKey
                }));
                console.log('🔐 Double Ratchet initialisé côté expéditeur pour', peer._id);
            } catch (err) {
                console.error('❌ Erreur init Double Ratchet expéditeur:', err);
            }
        }
        
        startFileTransfer();
    } else {
        console.error('❌ Challenge response invalide');
        showError('Vérification décryptée échouée.');
        peers.forEach(p => p.destroy());
        peers.clear();
    }
}

async function handleDoubleRatchetInit(data, fromOdId) {
    if (!fromOdId || !data.dhPublicKey || !cryptoKey) {
        return;
    }
    
    // Si le Double Ratchet n'est pas encore initialisé, bufferiser
    if (!doubleRatchetState.has(fromOdId)) {
        pendingDoubleRatchetInits.set(fromOdId, { dhPublicKey: data.dhPublicKey });
        return;
    }
    
    // Si déjà initialisé, c'est un reload de l'autre côté → réinitialiser
    try {
        // Anti-boucle: ne pas renvoyer si on a déjà répondu récemment (< 5s)
        const lastSent = lastDoubleRatchetInitSent.get(fromOdId) || 0;
        const now = Date.now();
        const shouldReply = (now - lastSent) > 5000;
        
        // Reset complet de notre état
        doubleRatchetState.delete(fromOdId);
        
        // Réinitialiser avec nouvelle clé
        const keyMaterial = await window.crypto.subtle.exportKey('raw', cryptoKey);
        const sharedSecret = new Uint8Array(keyMaterial);
        const amInitiator = isCreator;
        const dhPublicKey = await initializeDoubleRatchet(fromOdId, sharedSecret, amInitiator);
        
        // Compléter avec leur clé
        await completeDoubleRatchetHandshake(fromOdId, data.dhPublicKey);
        
        // Renvoyer notre nouvelle clé UNE SEULE FOIS
        if (shouldReply) {
            ws.send(JSON.stringify({
                type: 'double-ratchet-init',
                to: fromOdId,
                publicKey: Array.from(dhPublicKey)
            }));
            lastDoubleRatchetInitSent.set(fromOdId, now);
        }
        
    } catch (err) {
        console.error('❌ Handshake Double Ratchet:', err.message);
    }
}

async function handleDoubleRatchetMessage(encrypted, fromOdId) {
    if (!fromOdId || !encrypted.data || !encrypted.dhPublicKey) {
        console.error('❌ Message Double Ratchet invalide');
        return;
    }
    
    try {
        // Déchiffrer le message
        const decrypted = await receiveMessageWithDoubleRatchet(
            fromOdId,
            encrypted.data,
            encrypted.dhPublicKey
        );
        
        // Convertir en texte et parser le JSON original
        const decryptedText = new TextDecoder().decode(decrypted);
        const originalData = JSON.parse(decryptedText);
        
        // Message déchiffré
        
        // Dispatcher vers le bon handler selon le type
        switch (originalData.type) {
            case 'chat-message':
                handleChatMessage(originalData, fromOdId);
                break;
            case 'chat-edit':
                handleChatEdit(originalData, fromOdId);
                break;
            case 'chat-delete':
                handleChatDelete(originalData);
                break;
            case 'chat-reaction':
                handleChatReaction(originalData);
                break;
            case 'chat-typing':
                handleTypingSignal(originalData, fromOdId);
                break;
            default:
                console.warn('⚠️ Type de message déchiffré non géré:', originalData.type);
        }
    } catch (err) {
        console.error('❌ Erreur déchiffrement Double Ratchet:', err);
    }
}

async function startFileTransfer() {
    if (usePassword && !authVerified) return;
    const peer = getConnectedPeer();
    if (!peer) {
        showError('Aucun peer connecté pour le transfert.');
        return;
    }
    console.log('📤 Démarrage du transfert...');
    
    elements.senderSection.classList.add('hidden');
    elements.linkSection.classList.add('hidden');
    elements.progressSection.classList.remove('hidden');
    elements.progressTitle.textContent = 'Envoi en cours...';
    
    transferStartTime = Date.now();
    
    // Envoyer les métadonnées du fichier
    const metadata = {
        type: 'metadata',
        name: getSelectedFileName(),
        size: selectedFile.size,
        mimeType: getSelectedFileType('application/octet-stream')
    };
    peer.send(JSON.stringify(metadata));
    
    // Lire et envoyer le fichier par chunks
    const totalChunks = Math.ceil(selectedFile.size / CHUNK_SIZE);
    let sentBytes = 0;
    let chunkIndex = 0;
    
    // Calculer le hash du fichier complet
    const fileBuffer = await selectedFile.arrayBuffer();
    senderFileHash = await calculateHash(fileBuffer);
    
    for (let offset = 0; offset < selectedFile.size; offset += CHUNK_SIZE) {
        const chunk = selectedFile.slice(offset, offset + CHUNK_SIZE);
        const chunkBuffer = await chunk.arrayBuffer();
        const chunkData = new Uint8Array(chunkBuffer);
        
        // Chiffrer le chunk
        const encryptedChunk = await encryptChunk(chunkData);
        
        // Créer le paquet avec métadonnées
        const packet = {
            type: 'chunk',
            index: chunkIndex,
            total: totalChunks,
            data: Array.from(encryptedChunk) // Convertir en tableau pour JSON
        };
        
        // Attendre que le buffer soit vide avant d'envoyer
        while (peer.bufferSize > 1024 * 1024) {
            await new Promise(r => setTimeout(r, 50));
        }
        
        peer.send(JSON.stringify(packet));
        
        sentBytes += chunkData.length;
        chunkIndex++;
        
        updateProgress(sentBytes, selectedFile.size);
    }
    
    // Envoyer le hash final pour vérification
    const finalPacket = {
        type: 'complete',
        hash: senderFileHash
    };
    peer.send(JSON.stringify(finalPacket));
    
    console.log('✅ Tous les chunks envoyés');
}

function handlePeerData(rawData, fromOdId) {
    try {
        const data = JSON.parse(rawData.toString());
        
        // Détecter et déchiffrer les messages Double Ratchet
        if (data.type === 'double-ratchet-message') {
            handleDoubleRatchetMessage(data, fromOdId);
            return;
        }
        
        switch (data.type) {
            case 'chat-message':
                handleChatMessage(data, fromOdId);
                break;
            case 'chat-edit':
                handleChatEdit(data, fromOdId);
                break;
            case 'chat-delete':
                handleChatDelete(data);
                break;
            case 'chat-reaction':
                handleChatReaction(data);
                break;
            case 'chat-pin':
                handleChatPin(data);
                break;
            case 'chat-export-notify':
                handleExportNotify(data);
                break;
            case 'chat-ephemeral-sync':
                handleEphemeralSync(data);
                break;
            case 'chat-typing':
                handleTypingSignal(data, fromOdId);
                break;
            
            // Mode both - fichiers bidirectionnels
            case 'both-file-meta':
                handleBothFileMeta(data);
                break;
            case 'both-file-chunk':
                handleBothFileChunk(data);
                break;
            case 'both-file-complete':
                handleBothFileComplete(data);
                break;
                
            case 'auth-challenge':
                handleAuthChallenge(data, fromOdId);
                break;

            case 'auth-response':
                handleAuthResponse(data);
                break;
            
            case 'double-ratchet-init':
                handleDoubleRatchetInit(data, fromOdId);
                break;

            case 'metadata':
                // Réception des métadonnées du fichier
                fileInfo = {
                    name: data.name,
                    size: data.size,
                    mimeType: data.mimeType
                };
                elements.receiverSection.classList.add('hidden');
                elements.progressSection.classList.remove('hidden');
                elements.progressTitle.textContent = 'Réception en cours...';
                transferStartTime = Date.now();
                break;
                
            case 'chunk':
                receiveChunk(data);
                break;
                
            case 'complete':
                finalizeTransfer(data.hash);
                break;
        }
    } catch (err) {
        console.error('Erreur parsing data:', err);
    }
}

async function receiveChunk(data) {
    const encryptedData = new Uint8Array(data.data);
    
    try {
        const decryptedChunk = await decryptChunk(encryptedData);
        receivedChunks[data.index] = decryptedChunk;
        totalReceived += decryptedChunk.length;
        
        updateProgress(totalReceived, fileInfo.size);
    } catch (err) {
        console.error('Erreur déchiffrement chunk:', err);
        showError('Erreur de déchiffrement. Clé invalide ?');
    }
}

async function finalizeTransfer(expectedHash) {
    console.log('🔧 Reconstruction du fichier...');
    
    // Fusionner tous les chunks
    const totalLength = receivedChunks.reduce((acc, chunk) => acc + chunk.length, 0);
    const fileData = new Uint8Array(totalLength);
    let offset = 0;
    
    for (const chunk of receivedChunks) {
        fileData.set(chunk, offset);
        offset += chunk.length;
    }
    
    // Vérifier l'intégrité
    const calculatedHash = await calculateHash(fileData);
    const integrityOk = calculatedHash === expectedHash;
    
    if (!integrityOk) {
        console.warn('⚠️ Hash différent - fichier potentiellement corrompu');
        elements.integrityCheck.innerHTML = '<span class="integrity-icon">⚠️</span><span>Attention : intégrité non vérifiée</span>';
        elements.integrityCheck.style.background = 'rgba(245, 158, 11, 0.1)';
        elements.integrityCheck.style.color = 'var(--warning)';
    }
    
    // Créer le Blob et déclencher le téléchargement
    const blob = new Blob([fileData], { type: fileInfo.mimeType || 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = fileInfo.name;
    a.click();
    
    URL.revokeObjectURL(url);
    
    // Afficher la section terminée
    hideAllSections();
    elements.completeSection.classList.remove('hidden');
    elements.completeMessage.textContent = `${fileInfo.name} (${formatFileSize(fileInfo.size)}) téléchargé avec succès !`;
    
    // Nettoyer
    receivedChunks = [];
    totalReceived = 0;
    
    // Détruire tous les peers
    peers.forEach(p => p.destroy());
    peers.clear();
    
    // Effacer la session sauvegardée (transfert terminé)
    clearSessionStorage();
    
    console.log('✅ Transfert terminé !');
}

function updateProgress(current, total) {
    const percent = Math.min(100, Math.round((current / total) * 100));
    elements.progressFill.style.width = percent + '%';
    elements.progressPercent.textContent = percent + '%';
    elements.progressTransferred.textContent = `${formatFileSize(current)} / ${formatFileSize(total)}`;
    
    // Calculer la vitesse
    if (transferStartTime) {
        const elapsed = (Date.now() - transferStartTime) / 1000;
        if (elapsed > 0) {
            const speed = current / elapsed;
            elements.progressSpeed.textContent = formatFileSize(speed) + '/s';
        }
    }
    
    // Transfert terminé côté expéditeur
    if (percent >= 100 && !isReceiver) {
        setTimeout(() => {
            hideAllSections();
            elements.completeSection.classList.remove('hidden');
            elements.completeMessage.textContent = `${getSelectedFileName()} envoyé avec succès !`;
        }, 500);
    }
}

// ===== GÉNÉRATION DU LIEN =====

async function generateShareLink() {
    let link;
    const mode = sessionMode || 'file';
    
    if (usePassword) {
        // Lien avec mot de passe : roomId_mode_pwd_salt_iterations
        link = `${window.location.origin}${window.location.pathname}#${roomId}_${mode}_pwd_${passwordSaltB64}_${passwordIterations}`;
    } else {
        // Lien ECDH (sans clé dans l'URL) : roomId_mode_ecdh
        link = `${window.location.origin}${window.location.pathname}#${roomId}_${mode}_ecdh`;
    }
    
    elements.shareLink.value = link;
    elements.linkSection.classList.remove('hidden');
    
    // Afficher le badge "Session éphémère" dans le header
    showEphemeralBadge();
    
    // Génération du QR Code
    const qrcodeContainer = document.getElementById('qrcode-container');
    const qrcodeDiv = document.getElementById('qrcode');
    if (qrcodeContainer && qrcodeDiv && window.QRCode) {
        qrcodeDiv.innerHTML = ''; // Effacer le précédent
        new QRCode(qrcodeDiv, {
            text: link,
            width: 160,
            height: 160,
            colorDark : "#000000",
            colorLight : "#ffffff",
            correctLevel : QRCode.CorrectLevel.M
        });
        qrcodeContainer.classList.remove('hidden');
    }
    
    console.log('🔗 Lien de partage généré (mode:', mode, ', ECDH)');
}

// ===== GESTION DES FICHIERS =====

// Multi-fichiers: crée automatiquement une archive ZIP côté navigateur
async function handleMultiFileSelect(files) {
    if (!files || files.length === 0) return;
    try {
        console.log('📁 Sélection multiple:', files.map(f => f.name));
        // Indication UI le temps de la préparation
        elements.fileInfoDiv.classList.remove('hidden');
        elements.dropZone.classList.add('hidden');
        elements.passwordBlock.classList.remove('hidden');
        elements.fileName.textContent = 'Préparation de l\'archive...';
        elements.fileSize.textContent = '';

        // Créer le zip
        if (!window.JSZip) {
            throw new Error('JSZip indisponible');
        }
        const zip = new JSZip();
        for (const file of files) {
            const buffer = await file.arrayBuffer();
            zip.file(file.name, buffer);
        }
        const blob = await zip.generateAsync({ type: 'blob', compression: 'DEFLATE', compressionOptions: { level: 6 } });
        const archiveName = `SecurePeer-archive-${new Date().toISOString().slice(0,10)}.zip`;
        try {
            selectedFile = new File([blob], archiveName, { type: 'application/zip' });
            selectedFileNameOverride = null;
        } catch (e) {
            selectedFile = blob; // Fallback
            selectedFileNameOverride = archiveName;
        }

        // Afficher les infos d'archive
        elements.fileName.textContent = `${archiveName} (${files.length} fichiers)`;
        elements.fileSize.textContent = formatFileSize(selectedFile.size);

        // Réinitialiser l'état d'auth
        usePassword = false;
        passwordSaltB64 = null;
        authVerified = false;
        pendingChallenge = null;
        expectedChallengeB64 = null;
        
        // Mémoriser la liste pour le destinataire
        fileInfo = {
            name: archiveName,
            size: selectedFile.size,
            type: 'application/zip',
            passwordRequired: false,
            isArchive: true,
            files: files.map(f => ({ name: f.name, size: f.size }))
        };
    } catch (err) {
        console.error('❌ Erreur multi-fichiers:', err);
        showError('Erreur lors de la préparation de l\'archive: ' + err.message);
        elements.fileInput.value = '';
    }
}

function getSelectedFileName() {
    return (selectedFile && selectedFile.name) || selectedFileNameOverride || 'archive.zip';
}

function getSelectedFileType(fallback) {
    return (selectedFile && selectedFile.type) || fallback;
}

async function handleFileSelect(file) {
    if (!file) return;
    
    try {
        console.log('📁 Fichier sélectionné:', file.name);
        
        selectedFile = file;
        
        // Afficher les infos du fichier
        elements.fileName.textContent = file.name;
        elements.fileSize.textContent = formatFileSize(file.size);
        elements.fileInfoDiv.classList.remove('hidden');
        elements.dropZone.classList.add('hidden');
        elements.passwordBlock.classList.remove('hidden');
        
        // Réinitialiser l'état d'auth
        usePassword = false;
        passwordSaltB64 = null;
        authVerified = false;
        pendingChallenge = null;
        expectedChallengeB64 = null;
    } catch (err) {
        console.error('❌ Erreur dans handleFileSelect:', err);
        showError('Erreur lors de la sélection du fichier: ' + err.message);
        elements.fileInput.value = '';
    }
}

// Lance réellement l'envoi : dérive la clé, construit fileInfo, crée la room
async function startSend() {
    // En mode chat uniquement ou mode both, pas besoin de fichier
    if (sessionMode === 'file' && !selectedFile) {
        showToast('Sélectionnez un fichier d\'abord');
        return;
    }
    try {
        // Choisir la stratégie de clé : mot de passe ou ECDH (échange de clés)
        const passwordValue = elements.passwordInput.value.trim();
        usePassword = passwordValue.length > 0;
        passwordSaltB64 = usePassword ? generatePasswordSalt() : null;
        passwordIterations = KDF_ITERATIONS;

        if (usePassword) {
            console.log('🔐 Mot de passe détecté, dérivation en cours...');
            cryptoKey = await deriveKeyFromPassword(passwordValue, passwordSaltB64, passwordIterations);
        } else {
            // Mode ECDH : générer une paire de clés, la clé AES sera dérivée après échange
            console.log('🔑 Génération paire ECDH (Diffie-Hellman)...');
            await generateECDHKeyPair();
            // cryptoKey sera null jusqu'à ce qu'un receiver rejoigne et qu'on dérive la clé partagée
        }

        // Pour le mode chat uniquement ou both, pas besoin de fileInfo de fichier réel
        if (sessionMode === 'chat' || sessionMode === 'both') {
            fileInfo = {
                name: sessionMode === 'chat' ? 'Chat Session' : 'Chat + Files Session',
                size: 0,
                type: 'text/plain',
                passwordRequired: usePassword,
                chatOnly: sessionMode === 'chat',
                bothMode: sessionMode === 'both'
            };
            if (usePassword) {
                fileInfo.passwordSalt = passwordSaltB64;
                fileInfo.passwordIterations = passwordIterations;
            }
        } else if (selectedFile) {
            // Mode fichier : Préparer les infos du fichier AVEC paramètres de mot de passe si applicable
            const baseInfo = {
                name: getSelectedFileName(),
                size: selectedFile.size,
                type: getSelectedFileType('application/octet-stream'),
                passwordRequired: usePassword
            };
            // Conserver les métadonnées d'archive si déjà définies par handleMultiFileSelect
            if (fileInfo && fileInfo.isArchive && Array.isArray(fileInfo.files)) {
                fileInfo = { ...baseInfo, isArchive: true, files: fileInfo.files };
            } else {
                fileInfo = baseInfo;
            }

            if (usePassword) {
                fileInfo.passwordSalt = passwordSaltB64;
                fileInfo.passwordIterations = passwordIterations;
                console.log('📋 FileInfo avec mot de passe:', fileInfo);
            } else {
                console.log('📋 FileInfo sans mot de passe:', fileInfo);
            }
        }
        
        // Ajouter le mode de session aux infos
        fileInfo.sessionMode = sessionMode;

        // Se connecter au serveur WebSocket et créer la room
        connectWebSocket();
    } catch (err) {
        console.error('❌ Erreur dans startSend:', err);
        showError('Erreur lors de la préparation de l\'envoi: ' + err.message);
    }
}

function clearFileSelection() {
    selectedFile = null;
    selectedFileNameOverride = null;
    cryptoKey = null;
    cryptoIV = null;
    usePassword = false;
    passwordSaltB64 = null;
    expectedChallengeB64 = null;
    authVerified = false;
    
    elements.fileInfoDiv.classList.add('hidden');
    elements.linkSection.classList.add('hidden');
    elements.dropZone.classList.remove('hidden');
    elements.fileInput.value = '';
    elements.passwordInput.value = '';
    elements.passwordBlock.classList.add('hidden');
    
    if (ws) {
        ws.close();
        ws = null;
    }
}

async function applyReceiverPassword() {
    if (!passwordSaltB64) {
        showError('Lien invalide : salt manquant.');
        return;
    }
    const pwd = elements.receiverPassword.value.trim();
    if (!pwd) {
        showToast('Entrez un mot de passe.');
        return;
    }
    try {
        console.log('🔐 Dérivation du mot de passe reçu...');
        cryptoKey = await deriveKeyFromPassword(pwd, passwordSaltB64, passwordIterations);
        console.log('✅ Clé dérivée avec succès');
        elements.receiverPasswordBlock.classList.add('hidden');
        
        // Pour le mode chat ou both, démarrer directement P2P
        if (sessionMode === 'chat' || sessionMode === 'both') {
            console.log('🚀 Mode chat/both : démarrage P2P automatique...');
            
            // Masquer toute la section receiver (y compris boutons, infos fichier, etc.)
            const receiverInfo = document.querySelector('.receiver-info');
            if (receiverInfo) {
                receiverInfo.style.display = 'none';
            }
            
            // Afficher le chat
            if (sessionMode === 'chat') {
                elements.receiverChatSection.classList.remove('hidden');
            } else if (sessionMode === 'both') {
                elements.receiverChatSection.classList.remove('hidden');
                elements.receiverBothFileSection.classList.remove('hidden');
            }
            
            // Sauvegarder la session
            saveSessionToStorage();
            
            // Notifier l'expéditeur que le destinataire est prêt
            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ type: 'receiver-ready' }));
            }
            
            // Démarrer le peer (non-initiateur)
            if (!peer) {
                initPeer(false);
            }
            
            // Traiter le challenge en attente si applicable
            if (pendingChallenge) {
                console.log('📬 Traitement du challenge en attente...');
                const challenge = pendingChallenge;
                pendingChallenge = null;
                await handleAuthChallenge(challenge);
            }
        } else {
            // Mode fichier : afficher le bouton "Recevoir le fichier"
            elements.receiverStatus.textContent = 'Mot de passe validé. Cliquez sur le bouton pour recevoir le fichier.';
            if (elements.receiveFileBtn) {
                elements.receiveFileBtn.classList.remove('hidden');
            }
        }
        
        receiverReady = true;
    } catch (err) {
        console.error('❌ Erreur dérivation mot de passe:', err);
        showError('Erreur : ' + err.message);
        elements.receiverPasswordBlock.classList.remove('hidden');
    }
}

// Fonction appelée quand l'utilisateur clique sur "Recevoir le fichier"
async function startReceiving() {
    if (!receiverReady || !cryptoKey) {
        showToast('Veuillez d\'abord entrer le mot de passe.');
        return;
    }
    
    elements.receiveFileBtn.classList.add('hidden');
    elements.receiverStatus.textContent = 'Connexion P2P en cours...';
    
    // Démarrer le peer
    console.log('🚀 Initialisation du peer...');
    if (!peer) {
        initPeer(false); // Receiver = non-initiateur
    }
    
    // Notifier l'expéditeur que le destinataire est prêt
    console.log('📤 Envoi de receiver-ready à l\'expéditeur...');
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'receiver-ready' }));
    }

    // Puis traiter le challenge en attente
    if (pendingChallenge) {
        console.log('📬 Traitement du challenge en attente...');
        const challenge = pendingChallenge;
        pendingChallenge = null;
        await handleAuthChallenge(challenge);
    }
}

// ===== GESTION DES PSEUDOS =====

function updateConnectedUsersDropdown() {
    // Sélectionner le bon dropdown selon si on est receiver ou creator
    const dropdownEl = isReceiver ? elements.receiverConnectedUsersDropdown : elements.connectedUsersDropdown;
    const sectionEl = isReceiver ? elements.receiverConnectedUsersSection : elements.connectedUsersSection;
    
    console.log(`🔄 updateConnectedUsersDropdown: isReceiver=${isReceiver}, participants.size=${participants.size}`);
    
    if (!dropdownEl) {
        console.log('⚠️ Dropdown non trouvé');
        return;
    }
    
    // Effacer les options existantes
    dropdownEl.innerHTML = '';
    
    // Ajouter l'utilisateur actuel
    const optionMe = document.createElement('option');
    optionMe.textContent = `${userPseudo} (vous)` + (isCreator ? ' 👑' : '');
    optionMe.disabled = true;
    dropdownEl.appendChild(optionMe);
    
    // Ajouter tous les participants (en évitant les doublons par pseudo)
    const addedPseudos = new Set([userPseudo]);
    participants.forEach((info, odId) => {
        // Éviter les doublons (même pseudo)
        if (!addedPseudos.has(info.pseudo)) {
            addedPseudos.add(info.pseudo);
            const optionOther = document.createElement('option');
            optionOther.textContent = info.pseudo + (info.isCreator ? ' 👑' : '');
            optionOther.disabled = true;
            dropdownEl.appendChild(optionOther);
        }
    });
    
    // Toujours montrer la section dès qu'il y a au moins 1 autre participant
    if (sectionEl) {
        if (participants.size > 0) {
            sectionEl.classList.remove('hidden');
            console.log('✅ Section dropdown visible');
        } else {
            sectionEl.classList.add('hidden');
        }
    }
}

// ===== SAUVEGARDE ET RESTAURATION DE SESSION =====

async function saveSessionToStorage() {
    try {
        // Exporter la clé crypto si elle existe (pour pouvoir la restaurer)
        let cryptoKeyB64 = null;
        if (cryptoKey) {
            try {
                cryptoKeyB64 = await exportKeyToBase64();
            } catch (e) {
                console.warn('⚠️ Impossible d\'exporter la clé crypto:', e);
            }
        }
        
        // Exporter la paire ECDH si elle existe
        let ecdhExported = null;
        if (ecdhKeyPair) {
            try {
                ecdhExported = await exportECDHKeyPair();
            } catch (e) {
                console.warn('⚠️ Impossible d\'exporter la paire ECDH:', e);
            }
        }
        
        const session = {
            roomId: roomId,
            sessionMode: sessionMode,
            isReceiver: isReceiver,
            usePassword: usePassword,
            passwordSaltB64: passwordSaltB64,
            passwordIterations: passwordIterations,
            hash: window.location.hash.substring(1),
            // Persist pseudo and odId so creator can be restored exactly
            pseudo: userPseudo || localStorage.getItem('securepeer_pseudo') || null,
            odId: myOdId || localStorage.getItem('securepeer_odid') || null,
            isCreator: isCreator || false,
            // include minimal fileInfo to restore UI/state if available
            fileInfo: fileInfo || null,
            // Stocker la clé crypto pour restauration
            cryptoKeyB64: cryptoKeyB64,
            // Stocker la paire ECDH pour restauration
            ecdhKeyPair: ecdhExported,
            timestamp: Date.now()
        };
        localStorage.setItem('securepeer_session', JSON.stringify(session));
        console.log('💾 Session sauvegardée (avec clé crypto et ECDH)');
    } catch (err) {
        console.error('❌ Erreur sauvegarde session:', err);
    }
}

function restoreSessionFromStorage() {
    try {
        const sessionData = localStorage.getItem('securepeer_session');
        if (!sessionData) return null;
        
        const session = JSON.parse(sessionData);
        
        // Vérifier que la session n'est pas trop vieille (24h max)
        const age = Date.now() - session.timestamp;
        if (age > 24 * 60 * 60 * 1000) {
            console.log('⏰ Session expirée');
            clearSessionStorage();
            return null;
        }
        
        console.log('📂 Session restaurée:', session);
        return session;
    } catch (err) {
        console.error('❌ Erreur restauration session:', err);
        return null;
    }
}

function clearSessionStorage() {
    localStorage.removeItem('securepeer_session');
    console.log('🗑️ Session effacée');
}

function closeSessionProperly() {
    // Notifier le serveur de la fermeture
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'close-room' }));
    }
    
    // Nettoyer localement
    clearSessionStorage();
    
    // Fermer les connexions P2P
    peers.forEach(p => p.destroy());
    peers.clear();
    
    // Fermer le WebSocket
    if (ws) ws.close();
    
    // Rediriger vers l'accueil
    window.location.href = window.location.origin + window.location.pathname;
}

function setupCloseSessionButtons() {
    // Boutons pour fermer la session (attachés une seule fois)
    if (elements.closeSession && !elements.closeSession._hasCloseListener) {
        elements.closeSession.addEventListener('click', () => {
            if (confirm('Voulez-vous vraiment fermer cette session ?')) {
                closeSessionProperly();
            }
        });
        elements.closeSession._hasCloseListener = true;
    }
    
    if (elements.closeChatSession && !elements.closeChatSession._hasCloseListener) {
        elements.closeChatSession.addEventListener('click', () => {
            if (confirm('Voulez-vous vraiment fermer cette session ?')) {
                closeSessionProperly();
            }
        });
        elements.closeChatSession._hasCloseListener = true;
    }
    
    if (elements.closeReceiverSession && !elements.closeReceiverSession._hasCloseListener) {
        elements.closeReceiverSession.addEventListener('click', () => {
            if (confirm('Voulez-vous vraiment fermer cette session ?')) {
                closeSessionProperly();
            }
        });
        elements.closeReceiverSession._hasCloseListener = true;
    }
    
    // Bouton de verrouillage de session (créateur uniquement)
    if (elements.lockSessionBtn && !elements.lockSessionBtn._hasLockListener) {
        elements.lockSessionBtn.addEventListener('click', () => {
            toggleSessionLock();
        });
        elements.lockSessionBtn._hasLockListener = true;
    }
    
    console.log('🚪 Event listeners de fermeture de session attachés');
}

function handleHashConnection(hash) {
    // Mode destinataire - cacher la sélection de mode
    elements.modeSelection.classList.add('hidden');
    
    const parts = hash.split('_');
    roomId = parts[0];
    
    // Extraire le mode de session depuis le lien
    // Format: roomId_mode_...reste
    const modeFromLink = parts[1];
    let keyOrPasswordIndex = 2; // Index où commence la clé ou 'pwd' ou 'ecdh'
    
    if (['file', 'chat', 'both'].includes(modeFromLink)) {
        sessionMode = modeFromLink;
    } else {
        sessionMode = 'file'; // Par défaut pour les anciens liens
        keyOrPasswordIndex = 1; // Pas de mode explicite, la clé/pwd commence à l'index 1
    }

    // Cas lien protégé par mot de passe : roomId_mode_pwd_salt_iterations
    if (parts[keyOrPasswordIndex] === 'pwd') {
        isReceiver = true;
        usePassword = true;
        passwordRequired = true;
        passwordSaltB64 = parts[keyOrPasswordIndex + 1];
        passwordIterations = parts[keyOrPasswordIndex + 2] ? parseInt(parts[keyOrPasswordIndex + 2], 10) : KDF_ITERATIONS;

        elements.receiverSection.classList.remove('hidden');
        elements.receiverPasswordBlock.classList.remove('hidden');
        elements.receiverStatus.textContent = 'Mot de passe requis pour déchiffrer.';
        showEphemeralBadge();
        
        // Afficher le chat si le mode l'inclut
        if (sessionMode === 'chat' || sessionMode === 'both') {
            elements.receiverChatSection.classList.remove('hidden');
        }
        // Adapter l'interface selon le mode
        if (sessionMode === 'chat') {
            document.getElementById('incoming-file-info').classList.add('hidden');
            elements.receiverTitle.textContent = '💬 Chat P2P sécurisé';
            elements.receiverStatus.textContent = 'Connexion au chat...';
        } else if (sessionMode === 'both') {
            elements.receiverBothFileSection.classList.remove('hidden');
            elements.receiverTitle.textContent = '💬 Chat + Fichiers';
            document.getElementById('incoming-file-info').classList.add('hidden');
        }

        connectWebSocket();
    }
    // Cas ECDH (échange de clés Diffie-Hellman) : roomId_mode_ecdh
    else if (parts[keyOrPasswordIndex] === 'ecdh') {
        isReceiver = true;
        usePassword = false;
        
        elements.receiverSection.classList.remove('hidden');
        elements.receiverStatus.textContent = 'Échange de clés sécurisé en cours...';
        showEphemeralBadge();
        
        // Afficher le chat si le mode l'inclut
        if (sessionMode === 'chat' || sessionMode === 'both') {
            elements.receiverChatSection.classList.remove('hidden');
        }
        // Adapter l'interface selon le mode
        if (sessionMode === 'chat') {
            document.getElementById('incoming-file-info').classList.add('hidden');
            elements.receiverTitle.textContent = '💬 Chat P2P sécurisé';
        } else if (sessionMode === 'both') {
            elements.receiverBothFileSection.classList.remove('hidden');
            elements.receiverTitle.textContent = '💬 Chat + Fichiers';
            document.getElementById('incoming-file-info').classList.add('hidden');
        }

        // Générer notre paire ECDH puis connecter
        generateECDHKeyPair().then(() => {
            connectWebSocket();
        }).catch(err => {
            console.error('❌ Erreur génération ECDH:', err);
            showError('Erreur lors de la génération des clés sécurisées.');
        });
    } else {
        // Lien legacy avec clé incluse (pour rétrocompatibilité)
        const keyString = parts.slice(keyOrPasswordIndex).join('_');
        isReceiver = true;

        elements.receiverSection.classList.remove('hidden');
        showEphemeralBadge();
        
        // Afficher le chat si le mode l'inclut
        if (sessionMode === 'chat' || sessionMode === 'both') {
            elements.receiverChatSection.classList.remove('hidden');
        }
        // Adapter l'interface selon le mode
        if (sessionMode === 'chat') {
            document.getElementById('incoming-file-info').classList.add('hidden');
            elements.receiverTitle.textContent = '💬 Chat P2P sécurisé';
            elements.receiverStatus.textContent = 'Connexion au chat...';
        } else if (sessionMode === 'both') {
            elements.receiverBothFileSection.classList.remove('hidden');
            elements.receiverTitle.textContent = '💬 Chat + Fichiers';
            document.getElementById('incoming-file-info').classList.add('hidden');
        }

        importKeyFromBase64(keyString).then(() => {
            connectWebSocket();
        }).catch(err => {
            showError('Lien invalide : impossible de décoder la clé de chiffrement.');
        });
    }
}

// ===== INITIALISATION =====

function init() {
    // Vérifier la présence de la Web Crypto API
    if (!window.crypto || !window.crypto.subtle) {
        showError('La Web Crypto API n\'est pas disponible dans ce navigateur. Utilisez Chrome, Firefox, Edge ou Safari récent.');
        return;
    }
    
    // Vérifier si on est en mode destinataire (URL avec hash = lien de partage)
    const hash = window.location.hash.substring(1);
    
    if (hash && hash.includes('_')) {
        // Lien de partage détecté - cacher la landing, demander pseudo puis connecter
        elements.landingPage.classList.add('hidden');
        showPseudoThenConnect(hash);
    } else {
        // Afficher la landing page par défaut
        elements.landingPage.classList.remove('hidden');
        elements.pseudoSection.classList.add('hidden');
        elements.modeSelection.classList.add('hidden');
        
        // Setup du bouton "Commencer"
        setupLandingPage();
    }
}

// Setup de la landing page
function setupLandingPage() {
    console.log('🚀 setupLandingPage called, startSessionBtn:', elements.startSessionBtn);
    if (elements.startSessionBtn) {
        elements.startSessionBtn.addEventListener('click', () => {
            elements.startSessionBtn.disabled = true; // Empêche le double clic
            console.log('✅ Bouton Commencer cliqué!');
            // Cacher la landing, montrer la sélection de mode directement
            elements.landingPage.classList.add('hidden');
            elements.modeSelection.classList.remove('hidden');
            // Setup des cartes de sélection de mode
            setupModeSelection();
        });
    } else {
        console.error('❌ startSessionBtn non trouvé!');
    }
}

// Demander le pseudo puis connecter (pour receivers)
function showPseudoThenConnect(hash) {
    // Toujours demander le pseudo, ignorer le pseudo sauvegardé
    elements.pseudoSection.classList.remove('hidden');
    elements.pseudoInputMain.value = '';
    elements.pseudoInputMain?.focus();
    elements.pseudoConfirmBtn.onclick = () => {
        const pseudoValue = elements.pseudoInputMain.value.trim();
        if (!pseudoValue || pseudoValue.length < 3) {
            showToast('⚠️ Le pseudo doit faire au moins 3 caractères');
            return;
        }
        if (pseudoValue.length > 20) {
            showToast('⚠️ Le pseudo doit faire maximum 20 caractères');
            return;
        }
        // Sauvegarder le pseudo uniquement pour la session
        userPseudo = pseudoValue;
        localStorage.setItem('securepeer_pseudo', pseudoValue);
        console.log('✅ Pseudo défini:', userPseudo);
        // Cacher la section pseudo et connecter
        elements.pseudoSection.classList.add('hidden');
        handleHashConnection(hash);
        setupChat();
        setupBothModeFiles();
    };
}

// Afficher l'interface créateur selon le mode
function showCreatorInterface(mode) {
    // Setup du chat et des fichiers
    setupChat();
    setupBothModeFiles();
    setupEventListeners();
    
    // Récupérer les éléments de header
    const header = document.querySelector('#sender-section .sender-header h2');
    const desc = document.querySelector('#sender-section .section-desc');
    
    // Afficher la section appropriée
    if (mode === 'chat') {
        elements.senderSection.classList.remove('hidden');
        elements.dropZone.classList.add('hidden');
        elements.passwordBlock.classList.remove('hidden');
        elements.sendFileBtn.textContent = '💬 Démarrer le chat';
        if (header) header.textContent = '💬 Chat sécurisé';
        if (desc) desc.textContent = 'Démarrez une conversation chiffrée de bout en bout';
    } else if (mode === 'file') {
        elements.senderSection.classList.remove('hidden');
        elements.dropZone.classList.remove('hidden');
        if (header) header.textContent = '📤 Envoyer un fichier';
        if (desc) desc.textContent = 'Choisissez un fichier et partagez le lien sécurisé';
    } else {
        // mode 'both'
        elements.senderSection.classList.remove('hidden');
        elements.dropZone.classList.add('hidden');
        elements.passwordBlock.classList.remove('hidden');
        elements.sendFileBtn.textContent = '🚀 Démarrer la session';
        if (header) header.textContent = '💬 Chat + Fichiers';
        if (desc) desc.textContent = 'Discutez et échangez des fichiers en temps réel';
    }
    console.log('📋 Interface créateur affichée pour mode:', mode);
}

function continueInit() {
    // Cacher la section pseudo
    elements.pseudoSection.classList.add('hidden');
    
    // Mode expéditeur - afficher la sélection de mode
    isReceiver = false;
    elements.modeSelection.classList.remove('hidden');
    elements.senderSection.classList.add('hidden');
    
    // Setup des cartes de sélection de mode
    setupModeSelection();
    
    // Setup du chat
    setupChat();
    
    // Setup du mode both (fichiers bidirectionnels)
    setupBothModeFiles();
    
    // Setup des event listeners
    setupEventListeners();
}

function setupEventListeners() {
    // Event listeners - Drag & Drop
    elements.dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        elements.dropZone.classList.add('drag-over');
    });
    
    elements.dropZone.addEventListener('dragleave', () => {
        elements.dropZone.classList.remove('drag-over');
    });
    
    elements.dropZone.addEventListener('drop', async (e) => {
        e.preventDefault();
        elements.dropZone.classList.remove('drag-over');
        const files = Array.from(e.dataTransfer.files || []);
        if (files.length === 0) return;
        if (files.length === 1) {
            handleFileSelect(files[0]);
        } else {
            await handleMultiFileSelect(files);
        }
    });
    
    // Event listeners - Input file
    elements.fileInput.addEventListener('click', () => { elements.fileInput.value = ''; });
    elements.fileInput.addEventListener('change', async (e) => {
        try {
            const files = Array.from(e.target.files || []);
            if (files.length === 0) return;
            if (files.length === 1) {
                handleFileSelect(files[0]);
            } else {
                await handleMultiFileSelect(files);
            }
        } catch (err) {
            console.error('❌ Erreur dans file input change event:', err);
            showError('Erreur lors de la sélection du fichier');
        } finally {
            elements.fileInput.value = '';
        }
    });
    
    // Event listeners - Boutons
    elements.clearFile.addEventListener('click', clearFileSelection);
    elements.sendFileBtn.addEventListener('click', () => {
        startSend();
    });
    
    
    elements.copyLink.addEventListener('click', () => {
        elements.shareLink.select();
        navigator.clipboard.writeText(elements.shareLink.value);
        showToast('Lien copié !');
    });
    
    elements.newTransfer.addEventListener('click', () => {
        clearSessionStorage();
        location.reload();
    });
    
    elements.retryTransfer.addEventListener('click', () => {
        // Effacer la session pour éviter de recharger une session invalide
        clearSessionStorage();
        window.location.href = window.location.origin + window.location.pathname;
    });
    
    // Clic sur la zone de drop
    elements.dropZone.addEventListener('click', () => {
        elements.fileInput.click();
    });

    if (elements.receiverPasswordApply) {
        elements.receiverPasswordApply.addEventListener('click', applyReceiverPassword);
    }
    if (elements.receiverPassword) {
        elements.receiverPassword.addEventListener('keyup', (e) => {
            if (e.key === 'Enter') {
                applyReceiverPassword();
            }
        });
    }
    
    // Bouton "Recevoir le fichier"
    if (elements.receiveFileBtn) {
        elements.receiveFileBtn.addEventListener('click', startReceiving);
    }
    
    // Sélecteur de langue: initialisé une seule fois via DOMContentLoaded
    // (évite les doubles écouteurs qui togglent deux fois et referment le menu)
}

function setupLanguageSelector() {
    const languageToggle = document.getElementById('language-toggle');
    const languageMenu = document.getElementById('language-menu');
    
    if (!languageToggle || !languageMenu) {
        console.log('Language elements not found');
        return;
    }
    
    languageToggle.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        const isHidden = languageMenu.classList.contains('hidden');
        languageMenu.classList.toggle('hidden');
        console.log('Menu toggled:', !isHidden);
    });
    
    // Fermer le menu au clic ailleurs
    document.addEventListener('click', (e) => {
        if (languageMenu && !e.target.closest('.language-selector')) {
            languageMenu.classList.add('hidden');
        }
    });
    
    // Sélection de langue
    document.querySelectorAll('.lang-option').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            setLanguage(btn.dataset.lang);
            languageMenu.classList.add('hidden');
            console.log('Language set to:', btn.dataset.lang);
        });
    });
}

// ===== GESTION DES LANGUES =====
let currentLanguage = localStorage.getItem('language') || 'fr';

function setLanguage(lang) {
    currentLanguage = lang;
    localStorage.setItem('language', currentLanguage);
    updateLanguage();
}

function updateLanguage() {
    const languageToggle = document.getElementById('language-toggle');
    const langNames = {
        fr: '🇫🇷 FR',
        en: '🇬🇧 EN',
        es: '🇪🇸 ES',
        it: '🇮🇹 IT',
        ru: '🇷🇺 RU'
    };
    
    if (languageToggle) {
        languageToggle.textContent = langNames[currentLanguage] || langNames.fr;
    }
    
    // Mettre à jour l'option active
    document.querySelectorAll('.lang-option').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.lang === currentLanguage);
    });
    
    // Mettre à jour les textes de la page
    const translations = {
        fr: {
            title: '🔒 SecurePeer',
            subtitle: 'Transfert de fichiers chiffré de bout en bout, sans serveur intermédiaire',
            modeTitle: '🚀 Créer une session',
            modeDesc: 'Choisissez le type de session que vous souhaitez démarrer',
            modeFile: 'Transfert de fichiers',
            modeFileDesc: 'Envoyez des fichiers de manière sécurisée',
            modeChat: 'Chat sécurisé',
            modeChatDesc: 'Discutez en temps réel, chiffré E2E',
            modeBoth: 'Fichiers + Chat',
            modeBothDesc: 'Transférez et discutez simultanément',
            senderHeader: '📤 Envoyer un fichier',
            sectionDesc: 'Choisissez un fichier et partagez le lien sécurisé',
            dropZone: 'Glissez-déposez un fichier ici',
            or: 'ou cliquez pour sélectionner',
            chooseFile: 'Choisir un fichier',
            deleteFile: '✕ Supprimer',
            password: '🔐 Protection par mot de passe (optionnel)',
            passwordPlaceholder: 'Entrez un mot de passe pour plus de sécurité',
            sendBtn: '📤 Envoyer le fichier',
            startChatBtn: '💬 Démarrer le chat',
            passwordHint: 'Le mot de passe ne quitte jamais votre appareil',
            shareTitle: '🔗 Lien de partage généré',
            linkInfo: 'Partagez ce lien avec le destinataire',
            copyBtn: '📋 Copier',
            waiting: '📍 En attente du destinataire...',
            chatTitle: '💬 Chat sécurisé',
            chatPlaceholder: 'Tapez votre message...',
            chatSend: 'Envoyer',
            chatWaiting: 'En attente...',
            chatConnected: 'Connecté',
            chatP2PTitle: '💬 Chat P2P sécurisé',
            chatFilesTitle: '💬 Chat + Fichiers',
            filesTitle: '📁 Fichiers',
            addFile: '📎 Ajouter',
            sendFiles: '📤 Envoyer',
            pending: 'En attente',
            receiving: 'Réception...',
            sent: 'Envoyé',
            download: '📥 Télécharger',
            receiverTitle: '📥 Réception de fichier',
            receiverPassword: 'Mot de passe requis',
            receiverPasswordPlaceholder: 'Entrez le mot de passe partagé',
            unlockBtn: 'Déverrouiller',
            passwordHintReceiver: 'Le mot de passe reste sur cet appareil et dérive la clé de chiffrement.',
            receiveBtn: '📥 Recevoir le fichier',
            connecting: 'Connexion en cours...',
            transferProgress: 'Transfert en cours...',
            complete: 'Transfert terminé !',
            integrity: 'Intégrité vérifiée (SHA-256)',
            newTransfer: 'Nouveau transfert',
            qrHint: 'Scannez pour recevoir sur mobile',
            error: 'Erreur',
            retry: 'Réessayer',
            footer: '🔐 Chiffrement AES-256-GCM | 🌐 WebRTC P2P | 🚫 Aucune donnée stockée sur le serveur | SecurePeer'
        },
        en: {
            title: '🔒 SecurePeer',
            subtitle: 'End-to-end encrypted file transfer, no intermediate server',
            modeTitle: '🚀 Create a session',
            modeDesc: 'Choose the type of session you want to start',
            modeFile: 'File Transfer',
            modeFileDesc: 'Send files securely',
            modeChat: 'Secure Chat',
            modeChatDesc: 'Chat in real-time, E2E encrypted',
            modeBoth: 'Files + Chat',
            modeBothDesc: 'Transfer and chat simultaneously',
            senderHeader: '📤 Send a file',
            sectionDesc: 'Choose a file and share the secure link',
            dropZone: 'Drag and drop a file here',
            or: 'or click to select',
            chooseFile: 'Choose a file',
            deleteFile: '✕ Delete',
            password: '🔐 Password protection (optional)',
            passwordPlaceholder: 'Enter a password for extra security',
            sendBtn: '📤 Send file',
            startChatBtn: '💬 Start chat',
            passwordHint: 'Your password never leaves your device',
            shareTitle: '🔗 Share link generated',
            linkInfo: 'Share this link with the recipient',
            copyBtn: '📋 Copy',
            waiting: '📍 Waiting for recipient...',
            chatTitle: '💬 Secure Chat',
            chatPlaceholder: 'Type your message...',
            chatSend: 'Send',
            chatWaiting: 'Waiting...',
            chatConnected: 'Connected',
            chatP2PTitle: '💬 Secure P2P Chat',
            chatFilesTitle: '💬 Chat + Files',
            filesTitle: '📁 Files',
            addFile: '📎 Add',
            sendFiles: '📤 Send',
            pending: 'Pending',
            receiving: 'Receiving...',
            sent: 'Sent',
            download: '📥 Download',
            receiverTitle: '📥 Receiving file',
            receiverPassword: 'Password required',
            receiverPasswordPlaceholder: 'Enter the shared password',
            unlockBtn: 'Unlock',
            passwordHintReceiver: 'Password stays on this device and derives the encryption key.',
            receiveBtn: '📥 Receive file',
            connecting: 'Connecting...',
            transferProgress: 'Transfer in progress...',
            complete: 'Transfer complete!',
            integrity: 'Integrity verified (SHA-256)',
            newTransfer: 'New transfer',
            qrHint: 'Scan to receive on mobile',
            error: 'Error',
            retry: 'Retry',
            footer: '🔐 AES-256-GCM Encryption | 🌐 WebRTC P2P | 🚫 No data stored on server | SecurePeer'
        },
        es: {
            title: '🔒 SecurePeer',
            subtitle: 'Transferencia de archivos cifrada de extremo a extremo, sin servidor intermedio',
            modeTitle: '🚀 Crear una sesión',
            modeDesc: 'Elige el tipo de sesión que quieres iniciar',
            modeFile: 'Transferencia de archivos',
            modeFileDesc: 'Envía archivos de forma segura',
            modeChat: 'Chat seguro',
            modeChatDesc: 'Chatea en tiempo real, cifrado E2E',
            modeBoth: 'Archivos + Chat',
            modeBothDesc: 'Transfiere y chatea simultáneamente',
            senderHeader: '📤 Enviar un archivo',
            sectionDesc: 'Elige un archivo y comparte el enlace seguro',
            dropZone: 'Arrastra y suelta un archivo aquí',
            or: 'o haz clic para seleccionar',
            chooseFile: 'Elegir un archivo',
            deleteFile: '✕ Eliminar',
            password: '🔐 Protección por contraseña (opcional)',
            passwordPlaceholder: 'Ingresa una contraseña para mayor seguridad',
            sendBtn: '📤 Enviar archivo',
            startChatBtn: '💬 Iniciar chat',
            passwordHint: 'Tu contraseña nunca sale de tu dispositivo',
            shareTitle: '🔗 Enlace de compartir generado',
            linkInfo: 'Comparte este enlace con el destinatario',
            copyBtn: '📋 Copiar',
            waiting: '📍 Esperando al destinatario...',
            chatTitle: '💬 Chat seguro',
            chatPlaceholder: 'Escribe tu mensaje...',
            chatSend: 'Enviar',
            chatWaiting: 'Esperando...',
            chatConnected: 'Conectado',
            chatP2PTitle: '💬 Chat P2P seguro',
            chatFilesTitle: '💬 Chat + Archivos',
            filesTitle: '📁 Archivos',
            addFile: '📎 Añadir',
            sendFiles: '📤 Enviar',
            pending: 'Pendiente',
            receiving: 'Recibiendo...',
            sent: 'Enviado',
            download: '📥 Descargar',
            receiverTitle: '📥 Recibiendo archivo',
            receiverPassword: 'Se requiere contraseña',
            receiverPasswordPlaceholder: 'Ingresa la contraseña compartida',
            unlockBtn: 'Desbloquear',
            passwordHintReceiver: 'La contraseña se mantiene en este dispositivo y deriva la clave de cifrado.',
            receiveBtn: '📥 Recibir archivo',
            connecting: 'Conectando...',
            transferProgress: 'Transferencia en progreso...',
            complete: '¡Transferencia completada!',
            integrity: 'Integridad verificada (SHA-256)',
            newTransfer: 'Nueva transferencia',
            qrHint: 'Escanea para recibir en el móvil',
            error: 'Error',
            retry: 'Reintentar',
            footer: '🔐 Cifrado AES-256-GCM | 🌐 WebRTC P2P | 🚫 Sin datos almacenados en servidor | SecurePeer'
        },
        it: {
            title: '🔒 SecurePeer',
            subtitle: 'Trasferimento file crittografato end-to-end, senza server intermediario',
            modeTitle: '🚀 Crea una sessione',
            modeDesc: 'Scegli il tipo di sessione che vuoi avviare',
            modeFile: 'Trasferimento file',
            modeFileDesc: 'Invia file in modo sicuro',
            modeChat: 'Chat sicura',
            modeChatDesc: 'Chatta in tempo reale, crittografato E2E',
            modeBoth: 'File + Chat',
            modeBothDesc: 'Trasferisci e chatta simultaneamente',
            senderHeader: '📤 Invia un file',
            sectionDesc: 'Scegli un file e condividi il collegamento sicuro',
            dropZone: 'Trascina e rilascia un file qui',
            or: 'o fai clic per selezionare',
            chooseFile: 'Scegli un file',
            deleteFile: '✕ Elimina',
            password: '🔐 Protezione con password (facoltativa)',
            passwordPlaceholder: 'Inserisci una password per maggiore sicurezza',
            sendBtn: '📤 Invia file',
            startChatBtn: '💬 Avvia chat',
            passwordHint: 'La tua password non lascia mai il tuo dispositivo',
            shareTitle: '🔗 Collegamento di condivisione generato',
            linkInfo: 'Condividi questo collegamento con il destinatario',
            copyBtn: '📋 Copia',
            waiting: '📍 In attesa del destinatario...',
            chatTitle: '💬 Chat sicura',
            chatPlaceholder: 'Scrivi il tuo messaggio...',
            chatSend: 'Invia',
            chatWaiting: 'In attesa...',
            chatConnected: 'Connesso',
            chatP2PTitle: '💬 Chat P2P sicura',
            chatFilesTitle: '💬 Chat + File',
            filesTitle: '📁 File',
            addFile: '📎 Aggiungi',
            sendFiles: '📤 Invia',
            pending: 'In attesa',
            receiving: 'Ricezione...',
            sent: 'Inviato',
            download: '📥 Scarica',
            receiverTitle: '📥 Ricezione file',
            receiverPassword: 'Password richiesta',
            receiverPasswordPlaceholder: 'Inserisci la password condivisa',
            unlockBtn: 'Sblocca',
            passwordHintReceiver: 'La password rimane su questo dispositivo e deriva la chiave di crittografia.',
            receiveBtn: '📥 Ricevi file',
            connecting: 'Connessione in corso...',
            transferProgress: 'Trasferimento in corso...',
            complete: 'Trasferimento completato!',
            integrity: 'Integrità verificata (SHA-256)',
            newTransfer: 'Nuovo trasferimento',
            qrHint: 'Scansiona per ricevere sul cellulare',
            error: 'Errore',
            retry: 'Riprova',
            footer: '🔐 Crittografia AES-256-GCM | 🌐 WebRTC P2P | 🚫 Nessun dato archiviato sul server | SecurePeer'
        },
        ru: {
            title: '🔒 SecurePeer',
            subtitle: 'Сквозное зашифрованная передача файлов без промежуточного сервера',
            modeTitle: '🚀 Создать сессию',
            modeDesc: 'Выберите тип сессии, которую хотите начать',
            modeFile: 'Передача файлов',
            modeFileDesc: 'Отправляйте файлы безопасно',
            modeChat: 'Безопасный чат',
            modeChatDesc: 'Общайтесь в реальном времени, E2E шифрование',
            modeBoth: 'Файлы + Чат',
            modeBothDesc: 'Передавайте и общайтесь одновременно',
            senderHeader: '📤 Отправить файл',
            sectionDesc: 'Выберите файл и поделитесь безопасной ссылкой',
            dropZone: 'Перетащите файл сюда',
            or: 'или нажмите для выбора',
            chooseFile: 'Выбрать файл',
            deleteFile: '✕ Удалить',
            password: '🔐 Защита паролем (необязательно)',
            passwordPlaceholder: 'Введите пароль для дополнительной безопасности',
            sendBtn: '📤 Отправить файл',
            startChatBtn: '💬 Начать чат',
            passwordHint: 'Ваш пароль никогда не покидает ваше устройство',
            shareTitle: '🔗 Ссылка для обмена создана',
            linkInfo: 'Поделитесь этой ссылкой с получателем',
            copyBtn: '📋 Копировать',
            waiting: '📍 Ожидание получателя...',
            chatTitle: '💬 Безопасный чат',
            chatPlaceholder: 'Введите сообщение...',
            chatSend: 'Отправить',
            chatWaiting: 'Ожидание...',
            chatConnected: 'Подключен',
            chatP2PTitle: '💬 Безопасный P2P чат',
            chatFilesTitle: '💬 Чат + Файлы',
            filesTitle: '📁 Файлы',
            addFile: '📎 Добавить',
            sendFiles: '📤 Отправить',
            pending: 'Ожидание',
            receiving: 'Получение...',
            sent: 'Отправлено',
            download: '📥 Скачать',
            receiverTitle: '📥 Получение файла',
            receiverPassword: 'Требуется пароль',
            receiverPasswordPlaceholder: 'Введите общий пароль',
            unlockBtn: 'Разблокировать',
            passwordHintReceiver: 'Пароль остается на этом устройстве и производит ключ шифрования.',
            receiveBtn: '📥 Получить файл',
            connecting: 'Подключение...',
            transferProgress: 'Передача в процессе...',
            complete: 'Передача завершена!',
            integrity: 'Целостность проверена (SHA-256)',
            newTransfer: 'Новая передача',
            qrHint: 'Сканируйте для получения на мобильном',
            error: 'Ошибка',
            retry: 'Повторить',
            footer: '🔐 Шифрование AES-256-GCM | 🌐 WebRTC P2P | 🚫 Нет данных, хранящихся на сервере | SecurePeer'
        }
    };
    
    const t = translations[currentLanguage] || translations.fr;
    
    // Mettre à jour les éléments DOM (avec garde anti-null)
    const heroTitleEl = document.querySelector('.hero-content h1');
    if (heroTitleEl) heroTitleEl.textContent = t.title;
    const subtitleEl = document.querySelector('.subtitle');
    if (subtitleEl) subtitleEl.textContent = t.subtitle;
    
    // Mettre à jour le header sender - selon le mode de session actuel
    const senderHeader = document.querySelector('.sender-header h2');
    const sectionDesc = document.querySelector('.section-desc');
    if (sessionMode === 'chat') {
        if (senderHeader) senderHeader.textContent = t.chatTitle || '💬 Chat sécurisé';
        if (sectionDesc) sectionDesc.textContent = t.modeChatDesc || 'Discutez en temps réel, chiffré E2E';
    } else if (sessionMode === 'both') {
        if (senderHeader) senderHeader.textContent = t.chatFilesTitle || '💬 Chat + Fichiers';
        if (sectionDesc) sectionDesc.textContent = t.modeBothDesc || 'Transférez et discutez simultanément';
    } else {
        if (senderHeader) senderHeader.textContent = t.senderHeader;
        if (sectionDesc) sectionDesc.textContent = t.sectionDesc;
    }
    
    const dropTextEl = document.querySelector('.drop-zone-content p');
    if (dropTextEl) dropTextEl.textContent = t.dropZone;
    const orEl = document.querySelector('.or');
    if (orEl) orEl.textContent = t.or;
    const chooseBtnEl = document.querySelector('.file-input-label .btn');
    if (chooseBtnEl) chooseBtnEl.textContent = t.chooseFile;
    
    const clearFileBtn = document.getElementById('clear-file');
    if (clearFileBtn) clearFileBtn.textContent = t.deleteFile;
    
    const passwordLabel = document.querySelector('.password-block label');
    if (passwordLabel) passwordLabel.textContent = t.password;
    document.getElementById('password-input').placeholder = t.passwordPlaceholder;
    document.getElementById('send-file-btn').textContent = t.sendBtn;
    document.querySelector('.password-block .hint').textContent = t.passwordHint;
    
    const linkHeader = document.querySelector('.link-header h3');
    if (linkHeader) linkHeader.textContent = t.shareTitle;
    const linkInfo = document.querySelector('.link-info');
    if (linkInfo) linkInfo.textContent = t.linkInfo;
    document.getElementById('copy-link').textContent = t.copyBtn;
    document.getElementById('link-status').innerHTML = `<span class="pulse"></span>${t.waiting}`;
    
    const qrHintEl = document.querySelector('.qrcode-hint');
    if (qrHintEl) qrHintEl.textContent = t.qrHint;
    
    // Mode selection
    const modeHeader = document.querySelector('.mode-header h2');
    if (modeHeader) modeHeader.textContent = t.modeTitle;
    const modeDesc = document.querySelector('.mode-header .section-desc');
    if (modeDesc) modeDesc.textContent = t.modeDesc;
    
    const modeCards = document.querySelectorAll('.mode-card');
    modeCards.forEach(card => {
        const mode = card.dataset.mode;
        const h3 = card.querySelector('h3');
        const p = card.querySelector('p');
        if (mode === 'file' && h3 && p) {
            h3.textContent = t.modeFile;
            p.textContent = t.modeFileDesc;
        } else if (mode === 'chat' && h3 && p) {
            h3.textContent = t.modeChat;
            p.textContent = t.modeChatDesc;
        } else if (mode === 'both' && h3 && p) {
            h3.textContent = t.modeBoth;
            p.textContent = t.modeBothDesc;
        }
    });
    
    // Chat
    const chatHeaders = document.querySelectorAll('.chat-header h3');
    chatHeaders.forEach(el => { if (el) el.textContent = t.chatTitle; });
    const chatInputs = document.querySelectorAll('.chat-input-container input');
    chatInputs.forEach(el => { if (el) el.placeholder = t.chatPlaceholder; });
    const chatSendBtns = document.querySelectorAll('.chat-input-container .btn');
    chatSendBtns.forEach(el => { if (el) el.textContent = t.chatSend; });
    
    const receiverTitle = document.querySelector('.receiver-info h2');
    if (receiverTitle) receiverTitle.textContent = t.receiverTitle;
    
    const receiverPasswordLabel = document.querySelector('#receiver-password-block label');
    if (receiverPasswordLabel) receiverPasswordLabel.textContent = t.receiverPassword;
    document.getElementById('receiver-password').placeholder = t.receiverPasswordPlaceholder;
    document.getElementById('receiver-password-apply').textContent = t.unlockBtn;
    
    const receiverPasswordHint = document.querySelector('#receiver-password-block .hint');
    if (receiverPasswordHint) receiverPasswordHint.textContent = t.passwordHintReceiver;
    
    if (document.getElementById('receive-file-btn')) {
        document.getElementById('receive-file-btn').textContent = t.receiveBtn;
    }
    
    document.getElementById('progress-title').textContent = t.transferProgress;
    
    const completeHeading = document.querySelector('.complete-content h2');
    if (completeHeading) completeHeading.textContent = t.complete;
    document.querySelector('.integrity-check span:last-child').textContent = t.integrity;
    document.getElementById('new-transfer').textContent = t.newTransfer;
    
    const errorHeading = document.querySelector('.error-content h2');
    if (errorHeading) errorHeading.textContent = t.error;
    document.getElementById('retry-transfer').textContent = t.retry;
    
    document.querySelector('footer p').textContent = t.footer;
}

// Appliquer la langue au chargement

document.addEventListener('DOMContentLoaded', async () => {
    console.log('🚀 [INIT] DOMContentLoaded - Démarrage de l\'application');
    
    // Vérifier d'abord si on a un hash (lien de partage)
    const hash = window.location.hash.substring(1);
    const hasShareLink = hash && hash.includes('_');
    
    // Récupérer la session stockée
    const restored = restoreSessionFromStorage();
    
    console.log('🔍 [INIT] Hash URL:', hash || '(aucun)');
    console.log('🔍 [INIT] Session stockée:', restored);
    
    // PRIORITÉ 1: Lien de partage (receiver qui arrive ou revient)
    if (hasShareLink) {
        // Extraire le roomId du hash
        const hashRoomId = hash.split('_')[0];
        console.log('🔗 [INIT] Lien de partage détecté, roomId:', hashRoomId);
        
        // Vérifier si c'est la même session que celle stockée
        if (restored && restored.roomId === hashRoomId && restored.isReceiver) {
            console.log('🔄 [INIT] Même session receiver, restauration...');
            // Restaurer la session receiver existante
            await restoreReceiverSession(restored, hash);
        } else {
            console.log('🆕 [INIT] Nouvelle visite via lien, flow receiver normal');
            // Effacer toute ancienne session pour éviter les conflits
            clearSessionStorage();
            // Flow normal pour nouveau receiver
            elements.landingPage.classList.add('hidden');
            showPseudoThenConnect(hash);
        }
    }
    // PRIORITÉ 2: Session créateur stockée (créateur qui rafraîchit)
    else if (restored && restored.roomId && !restored.isReceiver && restored.sessionMode) {
        console.log('👑 [INIT] Session créateur détectée, restauration...');
        await restoreCreatorSession(restored);
    }
    // PRIORITÉ 3: Pas de session, afficher la landing page
    else {
        console.log('🏠 [INIT] Pas de session, affichage landing page');
        // Effacer toute session invalide
        if (restored) clearSessionStorage();
        setupPseudoSection();
        init();
    }
    
    setupLanguageSelector();
    updateLanguage();
    setupThemeToggle();
    
    // Vérifier et afficher le popup Tor (première utilisation)
    checkAndShowTorPopup();
    
    // Attacher les event listeners des boutons de fermeture de session (toujours, quel que soit le mode)
    setupCloseSessionButtons();
    
    // Initialiser les fonctionnalités du chat
    setupChatSearch();
    setupPinnedMessages();
    setupChatExport();
    setupEphemeralMessages();
    
    // Raccourci Escape pour fermer la session
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && (roomId || isReceiver)) {
            if (confirm('Voulez-vous vraiment fermer cette session ? (Appuyez sur Escape)')) {
                closeSessionProperly();
            }
        }
    });
});

// ===== FONCTIONS DE RESTAURATION DE SESSION =====

async function restoreCreatorSession(restored) {
    console.log('👑 [RESTORE-CREATOR] Début restauration créateur');
    
    // Restaurer les variables globales
    roomId = restored.roomId;
    sessionMode = restored.sessionMode;
    isReceiver = false;
    isCreator = true;
    usePassword = restored.usePassword || false;
    passwordSaltB64 = restored.passwordSaltB64 || '';
    passwordIterations = restored.passwordIterations || KDF_ITERATIONS;
    userPseudo = restored.pseudo || localStorage.getItem('securepeer_pseudo') || '';
    
    // Restaurer le odId
    if (restored.odId) {
        myOdId = restored.odId;
        localStorage.setItem('securepeer_odid', myOdId);
    }
    
    // Sauvegarder le pseudo
    localStorage.setItem('securepeer_pseudo', userPseudo);
    
    console.log('   📦 roomId:', roomId);
    console.log('   📋 mode:', sessionMode);
    console.log('   👤 pseudo:', userPseudo);
    console.log('   🔑 odId:', myOdId);
    
    // Cacher les sections non nécessaires
    if (elements.landingPage) elements.landingPage.classList.add('hidden');
    if (elements.modeSelection) elements.modeSelection.classList.add('hidden');
    if (elements.pseudoSection) elements.pseudoSection.classList.add('hidden');
    
    // Restaurer la clé crypto depuis la session stockée (au lieu d'en générer une nouvelle)
    if (restored.cryptoKeyB64) {
        try {
            await importKeyFromBase64(restored.cryptoKeyB64);
            console.log('🔐 [RESTORE-CREATOR] Clé crypto RESTAURÉE depuis localStorage');
        } catch (err) {
            console.error('❌ [RESTORE-CREATOR] Erreur import clé:', err);
            // Ne pas générer de nouvelle clé, on utilisera ECDH
        }
    }
    
    // Restaurer la paire ECDH si elle existe
    if (restored.ecdhKeyPair) {
        try {
            const success = await importECDHKeyPair(restored.ecdhKeyPair);
            if (success) {
                console.log('🔐 [RESTORE-CREATOR] Paire ECDH RESTAURÉE depuis localStorage');
            } else {
                // Générer une nouvelle paire ECDH
                await generateECDHKeyPair();
                console.log('🔐 [RESTORE-CREATOR] Nouvelle paire ECDH générée (import échoué)');
            }
        } catch (err) {
            console.error('❌ [RESTORE-CREATOR] Erreur import ECDH:', err);
            await generateECDHKeyPair();
            console.log('🔐 [RESTORE-CREATOR] Nouvelle paire ECDH générée (erreur)');
        }
    } else if (!usePassword && !restored.cryptoKeyB64) {
        // Pas de clé stockée et pas de mot de passe, générer ECDH
        await generateECDHKeyPair();
        console.log('🔐 [RESTORE-CREATOR] Nouvelle paire ECDH générée (pas de clé stockée)');
    }
    
    // Restaurer ou régénérer fileInfo selon le mode
    if (restored.fileInfo) {
        // Utiliser le fileInfo stocké
        fileInfo = restored.fileInfo;
        console.log('   📄 fileInfo restauré:', fileInfo.name);
    } else if (sessionMode === 'chat' || sessionMode === 'both') {
        fileInfo = {
            name: sessionMode === 'chat' ? 'Chat Session' : 'Chat + Files Session',
            size: 0,
            type: 'text/plain',
            passwordRequired: usePassword,
            chatOnly: sessionMode === 'chat',
            bothMode: sessionMode === 'both'
        };
    } else {
        fileInfo = {
            name: 'Fichier',
            size: 0,
            type: 'application/octet-stream',
            passwordRequired: usePassword
        };
    }
    if (usePassword && passwordSaltB64) {
        fileInfo.passwordSalt = passwordSaltB64;
        fileInfo.passwordIterations = passwordIterations;
    }
    
    // Afficher l'interface créateur
    showCreatorInterface(sessionMode);
    
    // Afficher la section lien avec statut "en attente"
    if (elements.linkSection) elements.linkSection.classList.remove('hidden');
    if (elements.linkStatus) {
        elements.linkStatus.innerHTML = `<span class="pulse"></span> Reconnexion en cours...`;
    }
    
    // Se reconnecter au WebSocket
    console.log('🌐 [RESTORE-CREATOR] Connexion WebSocket...');
    connectWebSocket();
    
    showToast('Session créateur restaurée');
}

async function restoreReceiverSession(restored, hash) {
    console.log('📥 [RESTORE-RECEIVER] Début restauration receiver');
    
    // Restaurer les variables globales
    roomId = restored.roomId;
    sessionMode = restored.sessionMode;
    isReceiver = true;
    isCreator = false;
    usePassword = restored.usePassword || false;
    passwordSaltB64 = restored.passwordSaltB64 || '';
    passwordIterations = restored.passwordIterations || KDF_ITERATIONS;
    userPseudo = restored.pseudo || localStorage.getItem('securepeer_pseudo') || '';
    fileInfo = restored.fileInfo || null;
    
    // Sauvegarder le pseudo et odId
    localStorage.setItem('securepeer_pseudo', userPseudo);
    if (restored.odId) {
        myOdId = restored.odId;
        localStorage.setItem('securepeer_odid', myOdId);
    }
    
    console.log('   📦 roomId:', roomId);
    console.log('   📋 mode:', sessionMode);
    console.log('   👤 pseudo:', userPseudo);
    console.log('   🔑 odId:', myOdId);
    console.log('   🔐 usePassword:', usePassword);
    console.log('   🔐 cryptoKeyB64 stocké:', !!restored.cryptoKeyB64);
    
    // Cacher les sections non nécessaires
    if (elements.landingPage) elements.landingPage.classList.add('hidden');
    if (elements.modeSelection) elements.modeSelection.classList.add('hidden');
    if (elements.pseudoSection) elements.pseudoSection.classList.add('hidden');
    
    // Afficher la section receiver
    elements.receiverSection.classList.remove('hidden');
    
    // Afficher le badge "Session éphémère" dans le header
    showEphemeralBadge();
    
    // Gérer la clé crypto
    if (usePassword && !restored.cryptoKeyB64) {
        // Session protégée par mot de passe ET pas de clé stockée - redemander le mot de passe
        console.log('🔐 [RESTORE-RECEIVER] Session protégée, redemander mot de passe');
        elements.receiverStatus.textContent = 'Entrez le mot de passe pour reprendre la session';
        elements.receiverPasswordBlock.classList.remove('hidden');
        elements.receiverPasswordApply.onclick = async () => {
            await applyReceiverPassword();
            // Après application du mot de passe, se reconnecter
            if (cryptoKey) {
                console.log('🌐 [RESTORE-RECEIVER] Mot de passe OK, connexion WebSocket...');
                connectWebSocket();
            }
        };
        showToast('Entrez le mot de passe pour reprendre votre session');
        return; // Ne pas continuer tant que le mot de passe n'est pas entré
    }
    
    // Restaurer la clé depuis la session stockée (priorité) ou depuis le hash (fallback)
    if (restored.cryptoKeyB64) {
        try {
            await importKeyFromBase64(restored.cryptoKeyB64);
            console.log('🔐 [RESTORE-RECEIVER] Clé crypto RESTAURÉE depuis localStorage');
        } catch (err) {
            console.error('❌ [RESTORE-RECEIVER] Erreur import clé stockée:', err);
            // La clé sera dérivée via ECDH après connexion
        }
    }
    
    // Restaurer la paire ECDH si elle existe
    if (restored.ecdhKeyPair) {
        try {
            const success = await importECDHKeyPair(restored.ecdhKeyPair);
            if (success) {
                console.log('🔐 [RESTORE-RECEIVER] Paire ECDH RESTAURÉE depuis localStorage');
            } else {
                // Générer une nouvelle paire ECDH
                await generateECDHKeyPair();
                console.log('🔐 [RESTORE-RECEIVER] Nouvelle paire ECDH générée');
            }
        } catch (err) {
            console.error('❌ [RESTORE-RECEIVER] Erreur import ECDH:', err);
            await generateECDHKeyPair();
        }
    } else if (!usePassword && !restored.cryptoKeyB64) {
        // Pas de clé et pas de mot de passe, générer ECDH pour le nouvel échange
        await generateECDHKeyPair();
        console.log('🔐 [RESTORE-RECEIVER] Nouvelle paire ECDH générée (pas de clé stockée)');
    }
    
    // Afficher le chat/fichiers selon le mode
    if (sessionMode === 'chat' || sessionMode === 'both') {
        elements.receiverChatSection.classList.remove('hidden');
        if (sessionMode === 'both') {
            elements.receiverBothFileSection.classList.remove('hidden');
        }
    }
    
    // Afficher les infos du fichier si disponibles
    if (fileInfo) {
        if (elements.incomingFileName) elements.incomingFileName.textContent = fileInfo.name || 'Fichier';
        if (elements.incomingFileSize) elements.incomingFileSize.textContent = formatFileSize(fileInfo.size || 0);
    }
    
    // Mettre à jour le statut
    elements.receiverStatus.textContent = 'Reconnexion en cours...';
    
    // Setup chat et fichiers
    setupChat();
    setupBothModeFiles();
    
    // Se reconnecter au WebSocket
    console.log('🌐 [RESTORE-RECEIVER] Connexion WebSocket...');
    connectWebSocket();
    
    showToast('Session receiver restaurée');
}

function setupThemeToggle() {
    const themeToggle = document.getElementById('theme-toggle');
    const currentTheme = localStorage.getItem('theme') || 'light';
    
    // Appliquer le thème initial
    if (currentTheme === 'dark') {
        document.documentElement.setAttribute('data-theme', 'dark');
    }
    
    if (themeToggle) {
        themeToggle.addEventListener('click', () => {
            const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
            const newTheme = isDark ? 'light' : 'dark';
            
            document.documentElement.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
            
            console.log('🌓 Thème changé en:', newTheme);
        });
    }
}

// ===== SÉLECTION DU PSEUDO =====
function setupPseudoSection() {
    // Event listener pour le bouton confirmer pseudo
    if (elements.pseudoConfirmBtn) {
        elements.pseudoConfirmBtn.addEventListener('click', () => {
            const pseudoValue = elements.pseudoInputMain.value.trim();
            if (!pseudoValue || pseudoValue.length < 3) {
                showToast('⚠️ Le pseudo doit faire au moins 3 caractères');
                return;
            }
            if (pseudoValue.length > 20) {
                showToast('⚠️ Le pseudo doit faire maximum 20 caractères');
                return;
            }
            // Sauvegarder le pseudo UNIQUEMENT si pas déjà défini
            if (!userPseudo || userPseudo !== pseudoValue) {
                userPseudo = pseudoValue;
                localStorage.setItem('securepeer_pseudo', pseudoValue);
                console.log('✅ Pseudo défini:', userPseudo);
            }
            // Cacher la section pseudo et continuer
            elements.pseudoSection.classList.add('hidden');
            continueInit();
        });
    }
    // Permettre Entrée pour confirmer
    if (elements.pseudoInputMain) {
        elements.pseudoInputMain.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                elements.pseudoConfirmBtn.click();
            }
        });
    }
}

// Demander le pseudo puis afficher l'interface créateur
function showPseudoForCreator(mode) {
    console.log('🎭 [PSEUDO] showPseudoForCreator appelé pour mode:', mode);
    // Toujours demander le pseudo (pré-remplir si sauvegardé)
    const savedPseudo = localStorage.getItem('securepeer_pseudo');
    // Afficher la section pseudo
    elements.pseudoSection.classList.remove('hidden');
    // Pré-remplir si un pseudo est sauvegardé
    if (savedPseudo) {
        elements.pseudoInputMain.value = savedPseudo;
    } else {
        elements.pseudoInputMain.value = '';
    }
    elements.pseudoInputMain?.focus();
    
    // Créer un nouveau bouton pour éviter les conflits d'event listeners
    const oldBtn = elements.pseudoConfirmBtn;
    const newBtn = oldBtn.cloneNode(true);
    oldBtn.parentNode.replaceChild(newBtn, oldBtn);
    elements.pseudoConfirmBtn = newBtn;
    
    // Attacher le handler spécifique pour le créateur
    newBtn.addEventListener('click', () => {
        const pseudoValue = elements.pseudoInputMain.value.trim();
        if (!pseudoValue || pseudoValue.length < 3) {
            showToast('⚠️ Le pseudo doit faire au moins 3 caractères');
            return;
        }
        if (pseudoValue.length > 20) {
            showToast('⚠️ Le pseudo doit faire maximum 20 caractères');
            return;
        }
        // Sauvegarder le pseudo
        userPseudo = pseudoValue;
        localStorage.setItem('securepeer_pseudo', pseudoValue);
        console.log('✅ [PSEUDO] Pseudo défini:', userPseudo);
        // Cacher la section pseudo et afficher l'interface créateur
        elements.pseudoSection.classList.add('hidden');
        console.log('🎨 [PSEUDO] Appel de showCreatorInterface pour mode:', mode);
        showCreatorInterface(mode);
    });
}

// ===== SÉLECTION DU MODE =====
function setupModeSelection() {
    const modeCards = document.querySelectorAll('.mode-card');
    
    modeCards.forEach(card => {
        card.addEventListener('click', () => {
            const mode = card.dataset.mode;
            sessionMode = mode;
            
            // Sauvegarder la session avec le mode
            if (roomId) {
                saveSessionToStorage();
            }
            
            // Marquer la carte sélectionnée
            modeCards.forEach(c => c.classList.remove('selected'));
            card.classList.add('selected');
            
            // Cacher la sélection de mode, demander le pseudo
            elements.modeSelection.classList.add('hidden');
            
            // Demander le pseudo avant de continuer
            showPseudoForCreator(mode);
            
            console.log('📋 Mode sélectionné:', mode);
        });
    });
}

// ===== CHAT =====
function setupChat() {
    // Sender side
    if (elements.chatSend) {
        elements.chatSend.addEventListener('click', () => sendChatMessage(false));
    }
    if (elements.chatInput) {
        elements.chatInput.addEventListener('keyup', (e) => {
            sendTypingSignal(false);
            if (e.key === 'Enter') sendChatMessage(false);
        });
    }
    
    // Receiver side
    if (elements.receiverChatSend) {
        elements.receiverChatSend.addEventListener('click', () => sendChatMessage(true));
    }
    if (elements.receiverChatInput) {
        elements.receiverChatInput.addEventListener('keyup', (e) => {
            sendTypingSignal(true);
            if (e.key === 'Enter') sendChatMessage(true);
        });
    }
}

function getActiveChatElements(isReceiverSide) {
    return {
        inputEl: isReceiverSide ? elements.receiverChatInput : elements.chatInput,
        messagesEl: isReceiverSide ? elements.receiverChatMessages : elements.chatMessages,
        statusEl: isReceiverSide ? elements.receiverChatStatus : elements.chatStatus
    };
}

function generateMessageId() {
    const arr = new Uint8Array(12);
    window.crypto.getRandomValues(arr);
    return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

function findMessageById(messageId) {
    return chatMessages.find(m => m.id === messageId) || null;
}

function setReplyPreview(targetId, isReceiverSide) {
    replyToMessageId = targetId;
    const { inputEl } = getActiveChatElements(isReceiverSide);
    const target = findMessageById(targetId);
    if (!inputEl || !target) return;
    
    // Annuler l'édition si active
    editingMessageId = null;
    document.querySelectorAll('.editing-indicator').forEach(ind => ind.remove());
    
    // Ajouter un indicateur visuel de réponse
    const replyIndicator = document.createElement('div');
    replyIndicator.className = 'reply-indicator';
    replyIndicator.innerHTML = `
        <div class="reply-preview">
            <span class="reply-icon">↩</span>
            <div class="reply-info">
                <strong>${escapeHtml(target.pseudo || 'Message')}</strong>
                <span>${escapeHtml(target.text.slice(0, 50))}${target.text.length > 50 ? '…' : ''}</span>
            </div>
            <button class="cancel-reply-btn" onclick="cancelReply()">✕</button>
        </div>
    `;
    
    const inputContainer = inputEl.parentElement;
    const existingIndicator = inputContainer.querySelector('.reply-indicator');
    if (existingIndicator) existingIndicator.remove();
    
    inputContainer.insertBefore(replyIndicator, inputEl);
    inputEl.focus();
}

function cancelReply() {
    replyToMessageId = null;
    document.querySelectorAll('.reply-indicator').forEach(ind => ind.remove());
}

function clearReplyEditState(isReceiverSide) {
    replyToMessageId = null;
    editingMessageId = null;
    const { inputEl } = getActiveChatElements(isReceiverSide);
    if (inputEl) {
        inputEl.placeholder = 'Votre message...';
    }
    
    // Nettoyer les indicateurs visuels
    document.querySelectorAll('.editing-indicator, .reply-indicator').forEach(ind => ind.remove());
}

async function sendChatMessage(isReceiverSide) {
    const { inputEl, messagesEl } = getActiveChatElements(isReceiverSide);
    const text = inputEl.value.trim();
    const hasConnectedPeer = Array.from(peers.values()).some(p => p.connected);
    if (!text || !hasConnectedPeer) return;
    
    try {
        // Mode édition : envoyer un patch
        if (editingMessageId) {
            const editPayload = {
                type: 'chat-edit',
                messageId: editingMessageId,
                text: text, // Envoi en clair temporairement pour l'édition
                senderPseudo: userPseudo,
                timestamp: Date.now()
            };
            broadcastToAllPeers(editPayload);

            // Mise à jour locale
            const target = findMessageById(editingMessageId);
            if (target) {
                target.text = text;
                target.edited = true;
            }
            inputEl.value = '';
            clearReplyEditState(isReceiverSide);
            renderChatMessages(messagesEl);
            console.log('✏️ Message édité');
            return;
        }

        const messageId = generateMessageId();
        const messageData = {
            type: 'chat-message',
            messageId,
            replyToId: replyToMessageId,
            text: text, // Le texte sera chiffré par Double Ratchet
            senderPseudo: userPseudo,
            timestamp: Date.now()
        };
        broadcastToAllPeers(messageData);

        // Local append
        chatMessages.push({
            id: messageId,
            text,
            isSent: true,
            pseudo: userPseudo,
            timestamp: Date.now(),
            replyToId: replyToMessageId,
            edited: false,
            deleted: false,
            reactions: {},
            ephemeral: ephemeralMode ? ephemeralDuration : null
        });
        inputEl.value = '';
        clearReplyEditState(isReceiverSide);
        renderChatMessages(messagesEl);
        
        // Programmer la suppression si éphémère
        if (ephemeralMode) {
            scheduleMessageDeletion(messageId, ephemeralDuration);
        }
        
        console.log('💬 Message envoyé à', peers.size, 'peer(s)');
    } catch (err) {
        console.error('❌ Erreur envoi message:', err);
        showToast('Erreur lors de l\'envoi du message');
    }
}

async function handleChatMessage(data, fromOdId) {
    try {
        // Le message est déjà déchiffré si passé par handleDoubleRatchetMessage
        // Sinon c'est un ancien format avec iv/ciphertext
        let text;
        
        if (data.text) {
            // Nouveau format: texte déjà déchiffré par Double Ratchet
            text = data.text;
        } else if (data.iv && data.ciphertext) {
            // Ancien format: déchiffrer avec AES-GCM (compatibilité)
            const iv = fromBase64(data.iv);
            const ciphertext = fromBase64(data.ciphertext);
            
            const decrypted = await window.crypto.subtle.decrypt(
                { name: 'AES-GCM', iv },
                cryptoKey,
                ciphertext
            );
            
            const decoder = new TextDecoder();
            text = decoder.decode(decrypted);
        } else {
            console.error('❌ Format de message invalide');
            return;
        }
        
        // Récupérer le pseudo de l'expéditeur
        const senderPseudo = data.senderPseudo || participants.get(fromOdId)?.pseudo || 'Anonyme';
        const messagesEl = isReceiver ? elements.receiverChatMessages : elements.chatMessages;
        
        const messageId = data.messageId || generateMessageId();
        chatMessages.push({
            id: messageId,
            text,
            isSent: false,
            pseudo: senderPseudo,
            timestamp: data.timestamp || Date.now(),
            replyToId: data.replyToId || null,
            edited: false,
            deleted: false,
            reactions: {},
            ephemeral: ephemeralMode ? ephemeralDuration : null
        });
        renderChatMessages(messagesEl);
        
        // Programmer la suppression si éphémère
        if (ephemeralMode) {
            scheduleMessageDeletion(messageId, ephemeralDuration);
        }
        
        console.log('💬 Message reçu de', senderPseudo);
    } catch (err) {
        console.error('❌ Erreur traitement message:', err);
    }
}

function renderChatMessages(containerEl) {
    if (!containerEl) return;
    containerEl.innerHTML = '';
    const reactionList = ['👍', '❤️', '😂', '😮', '😢', '👏'];

    // Filtrer les messages selon la recherche
    let filteredMessages = chatMessages;
    let searchMatchCount = 0;
    
    if (chatSearchQuery || chatSearchUserFilter) {
        filteredMessages = chatMessages.filter(msg => {
            if (msg.deleted) return false;
            
            // Filtre par utilisateur
            if (chatSearchUserFilter) {
                const msgPseudo = msg.isSent ? userPseudo : (msg.pseudo || '');
                if (msgPseudo !== chatSearchUserFilter) return false;
            }
            
            // Filtre par mot-clé
            if (chatSearchQuery) {
                const text = (msg.text || '').toLowerCase();
                if (!text.includes(chatSearchQuery.toLowerCase())) return false;
            }
            
            searchMatchCount++;
            return true;
        });
    }
    
    // Mettre à jour le compteur de résultats
    updateSearchResultsCount(searchMatchCount);

    filteredMessages.forEach(msg => {
        const msgWrapper = document.createElement('div');
        msgWrapper.className = `message-wrapper ${msg.isSent ? 'sent' : 'received'}`;
        msgWrapper.dataset.messageId = msg.id;
        
        // Badge épinglé
        if (pinnedMessageIds.has(msg.id)) {
            msgWrapper.classList.add('pinned');
        }

        const msgBubble = document.createElement('div');
        msgBubble.className = 'message-bubble';

        // Pseudo (pour messages reçus en groupe)
        if (!msg.isSent && msg.pseudo && participants.size > 1) {
            const pseudoEl = document.createElement('div');
            pseudoEl.className = 'message-author';
            pseudoEl.textContent = msg.pseudo;
            msgBubble.appendChild(pseudoEl);
        }

        // Réponse/quote avec style amélioré
        if (msg.replyToId && !msg.deleted) {
            const target = findMessageById(msg.replyToId);
            if (target) {
                const replyBar = document.createElement('div');
                replyBar.className = 'message-reply-bar';
                
                const replyIcon = document.createElement('span');
                replyIcon.className = 'reply-icon';
                replyIcon.textContent = '↩';
                
                const replyContent = document.createElement('div');
                replyContent.className = 'reply-content';
                
                const replyAuthor = document.createElement('div');
                replyAuthor.className = 'reply-author';
                replyAuthor.textContent = target.pseudo || (target.isSent ? 'Vous' : 'Message');
                
                const replyText = document.createElement('div');
                replyText.className = 'reply-text';
                const truncated = target.text.slice(0, 60);
                replyText.textContent = truncated + (target.text.length > 60 ? '…' : '');
                
                replyContent.appendChild(replyAuthor);
                replyContent.appendChild(replyText);
                replyBar.appendChild(replyIcon);
                replyBar.appendChild(replyContent);
                msgBubble.appendChild(replyBar);
            }
        }

        // Contenu principal du message
        const contentEl = document.createElement('div');
        contentEl.className = 'message-content';
        
        if (msg.deleted) {
            contentEl.classList.add('deleted');
            contentEl.innerHTML = '<em>🗑️ Message supprimé</em>';
        } else {
            // Mettre en surbrillance les termes de recherche
            if (chatSearchQuery && msg.text) {
                contentEl.innerHTML = highlightSearchTerm(escapeHtml(msg.text), chatSearchQuery);
            } else {
                contentEl.textContent = msg.text;
            }
            
            // Indicateur d'édition discret
            if (msg.edited) {
                const editBadge = document.createElement('span');
                editBadge.className = 'edit-badge';
                editBadge.textContent = 'modifié';
                editBadge.title = 'Ce message a été modifié';
                contentEl.appendChild(editBadge);
            }
        }
        msgBubble.appendChild(contentEl);

        // Réactions (affichées dans la bulle)
        if (!msg.deleted) {
            const existingReactions = Object.entries(msg.reactions || {}).filter(([_, users]) => users.length > 0);
            if (existingReactions.length > 0) {
                const reactionsContainer = document.createElement('div');
                reactionsContainer.className = 'message-reactions-row';
                
                existingReactions.forEach(([emoji, users]) => {
                    const reactionBtn = document.createElement('button');
                    reactionBtn.className = 'reaction-pill';
                    const hasMyReaction = users.includes(userPseudo);
                    if (hasMyReaction) reactionBtn.classList.add('my-reaction');
                    
                    reactionBtn.innerHTML = `<span class="reaction-emoji">${emoji}</span> <span class="reaction-count">${users.length}</span>`;
                    reactionBtn.title = users.join(', ');
                    reactionBtn.onclick = () => toggleQuickReaction(msg.id, emoji);
                    
                    reactionsContainer.appendChild(reactionBtn);
                });
                
                // Bouton + pour ajouter une nouvelle réaction
                const addReactionBtn = document.createElement('button');
                addReactionBtn.className = 'reaction-pill add-reaction';
                addReactionBtn.innerHTML = '➕';
                addReactionBtn.title = 'Ajouter une réaction';
                addReactionBtn.onclick = (e) => {
                    e.stopPropagation();
                    toggleReactionPicker(msg.id, msgWrapper);
                };
                reactionsContainer.appendChild(addReactionBtn);
                
                msgBubble.appendChild(reactionsContainer);
            }
        }

        // Footer avec timestamp
        const footer = document.createElement('div');
        footer.className = 'message-meta';
        
        const timeEl = document.createElement('span');
        timeEl.className = 'message-time';
        timeEl.textContent = new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        footer.appendChild(timeEl);
        
        msgBubble.appendChild(footer);
        msgWrapper.appendChild(msgBubble);

        // Menu d'actions (visible au hover)
        if (!msg.deleted) {
            const actionsMenu = document.createElement('div');
            actionsMenu.className = 'message-actions-menu';

            // Bouton réaction (ouvre le picker)
            const reactionBtn = document.createElement('button');
            reactionBtn.className = 'action-btn reaction-btn';
            reactionBtn.innerHTML = '➕';
            reactionBtn.title = 'Ajouter une réaction';
            reactionBtn.onclick = (e) => {
                e.stopPropagation();
                toggleReactionPicker(msg.id, msgWrapper);
            };
            actionsMenu.appendChild(reactionBtn);

            // Bouton répondre
            const replyBtn = document.createElement('button');
            replyBtn.className = 'action-btn reply-btn';
            replyBtn.innerHTML = '↩';
            replyBtn.title = 'Répondre';
            replyBtn.onclick = () => setReplyPreview(msg.id, isReceiver);
            actionsMenu.appendChild(replyBtn);
            
            // Bouton épingler
            const pinBtn = document.createElement('button');
            pinBtn.className = 'action-btn pin-btn';
            pinBtn.innerHTML = pinnedMessageIds.has(msg.id) ? '📌' : '📍';
            pinBtn.title = pinnedMessageIds.has(msg.id) ? 'Désépingler' : 'Épingler';
            pinBtn.onclick = () => togglePinMessage(msg.id);
            actionsMenu.appendChild(pinBtn);

            // Boutons éditer/supprimer (uniquement pour mes messages)
            if (msg.isSent) {
                const editBtn = document.createElement('button');
                editBtn.className = 'action-btn edit-btn';
                editBtn.innerHTML = '✏️';
                editBtn.title = 'Modifier';
                editBtn.onclick = () => startEditingMessage(msg.id);
                actionsMenu.appendChild(editBtn);

                const deleteBtn = document.createElement('button');
                deleteBtn.className = 'action-btn delete-btn';
                deleteBtn.innerHTML = '🗑️';
                deleteBtn.title = 'Supprimer';
                deleteBtn.onclick = () => {
                    if (confirm('Supprimer ce message ?')) {
                        deleteMessage(msg.id);
                    }
                };
                actionsMenu.appendChild(deleteBtn);
            }

            msgWrapper.appendChild(actionsMenu);
        }

        containerEl.appendChild(msgWrapper);
    });

    containerEl.scrollTop = containerEl.scrollHeight;
}

function toggleQuickReaction(messageId, emoji) {
    const msg = findMessageById(messageId);
    if (!msg || msg.deleted) return;
    const users = msg.reactions?.[emoji] || [];
    const already = users.includes(userPseudo);
    const updated = already ? users.filter(u => u !== userPseudo) : [...users, userPseudo];
    msg.reactions = { ...msg.reactions, [emoji]: updated };

    broadcastToAllPeers({
        type: 'chat-reaction',
        messageId,
        emoji,
        pseudo: userPseudo,
        action: already ? 'remove' : 'add'
    });

    const container = isReceiver ? elements.receiverChatMessages : elements.chatMessages;
    renderChatMessages(container);
}

function toggleReactionPicker(messageId, msgWrapper) {
    // Fermer tout picker ouvert
    document.querySelectorAll('.reaction-picker-popup').forEach(p => p.remove());
    
    const reactionList = ['👍', '❤️', '😂', '😮', '😢', '👏', '🔥', '🎉'];
    
    const picker = document.createElement('div');
    picker.className = 'reaction-picker-popup';
    
    reactionList.forEach(emoji => {
        const btn = document.createElement('button');
        btn.className = 'reaction-option';
        btn.textContent = emoji;
        btn.onclick = (e) => {
            e.stopPropagation();
            toggleQuickReaction(messageId, emoji);
            picker.remove();
        };
        picker.appendChild(btn);
    });
    
    // Ajouter au body pour éviter les problèmes de débordement
    document.body.appendChild(picker);
    
    // Positionner le picker près du message
    const wrapperRect = msgWrapper.getBoundingClientRect();
    const pickerWidth = 280; // Largeur approximative du picker
    const pickerHeight = 50; // Hauteur approximative
    
    // Position horizontale: centré par rapport au message
    let left = wrapperRect.left + (wrapperRect.width / 2) - (pickerWidth / 2);
    
    // Vérifier les limites horizontales
    if (left < 10) left = 10;
    if (left + pickerWidth > window.innerWidth - 10) {
        left = window.innerWidth - pickerWidth - 10;
    }
    
    // Position verticale: au-dessus du message si possible, sinon en-dessous
    let top = wrapperRect.top - pickerHeight - 10;
    if (top < 10) {
        top = wrapperRect.bottom + 10;
    }
    
    picker.style.position = 'fixed';
    picker.style.left = left + 'px';
    picker.style.top = top + 'px';
    picker.style.zIndex = '10000';
    
    // Fermer au clic extérieur
    setTimeout(() => {
        document.addEventListener('click', function closePickerOnce(e) {
            if (!picker.contains(e.target)) {
                picker.remove();
            }
            document.removeEventListener('click', closePickerOnce);
        });
    }, 10);
}

function startEditingMessage(messageId) {
    const msg = findMessageById(messageId);
    if (!msg || !msg.isSent || msg.deleted) return;
    
    editingMessageId = messageId;
    replyToMessageId = null;
    
    const { inputEl } = getActiveChatElements(isReceiver);
    if (!inputEl) return;
    
    inputEl.value = msg.text;
    inputEl.focus();
    inputEl.setSelectionRange(msg.text.length, msg.text.length);
    
    // Ajouter un indicateur visuel d'édition
    const editingIndicator = document.createElement('div');
    editingIndicator.className = 'editing-indicator';
    editingIndicator.innerHTML = `
        <span>✏️ Modification du message</span>
        <button class="cancel-edit-btn" onclick="cancelEditing()">Annuler</button>
    `;
    
    const inputContainer = inputEl.parentElement;
    const existingIndicator = inputContainer.querySelector('.editing-indicator');
    if (existingIndicator) existingIndicator.remove();
    
    inputContainer.insertBefore(editingIndicator, inputEl);
}

function cancelEditing() {
    editingMessageId = null;
    const { inputEl } = getActiveChatElements(isReceiver);
    if (inputEl) {
        inputEl.value = '';
        inputEl.placeholder = 'Votre message...';
    }
    
    document.querySelectorAll('.editing-indicator').forEach(ind => ind.remove());
}

function deleteMessage(messageId) {
    const msg = findMessageById(messageId);
    if (!msg || !msg.isSent) return;
    msg.deleted = true;
    broadcastToAllPeers({
        type: 'chat-delete',
        messageId,
        pseudo: userPseudo
    });
    const container = isReceiver ? elements.receiverChatMessages : elements.chatMessages;
    renderChatMessages(container);
}

function sendTypingSignal(isReceiverSide) {
    const hasConnectedPeer = Array.from(peers.values()).some(p => p.connected);
    if (!hasConnectedPeer) return;
    broadcastToAllPeers({ type: 'chat-typing', pseudo: userPseudo, timestamp: Date.now() });
    clearTimeout(typingSignalTimeout);
    typingSignalTimeout = setTimeout(() => {
        broadcastToAllPeers({ type: 'chat-typing', pseudo: userPseudo, stop: true, timestamp: Date.now() });
    }, 2000);
}

function handleTypingSignal(data, fromOdId) {
    if (data.stop) {
        updateChatStatus(true);
        return;
    }
    const pseudo = data.pseudo || participants.get(fromOdId)?.pseudo || 'Quelqu\'un';
    const { statusEl } = getActiveChatElements(isReceiver);
    if (!statusEl) return;
    statusEl.textContent = `${pseudo} écrit...`;
    statusEl.classList.add('typing');
    clearTimeout(typingIndicatorTimer);
    typingIndicatorTimer = setTimeout(() => updateChatStatus(true), 2500);
}

async function handleChatEdit(data, fromOdId) {
    try {
        let text;
        
        if (data.text) {
            // Nouveau format: déjà déchiffré
            text = data.text;
        } else if (data.iv && data.ciphertext) {
            // Ancien format: déchiffrer avec AES-GCM
            const iv = fromBase64(data.iv);
            const ciphertext = fromBase64(data.ciphertext);
            const decrypted = await window.crypto.subtle.decrypt(
                { name: 'AES-GCM', iv },
                cryptoKey,
                ciphertext
            );
            text = new TextDecoder().decode(decrypted);
        } else {
            console.error('❌ Format d\'édition invalide');
            return;
        }
        
        const msg = findMessageById(data.messageId);
        if (msg) {
            msg.text = text;
            msg.edited = true;
            msg.deleted = false;
        }
        const container = isReceiver ? elements.receiverChatMessages : elements.chatMessages;
        renderChatMessages(container);
    } catch (err) {
        console.error('❌ Erreur handleChatEdit:', err);
    }
}

function handleChatDelete(data) {
    const msg = findMessageById(data.messageId);
    if (msg) {
        msg.deleted = true;
        const container = isReceiver ? elements.receiverChatMessages : elements.chatMessages;
        renderChatMessages(container);
    }
}

function handleChatReaction(data) {
    const msg = findMessageById(data.messageId);
    if (!msg || msg.deleted) return;
    const list = msg.reactions?.[data.emoji] || [];
    const exists = list.includes(data.pseudo);
    let updated = list;
    if (data.action === 'add' && !exists) {
        updated = [...list, data.pseudo];
    } else if (data.action === 'remove' && exists) {
        updated = list.filter(u => u !== data.pseudo);
    }
    msg.reactions = { ...msg.reactions, [data.emoji]: updated };
    const container = isReceiver ? elements.receiverChatMessages : elements.chatMessages;
    renderChatMessages(container);
}

function updateChatStatus(connected) {
    const statusEls = [elements.chatStatus, elements.receiverChatStatus];
    const connectedPeers = Array.from(peers.values()).filter(p => p.connected).length;
    statusEls.forEach(el => {
        if (el) {
            el.textContent = connected ? `Connecté (${connectedPeers + 1} participants)` : 'En attente...';
            el.classList.toggle('connected', connected);
            el.classList.remove('typing');
        }
    });
}

// ===== RECHERCHE DANS LE CHAT =====

function setupChatSearch() {
    // Créateur
    const searchToggle = document.getElementById('chat-search-toggle');
    const searchBar = document.getElementById('chat-search-bar');
    const searchInput = document.getElementById('chat-search-input');
    const searchUserFilter = document.getElementById('chat-search-user-filter');
    const searchClear = document.getElementById('chat-search-clear');
    
    if (searchToggle && searchBar) {
        searchToggle.addEventListener('click', () => {
            searchBar.classList.toggle('hidden');
            if (!searchBar.classList.contains('hidden')) {
                searchInput?.focus();
                updateSearchUserFilter(false);
            }
        });
    }
    
    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            chatSearchQuery = e.target.value;
            renderChatMessages(elements.chatMessages);
        });
    }
    
    if (searchUserFilter) {
        searchUserFilter.addEventListener('change', (e) => {
            chatSearchUserFilter = e.target.value;
            renderChatMessages(elements.chatMessages);
        });
    }
    
    if (searchClear) {
        searchClear.addEventListener('click', () => {
            clearChatSearch(false);
        });
    }
    
    // Receiver
    const rSearchToggle = document.getElementById('receiver-chat-search-toggle');
    const rSearchBar = document.getElementById('receiver-chat-search-bar');
    const rSearchInput = document.getElementById('receiver-chat-search-input');
    const rSearchUserFilter = document.getElementById('receiver-chat-search-user-filter');
    const rSearchClear = document.getElementById('receiver-chat-search-clear');
    
    if (rSearchToggle && rSearchBar) {
        rSearchToggle.addEventListener('click', () => {
            rSearchBar.classList.toggle('hidden');
            if (!rSearchBar.classList.contains('hidden')) {
                rSearchInput?.focus();
                updateSearchUserFilter(true);
            }
        });
    }
    
    if (rSearchInput) {
        rSearchInput.addEventListener('input', (e) => {
            chatSearchQuery = e.target.value;
            renderChatMessages(elements.receiverChatMessages);
        });
    }
    
    if (rSearchUserFilter) {
        rSearchUserFilter.addEventListener('change', (e) => {
            chatSearchUserFilter = e.target.value;
            renderChatMessages(elements.receiverChatMessages);
        });
    }
    
    if (rSearchClear) {
        rSearchClear.addEventListener('click', () => {
            clearChatSearch(true);
        });
    }
}

function updateSearchUserFilter(isReceiverSide) {
    const selectEl = isReceiverSide 
        ? document.getElementById('receiver-chat-search-user-filter')
        : document.getElementById('chat-search-user-filter');
    
    if (!selectEl) return;
    
    // Garder l'option "Tous"
    selectEl.innerHTML = '<option value="">Tous les utilisateurs</option>';
    
    // Ajouter l'utilisateur courant
    const optionMe = document.createElement('option');
    optionMe.value = userPseudo;
    optionMe.textContent = userPseudo + ' (vous)';
    selectEl.appendChild(optionMe);
    
    // Ajouter les autres participants
    participants.forEach((info, odId) => {
        const opt = document.createElement('option');
        opt.value = info.pseudo;
        opt.textContent = info.pseudo;
        selectEl.appendChild(opt);
    });
}

function clearChatSearch(isReceiverSide) {
    chatSearchQuery = '';
    chatSearchUserFilter = '';
    
    const searchInput = isReceiverSide 
        ? document.getElementById('receiver-chat-search-input')
        : document.getElementById('chat-search-input');
    const userFilter = isReceiverSide 
        ? document.getElementById('receiver-chat-search-user-filter')
        : document.getElementById('chat-search-user-filter');
    const searchBar = isReceiverSide 
        ? document.getElementById('receiver-chat-search-bar')
        : document.getElementById('chat-search-bar');
    
    if (searchInput) searchInput.value = '';
    if (userFilter) userFilter.value = '';
    if (searchBar) searchBar.classList.add('hidden');
    
    const container = isReceiverSide ? elements.receiverChatMessages : elements.chatMessages;
    renderChatMessages(container);
}

function updateSearchResultsCount(count) {
    const countEl = isReceiver 
        ? document.getElementById('receiver-chat-search-count')
        : document.getElementById('chat-search-count');
    
    if (countEl) {
        if (chatSearchQuery || chatSearchUserFilter) {
            countEl.textContent = `${count} résultat(s)`;
            countEl.classList.remove('hidden');
        } else {
            countEl.textContent = '';
            countEl.classList.add('hidden');
        }
    }
}

function highlightSearchTerm(text, query) {
    if (!query) return text;
    const regex = new RegExp(`(${escapeRegex(query)})`, 'gi');
    return text.replace(regex, '<mark class="search-highlight">$1</mark>');
}

function escapeRegex(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ===== MESSAGES ÉPINGLÉS =====

function setupPinnedMessages() {
    // Créateur
    const pinsToggle = document.getElementById('chat-pins-toggle');
    if (pinsToggle) {
        pinsToggle.addEventListener('click', () => showPinnedModal(false));
    }
    
    // Receiver
    const rPinsToggle = document.getElementById('receiver-chat-pins-toggle');
    if (rPinsToggle) {
        rPinsToggle.addEventListener('click', () => showPinnedModal(true));
    }
}

function togglePinMessage(messageId) {
    if (pinnedMessageIds.has(messageId)) {
        pinnedMessageIds.delete(messageId);
        showToast('Message désépinglé');
    } else {
        pinnedMessageIds.add(messageId);
        showToast('📌 Message épinglé');
    }
    
    // Synchroniser avec les autres participants
    broadcastToAllPeers({
        type: 'chat-pin',
        messageId,
        action: pinnedMessageIds.has(messageId) ? 'pin' : 'unpin'
    });
    
    const container = isReceiver ? elements.receiverChatMessages : elements.chatMessages;
    renderChatMessages(container);
    renderPinnedMessages(isReceiver);
}

function handleChatPin(data) {
    if (data.action === 'pin') {
        pinnedMessageIds.add(data.messageId);
    } else {
        pinnedMessageIds.delete(data.messageId);
    }
    
    const container = isReceiver ? elements.receiverChatMessages : elements.chatMessages;
    renderChatMessages(container);
    renderPinnedMessages(isReceiver);
}

function renderPinnedMessages(isReceiverSide) {
    const listEl = isReceiverSide 
        ? document.getElementById('receiver-chat-pinned-list')
        : document.getElementById('chat-pinned-list');
    
    if (!listEl) return;
    listEl.innerHTML = '';
    
    if (pinnedMessageIds.size === 0) {
        listEl.innerHTML = '<p class="no-pins">Aucun message épinglé</p>';
        return;
    }
    
    pinnedMessageIds.forEach(msgId => {
        const msg = findMessageById(msgId);
        if (!msg || msg.deleted) return;
        
        const pinnedItem = document.createElement('div');
        pinnedItem.className = 'pinned-message-item';
        pinnedItem.onclick = () => scrollToMessage(msgId);
        
        const author = document.createElement('span');
        author.className = 'pinned-author';
        author.textContent = msg.isSent ? 'Vous' : (msg.pseudo || 'Anonyme');
        
        const text = document.createElement('span');
        text.className = 'pinned-text';
        text.textContent = msg.text.slice(0, 50) + (msg.text.length > 50 ? '…' : '');
        
        const unpinBtn = document.createElement('button');
        unpinBtn.className = 'unpin-btn';
        unpinBtn.innerHTML = '✕';
        unpinBtn.title = 'Désépingler';
        unpinBtn.onclick = (e) => {
            e.stopPropagation();
            togglePinMessage(msgId);
        };
        
        pinnedItem.appendChild(author);
        pinnedItem.appendChild(text);
        pinnedItem.appendChild(unpinBtn);
        listEl.appendChild(pinnedItem);
    });
}

function scrollToMessage(messageId) {
    const container = isReceiver ? elements.receiverChatMessages : elements.chatMessages;
    if (!container) return;
    
    const msgEl = container.querySelector(`[data-message-id="${messageId}"]`);
    if (msgEl) {
        msgEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
        msgEl.classList.add('highlight-flash');
        setTimeout(() => msgEl.classList.remove('highlight-flash'), 2000);
    }
}

// ===== EXPORT DE CONVERSATION =====

function openChatModal(innerHtml) {
    const existing = document.querySelector('.chat-modal');
    if (existing) existing.remove();
    ensureChatModalStyles();
    const overlay = document.createElement('div');
    overlay.className = 'chat-modal export-popup';
    overlay.innerHTML = innerHtml;
    document.body.appendChild(overlay);
    overlay.addEventListener('click', (e) => {
        if (e.target === overlay) overlay.remove();
    });
    overlay.querySelector('.modal-close')?.addEventListener('click', () => overlay.remove());
    return overlay;
}

function ensureChatModalStyles() {
    if (document.getElementById('chat-modal-styles')) return;
    const style = document.createElement('style');
    style.id = 'chat-modal-styles';
    style.textContent = `
    .chat-modal { position: fixed; inset: 0; display: flex; align-items: center; justify-content: center; z-index: 10000; background: rgba(0,0,0,0.5); padding: 12px; -webkit-backdrop-filter: blur(4px); backdrop-filter: blur(4px); }
    .modal-card { max-width: 560px; width: min(560px, 94vw); background: var(--bg, #fff); border-radius: 18px; box-shadow: 0 20px 50px rgba(0,0,0,0.3); padding: 24px; position: relative; }
    .modal-header { display: flex; gap: 12px; align-items: center; margin-bottom: 16px; }
    .modal-icon { width: 42px; height: 42px; border-radius: 12px; display: inline-flex; align-items: center; justify-content: center; background: rgba(0,102,255,0.12); font-size: 1.2rem; }
    .modal-close { position: absolute; top: 12px; right: 12px; background: transparent; border: none; font-size: 1.2rem; cursor: pointer; color: #666; padding: 6px; border-radius: 8px; }
    .modal-close:hover { background: rgba(0,0,0,0.06); }
    .export-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; margin: 12px 0 18px; }
    .option-card { border: 1px solid #ddd; border-radius: 12px; padding: 14px; text-align: left; background: #fff; cursor: pointer; transition: all 0.2s ease; }
    .option-card:hover { border-color: #0066ff; box-shadow: 0 6px 18px rgba(0,0,0,0.08); }
    .option-title { font-weight: 700; display: flex; align-items: center; gap: 6px; }
    .option-desc { margin: 6px 0 4px; color: #555; }
    .option-meta { font-size: 0.85rem; color: #777; }
    .modal-footer { display: flex; justify-content: space-between; align-items: center; gap: 10px; }
    .pinned-modal-list { max-height: 320px; overflow-y: auto; display: flex; flex-direction: column; gap: 10px; margin: 8px 0 14px; }
    .pinned-modal-item { border: 1px solid #ddd; border-radius: 10px; padding: 10px 12px; background: #f7f7f8; cursor: pointer; transition: all 0.2s ease; }
    .pinned-modal-item:hover { border-color: #0066ff; box-shadow: 0 6px 18px rgba(0,0,0,0.08); }
    .pinned-meta { display: flex; justify-content: space-between; font-size: 0.85rem; margin-bottom: 6px; color: #666; }
    .pinned-text { font-size: 0.95rem; color: #222; }
    .modal-note { font-size: 0.85rem; color: #666; }
    `;
    document.head.appendChild(style);
}

function setupChatExport() {
    // Créateur
    const exportBtn = document.getElementById('chat-export-btn');
    if (exportBtn) {
        exportBtn.addEventListener('click', () => showExportDialog());
    }
    
    // Receiver
    const rExportBtn = document.getElementById('receiver-chat-export-btn');
    if (rExportBtn) {
        rExportBtn.addEventListener('click', () => showExportDialog());
    }
}

function showExportDialog() {
    const popup = openChatModal(`
        <div class="export-content modal-card">
            <button class="modal-close" aria-label="Fermer">×</button>
            <div class="modal-header">
                <div class="modal-icon">📥</div>
                <div>
                    <h3>Exporter la conversation</h3>
                    <p class="modal-subtitle">Fichier local, rien n'est envoyé au serveur.</p>
                </div>
            </div>
            <div class="export-grid">
                <button class="option-card export-txt-btn">
                    <div class="option-icon">📄</div>
                    <div class="option-title">Texte (.txt) <span class="option-badge">Rapide</span></div>
                    <div class="option-desc">Brut et léger, lisible partout.</div>
                    <div class="option-meta">Idéal pour archiver</div>
                </button>
                <button class="option-card export-html-btn">
                    <div class="option-icon">🌐</div>
                    <div class="option-title">HTML stylé</div>
                    <div class="option-desc">Mise en page avec couleurs et badges.</div>
                    <div class="option-meta">Idéal pour imprimer</div>
                </button>
            </div>
            <div class="modal-footer">
                <span class="modal-note">⚠️ Les autres participants seront notifiés.</span>
                <button class="btn btn-secondary export-cancel-btn">Annuler</button>
            </div>
        </div>
    `);
    
    popup.querySelector('.export-txt-btn').addEventListener('click', () => {
        exportChatAsTxt();
        popup.remove();
    });
    
    popup.querySelector('.export-html-btn').addEventListener('click', () => {
        exportChatAsHtml();
        popup.remove();
    });
    
    popup.querySelector('.export-cancel-btn').addEventListener('click', () => popup.remove());
}

function exportChatAsTxt() {
    // Notifier les autres participants
    broadcastToAllPeers({
        type: 'chat-export-notify',
        pseudo: userPseudo,
        format: 'TXT'
    });
    
    let content = `SecurePeer - Export de conversation\n`;
    content += `Date: ${new Date().toLocaleString()}\n`;
    content += `Session: ${roomId}\n`;
    content += `Mode: ${sessionMode}\n`;
    content += `${'='.repeat(50)}\n\n`;
    
    chatMessages.forEach(msg => {
        if (msg.deleted) return;
        
        const time = new Date(msg.timestamp).toLocaleString();
        const author = msg.isSent ? userPseudo : (msg.pseudo || 'Anonyme');
        const edited = msg.edited ? ' (modifié)' : '';
        const pinned = pinnedMessageIds.has(msg.id) ? ' 📌' : '';
        
        content += `[${time}] ${author}${edited}${pinned}:\n`;
        content += `${msg.text}\n\n`;
    });
    
    content += `${'='.repeat(50)}\n`;
    content += `Total: ${chatMessages.filter(m => !m.deleted).length} messages\n`;
    
    downloadFile(content, `securepeer-chat-${roomId}.txt`, 'text/plain');
    showToast('✅ Conversation exportée en TXT');
}

function exportChatAsHtml() {
    // Notifier les autres participants
    broadcastToAllPeers({
        type: 'chat-export-notify',
        pseudo: userPseudo,
        format: 'HTML'
    });
    
    let html = `<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecurePeer - Export de conversation</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; background: #f5f5f5; }
        .header { background: #0066ff; color: white; padding: 20px; border-radius: 12px; margin-bottom: 20px; }
        .header h1 { margin: 0 0 10px 0; }
        .header p { margin: 5px 0; opacity: 0.9; }
        .message { background: white; padding: 12px 16px; margin: 8px 0; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .message.sent { background: #0066ff; color: white; margin-left: 20%; }
        .message.received { margin-right: 20%; }
        .message.pinned { border-left: 3px solid #f59e0b; }
        .meta { font-size: 0.8em; opacity: 0.7; margin-bottom: 4px; }
        .text { line-height: 1.5; }
        .badge { font-size: 0.75em; background: rgba(0,0,0,0.1); padding: 2px 6px; border-radius: 4px; margin-left: 5px; }
        .footer { text-align: center; color: #666; margin-top: 20px; padding-top: 20px; border-top: 1px solid #ddd; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 SecurePeer</h1>
        <p>Export de conversation</p>
        <p>Date: ${new Date().toLocaleString()}</p>
        <p>Session: ${roomId} | Mode: ${sessionMode}</p>
    </div>
    <div class="messages">`;
    
    chatMessages.forEach(msg => {
        if (msg.deleted) return;
        
        const time = new Date(msg.timestamp).toLocaleString();
        const author = msg.isSent ? userPseudo : (msg.pseudo || 'Anonyme');
        const edited = msg.edited ? '<span class="badge">modifié</span>' : '';
        const pinned = pinnedMessageIds.has(msg.id) ? ' pinned' : '';
        const pinnedBadge = pinnedMessageIds.has(msg.id) ? '<span class="badge">📌</span>' : '';
        
        html += `
        <div class="message ${msg.isSent ? 'sent' : 'received'}${pinned}">
            <div class="meta">${escapeHtml(author)} - ${time}${edited}${pinnedBadge}</div>
            <div class="text">${escapeHtml(msg.text)}</div>
        </div>`;
    });
    
    html += `
    </div>
    <div class="footer">
        <p>Total: ${chatMessages.filter(m => !m.deleted).length} messages</p>
        <p>Exporté depuis SecurePeer - Chiffrement E2E</p>
    </div>
</body>
</html>`;
    
    downloadFile(html, `securepeer-chat-${roomId}.html`, 'text/html');
    showToast('✅ Conversation exportée en HTML');
}

function downloadFile(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}

// ===== NOTIFICATION D'EXPORT =====

function handleExportNotify(data) {
    showToast(`📥 ${data.pseudo} a exporté la conversation (${data.format})`, 5000);
}

// ===== MESSAGES ÉPHÉMÈRES =====

function setupEphemeralMessages() {
    // Créateur
    const ephemeralToggle = document.getElementById('chat-ephemeral-toggle');
    if (ephemeralToggle) {
        ephemeralToggle.addEventListener('click', () => showEphemeralDialog());
        updateEphemeralButton(ephemeralToggle);
    }
    
    // Receiver
    const rEphemeralToggle = document.getElementById('receiver-chat-ephemeral-toggle');
    if (rEphemeralToggle) {
        rEphemeralToggle.addEventListener('click', () => showEphemeralDialog());
        updateEphemeralButton(rEphemeralToggle);
    }
}

function updateEphemeralButton(btn) {
    if (!btn) return;
    btn.classList.toggle('active', ephemeralMode);
    btn.title = ephemeralMode 
        ? `Messages éphémères: ${ephemeralDuration}s` 
        : 'Messages éphémères (désactivé)';
}

function showEphemeralDialog() {
    const popup = openChatModal(`
        <div class="export-content modal-card">
            <button class="modal-close" aria-label="Fermer">×</button>
            <div class="modal-header">
                <div class="modal-icon">⏱️</div>
                <div>
                    <h3>Messages éphémères</h3>
                    <p class="modal-subtitle">Suppression automatique après le délai choisi.</p>
                </div>
            </div>
            <div class="ephemeral-body">
                <label class="toggle-row">
                    <span>Activer</span>
                    <input type="checkbox" id="ephemeral-enabled" ${ephemeralMode ? 'checked' : ''}>
                </label>
                <div class="ephemeral-duration-row">
                    <label for="ephemeral-duration-select">Durée</label>
                    <select id="ephemeral-duration-select">
                        <option value="10" ${ephemeralDuration === 10 ? 'selected' : ''}>10 secondes</option>
                        <option value="30" ${ephemeralDuration === 30 ? 'selected' : ''}>30 secondes</option>
                        <option value="60" ${ephemeralDuration === 60 ? 'selected' : ''}>1 minute</option>
                        <option value="300" ${ephemeralDuration === 300 ? 'selected' : ''}>5 minutes</option>
                        <option value="600" ${ephemeralDuration === 600 ? 'selected' : ''}>10 minutes</option>
                    </select>
                </div>
                <p class="modal-note">⚠️ Synchronisé avec tous les participants.</p>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary ephemeral-cancel-btn">Annuler</button>
                <button class="btn btn-primary ephemeral-save-btn">Appliquer</button>
            </div>
        </div>
    `);
    
    popup.querySelector('.ephemeral-save-btn').addEventListener('click', () => {
        const enabled = popup.querySelector('#ephemeral-enabled').checked;
        const duration = parseInt(popup.querySelector('#ephemeral-duration-select').value);
        
        ephemeralMode = enabled;
        ephemeralDuration = duration;
        
        // Synchroniser avec les autres
        broadcastToAllPeers({
            type: 'chat-ephemeral-sync',
            enabled: ephemeralMode,
            duration: ephemeralDuration,
            pseudo: userPseudo
        });
        
        updateAllEphemeralButtons();
        showToast(ephemeralMode 
            ? `⏱️ Messages éphémères: ${ephemeralDuration}s` 
            : '⏱️ Messages éphémères désactivés');
        popup.remove();
    });
    
    popup.querySelector('.ephemeral-cancel-btn').addEventListener('click', () => popup.remove());
}

function showPinnedModal(isReceiverSide) {
    const items = [];
    pinnedMessageIds.forEach(id => {
        const msg = findMessageById(id);
        if (!msg || msg.deleted) return;
        const author = msg.isSent ? 'Vous' : (msg.pseudo || 'Anonyme');
        const preview = msg.text.slice(0, 120) + (msg.text.length > 120 ? '…' : '');
        items.push(`
            <div class="pinned-modal-item" data-id="${id}">
                <div class="pinned-meta">
                    <span class="pinned-author">${escapeHtml(author)}</span>
                    <span class="pinned-time">${new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                </div>
                <div class="pinned-text">${escapeHtml(preview)}</div>
            </div>
        `);
    });
    const listHtml = items.length ? items.join('') : '<div class="no-pins">Aucun message épinglé</div>';
    const popup = openChatModal(`
        <div class="export-content modal-card">
            <button class="modal-close" aria-label="Fermer">×</button>
            <div class="modal-header">
                <div class="modal-icon">📌</div>
                <div>
                    <h3>Messages épinglés</h3>
                    <p class="modal-subtitle">Clique pour naviguer dans la conversation.</p>
                </div>
            </div>
            <div class="pinned-modal-list">${listHtml}</div>
            <div class="modal-footer">
                <span class="modal-note">Synchronisé entre tous les participants.</span>
                <button class="btn btn-secondary export-cancel-btn">Fermer</button>
            </div>
        </div>
    `);
    popup.querySelectorAll('.pinned-modal-item').forEach(el => {
        el.addEventListener('click', () => {
            const id = el.getAttribute('data-id');
            scrollToMessage(id);
            popup.remove();
        });
    });
    popup.querySelector('.export-cancel-btn')?.addEventListener('click', () => popup.remove());
}

function handleEphemeralSync(data) {
    ephemeralMode = data.enabled;
    ephemeralDuration = data.duration;
    updateAllEphemeralButtons();
    showToast(data.enabled 
        ? `⏱️ ${data.pseudo} a activé les messages éphémères (${data.duration}s)`
        : `⏱️ ${data.pseudo} a désactivé les messages éphémères`);
}

function updateAllEphemeralButtons() {
    updateEphemeralButton(document.getElementById('chat-ephemeral-toggle'));
    updateEphemeralButton(document.getElementById('receiver-chat-ephemeral-toggle'));
}

function scheduleMessageDeletion(messageId, delay) {
    if (!ephemeralMode) return;
    
    setTimeout(() => {
        const msg = findMessageById(messageId);
        if (msg && !msg.deleted) {
            msg.deleted = true;
            msg.text = '💨 Message éphémère expiré';
            const container = isReceiver ? elements.receiverChatMessages : elements.chatMessages;
            renderChatMessages(container);
        }
    }, delay * 1000);
}

// ===== MODE BOTH - FICHIERS BIDIRECTIONNELS =====
let pendingBothFiles = []; // Fichiers en attente d'envoi

function setupBothModeFiles() {
    // Sender side
    if (elements.bothFileInput) {
        elements.bothFileInput.addEventListener('change', (e) => {
            handleBothFileSelect(e.target.files, false);
            e.target.value = '';
        });
    }
    if (elements.bothFileSend) {
        elements.bothFileSend.addEventListener('click', () => sendBothFiles(false));
    }
    
    // Receiver side
    if (elements.receiverBothFileInput) {
        elements.receiverBothFileInput.addEventListener('change', (e) => {
            handleBothFileSelect(e.target.files, true);
            e.target.value = '';
        });
    }
    if (elements.receiverBothFileSend) {
        elements.receiverBothFileSend.addEventListener('click', () => sendBothFiles(true));
    }
}

function handleBothFileSelect(files, isReceiverSide) {
    if (!files || files.length === 0) return;
    
    const listEl = isReceiverSide ? elements.receiverBothFileList : elements.bothFileList;
    const sendBtn = isReceiverSide ? elements.receiverBothFileSend : elements.bothFileSend;
    
    for (const file of files) {
        pendingBothFiles.push({ file, isReceiverSide });
        
        // Ajouter à la liste visuelle
        const itemDiv = document.createElement('div');
        itemDiv.className = 'both-file-item pending-send';
        itemDiv.dataset.fileName = file.name;
        itemDiv.innerHTML = `
            <span class="file-icon">📄</span>
            <div class="file-details">
                <span class="file-name">${escapeHtml(file.name)}</span>
                <span class="file-size">${formatFileSize(file.size)}</span>
            </div>
            <span class="file-status pending">En attente</span>
        `;
        listEl.appendChild(itemDiv);
    }
    
    sendBtn.disabled = pendingBothFiles.length === 0;
}

async function sendBothFiles(isReceiverSide) {
    const filesToSend = pendingBothFiles.filter(f => f.isReceiverSide === isReceiverSide);
    const hasConnectedPeer = Array.from(peers.values()).some(p => p.connected);
    if (filesToSend.length === 0 || !hasConnectedPeer) return;
    
    const sendBtn = isReceiverSide ? elements.receiverBothFileSend : elements.bothFileSend;
    sendBtn.disabled = true;
    
    for (const { file } of filesToSend) {
        try {
            await sendBothFile(file, isReceiverSide);
            
            // Mettre à jour le statut dans la liste
            const listEl = isReceiverSide ? elements.receiverBothFileList : elements.bothFileList;
            const itemEl = listEl.querySelector(`[data-file-name="${file.name}"]`);
            if (itemEl) {
                itemEl.classList.remove('pending-send');
                const statusEl = itemEl.querySelector('.file-status');
                if (statusEl) {
                    statusEl.textContent = 'Envoyé';
                    statusEl.classList.remove('pending');
                }
            }
        } catch (err) {
            console.error('❌ Erreur envoi fichier:', err);
            showToast('Erreur lors de l\'envoi de ' + file.name);
        }
    }
    
    // Retirer les fichiers envoyés de la liste
    pendingBothFiles = pendingBothFiles.filter(f => f.isReceiverSide !== isReceiverSide);
}

async function sendBothFile(file, isReceiverSide) {
    // Lire le fichier
    const arrayBuffer = await file.arrayBuffer();
    const data = new Uint8Array(arrayBuffer);
    
    // Chiffrer
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        cryptoKey,
        data
    );
    
    // Envoyer les métadonnées à tous les peers
    broadcastToAllPeers({
        type: 'both-file-meta',
        name: file.name,
        size: file.size,
        mimeType: file.type || 'application/octet-stream',
        iv: toBase64(iv),
        senderPseudo: userPseudo
    });
    
    // Envoyer les données chiffrées en chunks
    const encryptedData = new Uint8Array(encrypted);
    const chunkSize = 64 * 1024;
    let offset = 0;
    let index = 0;
    
    while (offset < encryptedData.length) {
        const chunk = encryptedData.slice(offset, offset + chunkSize);
        broadcastToAllPeers({
            type: 'both-file-chunk',
            index: index,
            data: Array.from(chunk)
        });
        offset += chunkSize;
        index++;
        
        // Petit délai pour éviter de saturer le buffer
        await new Promise(resolve => setTimeout(resolve, 5));
    }
    
    // Signaler la fin
    broadcastToAllPeers({
        type: 'both-file-complete',
        name: file.name
    });
    
    console.log('📤 Fichier envoyé à tous les participants:', file.name);
}

// Variables pour la réception de fichiers en mode both
let incomingBothFile = null;
let incomingBothChunks = [];

async function handleBothFileMeta(data) {
    incomingBothFile = {
        name: data.name,
        size: data.size,
        mimeType: data.mimeType,
        iv: fromBase64(data.iv),
        senderPseudo: data.senderPseudo || 'Anonyme'
    };
    incomingBothChunks = [];
    
    // Ajouter à la liste visuelle
    const listEl = isReceiver ? elements.receiverBothFileList : elements.bothFileList;
    const itemDiv = document.createElement('div');
    itemDiv.className = 'both-file-item';
    itemDiv.dataset.fileName = data.name;
    itemDiv.innerHTML = `
        <span class="file-icon">📥</span>
        <div class="file-details">
            <span class="file-sender">${escapeHtml(incomingBothFile.senderPseudo)}</span>
            <span class="file-name">${escapeHtml(data.name)}</span>
            <span class="file-size">${formatFileSize(data.size)}</span>
        </div>
        <span class="file-status pending">Réception...</span>
    `;
    listEl.appendChild(itemDiv);
    
    console.log('📥 Réception fichier de', incomingBothFile.senderPseudo, ':', data.name);
}

function handleBothFileChunk(data) {
    incomingBothChunks[data.index] = new Uint8Array(data.data);
}

async function handleBothFileComplete(data) {
    if (!incomingBothFile) return;
    
    try {
        // Reconstituer les données chiffrées
        const totalLength = incomingBothChunks.reduce((acc, chunk) => acc + chunk.length, 0);
        const encryptedData = new Uint8Array(totalLength);
        let offset = 0;
        for (const chunk of incomingBothChunks) {
            encryptedData.set(chunk, offset);
            offset += chunk.length;
        }
        
        // Déchiffrer
        const decrypted = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: incomingBothFile.iv },
            cryptoKey,
            encryptedData
        );
        
        // Créer le blob et proposer le téléchargement
        const blob = new Blob([decrypted], { type: incomingBothFile.mimeType });
        const url = URL.createObjectURL(blob);
        
        // Mettre à jour la liste avec un bouton de téléchargement
        const listEl = isReceiver ? elements.receiverBothFileList : elements.bothFileList;
        const itemEl = listEl.querySelector(`[data-file-name="${data.name}"]`);
        if (itemEl) {
            const statusEl = itemEl.querySelector('.file-status');
            if (statusEl) {
                statusEl.outerHTML = `<a href="${url}" download="${data.name}" class="btn btn-small file-action">📥 Télécharger</a>`;
            }
            itemEl.querySelector('.file-icon').textContent = '✅';
        }
        
        console.log('✅ Fichier reçu:', data.name);
        showToast('Fichier reçu: ' + data.name);
    } catch (err) {
        console.error('❌ Erreur déchiffrement fichier:', err);
        showToast('Erreur lors de la réception du fichier');
    }
    
    incomingBothFile = null;
    incomingBothChunks = [];
}

// Démarrer l'application
// document.addEventListener('DOMContentLoaded', init);

// Vérifier et afficher le popup Tor Browser pour la première utilisation
function checkAndShowTorPopup() {
    const torPopupDismissed = localStorage.getItem('torPopupDismissed');
    
    // Afficher seulement si jamais affiché ou pas définitivement masqué
    if (!torPopupDismissed) {
        const torPopup = document.getElementById('tor-popup');
        const torDismissBtn = document.getElementById('tor-dismiss');
        const torDontShow = document.getElementById('tor-dont-show');
        
        // Afficher le popup après 1 seconde
        setTimeout(() => {
            torPopup.classList.remove('hidden');
        }, 1000);
        
        // Bouton "Continuer sans Tor"
        torDismissBtn.addEventListener('click', () => {
            torPopup.classList.add('hidden');
            
            // Si l'utilisateur a coché "Ne plus afficher"
            if (torDontShow.checked) {
                localStorage.setItem('torPopupDismissed', 'true');
            }
        });
        
        // Fermer aussi en cliquant sur le fond
        torPopup.addEventListener('click', (e) => {
            if (e.target === torPopup) {
                torPopup.classList.add('hidden');
                if (torDontShow.checked) {
                    localStorage.setItem('torPopupDismissed', 'true');
                }
            }
        });
    }
}

// Afficher le badge "Session éphémère" quand une session est active
function showEphemeralBadge() {
    const badge = document.getElementById('ephemeral-badge');
    if (badge) {
        badge.classList.remove('hidden');
    }
}

// Masquer le badge "Session éphémère"
function hideEphemeralBadge() {
    const badge = document.getElementById('ephemeral-badge');
    if (badge) {
        badge.classList.add('hidden');
    }
}

// Recharger la page quand le hash change (pour coller un nouveau lien)
window.addEventListener('hashchange', () => {
    // Forcer un rechargement complet depuis le serveur
    window.location.reload(true);
});

// Détecter aussi les changements via popstate (bouton retour/avant)
window.addEventListener('popstate', () => {
    window.location.reload(true);
});
