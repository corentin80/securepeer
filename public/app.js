/**
 * P2P File Transfer - Application principale
 * Transfert de fichiers chiffrÃ© E2E via WebRTC
 */

// ===== CONFIGURATION =====
const CHUNK_SIZE = 64 * 1024; // 64 Ko par morceau


const STUN_SERVERS = [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' },
    { urls: 'stun:stun2.l.google.com:19302' }
];
const KDF_ITERATIONS = 200000; // itÃ©rations PBKDF2 pour le mot de passe
const PASSWORD_SALT_BYTES = 16;

// ===== Ã‰TAT GLOBAL =====
let ws = null;
let peers = new Map(); // Map<odId, SimplePeer> - un peer par participant
let myOdId = null; // Mon identifiant unique dans la room
let participants = new Map(); // Map<odId, {pseudo, isCreator}> - liste des participants
let isCreator = false; // Suis-je le crÃ©ateur de la room ?
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
let replyToMessageId = null; // message cible pour une rÃ©ponse/quote
let editingMessageId = null; // message en cours d'Ã©dition
let typingSignalTimeout = null; // debounce pour signaux "typing"
let typingIndicatorTimer = null; // timer d'effacement du statut "X Ã©crit..."

// Chat search and pinned messages
let chatSearchQuery = '';
let chatSearchUserFilter = '';
let pinnedMessageIds = new Set(); // IDs des messages Ã©pinglÃ©s

// Messages Ã©phÃ©mÃ¨res
let ephemeralMode = true; // ActivÃ© par dÃ©faut pour la sÃ©curitÃ©
let ephemeralDuration = 30; // secondes par dÃ©faut
let ephemeralCountdowns = new Map(); // Map<messageId, intervalId> - timers de countdown

// Session security options
let sessionOptions = {
    expirationMinutes: 0,      // 0 = illimitÃ©
    maxParticipants: 20,       // 1-20
    requireApproval: false,    // Approbation manuelle des participants
    autoLock: false,           // Verrouiller aprÃ¨s 1er participant
    isLocked: false            // Ã‰tat actuel du verrouillage
};
let pendingApprovals = new Map(); // Map<odId, {pseudo, timestamp}> - participants en attente d'approbation

// ===== ECDH (Diffie-Hellman) Ã‰tat =====
let ecdhKeyPair = null; // Ma paire de clÃ©s ECDH {privateKey, publicKey}
let ecdhPublicKeyB64 = null; // Ma clÃ© publique en base64 pour partage
let pendingKeyExchanges = new Map(); // Map<odId, {publicKeyB64, resolved}> - Ã©changes en attente
let keyExchangeResolvers = new Map(); // Map<odId, {resolve, reject}> - promesses d'Ã©change

// ===== SAFETY NUMBERS =====
let myFingerprint = null; // Mon fingerprint (safety number)
let peerFingerprints = new Map(); // Map<odId, fingerprint> - fingerprints de session actuelle
let knownFingerprints = new Map(); // Map<pseudo, fingerprint> - fingerprints connus persistants

// ===== Ã‰LÃ‰MENTS DOM =====
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
    // UnifiÃ©: receiver utilise les mÃªmes Ã©lÃ©ments
    receiverConnectedUsersSection: document.getElementById('connected-users-section'),
    receiverConnectedUsersDropdown: document.getElementById('connected-users-dropdown'),
    
    // Chat (unifiÃ© - utilisÃ© par tous)
    chatSection: document.getElementById('chat-section'),
    chatMessages: document.getElementById('chat-messages'),
    chatInput: document.getElementById('chat-input'),
    chatSend: document.getElementById('chat-send'),
    chatStatus: document.getElementById('chat-status'),
    
    // Receiver (Ã©lÃ©ments spÃ©cifiques pour mot de passe / fichiers entrants)
    receiverSection: document.getElementById('sender-section'), // UnifiÃ©: utilise sender-section
    receiverPasswordBlock: document.getElementById('password-block'), // UnifiÃ©: utilise password-block
    receiverPassword: document.getElementById('password-input'), // UnifiÃ©: utilise password-input
    receiverPasswordApply: document.getElementById('send-file-btn'), // UnifiÃ©
    incomingFileName: document.getElementById('file-name'), // UnifiÃ©
    incomingFileSize: document.getElementById('file-size'), // UnifiÃ©
    receiverStatus: document.getElementById('link-status'), // UnifiÃ©
    receiveFileBtn: document.getElementById('send-file-btn'), // UnifiÃ©
    
    // Chat receiver = Chat unifiÃ©
    receiverChatSection: document.getElementById('chat-section'), // UnifiÃ©
    receiverChatMessages: document.getElementById('chat-messages'), // UnifiÃ©
    receiverChatInput: document.getElementById('chat-input'), // UnifiÃ©
    receiverChatSend: document.getElementById('chat-send'), // UnifiÃ©
    receiverChatStatus: document.getElementById('chat-status'), // UnifiÃ©
    
    // Both mode - file sections (unifiÃ©)
    bothFileSection: document.getElementById('both-file-section'),
    bothFileList: document.getElementById('both-file-list'),
    bothFileInput: document.getElementById('both-file-input'),
    bothFileSend: document.getElementById('both-file-send'),
    receiverBothFileSection: document.getElementById('both-file-section'), // UnifiÃ©
    receiverBothFileList: document.getElementById('both-file-list'), // UnifiÃ©
    receiverBothFileInput: document.getElementById('both-file-input'), // UnifiÃ©
    receiverBothFileSend: document.getElementById('both-file-send'), // UnifiÃ©
    receiverTitle: document.getElementById('progress-title'), // UnifiÃ©,
    
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

// ===== SYSTÃˆME D'APPROBATION ET VERROUILLAGE =====

function showApprovalRequest(odId, pseudo) {
    // CrÃ©er une popup pour approuver/refuser
    const existing = document.querySelector('.approval-popup');
    if (existing) existing.remove();
    
    const popup = document.createElement('div');
    popup.className = 'approval-popup';
    popup.innerHTML = `
        <div class="approval-content">
            <h3>âœ‹ Demande d'accÃ¨s</h3>
            <p><strong>${escapeHtml(pseudo)}</strong> souhaite rejoindre la session</p>
            <div class="approval-actions">
                <button class="btn btn-success approve-btn" data-odid="${odId}">âœ“ Accepter</button>
                <button class="btn btn-danger reject-btn" data-odid="${odId}">âœ• Refuser</button>
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
        showToast('âœ… Participant acceptÃ©');
        
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
        showToast('âŒ Participant refusÃ©');
        
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
        lockBtn.textContent = sessionOptions.isLocked ? 'ðŸ”“ DÃ©verrouiller' : 'ðŸ”’ Verrouiller';
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

// ===== SÃ‰CURITÃ‰ - Ã‰chappement HTML pour prÃ©venir XSS =====
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
        throw new Error('La Web Crypto API n\'est pas disponible dans ce navigateur. Utilisez Chrome, Firefox, Edge ou Safari rÃ©cent.');
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
    // GÃ©nÃ©rer une clÃ© AES-GCM 256 bits
    cryptoKey = await window.crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true, // extractable
        ['encrypt', 'decrypt']
    );
    
    // GÃ©nÃ©rer un IV (Initialization Vector) de 12 octets
    cryptoIV = window.crypto.getRandomValues(new Uint8Array(12));
    
    console.log('ðŸ” ClÃ© de chiffrement gÃ©nÃ©rÃ©e');
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
        true, // extractable = true pour pouvoir rÃ©-exporter la clÃ©
        ['encrypt', 'decrypt']
    );
    
    console.log('ðŸ” ClÃ© de chiffrement importÃ©e');
}

async function encryptChunk(data) {
    // GÃ©nÃ©rer un IV unique pour chaque chunk
    const chunkIV = window.crypto.getRandomValues(new Uint8Array(12));
    
    const encrypted = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: chunkIV },
        cryptoKey,
        data
    );
    
    // Combiner IV + donnÃ©es chiffrÃ©es
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

// ===== SAFETY NUMBERS (Fingerprint Verification) =====

/**
 * GÃ©nÃ¨re un fingerprint (safety number) depuis une clÃ© publique ECDH
 * Format: 12 groupes de 4 chiffres (style Signal)
 * @param {CryptoKey} publicKey - ClÃ© publique ECDH
 * @returns {Promise<string>} - Fingerprint formatÃ© "1234 5678 9012 ..."
 */
async function generateFingerprint(publicKey) {
    // Exporter la clÃ© publique en format brut
    const publicKeyBytes = await window.crypto.subtle.exportKey('raw', publicKey);
    
    // SHA-256 du contenu de la clÃ©
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', publicKeyBytes);
    const hashArray = new Uint8Array(hashBuffer);
    
    // Convertir en chaÃ®ne de chiffres (prendre 48 chiffres = 12 groupes de 4)
    let numericString = '';
    for (let i = 0; i < hashArray.length && numericString.length < 48; i++) {
        numericString += hashArray[i].toString().padStart(3, '0');
    }
    
    // DÃ©couper en groupes de 4 chiffres
    const groups = [];
    for (let i = 0; i < 48; i += 4) {
        groups.push(numericString.substr(i, 4));
    }
    
    return groups.join(' ');
}

/**
 * GÃ©nÃ¨re un fingerprint depuis une clÃ© publique en base64
 * @param {string} publicKeyB64 - ClÃ© publique ECDH en base64
 * @returns {Promise<string>} - Fingerprint formatÃ©
 */
async function generateFingerprintFromB64(publicKeyB64) {
    const publicKeyBytes = Uint8Array.from(atob(publicKeyB64), c => c.charCodeAt(0));
    
    // SHA-256
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', publicKeyBytes);
    const hashArray = new Uint8Array(hashBuffer);
    
    // Convertir en numÃ©rique
    let numericString = '';
    for (let i = 0; i < hashArray.length && numericString.length < 48; i++) {
        numericString += hashArray[i].toString().padStart(3, '0');
    }
    
    // Groupes de 4
    const groups = [];
    for (let i = 0; i < 48; i += 4) {
        groups.push(numericString.substr(i, 4));
    }
    
    return groups.join(' ');
}

// ===== ECDH (Diffie-Hellman Elliptic Curve) =====

/**
 * GÃ©nÃ¨re une paire de clÃ©s ECDH (Elliptic Curve Diffie-Hellman)
 * Utilise la courbe P-256 (secp256r1) recommandÃ©e par le NIST
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
    
    // Exporter la clÃ© publique en format raw pour partage
    const publicKeyRaw = await window.crypto.subtle.exportKey('raw', ecdhKeyPair.publicKey);
    ecdhPublicKeyB64 = btoa(String.fromCharCode(...new Uint8Array(publicKeyRaw)));
    
    // GÃ©nÃ©rer le fingerprint (safety number)
    myFingerprint = await generateFingerprint(ecdhKeyPair.publicKey);
    
    console.log('ðŸ” Paire de clÃ©s ECDH gÃ©nÃ©rÃ©e');
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
        
        // Reconstruire la clÃ© publique depuis le JWK (la clÃ© publique est incluse dans le JWK privÃ©)
        const publicKey = await window.crypto.subtle.importKey(
            'jwk',
            { ...exported.privateKeyJwk, d: undefined }, // Retirer la partie privÃ©e
            { name: 'ECDH', namedCurve: 'P-256' },
            true,
            []
        );
        
        ecdhKeyPair = { privateKey, publicKey };
        ecdhPublicKeyB64 = exported.publicKeyB64;
        
        // RÃ©gÃ©nÃ©rer le fingerprint depuis la clÃ© publique restaurÃ©e
        myFingerprint = await generateFingerprint(ecdhKeyPair.publicKey);
        
        console.log('ðŸ” Paire ECDH restaurÃ©e depuis localStorage (fingerprint rÃ©gÃ©nÃ©rÃ©)');
        return true;
    } catch (err) {
        console.error('âŒ Erreur import ECDH:', err);
        return false;
    }
}

/**
 * DÃ©rive une clÃ© AES-256-GCM depuis le secret partagÃ© ECDH
 * @param {string} theirPublicKeyB64 - ClÃ© publique de l'autre partie en base64
 */
async function deriveSharedKey(theirPublicKeyB64) {
    if (!ecdhKeyPair) {
        throw new Error('Paire ECDH non initialisÃ©e');
    }
    
    // Importer la clÃ© publique de l'autre partie
    const theirPublicKeyRaw = Uint8Array.from(atob(theirPublicKeyB64), c => c.charCodeAt(0));
    const theirPublicKey = await window.crypto.subtle.importKey(
        'raw',
        theirPublicKeyRaw,
        { name: 'ECDH', namedCurve: 'P-256' },
        false,
        []
    );
    
    // DÃ©river les bits partagÃ©s
    const sharedBits = await window.crypto.subtle.deriveBits(
        {
            name: 'ECDH',
            public: theirPublicKey
        },
        ecdhKeyPair.privateKey,
        256 // 256 bits
    );
    
    // Utiliser HKDF pour dÃ©river une clÃ© AES robuste
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
    
    // GÃ©nÃ©rer un IV dÃ©terministe basÃ© sur le secret partagÃ© (pour la compatibilitÃ©)
    const ivMaterial = await window.crypto.subtle.digest('SHA-256', 
        new TextEncoder().encode(btoa(String.fromCharCode(...new Uint8Array(sharedBits))) + '-IV')
    );
    cryptoIV = new Uint8Array(ivMaterial).slice(0, 12);
    
    // ClÃ© AES dÃ©rivÃ©e
    return true;
}

/**
 * Envoie ma clÃ© publique ECDH Ã  un participant via WebSocket
 */
function sendECDHPublicKey(targetOdId) {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    
    ws.send(JSON.stringify({
        type: 'ecdh-public-key',
        targetOdId: targetOdId,
        publicKeyB64: ecdhPublicKeyB64
    }));
    
    console.log('ðŸ“¤ ClÃ© publique ECDH envoyÃ©e Ã :', targetOdId);
}

/**
 * Attend la rÃ©ception de la clÃ© publique d'un participant
 * @returns {Promise<string>} La clÃ© publique reÃ§ue
 */
function waitForECDHPublicKey(fromOdId, timeoutMs = 30000) {
    return new Promise((resolve, reject) => {
        // VÃ©rifier si on a dÃ©jÃ  reÃ§u la clÃ©
        if (pendingKeyExchanges.has(fromOdId)) {
            const exchange = pendingKeyExchanges.get(fromOdId);
            if (exchange.publicKeyB64) {
                resolve(exchange.publicKeyB64);
                return;
            }
        }
        
        // Attendre la rÃ©ception
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
 * Handler pour la rÃ©ception d'une clÃ© publique ECDH
 */
async function handleECDHPublicKey(fromOdId, publicKeyB64) {
    console.log('ðŸ“¥ ClÃ© publique ECDH reÃ§ue de:', fromOdId);
    
    pendingKeyExchanges.set(fromOdId, { publicKeyB64, resolved: true });
    
    // GÃ©nÃ©rer et stocker le fingerprint du pair
    try {
        const peerFingerprint = await generateFingerprintFromB64(publicKeyB64);
        
        // RÃ©cupÃ©rer le pseudo de ce peer
        const participantInfo = participants.get(fromOdId);
        const pseudo = participantInfo ? participantInfo.pseudo : null;
        
        // Utiliser pseudo_roomId comme clÃ© pour Ã©viter les faux positifs entre rooms diffÃ©rentes
        const fingerprintKey = pseudo && roomId ? `${pseudo}_${roomId}` : null;
        
        // VÃ©rifier si le fingerprint a changÃ© pour ce PSEUDO dans cette ROOM (dÃ©tection MITM)
        if (fingerprintKey && knownFingerprints.has(fingerprintKey)) {
            const knownFingerprint = knownFingerprints.get(fingerprintKey);
            if (knownFingerprint !== peerFingerprint) {
                // ALERTE SÃ‰CURITÃ‰: Le fingerprint a changÃ©!
                console.error('ðŸš¨ ALERTE SÃ‰CURITÃ‰: Fingerprint changÃ© pour', pseudo, 'dans room', roomId);
                showSecurityAlert(fromOdId, knownFingerprint, peerFingerprint);
            } else {
                console.log('âœ… Fingerprint vÃ©rifiÃ© OK pour', pseudo);
            }
        } else if (fingerprintKey) {
            console.log('â„¹ï¸ Premier fingerprint enregistrÃ© pour', pseudo, 'dans room', roomId);
        }
        
        // Stocker le fingerprint pour ce pseudo dans cette room
        if (fingerprintKey) {
            knownFingerprints.set(fingerprintKey, peerFingerprint);
            saveKnownFingerprints();
        }
        
        // Stocker aussi par odId pour la session actuelle
        peerFingerprints.set(fromOdId, peerFingerprint);
    } catch (err) {
        console.error('âŒ Erreur gÃ©nÃ©ration fingerprint peer:', err);
    }
    
    // RÃ©soudre la promesse en attente si elle existe
    if (keyExchangeResolvers.has(fromOdId)) {
        const { resolve } = keyExchangeResolvers.get(fromOdId);
        keyExchangeResolvers.delete(fromOdId);
        resolve(publicKeyB64);
    }
}

// ===== DOUBLE RATCHET (Signal Protocol Post-Quantum) =====

/**
 * Ã‰tat du Double Ratchet par paire de peers
 * Chaque conversation peerâ†”peer a son propre ratchet
 */
let doubleRatchetState = new Map(); // Map<odId, {rootKey, sendChain, recvChain, dhRatchet, skippedKeys}>

/**
 * Buffer pour les messages double-ratchet-init reÃ§us avant l'initialisation
 */
let pendingDoubleRatchetInits = new Map(); // Map<odId, {dhPublicKey}>

/**
 * Timestamp du dernier envoi de double-ratchet-init (anti-boucle)
 */
let lastDoubleRatchetInitSent = new Map(); // Map<odId, timestamp>

/**
 * Structure du ratchet pour une paire de peers:
 * {
 *   rootKey: Uint8Array(32), // Root key dÃ©rivÃ©e d'ECDH initial
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
 * Expanded du rootKey en chaÃ®nes de ratcheting
 */
async function hkdfExpand(prk, info, length) {
    const hash = 'SHA-256';
    const hashLen = 32; // SHA-256 = 32 bytes
    
    // Nombre d'itÃ©rations N = ceil(L / HashLen)
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
 * DÃ©rive un PRK depuis le secret partagÃ©
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
 * KDF_RK: DÃ©rive une nouvelle rootKey et une chainKey initiale
 * UtilisÃ© quand le DH ratchet tourne (nouveau ECDH)
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
 * KDF_CK: Avance la chaÃ®ne (symmetric ratchet)
 * UtilisÃ© Ã  chaque message envoyÃ©/reÃ§u
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
 * @param {boolean} isInitiator - True si tu es l'initiateur (dÃ©termine qui envoie en premier)
 */
async function initializeDoubleRatchet(odId, sharedSecret, isInitiator) {
    try {
        // DÃ©river rootKey initial depuis le secret partagÃ© ECDH
        const salt = new TextEncoder().encode('SecurePeer-X3DH-Salt');
        const info = new TextEncoder().encode('SecurePeer-Double-Ratchet-Initialization');
        
        const prk = await hkdfExtract(salt, sharedSecret);
        const expanded = await hkdfExpand(prk, info, 96); // 96 bytes = 32 RK + 32 CK + 32 reserved
        
        const rootKey = expanded.slice(0, 32);
        const initialChainKey = expanded.slice(32, 64);
        
        // GÃ©nÃ©rer une nouvelle paire DH pour le ratchet
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
            // Initiateur : sendChain actif, recvChain inactif (attend clÃ© publique du pair)
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
                    active: false // N'activera que quand on reÃ§oit la clÃ© DH du pair
                },
                dhRatchet: {
                    keyPair: dhKeyPair,
                    publicKeyB64: dhPublicKeyB64,
                    theirPublicKeyB64: null, // Ã€ remplir quand on reÃ§oit leur clÃ©
                    numberUsed: 0,
                    lastRatchetTime: Date.now() // Timer pour rotation 30min
                },
                skippedKeys: new Map(), // Map<"odId:msgNum", {key: Uint8Array(32), timestamp, expiry}>
                skippedKeysMaxAge: 1000 * 60 * 60, // 1 heure
                dhRatchetMaxAge: 1000 * 60 * 30 // 30 minutes
            };
        } else {
            // Non-initiateur : recvChain actif, sendChain inactif (attend clÃ© publique du pair)
            state = {
                rootKey,
                sendChain: {
                    chainKey: initialChainKey,
                    messageNumber: 0,
                    active: false // N'activera que quand on reÃ§oit la clÃ© DH du pair
                },
                recvChain: {
                    chainKey: initialChainKey,
                    messageNumber: 0,
                    active: true // Non-initiator reÃ§oit en premier
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
        
        // Retourner la clÃ© publique DH en Uint8Array
        return new Uint8Array(dhPublicKeyRaw);
        
    } catch (err) {
        console.error('âŒ Erreur initialisation Double Ratchet:', err);
        throw err;
    }
}

/**
 * ComplÃ¨te l'initialisation du DH Ratchet quand on reÃ§oit la clÃ© publique du pair
 */
async function completeDoubleRatchetHandshake(odId, theirPublicKey) {
    try {
        const state = doubleRatchetState.get(odId);
        if (!state) {
            throw new Error('Double Ratchet non initialisÃ© pour ' + odId);
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
        
        // DÃ©river nouvelle rootKey + chainKey depuis le DH
        const result = await kdfRK(state.rootKey, new Uint8Array(sharedBits));
        state.rootKey = result.rootKey;
        
        // Mettre Ã  jour la chainKey de la chaÃ®ne ACTIVE (pas les deux!)
        // L'initiator met Ã  jour sendChain, le non-initiator met Ã  jour recvChain
        if (state.sendChain.active) {
            // Initiator: update sendChain
            state.sendChain.chainKey = result.chainKey;
        } else {
            // Non-initiator: update recvChain
            state.recvChain.chainKey = result.chainKey;
        }
        
        // Activer les chaÃ®nes si elles ne sont pas encore actives
        if (!state.sendChain.active && state.sendChain.messageNumber === 0) {
            state.sendChain.active = true;
        }
        if (!state.recvChain.active && state.recvChain.messageNumber === 0) {
            state.recvChain.active = true;
        }
        
        // RÃ©initialiser le timer DH ratchet aprÃ¨s handshake
        state.dhRatchet.lastRatchetTime = Date.now();
        
    } catch (err) {
        console.error('âŒ Erreur handshake Double Ratchet:', err);
        throw err;
    }
}

/**
 * Encode un message avec header chiffrÃ©
 * Header = encryptedHeader(messageNumber || dhPublicKey)
 */
async function encryptMessageHeader(state, plaintext, chainKey, messageNumber) {
    try {
        // DÃ©river une clÃ© de header depuis la chainKey fournie (non avancÃ©e)
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
        console.error('âŒ Erreur chiffrement header:', err);
        throw err;
    }
}

/**
 * Envoie un message avec Double Ratchet
 * Effectue le ratcheting symÃ©trique et DH automatiquement
 */
async function sendMessageWithDoubleRatchet(odId, plaintext) {
    try {
        const state = doubleRatchetState.get(odId);
        if (!state) {
            throw new Error('Double Ratchet non initialisÃ© pour ' + odId);
        }
        
        if (!state.sendChain.active) {
            throw new Error('Send chain pas encore active (handshake incomplet)');
        }
        
        // Sauvegarder la chainKey AVANT de l'avancer (pour le header)
        const currentChainKey = state.sendChain.chainKey;
        const currentMessageNumber = state.sendChain.messageNumber;
        
        // Avancer la chaÃ®ne symÃ©trique
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
        
        // DH Ratchet: tous les 100 messages OU aprÃ¨s 30 minutes
        state.sendChain.messageNumber++;
        const timeSinceLastRatchet = Date.now() - state.dhRatchet.lastRatchetTime;
        if (state.sendChain.messageNumber % 100 === 0 || timeSinceLastRatchet > state.dhRatchetMaxAge) {
            await performDHRatchet(state);
            console.log(`ðŸ”„ DH Ratchet dÃ©clenchÃ© (${timeSinceLastRatchet > state.dhRatchetMaxAge ? 'timer 30min' : '100 messages'})`);
        }
        
        // RÃ©sultat : Buffer contenant le message chiffrÃ© complet
        return {
            type: 'double-ratchet-message',
            odId: odId,
            data: btoa(String.fromCharCode(...headerEncrypted)),
            messageNumber: state.sendChain.messageNumber - 1, // Pour reference
            dhPublicKey: state.dhRatchet.publicKeyB64
        };
        
    } catch (err) {
        console.error('âŒ Erreur send Double Ratchet:', err);
        throw err;
    }
}

/**
 * ReÃ§oit et dÃ©chiffre un message avec Double Ratchet
 */
async function receiveMessageWithDoubleRatchet(odId, headerEncryptedB64, senderDHPublicKeyB64) {
    try {
        const state = doubleRatchetState.get(odId);
        if (!state) {
            throw new Error('Double Ratchet non initialisÃ© pour ' + odId);
        }
        
        const headerEncrypted = Uint8Array.from(atob(headerEncryptedB64), c => c.charCodeAt(0));
        
        // Extraire IV et messages
        const headerIV = headerEncrypted.slice(0, 12);
        const rest = headerEncrypted.slice(12);
        
        // Essayer de dÃ©chiffrer le header avec la recvChain courante
        let plaintext = null;
        let headerDecrypted = null;
        
        try {
            // DÃ©river la clÃ© de header depuis la recvChain
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
            
            // ChiffrÃ© = 69 bytes (4 msg num + 65 DH public)
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
            
            // Si leur clÃ© DH a changÃ©, effectuer DH ratchet
            if (state.dhRatchet.theirPublicKeyB64 && theirPublicKeyB64 !== state.dhRatchet.theirPublicKeyB64) {
                console.log('ðŸ”„ DH Ratchet dÃ©tectÃ© (leur clÃ© a changÃ©)');
                
                // Calculer skipped keys pour les messages entre ancien et nouveau numÃ©ro
                const oldRecvNum = state.recvChain.messageNumber;
                const newRecvNum = messageNumber;
                
                // Stocker les clÃ©s sautÃ©es (max 100)
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
                
                // DÃ©river new rootKey
                const kdfResult = await kdfRK(state.rootKey, new Uint8Array(sharedBits));
                state.rootKey = kdfResult.rootKey;
                state.recvChain.chainKey = kdfResult.chainKey;
                state.recvChain.messageNumber = 0;
            }
            
            // Avancer recvChain jusqu'au numÃ©ro du message
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
            
            // DÃ©chiffrer le message avec le messageKey
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
            console.warn('âš ï¸ Impossible dÃ©chiffrer avec chaÃ®ne actuelle, essai skipped keys buffer...');
            
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
                    
                    // Zeroize et delete la clÃ© utilisÃ©e
                    skippedKeyEntry.key.fill(0);
                    state.skippedKeys.delete(keyId);
                    
                    console.log('âœ… Message dÃ©chiffrÃ© avec skipped key:', messageNumber);
                } else {
                    throw new Error('ClÃ© sautÃ©e non trouvÃ©e dans le buffer');
                }
            } catch (innerErr) {
                console.error('âŒ Erreur avec skipped keys:', innerErr.message, innerErr);
                throw err; // Throw original error
            }
        }
        
        // Nettoyer les clÃ©s expirÃ©es
        cleanupSkippedKeys(state);
        
        return plaintext;
        
    } catch (err) {
        console.error('âŒ Erreur receive Double Ratchet:', err);
        throw err;
    }
}

/**
 * Effectue le DH Ratchet: renouvelle la paire ECDH
 */
async function performDHRatchet(state) {
    try {
        // GÃ©nÃ©rer une nouvelle paire ECDH
        const newKeyPair = await window.crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' },
            true,
            ['deriveKey', 'deriveBits']
        );
        
        const newPublicKeyRaw = await window.crypto.subtle.exportKey('raw', newKeyPair.publicKey);
        const newPublicKeyB64 = btoa(String.fromCharCode(...new Uint8Array(newPublicKeyRaw)));
        
        // DÃ©river le secret avec leur derniÃ¨re clÃ© publique
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
            
            // DÃ©river new rootKey + initChainKey
            const result = await kdfRK(state.rootKey, new Uint8Array(sharedBits));
            state.rootKey = result.rootKey;
            state.sendChain.chainKey = result.chainKey;
            state.sendChain.messageNumber = 0;
        }
        
        // Mettre Ã  jour la paire ECDH
        state.dhRatchet.keyPair = newKeyPair;
        state.dhRatchet.publicKeyB64 = newPublicKeyB64;
        state.dhRatchet.numberUsed = state.sendChain.messageNumber;
        state.dhRatchet.lastRatchetTime = Date.now(); // RÃ©initialiser le timer
        
        console.log('ðŸ”„ DH Ratchet effectuÃ© | Nouvelle clÃ© DH:', newPublicKeyB64.substring(0, 10) + '...');
        
    } catch (err) {
        console.error('âŒ Erreur DH Ratchet:', err);
        throw err;
    }
}

/**
 * Nettoie les clÃ©s sautÃ©es expirÃ©es
 */
function cleanupSkippedKeys(state) {
    const now = Date.now();
    for (const [keyId, entry] of state.skippedKeys.entries()) {
        if (entry.expiry < now) {
            // Zeroize la clÃ© avant suppression
            entry.key.fill(0);
            state.skippedKeys.delete(keyId);
        }
    }
}

/**
 * Zeroize complÃ¨te l'Ã©tat du ratchet (logout)
 */
function zeroizeDoubleRatchet(odId) {
    const state = doubleRatchetState.get(odId);
    if (!state) return;
    
    // Zeroize toutes les clÃ©s
    if (state.rootKey) state.rootKey.fill(0);
    if (state.sendChain.chainKey) state.sendChain.chainKey.fill(0);
    if (state.recvChain.chainKey) state.recvChain.chainKey.fill(0);
    
    // Zeroize les clÃ©s sautÃ©es
    for (const [_, entry] of state.skippedKeys.entries()) {
        entry.key.fill(0);
    }
    
    doubleRatchetState.delete(odId);
    console.log('ðŸ” Double Ratchet zÃ©roisÃ© pour', odId);
}

// ===== WEBSOCKET =====

function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}`;
    
    ws = new WebSocket(wsUrl);
    
    ws.onopen = () => {
        console.log('ðŸŒ WebSocket connectÃ©');
        
        // RÃ©cupÃ©rer le pseudo (dÃ©jÃ  dÃ©fini avant connectWebSocket)
        // userPseudo est dÃ©fini dans setupPseudoSection()
        
        // VÃ©rifier si on a une session sauvegardÃ©e (reconnexion)
        const savedSession = localStorage.getItem('securepeer_session');
        const isReconnection = savedSession !== null;
        const savedOdId = localStorage.getItem('securepeer_odid');

        if (isReceiver && !isReconnection) {
            // Mode destinataire pour la premiÃ¨re fois : rejoindre la room
            console.log('ðŸ“¥ PremiÃ¨re connexion destinataire');
            ws.send(JSON.stringify({
                type: 'join-room',
                roomId: roomId,
                pseudo: userPseudo,
                odId: savedOdId || undefined
            }));
        } else if (isReceiver && isReconnection) {
            // Destinataire qui se reconnecte
            console.log('ðŸ”„ Reconnexion destinataire');
            ws.send(JSON.stringify({
                type: 'join-room',
                roomId: roomId,
                pseudo: userPseudo,
                odId: savedOdId || undefined
            }));
        } else if (roomId && isReconnection) {
            // Mode expÃ©diteur qui se reconnecte
            console.log('ðŸ”„ [WS] Reconnexion expÃ©diteur dÃ©tectÃ©e');
            console.log('   ðŸ“¦ roomId:', roomId);
            console.log('   ðŸ‘¤ pseudo:', userPseudo);
            console.log('   ðŸ”‘ odId:', savedOdId);
            const rejoinMsg = {
                type: 'rejoin-room',
                roomId: roomId,
                pseudo: userPseudo,
                role: 'sender',
                odId: savedOdId || undefined
            };
            console.log('ðŸ“¤ [WS] Envoi rejoin-room:', rejoinMsg);
            ws.send(JSON.stringify(rejoinMsg));
        } else {
            // Mode expÃ©diteur : crÃ©er une nouvelle room
            // RÃ©cupÃ©rer les options de sÃ©curitÃ© depuis l'UI
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
            
            console.log('ðŸ“¤ CrÃ©ation nouvelle room avec options:', sessionOptions);
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
        console.log('ðŸ”Œ WebSocket dÃ©connectÃ©');
    };
    
    ws.onerror = (error) => {
        console.error('âŒ Erreur WebSocket:', error);
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
            console.log('âœ… [WS] room-rejoined reÃ§u !');
            console.log('   ðŸ“¦ roomId:', data.roomId);
            console.log('   ðŸ”‘ odId:', data.odId);
            console.log('   ðŸ‘¥ participants:', data.participants);
            console.log('   ðŸ“„ fileInfo:', data.fileInfo);
            console.log('   ðŸ”— hasReceiver:', data.hasReceiver);
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
                console.log(`ðŸ‘¥ ${connectedCount} participant(s) dÃ©jÃ  dans la room`);
                
                // Si on recharge (doubleRatchetState vide), rÃ©init complÃ¨te
                if (cryptoKey && connectedCount > 0 && doubleRatchetState.size === 0) {
                    console.log('ðŸ”„ RÃ©initialisation Double Ratchet aprÃ¨s reload crÃ©ateur...');
                    (async () => {
                        try {
                            const keyMaterial = await window.crypto.subtle.exportKey('raw', cryptoKey);
                            const sharedSecret = new Uint8Array(keyMaterial);
                            
                            for (const [odId, info] of participants.entries()) {
                                // CrÃ©ateur = toujours initiateur
                                const dhPublicKey = await initializeDoubleRatchet(odId, sharedSecret, true);
                                console.log('ðŸ” Double Ratchet rÃ©initialisÃ© (crÃ©ateur) pour', odId);
                                
                                // Envoyer la clÃ© publique DH
                                ws.send(JSON.stringify({
                                    type: 'double-ratchet-init',
                                    to: odId,
                                    publicKey: Array.from(dhPublicKey)
                                }));
                            }
                        } catch (err) {
                            console.error('âŒ Erreur rÃ©init Double Ratchet crÃ©ateur:', err);
                        }
                    })();
                }
            }
            updateConnectedUsersDropdown();
            generateShareLink();
            saveSessionToStorage();
            // Si un receiver est dÃ©jÃ  lÃ , mettre Ã  jour le statut
            if (data.hasReceiver || connectedCount > 0) {
                elements.linkStatus.innerHTML = `<span class="pulse"></span> ðŸ‘¥ ${connectedCount} utilisateur(s) connectÃ©(s)`;
                elements.linkStatus.className = 'status status-connected';
            }
            break;
            
        case 'room-joined':
            console.log('âœ… Room rejointe');
            console.log('ðŸ“¦ FileInfo reÃ§ue:', data.fileInfo);
            myOdId = data.odId;
            // Sauvegarder l'odId pour reconnexion future
            localStorage.setItem('securepeer_odid', myOdId);
            fileInfo = data.fileInfo;
            if (fileInfo) {
                elements.incomingFileName.textContent = fileInfo.name;
                elements.incomingFileSize.textContent = formatFileSize(fileInfo.size);
            }
            
            // Nettoyer et stocker les participants existants
            participants.clear(); // Reset pour Ã©viter doublons si reconnexion
            if (data.participants && Array.isArray(data.participants)) {
                data.participants.forEach(p => {
                    // Ne pas s'ajouter soi-mÃªme
                    if (p.odId !== myOdId) {
                        participants.set(p.odId, { pseudo: p.pseudo, isCreator: p.isCreator || false });
                    }
                });
                connectedCount = participants.size;
                console.log(`ðŸ‘¥ ${connectedCount} participant(s) dÃ©jÃ  dans la room`);
                
                // Si on recharge (doubleRatchetState vide), rÃ©init complÃ¨te
                if (cryptoKey && connectedCount > 0 && doubleRatchetState.size === 0) {
                    console.log('ðŸ”„ RÃ©initialisation Double Ratchet aprÃ¨s reload...');
                    (async () => {
                        try {
                            const keyMaterial = await window.crypto.subtle.exportKey('raw', cryptoKey);
                            const sharedSecret = new Uint8Array(keyMaterial);
                            
                            for (const [odId, info] of participants.entries()) {
                                // RÃ©initialiser localement
                                const amInitiator = isCreator || !info.isCreator;
                                const dhPublicKey = await initializeDoubleRatchet(odId, sharedSecret, amInitiator);
                                console.log('ðŸ” Double Ratchet rÃ©initialisÃ© pour', odId);
                                
                                // Envoyer la clÃ© publique DH
                                ws.send(JSON.stringify({
                                    type: 'double-ratchet-init',
                                    to: odId,
                                    publicKey: Array.from(dhPublicKey)
                                }));
                            }
                        } catch (err) {
                            console.error('âŒ Erreur rÃ©init Double Ratchet:', err);
                        }
                    })();
                } else {
                    console.log('â­ï¸ Skip rÃ©init Double Ratchet:', { hasCryptoKey: !!cryptoKey, connectedCount, doubleRatchetStateSize: doubleRatchetState.size });
                }
            }
            // Toujours mettre Ã  jour le dropdown (mÃªme si vide)
            updateConnectedUsersDropdown();
            
            // VÃ©rifier si un mot de passe est requis
            if (fileInfo && fileInfo.passwordRequired) {
                console.log('ðŸ” Mot de passe requis! Salt:', fileInfo.passwordSalt);
                passwordSaltB64 = fileInfo.passwordSalt;
                passwordIterations = fileInfo.passwordIterations || KDF_ITERATIONS;
                usePassword = true;
                elements.receiverStatus.textContent = 'Mot de passe requis pour dÃ©chiffrer';
                elements.receiverPasswordBlock.classList.remove('hidden');
                console.log('ðŸ”“ receiverPasswordBlock rendu visible');
                elements.receiverPasswordApply.onclick = applyReceiverPassword;
            } else if (ecdhKeyPair && ecdhPublicKeyB64) {
                // Mode ECDH : envoyer ma clÃ© publique au crÃ©ateur pour dÃ©river la clÃ© partagÃ©e
                console.log('ðŸ” [ECDH] Envoi de ma clÃ© publique au crÃ©ateur...');
                elements.receiverStatus.textContent = 'Ã‰change de clÃ©s sÃ©curisÃ©...';
                
                // Trouver le crÃ©ateur dans les participants
                const creatorOdId = Array.from(participants.entries())
                    .find(([id, p]) => p.isCreator)?.[0];
                
                if (creatorOdId) {
                    sendECDHPublicKey(creatorOdId);
                    // La dÃ©rivation se fera quand on recevra la clÃ© publique du crÃ©ateur
                } else {
                    console.error('âŒ [ECDH] CrÃ©ateur non trouvÃ© dans les participants');
                    showError('Erreur: crÃ©ateur de la session introuvable.');
                }
                saveSessionToStorage();
            } else {
                console.log('âœ… Pas de mot de passe requis');
                elements.receiverStatus.textContent = 'Connexion P2P en cours...';
                saveSessionToStorage();
                // Initier les connexions P2P avec tous les participants existants
                initPeersWithExistingParticipants();
            }
            break;
            
        case 'peer-joined':
            console.log('ðŸ‘‹ [PEER] Nouveau participant dÃ©tectÃ© !');
            console.log('   ðŸ‘¤ pseudo:', data.pseudo);
            console.log('   ðŸ”‘ odId:', data.odId);
            console.log('   ðŸ‘‘ isCreator:', data.isCreator);
            
            // Ã‰viter les doublons (mÃªme odId dÃ©jÃ  connu)
            if (participants.has(data.odId)) {
                console.log(`âš ï¸ [PEER] Participant dÃ©jÃ  connu, ignorÃ©: ${data.pseudo}`);
                break;
            }
            
            console.log(`âœ… [PEER] Ajout du participant: ${data.pseudo}`);
            participants.set(data.odId, { pseudo: data.pseudo, isCreator: data.isCreator || false });
            connectedCount = participants.size;
            console.log('   ðŸ‘¥ Total participants maintenant:', connectedCount);
            
            // Mettre Ã  jour le statut (selon si on est creator ou receiver)
            if (!isReceiver && elements.linkStatus) {
                elements.linkStatus.innerHTML = `<span class="pulse"></span> ðŸ‘¥ ${connectedCount} participant(s) connectÃ©(s)`;
                elements.linkStatus.className = 'status status-connected';
            }
            
            // Mettre Ã  jour le dropdown des utilisateurs connectÃ©s
            updateConnectedUsersDropdown();
            
            // CrÃ©er une connexion P2P avec ce nouveau participant (je suis l'initiateur)
            if (!usePassword) {
                console.log(`ðŸš€ CrÃ©ation connexion P2P avec ${data.pseudo}`);
                initPeerWith(data.odId, true);
            }
            break;
            
        case 'peer-left':
            console.log(`ðŸ‘‹ Participant parti: ${data.pseudo} (${data.odId})`);
            participants.delete(data.odId);
            connectedCount = participants.size;
            
            // DÃ©truire le peer correspondant
            const leavingPeer = peers.get(data.odId);
            if (leavingPeer) {
                leavingPeer.destroy();
                peers.delete(data.odId);
            }
            
            // Mettre Ã  jour le statut (selon si on est creator ou receiver)
            if (!isReceiver && elements.linkStatus) {
                if (connectedCount > 0) {
                    elements.linkStatus.innerHTML = `<span class="pulse"></span> ðŸ‘¥ ${connectedCount} participant(s) connectÃ©(s)`;
                } else {
                    elements.linkStatus.innerHTML = '<span class="pulse"></span> En attente de participants...';
                    elements.linkStatus.className = 'status status-waiting';
                }
            }
            
            updateConnectedUsersDropdown();
            break;
            
        case 'receiver-ready':
            console.log(`ðŸ”“ Participant prÃªt: ${data.pseudo} (${data.odId})`);
            elements.linkStatus.innerHTML = '<span class="pulse"></span> Ã‰tablissement P2P...';
            // CrÃ©er une connexion P2P avec ce participant (je suis l'initiateur)
            if (!peers.has(data.odId)) {
                initPeerWith(data.odId, true);
            }
            break;
            
        case 'signal':
            // Signal WebRTC d'un participant spÃ©cifique
            const fromId = data.fromId;
            let existingPeer = peers.get(fromId);
            
            if (!existingPeer) {
                // CrÃ©er le peer s'il n'existe pas (je suis le rÃ©pondeur)
                console.log(`ðŸ“¡ Signal reÃ§u de ${data.fromPseudo || fromId}, crÃ©ation du peer...`);
                initPeerWith(fromId, false);
                existingPeer = peers.get(fromId);
            }
            
            if (existingPeer) {
                existingPeer.signal(data.signal);
            }
            break;
            
        case 'session-closed':
            // La session a Ã©tÃ© fermÃ©e
            console.log('ðŸ”´ Session fermÃ©e par:', data.closedBy);
            clearSessionStorage();
            
            // Fermer les connexions P2P
            peers.forEach(p => p.destroy());
            peers.clear();
            
            const closeMessage = data.isCreatorClose 
                ? `La session a Ã©tÃ© fermÃ©e par le crÃ©ateur (${data.closedBy}).`
                : `${data.closedBy} a quittÃ© la session.`;
            
            showError(closeMessage + '\n\nRetour Ã  l\'accueil...');
            setTimeout(() => {
                window.location.href = window.location.origin + window.location.pathname;
            }, 2000);
            break;
        
        case 'approval-pending':
            // Je suis en attente d'approbation
            console.log('âœ‹ En attente d\'approbation...');
            showToast('â³ ' + data.message);
            if (elements.receiverStatus) {
                elements.receiverStatus.textContent = 'â³ ' + data.message;
            }
            break;
        
        case 'approval-request':
            // Un participant demande Ã  rejoindre (je suis le crÃ©ateur)
            console.log('âœ‹ Demande d\'approbation de:', data.pseudo);
            pendingApprovals.set(data.odId, { pseudo: data.pseudo, timestamp: Date.now() });
            showApprovalRequest(data.odId, data.pseudo);
            break;
        
        case 'approval-rejected':
            // Ma demande a Ã©tÃ© refusÃ©e
            console.log('âŒ Demande refusÃ©e');
            showError(data.message);
            setTimeout(() => {
                clearSessionStorage();
                window.location.href = window.location.origin + window.location.pathname;
            }, 3000);
            break;
        
        case 'approval-update':
            // Mise Ã  jour du nombre de demandes en attente
            console.log('ðŸ“Š Demandes en attente:', data.pendingCount);
            updatePendingBadge(data.pendingCount);
            break;
        
        case 'session-locked':
            // La session est verrouillÃ©e
            console.log('ðŸ”’ Session verrouillÃ©e');
            sessionOptions.isLocked = true;
            showToast('ðŸ”’ ' + data.message);
            updateLockButton();
            break;
        
        case 'session-unlocked':
            // La session est dÃ©verrouillÃ©e
            console.log('ðŸ”“ Session dÃ©verrouillÃ©e');
            sessionOptions.isLocked = false;
            showToast('ðŸ”“ ' + data.message);
            updateLockButton();
            break;
            
        case 'error':
            console.log('âŒ Erreur serveur:', data.message);
            // Si l'erreur indique une session/room expirÃ©e, effacer et revenir Ã  l'accueil
            const expiredErrors = ['expirÃ©', 'invalide', 'expired', 'invalid', 'not found', 'introuvable'];
            const isSessionExpired = expiredErrors.some(e => 
                data.message && data.message.toLowerCase().includes(e)
            );
            
            if (isSessionExpired) {
                console.log('ðŸ—‘ï¸ Session expirÃ©e dÃ©tectÃ©e, nettoyage...');
                clearSessionStorage();
                showError(data.message + '\n\nRetour Ã  l\'accueil dans 3 secondes...');
                setTimeout(() => {
                    location.reload();
                }, 3000);
            } else {
                showError(data.message);
            }
            break;
            
        case 'ecdh-public-key':
            // RÃ©ception de la clÃ© publique ECDH d'un autre participant
            console.log('ðŸ” [ECDH] ClÃ© publique reÃ§ue de:', data.fromId);
            handleECDHPublicKey(data.fromId, data.publicKeyB64);
            
            // Si je suis le crÃ©ateur, dÃ©river la clÃ© pour ce participant
            if (isCreator && ecdhKeyPair) {
                // VÃ©rifier si on a dÃ©jÃ  un Double Ratchet pour ce participant
                const needsInit = !doubleRatchetState.has(data.fromId);
                
                if (needsInit) {
                    (async () => {
                        try {
                            // DÃ©river la clÃ© AES partagÃ©e
                            await deriveSharedKey(data.publicKeyB64);
                            console.log('ðŸ” [ECDH] ClÃ© AES dÃ©rivÃ©e avec succÃ¨s (crÃ©ateur)');
                            
                            // Initialiser le Double Ratchet (crÃ©ateur = initiateur)
                            if (cryptoKey) {
                                const keyMaterial = await window.crypto.subtle.exportKey('raw', cryptoKey);
                                const sharedSecret = new Uint8Array(keyMaterial);
                                const dhPublicKey = await initializeDoubleRatchet(data.fromId, sharedSecret, true);
                                console.log('ðŸ” Double Ratchet initialisÃ© (crÃ©ateur) pour', data.fromId);
                                
                                // Traiter les double-ratchet-init en attente
                                if (pendingDoubleRatchetInits.has(data.fromId)) {
                                    const pending = pendingDoubleRatchetInits.get(data.fromId);
                                    await completeDoubleRatchetHandshake(data.fromId, pending.dhPublicKey);
                                    pendingDoubleRatchetInits.delete(data.fromId);
                                    console.log('âœ… Pending init traitÃ© (crÃ©ateur) pour', data.fromId);
                                }
                                
                                // Envoyer la clÃ© publique DH via signaling
                                ws.send(JSON.stringify({
                                    type: 'double-ratchet-init',
                                    to: data.fromId,
                                    publicKey: Array.from(dhPublicKey)
                                }));
                            } else {
                                console.error('âŒ cryptoKey null aprÃ¨s deriveSharedKey (crÃ©ateur)!');
                            }
                            
                            // Envoyer ma clÃ© publique en retour
                            sendECDHPublicKey(data.fromId);
                            
                            // Sauvegarder la session avec la nouvelle clÃ©
                            saveSessionToStorage();
                        } catch (err) {
                            console.error('âŒ [ECDH] Erreur dÃ©rivation clÃ©:', err);
                            showError('Erreur lors de l\'Ã©change de clÃ©s sÃ©curisÃ©.');
                        }
                    })();
                }
            }
            // Si je suis receiver et que j'attends une clÃ©
            else if (isReceiver && ecdhKeyPair && !cryptoKey) {
                (async () => {
                    try {
                        // DÃ©river la clÃ© AES partagÃ©e
                        await deriveSharedKey(data.publicKeyB64);
                        console.log('ðŸ” [ECDH] ClÃ© AES dÃ©rivÃ©e avec succÃ¨s (receiver)');
                        
                        // Initialiser le Double Ratchet (receiver = non-initiateur)
                        if (cryptoKey) {
                            const keyMaterial = await window.crypto.subtle.exportKey('raw', cryptoKey);
                            const sharedSecret = new Uint8Array(keyMaterial);
                            const dhPublicKey = await initializeDoubleRatchet(data.fromId, sharedSecret, false);
                            console.log('ðŸ” Double Ratchet initialisÃ© (receiver) pour', data.fromId);
                            
                            // Traiter les double-ratchet-init en attente
                            if (pendingDoubleRatchetInits.has(data.fromId)) {
                                const pending = pendingDoubleRatchetInits.get(data.fromId);
                                await completeDoubleRatchetHandshake(data.fromId, pending.dhPublicKey);
                                pendingDoubleRatchetInits.delete(data.fromId);
                            }
                            
                            // Envoyer la clÃ© publique DH via signaling
                            ws.send(JSON.stringify({
                                type: 'double-ratchet-init',
                                to: data.fromId,
                                publicKey: Array.from(dhPublicKey)
                            }));
                        } else {
                            console.error('âŒ cryptoKey null aprÃ¨s deriveSharedKey!');
                        }
                        
                        // Sauvegarder la session
                        saveSessionToStorage();
                        
                        // Maintenant on peut initier les connexions P2P
                        elements.receiverStatus.textContent = 'ClÃ© sÃ©curisÃ©e Ã©tablie, connexion P2P...';
                        initPeersWithExistingParticipants();
                    } catch (err) {
                        console.error('âŒ [ECDH] Erreur dÃ©rivation clÃ©:', err);
                        showError('Erreur lors de l\'Ã©change de clÃ©s sÃ©curisÃ©.');
                    }
                })();
            }
            break;
        
        case 'double-ratchet-init':
            // RÃ©ception de la clÃ© publique DH pour complÃ©ter le handshake
            handleDoubleRatchetInit(data, data.fromOdId);
            break;
    }
}

// ===== WEBRTC / SIMPLE-PEER =====

// Initialiser les connexions P2P avec tous les participants existants (quand on rejoint une room)
function initPeersWithExistingParticipants() {
    console.log('ðŸ”— initPeersWithExistingParticipants: participants.size =', participants.size);
    
    // Toujours envoyer receiver-ready pour signaler qu'on est prÃªt
    // Le crÃ©ateur recevra ce signal et initiera la connexion P2P
    if (ws && ws.readyState === WebSocket.OPEN) {
        console.log('ðŸ“¤ Envoi de receiver-ready');
        ws.send(JSON.stringify({ type: 'receiver-ready' }));
    }
    
    // Si on a dÃ©jÃ  des participants, crÃ©er les connexions P2P avec eux
    participants.forEach((info, odId) => {
        if (!peers.has(odId)) {
            console.log(`ðŸš€ Connexion P2P avec ${info.pseudo} (${odId})`);
        }
    });
}

// CrÃ©er une connexion P2P avec un participant spÃ©cifique
function initPeerWith(targetOdId, initiator) {
    if (peers.has(targetOdId)) {
        console.log(`âš ï¸ Peer dÃ©jÃ  existant pour ${targetOdId}`);
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
        // Envoyer le signal SDP/ICE via WebSocket vers ce participant spÃ©cifique
        ws.send(JSON.stringify({
            type: 'signal',
            signal: signal,
            targetId: targetOdId
        }));
    });
    
    newPeer.on('connect', () => {
        console.log(`ðŸ¤ Connexion P2P Ã©tablie avec ${targetOdId} !`);
        
        // Mettre Ã  jour le statut du chat
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
            // CÃ´tÃ© crÃ©ateur : dÃ©marrer le flux d'auth puis transfert (si mode fichier uniquement)
            if (sessionMode === 'file' && peers.size === 1) {
                startTransferFlow();
            }
            // En mode both, pas de transfert automatique - les fichiers sont envoyÃ©s via la zone latÃ©rale
        } else {
            if (sessionMode === 'chat') {
                elements.receiverStatus.textContent = 'ConnectÃ© ! Vous pouvez discuter.';
                document.querySelector('.receiver-info').style.display = 'none';
            } else if (sessionMode === 'both') {
                elements.receiverStatus.textContent = 'ConnectÃ© ! Vous pouvez discuter et Ã©changer des fichiers.';
                document.querySelector('.receiver-info').style.display = 'none';
            } else {
                elements.receiverStatus.textContent = 'Connexion Ã©tablie ! Transfert en cours...';
            }
        }
    });
    
    newPeer.on('data', (data) => {
        handlePeerData(data, targetOdId);
    });
    
    newPeer.on('close', () => {
        console.log(`ðŸ”Œ Connexion P2P fermÃ©e avec ${targetOdId}`);
        peers.delete(targetOdId);
    });
    
    newPeer.on('error', (err) => {
        // Ignorer les erreurs d'annulation volontaire
        if (err.message && (err.message.includes('User-Initiated Abort') || err.message.includes('Close called'))) {
            console.log(`â„¹ï¸ Connexion P2P fermÃ©e proprement avec ${targetOdId}`);
            return;
        }
        
        // Si le peer est dÃ©jÃ  connectÃ©, ne pas afficher d'erreur
        if (newPeer && newPeer.connected) {
            console.log(`â„¹ï¸ Erreur P2P ignorÃ©e (peer ${targetOdId} dÃ©jÃ  connectÃ©):`, err.message);
            return;
        }
        
        console.error(`âŒ Erreur P2P avec ${targetOdId}:`, err);
    });
}

// Fonction legacy pour compatibilitÃ© (utilisÃ©e dans quelques endroits)
function initPeer(initiator) {
    // Si on a des participants, se connecter au premier
    if (participants.size > 0) {
        const firstOdId = participants.keys().next().value;
        initPeerWith(firstOdId, initiator);
    }
}

// Obtenir un peer connectÃ© (pour envoyer des messages)
function getConnectedPeer() {
    for (const [odId, p] of peers) {
        if (p.connected) return p;
    }
    return null;
}

// Envoyer des donnÃ©es Ã  tous les peers connectÃ©s
async function broadcastToAllPeers(data) {
    const dataStr = typeof data === 'string' ? data : JSON.stringify(data);
    
    for (const [odId, p] of peers.entries()) {
        if (p.connected) {
            try {
                // Si Double Ratchet est initialisÃ© pour ce peer, chiffrer
                if (doubleRatchetState.has(odId)) {
                    const plaintext = new TextEncoder().encode(dataStr);
                    const encrypted = await sendMessageWithDoubleRatchet(odId, plaintext);
                    p.send(JSON.stringify(encrypted));
                    // Message chiffrÃ©
                } else {
                    // Fallback: envoi en clair (pour compatibilitÃ© temporaire)
                    p.send(dataStr);
                    console.warn('âš ï¸ Envoi non chiffrÃ© vers', odId, '(Double Ratchet non initialisÃ©)');
                }
            } catch (err) {
                console.error(`âŒ Erreur envoi vers ${odId}:`, err);
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
    // CÃ´tÃ© destinataire
    const peer = fromOdId ? peers.get(fromOdId) : getConnectedPeer();
    console.log('ðŸ”‘ handleAuthChallenge appelÃ©, cryptoKey existe?', !!cryptoKey, 'peer existe?', !!peer);
    
    if (!cryptoKey) {
        // Pas encore de mot de passe saisi : on met en attente
        console.log('â³ Pas de clÃ©, mise en attente');
        pendingChallenge = data;
        return;
    }

    if (!peer) {
        console.error('âŒ ERREUR: peer inexistant dans handleAuthChallenge!');
        pendingChallenge = data;
        return;
    }

    try {
        console.log('ðŸ”“ DÃ©chiffrement du challenge...');
        const iv = fromBase64(data.iv);
        const cipher = fromBase64(data.cipher);
        const plainBuf = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            cryptoKey,
            cipher
        );

        const plainB64 = toBase64(new Uint8Array(plainBuf));
        console.log('âœ… Challenge dÃ©chiffrÃ© avec succÃ¨s, envoi de auth-response ok');
        peer.send(JSON.stringify({
            type: 'auth-response',
            ok: true,
            value: plainB64
        }));

        authVerified = true;
        elements.receiverStatus.textContent = 'Mot de passe validÃ©. Connexion sÃ©curisÃ©e.';
        
        // Initialiser Double Ratchet cÃ´tÃ© destinataire (non-initiator)
        if (fromOdId && cryptoKey) {
            try {
                const keyMaterial = await window.crypto.subtle.exportKey('raw', cryptoKey);
                const sharedSecret = new Uint8Array(keyMaterial);
                const dhPublicKey = await initializeDoubleRatchet(fromOdId, sharedSecret, false);
                
                // Envoyer notre clÃ© DH publique
                peer.send(JSON.stringify({
                    type: 'double-ratchet-init',
                    dhPublicKey: dhPublicKey
                }));
                console.log('ðŸ” Double Ratchet initialisÃ© cÃ´tÃ© destinataire pour', fromOdId);
            } catch (err) {
                console.error('âŒ Erreur init Double Ratchet destinataire:', err);
            }
        }
    } catch (err) {
        console.error('âŒ ERREUR dÃ©chiffrement - mot de passe incorrect ou donnÃ©es corrompu', err);
        if (peer) peer.send(JSON.stringify({ type: 'auth-response', ok: false, reason: 'bad-password' }));
        showError('Mot de passe incorrect.');
        peers.forEach(p => p.destroy());
        peers.clear();
    }
}

async function handleAuthResponse(data) {
    // CÃ´tÃ© expÃ©diteur
    console.log('ðŸ” handleAuthResponse reÃ§ue:', data);
    
    if (!usePassword) {
        console.log('âœ… Pas de mot de passe, ignorant auth-response');
        return;
    }

    if (!data.ok) {
        console.error('âŒ Mot de passe incorrect cÃ´tÃ© destinataire');
        showError('Mot de passe incorrect cÃ´tÃ© destinataire.');
        // DÃ©truire tous les peers
        peers.forEach(p => p.destroy());
        peers.clear();
        return;
    }

    if (expectedChallengeB64 && data.value === expectedChallengeB64) {
        console.log('âœ… Mot de passe vÃ©rifiÃ©! DÃ©marrage du transfert...');
        authVerified = true;
        
        // Initialiser Double Ratchet cÃ´tÃ© expÃ©diteur (initiator)
        const peer = getConnectedPeer();
        if (peer && peer._id && cryptoKey) {
            try {
                const keyMaterial = await window.crypto.subtle.exportKey('raw', cryptoKey);
                const sharedSecret = new Uint8Array(keyMaterial);
                const dhPublicKey = await initializeDoubleRatchet(peer._id, sharedSecret, true);
                
                // Envoyer notre clÃ© DH publique
                peer.send(JSON.stringify({
                    type: 'double-ratchet-init',
                    dhPublicKey: dhPublicKey
                }));
                console.log('ðŸ” Double Ratchet initialisÃ© cÃ´tÃ© expÃ©diteur pour', peer._id);
            } catch (err) {
                console.error('âŒ Erreur init Double Ratchet expÃ©diteur:', err);
            }
        }
        
        startFileTransfer();
    } else {
        console.error('âŒ Challenge response invalide');
        showError('VÃ©rification dÃ©cryptÃ©e Ã©chouÃ©e.');
        peers.forEach(p => p.destroy());
        peers.clear();
    }
}

async function handleDoubleRatchetInit(data, fromOdId) {
    if (!fromOdId || !data.dhPublicKey) {
        return;
    }
    
    // Si cryptoKey n'est pas encore disponible, bufferiser et attendre
    if (!cryptoKey) {
        pendingDoubleRatchetInits.set(fromOdId, { dhPublicKey: data.dhPublicKey });
        return;
    }
    
    // Si le Double Ratchet n'est pas encore initialisÃ©, bufferiser aussi
    if (!doubleRatchetState.has(fromOdId)) {
        pendingDoubleRatchetInits.set(fromOdId, { dhPublicKey: data.dhPublicKey });
        return;
    }
    
    const state = doubleRatchetState.get(fromOdId);
    
    // Si on n'a pas encore leur clÃ© publique, c'est la rÃ©ponse Ã  notre init
    if (!state.dhRatchet.theirPublicKeyB64) {
        try {
            await completeDoubleRatchetHandshake(fromOdId, data.dhPublicKey);
        } catch (err) {
            console.error('âŒ Handshake Double Ratchet:', err.message);
        }
        return;
    }
    
    // Sinon c'est un reload de l'autre cÃ´tÃ© â†’ rÃ©initialiser complÃ¨tement
    try {
        // Anti-boucle: ne pas renvoyer si on a dÃ©jÃ  rÃ©pondu rÃ©cemment (< 5s)
        const lastSent = lastDoubleRatchetInitSent.get(fromOdId) || 0;
        const now = Date.now();
        const shouldReply = (now - lastSent) > 5000;
        
        // Reset complet de notre Ã©tat
        doubleRatchetState.delete(fromOdId);
        
        // RÃ©initialiser avec nouvelle clÃ©
        const keyMaterial = await window.crypto.subtle.exportKey('raw', cryptoKey);
        const sharedSecret = new Uint8Array(keyMaterial);
        const amInitiator = isCreator;
        const dhPublicKey = await initializeDoubleRatchet(fromOdId, sharedSecret, amInitiator);
        
        // ComplÃ©ter avec leur clÃ©
        await completeDoubleRatchetHandshake(fromOdId, data.dhPublicKey);
        
        // Renvoyer notre nouvelle clÃ© UNE SEULE FOIS
        if (shouldReply) {
            ws.send(JSON.stringify({
                type: 'double-ratchet-init',
                to: fromOdId,
                publicKey: Array.from(dhPublicKey)
            }));
            lastDoubleRatchetInitSent.set(fromOdId, now);
        }
        
    } catch (err) {
        console.error('âŒ Handshake Double Ratchet:', err.message);
    }
}

async function handleDoubleRatchetMessage(encrypted, fromOdId) {
    if (!fromOdId || !encrypted.data || !encrypted.dhPublicKey) {
        console.error('âŒ Message Double Ratchet invalide');
        return;
    }
    
    try {
        // DÃ©chiffrer le message
        const decrypted = await receiveMessageWithDoubleRatchet(
            fromOdId,
            encrypted.data,
            encrypted.dhPublicKey
        );
        
        // Convertir en texte et parser le JSON original
        const decryptedText = new TextDecoder().decode(decrypted);
        const originalData = JSON.parse(decryptedText);
        
        // Message dÃ©chiffrÃ©
        
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
                console.warn('âš ï¸ Type de message dÃ©chiffrÃ© non gÃ©rÃ©:', originalData.type);
        }
    } catch (err) {
        console.error('âŒ Erreur dÃ©chiffrement Double Ratchet:', err);
    }
}

async function startFileTransfer() {
    if (usePassword && !authVerified) return;
    const peer = getConnectedPeer();
    if (!peer) {
        showError('Aucun peer connectÃ© pour le transfert.');
        return;
    }
    console.log('ðŸ“¤ DÃ©marrage du transfert...');
    
    elements.senderSection.classList.add('hidden');
    elements.linkSection.classList.add('hidden');
    elements.progressSection.classList.remove('hidden');
    elements.progressTitle.textContent = 'Envoi en cours...';
    
    transferStartTime = Date.now();
    
    // Envoyer les mÃ©tadonnÃ©es du fichier
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
        
        // CrÃ©er le paquet avec mÃ©tadonnÃ©es
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
    
    // Envoyer le hash final pour vÃ©rification
    const finalPacket = {
        type: 'complete',
        hash: senderFileHash
    };
    peer.send(JSON.stringify(finalPacket));
    
    console.log('âœ… Tous les chunks envoyÃ©s');
}

function handlePeerData(rawData, fromOdId) {
    try {
        const data = JSON.parse(rawData.toString());
        
        // DÃ©tecter et dÃ©chiffrer les messages Double Ratchet
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
                // RÃ©ception des mÃ©tadonnÃ©es du fichier
                fileInfo = {
                    name: data.name,
                    size: data.size,
                    mimeType: data.mimeType
                };
                elements.receiverSection.classList.add('hidden');
                elements.progressSection.classList.remove('hidden');
                elements.progressTitle.textContent = 'RÃ©ception en cours...';
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
        console.error('Erreur dÃ©chiffrement chunk:', err);
        showError('Erreur de dÃ©chiffrement. ClÃ© invalide ?');
    }
}

async function finalizeTransfer(expectedHash) {
    console.log('ðŸ”§ Reconstruction du fichier...');
    
    // Fusionner tous les chunks
    const totalLength = receivedChunks.reduce((acc, chunk) => acc + chunk.length, 0);
    const fileData = new Uint8Array(totalLength);
    let offset = 0;
    
    for (const chunk of receivedChunks) {
        fileData.set(chunk, offset);
        offset += chunk.length;
    }
    
    // VÃ©rifier l'intÃ©gritÃ©
    const calculatedHash = await calculateHash(fileData);
    const integrityOk = calculatedHash === expectedHash;
    
    if (!integrityOk) {
        console.warn('âš ï¸ Hash diffÃ©rent - fichier potentiellement corrompu');
        elements.integrityCheck.innerHTML = '<span class="integrity-icon">âš ï¸</span><span>Attention : intÃ©gritÃ© non vÃ©rifiÃ©e</span>';
        elements.integrityCheck.style.background = 'rgba(245, 158, 11, 0.1)';
        elements.integrityCheck.style.color = 'var(--warning)';
    }
    
    // CrÃ©er le Blob et dÃ©clencher le tÃ©lÃ©chargement
    const blob = new Blob([fileData], { type: fileInfo.mimeType || 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = fileInfo.name;
    a.click();
    
    URL.revokeObjectURL(url);
    
    // Afficher la section terminÃ©e
    hideAllSections();
    elements.completeSection.classList.remove('hidden');
    elements.completeMessage.textContent = `${fileInfo.name} (${formatFileSize(fileInfo.size)}) tÃ©lÃ©chargÃ© avec succÃ¨s !`;
    
    // Nettoyer
    receivedChunks = [];
    totalReceived = 0;
    
    // DÃ©truire tous les peers
    peers.forEach(p => p.destroy());
    peers.clear();
    
    // Effacer la session sauvegardÃ©e (transfert terminÃ©)
    clearSessionStorage();
    
    console.log('âœ… Transfert terminÃ© !');
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
    
    // Transfert terminÃ© cÃ´tÃ© expÃ©diteur
    if (percent >= 100 && !isReceiver) {
        setTimeout(() => {
            hideAllSections();
            elements.completeSection.classList.remove('hidden');
            elements.completeMessage.textContent = `${getSelectedFileName()} envoyÃ© avec succÃ¨s !`;
        }, 500);
    }
}

// ===== GÃ‰NÃ‰RATION DU LIEN =====

async function generateShareLink() {
    let link;
    const mode = sessionMode || 'file';
    let hashPart;
    
    if (usePassword) {
        // Lien avec mot de passe : roomId_mode_pwd_salt_iterations
        hashPart = `${roomId}_${mode}_pwd_${passwordSaltB64}_${passwordIterations}`;
        link = `${window.location.origin}${window.location.pathname}#${hashPart}`;
    } else {
        // Lien ECDH (sans clÃ© dans l'URL) : roomId_mode_ecdh
        hashPart = `${roomId}_${mode}_ecdh`;
        link = `${window.location.origin}${window.location.pathname}#${hashPart}`;
    }
    
    // Uniformiser: le crÃ©ateur bascule aussi sur l'URL avec hash
    if (window.location.hash !== `#${hashPart}`) {
        window.location.hash = hashPart;
        console.log('ðŸ”— CrÃ©ateur redirigÃ© vers:', hashPart);
    }
    
    elements.shareLink.value = link;
    elements.linkSection.classList.remove('hidden');
    
    // Afficher le badge "Session Ã©phÃ©mÃ¨re" dans le header
    showEphemeralBadge();
    
    // GÃ©nÃ©ration du QR Code
    const qrcodeContainer = document.getElementById('qrcode-container');
    const qrcodeDiv = document.getElementById('qrcode');
    if (qrcodeContainer && qrcodeDiv && window.QRCode) {
        qrcodeDiv.innerHTML = ''; // Effacer le prÃ©cÃ©dent
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
    
    console.log('ðŸ”— Lien de partage gÃ©nÃ©rÃ© (mode:', mode, ', ECDH)');
}

// ===== GESTION DES FICHIERS =====

// Multi-fichiers: crÃ©e automatiquement une archive ZIP cÃ´tÃ© navigateur
async function handleMultiFileSelect(files) {
    if (!files || files.length === 0) return;
    try {
        console.log('ðŸ“ SÃ©lection multiple:', files.map(f => f.name));
        // Indication UI le temps de la prÃ©paration
        elements.fileInfoDiv.classList.remove('hidden');
        elements.dropZone.classList.add('hidden');
        elements.passwordBlock.classList.remove('hidden');
        elements.fileName.textContent = 'PrÃ©paration de l\'archive...';
        elements.fileSize.textContent = '';

        // CrÃ©er le zip
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

        // RÃ©initialiser l'Ã©tat d'auth
        usePassword = false;
        passwordSaltB64 = null;
        authVerified = false;
        pendingChallenge = null;
        expectedChallengeB64 = null;
        
        // MÃ©moriser la liste pour le destinataire
        fileInfo = {
            name: archiveName,
            size: selectedFile.size,
            type: 'application/zip',
            passwordRequired: false,
            isArchive: true,
            files: files.map(f => ({ name: f.name, size: f.size }))
        };
    } catch (err) {
        console.error('âŒ Erreur multi-fichiers:', err);
        showError('Erreur lors de la prÃ©paration de l\'archive: ' + err.message);
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
        console.log('ðŸ“ Fichier sÃ©lectionnÃ©:', file.name);
        
        selectedFile = file;
        
        // Afficher les infos du fichier
        elements.fileName.textContent = file.name;
        elements.fileSize.textContent = formatFileSize(file.size);
        elements.fileInfoDiv.classList.remove('hidden');
        elements.dropZone.classList.add('hidden');
        elements.passwordBlock.classList.remove('hidden');
        
        // RÃ©initialiser l'Ã©tat d'auth
        usePassword = false;
        passwordSaltB64 = null;
        authVerified = false;
        pendingChallenge = null;
        expectedChallengeB64 = null;
    } catch (err) {
        console.error('âŒ Erreur dans handleFileSelect:', err);
        showError('Erreur lors de la sÃ©lection du fichier: ' + err.message);
        elements.fileInput.value = '';
    }
}

// Lance rÃ©ellement l'envoi : dÃ©rive la clÃ©, construit fileInfo, crÃ©e la room
async function startSend() {
    // En mode chat uniquement ou mode both, pas besoin de fichier
    if (sessionMode === 'file' && !selectedFile) {
        showToast('SÃ©lectionnez un fichier d\'abord');
        return;
    }
    try {
        // Choisir la stratÃ©gie de clÃ© : mot de passe ou ECDH (Ã©change de clÃ©s)
        const passwordValue = elements.passwordInput.value.trim();
        usePassword = passwordValue.length > 0;
        passwordSaltB64 = usePassword ? generatePasswordSalt() : null;
        passwordIterations = KDF_ITERATIONS;

        if (usePassword) {
            console.log('ðŸ” Mot de passe dÃ©tectÃ©, dÃ©rivation en cours...');
            cryptoKey = await deriveKeyFromPassword(passwordValue, passwordSaltB64, passwordIterations);
        } else {
            // Mode ECDH : gÃ©nÃ©rer une paire de clÃ©s, la clÃ© AES sera dÃ©rivÃ©e aprÃ¨s Ã©change
            console.log('ðŸ”‘ GÃ©nÃ©ration paire ECDH (Diffie-Hellman)...');
            await generateECDHKeyPair();
            // cryptoKey sera null jusqu'Ã  ce qu'un receiver rejoigne et qu'on dÃ©rive la clÃ© partagÃ©e
        }

        // Pour le mode chat uniquement ou both, pas besoin de fileInfo de fichier rÃ©el
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
            // Mode fichier : PrÃ©parer les infos du fichier AVEC paramÃ¨tres de mot de passe si applicable
            const baseInfo = {
                name: getSelectedFileName(),
                size: selectedFile.size,
                type: getSelectedFileType('application/octet-stream'),
                passwordRequired: usePassword
            };
            // Conserver les mÃ©tadonnÃ©es d'archive si dÃ©jÃ  dÃ©finies par handleMultiFileSelect
            if (fileInfo && fileInfo.isArchive && Array.isArray(fileInfo.files)) {
                fileInfo = { ...baseInfo, isArchive: true, files: fileInfo.files };
            } else {
                fileInfo = baseInfo;
            }

            if (usePassword) {
                fileInfo.passwordSalt = passwordSaltB64;
                fileInfo.passwordIterations = passwordIterations;
                console.log('ðŸ“‹ FileInfo avec mot de passe:', fileInfo);
            } else {
                console.log('ðŸ“‹ FileInfo sans mot de passe:', fileInfo);
            }
        }
        
        // Ajouter le mode de session aux infos
        fileInfo.sessionMode = sessionMode;

        // Se connecter au serveur WebSocket et crÃ©er la room
        connectWebSocket();
    } catch (err) {
        console.error('âŒ Erreur dans startSend:', err);
        showError('Erreur lors de la prÃ©paration de l\'envoi: ' + err.message);
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
        console.log('ðŸ” DÃ©rivation du mot de passe reÃ§u...');
        cryptoKey = await deriveKeyFromPassword(pwd, passwordSaltB64, passwordIterations);
        console.log('âœ… ClÃ© dÃ©rivÃ©e avec succÃ¨s');
        elements.receiverPasswordBlock.classList.add('hidden');
        
        // Pour le mode chat ou both, dÃ©marrer directement P2P
        if (sessionMode === 'chat' || sessionMode === 'both') {
            console.log('ðŸš€ Mode chat/both : dÃ©marrage P2P automatique...');
            
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
            
            // Notifier l'expÃ©diteur que le destinataire est prÃªt
            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ type: 'receiver-ready' }));
            }
            
            // DÃ©marrer le peer (non-initiateur)
            if (!peer) {
                initPeer(false);
            }
            
            // Traiter le challenge en attente si applicable
            if (pendingChallenge) {
                console.log('ðŸ“¬ Traitement du challenge en attente...');
                const challenge = pendingChallenge;
                pendingChallenge = null;
                await handleAuthChallenge(challenge);
            }
        } else {
            // Mode fichier : afficher le bouton "Recevoir le fichier"
            elements.receiverStatus.textContent = 'Mot de passe validÃ©. Cliquez sur le bouton pour recevoir le fichier.';
            if (elements.receiveFileBtn) {
                elements.receiveFileBtn.classList.remove('hidden');
            }
        }
        
        receiverReady = true;
    } catch (err) {
        console.error('âŒ Erreur dÃ©rivation mot de passe:', err);
        showError('Erreur : ' + err.message);
        elements.receiverPasswordBlock.classList.remove('hidden');
    }
}

// Fonction appelÃ©e quand l'utilisateur clique sur "Recevoir le fichier"
async function startReceiving() {
    if (!receiverReady || !cryptoKey) {
        showToast('Veuillez d\'abord entrer le mot de passe.');
        return;
    }
    
    elements.receiveFileBtn.classList.add('hidden');
    elements.receiverStatus.textContent = 'Connexion P2P en cours...';
    
    // DÃ©marrer le peer
    console.log('ðŸš€ Initialisation du peer...');
    if (!peer) {
        initPeer(false); // Receiver = non-initiateur
    }
    
    // Notifier l'expÃ©diteur que le destinataire est prÃªt
    console.log('ðŸ“¤ Envoi de receiver-ready Ã  l\'expÃ©diteur...');
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'receiver-ready' }));
    }

    // Puis traiter le challenge en attente
    if (pendingChallenge) {
        console.log('ðŸ“¬ Traitement du challenge en attente...');
        const challenge = pendingChallenge;
        pendingChallenge = null;
        await handleAuthChallenge(challenge);
    }
}

// ===== GESTION DES PSEUDOS =====

function updateConnectedUsersDropdown() {
    // Interface unifiÃ©e - un seul dropdown
    const dropdownEl = elements.connectedUsersDropdown;
    const sectionEl = elements.connectedUsersSection;
    
    console.log(`ðŸ”„ updateConnectedUsersDropdown: participants.size=${participants.size}`);
    
    if (!dropdownEl) {
        console.log('âš ï¸ Dropdown non trouvÃ©');
        return;
    }
    
    // Effacer les options existantes
    dropdownEl.innerHTML = '';
    
    // Ajouter l'utilisateur actuel
    const optionMe = document.createElement('option');
    optionMe.textContent = `${userPseudo} (vous)` + (isCreator ? ' ðŸ‘‘' : '');
    optionMe.disabled = true;
    dropdownEl.appendChild(optionMe);
    
    // Ajouter tous les participants (en Ã©vitant les doublons par pseudo)
    const addedPseudos = new Set([userPseudo]);
    participants.forEach((info, odId) => {
        // Ã‰viter les doublons (mÃªme pseudo)
        if (!addedPseudos.has(info.pseudo)) {
            addedPseudos.add(info.pseudo);
            const optionOther = document.createElement('option');
            optionOther.textContent = info.pseudo + (info.isCreator ? ' ðŸ‘‘' : '');
            optionOther.disabled = true;
            dropdownEl.appendChild(optionOther);
        }
    });
    
    // Toujours montrer la section dÃ¨s qu'il y a au moins 1 autre participant
    if (sectionEl) {
        if (participants.size > 0) {
            sectionEl.classList.remove('hidden');
            console.log('âœ… Section dropdown visible');
        } else {
            sectionEl.classList.add('hidden');
        }
    }
}

// ===== SAUVEGARDE ET RESTAURATION DE SESSION =====

async function saveSessionToStorage() {
    try {
        // Exporter la clÃ© crypto si elle existe (pour pouvoir la restaurer)
        let cryptoKeyB64 = null;
        if (cryptoKey) {
            try {
                cryptoKeyB64 = await exportKeyToBase64();
            } catch (e) {
                console.warn('âš ï¸ Impossible d\'exporter la clÃ© crypto:', e);
            }
        }
        
        // Exporter la paire ECDH si elle existe
        let ecdhExported = null;
        if (ecdhKeyPair) {
            try {
                ecdhExported = await exportECDHKeyPair();
            } catch (e) {
                console.warn('âš ï¸ Impossible d\'exporter la paire ECDH:', e);
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
            // Stocker la clÃ© crypto pour restauration
            cryptoKeyB64: cryptoKeyB64,
            // Stocker la paire ECDH pour restauration
            ecdhKeyPair: ecdhExported,
            timestamp: Date.now()
        };
        localStorage.setItem('securepeer_session', JSON.stringify(session));
        console.log('ðŸ’¾ Session sauvegardÃ©e (avec clÃ© crypto et ECDH)');
    } catch (err) {
        console.error('âŒ Erreur sauvegarde session:', err);
    }
}

function restoreSessionFromStorage() {
    try {
        const sessionData = localStorage.getItem('securepeer_session');
        if (!sessionData) return null;
        
        const session = JSON.parse(sessionData);
        
        // VÃ©rifier que la session n'est pas trop vieille (24h max)
        const age = Date.now() - session.timestamp;
        if (age > 24 * 60 * 60 * 1000) {
            console.log('â° Session expirÃ©e');
            clearSessionStorage();
            return null;
        }
        
        console.log('ðŸ“‚ Session restaurÃ©e:', session);
        return session;
    } catch (err) {
        console.error('âŒ Erreur restauration session:', err);
        return null;
    }
}

function clearSessionStorage() {
    localStorage.removeItem('securepeer_session');
    console.log('ðŸ—‘ï¸ Session effacÃ©e');
}

// ===== SAFETY NUMBERS - Persistence =====

/**
 * Charge les fingerprints connus depuis localStorage
 */
function loadKnownFingerprints() {
    try {
        const stored = localStorage.getItem('securepeer_known_fingerprints');
        if (stored) {
            const data = JSON.parse(stored);
            knownFingerprints = new Map(Object.entries(data));
            console.log('ðŸ“‚ Fingerprints connus chargÃ©s:', knownFingerprints.size);
        }
    } catch (err) {
        console.error('âŒ Erreur chargement fingerprints:', err);
    }
}

/**
 * Sauvegarde les fingerprints connus dans localStorage
 */
function saveKnownFingerprints() {
    try {
        const data = Object.fromEntries(knownFingerprints);
        localStorage.setItem('securepeer_known_fingerprints', JSON.stringify(data));
    } catch (err) {
        console.error('âŒ Erreur sauvegarde fingerprints:', err);
    }
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
    // Boutons pour fermer la session (attachÃ©s une seule fois)
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
    
    // Bouton de verrouillage de session (crÃ©ateur uniquement)
    if (elements.lockSessionBtn && !elements.lockSessionBtn._hasLockListener) {
        elements.lockSessionBtn.addEventListener('click', () => {
            toggleSessionLock();
        });
        elements.lockSessionBtn._hasLockListener = true;
    }
    
    console.log('ðŸšª Event listeners de fermeture de session attachÃ©s');
}

function handleHashConnection(hash) {
    // Mode destinataire - cacher la sÃ©lection de mode
    elements.modeSelection.classList.add('hidden');
    
    const parts = hash.split('_');
    roomId = parts[0];
    
    // Extraire le mode de session depuis le lien
    // Format: roomId_mode_...reste
    const modeFromLink = parts[1];
    let keyOrPasswordIndex = 2; // Index oÃ¹ commence la clÃ© ou 'pwd' ou 'ecdh'
    
    if (['file', 'chat', 'both'].includes(modeFromLink)) {
        sessionMode = modeFromLink;
    } else {
        sessionMode = 'file'; // Par dÃ©faut pour les anciens liens
        keyOrPasswordIndex = 1; // Pas de mode explicite, la clÃ©/pwd commence Ã  l'index 1
    }
    
    // Interface unifiÃ©e - utiliser showSessionInterface pour tout le monde
    const header = document.querySelector('#sender-section .sender-header h2');
    const desc = document.querySelector('#sender-section .section-desc');

    // Cas lien protÃ©gÃ© par mot de passe : roomId_mode_pwd_salt_iterations
    if (parts[keyOrPasswordIndex] === 'pwd') {
        isReceiver = true;
        usePassword = true;
        passwordRequired = true;
        passwordSaltB64 = parts[keyOrPasswordIndex + 1];
        passwordIterations = parts[keyOrPasswordIndex + 2] ? parseInt(parts[keyOrPasswordIndex + 2], 10) : KDF_ITERATIONS;

        // Interface unifiÃ©e
        elements.senderSection.classList.remove('hidden');
        elements.dropZone.classList.add('hidden');
        elements.passwordBlock.classList.remove('hidden');
        elements.sendFileBtn.textContent = 'ðŸ”“ DÃ©verrouiller';
        elements.linkStatus.textContent = 'Mot de passe requis pour dÃ©chiffrer.';
        showEphemeralBadge();
        
        // Adapter l'interface selon le mode
        if (sessionMode === 'chat') {
            if (header) header.textContent = 'ðŸ’¬ Rejoindre le chat';
            if (desc) desc.textContent = 'Entrez le mot de passe pour rejoindre la conversation';
            elements.chatSection.classList.remove('hidden');
        } else if (sessionMode === 'both') {
            if (header) header.textContent = 'ðŸ’¬ Chat + Fichiers';
            if (desc) desc.textContent = 'Entrez le mot de passe pour rejoindre la session';
            elements.chatSection.classList.remove('hidden');
            elements.bothFileSection.classList.remove('hidden');
        } else {
            if (header) header.textContent = 'ðŸ“¥ Recevoir un fichier';
            if (desc) desc.textContent = 'Entrez le mot de passe pour recevoir le fichier';
        }

        connectWebSocket();
    }
    // Cas ECDH (Ã©change de clÃ©s Diffie-Hellman) : roomId_mode_ecdh
    else if (parts[keyOrPasswordIndex] === 'ecdh') {
        isReceiver = true;
        usePassword = false;
        
        // Interface unifiÃ©e
        elements.senderSection.classList.remove('hidden');
        elements.dropZone.classList.add('hidden');
        elements.passwordBlock.classList.add('hidden');
        elements.linkSection.classList.remove('hidden');
        elements.linkStatus.textContent = 'Ã‰change de clÃ©s sÃ©curisÃ© en cours...';
        // Cacher les Ã©lÃ©ments inutiles pour le receiver
        if (elements.shareLink) elements.shareLink.parentElement.classList.add('hidden');
        if (document.getElementById('qrcode-container')) document.getElementById('qrcode-container').classList.add('hidden');
        showEphemeralBadge();
        
        // Adapter l'interface selon le mode
        if (sessionMode === 'chat') {
            if (header) header.textContent = 'ðŸ’¬ Rejoindre le chat';
            if (desc) desc.textContent = 'Connexion sÃ©curisÃ©e en cours...';
            elements.chatSection.classList.remove('hidden');
        } else if (sessionMode === 'both') {
            if (header) header.textContent = 'ðŸ’¬ Chat + Fichiers';
            if (desc) desc.textContent = 'Connexion sÃ©curisÃ©e en cours...';
            elements.chatSection.classList.remove('hidden');
            elements.bothFileSection.classList.remove('hidden');
        } else {
            if (header) header.textContent = 'ðŸ“¥ Recevoir un fichier';
            if (desc) desc.textContent = 'Connexion sÃ©curisÃ©e en cours...';
        }

        // GÃ©nÃ©rer notre paire ECDH puis connecter
        generateECDHKeyPair().then(() => {
            connectWebSocket();
        }).catch(err => {
            console.error('âŒ Erreur gÃ©nÃ©ration ECDH:', err);
            showError('Erreur lors de la gÃ©nÃ©ration des clÃ©s sÃ©curisÃ©es.');
        });
    } else {
        // Lien legacy avec clÃ© incluse (pour rÃ©trocompatibilitÃ©)
        const keyString = parts.slice(keyOrPasswordIndex).join('_');
        isReceiver = true;

        // Interface unifiÃ©e
        elements.senderSection.classList.remove('hidden');
        elements.dropZone.classList.add('hidden');
        elements.linkSection.classList.remove('hidden');
        elements.linkStatus.textContent = 'Connexion en cours...';
        showEphemeralBadge();
        
        // Adapter l'interface selon le mode
        if (sessionMode === 'chat') {
            if (header) header.textContent = 'ðŸ’¬ Rejoindre le chat';
            elements.chatSection.classList.remove('hidden');
        } else if (sessionMode === 'both') {
            if (header) header.textContent = 'ðŸ’¬ Chat + Fichiers';
            elements.chatSection.classList.remove('hidden');
            elements.bothFileSection.classList.remove('hidden');
        } else {
            if (header) header.textContent = 'ðŸ“¥ Recevoir un fichier';
        }

        importKeyFromBase64(keyString).then(() => {
            connectWebSocket();
        }).catch(err => {
            showError('Lien invalide : impossible de dÃ©coder la clÃ© de chiffrement.');
        });
    }
}

// ===== INITIALISATION =====

function init() {
    // VÃ©rifier la prÃ©sence de la Web Crypto API
    if (!window.crypto || !window.crypto.subtle) {
        showError('La Web Crypto API n\'est pas disponible dans ce navigateur. Utilisez Chrome, Firefox, Edge ou Safari rÃ©cent.');
        return;
    }
    
    // VÃ©rifier si on est en mode destinataire (URL avec hash = lien de partage)
    const hash = window.location.hash.substring(1);
    
    if (hash && hash.includes('_')) {
        // Lien de partage dÃ©tectÃ© - cacher la landing, demander pseudo puis connecter
        elements.landingPage.classList.add('hidden');
        showPseudoThenConnect(hash);
    } else {
        // Afficher la landing page par dÃ©faut
        elements.landingPage.classList.remove('hidden');
        elements.pseudoSection.classList.add('hidden');
        elements.modeSelection.classList.add('hidden');
        
        // Setup du bouton "Commencer"
        setupLandingPage();
    }
}

// Setup de la landing page
function setupLandingPage() {
    console.log('ðŸš€ setupLandingPage called, startSessionBtn:', elements.startSessionBtn);
    if (elements.startSessionBtn) {
        elements.startSessionBtn.addEventListener('click', () => {
            elements.startSessionBtn.disabled = true; // EmpÃªche le double clic
            console.log('âœ… Bouton Commencer cliquÃ©!');
            // Cacher la landing, montrer la sÃ©lection de mode directement
            elements.landingPage.classList.add('hidden');
            elements.modeSelection.classList.remove('hidden');
            // Setup des cartes de sÃ©lection de mode
            setupModeSelection();
        });
    } else {
        console.error('âŒ startSessionBtn non trouvÃ©!');
    }
}

// Demander le pseudo puis connecter (pour receivers)
function showPseudoThenConnect(hash) {
    // Toujours demander le pseudo, ignorer le pseudo sauvegardÃ©
    elements.pseudoSection.classList.remove('hidden');
    elements.pseudoInputMain.value = '';
    elements.pseudoInputMain?.focus();
    elements.pseudoConfirmBtn.onclick = () => {
        const pseudoValue = elements.pseudoInputMain.value.trim();
        if (!pseudoValue || pseudoValue.length < 3) {
            showToast('âš ï¸ Le pseudo doit faire au moins 3 caractÃ¨res');
            return;
        }
        if (pseudoValue.length > 20) {
            showToast('âš ï¸ Le pseudo doit faire maximum 20 caractÃ¨res');
            return;
        }
        // Sauvegarder le pseudo uniquement pour la session
        userPseudo = pseudoValue;
        localStorage.setItem('securepeer_pseudo', pseudoValue);
        console.log('âœ… Pseudo dÃ©fini:', userPseudo);
        // Cacher la section pseudo et connecter
        elements.pseudoSection.classList.add('hidden');
        handleHashConnection(hash);
        setupChat();
        setupBothModeFiles();
    };
}

// Afficher l'interface crÃ©ateur selon le mode
function showCreatorInterface(mode) {
    // Setup du chat et des fichiers
    setupChat();
    setupBothModeFiles();
    setupEventListeners();
    
    // RÃ©cupÃ©rer les Ã©lÃ©ments de header
    const header = document.querySelector('#sender-section .sender-header h2');
    const desc = document.querySelector('#sender-section .section-desc');
    
    // Afficher la section appropriÃ©e
    if (mode === 'chat') {
        elements.senderSection.classList.remove('hidden');
        elements.dropZone.classList.add('hidden');
        elements.passwordBlock.classList.remove('hidden');
        elements.sendFileBtn.textContent = 'ðŸ’¬ DÃ©marrer le chat';
        if (header) header.textContent = 'ðŸ’¬ Chat sÃ©curisÃ©';
        if (desc) desc.textContent = 'DÃ©marrez une conversation chiffrÃ©e de bout en bout';
    } else if (mode === 'file') {
        elements.senderSection.classList.remove('hidden');
        elements.dropZone.classList.remove('hidden');
        if (header) header.textContent = 'ðŸ“¤ Envoyer un fichier';
        if (desc) desc.textContent = 'Choisissez un fichier et partagez le lien sÃ©curisÃ©';
    } else {
        // mode 'both'
        elements.senderSection.classList.remove('hidden');
        elements.dropZone.classList.add('hidden');
        elements.passwordBlock.classList.remove('hidden');
        elements.sendFileBtn.textContent = 'ðŸš€ DÃ©marrer la session';
        if (header) header.textContent = 'ðŸ’¬ Chat + Fichiers';
        if (desc) desc.textContent = 'Discutez et Ã©changez des fichiers en temps rÃ©el';
    }
    console.log('ðŸ“‹ Interface crÃ©ateur affichÃ©e pour mode:', mode);
}

function continueInit() {
    // Cacher la section pseudo
    elements.pseudoSection.classList.add('hidden');
    
    // Mode expÃ©diteur - afficher la sÃ©lection de mode
    isReceiver = false;
    elements.modeSelection.classList.remove('hidden');
    elements.senderSection.classList.add('hidden');
    
    // Setup des cartes de sÃ©lection de mode
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
            console.error('âŒ Erreur dans file input change event:', err);
            showError('Erreur lors de la sÃ©lection du fichier');
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
        showToast('Lien copiÃ© !');
    });
    
    elements.newTransfer.addEventListener('click', () => {
        clearSessionStorage();
        location.reload();
    });
    
    elements.retryTransfer.addEventListener('click', () => {
        // Effacer la session pour Ã©viter de recharger une session invalide
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
    
    // SÃ©lecteur de langue: initialisÃ© une seule fois via DOMContentLoaded
    // (Ã©vite les doubles Ã©couteurs qui togglent deux fois et referment le menu)
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
    
    // SÃ©lection de langue
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
        fr: 'ðŸ‡«ðŸ‡· FR',
        en: 'ðŸ‡¬ðŸ‡§ EN',
        es: 'ðŸ‡ªðŸ‡¸ ES',
        it: 'ðŸ‡®ðŸ‡¹ IT',
        ru: 'ðŸ‡·ðŸ‡º RU'
    };
    
    if (languageToggle) {
        languageToggle.textContent = langNames[currentLanguage] || langNames.fr;
    }
    
    // Mettre Ã  jour l'option active
    document.querySelectorAll('.lang-option').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.lang === currentLanguage);
    });
    
    // Mettre Ã  jour les textes de la page
    const translations = {
        fr: {
            title: 'ðŸ”’ SecurePeer',
            subtitle: 'Transfert de fichiers chiffrÃ© de bout en bout, sans serveur intermÃ©diaire',
            modeTitle: 'ðŸš€ CrÃ©er une session',
            modeDesc: 'Choisissez le type de session que vous souhaitez dÃ©marrer',
            modeFile: 'Transfert de fichiers',
            modeFileDesc: 'Envoyez des fichiers de maniÃ¨re sÃ©curisÃ©e',
            modeChat: 'Chat sÃ©curisÃ©',
            modeChatDesc: 'Discutez en temps rÃ©el, chiffrÃ© E2E',
            modeBoth: 'Fichiers + Chat',
            modeBothDesc: 'TransfÃ©rez et discutez simultanÃ©ment',
            senderHeader: 'ðŸ“¤ Envoyer un fichier',
            sectionDesc: 'Choisissez un fichier et partagez le lien sÃ©curisÃ©',
            dropZone: 'Glissez-dÃ©posez un fichier ici',
            or: 'ou cliquez pour sÃ©lectionner',
            chooseFile: 'Choisir un fichier',
            deleteFile: 'âœ• Supprimer',
            password: 'ðŸ” Protection par mot de passe (optionnel)',
            passwordPlaceholder: 'Entrez un mot de passe pour plus de sÃ©curitÃ©',
            sendBtn: 'ðŸ“¤ Envoyer le fichier',
            startChatBtn: 'ðŸ’¬ DÃ©marrer le chat',
            passwordHint: 'Le mot de passe ne quitte jamais votre appareil',
            shareTitle: 'ðŸ”— Lien de partage gÃ©nÃ©rÃ©',
            linkInfo: 'Partagez ce lien avec le destinataire',
            copyBtn: 'ðŸ“‹ Copier',
            waiting: 'ðŸ“ En attente du destinataire...',
            chatTitle: 'ðŸ’¬ Chat sÃ©curisÃ©',
            chatPlaceholder: 'Tapez votre message...',
            chatSend: 'Envoyer',
            chatWaiting: 'En attente...',
            chatConnected: 'ConnectÃ©',
            chatP2PTitle: 'ðŸ’¬ Chat P2P sÃ©curisÃ©',
            chatFilesTitle: 'ðŸ’¬ Chat + Fichiers',
            filesTitle: 'ðŸ“ Fichiers',
            addFile: 'ðŸ“Ž Ajouter',
            sendFiles: 'ðŸ“¤ Envoyer',
            pending: 'En attente',
            receiving: 'RÃ©ception...',
            sent: 'EnvoyÃ©',
            download: 'ðŸ“¥ TÃ©lÃ©charger',
            receiverTitle: 'ðŸ“¥ RÃ©ception de fichier',
            receiverPassword: 'Mot de passe requis',
            receiverPasswordPlaceholder: 'Entrez le mot de passe partagÃ©',
            unlockBtn: 'DÃ©verrouiller',
            passwordHintReceiver: 'Le mot de passe reste sur cet appareil et dÃ©rive la clÃ© de chiffrement.',
            receiveBtn: 'ðŸ“¥ Recevoir le fichier',
            connecting: 'Connexion en cours...',
            transferProgress: 'Transfert en cours...',
            complete: 'Transfert terminÃ© !',
            integrity: 'IntÃ©gritÃ© vÃ©rifiÃ©e (SHA-256)',
            newTransfer: 'Nouveau transfert',
            qrHint: 'Scannez pour recevoir sur mobile',
            error: 'Erreur',
            retry: 'RÃ©essayer',
            footer: 'ðŸ” Chiffrement AES-256-GCM | ðŸŒ WebRTC P2P | ðŸš« Aucune donnÃ©e stockÃ©e sur le serveur | SecurePeer'
        },
        en: {
            title: 'ðŸ”’ SecurePeer',
            subtitle: 'End-to-end encrypted file transfer, no intermediate server',
            modeTitle: 'ðŸš€ Create a session',
            modeDesc: 'Choose the type of session you want to start',
            modeFile: 'File Transfer',
            modeFileDesc: 'Send files securely',
            modeChat: 'Secure Chat',
            modeChatDesc: 'Chat in real-time, E2E encrypted',
            modeBoth: 'Files + Chat',
            modeBothDesc: 'Transfer and chat simultaneously',
            senderHeader: 'ðŸ“¤ Send a file',
            sectionDesc: 'Choose a file and share the secure link',
            dropZone: 'Drag and drop a file here',
            or: 'or click to select',
            chooseFile: 'Choose a file',
            deleteFile: 'âœ• Delete',
            password: 'ðŸ” Password protection (optional)',
            passwordPlaceholder: 'Enter a password for extra security',
            sendBtn: 'ðŸ“¤ Send file',
            startChatBtn: 'ðŸ’¬ Start chat',
            passwordHint: 'Your password never leaves your device',
            shareTitle: 'ðŸ”— Share link generated',
            linkInfo: 'Share this link with the recipient',
            copyBtn: 'ðŸ“‹ Copy',
            waiting: 'ðŸ“ Waiting for recipient...',
            chatTitle: 'ðŸ’¬ Secure Chat',
            chatPlaceholder: 'Type your message...',
            chatSend: 'Send',
            chatWaiting: 'Waiting...',
            chatConnected: 'Connected',
            chatP2PTitle: 'ðŸ’¬ Secure P2P Chat',
            chatFilesTitle: 'ðŸ’¬ Chat + Files',
            filesTitle: 'ðŸ“ Files',
            addFile: 'ðŸ“Ž Add',
            sendFiles: 'ðŸ“¤ Send',
            pending: 'Pending',
            receiving: 'Receiving...',
            sent: 'Sent',
            download: 'ðŸ“¥ Download',
            receiverTitle: 'ðŸ“¥ Receiving file',
            receiverPassword: 'Password required',
            receiverPasswordPlaceholder: 'Enter the shared password',
            unlockBtn: 'Unlock',
            passwordHintReceiver: 'Password stays on this device and derives the encryption key.',
            receiveBtn: 'ðŸ“¥ Receive file',
            connecting: 'Connecting...',
            transferProgress: 'Transfer in progress...',
            complete: 'Transfer complete!',
            integrity: 'Integrity verified (SHA-256)',
            newTransfer: 'New transfer',
            qrHint: 'Scan to receive on mobile',
            error: 'Error',
            retry: 'Retry',
            footer: 'ðŸ” AES-256-GCM Encryption | ðŸŒ WebRTC P2P | ðŸš« No data stored on server | SecurePeer'
        },
        es: {
            title: 'ðŸ”’ SecurePeer',
            subtitle: 'Transferencia de archivos cifrada de extremo a extremo, sin servidor intermedio',
            modeTitle: 'ðŸš€ Crear una sesiÃ³n',
            modeDesc: 'Elige el tipo de sesiÃ³n que quieres iniciar',
            modeFile: 'Transferencia de archivos',
            modeFileDesc: 'EnvÃ­a archivos de forma segura',
            modeChat: 'Chat seguro',
            modeChatDesc: 'Chatea en tiempo real, cifrado E2E',
            modeBoth: 'Archivos + Chat',
            modeBothDesc: 'Transfiere y chatea simultÃ¡neamente',
            senderHeader: 'ðŸ“¤ Enviar un archivo',
            sectionDesc: 'Elige un archivo y comparte el enlace seguro',
            dropZone: 'Arrastra y suelta un archivo aquÃ­',
            or: 'o haz clic para seleccionar',
            chooseFile: 'Elegir un archivo',
            deleteFile: 'âœ• Eliminar',
            password: 'ðŸ” ProtecciÃ³n por contraseÃ±a (opcional)',
            passwordPlaceholder: 'Ingresa una contraseÃ±a para mayor seguridad',
            sendBtn: 'ðŸ“¤ Enviar archivo',
            startChatBtn: 'ðŸ’¬ Iniciar chat',
            passwordHint: 'Tu contraseÃ±a nunca sale de tu dispositivo',
            shareTitle: 'ðŸ”— Enlace de compartir generado',
            linkInfo: 'Comparte este enlace con el destinatario',
            copyBtn: 'ðŸ“‹ Copiar',
            waiting: 'ðŸ“ Esperando al destinatario...',
            chatTitle: 'ðŸ’¬ Chat seguro',
            chatPlaceholder: 'Escribe tu mensaje...',
            chatSend: 'Enviar',
            chatWaiting: 'Esperando...',
            chatConnected: 'Conectado',
            chatP2PTitle: 'ðŸ’¬ Chat P2P seguro',
            chatFilesTitle: 'ðŸ’¬ Chat + Archivos',
            filesTitle: 'ðŸ“ Archivos',
            addFile: 'ðŸ“Ž AÃ±adir',
            sendFiles: 'ðŸ“¤ Enviar',
            pending: 'Pendiente',
            receiving: 'Recibiendo...',
            sent: 'Enviado',
            download: 'ðŸ“¥ Descargar',
            receiverTitle: 'ðŸ“¥ Recibiendo archivo',
            receiverPassword: 'Se requiere contraseÃ±a',
            receiverPasswordPlaceholder: 'Ingresa la contraseÃ±a compartida',
            unlockBtn: 'Desbloquear',
            passwordHintReceiver: 'La contraseÃ±a se mantiene en este dispositivo y deriva la clave de cifrado.',
            receiveBtn: 'ðŸ“¥ Recibir archivo',
            connecting: 'Conectando...',
            transferProgress: 'Transferencia en progreso...',
            complete: 'Â¡Transferencia completada!',
            integrity: 'Integridad verificada (SHA-256)',
            newTransfer: 'Nueva transferencia',
            qrHint: 'Escanea para recibir en el mÃ³vil',
            error: 'Error',
            retry: 'Reintentar',
            footer: 'ðŸ” Cifrado AES-256-GCM | ðŸŒ WebRTC P2P | ðŸš« Sin datos almacenados en servidor | SecurePeer'
        },
        it: {
            title: 'ðŸ”’ SecurePeer',
            subtitle: 'Trasferimento file crittografato end-to-end, senza server intermediario',
            modeTitle: 'ðŸš€ Crea una sessione',
            modeDesc: 'Scegli il tipo di sessione che vuoi avviare',
            modeFile: 'Trasferimento file',
            modeFileDesc: 'Invia file in modo sicuro',
            modeChat: 'Chat sicura',
            modeChatDesc: 'Chatta in tempo reale, crittografato E2E',
            modeBoth: 'File + Chat',
            modeBothDesc: 'Trasferisci e chatta simultaneamente',
            senderHeader: 'ðŸ“¤ Invia un file',
            sectionDesc: 'Scegli un file e condividi il collegamento sicuro',
            dropZone: 'Trascina e rilascia un file qui',
            or: 'o fai clic per selezionare',
            chooseFile: 'Scegli un file',
            deleteFile: 'âœ• Elimina',
            password: 'ðŸ” Protezione con password (facoltativa)',
            passwordPlaceholder: 'Inserisci una password per maggiore sicurezza',
            sendBtn: 'ðŸ“¤ Invia file',
            startChatBtn: 'ðŸ’¬ Avvia chat',
            passwordHint: 'La tua password non lascia mai il tuo dispositivo',
            shareTitle: 'ðŸ”— Collegamento di condivisione generato',
            linkInfo: 'Condividi questo collegamento con il destinatario',
            copyBtn: 'ðŸ“‹ Copia',
            waiting: 'ðŸ“ In attesa del destinatario...',
            chatTitle: 'ðŸ’¬ Chat sicura',
            chatPlaceholder: 'Scrivi il tuo messaggio...',
            chatSend: 'Invia',
            chatWaiting: 'In attesa...',
            chatConnected: 'Connesso',
            chatP2PTitle: 'ðŸ’¬ Chat P2P sicura',
            chatFilesTitle: 'ðŸ’¬ Chat + File',
            filesTitle: 'ðŸ“ File',
            addFile: 'ðŸ“Ž Aggiungi',
            sendFiles: 'ðŸ“¤ Invia',
            pending: 'In attesa',
            receiving: 'Ricezione...',
            sent: 'Inviato',
            download: 'ðŸ“¥ Scarica',
            receiverTitle: 'ðŸ“¥ Ricezione file',
            receiverPassword: 'Password richiesta',
            receiverPasswordPlaceholder: 'Inserisci la password condivisa',
            unlockBtn: 'Sblocca',
            passwordHintReceiver: 'La password rimane su questo dispositivo e deriva la chiave di crittografia.',
            receiveBtn: 'ðŸ“¥ Ricevi file',
            connecting: 'Connessione in corso...',
            transferProgress: 'Trasferimento in corso...',
            complete: 'Trasferimento completato!',
            integrity: 'IntegritÃ  verificata (SHA-256)',
            newTransfer: 'Nuovo trasferimento',
            qrHint: 'Scansiona per ricevere sul cellulare',
            error: 'Errore',
            retry: 'Riprova',
            footer: 'ðŸ” Crittografia AES-256-GCM | ðŸŒ WebRTC P2P | ðŸš« Nessun dato archiviato sul server | SecurePeer'
        },
        ru: {
            title: 'ðŸ”’ SecurePeer',
            subtitle: 'Ð¡ÐºÐ²Ð¾Ð·Ð½Ð¾Ðµ Ð·Ð°ÑˆÐ¸Ñ„Ñ€Ð¾Ð²Ð°Ð½Ð½Ð°Ñ Ð¿ÐµÑ€ÐµÐ´Ð°Ñ‡Ð° Ñ„Ð°Ð¹Ð»Ð¾Ð² Ð±ÐµÐ· Ð¿Ñ€Ð¾Ð¼ÐµÐ¶ÑƒÑ‚Ð¾Ñ‡Ð½Ð¾Ð³Ð¾ ÑÐµÑ€Ð²ÐµÑ€Ð°',
            modeTitle: 'ðŸš€ Ð¡Ð¾Ð·Ð´Ð°Ñ‚ÑŒ ÑÐµÑÑÐ¸ÑŽ',
            modeDesc: 'Ð’Ñ‹Ð±ÐµÑ€Ð¸Ñ‚Ðµ Ñ‚Ð¸Ð¿ ÑÐµÑÑÐ¸Ð¸, ÐºÐ¾Ñ‚Ð¾Ñ€ÑƒÑŽ Ñ…Ð¾Ñ‚Ð¸Ñ‚Ðµ Ð½Ð°Ñ‡Ð°Ñ‚ÑŒ',
            modeFile: 'ÐŸÐµÑ€ÐµÐ´Ð°Ñ‡Ð° Ñ„Ð°Ð¹Ð»Ð¾Ð²',
            modeFileDesc: 'ÐžÑ‚Ð¿Ñ€Ð°Ð²Ð»ÑÐ¹Ñ‚Ðµ Ñ„Ð°Ð¹Ð»Ñ‹ Ð±ÐµÐ·Ð¾Ð¿Ð°ÑÐ½Ð¾',
            modeChat: 'Ð‘ÐµÐ·Ð¾Ð¿Ð°ÑÐ½Ñ‹Ð¹ Ñ‡Ð°Ñ‚',
            modeChatDesc: 'ÐžÐ±Ñ‰Ð°Ð¹Ñ‚ÐµÑÑŒ Ð² Ñ€ÐµÐ°Ð»ÑŒÐ½Ð¾Ð¼ Ð²Ñ€ÐµÐ¼ÐµÐ½Ð¸, E2E ÑˆÐ¸Ñ„Ñ€Ð¾Ð²Ð°Ð½Ð¸Ðµ',
            modeBoth: 'Ð¤Ð°Ð¹Ð»Ñ‹ + Ð§Ð°Ñ‚',
            modeBothDesc: 'ÐŸÐµÑ€ÐµÐ´Ð°Ð²Ð°Ð¹Ñ‚Ðµ Ð¸ Ð¾Ð±Ñ‰Ð°Ð¹Ñ‚ÐµÑÑŒ Ð¾Ð´Ð½Ð¾Ð²Ñ€ÐµÐ¼ÐµÐ½Ð½Ð¾',
            senderHeader: 'ðŸ“¤ ÐžÑ‚Ð¿Ñ€Ð°Ð²Ð¸Ñ‚ÑŒ Ñ„Ð°Ð¹Ð»',
            sectionDesc: 'Ð’Ñ‹Ð±ÐµÑ€Ð¸Ñ‚Ðµ Ñ„Ð°Ð¹Ð» Ð¸ Ð¿Ð¾Ð´ÐµÐ»Ð¸Ñ‚ÐµÑÑŒ Ð±ÐµÐ·Ð¾Ð¿Ð°ÑÐ½Ð¾Ð¹ ÑÑÑ‹Ð»ÐºÐ¾Ð¹',
            dropZone: 'ÐŸÐµÑ€ÐµÑ‚Ð°Ñ‰Ð¸Ñ‚Ðµ Ñ„Ð°Ð¹Ð» ÑÑŽÐ´Ð°',
            or: 'Ð¸Ð»Ð¸ Ð½Ð°Ð¶Ð¼Ð¸Ñ‚Ðµ Ð´Ð»Ñ Ð²Ñ‹Ð±Ð¾Ñ€Ð°',
            chooseFile: 'Ð’Ñ‹Ð±Ñ€Ð°Ñ‚ÑŒ Ñ„Ð°Ð¹Ð»',
            deleteFile: 'âœ• Ð£Ð´Ð°Ð»Ð¸Ñ‚ÑŒ',
            password: 'ðŸ” Ð—Ð°Ñ‰Ð¸Ñ‚Ð° Ð¿Ð°Ñ€Ð¾Ð»ÐµÐ¼ (Ð½ÐµÐ¾Ð±ÑÐ·Ð°Ñ‚ÐµÐ»ÑŒÐ½Ð¾)',
            passwordPlaceholder: 'Ð’Ð²ÐµÐ´Ð¸Ñ‚Ðµ Ð¿Ð°Ñ€Ð¾Ð»ÑŒ Ð´Ð»Ñ Ð´Ð¾Ð¿Ð¾Ð»Ð½Ð¸Ñ‚ÐµÐ»ÑŒÐ½Ð¾Ð¹ Ð±ÐµÐ·Ð¾Ð¿Ð°ÑÐ½Ð¾ÑÑ‚Ð¸',
            sendBtn: 'ðŸ“¤ ÐžÑ‚Ð¿Ñ€Ð°Ð²Ð¸Ñ‚ÑŒ Ñ„Ð°Ð¹Ð»',
            startChatBtn: 'ðŸ’¬ ÐÐ°Ñ‡Ð°Ñ‚ÑŒ Ñ‡Ð°Ñ‚',
            passwordHint: 'Ð’Ð°Ñˆ Ð¿Ð°Ñ€Ð¾Ð»ÑŒ Ð½Ð¸ÐºÐ¾Ð³Ð´Ð° Ð½Ðµ Ð¿Ð¾ÐºÐ¸Ð´Ð°ÐµÑ‚ Ð²Ð°ÑˆÐµ ÑƒÑÑ‚Ñ€Ð¾Ð¹ÑÑ‚Ð²Ð¾',
            shareTitle: 'ðŸ”— Ð¡ÑÑ‹Ð»ÐºÐ° Ð´Ð»Ñ Ð¾Ð±Ð¼ÐµÐ½Ð° ÑÐ¾Ð·Ð´Ð°Ð½Ð°',
            linkInfo: 'ÐŸÐ¾Ð´ÐµÐ»Ð¸Ñ‚ÐµÑÑŒ ÑÑ‚Ð¾Ð¹ ÑÑÑ‹Ð»ÐºÐ¾Ð¹ Ñ Ð¿Ð¾Ð»ÑƒÑ‡Ð°Ñ‚ÐµÐ»ÐµÐ¼',
            copyBtn: 'ðŸ“‹ ÐšÐ¾Ð¿Ð¸Ñ€Ð¾Ð²Ð°Ñ‚ÑŒ',
            waiting: 'ðŸ“ ÐžÐ¶Ð¸Ð´Ð°Ð½Ð¸Ðµ Ð¿Ð¾Ð»ÑƒÑ‡Ð°Ñ‚ÐµÐ»Ñ...',
            chatTitle: 'ðŸ’¬ Ð‘ÐµÐ·Ð¾Ð¿Ð°ÑÐ½Ñ‹Ð¹ Ñ‡Ð°Ñ‚',
            chatPlaceholder: 'Ð’Ð²ÐµÐ´Ð¸Ñ‚Ðµ ÑÐ¾Ð¾Ð±Ñ‰ÐµÐ½Ð¸Ðµ...',
            chatSend: 'ÐžÑ‚Ð¿Ñ€Ð°Ð²Ð¸Ñ‚ÑŒ',
            chatWaiting: 'ÐžÐ¶Ð¸Ð´Ð°Ð½Ð¸Ðµ...',
            chatConnected: 'ÐŸÐ¾Ð´ÐºÐ»ÑŽÑ‡ÐµÐ½',
            chatP2PTitle: 'ðŸ’¬ Ð‘ÐµÐ·Ð¾Ð¿Ð°ÑÐ½Ñ‹Ð¹ P2P Ñ‡Ð°Ñ‚',
            chatFilesTitle: 'ðŸ’¬ Ð§Ð°Ñ‚ + Ð¤Ð°Ð¹Ð»Ñ‹',
            filesTitle: 'ðŸ“ Ð¤Ð°Ð¹Ð»Ñ‹',
            addFile: 'ðŸ“Ž Ð”Ð¾Ð±Ð°Ð²Ð¸Ñ‚ÑŒ',
            sendFiles: 'ðŸ“¤ ÐžÑ‚Ð¿Ñ€Ð°Ð²Ð¸Ñ‚ÑŒ',
            pending: 'ÐžÐ¶Ð¸Ð´Ð°Ð½Ð¸Ðµ',
            receiving: 'ÐŸÐ¾Ð»ÑƒÑ‡ÐµÐ½Ð¸Ðµ...',
            sent: 'ÐžÑ‚Ð¿Ñ€Ð°Ð²Ð»ÐµÐ½Ð¾',
            download: 'ðŸ“¥ Ð¡ÐºÐ°Ñ‡Ð°Ñ‚ÑŒ',
            receiverTitle: 'ðŸ“¥ ÐŸÐ¾Ð»ÑƒÑ‡ÐµÐ½Ð¸Ðµ Ñ„Ð°Ð¹Ð»Ð°',
            receiverPassword: 'Ð¢Ñ€ÐµÐ±ÑƒÐµÑ‚ÑÑ Ð¿Ð°Ñ€Ð¾Ð»ÑŒ',
            receiverPasswordPlaceholder: 'Ð’Ð²ÐµÐ´Ð¸Ñ‚Ðµ Ð¾Ð±Ñ‰Ð¸Ð¹ Ð¿Ð°Ñ€Ð¾Ð»ÑŒ',
            unlockBtn: 'Ð Ð°Ð·Ð±Ð»Ð¾ÐºÐ¸Ñ€Ð¾Ð²Ð°Ñ‚ÑŒ',
            passwordHintReceiver: 'ÐŸÐ°Ñ€Ð¾Ð»ÑŒ Ð¾ÑÑ‚Ð°ÐµÑ‚ÑÑ Ð½Ð° ÑÑ‚Ð¾Ð¼ ÑƒÑÑ‚Ñ€Ð¾Ð¹ÑÑ‚Ð²Ðµ Ð¸ Ð¿Ñ€Ð¾Ð¸Ð·Ð²Ð¾Ð´Ð¸Ñ‚ ÐºÐ»ÑŽÑ‡ ÑˆÐ¸Ñ„Ñ€Ð¾Ð²Ð°Ð½Ð¸Ñ.',
            receiveBtn: 'ðŸ“¥ ÐŸÐ¾Ð»ÑƒÑ‡Ð¸Ñ‚ÑŒ Ñ„Ð°Ð¹Ð»',
            connecting: 'ÐŸÐ¾Ð´ÐºÐ»ÑŽÑ‡ÐµÐ½Ð¸Ðµ...',
            transferProgress: 'ÐŸÐµÑ€ÐµÐ´Ð°Ñ‡Ð° Ð² Ð¿Ñ€Ð¾Ñ†ÐµÑÑÐµ...',
            complete: 'ÐŸÐµÑ€ÐµÐ´Ð°Ñ‡Ð° Ð·Ð°Ð²ÐµÑ€ÑˆÐµÐ½Ð°!',
            integrity: 'Ð¦ÐµÐ»Ð¾ÑÑ‚Ð½Ð¾ÑÑ‚ÑŒ Ð¿Ñ€Ð¾Ð²ÐµÑ€ÐµÐ½Ð° (SHA-256)',
            newTransfer: 'ÐÐ¾Ð²Ð°Ñ Ð¿ÐµÑ€ÐµÐ´Ð°Ñ‡Ð°',
            qrHint: 'Ð¡ÐºÐ°Ð½Ð¸Ñ€ÑƒÐ¹Ñ‚Ðµ Ð´Ð»Ñ Ð¿Ð¾Ð»ÑƒÑ‡ÐµÐ½Ð¸Ñ Ð½Ð° Ð¼Ð¾Ð±Ð¸Ð»ÑŒÐ½Ð¾Ð¼',
            error: 'ÐžÑˆÐ¸Ð±ÐºÐ°',
            retry: 'ÐŸÐ¾Ð²Ñ‚Ð¾Ñ€Ð¸Ñ‚ÑŒ',
            footer: 'ðŸ” Ð¨Ð¸Ñ„Ñ€Ð¾Ð²Ð°Ð½Ð¸Ðµ AES-256-GCM | ðŸŒ WebRTC P2P | ðŸš« ÐÐµÑ‚ Ð´Ð°Ð½Ð½Ñ‹Ñ…, Ñ…Ñ€Ð°Ð½ÑÑ‰Ð¸Ñ…ÑÑ Ð½Ð° ÑÐµÑ€Ð²ÐµÑ€Ðµ | SecurePeer'
        }
    };
    
    const t = translations[currentLanguage] || translations.fr;
    
    // Mettre Ã  jour les Ã©lÃ©ments DOM (avec garde anti-null)
    const heroTitleEl = document.querySelector('.hero-content h1');
    if (heroTitleEl) heroTitleEl.textContent = t.title;
    const subtitleEl = document.querySelector('.subtitle');
    if (subtitleEl) subtitleEl.textContent = t.subtitle;
    
    // Mettre Ã  jour le header sender - selon le mode de session actuel
    const senderHeader = document.querySelector('.sender-header h2');
    const sectionDesc = document.querySelector('.section-desc');
    if (sessionMode === 'chat') {
        if (senderHeader) senderHeader.textContent = t.chatTitle || 'ðŸ’¬ Chat sÃ©curisÃ©';
        if (sectionDesc) sectionDesc.textContent = t.modeChatDesc || 'Discutez en temps rÃ©el, chiffrÃ© E2E';
    } else if (sessionMode === 'both') {
        if (senderHeader) senderHeader.textContent = t.chatFilesTitle || 'ðŸ’¬ Chat + Fichiers';
        if (sectionDesc) sectionDesc.textContent = t.modeBothDesc || 'TransfÃ©rez et discutez simultanÃ©ment';
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
    console.log('ðŸš€ [INIT] DOMContentLoaded - DÃ©marrage de l\'application');
    
    // Charger les fingerprints connus
    loadKnownFingerprints();
    
    // VÃ©rifier d'abord si on a un hash (lien de partage)
    const hash = window.location.hash.substring(1);
    const hasShareLink = hash && hash.includes('_');
    
    // RÃ©cupÃ©rer la session stockÃ©e
    const restored = restoreSessionFromStorage();
    
    console.log('ðŸ” [INIT] Hash URL:', hash || '(aucun)');
    console.log('ðŸ” [INIT] Session stockÃ©e:', restored);
    
    // PRIORITÃ‰ 1: Lien de partage (receiver qui arrive ou revient)
    if (hasShareLink) {
        // Extraire le roomId du hash
        const hashRoomId = hash.split('_')[0];
        console.log('ðŸ”— [INIT] Lien de partage dÃ©tectÃ©, roomId:', hashRoomId);
        
        // VÃ©rifier si c'est la mÃªme session que celle stockÃ©e
        if (restored && restored.roomId === hashRoomId) {
            // MÃªme room: vÃ©rifier si c'est le crÃ©ateur ou le receiver
            if (restored.isCreator) {
                console.log('ðŸ‘‘ [INIT] CrÃ©ateur qui rafraÃ®chit (avec hash URL), restauration...');
                await restoreCreatorSession(restored);
            } else if (restored.isReceiver) {
                console.log('ðŸ”„ [INIT] Receiver qui rafraÃ®chit, restauration...');
                await restoreReceiverSession(restored, hash);
            } else {
                console.log('ðŸ†• [INIT] Nouvelle visite via lien, flow receiver normal');
                clearSessionStorage();
                elements.landingPage.classList.add('hidden');
                showPseudoThenConnect(hash);
            }
        } else {
            console.log('ðŸ†• [INIT] Nouvelle visite via lien, flow receiver normal');
            // Effacer toute ancienne session pour Ã©viter les conflits
            clearSessionStorage();
            // Flow normal pour nouveau receiver
            elements.landingPage.classList.add('hidden');
            showPseudoThenConnect(hash);
        }
    }
    // PRIORITÃ‰ 2: Session crÃ©ateur stockÃ©e (crÃ©ateur qui rafraÃ®chit)
    else if (restored && restored.roomId && !restored.isReceiver && restored.sessionMode) {
        console.log('ðŸ‘‘ [INIT] Session crÃ©ateur dÃ©tectÃ©e, restauration...');
        await restoreCreatorSession(restored);
    }
    // PRIORITÃ‰ 3: Pas de session, afficher la landing page
    else {
        console.log('ðŸ  [INIT] Pas de session, affichage landing page');
        // Effacer toute session invalide
        if (restored) clearSessionStorage();
        setupPseudoSection();
        init();
    }
    
    setupLanguageSelector();
    updateLanguage();
    setupThemeToggle();
    
    // VÃ©rifier et afficher le popup Tor (premiÃ¨re utilisation)
    checkAndShowTorPopup();
    
    // Attacher les event listeners des boutons de fermeture de session (toujours, quel que soit le mode)
    setupCloseSessionButtons();
    
    // Initialiser les fonctionnalitÃ©s du chat
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
    console.log('ðŸ‘‘ [RESTORE-CREATOR] DÃ©but restauration crÃ©ateur');
    
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
    
    console.log('   ðŸ“¦ roomId:', roomId);
    console.log('   ðŸ“‹ mode:', sessionMode);
    console.log('   ðŸ‘¤ pseudo:', userPseudo);
    console.log('   ðŸ”‘ odId:', myOdId);
    
    // Cacher les sections non nÃ©cessaires
    if (elements.landingPage) elements.landingPage.classList.add('hidden');
    if (elements.modeSelection) elements.modeSelection.classList.add('hidden');
    if (elements.pseudoSection) elements.pseudoSection.classList.add('hidden');
    
    // Restaurer la clÃ© crypto depuis la session stockÃ©e (au lieu d'en gÃ©nÃ©rer une nouvelle)
    if (restored.cryptoKeyB64) {
        try {
            await importKeyFromBase64(restored.cryptoKeyB64);
            console.log('ðŸ” [RESTORE-CREATOR] ClÃ© crypto RESTAURÃ‰E depuis localStorage');
        } catch (err) {
            console.error('âŒ [RESTORE-CREATOR] Erreur import clÃ©:', err);
            // Ne pas gÃ©nÃ©rer de nouvelle clÃ©, on utilisera ECDH
        }
    }
    
    // Restaurer la paire ECDH si elle existe
    if (restored.ecdhKeyPair) {
        try {
            const success = await importECDHKeyPair(restored.ecdhKeyPair);
            if (success) {
                console.log('ðŸ” [RESTORE-CREATOR] Paire ECDH RESTAURÃ‰E depuis localStorage');
            } else {
                // GÃ©nÃ©rer une nouvelle paire ECDH
                await generateECDHKeyPair();
                console.log('ðŸ” [RESTORE-CREATOR] Nouvelle paire ECDH gÃ©nÃ©rÃ©e (import Ã©chouÃ©)');
            }
        } catch (err) {
            console.error('âŒ [RESTORE-CREATOR] Erreur import ECDH:', err);
            await generateECDHKeyPair();
            console.log('ðŸ” [RESTORE-CREATOR] Nouvelle paire ECDH gÃ©nÃ©rÃ©e (erreur)');
        }
    } else if (!usePassword && !restored.cryptoKeyB64) {
        // Pas de clÃ© stockÃ©e et pas de mot de passe, gÃ©nÃ©rer ECDH
        await generateECDHKeyPair();
        console.log('ðŸ” [RESTORE-CREATOR] Nouvelle paire ECDH gÃ©nÃ©rÃ©e (pas de clÃ© stockÃ©e)');
    }
    
    // Restaurer ou rÃ©gÃ©nÃ©rer fileInfo selon le mode
    if (restored.fileInfo) {
        // Utiliser le fileInfo stockÃ©
        fileInfo = restored.fileInfo;
        console.log('   ðŸ“„ fileInfo restaurÃ©:', fileInfo.name);
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
    
    // Afficher l'interface crÃ©ateur
    showCreatorInterface(sessionMode);
    
    // Afficher la section lien avec statut "en attente"
    if (elements.linkSection) elements.linkSection.classList.remove('hidden');
    if (elements.linkStatus) {
        elements.linkStatus.innerHTML = `<span class="pulse"></span> Reconnexion en cours...`;
    }
    
    // Se reconnecter au WebSocket
    console.log('ðŸŒ [RESTORE-CREATOR] Connexion WebSocket...');
    connectWebSocket();
    
    showToast('Session crÃ©ateur restaurÃ©e');
}

async function restoreReceiverSession(restored, hash) {
    console.log('ðŸ“¥ [RESTORE-RECEIVER] DÃ©but restauration receiver');
    
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
    
    console.log('   ðŸ“¦ roomId:', roomId);
    console.log('   ðŸ“‹ mode:', sessionMode);
    console.log('   ðŸ‘¤ pseudo:', userPseudo);
    console.log('   ðŸ”‘ odId:', myOdId);
    console.log('   ðŸ” usePassword:', usePassword);
    console.log('   ðŸ” cryptoKeyB64 stockÃ©:', !!restored.cryptoKeyB64);
    
    // Cacher les sections non nÃ©cessaires
    if (elements.landingPage) elements.landingPage.classList.add('hidden');
    if (elements.modeSelection) elements.modeSelection.classList.add('hidden');
    if (elements.pseudoSection) elements.pseudoSection.classList.add('hidden');
    
    // Interface unifiÃ©e - utiliser sender-section pour tout le monde
    elements.senderSection.classList.remove('hidden');
    elements.dropZone.classList.add('hidden');
    elements.linkSection.classList.remove('hidden');
    // Cacher les Ã©lÃ©ments crÃ©ateur-only
    if (elements.shareLink) elements.shareLink.parentElement.classList.add('hidden');
    if (document.getElementById('qrcode-container')) document.getElementById('qrcode-container').classList.add('hidden');
    
    // Adapter le header selon le mode
    const header = document.querySelector('#sender-section .sender-header h2');
    const desc = document.querySelector('#sender-section .section-desc');
    if (sessionMode === 'chat') {
        if (header) header.textContent = 'ðŸ’¬ Chat sÃ©curisÃ©';
        if (desc) desc.textContent = 'Reconnexion en cours...';
    } else if (sessionMode === 'both') {
        if (header) header.textContent = 'ðŸ’¬ Chat + Fichiers';
        if (desc) desc.textContent = 'Reconnexion en cours...';
    } else {
        if (header) header.textContent = 'ðŸ“¥ Recevoir un fichier';
        if (desc) desc.textContent = 'Reconnexion en cours...';
    }
    
    // Afficher le badge "Session Ã©phÃ©mÃ¨re" dans le header
    showEphemeralBadge();
    
    // GÃ©rer la clÃ© crypto
    if (usePassword && !restored.cryptoKeyB64) {
        // Session protÃ©gÃ©e par mot de passe ET pas de clÃ© stockÃ©e - redemander le mot de passe
        console.log('ðŸ” [RESTORE-RECEIVER] Session protÃ©gÃ©e, redemander mot de passe');
        elements.linkStatus.textContent = 'Entrez le mot de passe pour reprendre la session';
        elements.passwordBlock.classList.remove('hidden');
        elements.sendFileBtn.textContent = 'ðŸ”“ DÃ©verrouiller';
        elements.sendFileBtn.onclick = async () => {
            await applyReceiverPassword();
            // AprÃ¨s application du mot de passe, se reconnecter
            if (cryptoKey) {
                console.log('ðŸŒ [RESTORE-RECEIVER] Mot de passe OK, connexion WebSocket...');
                connectWebSocket();
            }
        };
        showToast('Entrez le mot de passe pour reprendre votre session');
        return; // Ne pas continuer tant que le mot de passe n'est pas entrÃ©
    }
    
    // Restaurer la clÃ© depuis la session stockÃ©e (prioritÃ©) ou depuis le hash (fallback)
    if (restored.cryptoKeyB64) {
        try {
            await importKeyFromBase64(restored.cryptoKeyB64);
            console.log('ðŸ” [RESTORE-RECEIVER] ClÃ© crypto RESTAURÃ‰E depuis localStorage');
        } catch (err) {
            console.error('âŒ [RESTORE-RECEIVER] Erreur import clÃ© stockÃ©e:', err);
            // La clÃ© sera dÃ©rivÃ©e via ECDH aprÃ¨s connexion
        }
    }
    
    // Restaurer la paire ECDH si elle existe
    if (restored.ecdhKeyPair) {
        try {
            const success = await importECDHKeyPair(restored.ecdhKeyPair);
            if (success) {
                console.log('ðŸ” [RESTORE-RECEIVER] Paire ECDH RESTAURÃ‰E depuis localStorage');
            } else {
                // GÃ©nÃ©rer une nouvelle paire ECDH
                await generateECDHKeyPair();
                console.log('ðŸ” [RESTORE-RECEIVER] Nouvelle paire ECDH gÃ©nÃ©rÃ©e');
            }
        } catch (err) {
            console.error('âŒ [RESTORE-RECEIVER] Erreur import ECDH:', err);
            await generateECDHKeyPair();
        }
    } else if (!usePassword && !restored.cryptoKeyB64) {
        // Pas de clÃ© et pas de mot de passe, gÃ©nÃ©rer ECDH pour le nouvel Ã©change
        await generateECDHKeyPair();
        console.log('ðŸ” [RESTORE-RECEIVER] Nouvelle paire ECDH gÃ©nÃ©rÃ©e (pas de clÃ© stockÃ©e)');
    }
    
    // Afficher le chat/fichiers selon le mode (interface unifiÃ©e)
    if (sessionMode === 'chat' || sessionMode === 'both') {
        elements.chatSection.classList.remove('hidden');
        if (sessionMode === 'both') {
            elements.bothFileSection.classList.remove('hidden');
        }
    }
    
    // Mettre Ã  jour le statut
    elements.linkStatus.textContent = 'Reconnexion en cours...';
    
    // Setup chat et fichiers
    setupChat();
    setupBothModeFiles();
    
    // Se reconnecter au WebSocket
    console.log('ðŸŒ [RESTORE-RECEIVER] Connexion WebSocket...');
    connectWebSocket();
    
    showToast('Session receiver restaurÃ©e');
}

function setupThemeToggle() {
    const themeToggle = document.getElementById('theme-toggle');
    const currentTheme = localStorage.getItem('theme') || 'light';
    
    // Appliquer le thÃ¨me initial
    if (currentTheme === 'dark') {
        document.documentElement.setAttribute('data-theme', 'dark');
    }
    
    if (themeToggle) {
        themeToggle.addEventListener('click', () => {
            const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
            const newTheme = isDark ? 'light' : 'dark';
            
            document.documentElement.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
            
            console.log('ðŸŒ“ ThÃ¨me changÃ© en:', newTheme);
        });
    }
}

// ===== SÃ‰LECTION DU PSEUDO =====
function setupPseudoSection() {
    // Event listener pour le bouton confirmer pseudo
    if (elements.pseudoConfirmBtn) {
        elements.pseudoConfirmBtn.addEventListener('click', () => {
            const pseudoValue = elements.pseudoInputMain.value.trim();
            if (!pseudoValue || pseudoValue.length < 3) {
                showToast('âš ï¸ Le pseudo doit faire au moins 3 caractÃ¨res');
                return;
            }
            if (pseudoValue.length > 20) {
                showToast('âš ï¸ Le pseudo doit faire maximum 20 caractÃ¨res');
                return;
            }
            // Sauvegarder le pseudo UNIQUEMENT si pas dÃ©jÃ  dÃ©fini
            if (!userPseudo || userPseudo !== pseudoValue) {
                userPseudo = pseudoValue;
                localStorage.setItem('securepeer_pseudo', pseudoValue);
                console.log('âœ… Pseudo dÃ©fini:', userPseudo);
            }
            // Cacher la section pseudo et continuer
            elements.pseudoSection.classList.add('hidden');
            continueInit();
        });
    }
    // Permettre EntrÃ©e pour confirmer
    if (elements.pseudoInputMain) {
        elements.pseudoInputMain.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                elements.pseudoConfirmBtn.click();
            }
        });
    }
}

// Demander le pseudo puis afficher l'interface crÃ©ateur
function showPseudoForCreator(mode) {
    console.log('ðŸŽ­ [PSEUDO] showPseudoForCreator appelÃ© pour mode:', mode);
    // Toujours demander le pseudo (prÃ©-remplir si sauvegardÃ©)
    const savedPseudo = localStorage.getItem('securepeer_pseudo');
    // Afficher la section pseudo
    elements.pseudoSection.classList.remove('hidden');
    // PrÃ©-remplir si un pseudo est sauvegardÃ©
    if (savedPseudo) {
        elements.pseudoInputMain.value = savedPseudo;
    } else {
        elements.pseudoInputMain.value = '';
    }
    elements.pseudoInputMain?.focus();
    
    // CrÃ©er un nouveau bouton pour Ã©viter les conflits d'event listeners
    const oldBtn = elements.pseudoConfirmBtn;
    const newBtn = oldBtn.cloneNode(true);
    oldBtn.parentNode.replaceChild(newBtn, oldBtn);
    elements.pseudoConfirmBtn = newBtn;
    
    // Attacher le handler spÃ©cifique pour le crÃ©ateur
    newBtn.addEventListener('click', () => {
        const pseudoValue = elements.pseudoInputMain.value.trim();
        if (!pseudoValue || pseudoValue.length < 3) {
            showToast('âš ï¸ Le pseudo doit faire au moins 3 caractÃ¨res');
            return;
        }
        if (pseudoValue.length > 20) {
            showToast('âš ï¸ Le pseudo doit faire maximum 20 caractÃ¨res');
            return;
        }
        // Sauvegarder le pseudo
        userPseudo = pseudoValue;
        localStorage.setItem('securepeer_pseudo', pseudoValue);
        console.log('âœ… [PSEUDO] Pseudo dÃ©fini:', userPseudo);
        // Cacher la section pseudo et afficher l'interface crÃ©ateur
        elements.pseudoSection.classList.add('hidden');
        console.log('ðŸŽ¨ [PSEUDO] Appel de showCreatorInterface pour mode:', mode);
        showCreatorInterface(mode);
    });
}

// ===== SÃ‰LECTION DU MODE =====
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
            
            // Marquer la carte sÃ©lectionnÃ©e
            modeCards.forEach(c => c.classList.remove('selected'));
            card.classList.add('selected');
            
            // Cacher la sÃ©lection de mode, demander le pseudo
            elements.modeSelection.classList.add('hidden');
            
            // Demander le pseudo avant de continuer
            showPseudoForCreator(mode);
            
            console.log('ðŸ“‹ Mode sÃ©lectionnÃ©:', mode);
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
    // Interface unifiÃ©e - toujours les mÃªmes Ã©lÃ©ments
    return {
        inputEl: elements.chatInput,
        messagesEl: elements.chatMessages,
        statusEl: elements.chatStatus
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
    
    // Annuler l'Ã©dition si active
    editingMessageId = null;
    document.querySelectorAll('.editing-indicator').forEach(ind => ind.remove());
    
    // Ajouter un indicateur visuel de rÃ©ponse
    const replyIndicator = document.createElement('div');
    replyIndicator.className = 'reply-indicator';
    replyIndicator.innerHTML = `
        <div class="reply-preview">
            <span class="reply-icon">â†©</span>
            <div class="reply-info">
                <strong>${escapeHtml(target.pseudo || 'Message')}</strong>
                <span>${escapeHtml(target.text.slice(0, 50))}${target.text.length > 50 ? 'â€¦' : ''}</span>
            </div>
            <button class="cancel-reply-btn" onclick="cancelReply()">âœ•</button>
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
        // Mode Ã©dition : envoyer un patch
        if (editingMessageId) {
            const editPayload = {
                type: 'chat-edit',
                messageId: editingMessageId,
                text: text, // Envoi en clair temporairement pour l'Ã©dition
                senderPseudo: userPseudo,
                timestamp: Date.now()
            };
            broadcastToAllPeers(editPayload);

            // Mise Ã  jour locale
            const target = findMessageById(editingMessageId);
            if (target) {
                target.text = text;
                target.edited = true;
            }
            inputEl.value = '';
            clearReplyEditState(isReceiverSide);
            renderChatMessages(messagesEl);
            console.log('âœï¸ Message Ã©ditÃ©');
            return;
        }

        const messageId = generateMessageId();
        const now = Date.now();
        const messageData = {
            type: 'chat-message',
            messageId,
            replyToId: replyToMessageId,
            text: text, // Le texte sera chiffrÃ© par Double Ratchet
            senderPseudo: userPseudo,
            timestamp: now,
            ephemeralDuration: ephemeralMode ? ephemeralDuration : null
        };
        broadcastToAllPeers(messageData);

        // Local append
        chatMessages.push({
            id: messageId,
            text,
            isSent: true,
            pseudo: userPseudo,
            timestamp: now,
            replyToId: replyToMessageId,
            edited: false,
            deleted: false,
            reactions: {},
            ephemeral: ephemeralMode ? ephemeralDuration : null,
            ephemeralExpiry: ephemeralMode ? now + (ephemeralDuration * 1000) : null
        });
        inputEl.value = '';
        clearReplyEditState(isReceiverSide);
        renderChatMessages(messagesEl);
        
        // Programmer la suppression si Ã©phÃ©mÃ¨re
        if (ephemeralMode) {
            scheduleMessageDeletion(messageId, ephemeralDuration);
        }
        
        console.log('ðŸ’¬ Message envoyÃ© Ã ', peers.size, 'peer(s)');
    } catch (err) {
        console.error('âŒ Erreur envoi message:', err);
        showToast('Erreur lors de l\'envoi du message');
    }
}

async function handleChatMessage(data, fromOdId) {
    try {
        // Le message est dÃ©jÃ  dÃ©chiffrÃ© si passÃ© par handleDoubleRatchetMessage
        // Sinon c'est un ancien format avec iv/ciphertext
        let text;
        
        if (data.text) {
            // Nouveau format: texte dÃ©jÃ  dÃ©chiffrÃ© par Double Ratchet
            text = data.text;
        } else if (data.iv && data.ciphertext) {
            // Ancien format: dÃ©chiffrer avec AES-GCM (compatibilitÃ©)
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
            console.error('âŒ Format de message invalide');
            return;
        }
        
        // RÃ©cupÃ©rer le pseudo de l'expÃ©diteur
        const senderPseudo = data.senderPseudo || participants.get(fromOdId)?.pseudo || 'Anonyme';
        const messagesEl = elements.chatMessages;
        
        const messageId = data.messageId || generateMessageId();
        const now = Date.now();
        const ephemeralDur = data.ephemeralDuration || (ephemeralMode ? ephemeralDuration : null);
        
        chatMessages.push({
            id: messageId,
            text,
            isSent: false,
            pseudo: senderPseudo,
            timestamp: data.timestamp || now,
            replyToId: data.replyToId || null,
            edited: false,
            deleted: false,
            reactions: {},
            ephemeral: ephemeralDur,
            ephemeralExpiry: ephemeralDur ? now + (ephemeralDur * 1000) : null
        });
        renderChatMessages(messagesEl);
        
        // Programmer la suppression si Ã©phÃ©mÃ¨re
        if (ephemeralDur) {
            scheduleMessageDeletion(messageId, ephemeralDur);
            scheduleMessageDeletion(messageId, ephemeralDuration);
        }
        
        console.log('ðŸ’¬ Message reÃ§u de', senderPseudo);
    } catch (err) {
        console.error('âŒ Erreur traitement message:', err);
    }
}

function renderChatMessages(containerEl) {
    if (!containerEl) return;
    containerEl.innerHTML = '';
    const reactionList = ['ðŸ‘', 'â¤ï¸', 'ðŸ˜‚', 'ðŸ˜®', 'ðŸ˜¢', 'ðŸ‘'];

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
            
            // Filtre par mot-clÃ©
            if (chatSearchQuery) {
                const text = (msg.text || '').toLowerCase();
                if (!text.includes(chatSearchQuery.toLowerCase())) return false;
            }
            
            searchMatchCount++;
            return true;
        });
    }
    
    // Mettre Ã  jour le compteur de rÃ©sultats
    updateSearchResultsCount(searchMatchCount);

    filteredMessages.forEach(msg => {
        const msgWrapper = document.createElement('div');
        msgWrapper.className = `message-wrapper ${msg.isSent ? 'sent' : 'received'}`;
        msgWrapper.dataset.messageId = msg.id;
        
        // Badge Ã©pinglÃ©
        if (pinnedMessageIds.has(msg.id)) {
            msgWrapper.classList.add('pinned');
        }

        const msgBubble = document.createElement('div');
        msgBubble.className = 'message-bubble';

        // Pseudo (pour messages reÃ§us en groupe)
        if (!msg.isSent && msg.pseudo && participants.size > 1) {
            const pseudoEl = document.createElement('div');
            pseudoEl.className = 'message-author';
            pseudoEl.textContent = msg.pseudo;
            msgBubble.appendChild(pseudoEl);
        }

        // RÃ©ponse/quote avec style amÃ©liorÃ©
        if (msg.replyToId && !msg.deleted) {
            const target = findMessageById(msg.replyToId);
            if (target) {
                const replyBar = document.createElement('div');
                replyBar.className = 'message-reply-bar';
                
                const replyIcon = document.createElement('span');
                replyIcon.className = 'reply-icon';
                replyIcon.textContent = 'â†©';
                
                const replyContent = document.createElement('div');
                replyContent.className = 'reply-content';
                
                const replyAuthor = document.createElement('div');
                replyAuthor.className = 'reply-author';
                replyAuthor.textContent = target.pseudo || (target.isSent ? 'Vous' : 'Message');
                
                const replyText = document.createElement('div');
                replyText.className = 'reply-text';
                const truncated = target.text.slice(0, 60);
                replyText.textContent = truncated + (target.text.length > 60 ? 'â€¦' : '');
                
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
            contentEl.innerHTML = '<em>ðŸ—‘ï¸ Message supprimÃ©</em>';
        } else {
            // Mettre en surbrillance les termes de recherche
            if (chatSearchQuery && msg.text) {
                contentEl.innerHTML = highlightSearchTerm(escapeHtml(msg.text), chatSearchQuery);
            } else {
                contentEl.textContent = msg.text;
            }
            
            // Indicateur d'Ã©dition discret
            if (msg.edited) {
                const editBadge = document.createElement('span');
                editBadge.className = 'edit-badge';
                editBadge.textContent = 'modifiÃ©';
                editBadge.title = 'Ce message a Ã©tÃ© modifiÃ©';
                contentEl.appendChild(editBadge);
            }
        }
        msgBubble.appendChild(contentEl);

        // RÃ©actions (affichÃ©es dans la bulle)
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
                
                // Bouton + pour ajouter une nouvelle rÃ©action
                const addReactionBtn = document.createElement('button');
                addReactionBtn.className = 'reaction-pill add-reaction';
                addReactionBtn.innerHTML = 'âž•';
                addReactionBtn.title = 'Ajouter une rÃ©action';
                addReactionBtn.onclick = (e) => {
                    e.stopPropagation();
                    toggleReactionPicker(msg.id, msgWrapper);
                };
                reactionsContainer.appendChild(addReactionBtn);
                
                msgBubble.appendChild(reactionsContainer);
            }
        }

        // Footer avec timestamp et countdown Ã©phÃ©mÃ¨re
        const footer = document.createElement('div');
        footer.className = 'message-meta';
        
        const timeEl = document.createElement('span');
        timeEl.className = 'message-time';
        timeEl.textContent = new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        footer.appendChild(timeEl);
        
        // Countdown Ã©phÃ©mÃ¨re si activÃ© et message pas encore expirÃ©
        if (msg.ephemeralExpiry && !msg.deleted) {
            const countdownEl = document.createElement('span');
            countdownEl.className = 'ephemeral-countdown';
            countdownEl.dataset.messageId = msg.id;
            countdownEl.style.marginLeft = '8px';
            countdownEl.style.color = '#ff6b6b';
            countdownEl.style.fontWeight = 'bold';
            footer.appendChild(countdownEl);
            
            // Mettre Ã  jour le countdown immÃ©diatement
            updateEphemeralCountdown(msg.id, msg.ephemeralExpiry, countdownEl);
        }
        
        msgBubble.appendChild(footer);
        msgWrapper.appendChild(msgBubble);

        // Menu d'actions (visible au hover)
        if (!msg.deleted) {
            const actionsMenu = document.createElement('div');
            actionsMenu.className = 'message-actions-menu';

            // Bouton rÃ©action (ouvre le picker)
            const reactionBtn = document.createElement('button');
            reactionBtn.className = 'action-btn reaction-btn';
            reactionBtn.innerHTML = 'âž•';
            reactionBtn.title = 'Ajouter une rÃ©action';
            reactionBtn.onclick = (e) => {
                e.stopPropagation();
                toggleReactionPicker(msg.id, msgWrapper);
            };
            actionsMenu.appendChild(reactionBtn);

            // Bouton rÃ©pondre
            const replyBtn = document.createElement('button');
            replyBtn.className = 'action-btn reply-btn';
            replyBtn.innerHTML = 'â†©';
            replyBtn.title = 'RÃ©pondre';
            replyBtn.onclick = () => setReplyPreview(msg.id, isReceiver);
            actionsMenu.appendChild(replyBtn);
            
            // Bouton Ã©pingler
            const pinBtn = document.createElement('button');
            pinBtn.className = 'action-btn pin-btn';
            pinBtn.innerHTML = pinnedMessageIds.has(msg.id) ? 'ðŸ“Œ' : 'ðŸ“';
            pinBtn.title = pinnedMessageIds.has(msg.id) ? 'DÃ©sÃ©pingler' : 'Ã‰pingler';
            pinBtn.onclick = () => togglePinMessage(msg.id);
            actionsMenu.appendChild(pinBtn);

            // Boutons Ã©diter/supprimer (uniquement pour mes messages)
            if (msg.isSent) {
                const editBtn = document.createElement('button');
                editBtn.className = 'action-btn edit-btn';
                editBtn.innerHTML = 'âœï¸';
                editBtn.title = 'Modifier';
                editBtn.onclick = () => startEditingMessage(msg.id);
                actionsMenu.appendChild(editBtn);

                const deleteBtn = document.createElement('button');
                deleteBtn.className = 'action-btn delete-btn';
                deleteBtn.innerHTML = 'ðŸ—‘ï¸';
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

    const container = elements.chatMessages;
    renderChatMessages(container);
}

function toggleReactionPicker(messageId, msgWrapper) {
    // Fermer tout picker ouvert
    document.querySelectorAll('.reaction-picker-popup').forEach(p => p.remove());
    
    const reactionList = ['ðŸ‘', 'â¤ï¸', 'ðŸ˜‚', 'ðŸ˜®', 'ðŸ˜¢', 'ðŸ‘', 'ðŸ”¥', 'ðŸŽ‰'];
    
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
    
    // Ajouter au body pour Ã©viter les problÃ¨mes de dÃ©bordement
    document.body.appendChild(picker);
    
    // Positionner le picker prÃ¨s du message
    const wrapperRect = msgWrapper.getBoundingClientRect();
    const pickerWidth = 280; // Largeur approximative du picker
    const pickerHeight = 50; // Hauteur approximative
    
    // Position horizontale: centrÃ© par rapport au message
    let left = wrapperRect.left + (wrapperRect.width / 2) - (pickerWidth / 2);
    
    // VÃ©rifier les limites horizontales
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
    
    // Fermer au clic extÃ©rieur
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
    
    // Ajouter un indicateur visuel d'Ã©dition
    const editingIndicator = document.createElement('div');
    editingIndicator.className = 'editing-indicator';
    editingIndicator.innerHTML = `
        <span>âœï¸ Modification du message</span>
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
    const container = elements.chatMessages;
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
    statusEl.textContent = `${pseudo} Ã©crit...`;
    statusEl.classList.add('typing');
    clearTimeout(typingIndicatorTimer);
    typingIndicatorTimer = setTimeout(() => updateChatStatus(true), 2500);
}

async function handleChatEdit(data, fromOdId) {
    try {
        let text;
        
        if (data.text) {
            // Nouveau format: dÃ©jÃ  dÃ©chiffrÃ©
            text = data.text;
        } else if (data.iv && data.ciphertext) {
            // Ancien format: dÃ©chiffrer avec AES-GCM
            const iv = fromBase64(data.iv);
            const ciphertext = fromBase64(data.ciphertext);
            const decrypted = await window.crypto.subtle.decrypt(
                { name: 'AES-GCM', iv },
                cryptoKey,
                ciphertext
            );
            text = new TextDecoder().decode(decrypted);
        } else {
            console.error('âŒ Format d\'Ã©dition invalide');
            return;
        }
        
        const msg = findMessageById(data.messageId);
        if (msg) {
            msg.text = text;
            msg.edited = true;
            msg.deleted = false;
        }
        const container = elements.chatMessages;
        renderChatMessages(container);
    } catch (err) {
        console.error('âŒ Erreur handleChatEdit:', err);
    }
}

function handleChatDelete(data) {
    const msg = findMessageById(data.messageId);
    if (msg) {
        msg.deleted = true;
        const container = elements.chatMessages;
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
    const container = elements.chatMessages;
    renderChatMessages(container);
}

function updateChatStatus(connected) {
    const statusEls = [elements.chatStatus, elements.receiverChatStatus];
    const connectedPeers = Array.from(peers.values()).filter(p => p.connected).length;
    statusEls.forEach(el => {
        if (el) {
            el.textContent = connected ? `ConnectÃ© (${connectedPeers + 1} participants)` : 'En attente...';
            el.classList.toggle('connected', connected);
            el.classList.remove('typing');
        }
    });
}

// ===== RECHERCHE DANS LE CHAT =====

function setupChatSearch() {
    // CrÃ©ateur
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
            countEl.textContent = `${count} rÃ©sultat(s)`;
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

// ===== MESSAGES Ã‰PINGLÃ‰S =====

function setupPinnedMessages() {
    // CrÃ©ateur
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
        showToast('Message dÃ©sÃ©pinglÃ©');
    } else {
        pinnedMessageIds.add(messageId);
        showToast('ðŸ“Œ Message Ã©pinglÃ©');
    }
    
    // Synchroniser avec les autres participants
    broadcastToAllPeers({
        type: 'chat-pin',
        messageId,
        action: pinnedMessageIds.has(messageId) ? 'pin' : 'unpin'
    });
    
    const container = elements.chatMessages;
    renderChatMessages(container);
    renderPinnedMessages(isReceiver);
}

function handleChatPin(data) {
    if (data.action === 'pin') {
        pinnedMessageIds.add(data.messageId);
    } else {
        pinnedMessageIds.delete(data.messageId);
    }
    
    const container = elements.chatMessages;
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
        listEl.innerHTML = '<p class="no-pins">Aucun message Ã©pinglÃ©</p>';
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
        text.textContent = msg.text.slice(0, 50) + (msg.text.length > 50 ? 'â€¦' : '');
        
        const unpinBtn = document.createElement('button');
        unpinBtn.className = 'unpin-btn';
        unpinBtn.innerHTML = 'âœ•';
        unpinBtn.title = 'DÃ©sÃ©pingler';
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
    const container = elements.chatMessages;
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
    // CrÃ©ateur
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
            <button class="modal-close" aria-label="Fermer">Ã—</button>
            <div class="modal-header">
                <div class="modal-icon">ðŸ“¥</div>
                <div>
                    <h3>Exporter la conversation</h3>
                    <p class="modal-subtitle">Fichier local, rien n'est envoyÃ© au serveur.</p>
                </div>
            </div>
            <div class="export-grid">
                <button class="option-card export-txt-btn">
                    <div class="option-icon">ðŸ“„</div>
                    <div class="option-title">Texte (.txt) <span class="option-badge">Rapide</span></div>
                    <div class="option-desc">Brut et lÃ©ger, lisible partout.</div>
                    <div class="option-meta">IdÃ©al pour archiver</div>
                </button>
                <button class="option-card export-html-btn">
                    <div class="option-icon">ðŸŒ</div>
                    <div class="option-title">HTML stylÃ©</div>
                    <div class="option-desc">Mise en page avec couleurs et badges.</div>
                    <div class="option-meta">IdÃ©al pour imprimer</div>
                </button>
            </div>
            <div class="modal-footer">
                <span class="modal-note">âš ï¸ Les autres participants seront notifiÃ©s.</span>
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
        const edited = msg.edited ? ' (modifiÃ©)' : '';
        const pinned = pinnedMessageIds.has(msg.id) ? ' ðŸ“Œ' : '';
        
        content += `[${time}] ${author}${edited}${pinned}:\n`;
        content += `${msg.text}\n\n`;
    });
    
    content += `${'='.repeat(50)}\n`;
    content += `Total: ${chatMessages.filter(m => !m.deleted).length} messages\n`;
    
    downloadFile(content, `securepeer-chat-${roomId}.txt`, 'text/plain');
    showToast('âœ… Conversation exportÃ©e en TXT');
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
        <h1>ðŸ”’ SecurePeer</h1>
        <p>Export de conversation</p>
        <p>Date: ${new Date().toLocaleString()}</p>
        <p>Session: ${roomId} | Mode: ${sessionMode}</p>
    </div>
    <div class="messages">`;
    
    chatMessages.forEach(msg => {
        if (msg.deleted) return;
        
        const time = new Date(msg.timestamp).toLocaleString();
        const author = msg.isSent ? userPseudo : (msg.pseudo || 'Anonyme');
        const edited = msg.edited ? '<span class="badge">modifiÃ©</span>' : '';
        const pinned = pinnedMessageIds.has(msg.id) ? ' pinned' : '';
        const pinnedBadge = pinnedMessageIds.has(msg.id) ? '<span class="badge">ðŸ“Œ</span>' : '';
        
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
        <p>ExportÃ© depuis SecurePeer - Chiffrement E2E</p>
    </div>
</body>
</html>`;
    
    downloadFile(html, `securepeer-chat-${roomId}.html`, 'text/html');
    showToast('âœ… Conversation exportÃ©e en HTML');
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
    showToast(`ðŸ“¥ ${data.pseudo} a exportÃ© la conversation (${data.format})`, 5000);
}

// ===== MESSAGES Ã‰PHÃ‰MÃˆRES =====

function setupEphemeralMessages() {
    // CrÃ©ateur
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
    
    // Bouton vÃ©rification d'identitÃ© (crÃ©ateur)
    const verifyBtn = document.getElementById('verify-identity-btn');
    if (verifyBtn) {
        verifyBtn.addEventListener('click', () => showSafetyNumbersModal());
    }
    
    // Bouton vÃ©rification d'identitÃ© (receiver)
    const rVerifyBtn = document.getElementById('receiver-verify-identity-btn');
    if (rVerifyBtn) {
        rVerifyBtn.addEventListener('click', () => showSafetyNumbersModal());
    }
}

function updateEphemeralButton(btn) {
    if (!btn) return;
    btn.classList.toggle('active', ephemeralMode);
    btn.title = ephemeralMode 
        ? `Messages Ã©phÃ©mÃ¨res: ${ephemeralDuration}s` 
        : 'Messages Ã©phÃ©mÃ¨res (dÃ©sactivÃ©)';
}

function showEphemeralDialog() {
    const popup = openChatModal(`
        <div class="export-content modal-card">
            <button class="modal-close" aria-label="Fermer">Ã—</button>
            <div class="modal-header">
                <div class="modal-icon">â±ï¸</div>
                <div>
                    <h3>Messages Ã©phÃ©mÃ¨res</h3>
                    <p class="modal-subtitle">Suppression automatique aprÃ¨s le dÃ©lai choisi.</p>
                </div>
            </div>
            <div class="ephemeral-body">
                <label class="toggle-row">
                    <span>Activer</span>
                    <input type="checkbox" id="ephemeral-enabled" ${ephemeralMode ? 'checked' : ''}>
                </label>
                <div class="ephemeral-duration-row">
                    <label for="ephemeral-duration-select">DurÃ©e</label>
                    <select id="ephemeral-duration-select">
                        <option value="10" ${ephemeralDuration === 10 ? 'selected' : ''}>10 secondes</option>
                        <option value="30" ${ephemeralDuration === 30 ? 'selected' : ''}>30 secondes</option>
                        <option value="60" ${ephemeralDuration === 60 ? 'selected' : ''}>1 minute</option>
                        <option value="300" ${ephemeralDuration === 300 ? 'selected' : ''}>5 minutes</option>
                        <option value="600" ${ephemeralDuration === 600 ? 'selected' : ''}>10 minutes</option>
                    </select>
                </div>
                <p class="modal-note">âš ï¸ SynchronisÃ© avec tous les participants.</p>
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
        
        // Warning si dÃ©sactivÃ©
        if (!enabled) {
            const warningHtml = `
                <div class="export-content modal-card" style="border: 2px solid #ffc107;">
                    <button class="modal-close" aria-label="Fermer">Ã—</button>
                    <div class="modal-header" style="background: #fff3cd;">
                        <div class="modal-icon">âš ï¸</div>
                        <div>
                            <h3>Messages Ã©phÃ©mÃ¨res dÃ©sactivÃ©s</h3>
                            <p class="modal-subtitle">Vos messages ne seront plus automatiquement supprimÃ©s</p>
                        </div>
                    </div>
                    <div style="padding: 20px;">
                        <p>Les messages persisteront dans le navigateur jusqu'Ã  ce que vous fermiez la session.</p>
                        <p style="margin-top: 10px;"><strong>Pour une sÃ©curitÃ© maximale, nous recommandons de garder les messages Ã©phÃ©mÃ¨res activÃ©s.</strong></p>
                    </div>
                    <div class="modal-footer">
                        <button class="btn btn-primary">Compris</button>
                    </div>
                </div>
            `;
            setTimeout(() => openChatModal(warningHtml), 500);
        }
        
        // Synchroniser avec les autres
        broadcastToAllPeers({
            type: 'chat-ephemeral-sync',
            enabled: ephemeralMode,
            duration: ephemeralDuration,
            pseudo: userPseudo
        });
        
        updateAllEphemeralButtons();
        showToast(ephemeralMode 
            ? `â±ï¸ Messages Ã©phÃ©mÃ¨res: ${ephemeralDuration}s` 
            : 'â±ï¸ Messages Ã©phÃ©mÃ¨res dÃ©sactivÃ©s');
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
        const preview = msg.text.slice(0, 120) + (msg.text.length > 120 ? 'â€¦' : '');
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
    const listHtml = items.length ? items.join('') : '<div class="no-pins">Aucun message Ã©pinglÃ©</div>';
    const popup = openChatModal(`
        <div class="export-content modal-card">
            <button class="modal-close" aria-label="Fermer">Ã—</button>
            <div class="modal-header">
                <div class="modal-icon">ðŸ“Œ</div>
                <div>
                    <h3>Messages Ã©pinglÃ©s</h3>
                    <p class="modal-subtitle">Clique pour naviguer dans la conversation.</p>
                </div>
            </div>
            <div class="pinned-modal-list">${listHtml}</div>
            <div class="modal-footer">
                <span class="modal-note">SynchronisÃ© entre tous les participants.</span>
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
        ? `â±ï¸ ${data.pseudo} a activÃ© les messages Ã©phÃ©mÃ¨res (${data.duration}s)`
        : `â±ï¸ ${data.pseudo} a dÃ©sactivÃ© les messages Ã©phÃ©mÃ¨res`);
}

function updateAllEphemeralButtons() {
    updateEphemeralButton(document.getElementById('chat-ephemeral-toggle'));
    updateEphemeralButton(document.getElementById('receiver-chat-ephemeral-toggle'));
}

// ===== SAFETY NUMBERS (VÃ©rification d'identitÃ©) =====

function showSafetyNumbersModal() {
    const modal = document.getElementById('safety-numbers-modal');
    if (!modal) return;
    
    // Afficher mon fingerprint
    const myNumberEl = document.getElementById('my-safety-number');
    if (myFingerprint) {
        myNumberEl.textContent = myFingerprint;
    } else {
        myNumberEl.textContent = 'âŒ ClÃ© non gÃ©nÃ©rÃ©e';
    }
    
    // Afficher le fingerprint du premier peer connectÃ©
    const peerNumberEl = document.getElementById('peer-safety-number');
    if (peerFingerprints.size > 0) {
        const firstPeerFingerprint = Array.from(peerFingerprints.values())[0];
        peerNumberEl.textContent = firstPeerFingerprint;
    } else {
        peerNumberEl.textContent = 'â³ Aucun correspondant connectÃ©';
    }
    
    // GÃ©nÃ©rer QR codes
    const myQrDiv = document.getElementById('my-safety-qr');
    const peerQrDiv = document.getElementById('peer-safety-qr');
    
    if (myFingerprint && window.QRCode) {
        myQrDiv.innerHTML = '';
        new QRCode(myQrDiv, {
            text: myFingerprint,
            width: 150,
            height: 150,
            correctLevel: QRCode.CorrectLevel.M
        });
    }
    
    if (peerFingerprints.size > 0 && window.QRCode) {
        const firstPeerFingerprint = Array.from(peerFingerprints.values())[0];
        peerQrDiv.innerHTML = '';
        new QRCode(peerQrDiv, {
            text: firstPeerFingerprint,
            width: 150,
            height: 150,
            correctLevel: QRCode.CorrectLevel.M
        });
    }
    
    // Afficher la modal
    modal.classList.remove('hidden');
    
    // Event listener pour fermer
    const closeBtn = document.getElementById('safety-numbers-close');
    if (closeBtn) {
        closeBtn.onclick = () => modal.classList.add('hidden');
    }
}

/**
 * Affiche une alerte de sÃ©curitÃ© critique quand le fingerprint change
 */
function showSecurityAlert(odId, oldFingerprint, newFingerprint) {
    const participantInfo = participants.get(odId);
    const pseudo = participantInfo ? participantInfo.pseudo : odId;
    
    const alertHtml = `
        <div class="export-content modal-card" style="border: 3px solid #dc3545;">
            <button class="modal-close" aria-label="Fermer">Ã—</button>
            <div class="modal-header" style="background: #dc3545; color: white;">
                <div class="modal-icon">ðŸš¨</div>
                <div>
                    <h3>ALERTE SÃ‰CURITÃ‰</h3>
                    <p class="modal-subtitle">Changement de clÃ© dÃ©tectÃ©</p>
                </div>
            </div>
            <div style="padding: 20px;">
                <p style="margin-bottom: 15px;"><strong>Le numÃ©ro de sÃ©curitÃ© de ${pseudo} a changÃ©.</strong></p>
                
                <div style="background: #fff3cd; padding: 15px; border-radius: 8px; margin-bottom: 15px; border-left: 4px solid #ffc107;">
                    <strong>âš ï¸ Cela peut signifier:</strong>
                    <ul style="margin: 10px 0 0 20px;">
                        <li>Votre correspondant a rÃ©installÃ© l'application</li>
                        <li>Quelqu'un intercepte vos messages (MITM)</li>
                    </ul>
                </div>
                
                <div style="margin: 15px 0;">
                    <p><strong>Ancien numÃ©ro:</strong></p>
                    <div style="font-family: monospace; font-size: 12px; padding: 10px; background: #f5f5f5; border-radius: 4px; margin: 5px 0;">
                        ${oldFingerprint}
                    </div>
                </div>
                
                <div style="margin: 15px 0;">
                    <p><strong>Nouveau numÃ©ro:</strong></p>
                    <div style="font-family: monospace; font-size: 12px; padding: 10px; background: #f5f5f5; border-radius: 4px; margin: 5px 0;">
                        ${newFingerprint}
                    </div>
                </div>
                
                <div style="background: #f8d7da; padding: 15px; border-radius: 8px; margin-top: 15px; border-left: 4px solid #dc3545;">
                    <strong>ðŸ›¡ï¸ Recommandation:</strong> VÃ©rifiez avec votre correspondant par tÃ©lÃ©phone ou en personne que ce changement est lÃ©gitime avant de continuer Ã  Ã©changer des informations sensibles.
                </div>
            </div>
        </div>
    `;
    
    openChatModal(alertHtml);
}

/**
 * Met Ã  jour le countdown visuel d'un message Ã©phÃ©mÃ¨re
 */
function updateEphemeralCountdown(messageId, expiryTime, countdownEl) {
    const updateCountdown = () => {
        const now = Date.now();
        const remaining = Math.max(0, Math.ceil((expiryTime - now) / 1000));
        
        if (remaining > 0) {
            countdownEl.textContent = `â±ï¸ ${remaining}s`;
            countdownEl.style.color = remaining <= 10 ? '#dc3545' : '#ff6b6b';
        } else {
            countdownEl.textContent = 'ðŸ’¨';
        }
    };
    
    // Mettre Ã  jour immÃ©diatement
    updateCountdown();
    
    // Mettre Ã  jour chaque seconde
    if (ephemeralCountdowns.has(messageId)) {
        clearInterval(ephemeralCountdowns.get(messageId));
    }
    
    const intervalId = setInterval(updateCountdown, 1000);
    ephemeralCountdowns.set(messageId, intervalId);
}

function scheduleMessageDeletion(messageId, delay) {
    if (!ephemeralMode) return;
    
    setTimeout(() => {
        const msg = findMessageById(messageId);
        if (msg && !msg.deleted) {
            msg.deleted = true;
            msg.text = 'ðŸ’¨ Message Ã©phÃ©mÃ¨re expirÃ©';
            
            // Nettoyer le countdown
            if (ephemeralCountdowns.has(messageId)) {
                clearInterval(ephemeralCountdowns.get(messageId));
                ephemeralCountdowns.delete(messageId);
            }
            
            const container = elements.chatMessages;
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
        
        // Ajouter Ã  la liste visuelle
        const itemDiv = document.createElement('div');
        itemDiv.className = 'both-file-item pending-send';
        itemDiv.dataset.fileName = file.name;
        itemDiv.innerHTML = `
            <span class="file-icon">ðŸ“„</span>
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
            
            // Mettre Ã  jour le statut dans la liste
            const listEl = isReceiverSide ? elements.receiverBothFileList : elements.bothFileList;
            const itemEl = listEl.querySelector(`[data-file-name="${file.name}"]`);
            if (itemEl) {
                itemEl.classList.remove('pending-send');
                const statusEl = itemEl.querySelector('.file-status');
                if (statusEl) {
                    statusEl.textContent = 'EnvoyÃ©';
                    statusEl.classList.remove('pending');
                }
            }
        } catch (err) {
            console.error('âŒ Erreur envoi fichier:', err);
            showToast('Erreur lors de l\'envoi de ' + file.name);
        }
    }
    
    // Retirer les fichiers envoyÃ©s de la liste
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
    
    // Envoyer les mÃ©tadonnÃ©es Ã  tous les peers
    broadcastToAllPeers({
        type: 'both-file-meta',
        name: file.name,
        size: file.size,
        mimeType: file.type || 'application/octet-stream',
        iv: toBase64(iv),
        senderPseudo: userPseudo
    });
    
    // Envoyer les donnÃ©es chiffrÃ©es en chunks
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
        
        // Petit dÃ©lai pour Ã©viter de saturer le buffer
        await new Promise(resolve => setTimeout(resolve, 5));
    }
    
    // Signaler la fin
    broadcastToAllPeers({
        type: 'both-file-complete',
        name: file.name
    });
    
    console.log('ðŸ“¤ Fichier envoyÃ© Ã  tous les participants:', file.name);
}

// Variables pour la rÃ©ception de fichiers en mode both
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
    
    // Ajouter Ã  la liste visuelle
    const listEl = elements.bothFileList;
    const itemDiv = document.createElement('div');
    itemDiv.className = 'both-file-item';
    itemDiv.dataset.fileName = data.name;
    itemDiv.innerHTML = `
        <span class="file-icon">ðŸ“¥</span>
        <div class="file-details">
            <span class="file-sender">${escapeHtml(incomingBothFile.senderPseudo)}</span>
            <span class="file-name">${escapeHtml(data.name)}</span>
            <span class="file-size">${formatFileSize(data.size)}</span>
        </div>
        <span class="file-status pending">RÃ©ception...</span>
    `;
    listEl.appendChild(itemDiv);
    
    console.log('ðŸ“¥ RÃ©ception fichier de', incomingBothFile.senderPseudo, ':', data.name);
}

function handleBothFileChunk(data) {
    incomingBothChunks[data.index] = new Uint8Array(data.data);
}

async function handleBothFileComplete(data) {
    if (!incomingBothFile) return;
    
    try {
        // Reconstituer les donnÃ©es chiffrÃ©es
        const totalLength = incomingBothChunks.reduce((acc, chunk) => acc + chunk.length, 0);
        const encryptedData = new Uint8Array(totalLength);
        let offset = 0;
        for (const chunk of incomingBothChunks) {
            encryptedData.set(chunk, offset);
            offset += chunk.length;
        }
        
        // DÃ©chiffrer
        const decrypted = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: incomingBothFile.iv },
            cryptoKey,
            encryptedData
        );
        
        // CrÃ©er le blob et proposer le tÃ©lÃ©chargement
        const blob = new Blob([decrypted], { type: incomingBothFile.mimeType });
        const url = URL.createObjectURL(blob);
        
        // Mettre Ã  jour la liste avec un bouton de tÃ©lÃ©chargement
        const listEl = elements.bothFileList;
        const itemEl = listEl.querySelector(`[data-file-name="${data.name}"]`);
        if (itemEl) {
            const statusEl = itemEl.querySelector('.file-status');
            if (statusEl) {
                statusEl.outerHTML = `<a href="${url}" download="${data.name}" class="btn btn-small file-action">ðŸ“¥ TÃ©lÃ©charger</a>`;
            }
            itemEl.querySelector('.file-icon').textContent = 'âœ…';
        }
        
        console.log('âœ… Fichier reÃ§u:', data.name);
        showToast('Fichier reÃ§u: ' + data.name);
    } catch (err) {
        console.error('âŒ Erreur dÃ©chiffrement fichier:', err);
        showToast('Erreur lors de la rÃ©ception du fichier');
    }
    
    incomingBothFile = null;
    incomingBothChunks = [];
}

// DÃ©marrer l'application
// document.addEventListener('DOMContentLoaded', init);

// VÃ©rifier et afficher le popup Tor Browser pour la premiÃ¨re utilisation
function checkAndShowTorPopup() {
    const torPopupDismissed = localStorage.getItem('torPopupDismissed');
    
    // Afficher seulement si jamais affichÃ© ou pas dÃ©finitivement masquÃ©
    if (!torPopupDismissed) {
        const torPopup = document.getElementById('tor-popup');
        const torDismissBtn = document.getElementById('tor-dismiss');
        const torDontShow = document.getElementById('tor-dont-show');
        
        // Afficher le popup aprÃ¨s 1 seconde
        setTimeout(() => {
            torPopup.classList.remove('hidden');
        }, 1000);
        
        // Bouton "Continuer sans Tor"
        torDismissBtn.addEventListener('click', () => {
            torPopup.classList.add('hidden');
            
            // Si l'utilisateur a cochÃ© "Ne plus afficher"
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

// Afficher le badge "Session Ã©phÃ©mÃ¨re" quand une session est active
function showEphemeralBadge() {
    const badge = document.getElementById('ephemeral-badge');
    if (badge) {
        badge.classList.remove('hidden');
    }
}

// Masquer le badge "Session Ã©phÃ©mÃ¨re"
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

// DÃ©tecter aussi les changements via popstate (bouton retour/avant)
window.addEventListener('popstate', () => {
    window.location.reload(true);
});
