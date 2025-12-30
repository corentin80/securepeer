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
    closeReceiverSession: document.getElementById('close-receiver-session')
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
    
    console.log('🔐 Clé AES dérivée via ECDH');
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
            console.log('📤 Création nouvelle room');
            ws.send(JSON.stringify({
                type: 'create-room',
                fileInfo: fileInfo,
                pseudo: userPseudo
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
            // Le créateur a fermé la session -> Retourner à l'accueil
            console.log('🔴 Session fermée:', data.message);
            clearSessionStorage();
            showError(data.message);
            setTimeout(() => {
                location.reload();
            }, 2000);
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
        
        // Afficher le chat si le mode l'inclut (côté expéditeur/créateur)
        if (isCreator && (sessionMode === 'chat' || sessionMode === 'both')) {
            elements.chatSection.classList.remove('hidden');
        }
        
        // Afficher la zone fichiers si mode both (côté expéditeur/créateur)
        if (isCreator && sessionMode === 'both') {
            elements.bothFileSection.classList.remove('hidden');
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
function broadcastToAllPeers(data) {
    const dataStr = typeof data === 'string' ? data : JSON.stringify(data);
    peers.forEach((p, odId) => {
        if (p.connected) {
            try {
                p.send(dataStr);
            } catch (err) {
                console.error(`❌ Erreur envoi vers ${odId}:`, err);
            }
        }
    });
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
    } catch (err) {
        console.error('❌ ERREUR déchiffrement - mot de passe incorrect ou données corrompu', err);
        if (peer) peer.send(JSON.stringify({ type: 'auth-response', ok: false, reason: 'bad-password' }));
        showError('Mot de passe incorrect.');
        peers.forEach(p => p.destroy());
        peers.clear();
    }
}

function handleAuthResponse(data) {
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
        startFileTransfer();
    } else {
        console.error('❌ Challenge response invalide');
        showError('Vérification décryptée échouée.');
        peers.forEach(p => p.destroy());
        peers.clear();
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
        
        switch (data.type) {
            case 'chat-message':
                handleChatMessage(data, fromOdId);
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
    // Réinitialiser la valeur avant ouverture pour éviter les sélections ignorées
        elements.fileInput.addEventListener('click', () => { elements.fileInput.value = ''; });
        elements.fileInput.addEventListener('change', async (e) => {
            try {
                const files = Array.from(e.target.files || []);
                if (files.length === 0) {
                    console.log('❌ Aucun fichier sélectionné');
                    return;
                }
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

    elements.fileInput.addEventListener('change', (e) => {
        try {
            const file = e.target.files[0];
            if (!file) {
    
                return;
            }
            handleFileSelect(file);
        } catch (err) {
            console.error('❌ Erreur dans file input change event:', err);
            showError('Erreur lors de la sélection du fichier');
        } finally {
            // Toujours remettre à zéro pour permettre de re-choisir le même fichier sans double ouverture
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
    
    // Boutons pour fermer la session
    if (elements.closeSession) {
        elements.closeSession.addEventListener('click', () => {
            if (confirm('Voulez-vous vraiment fermer cette session ?')) {
                clearSessionStorage();
                if (ws) ws.close();
                peers.forEach(p => p.destroy());
                peers.clear();
                location.reload();
            }
        });
    }
    
    if (elements.closeChatSession) {
        elements.closeChatSession.addEventListener('click', () => {
            if (confirm('Voulez-vous vraiment fermer cette session ?')) {
                clearSessionStorage();
                if (ws) ws.close();
                peers.forEach(p => p.destroy());
                peers.clear();
                location.reload();
            }
        });
    }
    
    if (elements.closeReceiverSession) {
        elements.closeReceiverSession.addEventListener('click', () => {
            if (confirm('Voulez-vous vraiment fermer cette session ?')) {
                clearSessionStorage();
                if (ws) ws.close();
                peers.forEach(p => p.destroy());
                peers.clear();
                location.reload();
            }
        });
    }
    
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
    
    // Raccourci Escape pour fermer la session
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && (roomId || isReceiver)) {
            if (confirm('Voulez-vous vraiment fermer cette session ? (Appuyez sur Escape)')) {
                clearSessionStorage();
                if (ws) ws.close();
                peers.forEach(p => p.destroy());
                peers.clear();
                location.reload();
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
            if (e.key === 'Enter') sendChatMessage(false);
        });
    }
    
    // Receiver side
    if (elements.receiverChatSend) {
        elements.receiverChatSend.addEventListener('click', () => sendChatMessage(true));
    }
    if (elements.receiverChatInput) {
        elements.receiverChatInput.addEventListener('keyup', (e) => {
            if (e.key === 'Enter') sendChatMessage(true);
        });
    }
}

async function sendChatMessage(isReceiverSide) {
    const inputEl = isReceiverSide ? elements.receiverChatInput : elements.chatInput;
    const messagesEl = isReceiverSide ? elements.receiverChatMessages : elements.chatMessages;
    
    const text = inputEl.value.trim();
    // Vérifier qu'on a au moins un peer connecté
    const hasConnectedPeer = Array.from(peers.values()).some(p => p.connected);
    if (!text || !hasConnectedPeer) return;
    
    try {
        // Chiffrer le message
        const encoder = new TextEncoder();
        const plaintext = encoder.encode(text);
        
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const ciphertext = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            cryptoKey,
            plaintext
        );
        
        // Envoyer via le canal P2P à tous les peers
        const messageData = {
            type: 'chat-message',
            iv: toBase64(iv),
            ciphertext: toBase64(new Uint8Array(ciphertext)),
            senderPseudo: userPseudo,
            timestamp: Date.now()
        };
        
        broadcastToAllPeers(messageData);
        
        // Afficher localement
        addChatMessage(text, true, messagesEl, userPseudo);
        inputEl.value = '';
        
        console.log('💬 Message envoyé à', peers.size, 'peer(s)');
    } catch (err) {
        console.error('❌ Erreur envoi message:', err);
        showToast('Erreur lors de l\'envoi du message');
    }
}

async function handleChatMessage(data, fromOdId) {
    try {
        const iv = fromBase64(data.iv);
        const ciphertext = fromBase64(data.ciphertext);
        
        const decrypted = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            cryptoKey,
            ciphertext
        );
        
        const decoder = new TextDecoder();
        const text = decoder.decode(decrypted);
        
        // Récupérer le pseudo de l'expéditeur
        const senderPseudo = data.senderPseudo || participants.get(fromOdId)?.pseudo || 'Anonyme';
        
        // Afficher le message reçu
        const messagesEl = isReceiver ? elements.receiverChatMessages : elements.chatMessages;
        addChatMessage(text, false, messagesEl, senderPseudo);
        
        console.log('💬 Message reçu de', senderPseudo);
    } catch (err) {
        console.error('❌ Erreur déchiffrement message:', err);
    }
}

function addChatMessage(text, isSent, containerEl, pseudo = '') {
    const msgDiv = document.createElement('div');
    msgDiv.className = `chat-message ${isSent ? 'sent' : 'received'}`;
    
    // Ajouter le pseudo pour les messages reçus (surtout utile en groupe)
    if (!isSent && pseudo) {
        const pseudoSpan = document.createElement('span');
        pseudoSpan.className = 'message-pseudo';
        pseudoSpan.textContent = pseudo;
        msgDiv.appendChild(pseudoSpan);
    }
    
    const textSpan = document.createElement('span');
    textSpan.className = 'message-text';
    textSpan.textContent = text;
    msgDiv.appendChild(textSpan);
    
    const timeSpan = document.createElement('span');
    timeSpan.className = 'timestamp';
    timeSpan.textContent = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    msgDiv.appendChild(timeSpan);
    
    containerEl.appendChild(msgDiv);
    containerEl.scrollTop = containerEl.scrollHeight;
    
    // Stocker le message
    chatMessages.push({ text, isSent, pseudo, timestamp: Date.now() });
}

function updateChatStatus(connected) {
    const statusEls = [elements.chatStatus, elements.receiverChatStatus];
    const connectedPeers = Array.from(peers.values()).filter(p => p.connected).length;
    statusEls.forEach(el => {
        if (el) {
            el.textContent = connected ? `Connecté (${connectedPeers + 1} participants)` : 'En attente...';
            el.classList.toggle('connected', connected);
        }
    });
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

// Recharger la page quand le hash change (pour coller un nouveau lien)
window.addEventListener('hashchange', () => {
    // Forcer un rechargement complet depuis le serveur
    window.location.reload(true);
});

// Détecter aussi les changements via popstate (bouton retour/avant)
window.addEventListener('popstate', () => {
    window.location.reload(true);
});
