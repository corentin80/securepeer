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
let peer = null;
let selectedFile = null;
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

// ===== ÉLÉMENTS DOM =====
const elements = {
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
    
    // Receiver
    receiverSection: document.getElementById('receiver-section'),
    receiverPasswordBlock: document.getElementById('receiver-password-block'),
    receiverPassword: document.getElementById('receiver-password'),
    receiverPasswordApply: document.getElementById('receiver-password-apply'),
    incomingFileName: document.getElementById('incoming-file-name'),
    incomingFileSize: document.getElementById('incoming-file-size'),
    receiverStatus: document.getElementById('receiver-status'),
    receiveFileBtn: document.getElementById('receive-file-btn'),
    
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
    retryTransfer: document.getElementById('retry-transfer')
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
        false,
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

// ===== WEBSOCKET =====

function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}`;
    
    ws = new WebSocket(wsUrl);
    
    ws.onopen = () => {
        console.log('🌐 WebSocket connecté');
        
        if (isReceiver) {
            // Mode destinataire : rejoindre la room
            ws.send(JSON.stringify({
                type: 'join-room',
                roomId: roomId
            }));
        } else {
            // Mode expéditeur : créer une room
            ws.send(JSON.stringify({
                type: 'create-room',
                fileInfo: fileInfo
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
            generateShareLink();
            break;
            
        case 'room-joined':
            console.log('✅ Room rejointe');
            console.log('📦 FileInfo reçue:', data.fileInfo);
            fileInfo = data.fileInfo;
            if (fileInfo) {
                elements.incomingFileName.textContent = fileInfo.name;
                elements.incomingFileSize.textContent = formatFileSize(fileInfo.size);
            }
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
            } else {
                console.log('✅ Pas de mot de passe requis');
                elements.receiverStatus.textContent = 'Connexion P2P en cours...';
                initPeer(false); // Receiver = non-initiateur
            }
            break;
            
        case 'peer-joined':
            console.log('👥 Le destinataire a rejoint');
            connectedCount++;
            elements.linkStatus.innerHTML = `<span class="pulse"></span> 👥 ${connectedCount} utilisateur(s) connecté(s)`;
            elements.linkStatus.className = 'status status-connected';
            // Si mot de passe requis, on attend receiver-ready avant d'initier le peer
            if (!usePassword) {
                console.log('🚀 Pas de mot de passe, démarrage P2P immédiat');
                initPeer(true); // Sender = initiateur
            }
            break;
            
        case 'receiver-ready':
            console.log('🔓 Destinataire prêt (mot de passe validé)');
            elements.linkStatus.innerHTML = '<span class="pulse"></span> Établissement P2P...';
            initPeer(true); // Sender = initiateur
            break;
            
        case 'signal':
            if (peer) {
                peer.signal(data.signal);
            }
            break;
            
        case 'peer-disconnected':
            showError(data.message);
            connectedCount = Math.max(0, connectedCount - 1);
            if (connectedCount > 0) {
                elements.linkStatus.innerHTML = `<span class="pulse"></span> 👥 ${connectedCount} utilisateur(s) connecté(s)`;
            } else {
                elements.linkStatus.innerHTML = '<span class="pulse"></span> En attente du destinataire...';
                elements.linkStatus.className = 'status status-waiting';
            }
            if (peer) {
                peer.destroy();
                peer = null;
            }
            break;
            
        case 'error':
            showError(data.message);
            break;
    }
}

// ===== WEBRTC / SIMPLE-PEER =====

function initPeer(initiator) {
    peer = new SimplePeer({
        initiator: initiator,
        trickle: true,
        config: {
            iceServers: STUN_SERVERS
        }
    });
    
    peer.on('signal', (signal) => {
        // Envoyer le signal SDP/ICE via WebSocket
        ws.send(JSON.stringify({
            type: 'signal',
            signal: signal
        }));
    });
    
    peer.on('connect', () => {
        console.log('🤝 Connexion P2P établie !');
        
        if (!isReceiver) {
            // Côté expéditeur : démarrer le flux d'auth puis transfert
            startTransferFlow();
        } else {
            elements.receiverStatus.textContent = 'Connexion établie ! Transfert en cours...';
        }
    });
    
    peer.on('data', (data) => {
        handlePeerData(data);
    });
    
    peer.on('close', () => {
        console.log('🔌 Connexion P2P fermée');
    });
    
    peer.on('error', (err) => {
        console.error('❌ Erreur P2P:', err);
        showError('Erreur de connexion P2P: ' + err.message);
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

async function handleAuthChallenge(data) {
    // Côté destinataire
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
        peer.send(JSON.stringify({ type: 'auth-response', ok: false, reason: 'bad-password' }));
        showError('Mot de passe incorrect.');
        if (peer) peer.destroy();
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
        if (peer) peer.destroy();
        return;
    }

    if (expectedChallengeB64 && data.value === expectedChallengeB64) {
        console.log('✅ Mot de passe vérifié! Démarrage du transfert...');
        authVerified = true;
        startFileTransfer();
    } else {
        console.error('❌ Challenge response invalide');
        showError('Vérification décryptée échouée.');
        if (peer) peer.destroy();
    }
}

async function startFileTransfer() {
    if (usePassword && !authVerified) return;
    console.log('📤 Démarrage du transfert...');
    
    elements.senderSection.classList.add('hidden');
    elements.linkSection.classList.add('hidden');
    elements.progressSection.classList.remove('hidden');
    elements.progressTitle.textContent = 'Envoi en cours...';
    
    transferStartTime = Date.now();
    
    // Envoyer les métadonnées du fichier
    const metadata = {
        type: 'metadata',
        name: selectedFile.name,
        size: selectedFile.size,
        mimeType: selectedFile.type
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

function handlePeerData(rawData) {
    try {
        const data = JSON.parse(rawData.toString());
        
        switch (data.type) {
            case 'auth-challenge':
                handleAuthChallenge(data);
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
    
    if (peer) {
        peer.destroy();
        peer = null;
    }
    
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
            elements.completeMessage.textContent = `${selectedFile.name} envoyé avec succès !`;
        }, 500);
    }
}

// ===== GÉNÉRATION DU LIEN =====

async function generateShareLink() {
    let link;
    if (usePassword) {
        // Lien sans clé : contient seulement le salt et les itérations pour dériver la clé côté destinataire
        link = `${window.location.origin}${window.location.pathname}#${roomId}_pwd_${passwordSaltB64}_${passwordIterations}`;
    } else {
        const keyString = await exportKeyToBase64();
        link = `${window.location.origin}${window.location.pathname}#${roomId}_${keyString}`;
    }
    
    elements.shareLink.value = link;
    elements.linkSection.classList.remove('hidden');
    
    console.log('🔗 Lien de partage généré');
}

// ===== GESTION DES FICHIERS =====

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
    if (!selectedFile) {
        showToast('Sélectionnez un fichier d\'abord');
        return;
    }
    try {
        // Choisir la stratégie de clé : mot de passe ou clé aléatoire
        const passwordValue = elements.passwordInput.value.trim();
        usePassword = passwordValue.length > 0;
        passwordSaltB64 = usePassword ? generatePasswordSalt() : null;
        passwordIterations = KDF_ITERATIONS;

        if (usePassword) {
            console.log('🔐 Mot de passe détecté, dérivation en cours...');
            cryptoKey = await deriveKeyFromPassword(passwordValue, passwordSaltB64, passwordIterations);
        } else {
            console.log('🔑 Génération d\'une clé aléatoire...');
            await generateCryptoKey();
        }

        // Préparer les infos du fichier AVEC paramètres de mot de passe si applicable
        fileInfo = {
            name: selectedFile.name,
            size: selectedFile.size,
            type: selectedFile.type,
            passwordRequired: usePassword
        };

        if (usePassword) {
            fileInfo.passwordSalt = passwordSaltB64;
            fileInfo.passwordIterations = passwordIterations;
            console.log('📋 FileInfo avec mot de passe:', fileInfo);
        } else {
            console.log('📋 FileInfo sans mot de passe:', fileInfo);
        }

        // Se connecter au serveur WebSocket et créer la room
        connectWebSocket();
    } catch (err) {
        console.error('❌ Erreur dans startSend:', err);
        showError('Erreur lors de la préparation de l\'envoi: ' + err.message);
    }
}

function clearFileSelection() {
    selectedFile = null;
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
        elements.receiverStatus.textContent = 'Mot de passe validé. Cliquez sur le bouton pour recevoir le fichier.';
        
        // Afficher le bouton "Recevoir le fichier"
        if (elements.receiveFileBtn) {
            elements.receiveFileBtn.classList.remove('hidden');
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

// ===== INITIALISATION =====

function init() {
    // Vérifier la présence de la Web Crypto API
    if (!window.crypto || !window.crypto.subtle) {
        showError('La Web Crypto API n\'est pas disponible dans ce navigateur. Utilisez Chrome, Firefox, Edge ou Safari récent.');
        return;
    }

    // Vérifier si on est en mode destinataire (URL avec hash)
    const hash = window.location.hash.substring(1);

    if (hash && hash.includes('_')) {
        // Mode destinataire
        const parts = hash.split('_');
        roomId = parts[0];

        // Cas lien protégé par mot de passe : roomId_pwd_salt_iterations
        if (parts[1] === 'pwd') {
            isReceiver = true;
            usePassword = true;
            passwordRequired = true;
            passwordSaltB64 = parts[2];
            passwordIterations = parts[3] ? parseInt(parts[3], 10) : KDF_ITERATIONS;

            elements.senderSection.classList.add('hidden');
            elements.receiverSection.classList.remove('hidden');
            elements.receiverPasswordBlock.classList.remove('hidden');
            elements.receiverStatus.textContent = 'Mot de passe requis pour déchiffrer.';

            connectWebSocket();
        } else {
            // Lien standard (clé incluse)
            const keyString = parts.slice(1).join('_');
            isReceiver = true;

            elements.senderSection.classList.add('hidden');
            elements.receiverSection.classList.remove('hidden');

            importKeyFromBase64(keyString).then(() => {
                connectWebSocket();
            }).catch(err => {
                showError('Lien invalide : impossible de décoder la clé de chiffrement.');
            });
        }
    } else {
        // Mode expéditeur
        isReceiver = false;
        elements.senderSection.classList.remove('hidden');
    }
    
    // Event listeners - Drag & Drop
    elements.dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        elements.dropZone.classList.add('drag-over');
    });
    
    elements.dropZone.addEventListener('dragleave', () => {
        elements.dropZone.classList.remove('drag-over');
    });
    
    elements.dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        elements.dropZone.classList.remove('drag-over');
        const file = e.dataTransfer.files[0];
        handleFileSelect(file);
    });
    
    // Event listeners - Input file
    // Réinitialiser la valeur avant ouverture pour éviter les sélections ignorées
    elements.fileInput.addEventListener('click', () => {
        elements.fileInput.value = '';
    });

    elements.fileInput.addEventListener('change', (e) => {
        try {
            const file = e.target.files[0];
            if (!file) {
                console.log('❌ Aucun fichier sélectionné');
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
        location.reload();
    });
    
    elements.retryTransfer.addEventListener('click', () => {
        window.location.reload();
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
}

// Démarrer l'application
document.addEventListener('DOMContentLoaded', init);

// Recharger la page quand le hash change (pour coller un nouveau lien)
window.addEventListener('hashchange', () => {
    // Forcer un rechargement complet depuis le serveur
    window.location.reload(true);
});

// Détecter aussi les changements via popstate (bouton retour/avant)
window.addEventListener('popstate', () => {
    window.location.reload(true);
});
