const WebSocket = require('ws');
const { v4: uuidv4 } = require('uuid');
const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;

// ===== LIMITES DE SÉCURITÉ =====
const MAX_MESSAGE_SIZE = 1024 * 1024; // 1 MB max par message WebSocket
const MAX_PSEUDO_LENGTH = 50;
const MAX_ROOM_PARTICIPANTS = 20;

// ===== RATE LIMITING =====
const RATE_LIMITS = {
    connection: { max: 10, windowMs: 60000 },    // 10 connexions/minute
    createRoom: { max: 5, windowMs: 60000 },     // 5 rooms/minute
    joinRoom: { max: 20, windowMs: 60000 },      // 20 joins/minute
    message: { max: 100, windowMs: 60000 }       // 100 messages/minute
};

const rateLimitStore = new Map(); // IP -> { action: { count, resetTime } }

function getRateLimitKey(ip, action) {
    return `${ip}:${action}`;
}

function checkRateLimit(ip, action) {
    const limit = RATE_LIMITS[action];
    if (!limit) return { allowed: true };
    
    const now = Date.now();
    const key = getRateLimitKey(ip, action);
    
    if (!rateLimitStore.has(key)) {
        rateLimitStore.set(key, { count: 1, resetTime: now + limit.windowMs });
        return { allowed: true, remaining: limit.max - 1 };
    }
    
    const record = rateLimitStore.get(key);
    
    // Reset si la fenêtre est expirée
    if (now > record.resetTime) {
        rateLimitStore.set(key, { count: 1, resetTime: now + limit.windowMs });
        return { allowed: true, remaining: limit.max - 1 };
    }
    
    // Vérifier la limite
    if (record.count >= limit.max) {
        const retryAfter = Math.ceil((record.resetTime - now) / 1000);
        return { allowed: false, retryAfter, remaining: 0 };
    }
    
    // Incrémenter le compteur
    record.count++;
    return { allowed: true, remaining: limit.max - record.count };
}

// Nettoyage périodique des entrées expirées (toutes les 5 minutes)
setInterval(() => {
    const now = Date.now();
    for (const [key, record] of rateLimitStore) {
        if (now > record.resetTime) {
            rateLimitStore.delete(key);
        }
    }
}, 5 * 60 * 1000);

// ===== FIN RATE LIMITING =====

// Handler HTTP(S) pour servir les fichiers statiques
const requestHandler = (req, res) => {
    let filePath = req.url === '/' ? '/index.html' : req.url;
    filePath = path.join(__dirname, 'public', filePath);
    
    const extname = path.extname(filePath);
    const contentTypes = {
        '.html': 'text/html',
        '.js': 'text/javascript',
        '.css': 'text/css',
        '.json': 'application/json',
        '.png': 'image/png',
        '.ico': 'image/x-icon'
    };
    
    const contentType = contentTypes[extname] || 'application/octet-stream';
    
    fs.readFile(filePath, (err, content) => {
        if (err) {
            if (err.code === 'ENOENT') {
                fs.readFile(path.join(__dirname, 'public', 'index.html'), (err, content) => {
                    if (err) {
                        res.writeHead(500);
                        res.end('Erreur serveur');
                    } else {
                        res.writeHead(200, { 'Content-Type': 'text/html' });
                        res.end(content, 'utf-8');
                    }
                });
            } else {
                res.writeHead(500);
                res.end('Erreur serveur');
            }
        } else {
            res.writeHead(200, { 'Content-Type': contentType });
            res.end(content, 'utf-8');
        }
    });
};

function createHttpOrHttpsServer() {
    return http.createServer(requestHandler);
}

const server = createHttpOrHttpsServer();
const wss = new WebSocket.Server({ server });

// Stockage des rooms en mémoire
// Structure: { participants: Map<odId, {ws, pseudo, isCreator}>, fileInfo, creatorId, deleteTimer }
const rooms = new Map();

// Délai avant suppression d'une room vide (5 minutes)
const ROOM_EMPTY_TIMEOUT = 5 * 60 * 1000;

wss.on('connection', (ws, req) => {
    // Récupérer l'IP du client (supporte reverse proxy)
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
               req.headers['x-real-ip'] || 
               req.socket.remoteAddress || 
               'unknown';
    
    // Rate limit sur les connexions
    const connLimit = checkRateLimit(ip, 'connection');
    if (!connLimit.allowed) {
        console.log(`🚫 [RATE LIMIT] Connexion refusée pour ${ip} (retry in ${connLimit.retryAfter}s)`);
        ws.close(1008, 'Too many connections. Please wait.');
        return;
    }
    
    console.log(`🔌 Nouvelle connexion WebSocket depuis ${ip}`);
    
    let currentRoom = null;
    let odId = uuidv4().substring(0, 8); // ID unique pour ce participant
    let pseudo = null;
    let isCreator = false;
    
    ws.on('message', (message) => {
        try {
            // Vérifier la taille du message
            if (message.length > MAX_MESSAGE_SIZE) {
                console.log(`🚫 [SECURITY] Message trop volumineux (${message.length} bytes) depuis ${ip}`);
                ws.send(JSON.stringify({ 
                    type: 'error', 
                    message: 'Message trop volumineux. Limite : 1 MB.' 
                }));
                return;
            }
            
            // Rate limit sur les messages généraux
            const msgLimit = checkRateLimit(ip, 'message');
            if (!msgLimit.allowed) {
                console.log(`🚫 [RATE LIMIT] Message refusé pour ${ip}`);
                ws.send(JSON.stringify({ 
                    type: 'error', 
                    message: `Trop de requêtes. Réessayez dans ${msgLimit.retryAfter} secondes.` 
                }));
                return;
            }
            
            const data = JSON.parse(message);
            
            switch (data.type) {
                case 'create-room': {
                    // Rate limit spécifique pour création de room
                    const createLimit = checkRateLimit(ip, 'createRoom');
                    if (!createLimit.allowed) {
                        console.log(`🚫 [RATE LIMIT] Création room refusée pour ${ip}`);
                        ws.send(JSON.stringify({ 
                            type: 'error', 
                            message: `Trop de sessions créées. Réessayez dans ${createLimit.retryAfter} secondes.` 
                        }));
                        return;
                    }
                    
                    // Valider et limiter le pseudo
                    pseudo = (data.pseudo || 'Anonyme').substring(0, MAX_PSEUDO_LENGTH).trim();
                    if (!pseudo) pseudo = 'Anonyme';
                    
                    const roomId = uuidv4().substring(0, 8);
                    isCreator = true;
                    
                    const participants = new Map();
                    participants.set(odId, { ws, pseudo, isCreator: true });
                    
                    // Options de sécurité (avec valeurs par défaut)
                    const options = data.options || {};
                    const securityOptions = {
                        expirationMinutes: Math.min(Math.max(0, parseInt(options.expirationMinutes) || 0), 10080), // Max 7 jours
                        maxParticipants: Math.min(Math.max(1, parseInt(options.maxParticipants) || 20), 20),
                        requireApproval: !!options.requireApproval,
                        autoLock: !!options.autoLock,
                        isLocked: false
                    };
                    
                    // Créer un timer d'expiration si spécifié
                    let expirationTimer = null;
                    if (securityOptions.expirationMinutes > 0) {
                        expirationTimer = setTimeout(() => {
                            const roomToExpire = rooms.get(roomId);
                            if (roomToExpire) {
                                // Notifier tous les participants
                                roomToExpire.participants.forEach((p) => {
                                    if (p.ws.readyState === WebSocket.OPEN) {
                                        p.ws.send(JSON.stringify({
                                            type: 'session-closed',
                                            closedBy: 'Système',
                                            isCreatorClose: true,
                                            reason: 'Session expirée'
                                        }));
                                    }
                                });
                                rooms.delete(roomId);
                                console.log(`⏰ Room ${roomId} expirée après ${securityOptions.expirationMinutes} minutes`);
                            }
                        }, securityOptions.expirationMinutes * 60 * 1000);
                    }
                    
                    rooms.set(roomId, {
                        participants,
                        fileInfo: data.fileInfo || null,
                        creatorId: odId,
                        options: securityOptions,
                        expirationTimer,
                        pendingApprovals: new Map() // Participants en attente d'approbation
                    });
                    
                    currentRoom = roomId;
                    
                    ws.send(JSON.stringify({
                        type: 'room-created',
                        roomId: roomId,
                        odId: odId,
                        options: securityOptions
                    }));
                    
                    console.log(`📦 Room créée: ${roomId} par ${pseudo} (options: ${JSON.stringify(securityOptions)})`);
                    break;
                }
                
                case 'join-room': {
                    // Rate limit spécifique pour rejoindre une room
                    const joinLimit = checkRateLimit(ip, 'joinRoom');
                    if (!joinLimit.allowed) {
                        console.log(`🚫 [RATE LIMIT] Join room refusé pour ${ip}`);
                        ws.send(JSON.stringify({ 
                            type: 'error', 
                            message: `Trop de tentatives. Réessayez dans ${joinLimit.retryAfter} secondes.` 
                        }));
                        return;
                    }
                    
                    console.log('🚪 [JOIN] Demande join-room reçue:');
                    console.log('   📦 roomId:', data.roomId);
                    console.log('   👤 pseudo:', data.pseudo);
                    console.log('   🔑 odId demandé:', data.odId);
                    
                    // Validation du format roomId
                    if (!data.roomId || !/^[a-f0-9]{8}$/i.test(data.roomId)) {
                        console.log('❌ [JOIN] Format roomId invalide:', data.roomId);
                        ws.send(JSON.stringify({
                            type: 'error',
                            message: 'Lien invalide.'
                        }));
                        return;
                    }
                    
                    const room = rooms.get(data.roomId);
                    if (!room) {
                        console.log('❌ [JOIN] Room non trouvée:', data.roomId);
                        ws.send(JSON.stringify({
                            type: 'error',
                            message: 'Lien expiré ou invalide.'
                        }));
                        return;
                    }
                    console.log('✅ [JOIN] Room trouvée, participants actuels:', room.participants.size);
                    console.log('   📋 Participants existants:', Array.from(room.participants.keys()));
                    
                    // Valider et limiter le pseudo
                    pseudo = (data.pseudo || 'Anonyme').substring(0, MAX_PSEUDO_LENGTH).trim();
                    if (!pseudo) pseudo = 'Anonyme';
                    
                    // Vérifier si c'est une reconnexion
                    const isReconnection = data.odId && room.participants.has(data.odId);
                    
                    if (!isReconnection) {
                        // === VÉRIFICATIONS DE SÉCURITÉ POUR NOUVEAUX PARTICIPANTS ===
                        
                        // 1. Vérifier si la session est verrouillée
                        if (room.options && room.options.isLocked) {
                            console.log(`🔒 [SECURITY] Session verrouillée, accès refusé pour ${pseudo}`);
                            ws.send(JSON.stringify({
                                type: 'error',
                                message: 'Cette session est verrouillée et n\'accepte plus de nouveaux participants.'
                            }));
                            return;
                        }
                        
                        // 2. Vérifier la limite de participants (utilise l'option ou le max global)
                        const maxAllowed = room.options ? room.options.maxParticipants : MAX_ROOM_PARTICIPANTS;
                        if (room.participants.size >= maxAllowed) {
                            console.log(`🚫 [SECURITY] Room pleine (${room.participants.size}/${maxAllowed})`);
                            ws.send(JSON.stringify({
                                type: 'error',
                                message: `Cette session est complète (maximum ${maxAllowed} participant${maxAllowed > 1 ? 's' : ''}).`
                            }));
                            return;
                        }
                        
                        // 3. Vérifier si l'approbation est requise
                        if (room.options && room.options.requireApproval) {
                            console.log(`✋ [APPROVAL] Approbation requise pour ${pseudo}`);
                            
                            // Ajouter à la liste d'attente
                            room.pendingApprovals.set(odId, { 
                                ws, 
                                pseudo, 
                                timestamp: Date.now(),
                                ip 
                            });
                            
                            // Notifier le participant qu'il est en attente
                            ws.send(JSON.stringify({
                                type: 'approval-pending',
                                message: 'En attente d\'approbation du créateur de la session...'
                            }));
                            
                            // Notifier le créateur
                            const creator = room.participants.get(room.creatorId);
                            if (creator && creator.ws.readyState === WebSocket.OPEN) {
                                creator.ws.send(JSON.stringify({
                                    type: 'approval-request',
                                    odId: odId,
                                    pseudo: pseudo,
                                    pendingCount: room.pendingApprovals.size
                                }));
                            }
                            
                            // Stocker la room pour ce ws
                            currentRoom = data.roomId;
                            return; // Ne pas continuer, attendre l'approbation
                        }
                    }
                    
                    // Annuler le timer de suppression si quelqu'un rejoint
                    if (room.deleteTimer) {
                        clearTimeout(room.deleteTimer);
                        room.deleteTimer = null;
                        console.log(`✅ Timer de suppression annulé pour room ${data.roomId}`);
                    }
                    
                    currentRoom = data.roomId;
                    // Gestion reconnexion : si odId fourni et déjà présent, réassocier
                    let effectiveOdId = odId;
                    if (isReconnection) {
                        effectiveOdId = data.odId;
                        // Mettre à jour le ws et le pseudo
                        const old = room.participants.get(effectiveOdId);
                        room.participants.set(effectiveOdId, { ws, pseudo, isCreator: old.isCreator });
                    } else {
                        // Nouveau participant
                        room.participants.set(odId, { ws, pseudo, isCreator: false });
                        
                        // Auto-lock si activé et c'est le premier participant
                        if (room.options && room.options.autoLock && room.participants.size >= 2) {
                            room.options.isLocked = true;
                            console.log(`🔒 [AUTO-LOCK] Session ${data.roomId} verrouillée automatiquement`);
                            
                            // Notifier le créateur
                            const creator = room.participants.get(room.creatorId);
                            if (creator && creator.ws.readyState === WebSocket.OPEN) {
                                creator.ws.send(JSON.stringify({
                                    type: 'session-locked',
                                    message: 'Session verrouillée automatiquement'
                                }));
                            }
                        }
                    }
                    // Envoyer la liste des participants existants au nouveau
                    const existingParticipants = [];
                    room.participants.forEach((p, odid) => {
                        if (odid !== effectiveOdId) {
                            existingParticipants.push({ odId: odid, pseudo: p.pseudo, isCreator: p.isCreator });
                        }
                    });
                    console.log('📤 [JOIN] Envoi room-joined avec participants:', existingParticipants.length);
                    console.log('   📋 Liste envoyée:', existingParticipants.map(p => p.pseudo));
                    ws.send(JSON.stringify({
                        type: 'room-joined',
                        roomId: data.roomId,
                        odId: effectiveOdId,
                        fileInfo: room.fileInfo,
                        participants: existingParticipants
                    }));
                    // Notifier tous les autres participants
                    room.participants.forEach((p, odid) => {
                        if (odid !== effectiveOdId && p.ws.readyState === WebSocket.OPEN) {
                            console.log('📤 [JOIN] Notification peer-joined envoyée à:', p.pseudo);
                            p.ws.send(JSON.stringify({
                                type: 'peer-joined',
                                odId: effectiveOdId,
                                pseudo: pseudo,
                                isCreator: false
                            }));
                        }
                    });
                    console.log(`✅ [JOIN] ${pseudo} a rejoint la room: ${data.roomId}`);
                    console.log(`   👥 Total participants: ${room.participants.size}`);
                    console.log(`   📋 Liste:`, Array.from(room.participants.keys()));
                    break;
                }
                
                case 'signal': {
                    // Relayer le signal WebRTC vers un participant spécifique
                    if (!currentRoom) return;
                    
                    const room = rooms.get(currentRoom);
                    if (!room) return;
                    
                    const targetId = data.targetId;
                    const target = room.participants.get(targetId);
                    
                    if (target && target.ws.readyState === WebSocket.OPEN) {
                        target.ws.send(JSON.stringify({
                            type: 'signal',
                            signal: data.signal,
                            fromId: odId,
                            fromPseudo: pseudo
                        }));
                    }
                    break;
                }
                
                case 'receiver-ready': {
                    // Notifier tous les autres participants que celui-ci est prêt
                    if (!currentRoom) return;
                    
                    const room = rooms.get(currentRoom);
                    if (!room) return;
                    
                    room.participants.forEach((p, odid) => {
                        if (odid !== odId && p.ws.readyState === WebSocket.OPEN) {
                            p.ws.send(JSON.stringify({
                                type: 'receiver-ready',
                                odId: odId,
                                pseudo: pseudo
                            }));
                        }
                    });
                    break;
                }
                
                case 'ecdh-public-key': {
                    // Relayer la clé publique ECDH vers un participant spécifique
                    if (!currentRoom) return;
                    
                    const room = rooms.get(currentRoom);
                    if (!room) return;
                    
                    const targetId = data.targetOdId;
                    const target = room.participants.get(targetId);
                    
                    if (target && target.ws.readyState === WebSocket.OPEN) {
                        target.ws.send(JSON.stringify({
                            type: 'ecdh-public-key',
                            fromId: odId,
                            fromPseudo: pseudo,
                            publicKeyB64: data.publicKeyB64
                        }));
                        console.log(`🔐 [ECDH] Clé publique relayée de ${pseudo} vers ${targetId}`);
                    }
                    break;
                }
                
                case 'double-ratchet-init': {
                    // Relayer la clé publique DH pour Double Ratchet
                    if (!currentRoom) return;
                    
                    const room = rooms.get(currentRoom);
                    if (!room) return;
                    
                    const targetId = data.to;
                    const target = room.participants.get(targetId);
                    
                    if (target && target.ws.readyState === WebSocket.OPEN) {
                        target.ws.send(JSON.stringify({
                            type: 'double-ratchet-init',
                            fromOdId: odId,
                            dhPublicKey: data.publicKey
                        }));
                        console.log(`🔐 [DR] Clé DH relayée de ${pseudo} vers ${targetId}`);
                    }
                    break;
                }
                
                case 'rejoin-room': {
                    console.log('🔄 [REJOIN] Demande rejoin-room reçue:');
                    console.log('   📦 roomId:', data.roomId);
                    console.log('   👤 pseudo:', data.pseudo);
                    console.log('   🔑 odId demandé:', data.odId);
                    console.log('   📋 rooms existantes:', Array.from(rooms.keys()));
                    
                    // Créateur qui se reconnecte à sa room existante
                    const room = rooms.get(data.roomId);
                    if (!room) {
                        console.log('❌ [REJOIN] Room non trouvée:', data.roomId);
                        ws.send(JSON.stringify({
                            type: 'error',
                            message: 'Room expirée ou invalide. Veuillez créer une nouvelle session.'
                        }));
                        return;
                    }
                    console.log('✅ [REJOIN] Room trouvée, participants actuels:', Array.from(room.participants.keys()));
                    // Annuler le timer de suppression si quelqu'un rejoint
                    if (room.deleteTimer) {
                        clearTimeout(room.deleteTimer);
                        room.deleteTimer = null;
                        console.log(`✅ Timer de suppression annulé pour room ${data.roomId}`);
                    }
                    pseudo = data.pseudo || 'Anonyme';
                    currentRoom = data.roomId;
                    // Gestion reconnexion : si odId fourni et déjà présent, réassocier
                    let effectiveOdId = odId;
                    if (data.odId && room.participants.has(data.odId)) {
                        effectiveOdId = data.odId;
                        odId = effectiveOdId; // Réutiliser l'ancien odId
                        // Mettre à jour le ws
                        const old = room.participants.get(effectiveOdId);
                        room.participants.set(effectiveOdId, { ws, pseudo, isCreator: old.isCreator });
                        console.log(`🔄 Créateur ${pseudo} reconnecté à la room ${data.roomId}`);
                    } else if (room.creatorId === data.odId) {
                        // Le créateur se reconnecte avec son ancien odId
                        effectiveOdId = data.odId;
                        odId = effectiveOdId;
                        room.participants.set(effectiveOdId, { ws, pseudo, isCreator: true });
                        console.log(`🔄 Créateur ${pseudo} reconnecté à la room ${data.roomId} (nouveau ws)`);
                    } else {
                        // Nouveau participant comme créateur fallback
                        room.participants.set(odId, { ws, pseudo, isCreator: false });
                    }
                    // Envoyer la liste des participants existants
                    const existingParticipants = [];
                    room.participants.forEach((p, odid) => {
                        if (odid !== effectiveOdId) {
                            existingParticipants.push({ odId: odid, pseudo: p.pseudo, isCreator: p.isCreator });
                        }
                    });
                    const rejoinResponse = {
                        type: 'room-rejoined',
                        roomId: data.roomId,
                        odId: effectiveOdId,
                        fileInfo: room.fileInfo,
                        participants: existingParticipants,
                        hasReceiver: room.participants.size > 1
                    };
                    console.log('📤 [REJOIN] Envoi room-rejoined:', rejoinResponse);
                    ws.send(JSON.stringify(rejoinResponse));
                    // Notifier tous les autres participants
                    room.participants.forEach((p, odid) => {
                        if (odid !== effectiveOdId && p.ws.readyState === WebSocket.OPEN) {
                            p.ws.send(JSON.stringify({
                                type: 'peer-joined',
                                odId: effectiveOdId,
                                pseudo: pseudo,
                                isCreator: true
                            }));
                        }
                    });
                    break;
                }
                
                case 'update-file-info': {
                    if (currentRoom && isCreator) {
                        const room = rooms.get(currentRoom);
                        if (room) {
                            room.fileInfo = data.fileInfo;
                        }
                    }
                    break;
                }
                
                case 'approve-participant': {
                    // Le créateur approuve un participant en attente
                    if (!currentRoom || !isCreator) return;
                    
                    const room = rooms.get(currentRoom);
                    if (!room || !room.pendingApprovals) return;
                    
                    const pendingOdId = data.odId;
                    const pending = room.pendingApprovals.get(pendingOdId);
                    
                    if (!pending) {
                        console.log(`❌ [APPROVAL] Participant ${pendingOdId} non trouvé dans la liste d'attente`);
                        return;
                    }
                    
                    console.log(`✅ [APPROVAL] ${pending.pseudo} approuvé par ${pseudo}`);
                    
                    // Retirer de la liste d'attente
                    room.pendingApprovals.delete(pendingOdId);
                    
                    // Ajouter aux participants
                    room.participants.set(pendingOdId, { 
                        ws: pending.ws, 
                        pseudo: pending.pseudo, 
                        isCreator: false 
                    });
                    
                    // Auto-lock si activé
                    if (room.options && room.options.autoLock && room.participants.size >= 2) {
                        room.options.isLocked = true;
                        console.log(`🔒 [AUTO-LOCK] Session ${currentRoom} verrouillée automatiquement`);
                        ws.send(JSON.stringify({
                            type: 'session-locked',
                            message: 'Session verrouillée automatiquement'
                        }));
                    }
                    
                    // Notifier le participant qu'il est approuvé
                    if (pending.ws.readyState === WebSocket.OPEN) {
                        // Envoyer la liste des participants existants
                        const existingParticipants = [];
                        room.participants.forEach((p, pOdId) => {
                            if (pOdId !== pendingOdId) {
                                existingParticipants.push({ odId: pOdId, pseudo: p.pseudo, isCreator: p.isCreator });
                            }
                        });
                        
                        pending.ws.send(JSON.stringify({
                            type: 'room-joined',
                            roomId: currentRoom,
                            odId: pendingOdId,
                            fileInfo: room.fileInfo,
                            participants: existingParticipants,
                            approved: true
                        }));
                    }
                    
                    // Notifier les autres participants
                    room.participants.forEach((p, pOdId) => {
                        if (pOdId !== pendingOdId && p.ws.readyState === WebSocket.OPEN) {
                            p.ws.send(JSON.stringify({
                                type: 'peer-joined',
                                odId: pendingOdId,
                                pseudo: pending.pseudo,
                                isCreator: false
                            }));
                        }
                    });
                    
                    // Mettre à jour le compte des demandes en attente
                    ws.send(JSON.stringify({
                        type: 'approval-update',
                        pendingCount: room.pendingApprovals.size
                    }));
                    break;
                }
                
                case 'reject-participant': {
                    // Le créateur refuse un participant en attente
                    if (!currentRoom || !isCreator) return;
                    
                    const room = rooms.get(currentRoom);
                    if (!room || !room.pendingApprovals) return;
                    
                    const pendingOdId = data.odId;
                    const pending = room.pendingApprovals.get(pendingOdId);
                    
                    if (!pending) return;
                    
                    console.log(`❌ [APPROVAL] ${pending.pseudo} refusé par ${pseudo}`);
                    
                    // Retirer de la liste d'attente
                    room.pendingApprovals.delete(pendingOdId);
                    
                    // Notifier le participant qu'il est refusé
                    if (pending.ws.readyState === WebSocket.OPEN) {
                        pending.ws.send(JSON.stringify({
                            type: 'approval-rejected',
                            message: 'Votre demande a été refusée par le créateur de la session.'
                        }));
                    }
                    
                    // Mettre à jour le compte
                    ws.send(JSON.stringify({
                        type: 'approval-update',
                        pendingCount: room.pendingApprovals.size
                    }));
                    break;
                }
                
                case 'lock-session': {
                    // Le créateur verrouille/déverrouille la session
                    if (!currentRoom || !isCreator) return;
                    
                    const room = rooms.get(currentRoom);
                    if (!room || !room.options) return;
                    
                    room.options.isLocked = !!data.locked;
                    console.log(`🔒 [LOCK] Session ${currentRoom} ${room.options.isLocked ? 'verrouillée' : 'déverrouillée'} par ${pseudo}`);
                    
                    // Notifier tous les participants
                    room.participants.forEach((p) => {
                        if (p.ws.readyState === WebSocket.OPEN) {
                            p.ws.send(JSON.stringify({
                                type: room.options.isLocked ? 'session-locked' : 'session-unlocked',
                                message: room.options.isLocked ? 'Session verrouillée' : 'Session déverrouillée'
                            }));
                        }
                    });
                    break;
                }
                
                case 'close-room': {
                    // Fermeture de session demandée
                    if (currentRoom) {
                        const room = rooms.get(currentRoom);
                        if (room) {
                            // Notifier tous les participants que la session est fermée
                            room.participants.forEach((p) => {
                                if (p.ws.readyState === WebSocket.OPEN) {
                                    p.ws.send(JSON.stringify({
                                        type: 'session-closed',
                                        closedBy: pseudo,
                                        isCreatorClose: isCreator
                                    }));
                                }
                            });
                            
                            // Si c'est le créateur qui ferme, supprimer la room immédiatement
                            if (isCreator) {
                                if (room.deleteTimer) clearTimeout(room.deleteTimer);
                                rooms.delete(currentRoom);
                                console.log(`🗑️ Room ${currentRoom} supprimée par le créateur`);
                            }
                        }
                    }
                    break;
                }
            }
        } catch (err) {
            console.error('❌ Erreur parsing message:', err);
        }
    });
    
    ws.on('close', () => {
        console.log('🔌 Connexion WebSocket fermée');
        
        if (currentRoom) {
            const room = rooms.get(currentRoom);
            
            if (room) {
                // Retirer ce participant
                room.participants.delete(odId);
                
                // Notifier les autres participants
                room.participants.forEach((p) => {
                    if (p.ws.readyState === WebSocket.OPEN) {
                        p.ws.send(JSON.stringify({
                            type: 'peer-left',
                            odId: odId,
                            pseudo: pseudo
                        }));
                    }
                });
                
                // Vérifier si la room est vide
                if (room.participants.size === 0) {
                    // Démarrer un timer pour supprimer la room après 5 min
                    console.log(`⏰ Room ${currentRoom} vide, suppression dans 5 minutes...`);
                    room.deleteTimer = setTimeout(() => {
                        // Vérifier à nouveau si la room est toujours vide
                        const roomCheck = rooms.get(currentRoom);
                        if (roomCheck && roomCheck.participants.size === 0) {
                            rooms.delete(currentRoom);
                            console.log(`🗑️ Room ${currentRoom} supprimée (vide depuis 5 min)`);
                        }
                    }, ROOM_EMPTY_TIMEOUT);
                } else {
                    console.log(`⏸️ ${pseudo} parti, room reste active: ${currentRoom} (${room.participants.size} restants)`);
                }
            }
        }
    });
    
    ws.on('error', (err) => {
        console.error('❌ Erreur WebSocket:', err);
    });
});

server.listen(PORT, () => {
    console.log(`
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   🚀 Serveur P2P Group Chat démarré                      ║
║                                                           ║
║   📡 URL locale:  http://localhost:${PORT}                 ║
║                                                           ║
║   Support: Groupe jusqu'à 20 participants (Mesh P2P)     ║
║   Le serveur ne stocke AUCUNE donnée.                    ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    `);
});
