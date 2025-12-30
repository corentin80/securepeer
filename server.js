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
                    
                    rooms.set(roomId, {
                        participants,
                        fileInfo: data.fileInfo || null,
                        creatorId: odId
                    });
                    
                    currentRoom = roomId;
                    
                    ws.send(JSON.stringify({
                        type: 'room-created',
                        roomId: roomId,
                        odId: odId
                    }));
                    
                    console.log(`📦 Room créée: ${roomId} par ${pseudo}`);
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
                    
                    // Limiter le nombre de participants
                    if (room.participants.size >= MAX_ROOM_PARTICIPANTS && !data.odId) {
                        console.log(`🚫 [SECURITY] Room pleine (${room.participants.size}/${MAX_ROOM_PARTICIPANTS})`);
                        ws.send(JSON.stringify({
                            type: 'error',
                            message: `Cette session est complète (maximum ${MAX_ROOM_PARTICIPANTS} participants).`
                        }));
                        return;
                    }
                    
                    // Annuler le timer de suppression si quelqu'un rejoint
                    if (room.deleteTimer) {
                        clearTimeout(room.deleteTimer);
                        room.deleteTimer = null;
                        console.log(`✅ Timer de suppression annulé pour room ${data.roomId}`);
                    }
                    
                    // Valider et limiter le pseudo
                    pseudo = (data.pseudo || 'Anonyme').substring(0, MAX_PSEUDO_LENGTH).trim();
                    if (!pseudo) pseudo = 'Anonyme';
                    
                    currentRoom = data.roomId;
                    // Gestion reconnexion : si odId fourni et déjà présent, réassocier
                    let effectiveOdId = odId;
                    if (data.odId && room.participants.has(data.odId)) {
                        effectiveOdId = data.odId;
                        // Mettre à jour le ws et le pseudo
                        const old = room.participants.get(effectiveOdId);
                        room.participants.set(effectiveOdId, { ws, pseudo, isCreator: old.isCreator });
                    } else {
                        // Nouveau participant
                        room.participants.set(odId, { ws, pseudo, isCreator: false });
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
