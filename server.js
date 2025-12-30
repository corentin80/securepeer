const WebSocket = require('ws');
const { v4: uuidv4 } = require('uuid');
const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;

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

wss.on('connection', (ws) => {
    console.log('🔌 Nouvelle connexion WebSocket');
    
    let currentRoom = null;
    let odId = uuidv4().substring(0, 8); // ID unique pour ce participant
    let pseudo = null;
    let isCreator = false;
    
    ws.on('message', (message) => {
        try {
            const data = JSON.parse(message);
            
            switch (data.type) {
                case 'create-room': {
                    const roomId = uuidv4().substring(0, 8);
                    pseudo = data.pseudo || 'Anonyme';
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
                    console.log('🚪 [JOIN] Demande join-room reçue:');
                    console.log('   📦 roomId:', data.roomId);
                    console.log('   👤 pseudo:', data.pseudo);
                    console.log('   🔑 odId demandé:', data.odId);
                    
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
