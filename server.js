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
                // Servir index.html pour toutes les routes (SPA)
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

// Créer serveur HTTP ou HTTPS selon présence des certificats
const server = createHttpOrHttpsServer();

// WebSocket Server attaché au serveur HTTP
const wss = new WebSocket.Server({ server });

// Stockage des rooms en mémoire (pas de persistance)
const rooms = new Map();

wss.on('connection', (ws) => {
    console.log('🔌 Nouvelle connexion WebSocket');
    
    let currentRoom = null;
    let role = null; // 'sender' ou 'receiver'
    
    ws.on('message', (message) => {
        try {
            const data = JSON.parse(message);
            
            switch (data.type) {
                case 'create-room':
                    // L'expéditeur crée une nouvelle room
                    const roomId = uuidv4().substring(0, 8);
                    rooms.set(roomId, {
                        sender: ws,
                        receiver: null,
                        fileInfo: data.fileInfo || null
                    });
                    currentRoom = roomId;
                    role = 'sender';
                    
                    ws.send(JSON.stringify({
                        type: 'room-created',
                        roomId: roomId
                    }));
                    
                    console.log(`📦 Room créée: ${roomId}`);
                    break;
                    
                case 'join-room':
                    // Le destinataire rejoint une room existante
                    const room = rooms.get(data.roomId);
                    
                    if (!room) {
                        ws.send(JSON.stringify({
                            type: 'error',
                            message: 'Lien expiré ou invalide. L\'expéditeur s\'est déconnecté.'
                        }));
                        return;
                    }
                    
                    if (room.receiver) {
                        ws.send(JSON.stringify({
                            type: 'error',
                            message: 'Un destinataire est déjà connecté à cette room.'
                        }));
                        return;
                    }
                    
                    room.receiver = ws;
                    currentRoom = data.roomId;
                    role = 'receiver';
                    
                    // Notifier l'expéditeur que le destinataire a rejoint
                    if (room.sender && room.sender.readyState === WebSocket.OPEN) {
                        room.sender.send(JSON.stringify({
                            type: 'peer-joined'
                        }));
                    }
                    
                    // Envoyer les infos du fichier au destinataire
                    ws.send(JSON.stringify({
                        type: 'room-joined',
                        fileInfo: room.fileInfo
                    }));
                    
                    console.log(`🤝 Destinataire rejoint la room: ${data.roomId}`);
                    break;
                    
                case 'signal':
                    // Relayer les messages de signalisation WebRTC (SDP, ICE)
                    if (!currentRoom) return;
                    
                    const signalRoom = rooms.get(currentRoom);
                    if (!signalRoom) return;
                    
                    const target = role === 'sender' ? signalRoom.receiver : signalRoom.sender;
                    
                    if (target && target.readyState === WebSocket.OPEN) {
                        target.send(JSON.stringify({
                            type: 'signal',
                            signal: data.signal
                        }));
                    }
                    break;
                    
                case 'update-file-info':
                    // Mettre à jour les infos du fichier dans la room
                    if (currentRoom && role === 'sender') {
                        const r = rooms.get(currentRoom);
                        if (r) {
                            r.fileInfo = data.fileInfo;
                        }
                    }
                    break;
                    
                case 'receiver-ready':
                    // Le destinataire a entré le mot de passe et est prêt pour P2P
                    if (currentRoom && role === 'receiver') {
                        const readyRoom = rooms.get(currentRoom);
                        if (readyRoom && readyRoom.sender && readyRoom.sender.readyState === WebSocket.OPEN) {
                            readyRoom.sender.send(JSON.stringify({
                                type: 'receiver-ready'
                            }));
                        }
                    }
                    break;
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
                if (role === 'sender') {
                    // L'expéditeur part -> notifier le destinataire et supprimer la room
                    if (room.receiver && room.receiver.readyState === WebSocket.OPEN) {
                        room.receiver.send(JSON.stringify({
                            type: 'peer-disconnected',
                            message: 'L\'expéditeur s\'est déconnecté.'
                        }));
                    }
                    rooms.delete(currentRoom);
                    console.log(`🗑️ Room supprimée: ${currentRoom}`);
                } else if (role === 'receiver') {
                    // Le destinataire part -> notifier l'expéditeur
                    if (room.sender && room.sender.readyState === WebSocket.OPEN) {
                        room.sender.send(JSON.stringify({
                            type: 'peer-disconnected',
                            message: 'Le destinataire s\'est déconnecté.'
                        }));
                    }
                    room.receiver = null;
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
║   🚀 Serveur P2P File Transfer démarré                   ║
║                                                           ║
║   📡 URL locale:  http://localhost:${PORT}                 ║
║                                                           ║
║   Le serveur ne stocke AUCUNE donnée.                    ║
║   Il ne fait que relayer les signaux WebRTC.             ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    `);
});
