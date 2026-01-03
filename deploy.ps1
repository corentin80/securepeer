# Script de déploiement rapide SecurePeer
# Envoie les fichiers modifiés vers le VPS et redémarre le service

$ErrorActionPreference = "Stop"

# Configuration
$SSHKey = "$env:USERPROFILE\.ssh\id_ed25519_securepeer"
$RemoteHost = "root@securepeer.eu"
$RemotePath = "/root/securepeer"  # Ajuste selon ton chemin réel
$LocalPath = "public"

Write-Host "🚀 Déploiement SecurePeer vers $RemoteHost" -ForegroundColor Cyan

# 1. Créer le dossier distant si nécessaire
Write-Host "`n📁 Création du dossier distant..." -ForegroundColor Yellow
ssh -i $SSHKey $RemoteHost "mkdir -p $RemotePath/public"

# 2. Copier les fichiers publics
Write-Host "`n📤 Envoi des fichiers..." -ForegroundColor Yellow
scp -i $SSHKey -r "$LocalPath/*" "${RemoteHost}:${RemotePath}/public/"

# 3. Copier server.js
Write-Host "`n📤 Envoi de server.js..." -ForegroundColor Yellow
scp -i $SSHKey "server.js" "${RemoteHost}:${RemotePath}/"

# 4. Copier package.json
Write-Host "`n📤 Envoi de package.json..." -ForegroundColor Yellow
scp -i $SSHKey "package.json" "${RemoteHost}:${RemotePath}/"

# 5. Installer les dépendances et redémarrer
Write-Host "`n🔄 Installation des dépendances et redémarrage..." -ForegroundColor Yellow
ssh -i $SSHKey $RemoteHost @"
cd $RemotePath
npm install --production
pm2 restart securepeer || pm2 start server.js --name securepeer
pm2 save
"@

Write-Host "`n✅ Déploiement terminé !" -ForegroundColor Green
Write-Host "🌐 Site accessible sur : https://securepeer.eu" -ForegroundColor Cyan
