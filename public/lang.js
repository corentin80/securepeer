// ===== GESTION DES LANGUES - FICHIER SÉPARÉ =====

let currentLanguage = localStorage.getItem('language') || 'fr';

// Au chargement du DOM, initialiser les événements de langue
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initLanguage);
} else {
    initLanguage();
}

function initLanguage() {
    const btn = document.getElementById('language-toggle');
    const menu = document.getElementById('language-menu');
    
    if (!btn) {
        console.error('❌ Bouton langue introuvable!');
        return;
    }
    
    console.log('✅ Initialisation langue');
    
    // Simple clic sur le bouton
    btn.onclick = function(e) {
        e.preventDefault();
        e.stopPropagation();
        console.log('🔄 Menu toggle');
        if (menu) {
            const hidden = menu.classList.contains('hidden');
            menu.classList.toggle('hidden');
            console.log('Menu affiché:', hidden);
        }
        return false;
    };
    
    // Clics sur les options
    document.querySelectorAll('.lang-option').forEach(opt => {
        opt.onclick = function(e) {
            e.preventDefault();
            e.stopPropagation();
            const lang = this.getAttribute('data-lang');
            console.log('🌐 Changement langue vers:', lang);
            setLanguage(lang);
            if (menu) menu.classList.add('hidden');
            return false;
        };
    });
    
    // Fermer quand on clique ailleurs
    document.addEventListener('click', function(e) {
        if (menu && !e.target.closest('.language-selector')) {
            menu.classList.add('hidden');
        }
    });
    
    // Mettre à jour la langue au démarrage
    updateLanguage();
}

function setLanguage(lang) {
    currentLanguage = lang;
    localStorage.setItem('language', currentLanguage);
    console.log('💾 Langue sauvegardée:', currentLanguage);
    updateLanguage();
}

function updateLanguage() {
    const btn = document.getElementById('language-toggle');
    const langNames = {
        fr: '🇫🇷 FR',
        en: '🇬🇧 EN',
        es: '🇪🇸 ES',
        it: '🇮🇹 IT',
        ru: '🇷🇺 RU'
    };
    
    if (btn) {
        btn.textContent = langNames[currentLanguage] || '🌐 FR';
    }
    
    // Marquer l'option active
    document.querySelectorAll('.lang-option').forEach(opt => {
        if (opt.getAttribute('data-lang') === currentLanguage) {
            opt.classList.add('active');
        } else {
            opt.classList.remove('active');
        }
    });
    
    console.log('✨ Langue mise à jour:', currentLanguage);
}
