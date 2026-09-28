/**
 * AudioManager — CoasterQuiz
 * Gestionnaire audio centralisé. Aucun son branché ici : infrastructure uniquement.
 * Usage : playSound("id")
 */

const AudioManager = (() => {
    const PREFS_KEY = 'cq_prefs';
    const DEFAULT_VOLUME = 0.8;

    // Catalogue des sons.
    // Format : { id: { src: 'audio/nom.mp3' } }
    const SOUND_CATALOG = {
        // Quiz - feedback le plus riche
        'quiz-start':   { src: 'audio/quiz-start.mp3' },   // démarrage du quiz (bouton "Jouer")
        'quiz-select':  { src: 'audio/quiz-select.mp3' },  // sélection d'une réponse (clic)
        'quiz-correct': { src: 'audio/quiz-correct.mp3' }, // bonne réponse révélée
        'quiz-wrong':   { src: 'audio/quiz-wrong.mp3' },   // mauvaise réponse révélée
        'quiz-timeout': { src: 'audio/quiz-timeout.mp3' }, // chrono expiré
        'quiz-finish':  { src: 'audio/quiz-finish.mp3' },  // quiz terminé (transition vers résultats)
        'quiz-result':  { src: 'audio/quiz-result.mp3' },  // affichage de la page résultats
        'quiz-replay':  { src: 'audio/quiz-replay.mp3' },  // bouton "Rejouer"

        // UI générale - effets légers, sobres
        'modal-open':   { src: 'audio/modal-open.mp3' },   // ouverture de modale importante
        'modal-close':  { src: 'audio/modal-close.mp3' },  // fermeture de modale
        'action-confirm': { src: 'audio/action-confirm.mp3' }, // confirmation / validation importante
        'action-delete':  { src: 'audio/action-delete.mp3' },  // suppression / action destructive
        'msg-send':     { src: 'audio/msg-send.mp3' },     // envoi de message
        'msg-receive':  { src: 'audio/msg-receive.mp3' },  // réception de message (admin → user)
        'notif':        { src: 'audio/notif.mp3' },        // notification générale
    };

    // Protection anti-accumulation : délai minimum entre deux lectures du même son (ms)
    const SOUND_COOLDOWN = {
        'quiz-select': 200,   // rapide mais pas accumulable
        'default': 50
    };
    const _lastPlayed = {}; // id → timestamp

    // État interne
    let _volume = DEFAULT_VOLUME;     // 0.0 – 1.0
    let _userInteracted = false;      // autoplay guard
    let _buffers = {};                // id → AudioBuffer (Web Audio API)
    let _ctx = null;                  // AudioContext (créé à la 1re interaction)

    /* ── Préférences ── */
    function _loadPrefs() {
        try {
            const raw = localStorage.getItem(PREFS_KEY);
            if (!raw) return;
            const prefs = JSON.parse(raw);
            if (typeof prefs.volume === 'number') {
                _volume = Math.min(1, Math.max(0, prefs.volume));
            }
        } catch (_) {}
    }

    function _savePrefs() {
        try {
            const existing = JSON.parse(localStorage.getItem(PREFS_KEY) || '{}');
            existing.volume = _volume;
            localStorage.setItem(PREFS_KEY, JSON.stringify(existing));
        } catch (_) {}
    }

    /* ── AudioContext (lazy, après interaction) ── */
    function _getCtx() {
        if (!_ctx) {
            _ctx = new (window.AudioContext || window.webkitAudioContext)();
        }
        if (_ctx.state === 'suspended') {
            _ctx.resume().catch(() => {});
        }
        return _ctx;
    }

    /* ── Chargement d'un son ── */
    async function _load(id) {
        if (_buffers[id]) return; // déjà chargé
        const entry = SOUND_CATALOG[id];
        if (!entry) return;
        try {
            const resp = await fetch(entry.src);
            if (!resp.ok) return;
            const arrayBuffer = await resp.arrayBuffer();
            const ctx = _getCtx();
            _buffers[id] = await ctx.decodeAudioData(arrayBuffer);
        } catch (_) {
            // Fichier absent ou erreur décodage : on ignore silencieusement
        }
    }

    /* ── Préchargement de tous les sons déclarés ── */
    function _preloadAll() {
        // Différé pour ne pas bloquer le rendu
        setTimeout(() => {
            Object.keys(SOUND_CATALOG).forEach(id => _load(id));
        }, 2000);
    }

    /* ── Lecture ── */
    function play(id) {
        if (!_userInteracted) return;   // respect autoplay policy
        if (_volume === 0) return;

        // Anti-accumulation : cooldown par son
        const now = Date.now();
        const cooldown = SOUND_COOLDOWN[id] ?? SOUND_COOLDOWN['default'];
        if (_lastPlayed[id] && (now - _lastPlayed[id]) < cooldown) return;
        _lastPlayed[id] = now;

        const buffer = _buffers[id];
        if (!buffer) {
            // Tentative de chargement à la volée, puis re-lecture
            _load(id).then(() => {
                const b = _buffers[id];
                if (b) _playBuffer(b);
            });
            return;
        }
        _playBuffer(buffer);
    }

    function _playBuffer(buffer) {
        try {
            const ctx = _getCtx();
            const source = ctx.createBufferSource();
            source.buffer = buffer;
            const gainNode = ctx.createGain();
            gainNode.gain.value = _volume;
            source.connect(gainNode);
            gainNode.connect(ctx.destination);
            source.start(0);
        } catch (_) {}
    }

    /* ── Volume ── */
    function setVolume(value) {
        _volume = Math.min(1, Math.max(0, parseFloat(value) || 0));
        _savePrefs();
    }

    function getVolume() {
        return _volume;
    }

    /* ── Init ── */
    function init() {
        _loadPrefs();

        // Marquer la 1re interaction utilisateur
        const markInteracted = () => {
            _userInteracted = true;
            // Débloquer le contexte audio si créé avant l'interaction
            if (_ctx && _ctx.state === 'suspended') _ctx.resume().catch(() => {});
            document.removeEventListener('click', markInteracted, true);
            document.removeEventListener('keydown', markInteracted, true);
            document.removeEventListener('touchstart', markInteracted, true);
            // Lancer le préchargement maintenant qu'on peut
            _preloadAll();
        };
        document.addEventListener('click', markInteracted, { capture: true, once: true });
        document.addEventListener('keydown', markInteracted, { capture: true, once: true });
        document.addEventListener('touchstart', markInteracted, { capture: true, once: true, passive: true });
    }

    return { init, play, setVolume, getVolume };
})();

/* ── API publique globale ── */
function playSound(id) {
    AudioManager.play(id);
}

/* ── Init au chargement ── */
document.addEventListener('DOMContentLoaded', () => {
    AudioManager.init();
});
