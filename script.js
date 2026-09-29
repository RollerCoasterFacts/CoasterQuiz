// ============================================
// FIRESTORE SYNC LAYER
// ============================================
const FirestoreSync = (() => {
    let _quizzesCache = null;
    let _isSyncing = false;

    // Clé pour stocker données locales si Firestore down
    const LOCAL_STORAGE_KEY = 'cq_quizzes_backup';

    async function loadQuizzesFromFirestore() {
        if (!window.firebaseDB) {
            console.warn("[Firestore] DB not ready, using localStorage");
            return _loadFromLocalStorage();
        }

        try {
            const userId = window.firebaseUser?.uid;
            if (!userId) return [];

            const snapshot = await window.firebaseDB.collection('users').doc(userId).collection('quizzes').get();
            const quizzes = [];
            snapshot.forEach(doc => {
                quizzes.push({ id: doc.id, ...doc.data() });
            });

            _quizzesCache = quizzes;
            _saveToLocalStorage(quizzes); // Backup local
            return quizzes;
        } catch (error) {
            console.warn("[Firestore] Erreur chargement, fallback localStorage:", error);
            return _loadFromLocalStorage();
        }
    }

    async function saveQuizzesToFirestore(quizzes) {
        _saveToLocalStorage(quizzes); // Toujours sauvegarder local d'abord

        if (!window.firebaseDB || _isSyncing) return;

        try {
            _isSyncing = true;
            const userId = window.firebaseUser?.uid;
            if (!userId) return;

            const userRef = window.firebaseDB.collection('users').doc(userId);

            // Supprimer anciens quizzes
            const snapshot = await userRef.collection('quizzes').get();
            for (const doc of snapshot.docs) {
                await doc.ref.delete();
            }

            // Sauvegarder nouveaux
            for (const quiz of quizzes) {
                await userRef.collection('quizzes').add(quiz);
            }

            console.log("[Firestore] Quizzes synchronisés avec succès");
            _quizzesCache = quizzes;
        } catch (error) {
            console.warn("[Firestore] Erreur sauvegarde:", error);
        } finally {
            _isSyncing = false;
        }
    }

    function _loadFromLocalStorage() {
        try {
            const raw = localStorage.getItem(LOCAL_STORAGE_KEY);
            return raw ? JSON.parse(raw) : [];
        } catch {
            return [];
        }
    }

    function _saveToLocalStorage(quizzes) {
        try {
            localStorage.setItem(LOCAL_STORAGE_KEY, JSON.stringify(quizzes));
        } catch (e) {
            console.warn("[LocalStorage] Quota dépassé:", e);
        }
    }

    return {
        load: loadQuizzesFromFirestore,
        save: saveQuizzesToFirestore,
        getCache: () => _quizzesCache
    };
})();

        const QUIZ_REGISTRY = {
            'test-quiz-1': {
                id: 'test-quiz-1',
                title: 'Quiz Test',
                questions: [
                    {
                        text: 'Quel est le plus grand',
                        time: 20,
                        answers: [
                            { text: '23', isCorrect: false },
                            { text: '89', isCorrect: false },
                            { text: '123', isCorrect: true },
                            { text: '4', isCorrect: false }
                        ]
                    },
                    {
                        text: 'Qui est le plus beau',
                        time: 20,
                        answers: [
                            { text: 'john', isCorrect: false },
                            { text: 'moi', isCorrect: true },
                            { text: 'toi', isCorrect: false },
                            { text: 'rien', isCorrect: false }
                        ]
                    }
                ]
            }
        };

        const BASE_POINTS = 2000;
        const MAX_SPEED_BONUS = 3000;
        const FEEDBACK_DELAY_MS = 2000;
        const TIMER_TICK_MS = 50;

        const ADMIN_STORAGE_KEY = 'cq_a';
        const _XK = 0xA7;
        const _XD = [0x4C,0x7E,0xE9,0x1B,0x98,0xEE,0xE4,0x08,0x19,0x9C,0x5F,0x82,0xEB,0x57,0x59,0xFA,0x18,0xE2,0x93,0x8B,0x16,0xD1,0x1F,0xFB,0xB0,0x36,0x3F,0x0B,0xBC,0x2F,0xF8,0x7F];
        let _adminSessionDigest = null;

        async function sha256Hex(value) {
            const buffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
            return Array.from(new Uint8Array(buffer), b => b.toString(16).padStart(2, '0')).join('');
        }

        function decodeCredentialDigest() {
            return _XD.map(b => (b ^ _XK).toString(16).padStart(2, '0')).join('');
        }

        function secureCompare(a, b) {
            if (a.length !== b.length) return false;
            let diff = 0;
            for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
            return diff === 0;
        }

        async function verifyAdminPassword(password) {
            const attempt = await sha256Hex(password);
            return secureCompare(attempt, decodeCredentialDigest());
        }

        async function getAdminSessionDigest() {
            if (!_adminSessionDigest) {
                _adminSessionDigest = await sha256Hex(`${decodeCredentialDigest()}\x00cq_sess_v1`);
            }
            return _adminSessionDigest;
        }

        async function grantAdminSession() {
            sessionStorage.setItem(ADMIN_STORAGE_KEY, await getAdminSessionDigest());
        }

        async function hasAdminSession() {
            const stored = sessionStorage.getItem(ADMIN_STORAGE_KEY);
            if (!stored) return false;
            return secureCompare(stored, await getAdminSessionDigest());
        }

        async function revokeAdminSession() {
            sessionStorage.removeItem(ADMIN_STORAGE_KEY);
            _adminSessionDigest = null;
        }

        /* --- AuthService : couche prête pour bascule API --- */
        let authSettingsContext = 'landing';

        const LocalAuthBackend = {
            STORAGE_KEY: 'cq_users',
            SESSION_KEY: 'cq_user_session',

            _readUsers() {
                try {
                    return JSON.parse(localStorage.getItem(this.STORAGE_KEY) || '[]');
                } catch {
                    return [];
                }
            },

            _writeUsers(users) {
                localStorage.setItem(this.STORAGE_KEY, JSON.stringify(users));
            },

            _normalizePseudo(pseudo) {
                return pseudo.trim().toLowerCase();
            },

            async hashPassword(password) {
                return sha256Hex(password);
            },

            _findUserByPseudo(pseudo) {
                const key = this._normalizePseudo(pseudo);
                return this._readUsers().find(u => u.pseudoNormalized === key) || null;
            },

            async isPseudoAvailable(pseudo) {
                const key = this._normalizePseudo(pseudo);
                if (!key) return false;
                return !this._readUsers().some(u => u.pseudoNormalized === key);
            },

            async register(pseudo, password) {
                const trimmed = pseudo.trim();
                if (!trimmed) return { success: false, error: 'Veuillez choisir un pseudo.' };
                if (!password) return { success: false, error: 'Veuillez choisir un mot de passe.' };
                if (!(await this.isPseudoAvailable(trimmed))) {
                    return { success: false, error: 'Ce pseudo est déjà pris.' };
                }

                const USER_COLORS = [
                    '#e05c5c','#e08c3a','#d4b800','#7cc44a','#3ab87c',
                    '#3ab8c0','#3a8ee0','#6a5ae0','#a44ae0','#e04aaa',
                    '#c0392b','#e67e22','#f1c40f','#27ae60','#16a085',
                    '#2980b9','#8e44ad','#c0392b','#d35400','#1abc9c',
                    '#2ecc71','#3498db','#9b59b6','#e74c3c','#e6857a',
                    '#a3d977','#77c9d4','#f7b731','#fd9644','#a55eea'
                ];
                const userColor = USER_COLORS[Math.floor(Math.random() * USER_COLORS.length)];

                const user = {
                    id: crypto.randomUUID(),
                    pseudo: trimmed,
                    pseudoNormalized: this._normalizePseudo(trimmed),
                    passwordHash: await this.hashPassword(password),
                    createdAt: new Date().toISOString(),
                    lastLogin: new Date().toISOString(),
                    bugReports: 0,
                    favorites: [],
                    color: userColor
                };

                const users = this._readUsers();
                users.push(user);
                this._writeUsers(users);

                return { success: true, user: { id: user.id, pseudo: user.pseudo } };
            },

            async login(pseudo, password) {
                const trimmed = pseudo.trim();
                if (!trimmed) return { success: false, error: 'Veuillez saisir votre pseudo.' };
                if (!password) return { success: false, error: 'Veuillez saisir votre mot de passe.' };

                const user = this._findUserByPseudo(trimmed);
                if (!user) return { success: false, error: 'Pseudo ou mot de passe incorrect.' };

                const hash = await this.hashPassword(password);
                if (!secureCompare(hash, user.passwordHash)) {
                    return { success: false, error: 'Pseudo ou mot de passe incorrect.' };
                }

                // Vérifier le bannissement
                if (user.banned) {
                    const now = new Date();
                    if (user.banned.type === 'temporary') {
                        const until = new Date(user.banned.until);
                        if (now < until) {
                            const daysLeft = Math.ceil((until - now) / (1000 * 60 * 60 * 24));
                            return { success: false, banned: true, banInfo: { ...user.banned, daysLeft } };
                        } else {
                            // Ban expiré : le lever automatiquement
                            const users = this._readUsers();
                            const idx = users.findIndex(u => u.id === user.id);
                            if (idx > -1) { delete users[idx].banned; this._writeUsers(users); }
                        }
                    } else {
                        // Bannissement définitif
                        return { success: false, banned: true, banInfo: user.banned };
                    }
                }

                // Enregistrer la dernière connexion
                const users = this._readUsers();
                const idx = users.findIndex(u => u.id === user.id);
                if (idx > -1) { users[idx].lastLogin = new Date().toISOString(); this._writeUsers(users); }

                sessionStorage.setItem(this.SESSION_KEY, JSON.stringify({ id: user.id, pseudo: user.pseudo }));
                if (typeof cqRecordConnection === 'function') cqRecordConnection();
                return { success: true, user: { id: user.id, pseudo: user.pseudo } };
            },

            getCurrentUser() {
                try {
                    const raw = sessionStorage.getItem(this.SESSION_KEY);
                    return raw ? JSON.parse(raw) : null;
                } catch {
                    return null;
                }
            },

            logout() {
                sessionStorage.removeItem(this.SESSION_KEY);
            },

            async deleteAccount(userId) {
                const users = this._readUsers().filter(u => u.id !== userId);
                this._writeUsers(users);
                this.logout();
                return { success: true };
            },

            async changePassword(userId, newPassword) {
                const users = this._readUsers();
                const user = users.find(u => u.id === userId);
                
                if (!user) return { success: false, error: 'Utilisateur non trouvé.' };
                if (!newPassword) return { success: false, error: 'Veuillez saisir un mot de passe.' };

                const newHash = await this.hashPassword(newPassword);
                user.passwordHash = newHash;
                this._writeUsers(users);

                // Mettre à jour la session (sans stocker le mot de passe en clair)
                const session = this.getCurrentUser();
                if (session) {
                    sessionStorage.setItem(this.SESSION_KEY, JSON.stringify(session));
                }

                return { success: true };
            }
        };

        const AuthService = {
            _backend: LocalAuthBackend,

            isPseudoAvailable(pseudo) {
                return this._backend.isPseudoAvailable(pseudo);
            },

            register(pseudo, password) {
                return this._backend.register(pseudo, password);
            },

            login(pseudo, password) {
                return this._backend.login(pseudo, password);
            },

            getCurrentUser() {
                return this._backend.getCurrentUser();
            },

            logout() {
                return this._backend.logout();
            },

            deleteAccount(userId) {
                return this._backend.deleteAccount(userId);
            },

            changePassword(userId, newPassword) {
                return this._backend.changePassword(userId, newPassword);
            }
        };

        function getUserColor(pseudo) {
            if (!pseudo) return null;
            try {
                const users = JSON.parse(localStorage.getItem('cq_users') || '[]');
                const u = users.find(x => x.pseudo === pseudo);
                return (u && u.color) ? u.color : null;
            } catch(e) { return null; }
        }

        function getUserAvatarByPseudo(pseudo) {
            if (!pseudo) return null;
            try {
                const users = JSON.parse(localStorage.getItem('cq_users') || '[]');
                const u = users.find(x => x.pseudo === pseudo);
                if (!u) return null;
                return localStorage.getItem('cq_avatar_' + u.id) || null;
            } catch(e) { return null; }
        }

        function buildMiniAvatarHtml(pseudo, extraStyle) {
            const customAvatar = getUserAvatarByPseudo(pseudo);
            const style = extraStyle || '';
            if (customAvatar) {
                return `<span class="leaderboard-mini-avatar" style="background-image:url(${customAvatar});background-size:cover;background-position:center;background-color:transparent;${style}"></span>`;
            }
            const avatarBg = generateAvatarColor(pseudo || '?');
            const avatarLetter = (pseudo || '?').charAt(0).toUpperCase();
            return `<span class="leaderboard-mini-avatar" style="background:${avatarBg};${style}">${avatarLetter}</span>`;
        }

        function buildChatAvatarHtml(pseudo, cssClass) {
            const customAvatar = getUserAvatarByPseudo(pseudo);
            const cls = cssClass || 'msg-chat-avatar';
            if (customAvatar) {
                return `<span class="${cls}" style="background-image:url(${customAvatar});background-size:cover;background-position:center;background-color:transparent;"></span>`;
            }
            const avatarBg = generateAvatarColor(pseudo || '?');
            const avatarLetter = (pseudo || '?').charAt(0).toUpperCase();
            return `<span class="${cls}" style="background:${avatarBg};">${avatarLetter}</span>`;
        }

        function resetLoginForm() {
            document.getElementById('login-pseudo').value = '';
            document.getElementById('login-password').value = '';
            document.getElementById('login-error').textContent = '';
        }

        function resetRegisterForm() {
            document.getElementById('register-pseudo').value = '';
            document.getElementById('register-password').value = '';
            document.getElementById('register-password-confirm').value = '';
            document.getElementById('register-error').textContent = '';
            document.getElementById('register-page-title').classList.remove('hidden');
            document.getElementById('register-form-block').classList.remove('hidden');
            const successBlock = document.getElementById('register-success-block');
            successBlock.classList.add('hidden');
            successBlock.style.display = 'none';
            document.getElementById('password-strength-wrap').classList.add('hidden');
            document.getElementById('password-strength-fill').style.width = '0%';
            document.getElementById('password-strength-label').textContent = '';
        }

        function openRegister(context) {
            if (context) authSettingsContext = context;
            resetRegisterForm();
            showView('view-register');
            
            // Add Enter key listener to register form fields
            setTimeout(() => {
                const registerFields = ['register-pseudo', 'register-password', 'register-password-confirm'];
                registerFields.forEach(fieldId => {
                    const field = document.getElementById(fieldId);
                    if (field) {
                        field.onkeypress = (e) => {
                            if (e.key === 'Enter') {
                                e.preventDefault();
                                submitRegister();
                            }
                        };
                    }
                });
            }, 0);
        }

        function openLogin(context) {
            if (context) authSettingsContext = context;
            
            // Check if persistent session exists and auto-login
            const persistentSession = localStorage.getItem('coasterquiz_persistent_session');
            if (persistentSession) {
                try {
                    const { pseudo, password } = JSON.parse(persistentSession);
                    autoLoginWithPersistentSession(pseudo, password);
                    return;
                } catch (e) {
                    // If parsing fails, show normal login form
                }
            }

            // Show normal login form
            resetLoginForm();
            showView('view-login');
            
            // Add Enter key listener to login form fields
            setTimeout(() => {
                const loginFields = ['login-pseudo', 'login-password'];
                loginFields.forEach(fieldId => {
                    const field = document.getElementById(fieldId);
                    if (field) {
                        field.onkeypress = (e) => {
                            if (e.key === 'Enter') {
                                e.preventDefault();
                                submitLogin();
                            }
                        };
                    }
                });
            }, 0);
        }

        async function autoLoginWithPersistentSession(pseudo, password) {
            const result = await AuthService.login(pseudo, password);
            
            if (!result.success) {
                if (result.banned) {
                    localStorage.removeItem('coasterquiz_persistent_session');
                    showBannedPage(result.banInfo);
                    return;
                }
                // If auto-login fails, show the login form
                resetLoginForm();
                showView('view-login');
                document.getElementById('login-error').textContent = 'Session expirée. Veuillez vous reconnecter.';
                return;
            }

            // Auto-login successful
            showView('view-user-home');
            updateHeaderAuthState();
        }

        async function submitLogin() {
            const pseudo = document.getElementById('login-pseudo').value;
            const password = document.getElementById('login-password').value;
            const errorEl = document.getElementById('login-error');

            errorEl.textContent = '';
            const result = await AuthService.login(pseudo, password);

            if (!result.success) {
                if (result.banned) {
                    showBannedPage(result.banInfo);
                    return;
                }
                errorEl.textContent = result.error || 'Connexion impossible.';
                return;
            }

            // Note: le stockage du mot de passe dans localStorage pour la session persistante
            // est une décision de design consciente pour l'auto-login.
            // Pour une vraie application, privilégier des tokens JWT ou OAuth.
            localStorage.setItem('coasterquiz_persistent_session', JSON.stringify({
                pseudo: pseudo,
                password: password
            }));

            playSound('action-confirm');
            showView('view-user-home');
            // Mettre à jour l'état du header immédiatement
            updateHeaderAuthState();
        }

        function goToAppHome() {
            if (AuthService.getCurrentUser()) showView('view-user-home');
            else showView('view-landing');
        }

        function openAuthSettings() {
            if (authSettingsContext === 'landing') openLandingSettings();
            else openSettings();
        }

        function computePasswordStrength(password) {
            if (!password) return { score: 0, label: '', color: '#ef4444' };

            let score = 0;
            if (password.length >= 4) score += 15;
            if (password.length >= 8) score += 20;
            if (password.length >= 12) score += 15;
            if (/[a-z]/.test(password)) score += 12;
            if (/[A-Z]/.test(password)) score += 12;
            if (/[0-9]/.test(password)) score += 13;
            if (/[^a-zA-Z0-9]/.test(password)) score += 13;

            score = Math.min(score, 100);

            if (score < 35) return { score, label: 'Faible', color: '#ef4444' };
            if (score < 60) return { score, label: 'Moyen', color: '#f97316' };
            if (score < 80) return { score, label: 'Correct', color: '#eab308' };
            return { score, label: 'Fort', color: '#22c55e' };
        }

        function updatePasswordStrength() {
            const password = document.getElementById('register-password').value;
            const wrap = document.getElementById('password-strength-wrap');
            const fill = document.getElementById('password-strength-fill');
            const label = document.getElementById('password-strength-label');

            if (!password) {
                wrap.classList.add('hidden');
                fill.style.width = '0%';
                label.textContent = '';
                return;
            }

            const { score, label: strengthLabel, color } = computePasswordStrength(password);
            wrap.classList.remove('hidden');
            fill.style.width = `${score}%`;
            fill.style.backgroundColor = color;
            label.textContent = `Complexité : ${strengthLabel}`;
        }

        async function submitRegister() {
            const pseudo = document.getElementById('register-pseudo').value;
            const password = document.getElementById('register-password').value;
            const confirm = document.getElementById('register-password-confirm').value;
            const errorEl = document.getElementById('register-error');

            errorEl.textContent = '';

            if (!pseudo.trim()) {
                errorEl.textContent = 'Veuillez choisir un pseudo.';
                return;
            }
            if (!password) {
                errorEl.textContent = 'Veuillez choisir un mot de passe.';
                return;
            }
            if (password !== confirm) {
                errorEl.textContent = 'Les mots de passe ne correspondent pas.';
                return;
            }
            if (!(await AuthService.isPseudoAvailable(pseudo))) {
                errorEl.textContent = 'Ce pseudo est déjà pris.';
                return;
            }

            const result = await AuthService.register(pseudo, password);
            if (!result.success) {
                errorEl.textContent = result.error || 'Impossible de créer le compte.';
                return;
            }

            document.getElementById('register-page-title').classList.add('hidden');
            document.getElementById('register-form-block').classList.add('hidden');
            const successBlock = document.getElementById('register-success-block');
            successBlock.classList.remove('hidden');
            successBlock.style.display = 'flex';
            document.getElementById('register-success-pseudo').textContent = result.user.pseudo;
            playSound('action-confirm');
        }

        // Track whether we're in guest mode (independent of login session)
        let isGuestMode = false;
        let isNavigatingHistory = false;
        let cqAdminTestMode = false;

        let currentGame = {
            quiz: null,
            currentQIndex: 0,
            score: 0,
            timerInterval: null,
            transitionTimeout: null,
            timeLeft: 0,
            totalTime: 0,
            canAnswer: false
        };

        function updateGuestModeFromView(viewId) {
            if (viewId === 'view-guest-home') {
                isGuestMode = true;
            } else if (viewId === 'view-landing') {
                isGuestMode = false;
            } else if (viewId === 'view-user-home' || viewId === 'view-user-profile' || viewId === 'view-admin') {
                isGuestMode = false;
            }
        }

        function pushViewState(viewId, replace = false) {
            if (!window.history || typeof window.history.replaceState !== 'function') return;
            const url = `#${viewId}`;
            const state = { view: viewId };
            if (replace) {
                window.history.replaceState(state, '', url);
            } else {
                window.history.pushState(state, '', url);
            }
        }

        function showView(viewId, options = {}) {
            if (viewId !== 'view-game') stopGameTimers();

            // Track guest mode state from the requested view.
            updateGuestModeFromView(viewId);

            // Protéger TOUTES les vues admin (view-admin et view-admin-*)
            if (viewId === 'view-admin' || viewId.startsWith('view-admin-')) {
                hasAdminSession().then(allowed => {
                    if (!allowed) showView('view-landing');
                    else applyView(viewId);
                });
                return;
            }

            if (viewId === 'view-user-home') {
                if (!AuthService.getCurrentUser()) {
                    applyView('view-login');
                    resetLoginForm();
                    if (!options.skipHistory) pushViewState('view-login');
                    return;
                }
            }

            applyView(viewId);
            if (!options.skipHistory && !isNavigatingHistory) {
                pushViewState(viewId);
            }
        }

        function applyView(viewId) {
            document.querySelectorAll('div[id^="view-"]').forEach(v => v.classList.add('hidden'));
            document.getElementById(viewId).classList.remove('hidden');

            // Admin-only pages: on masque les headers externes
            const guestHeader = document.getElementById('common-guest-header');
            const authHeader = document.getElementById('auth-header');
            if (viewId && viewId.startsWith('view-admin-')) {
                if (guestHeader) guestHeader.classList.add('hidden');
                if (authHeader) authHeader.classList.add('hidden');

                // Init UI "Outil Création" quand on entre dans la page
                if (viewId === 'view-admin-creation-quiz' && typeof cqInitCreationRightCard === 'function') {
                    cqInitCreationRightCard();
                }
                
                // Init UI "Gérer les jeux" quand on entre dans la page
                if (viewId === 'view-admin-manage-games') {
                    cqRenderManageGames();
                }

                // Init UI "Tester mes jeux" quand on entre dans la page
                if (viewId === 'view-admin-test-games' && typeof cqRenderAdminTestGames === 'function') {
                    cqRenderAdminTestGames();
                }

                // Init UI "Tableau de bord" quand on entre dans la page
                if (viewId === 'view-admin-dashboard' && typeof cqRenderAdminDashboard === 'function') {
                    cqRenderAdminDashboard();
                }

                // Init UI "Modération" quand on entre dans la page
                if (viewId === 'view-admin-moderation' && typeof cqRenderModeration === 'function') {
                    cqRenderModeration('');
                }

                // Init messagerie admin
                if (viewId === 'view-admin-messaging') {
                    msgAdminSwitchTab('classic');
                    msgAdminShowList();
                }
                if (typeof updateNotifBadges === 'function') setTimeout(updateNotifBadges, 50);
                return;
            }

            // Mode test admin : on rejoue view-game / view-results sans le header invité
            if (cqAdminTestMode && (viewId === 'view-game' || viewId === 'view-results')) {
                guestHeader.classList.add('hidden');
                authHeader.classList.add('hidden');
                return;
            }

            const authButtons = document.getElementById('header-auth-buttons');
            const profileButton = document.getElementById('header-profile-button');
            const navBtn = document.getElementById('nav-toggle-games');
            const guestViews = ['view-guest-home', 'view-all-games', 'view-game', 'view-results'];
            const userViews = ['view-user-home', 'view-user-profile', 'view-my-scores', 'view-messaging'];
            const authViews = ['view-register', 'view-login'];
            const isLoggedIn = !!AuthService.getCurrentUser();

            guestHeader.classList.add('hidden');
            authHeader.classList.add('hidden');

            if (authViews.includes(viewId)) {
                authHeader.classList.remove('hidden');
            } else if (guestViews.includes(viewId) || userViews.includes(viewId)) {
                guestHeader.classList.remove('hidden');
                // Mise à jour centralisée de l'état des boutons d'auth
                updateHeaderAuthState();

                // Rafraîchir les catégories affichées dans la bannière
                if (typeof cqRenderBannerCategoriesNav === 'function') {
                    cqRenderBannerCategoriesNav();
                }

                // Si on affiche le profil, le charger avec les données actuelles
                if (viewId === 'view-user-profile') {
                    loadProfileData();
                }

                // Si on affiche la page Mes Scores, la charger
                if (viewId === 'view-my-scores') {
                    renderMyScores();
                }

                // Si on affiche l'accueil connecté, charger pseudo + à la une + favoris
                if (viewId === 'view-user-home') {
                    cqInitUserHome();
                    if (typeof updateNotifBadges === 'function') updateNotifBadges();
                }
            }

            // Gestion des boutons de navigation dans la bannière
            const isOnHomeView = (viewId === 'view-guest-home' || viewId === 'view-user-home');
            const isOnAllGamesView = viewId === 'view-all-games';
            const homeBtn = document.getElementById('nav-btn-home');
            const categoriesNav = document.getElementById('banner-categories-nav');
            
            if (homeBtn) {
                homeBtn.onclick = () => showView(isLoggedIn ? 'view-user-home' : 'view-guest-home');
            }

            if (isOnHomeView) {
                // Sur l'accueil : afficher uniquement "Tous les jeux", cacher "Accueil"
                if (homeBtn) homeBtn.classList.add('hidden');
                navBtn.innerText = 'Tous les jeux';
                navBtn.onclick = () => showView('view-all-games');
                navBtn.classList.remove('hidden');
                if (categoriesNav) categoriesNav.classList.remove('ml-0');
            } else if (isOnAllGamesView) {
                // Sur "Tous les jeux" : afficher uniquement "Accueil", cacher "Tous les jeux"
                if (homeBtn) homeBtn.classList.remove('hidden');
                navBtn.classList.add('hidden');

                // Re-render les catégories en fonction des assignations admin actuelles
                if (typeof cqRenderPublicCategories === 'function') {
                    cqRenderPublicCategories();
                }
            } else {
                // Sur les autres pages : afficher les deux boutons
                if (homeBtn) homeBtn.classList.remove('hidden');
                navBtn.innerText = 'Tous les jeux';
                navBtn.onclick = () => showView('view-all-games');
                navBtn.classList.remove('hidden');
            }

            if (viewId === 'view-guest-home' && typeof cqRenderFeaturedBanner === 'function') {
                cqRenderFeaturedBanner();
            }

            if (viewId === 'view-messaging') {
                document.body.style.overflow = 'hidden';
                msgSwitchTab('classic');
                msgRenderUserChat();
                if (typeof updateNotifBadges === 'function') updateNotifBadges();
            } else {
                document.body.style.overflow = '';
            }
        }

        function getValidView(viewId) {
            return viewId && document.getElementById(viewId) ? viewId : 'view-landing';
        }

        function restoreViewFromHistory(viewId) {
            const validView = getValidView(viewId);
            isNavigatingHistory = true;
            showView(validView, { skipHistory: true });
            isNavigatingHistory = false;
        }

        window.addEventListener('popstate', (event) => {
            const state = event.state;
            const hashView = window.location.hash.replace('#', '');
            const viewId = state && state.view ? state.view : hashView || 'view-landing';
            restoreViewFromHistory(viewId);
        });

        window.addEventListener('load', () => {
            const initialView = window.location.hash.replace('#', '') || 'view-landing';
            if (document.getElementById(initialView)) {
                showView(initialView, { skipHistory: true });
                pushViewState(initialView, true);
            } else {
                showView('view-landing', { skipHistory: true });
                pushViewState('view-landing', true);
            }
        });

        function stopGameTimers() {
            if (currentGame.timerInterval) {
                clearInterval(currentGame.timerInterval);
                currentGame.timerInterval = null;
            }
            if (currentGame.transitionTimeout) {
                clearTimeout(currentGame.transitionTimeout);
                currentGame.transitionTimeout = null;
            }
        }

        function updateHeaderAuthState() {
            const authButtons = document.getElementById('header-auth-buttons');
            const profileButton = document.getElementById('header-profile-button');
            
            // In guest mode: always show auth buttons, never show profile button
            if (isGuestMode) {
                if (authButtons) authButtons.classList.remove('hidden');
                if (profileButton) profileButton.classList.add('hidden');
                return;
            }

            // In logged-in mode: show profile button if logged in, auth buttons if not
            const isLoggedIn = !!AuthService.getCurrentUser();
            if (authButtons) authButtons.classList.toggle('hidden', isLoggedIn);
            if (profileButton) profileButton.classList.toggle('hidden', !isLoggedIn);
        }

        let cqNoTimerMode = false;

        function startQuiz(quizOrId, noTimer) {
            let quiz = null;

            if (!quizOrId) return;

            if (typeof quizOrId === 'string') {
                quiz = QUIZ_REGISTRY[quizOrId] || null;
            } else if (typeof quizOrId === 'object') {
                quiz = quizOrId;
            }

            if (!quiz || !Array.isArray(quiz.questions) || !quiz.questions.length) return;

            // Randomisation : mélanger les questions et les réponses de chaque question
            function shuffleArray(arr) {
                const a = arr.slice();
                for (let i = a.length - 1; i > 0; i--) {
                    const j = Math.floor(Math.random() * (i + 1));
                    [a[i], a[j]] = [a[j], a[i]];
                }
                return a;
            }
            const shuffledQuestions = shuffleArray(quiz.questions).map(q => {
                if (!Array.isArray(q.answers)) return q;
                return Object.assign({}, q, { answers: shuffleArray(q.answers) });
            });
            const randomizedQuiz = Object.assign({}, quiz, { questions: shuffledQuestions });

            cqNoTimerMode = !!noTimer;
            stopGameTimers();
            currentGame = {
                quiz: randomizedQuiz,
                currentQIndex: 0,
                score: 0,
                timerInterval: null,
                transitionTimeout: null,
                timeLeft: 0,
                totalTime: 0,
                canAnswer: false
            };

            document.getElementById('game-quiz-title').textContent = quiz.title || 'Quiz';
            const testBanner = document.getElementById('cq-admin-test-banner');
            if (testBanner) testBanner.classList.toggle('hidden', !cqAdminTestMode);
            updateScoreDisplay();

            // Afficher la description si présente
            const descEl = document.getElementById('game-description');
            if (descEl) {
                if (quiz.description) {
                    descEl.textContent = quiz.description;
                    descEl.classList.remove('hidden');
                } else {
                    descEl.classList.add('hidden');
                }
            }

            showPreGameScreen(quiz);
            showView('view-game');

            // Bouton favori sous la carte (session connectée uniquement)
            cqUpdateFavoriteButtonState('game');

            // Classement du quiz
            if (quiz.id) {
                cqRenderQuizLeaderboard(quiz.id);
            } else {
                const section = document.getElementById('quiz-leaderboard-section');
                if (section) section.classList.add('hidden');
            }
        }

        /* ============================================================
           CQ CATEGORIES (gestion par l'admin + affichage côté joueur)
           - L'admin crée 1 à 6 catégories, et assigne des jeux existants
             (en ligne ou en fermeture temporaire) à chacune.
           - Un même jeu peut être assigné à plusieurs catégories.
           - Côté invité/connecté, "Tous les jeux" affiche les catégories
             telles que définies par l'admin ; seuls les jeux "en ligne"
             sont réellement jouables (bouton désactivé sinon).
           ============================================================ */

        const CQ_CATEGORIES_STORAGE_KEY = 'cq_categories_v1';
        const CQ_MAX_CATEGORIES = 6; // 5 catégories personnalisables max + 1 catégorie permanente "Divers"
        const CQ_DIVERS_CATEGORY_ID = 'divers';
        let cqCategoryPendingDeleteId = null;

        function cqGenId(prefix) {
            return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
        }

        function cqMakeDiversCategory() {
            return { id: CQ_DIVERS_CATEGORY_ID, name: 'Divers', quizTitles: [], isPermanent: true };
        }

        function cqDefaultCategories() {
            // Au tout premier lancement, seule la catégorie permanente "Divers" existe.
            return [cqMakeDiversCategory()];
        }

        // S'assure que la catégorie permanente "Divers" est toujours présente,
        // unique, et affichée en dernier dans la liste.
        function cqEnsureDiversCategory(categories) {
            const list = Array.isArray(categories) ? categories.slice() : [];
            let diversIdx = list.findIndex(c => c.id === CQ_DIVERS_CATEGORY_ID || c.isPermanent);
            let divers;
            if (diversIdx === -1) {
                divers = cqMakeDiversCategory();
            } else {
                divers = list.splice(diversIdx, 1)[0];
                divers = {
                    id: CQ_DIVERS_CATEGORY_ID,
                    name: 'Divers',
                    quizTitles: Array.isArray(divers.quizTitles) ? divers.quizTitles : [],
                    isPermanent: true
                };
            }
            list.push(divers);
            return list;
        }

        function cqGetCategories() {
            const stored = localStorage.getItem(CQ_CATEGORIES_STORAGE_KEY);
            if (!stored) {
                const defaults = cqDefaultCategories();
                localStorage.setItem(CQ_CATEGORIES_STORAGE_KEY, JSON.stringify(defaults));
                return defaults;
            }
            try {
                const parsed = JSON.parse(stored);
                if (!Array.isArray(parsed) || parsed.length === 0) {
                    const defaults = cqDefaultCategories();
                    localStorage.setItem(CQ_CATEGORIES_STORAGE_KEY, JSON.stringify(defaults));
                    return defaults;
                }
                const normalized = parsed.map(c => ({
                    id: c?.id || cqGenId('cat'),
                    name: typeof c?.name === 'string' ? c.name : 'Catégorie',
                    quizTitles: Array.isArray(c?.quizTitles) ? c.quizTitles : [],
                    isPermanent: !!c?.isPermanent || c?.id === CQ_DIVERS_CATEGORY_ID
                }));
                return cqEnsureDiversCategory(normalized);
            } catch (e) {
                const defaults = cqDefaultCategories();
                localStorage.setItem(CQ_CATEGORIES_STORAGE_KEY, JSON.stringify(defaults));
                return defaults;
            }
        }

        function cqSaveCategories(categories) {
            localStorage.setItem(CQ_CATEGORIES_STORAGE_KEY, JSON.stringify(cqEnsureDiversCategory(categories)));
            cqSyncPlayerViews();
        }

        // Calcule la liste des jeux qui tombent automatiquement dans "Divers" :
        // tous les jeux en ligne ou en fermeture temporaire qui ne sont assignés
        // à aucune autre catégorie (personnalisable).
        function cqComputeDiversQuizTitles(categories, quizzes) {
            const assignedElsewhere = new Set();
            categories.forEach(cat => {
                if (cat.id === CQ_DIVERS_CATEGORY_ID || cat.isPermanent) return;
                (cat.quizTitles || []).forEach(t => assignedElsewhere.add(t));
            });
            return quizzes
                .filter(q => (q.status === 'online' || q.status === 'temp') && !assignedElsewhere.has(q.title))
                .map(q => q.title);
        }

        // Retourne les catégories "telles qu'affichées" : la catégorie Divers
        // a son contenu recalculé dynamiquement (jamais stocké manuellement).
        function cqGetCategoriesForDisplay() {
            const categories = cqGetCategories();
            const quizzes = cqGetQuizzes();
            const diversTitles = cqComputeDiversQuizTitles(categories, quizzes);
            return categories.map(cat => {
                if (cat.id === CQ_DIVERS_CATEGORY_ID || cat.isPermanent) {
                    return { ...cat, quizTitles: diversTitles };
                }
                return cat;
            });
        }

        /* ============================================================
           CQ DASHBOARD (Tableau de bord admin)
           - Connexions par jour, comptes créés, jeux triés par parties jouées.
           ============================================================ */

        const CQ_CONNECTIONS_LOG_KEY = 'cq_connections_log_v1';
        const CQ_GAME_PLAYS_KEY = 'cq_game_plays_v1';
        const CQ_USERS_STORAGE_KEY = 'cq_users';

        function cqTodayISO() {
            return new Date().toISOString().split('T')[0];
        }

        function cqRecordConnection() {
            try {
                const raw = localStorage.getItem(CQ_CONNECTIONS_LOG_KEY);
                const log = raw ? JSON.parse(raw) : {};
                const today = cqTodayISO();
                log[today] = (log[today] || 0) + 1;
                localStorage.setItem(CQ_CONNECTIONS_LOG_KEY, JSON.stringify(log));
            } catch (e) { /* noop */ }
        }

        function cqGetConnectionsLog() {
            try {
                const raw = localStorage.getItem(CQ_CONNECTIONS_LOG_KEY);
                return raw ? JSON.parse(raw) : {};
            } catch (e) {
                return {};
            }
        }

        function cqRecordGamePlay(title) {
            if (!title) return;
            try {
                const raw = localStorage.getItem(CQ_GAME_PLAYS_KEY);
                const log = raw ? JSON.parse(raw) : {};
                log[title] = (log[title] || 0) + 1;
                localStorage.setItem(CQ_GAME_PLAYS_KEY, JSON.stringify(log));
            } catch (e) { /* noop */ }
        }

        function cqGetGamePlays() {
            try {
                const raw = localStorage.getItem(CQ_GAME_PLAYS_KEY);
                return raw ? JSON.parse(raw) : {};
            } catch (e) {
                return {};
            }
        }

        /* ============================================================
           MEILLEURS SCORES PAR COMPTE ET PAR QUIZ (Top 50)
           Cle de stockage : cq_best_scores_v1
           Structure : { [userId]: { [quizId]: [score1, score2, ...] } }
           ============================================================ */
        const CQ_BEST_SCORES_KEY = 'cq_best_scores_v1';
        const CQ_MAX_BEST_SCORES = 50;

        function cqGetAllBestScores() {
            try {
                const raw = localStorage.getItem(CQ_BEST_SCORES_KEY);
                return raw ? JSON.parse(raw) : {};
            } catch (e) {
                return {};
            }
        }

        function cqSaveAllBestScores(data) {
            localStorage.setItem(CQ_BEST_SCORES_KEY, JSON.stringify(data));
        }

        function cqGetBestScores(userId, quizId) {
            if (!userId || !quizId) return [];
            const all = cqGetAllBestScores();
            return (all[userId] && all[userId][quizId]) ? all[userId][quizId] : [];
        }

        function cqSaveBestScore(quizId, score) {
            const user = AuthService.getCurrentUser();
            if (!user || !quizId || typeof score !== 'number') return;
            const userId = user.id;
            const all = cqGetAllBestScores();
            if (!all[userId]) all[userId] = {};
            const list = Array.isArray(all[userId][quizId]) ? all[userId][quizId].slice() : [];
            if (list.length < CQ_MAX_BEST_SCORES) {
                list.push(score);
            } else {
                const minScore = Math.min(...list);
                if (score > minScore) {
                    const minIdx = list.lastIndexOf(minScore);
                    list.splice(minIdx, 1);
                    list.push(score);
                } else {
                    return;
                }
            }
            list.sort((a, b) => b - a);
            all[userId][quizId] = list;
            cqSaveAllBestScores(all);
            cqUpdateQuizLeaderboard(quizId, score);
        }

        /* ============================================================
           CLASSEMENT PAR QUIZ
           Stockage : { [quizId]: [ {userId, pseudo, score, date}, ... ] }
           ============================================================ */
        const CQ_QUIZ_LB_KEY = 'cq_quiz_leaderboard_v1';

        function cqGetQuizLeaderboard(quizId) {
            try {
                const raw = localStorage.getItem(CQ_QUIZ_LB_KEY);
                const all = raw ? JSON.parse(raw) : {};
                return Array.isArray(all[quizId]) ? all[quizId] : [];
            } catch(e) { return []; }
        }

        function cqSaveQuizLeaderboard(quizId, entries) {
            try {
                const raw = localStorage.getItem(CQ_QUIZ_LB_KEY);
                const all = raw ? JSON.parse(raw) : {};
                all[quizId] = entries;
                localStorage.setItem(CQ_QUIZ_LB_KEY, JSON.stringify(all));
            } catch(e) {}
        }

        function cqUpdateQuizLeaderboard(quizId, score) {
            const user = AuthService.getCurrentUser();
            if (!user || !quizId || typeof score !== 'number') return;
            const entries = cqGetQuizLeaderboard(quizId);
            const now = new Date().toISOString();
            const existingIdx = entries.findIndex(e => e.userId === user.id);
            if (existingIdx >= 0) {
                if (score > entries[existingIdx].score) {
                    entries[existingIdx].score = score;
                    entries[existingIdx].date = now;
                    entries[existingIdx].pseudo = user.pseudo;
                }
            } else {
                entries.push({ userId: user.id, pseudo: user.pseudo, score, date: now });
            }
            entries.sort((a, b) => b.score - a.score);
            const trimmed = entries.slice(0, 50);
            cqSaveQuizLeaderboard(quizId, trimmed);
        }

        function cqRenderQuizLeaderboard(quizId) {
            const section = document.getElementById('quiz-leaderboard-section');
            const list = document.getElementById('quiz-leaderboard-list');
            const empty = document.getElementById('quiz-leaderboard-empty');
            if (!section || !list || !empty) return;
            const entries = cqGetQuizLeaderboard(quizId);
            if (!entries.length) {
                section.classList.remove('hidden');
                empty.classList.remove('hidden');
                list.innerHTML = '';
                return;
            }
            section.classList.remove('hidden');
            empty.classList.add('hidden');
            let html = '';
            entries.forEach((e, i) => {
                const rank = i + 1;
                let rankClass = 'background:#e5e7eb;';
                if (rank === 1) rankClass = 'background:#FFD700;';
                else if (rank === 2) rankClass = 'background:#C0C0C0;';
                else if (rank === 3) rankClass = 'background:#CD7F32;color:#fff;';
                let dateStr = '';
                try {
                    const d = new Date(e.date);
                    dateStr = d.toLocaleDateString('fr-FR') + ' ' + d.toLocaleTimeString('fr-FR', {hour:'2-digit',minute:'2-digit'});
                } catch(_) {}
                const miniAvatar = buildMiniAvatarHtml(e.pseudo || '?');
                if (i > 0) html += '<div class="leaderboard-divider"></div>';
                html += `<div class="leaderboard-row">
                    <span class="rank-badge" style="${rankClass}flex-shrink:0;">${rank}</span>
                    ${miniAvatar}
                    <span class="leaderboard-chip leaderboard-chip-name" style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${clickablePseudoHtml(e.pseudo || '?')}</span>
                    <span class="leaderboard-chip leaderboard-chip-score">${Number(e.score).toLocaleString('fr-FR')}</span>
                    <span class="quiz-lb-date">${dateStr}</span>
                </div>`;
            });
            list.innerHTML = html;
        }

        function cqRenderResultsLeaderboard(quizId) {
            const section = document.getElementById('results-leaderboard-section');
            const list = document.getElementById('results-leaderboard-list');
            const empty = document.getElementById('results-leaderboard-empty');
            if (!section || !list || !empty) return;
            if (!isGuestMode && !AuthService.getCurrentUser()) {
                section.classList.add('hidden');
                return;
            }
            const entries = cqGetQuizLeaderboard(quizId);
            section.classList.remove('hidden');
            if (!entries.length) {
                empty.classList.remove('hidden');
                list.innerHTML = '';
                return;
            }
            empty.classList.add('hidden');
            let html = '';
            entries.forEach((e, i) => {
                const rank = i + 1;
                let rankClass = 'background:#e5e7eb;';
                if (rank === 1) rankClass = 'background:#FFD700;';
                else if (rank === 2) rankClass = 'background:#C0C0C0;';
                else if (rank === 3) rankClass = 'background:#CD7F32;color:#fff;';
                let dateStr = '';
                try {
                    const d = new Date(e.date);
                    dateStr = d.toLocaleDateString('fr-FR') + ' ' + d.toLocaleTimeString('fr-FR', {hour:'2-digit',minute:'2-digit'});
                } catch(_) {}
                const miniAvatar2 = buildMiniAvatarHtml(e.pseudo || '?');
                if (i > 0) html += '<div class="leaderboard-divider"></div>';
                html += `<div class="leaderboard-row">
                    <span class="rank-badge" style="${rankClass}flex-shrink:0;">${rank}</span>
                    ${miniAvatar2}
                    <span class="leaderboard-chip leaderboard-chip-name" style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${clickablePseudoHtml(e.pseudo || '?')}</span>
                    <span class="leaderboard-chip leaderboard-chip-score">${Number(e.score).toLocaleString('fr-FR')}</span>
                    <span class="quiz-lb-date">${dateStr}</span>
                </div>`;
            });
            list.innerHTML = html;
        }

        function cqGetAllUsersForDashboard() {
            try {
                const raw = localStorage.getItem(CQ_USERS_STORAGE_KEY);
                const users = raw ? JSON.parse(raw) : [];
                return Array.isArray(users) ? users : [];
            } catch (e) {
                return [];
            }
        }

        function cqFormatDateFr(isoDate) {
            if (!isoDate) return '-';
            const d = new Date(isoDate);
            if (isNaN(d.getTime())) return isoDate;
            return d.toLocaleDateString('fr-FR');
        }

        function cqRenderAdminDashboard() {
            cqRenderDashboardKpis();
            cqRenderDashboardConnections();
            cqRenderDashboardAccounts();
            cqRenderDashboardGamesByPlays();
        }

        function cqRenderDashboardKpis() {
            const container = document.getElementById('cq-dash-kpis');
            if (!container) return;

            const users = cqGetAllUsersForDashboard();
            const connectionsLog = cqGetConnectionsLog();
            const gamePlays = cqGetGamePlays();
            const quizzes = cqGetQuizzes();

            const today = cqTodayISO();
            const totalConnections = Object.values(connectionsLog).reduce((sum, n) => sum + n, 0);
            const totalPlays = Object.values(gamePlays).reduce((sum, n) => sum + n, 0);
            const onlineGamesCount = quizzes.filter(q => q.status === 'online').length;

            const kpis = [
                { label: 'Comptes créés', value: users.length },
                { label: 'Connexions aujourd\'hui', value: connectionsLog[today] || 0 },
                { label: 'Connexions au total', value: totalConnections },
                { label: 'Parties jouées au total', value: totalPlays },
                { label: 'Jeux en ligne', value: `${onlineGamesCount} / ${quizzes.length}` }
            ];

            container.innerHTML = kpis.map(k => `
                <div class="cq-dash-card cq-dash-kpi-card">
                    <div class="cq-dash-kpi-value">${escapeHtml(String(k.value))}</div>
                    <div class="cq-dash-kpi-label">${escapeHtml(k.label)}</div>
                </div>
            `).join('');
        }

        function cqRenderDashboardConnections() {
            const container = document.getElementById('cq-dash-connections-list');
            if (!container) return;

            const log = cqGetConnectionsLog();
            const days = Object.keys(log).sort((a, b) => b.localeCompare(a)).slice(0, 14);

            if (!days.length) {
                container.innerHTML = `<p class="cqcat-empty-hint">Aucune connexion enregistrée pour le moment.</p>`;
                return;
            }

            const maxCount = Math.max(...days.map(d => log[d]));

            container.innerHTML = days.map(day => {
                const count = log[day];
                const pct = maxCount > 0 ? Math.max(6, Math.round((count / maxCount) * 100)) : 0;
                return `
                    <div class="cq-dash-bar-row">
                        <span class="cq-dash-bar-label">${escapeHtml(cqFormatDateFr(day))}</span>
                        <div class="cq-dash-bar-track">
                            <div class="cq-dash-bar-fill" style="width:${pct}%;"></div>
                        </div>
                        <span class="cq-dash-bar-value">${escapeHtml(String(count))}</span>
                    </div>
                `;
            }).join('');
        }

        function cqRenderDashboardAccounts() {
            const container = document.getElementById('cq-dash-accounts-list');
            if (!container) return;

            const users = cqGetAllUsersForDashboard()
                .slice()
                .sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''));

            if (!users.length) {
                container.innerHTML = `<p class="cqcat-empty-hint">Aucun compte créé pour le moment.</p>`;
                return;
            }

            container.innerHTML = users.map(u => `
                <div class="cq-dash-row">
                    <span class="cq-dash-row-main">${clickablePseudoHtml(u.pseudo || '-')}</span>
                    <span class="cq-dash-row-sub">${escapeHtml(cqFormatDateFr(u.createdAt))}</span>
                </div>
            `).join('');
        }

        function cqRenderDashboardGamesByPlays() {
            const container = document.getElementById('cq-dash-games-list');
            if (!container) return;

            const quizzes = cqGetQuizzes();
            const plays = cqGetGamePlays();

            const sorted = quizzes
                .slice()
                .sort((a, b) => (plays[b.title] || 0) - (plays[a.title] || 0));

            if (!sorted.length) {
                container.innerHTML = `<p class="cqcat-empty-hint">Aucun jeu pour le moment.</p>`;
                return;
            }

            container.innerHTML = sorted.map(q => `
                <div class="cq-dash-row">
                    <span class="cq-dash-row-main">${escapeHtml(q.title)}</span>
                    <span class="${cqQuizStatusDotClass(q.status)}"></span>
                    <span class="cq-dash-row-sub">${escapeHtml(String(plays[q.title] || 0))} partie(s)</span>
                </div>
            `).join('');
        }

        function cqRenderBannerCategoriesNav() {
            const container = document.getElementById('banner-categories-nav');
            if (!container) return;

            const categories = cqGetCategoriesForDisplay();
            const quizzes = cqGetQuizzes();

            container.innerHTML = categories.map(cat => {
                const items = cat.quizTitles
                    .map(title => quizzes.find(q => q.title === title))
                    .filter(quiz => quiz && (quiz.status === 'online' || quiz.status === 'temp'))
                    .map(quiz => {
                        return `
                            <button type="button" class="cqcat-banner-dropdown-item"
                                data-title="${escapeHtml(quiz.title)}"
                                onclick="cqOnPublicQuizCardClick(this.dataset.title)">
                                ${escapeHtml(quiz.title)}
                            </button>
                        `;
                    }).join('');

                return `
                    <div class="relative group py-2">
                        <button type="button" class="px-3 py-1.5 rounded-lg text-xs font-bold uppercase font-button hover:bg-black/5">${escapeHtml(cat.name)}</button>
                        <div class="dropdown-menu">
                            ${items || '<div class="cqcat-banner-dropdown-empty">Aucun jeu</div>'}
                        </div>
                    </div>
                `;
            }).join('');
        }

        function cqSyncPlayerViews() {
            if (typeof cqRenderPublicCategories === 'function') cqRenderPublicCategories();
            if (typeof cqRenderFeaturedBanner === 'function') cqRenderFeaturedBanner();
            if (typeof cqRenderBannerCategoriesNav === 'function') cqRenderBannerCategoriesNav();
            if (typeof cqRenderFeaturedBannerInto === 'function') cqRenderFeaturedBannerInto('user-featured-quizzes-grid');
            if (typeof cqRenderUserFavorites === 'function') cqRenderUserFavorites();
        }

        // --- Nettoyage automatique des références (suppression / renommage d'un jeu) ---
        function cqRemoveQuizFromAllCategories(title) {
            const categories = cqGetCategories();
            let changed = false;
            categories.forEach(cat => {
                const before = cat.quizTitles.length;
                cat.quizTitles = cat.quizTitles.filter(t => t !== title);
                if (cat.quizTitles.length !== before) changed = true;
            });
            if (changed) cqSaveCategories(categories);
        }

        function cqRenameQuizInCategories(oldTitle, newTitle) {
            if (oldTitle === newTitle) return;
            const categories = cqGetCategories();
            let changed = false;
            categories.forEach(cat => {
                cat.quizTitles = cat.quizTitles.map(t => {
                    if (t === oldTitle) { changed = true; return newTitle; }
                    return t;
                });
            });
            if (changed) cqSaveCategories(categories);
        }

        // --- Modale "Gérer les catégories" ---
        function cqOpenCategoriesModal() {
            playSound('modal-open');
            cqCategoryPendingDeleteId = null;
            cqRenderCategoriesModal();
            const modal = document.getElementById('modal-cq-categories');
            if (modal) modal.classList.remove('hidden');
            const mainContent = document.getElementById('main-content');
            if (mainContent) mainContent.classList.add('blur-bg');
        }

        function cqCloseCategoriesModal() {
            playSound('modal-close');
            cqCategoryPendingDeleteId = null;
            const modal = document.getElementById('modal-cq-categories');
            if (modal) modal.classList.add('hidden');
            const mainContent = document.getElementById('main-content');
            if (mainContent) mainContent.classList.remove('blur-bg');
        }

        function cqQuizStatusLabel(status) {
            if (status === 'online') return 'En ligne';
            if (status === 'temp') return 'Fermeture temp.';
            return 'Hors ligne';
        }

        function cqQuizStatusDotClass(status) {
            if (status === 'online') return 'cq-admin-online-dot';
            if (status === 'temp') return 'cq-admin-temp-dot';
            return 'cq-admin-offline-dot';
        }

        function cqRenderCategoriesModal() {
            const list = document.getElementById('cq-categories-modal-list');
            if (!list) return;

            const categories = cqGetCategoriesForDisplay();
            const quizzes = cqGetQuizzes();
            const addBtn = document.getElementById('cq-add-category-btn');
            if (addBtn) {
                const reached = categories.length >= CQ_MAX_CATEGORIES;
                addBtn.disabled = reached;
                addBtn.classList.toggle('cqcat-disabled', reached);
            }

            list.innerHTML = categories.map(cat => {
                const isDivers = cat.id === CQ_DIVERS_CATEGORY_ID || cat.isPermanent;
                const canDelete = categories.length > 1 && !isDivers;
                const isPendingDelete = cqCategoryPendingDeleteId === cat.id;

                const assignedTitlesSet = new Set(cat.quizTitles);
                const availableForSelect = quizzes.filter(q => !assignedTitlesSet.has(q.title));

                const selectOptions = availableForSelect.map(q => `
                    <option value="${escapeHtml(q.title)}" class="bg-[#374151] text-white">${escapeHtml(q.title)} — ${cqQuizStatusLabel(q.status)}</option>
                `).join('');

                const quizChips = cat.quizTitles.map(title => {
                    const quiz = quizzes.find(q => q.title === title);
                    if (!quiz) return '';
                    const removeBtn = isDivers ? '' : `
                        <button type="button" class="cqcat-quiz-chip-remove" data-cat="${cat.id}" data-title="${escapeHtml(title)}"
                            onclick="cqUnassignQuizFromCategory(this.dataset.cat, this.dataset.title)" title="Détacher ce jeu">✕</button>
                    `;
                    return `
                        <div class="cqcat-quiz-chip">
                            <span class="${cqQuizStatusDotClass(quiz.status)}"></span>
                            <span class="cqcat-quiz-chip-name">${escapeHtml(title)}</span>
                            ${removeBtn}
                        </div>
                    `;
                }).join('');

                return `
                    <div class="cqcat-card">
                        <div class="cqcat-card-head">
                            <input type="text" class="cqcat-name-input" value="${escapeHtml(cat.name)}"
                                data-cat="${cat.id}"
                                ${isDivers ? 'disabled title="Catégorie permanente, non renommable"' : `onchange="cqRenameCategory(this.dataset.cat, this.value)"`} />
                            <button type="button" class="cqcat-delete-btn ${!canDelete ? 'cqcat-disabled' : ''}"
                                data-cat="${cat.id}"
                                onclick="cqRequestDeleteCategory(this.dataset.cat)"
                                ${!canDelete ? 'disabled' : ''}
                                title="${isDivers ? 'Catégorie permanente, non supprimable' : 'Supprimer la catégorie'}">
                                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" class="w-4 h-4"><path stroke-linecap="round" stroke-linejoin="round" d="m14.74 9-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 0 1-2.244 2.077H8.084a2.25 2.25 0 0 1-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 0 0-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 0 1 3.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0" /></svg>
                            </button>
                        </div>

                        ${isDivers ? `
                        <p class="cqcat-empty-hint" style="opacity:.7;">Catégorie permanente</p>
                        ` : ''}

                        <div class="cqcat-confirm-row ${isPendingDelete ? '' : 'hidden'}" data-cat="${cat.id}">
                            <span>Supprimer cette catégorie ? Les jeux seront détachés.</span>
                            <div class="cqcat-confirm-actions">
                                <button type="button" class="cqcat-confirm-no" onclick="cqCancelDeleteCategory()">Annuler</button>
                                <button type="button" class="cqcat-confirm-yes" data-cat="${cat.id}" onclick="cqConfirmDeleteCategory(this.dataset.cat)">Oui, supprimer</button>
                            </div>
                        </div>

                        ${isDivers ? '' : `
                        <div class="cqcat-assign-row">
                            <select id="cqcat-select-${cat.id}" class="cqcat-select">
                                <option value="" class="bg-[#374151] text-white">— Choisir un jeu à assigner —</option>
                                ${selectOptions}
                            </select>
                            <button type="button" class="cqcat-assign-btn" data-cat="${cat.id}" onclick="cqAssignQuizToCategory(this.dataset.cat)">Assigner</button>
                        </div>
                        <div id="cqcat-error-${cat.id}" class="cqcat-error hidden"></div>
                        `}

                        <div class="cqcat-quiz-list">
                            ${quizChips || '<p class="cqcat-empty-hint">Aucun jeu assigné pour le moment.</p>'}
                        </div>
                    </div>
                `;
            }).join('');
        }

        function cqAddCategory() {
            const categories = cqGetCategories();
            if (categories.length >= CQ_MAX_CATEGORIES) return;

            categories.push({
                id: cqGenId('cat'),
                name: `Catégorie ${categories.length + 1}`,
                quizTitles: []
            });
            cqSaveCategories(categories);
            cqRenderCategoriesModal();
        }

        function cqRenameCategory(catId, newName) {
            if (catId === CQ_DIVERS_CATEGORY_ID) return;
            const categories = cqGetCategories();
            const cat = categories.find(c => c.id === catId);
            if (!cat || cat.isPermanent) return;

            const trimmed = (newName || '').trim();
            cat.name = trimmed || cat.name;
            cqSaveCategories(categories);
            cqRenderCategoriesModal();
        }

        function cqRequestDeleteCategory(catId) {
            if (catId === CQ_DIVERS_CATEGORY_ID) return;
            const categories = cqGetCategories();
            const cat = categories.find(c => c.id === catId);
            if (!cat || cat.isPermanent) return;
            if (categories.length <= 1) return;
            cqCategoryPendingDeleteId = catId;
            cqRenderCategoriesModal();
        }

        function cqCancelDeleteCategory() {
            cqCategoryPendingDeleteId = null;
            cqRenderCategoriesModal();
        }

        function cqConfirmDeleteCategory(catId) {
            if (catId === CQ_DIVERS_CATEGORY_ID) return;
            const categories = cqGetCategories();
            const cat = categories.find(c => c.id === catId);
            if (!cat || cat.isPermanent) return;
            if (categories.length <= 1) return;

            const updated = categories.filter(c => c.id !== catId);
            cqCategoryPendingDeleteId = null;
            cqSaveCategories(updated);
            cqRenderCategoriesModal();
        }

        function cqAssignQuizToCategory(catId) {
            if (catId === CQ_DIVERS_CATEGORY_ID) return;
            const select = document.getElementById(`cqcat-select-${catId}`);
            const errorEl = document.getElementById(`cqcat-error-${catId}`);
            if (!select) return;

            const title = select.value;
            if (errorEl) { errorEl.textContent = ''; errorEl.classList.add('hidden'); }
            if (!title) return;

            const quiz = cqFindQuizByTitle(title);
            if (!quiz) return;

            const categories = cqGetCategories();
            const cat = categories.find(c => c.id === catId);
            if (!cat || cat.isPermanent) return;

            if (!cat.quizTitles.includes(title)) {
                cat.quizTitles.push(title);
                cqSaveCategories(categories);
            }
            cqRenderCategoriesModal();
        }

        function cqUnassignQuizFromCategory(catId, title) {
            if (catId === CQ_DIVERS_CATEGORY_ID) return;
            const categories = cqGetCategories();
            const cat = categories.find(c => c.id === catId);
            if (!cat || cat.isPermanent) return;

            cat.quizTitles = cat.quizTitles.filter(t => t !== title);
            cqSaveCategories(categories);
            cqRenderCategoriesModal();
        }

        // --- Construction d'un quiz jouable à partir d'un jeu admin ---
        function cqAdminSlidesToQuestions(slides) {
            if (!Array.isArray(slides)) return [];
            return slides.map(s => {
                const questionText = typeof s?.questionText === 'string' ? s.questionText : '';
                const answersRaw = Array.isArray(s?.answers) ? s.answers : [];

                const answers = answersRaw.map(a => ({
                    text: typeof a?.text === 'string' ? a.text : '',
                    isCorrect: !!a?.isCorrect,
                    imageData: (typeof a?.imageData === 'string' && a.imageData) ? a.imageData : null,
                    audioData: (typeof a?.audioData === 'string' && a.audioData) ? a.audioData : null
                }));

                const q = {
                    text: questionText,
                    questionImage: (typeof s?.questionImage === 'string' && s.questionImage) ? s.questionImage : null,
                    questionAudio: (typeof s?.questionAudio === 'string' && s.questionAudio) ? s.questionAudio : null,
                    time: s?.gcrTime || 20,  // Utiliser gcrTime si présent
                    answers
                };

                // Préserver les propriétés GeoCoast'R
                if (s?.gcrTarget) q.gcrTarget = s.gcrTarget;
                if (s?.gcrView) q.gcrView = s.gcrView;
                if (s?.gcrMaxDist) q.gcrMaxDist = s.gcrMaxDist;

                return q;
            });
        }

        function cqBuildPlayableQuizFromAdminQuiz(q) {
            const slides = q?.content?.slides;
            const questions = cqAdminSlidesToQuestions(slides);
            if (!questions.length) return null;

            return {
                id: q.title,
                title: q.title || 'Quiz',
                type: q.type || 'QCM',
                difficulty: q.difficulty || 0,
                description: q.description || '',
                questions
            };
        }

        function cqQuizCardHtml(quiz, btnId) {
            const isOnline = quiz.status === 'online';
            const isTemp = quiz.status === 'temp';
            const isClickable = isOnline || isTemp;
            const disabledAttr = isClickable ? '' : 'disabled';
            const disabledClasses = isClickable ? 'hover:bg-[#800000]' : 'opacity-50 cursor-not-allowed';
            const label = isTemp ? 'Fermé temporairement' : 'Jouer';

            return `
                <div class="bg-[var(--inner-grey)] p-4 rounded-xl flex flex-col items-center gap-3 shadow-md">
                    <span class="font-bold text-sm font-title text-center">${escapeHtml(quiz.title)}</span>
                    <button id="${btnId}" type="button"
                        data-title="${escapeHtml(quiz.title)}"
                        onclick="cqOnPublicQuizCardClick(this.dataset.title)"
                        class="bg-[#660000] text-white py-2 rounded-lg font-button text-[10px] px-8 cq-public-quiz-btn ${disabledClasses}"
                        ${disabledAttr}>${escapeHtml(label)}</button>
                </div>
            `;
        }

        function cqOnPublicQuizCardClick(title) {
            const quiz = cqFindQuizByTitle(title);
            if (!quiz) return;

            if (quiz.status === 'online') {
                const playable = cqBuildPlayableQuizFromAdminQuiz(quiz);
                if (!playable) return;

                cqAdminTestMode = false;
                startQuiz(playable);
                return;
            }

            if (quiz.status === 'temp') {
                cqOpenClosedGamePage(quiz.title);
            }
        }

        // Affiche la version "fermée" de la page de jeu dédiée pour un jeu
        // en fermeture temporaire : pas de quiz jouable, juste un message.
        function cqOpenClosedGamePage(title) {
            stopGameTimers();
            cqAdminTestMode = false;

            const titleEl = document.getElementById('game-quiz-title');
            if (titleEl) titleEl.textContent = title || 'Quiz';

            const testBanner = document.getElementById('cq-admin-test-banner');
            if (testBanner) testBanner.classList.add('hidden');

            const prestart = document.getElementById('game-prestart');
            const playArea = document.getElementById('game-play-area');
            const closedState = document.getElementById('game-closed-state');

            if (prestart) prestart.classList.add('hidden');
            if (playArea) { playArea.classList.add('hidden'); playArea.style.display = 'none'; }
            if (closedState) closedState.classList.remove('hidden');

            showView('view-game');
        }

        /* ============================================================
           CQ ADMIN : "Tester mes jeux"
           - Liste tous les jeux (en ligne, hors ligne, fermeture temp.)
           - Permet de les jouer pour les tester, peu importe le statut.
           ============================================================ */

        function cqRenderAdminTestGames() {
            const list = document.getElementById('cq-admin-test-list');
            if (!list) return;

            const quizzes = cqGetQuizzes().slice().sort((a, b) => (a.title || '').trim().toLowerCase().localeCompare((b.title || '').trim().toLowerCase()));

            if (!quizzes.length) {
                list.innerHTML = `<div class="flex items-center justify-center h-full py-12"><p class="text-sm font-button font-medium opacity-40 italic">C'est bien vide ici...</p></div>`;
                return;
            }

            list.innerHTML = quizzes.map(q => {
                const isOnline = q.status === 'online';
                const isTemp = q.status === 'temp';
                const dotClass = cqQuizStatusDotClass(q.status);
                const statusText = cqQuizStatusLabel(q.status);
                const hasContent = Array.isArray(q?.content?.slides) && q.content.slides.length > 0;

                return `
                    <div class="p-4 mb-3 rounded-xl bg-white/5 border border-black/5 relative flex justify-between items-center flex-wrap gap-4">
                        <div class="flex flex-col gap-2">
                            <div class="flex items-center gap-3">
                                <div class="font-bold text-base text-[var(--banner-text)]">${escapeHtml(q.title)}</div>
                                <div class="cq-admin-type-badge">${escapeHtml(q.type || 'QCM')}</div>
                            </div>
                            <div class="flex items-center gap-1.5">
                                <span class="${dotClass}"></span>
                                <span class="cq-admin-online-text text-[9px] font-bold uppercase tracking-wider">${escapeHtml(statusText)}</span>
                            </div>
                        </div>

                        <button type="button" data-title="${escapeHtml(q.title)}" onclick="cqStartAdminTestQuiz(this.dataset.title)"
                            class="bg-[#660000] text-white px-4 py-2 rounded-lg text-xs font-bold uppercase font-button transition hover:bg-[#800000] ${!hasContent ? 'opacity-50 cursor-not-allowed' : ''}"
                            ${!hasContent ? 'disabled' : ''}>
                            Jouer
                        </button>
                    </div>
                `;
            }).join('');
        }

        function cqStartAdminTestQuiz(title) {
            const quiz = cqFindQuizByTitle(title);
            if (!quiz) return;

            const playable = cqBuildPlayableQuizFromAdminQuiz(quiz);
            if (!playable) return;

            cqAdminTestMode = true;
            startQuiz(playable);
        }

        function cqExitAdminTest() {
            stopGameTimers();
            cqAdminTestMode = false;
            showView('view-admin-test-games');
        }

        function goBackFromResults() {
            const _doBack = () => {
                if (cqAdminTestMode) {
                    cqAdminTestMode = false;
                    showView('view-admin-test-games');
                } else if (AuthService.getCurrentUser() && !isGuestMode) {
                    showView('view-user-home');
                } else {
                    showView('view-guest-home');
                }
            };
            if (document.fullscreenElement || document.webkitFullscreenElement) {
                const exit = document.exitFullscreen ? document.exitFullscreen() : document.webkitExitFullscreen ? document.webkitExitFullscreen() : Promise.resolve();
                (exit || Promise.resolve()).then(_doBack).catch(_doBack);
            } else {
                _doBack();
            }
        }

        function cqRenderPublicCategories() {
            const container = document.getElementById('cq-all-games-categories-list');
            if (!container) return;

            const categories = cqGetCategoriesForDisplay();
            const quizzes = cqGetQuizzes();

            const html = categories.map((cat, catIdx) => {
                const cards = cat.quizTitles
                    .map(title => quizzes.find(q => q.title === title))
                    .filter(quiz => quiz && (quiz.status === 'online' || quiz.status === 'temp'))
                    .map((quiz, idx) => cqQuizCardHtml(quiz, `cq-cat-${catIdx}-quiz-${idx}`))
                    .join('');

                return `
                    <div class="bg-[var(--pastel-yellow)] p-6 rounded-2xl border border-black/5 flex flex-col gap-4">
                        <h3 class="font-black font-title text-sm uppercase text-[var(--cat-title-color)]">${escapeHtml(cat.name)}</h3>
                        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                            ${cards || '<p class="text-xs opacity-50 italic font-button">Aucun jeu disponible dans cette catégorie pour le moment.</p>'}
                        </div>
                    </div>
                `;
            }).join('');

            container.innerHTML = html || '<p class="text-sm opacity-50 italic font-button text-center py-8">Aucune catégorie pour le moment.</p>';
        }

        function cqRenderFeaturedBannerInto(containerId) {
            const container = document.getElementById(containerId);
            if (!container) return;

            const categories = cqGetCategoriesForDisplay();
            const quizzes = cqGetQuizzes();

            const seen = new Set();
            const featured = [];
            categories.forEach(cat => {
                cat.quizTitles.forEach(title => {
                    if (seen.has(title)) return;
                    const quiz = quizzes.find(q => q.title === title && q.status === 'online');
                    if (!quiz) return;
                    seen.add(title);
                    featured.push(quiz);
                });
            });

            if (!featured.length) {
                container.innerHTML = '<p class="text-sm opacity-60 italic font-button text-center py-8 col-span-full">Aucun jeu à la une pour le moment.</p>';
                return;
            }

            container.innerHTML = featured
                .slice(0, 6)
                .map((quiz, idx) => cqQuizCardHtml(quiz, `${containerId}-quiz-${idx}`))
                .join('');
        }

        function cqRenderFeaturedBanner() {
            cqRenderFeaturedBannerInto('featured-quizzes-grid');
            cqRenderLeaderboard('leaderboard-guest');
        }

        /* ============================================================
           CQ FAVORIS (session connectée uniquement)
           - Jusqu'à 3 jeux favoris par utilisateur, parmi les jeux
             en ligne ou en fermeture temporaire.
           ============================================================ */

        const CQ_MAX_FAVORITES = 3;

        function cqFavoritesStorageKey() {
            const user = AuthService.getCurrentUser();
            if (!user) return null;
            return `cq_favorites_${user.id}`;
        }

        function cqGetFavorites() {
            const key = cqFavoritesStorageKey();
            if (!key) return [];
            try {
                const stored = localStorage.getItem(key);
                const parsed = stored ? JSON.parse(stored) : [];
                return Array.isArray(parsed) ? parsed.slice(0, CQ_MAX_FAVORITES) : [];
            } catch (e) {
                return [];
            }
        }

        function cqSaveFavorites(titles) {
            const key = cqFavoritesStorageKey();
            if (!key) return;
            localStorage.setItem(key, JSON.stringify(titles.slice(0, CQ_MAX_FAVORITES)));
        }

        let cqFavoritesDraftSelection = [];

        function cqComputeLeaderboard() {
            // Read all users
            let users = [];
            try { users = JSON.parse(localStorage.getItem('cq_users') || '[]'); } catch(e) {}
            // Read all scores: { [userId]: { [quizId]: [score1, score2, ...] } }
            let allScores = {};
            try { allScores = JSON.parse(localStorage.getItem('cq_best_scores_v1') || '{}'); } catch(e) {}

            // Compute total score per user (sum of best score per quiz)
            const ranked = users.map(u => {
                const userScores = allScores[u.id] || {};
                const total = Object.values(userScores).reduce((sum, arr) => {
                    if (!Array.isArray(arr) || arr.length === 0) return sum;
                    return sum + Math.max(...arr);
                }, 0);
                return { id: u.id, pseudo: u.pseudo, total };
            });

            // Sort descending by total
            ranked.sort((a, b) => b.total - a.total);
            return ranked.slice(0, 3);
        }

        function cqLeaderboardRowHtml(player, rank, isPlaceholder) {
            const rankClasses = ['rank-gold', 'rank-silver', 'rank-bronze'];
            const rankClass = rankClasses[rank] || 'rank-bronze';
            if (isPlaceholder) {
                return `<div class="leaderboard-row">
                    <span class="rank-badge ${rankClass}">${rank + 1}</span>
                    <span class="leaderboard-chip leaderboard-chip-score" style="opacity:0.4;">-</span>
                    <span class="leaderboard-chip leaderboard-chip-name" style="opacity:0.4;">???</span>
                </div>`;
            }
            const miniAvatar = buildMiniAvatarHtml(player.pseudo);
            return `<div class="leaderboard-row">
                <span class="rank-badge ${rankClass}">${rank + 1}</span>
                <span class="leaderboard-chip leaderboard-chip-score">${player.total.toLocaleString('fr-FR')}</span>
                ${miniAvatar}
                <span class="leaderboard-chip leaderboard-chip-name" style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${clickablePseudoHtml(player.pseudo)}</span>
            </div>`;
        }

        function cqRenderLeaderboard(containerId) {
            const container = document.getElementById(containerId);
            if (!container) return;
            const top3 = cqComputeLeaderboard();
            let html = '';
            for (let i = 0; i < 3; i++) {
                if (i > 0) html += '<div class="leaderboard-divider"></div>';
                if (i < top3.length) {
                    html += cqLeaderboardRowHtml(top3[i], i, false);
                } else {
                    html += cqLeaderboardRowHtml(null, i, true);
                }
            }
            container.innerHTML = html;
        }

        function cqInitUserHome() {
            const user = AuthService.getCurrentUser();
            const pseudoEl = document.getElementById('user-home-pseudo');
            if (pseudoEl) pseudoEl.textContent = user?.pseudo || '-';

            cqRenderFeaturedBannerInto('user-featured-quizzes-grid');
            cqRenderUserFavorites();
            cqRenderLeaderboard('leaderboard-user');
        }

        function cqEligibleFavoriteQuizzes() {
            return cqGetQuizzes().filter(q => q.status === 'online' || q.status === 'temp');
        }

        function cqRenderUserFavorites() {
            const container = document.getElementById('user-favorites-grid');
            if (!container) return;

            const favTitles = cqGetFavorites();
            const quizzes = cqGetQuizzes();
            const favQuizzes = favTitles
                .map(title => quizzes.find(q => q.title === title))
                .filter(quiz => quiz && (quiz.status === 'online' || quiz.status === 'temp'));

            if (!favQuizzes.length) {
                container.innerHTML = `
                    <div class="flex flex-col items-center justify-center gap-2 flex-1 py-6">
                        <p style="color:#000;font-size:11px;font-weight:500;">Aucun favori pour le moment.</p>
                    </div>
                `;
                return;
            }

            container.innerHTML = favQuizzes
                .map((quiz, idx) => cqQuizCardHtml(quiz, `cq-favorite-quiz-${idx}`))
                .join('');
        }

        function cqOpenFavoritesModal() {
            const user = AuthService.getCurrentUser();
            if (!user) return;

            cqFavoritesDraftSelection = cqGetFavorites();
            cqRenderFavoritesModal();

            const modal = document.getElementById('modal-cq-favorites');
            if (modal) { playSound('modal-open'); modal.classList.remove('hidden'); }
            const mainContent = document.getElementById('main-content');
            if (mainContent) mainContent.classList.add('blur-bg');
        }

        function cqCloseFavoritesModal() {
            playSound('modal-close');
            const modal = document.getElementById('modal-cq-favorites');
            if (modal) modal.classList.add('hidden');
            const mainContent = document.getElementById('main-content');
            if (mainContent) mainContent.classList.remove('blur-bg');
        }

        function cqRenderFavoritesModal() {
            const list = document.getElementById('cq-favorites-modal-list');
            if (!list) return;

            const quizzes = cqEligibleFavoriteQuizzes()
                .slice()
                .sort((a, b) => (a.title || '').trim().toLowerCase().localeCompare((b.title || '').trim().toLowerCase()));

            const countEl = document.getElementById('cq-favorites-modal-count');
            if (countEl) countEl.textContent = `${cqFavoritesDraftSelection.length}/${CQ_MAX_FAVORITES}`;

            if (!quizzes.length) {
                list.innerHTML = `<p class="cqcat-empty-hint">Aucun jeu disponible pour le moment.</p>`;
                return;
            }

            list.innerHTML = quizzes.map(q => {
                const isChecked = cqFavoritesDraftSelection.includes(q.title);
                const isMaxedOut = !isChecked && cqFavoritesDraftSelection.length >= CQ_MAX_FAVORITES;
                return `
                    <label class="cqcat-quiz-chip cq-favorite-pick-row ${isMaxedOut ? 'cqcat-disabled' : ''}" style="cursor:pointer; justify-content:flex-start;">
                        <input type="checkbox" data-title="${escapeHtml(q.title)}"
                            onchange="cqToggleFavoriteDraftSelection(this.dataset.title, this.checked)"
                            ${isChecked ? 'checked' : ''} ${isMaxedOut ? 'disabled' : ''} />
                        <span class="${cqQuizStatusDotClass(q.status)}"></span>
                        <span class="cqcat-quiz-chip-name">${escapeHtml(q.title)}</span>
                    </label>
                `;
            }).join('');
        }

        function cqToggleFavoriteDraftSelection(title, checked) {
            if (checked) {
                if (!cqFavoritesDraftSelection.includes(title) && cqFavoritesDraftSelection.length < CQ_MAX_FAVORITES) {
                    cqFavoritesDraftSelection.push(title);
                }
            } else {
                cqFavoritesDraftSelection = cqFavoritesDraftSelection.filter(t => t !== title);
            }
            cqRenderFavoritesModal();
        }

        function cqConfirmFavoritesSelection() {
            cqSaveFavorites(cqFavoritesDraftSelection);
            cqRenderUserFavorites();
            cqCloseFavoritesModal();
        }

        function showPreGameScreen(quiz) {
            document.getElementById('game-prestart').classList.remove('hidden');
            const closedState = document.getElementById('game-closed-state');
            if (closedState) closedState.classList.add('hidden');
            const playArea = document.getElementById('game-play-area');
            playArea.classList.add('hidden');
            playArea.style.display = 'none';
            document.getElementById('game-answers-grid').innerHTML = '';
            document.getElementById('game-timer-fill').style.height = '100%';

            // Titre stylisé dans la carte
            const cardTitleEl = document.getElementById('game-prestart-card-title');
            if (cardTitleEl && quiz) cardTitleEl.textContent = quiz.title || '';

            // Parties jouées (uniquement mode En Ligne, pas admin test)
            const playsEl = document.getElementById('game-prestart-plays');
            if (playsEl && quiz && !cqAdminTestMode) {
                const plays = cqGetGamePlays();
                const count = plays[quiz.title] || 0;
                playsEl.textContent = `${count} partie${count !== 1 ? 's' : ''} jouée${count !== 1 ? 's' : ''}`;
            } else if (playsEl) {
                playsEl.textContent = '';
            }

            // Difficulté en étoiles
            const diffEl = document.getElementById('game-prestart-difficulty');
            if (diffEl && quiz) {
                const diff = quiz.difficulty || 0;
                let starsHtml = '';
                for (let i = 1; i <= 5; i++) {
                    starsHtml += `<span class="${i <= diff ? 'star-gold' : 'star-grey'}">★</span>`;
                }
                diffEl.innerHTML = starsHtml;
            }
        }

        function beginQuiz() {
            cqNoTimerMode = false;
            document.getElementById('game-prestart').classList.add('hidden');
            const playArea = document.getElementById('game-play-area');
            playArea.classList.remove('hidden');
            playArea.style.display = 'flex';
            playSound('quiz-start');
            renderQuestion();
        }

        function beginQuizNoTimer() {
            cqNoTimerMode = true;
            document.getElementById('game-prestart').classList.add('hidden');
            const playArea = document.getElementById('game-play-area');
            playArea.classList.remove('hidden');
            playArea.style.display = 'flex';
            // Masquer le timer en mode sans chrono (le score reste visible)
            const timerTrack = document.querySelector('.game-timer-track');
            if (timerTrack) timerTrack.style.display = 'none';
            playSound('quiz-start');
            renderQuestion();
        }

        function updateScoreDisplay() {
            document.getElementById('game-score').textContent = currentGame.score;
        }

        function getCorrectIndex(question) {
            return question.answers.findIndex(a => a.isCorrect);
        }

        function computeQuestionPoints() {
            // Base : 2000 pts toujours (bonne réponse)
            // Bonus vitesse (mode chrono uniquement) : 0 à 3000 pts selon temps restant
            const speedBonus = (currentGame.totalTime > 0)
                ? Math.round(MAX_SPEED_BONUS * (currentGame.timeLeft / currentGame.totalTime))
                : 0;
            return BASE_POINTS + speedBonus;
        }

        function isMultipleAnswerQuestion(question) {
            if (!question || !Array.isArray(question.answers)) return false;
            return question.answers.filter(a => a.isCorrect).length > 1;
        }

        // Global audio player for in-game answer audio
        let _gameCurrentAudio = null;
        function _gameStopCurrentAudio() {
            if (_gameCurrentAudio) {
                try { _gameCurrentAudio.pause(); _gameCurrentAudio.currentTime = 0; } catch(e) {}
                _gameCurrentAudio = null;
            }
        }
        function _gamePlayAnswerAudio(src) {
            _gameStopCurrentAudio();
            if (!src) return;
            _gameCurrentAudio = new Audio(src);
            _gameCurrentAudio.volume = AudioManager.getVolume();
            _gameCurrentAudio.play().catch(() => {});
        }

        function _renderQuestionMedia(question) {
            // Render image + audio above the question text area
            let mediaHtml = '';
            const qImg = question.questionImage;
            const qAudio = question.questionAudio;
            if (qImg) {
                mediaHtml += `<img src="${qImg}" class="game-question-img" alt="Question">`;
            }
            if (qAudio) {
                mediaHtml += `<div class="game-question-audio-wrap"><button type="button" class="game-audio-play-btn" onclick="(function(){var a=new Audio('${qAudio.replace(/'/g,"\\'")}');a.volume=AudioManager.getVolume();a.play().catch(()=>{});})()">▶ Écouter la question</button></div>`;
            }
            const mediaEl = document.getElementById('game-question-media');
            if (mediaEl) mediaEl.innerHTML = mediaHtml;
        }

        function renderQuestion() {
            const question = currentGame.quiz.questions[currentGame.currentQIndex];
            if (!question) {
                finishQuiz();
                return;
            }

            _gameStopCurrentAudio();

            document.getElementById('game-question-num').textContent =
                `${currentGame.currentQIndex + 1}/${currentGame.quiz.questions.length}`;
            document.getElementById('game-question-text').textContent = question.text;

            _renderQuestionMedia(question);

            const isMulti = isMultipleAnswerQuestion(question);
            const grid = document.getElementById('game-answers-grid');

            // Detect if all answers are image-only (no text) → use image grid layout
            const allHaveImg = question.answers.every(a => !!a.imageData);
            const allHaveAudioOnly = question.answers.every(a => !!a.audioData && !a.imageData && !(a.text||'').trim());

            grid.classList.toggle('quiz-images-grid', allHaveImg || allHaveAudioOnly);
            grid.classList.toggle('quiz-audio-grid', allHaveAudioOnly);

            // Build answer card HTML for a single answer (unified QCM)
            function buildAnswerCardContent(answer, index) {
                const hasImg = !!answer.imageData;
                const hasAudio = !!answer.audioData;
                const hasText = !!(answer.text || '').trim();
                const audioBtn = hasAudio
                    ? `<button type="button" class="answer-audio-mini-btn" onclick="event.stopPropagation();_gamePlayAnswerAudio('${answer.audioData.replace(/'/g,"\\'")}')">🔊</button>`
                    : '';

                if (allHaveAudioOnly) {
                    // Pure audio answers: show icon + optional label
                    return `<span class="answer-audio-icon">🔊</span><span class="answer-audio-label">${escapeHtml(answer.text || ('Réponse ' + (index+1)))}</span>`;
                }
                let inner = '';
                if (hasImg) inner += `<img src="${answer.imageData}" class="answer-inline-img" alt="Réponse ${index+1}">`;
                if (hasText) inner += `<span>${escapeHtml(answer.text)}</span>`;
                inner += audioBtn;
                return inner;
            }

            const validateBtn = `<div class="col-span-full flex justify-center mt-2">
                <button type="button" id="multi-validate-btn" onclick="handleMultiValidate()"
                    class="bg-[#660000] text-white px-8 py-3 rounded-xl font-bold font-button text-sm hover:bg-[#800000] transition">
                    Valider
                </button>
            </div>`;

            if (isMulti) {
                const clickExtra = allHaveAudioOnly
                    ? (a, i) => `; _gamePlayAnswerAudio('${(a.audioData||'').replace(/'/g,"\\'")}')`
                    : () => '';
                grid.innerHTML = question.answers.map((answer, index) => {
                    const hasImg = !!answer.imageData;
                    const extraClass = (allHaveImg || allHaveAudioOnly) ? 'answer-img-card' : (hasImg ? 'answer-has-img' : '');
                    return `<button type="button" class="answer-card ${extraClass} answer-multi" data-index="${index}" data-selected="0"
                        onclick="handleMultiAnswerToggle(${index})${clickExtra(answer, index)}">
                        ${buildAnswerCardContent(answer, index)}
                    </button>`;
                }).join('') + validateBtn;
            } else {
                const clickExtra = allHaveAudioOnly
                    ? (a, i) => `; _gamePlayAnswerAudio('${(a.audioData||'').replace(/'/g,"\\'")}')`
                    : () => '';
                grid.innerHTML = question.answers.map((answer, index) => {
                    const hasImg = !!answer.imageData;
                    const extraClass = (allHaveImg || allHaveAudioOnly) ? 'answer-img-card' : (hasImg ? 'answer-has-img' : '');
                    return `<button type="button" class="answer-card ${extraClass}" data-index="${index}"
                        onclick="handleAnswer(${index})${clickExtra(answer, index)}">
                        ${buildAnswerCardContent(answer, index)}
                    </button>`;
                }).join('');
            }

            startQuestionTimer(question.time || 20);
        }

        function handleMultiAnswerToggle(index) {
            if (!currentGame.canAnswer) return;
            const cards = document.querySelectorAll('.answer-multi');
            const card = cards[index];
            if (!card) return;
            const isSelected = card.dataset.selected === '1';
            card.dataset.selected = isSelected ? '0' : '1';
            card.classList.toggle('answer-multi-selected', !isSelected);
            playSound('quiz-select');
        }

        function handleMultiValidate() {
            if (!currentGame.canAnswer) return;
            currentGame.canAnswer = false;
            stopGameTimers();

            const question = currentGame.quiz.questions[currentGame.currentQIndex];
            const cards = document.querySelectorAll('.answer-multi');
            const selectedIndices = [];
            cards.forEach((card, idx) => {
                if (card.dataset.selected === '1') selectedIndices.push(idx);
            });

            const correctIndices = question.answers
                .map((a, i) => a.isCorrect ? i : -1)
                .filter(i => i !== -1);

            const isAllCorrect =
                selectedIndices.length === correctIndices.length &&
                correctIndices.every(i => selectedIndices.includes(i));

            if (isAllCorrect) {
                currentGame.score += cqNoTimerMode ? BASE_POINTS : computeQuestionPoints();
                updateScoreDisplay();
                playSound('quiz-correct');
            } else {
                playSound('quiz-wrong');
            }

            // Révéler : vert = correct, rouge = mauvaise sélection
            cards.forEach((card, idx) => {
                card.classList.add('answer-disabled');
                if (correctIndices.includes(idx)) {
                    card.classList.add('answer-correct');
                } else if (selectedIndices.includes(idx)) {
                    card.classList.add('answer-wrong');
                }
            });

            // Masquer le bouton Valider
            const validateBtn = document.getElementById('multi-validate-btn');
            if (validateBtn) validateBtn.style.display = 'none';

            scheduleNextQuestion();
        }

        function startQuestionTimer(duration) {
            stopGameTimers();
            currentGame.canAnswer = true;

            if (cqNoTimerMode) {
                currentGame.totalTime = 0;
                currentGame.timeLeft = 0;
                return; // Pas de timer
            }

            currentGame.totalTime = duration;
            currentGame.timeLeft = duration;

            const fill = document.getElementById('game-timer-fill');
            fill.style.height = '100%';

            currentGame.timerInterval = setInterval(() => {
                currentGame.timeLeft -= TIMER_TICK_MS / 1000;
                if (currentGame.timeLeft <= 0) {
                    currentGame.timeLeft = 0;
                    fill.style.height = '0%';
                    clearInterval(currentGame.timerInterval);
                    currentGame.timerInterval = null;
                    handleTimeUp();
                    return;
                }
                fill.style.height = `${(currentGame.timeLeft / currentGame.totalTime) * 100}%`;
            }, TIMER_TICK_MS);
        }

        function setAnswersDisabled() {
            document.querySelectorAll('.answer-card').forEach(card => {
                card.classList.add('answer-disabled');
            });
        }

        function revealAnswers(selectedIndex) {
            const question = currentGame.quiz.questions[currentGame.currentQIndex];
            const correctIndex = getCorrectIndex(question);
            const cards = document.querySelectorAll('.answer-card');

            cards.forEach((card, index) => {
                if (index === correctIndex) {
                    card.classList.add('answer-correct');
                } else if (index === selectedIndex) {
                    card.classList.add('answer-wrong');
                }
            });
        }

        function scheduleNextQuestion() {
            currentGame.transitionTimeout = setTimeout(() => {
                currentGame.currentQIndex++;
                renderQuestion();
            }, FEEDBACK_DELAY_MS);
        }

        function handleAnswer(index) {
            if (!currentGame.canAnswer) return;

            currentGame.canAnswer = false;
            _gameStopCurrentAudio();
            stopGameTimers();

            const question = currentGame.quiz.questions[currentGame.currentQIndex];
            const correctIndex = getCorrectIndex(question);
            const isCorrect = index === correctIndex;

            // Son sélection immédiat, puis feedback après révélation
            playSound('quiz-select');

            if (isCorrect) {
                currentGame.score += cqNoTimerMode ? BASE_POINTS : computeQuestionPoints();
                updateScoreDisplay();
                setTimeout(() => playSound('quiz-correct'), 80);
            } else {
                setTimeout(() => playSound('quiz-wrong'), 80);
            }

            setAnswersDisabled();
            revealAnswers(index);
            scheduleNextQuestion();
        }

        function handleTimeUp() {
            if (!currentGame.canAnswer) return;

            currentGame.canAnswer = false;
            _gameStopCurrentAudio();
            playSound('quiz-timeout');
            setAnswersDisabled();
            revealAnswers(-1);
            scheduleNextQuestion();
        }

        function finishQuiz() {
            stopGameTimers();
            playSound('quiz-finish');
            // Restaurer le timer et le score si masqués
            const scoreEl = document.getElementById('game-score');
            if (scoreEl) scoreEl.style.display = '';
            const timerTrack = document.querySelector('.game-timer-track');
            if (timerTrack) timerTrack.style.display = '';

            document.getElementById('results-final-score').textContent = currentGame.score;
            if (!cqAdminTestMode && currentGame.quiz && currentGame.quiz.id) {
                if (!isGuestMode) {
                    cqRecordGamePlay(currentGame.quiz.title);
                    cqSaveBestScore(currentGame.quiz.id, currentGame.score);
                }
                cqRenderQuizLeaderboard(currentGame.quiz.id);
                cqRenderResultsLeaderboard(currentGame.quiz.id);
            }

            // Remplir la carte visuelle dans la page résultats
            const quiz = currentGame.quiz;
            if (quiz) {
                const cardTitleEl = document.getElementById('results-game-card-title');
                if (cardTitleEl) cardTitleEl.textContent = quiz.title || '';

                const playsEl = document.getElementById('results-game-plays');
                if (playsEl && !cqAdminTestMode) {
                    const plays = cqGetGamePlays();
                    const count = plays[quiz.title] || 0;
                    playsEl.textContent = `${count} partie${count !== 1 ? 's' : ''} jouée${count !== 1 ? 's' : ''}`;
                } else if (playsEl) { playsEl.textContent = ''; }

                const diffEl = document.getElementById('results-game-difficulty');
                if (diffEl) {
                    const diff = quiz.difficulty || 0;
                    let starsHtml = '';
                    for (let i = 1; i <= 5; i++) {
                        starsHtml += `<span class="${i <= diff ? 'star-gold' : 'star-grey'}">★</span>`;
                    }
                    diffEl.innerHTML = starsHtml;
                }
            }

            // Bouton favori dans résultats (session connectée uniquement)
            cqUpdateFavoriteButtonState('results');

            // Si on était en plein écran sur la game-card, transférer sur results-card
            const wasFullscreen = !!(document.fullscreenElement || document.webkitFullscreenElement);
            if (wasFullscreen) {
                const exitFs = document.exitFullscreen ? document.exitFullscreen() : document.webkitExitFullscreen ? Promise.resolve(document.webkitExitFullscreen()) : Promise.resolve();
                exitFs.then(() => {
                    showView('view-results');
                    setTimeout(() => playSound('quiz-result'), 300);
                    const resultsCard = document.getElementById('results-game-card-wrap');
                    if (resultsCard) {
                        const req = resultsCard.requestFullscreen ? resultsCard.requestFullscreen() : resultsCard.webkitRequestFullscreen ? resultsCard.webkitRequestFullscreen() : null;
                    }
                }).catch(() => showView('view-results'));
            } else {
                showView('view-results');
                setTimeout(() => playSound('quiz-result'), 300);
            }
        }

        function toggleResultsFullscreen() {
            const card = document.getElementById('results-game-card-wrap');
            if (!card) return;
            if (!document.fullscreenElement && !document.webkitFullscreenElement) {
                card.requestFullscreen ? card.requestFullscreen() : card.webkitRequestFullscreen && card.webkitRequestFullscreen();
            } else {
                document.exitFullscreen ? document.exitFullscreen() : document.webkitExitFullscreen && document.webkitExitFullscreen();
            }
        }

        function _updateResultsFullscreenIcon() {
            const enter = document.getElementById('icon-fs-results-enter');
            const exit = document.getElementById('icon-fs-results-exit');
            if (!enter || !exit) return;
            const isFs = !!(document.fullscreenElement === document.getElementById('results-game-card-wrap') || document.webkitFullscreenElement === document.getElementById('results-game-card-wrap'));
            enter.style.display = isFs ? 'none' : '';
            exit.style.display = isFs ? '' : 'none';

        }

        document.addEventListener('fullscreenchange', _updateResultsFullscreenIcon);
        document.addEventListener('webkitfullscreenchange', _updateResultsFullscreenIcon);

        function replayCurrentQuiz() {
            if (!currentGame.quiz) return;
            playSound('quiz-replay');
            // Détecter si on est en plein écran sur la carte résultats
            const wasInResultsFullscreen = !!(
                document.fullscreenElement === document.getElementById('results-game-card-wrap') ||
                document.webkitFullscreenElement === document.getElementById('results-game-card-wrap')
            );
            if (wasInResultsFullscreen) {
                // Quitter le plein écran résultats, puis relancer et ré-entrer en plein écran jeu
                const exitFs = document.exitFullscreen
                    ? document.exitFullscreen()
                    : document.webkitExitFullscreen
                        ? Promise.resolve(document.webkitExitFullscreen())
                        : Promise.resolve();
                exitFs.then(() => {
                    startQuiz(currentGame.quiz, cqNoTimerMode);
                    // Après démarrage du quiz, entrer en plein écran sur la game-card
                    setTimeout(() => {
                        const card = document.getElementById('game-card-main');
                        if (card) {
                            card.requestFullscreen
                                ? card.requestFullscreen()
                                : card.webkitRequestFullscreen && card.webkitRequestFullscreen();
                        }
                    }, 80);
                }).catch(() => startQuiz(currentGame.quiz, cqNoTimerMode));
            } else {
                startQuiz(currentGame.quiz, cqNoTimerMode);
            }
        }

        // Met à jour l'état visuel du bouton favori (page jeu ou résultats)
        function cqUpdateFavoriteButtonState(context) {
            const user = AuthService.getCurrentUser();
            const quiz = currentGame.quiz;
            const isGuest = isGuestMode || !user;

            // Page jeu
            const gameWrap = document.getElementById('game-favorite-btn-wrap');
            // Page résultats
            const resultsWrap = document.getElementById('results-favorite-btn-wrap');

            if (isGuest || !quiz) {
                if (gameWrap) gameWrap.classList.add('hidden');
                if (resultsWrap) resultsWrap.classList.add('hidden');
                return;
            }

            const favTitles = cqGetFavorites();
            const isFav = favTitles.includes(quiz.title);

            // Icon/label helpers
            function applyFavState(iconId, labelId) {
                const icon = document.getElementById(iconId);
                const label = document.getElementById(labelId);
                if (icon) icon.setAttribute('fill', isFav ? '#7c3aed' : 'gray');
                if (label) label.textContent = isFav ? 'Favori' : 'Ajouter aux favoris';
            }

            if (context === 'game' || context === 'both') {
                if (gameWrap) gameWrap.classList.remove('hidden');
                applyFavState('game-favorite-icon', 'game-favorite-label');
            }
            if (context === 'results' || context === 'both') {
                if (resultsWrap) resultsWrap.classList.remove('hidden');
                applyFavState('results-favorite-icon', 'results-favorite-label');
            }
        }

        // Appelé depuis bouton favori page jeu OU résultats
        function cqToggleFavoriteFromGamePage() {
            const user = AuthService.getCurrentUser();
            const quiz = currentGame.quiz;
            if (!user || !quiz) return;

            const favTitles = cqGetFavorites();
            const isFav = favTitles.includes(quiz.title);

            if (isFav) {
                // Retirer des favoris
                cqSaveFavorites(favTitles.filter(t => t !== quiz.title));
                cqUpdateFavoriteButtonState('both');
                if (typeof cqRenderUserFavorites === 'function') cqRenderUserFavorites();
                return;
            }

            if (favTitles.length < CQ_MAX_FAVORITES) {
                // Ajouter directement
                favTitles.push(quiz.title);
                cqSaveFavorites(favTitles);
                cqUpdateFavoriteButtonState('both');
                if (typeof cqRenderUserFavorites === 'function') cqRenderUserFavorites();
            } else {
                // 3 favoris déjà remplis : ouvrir modale de remplacement
                cqOpenFavoritesGamePageModal();
            }
        }

        let cqFavoritesGamePageDraftSelection = [];

        function cqOpenFavoritesGamePageModal() {
            const user = AuthService.getCurrentUser();
            if (!user) return;
            cqFavoritesGamePageDraftSelection = cqGetFavorites().slice();
            cqRenderFavoritesGamePageModal();
            const modal = document.getElementById('modal-cq-favorites-gamepage');
            if (modal) { playSound('modal-open'); modal.classList.remove('hidden'); }
            const mainContent = document.getElementById('main-content');
            if (mainContent) mainContent.classList.add('blur-bg');
        }

        function cqCloseFavoritesGamePageModal() {
            playSound('modal-close');
            const modal = document.getElementById('modal-cq-favorites-gamepage');
            if (modal) modal.classList.add('hidden');
            const mainContent = document.getElementById('main-content');
            if (mainContent) mainContent.classList.remove('blur-bg');
        }

        function cqRenderFavoritesGamePageModal() {
            const list = document.getElementById('cq-favorites-gamepage-modal-list');
            if (!list) return;

            const quizzes = cqEligibleFavoriteQuizzes()
                .slice()
                .sort((a, b) => (a.title || '').toLowerCase().localeCompare((b.title || '').toLowerCase()));

            const countEl = document.getElementById('cq-favorites-gamepage-modal-count');
            if (countEl) countEl.textContent = `${cqFavoritesGamePageDraftSelection.length}/${CQ_MAX_FAVORITES}`;

            if (!quizzes.length) {
                list.innerHTML = `<p class="cqcat-empty-hint">Aucun jeu disponible.</p>`;
                return;
            }

            list.innerHTML = quizzes.map(q => {
                const isChecked = cqFavoritesGamePageDraftSelection.includes(q.title);
                const isMaxedOut = !isChecked && cqFavoritesGamePageDraftSelection.length >= CQ_MAX_FAVORITES;
                return `
                    <label class="cqcat-quiz-chip cq-favorite-pick-row ${isMaxedOut ? 'cqcat-disabled' : ''}" style="cursor:pointer; justify-content:flex-start;">
                        <input type="checkbox" data-title="${escapeHtml(q.title)}"
                            onchange="cqToggleFavGPDraft(this.dataset.title, this.checked)"
                            ${isChecked ? 'checked' : ''} ${isMaxedOut ? 'disabled' : ''} />
                        <span class="${cqQuizStatusDotClass(q.status)}"></span>
                        <span class="cqcat-quiz-chip-name">${escapeHtml(q.title)}</span>
                    </label>
                `;
            }).join('');
        }

        function cqToggleFavGPDraft(title, checked) {
            if (checked) {
                if (!cqFavoritesGamePageDraftSelection.includes(title) && cqFavoritesGamePageDraftSelection.length < CQ_MAX_FAVORITES) {
                    cqFavoritesGamePageDraftSelection.push(title);
                }
            } else {
                cqFavoritesGamePageDraftSelection = cqFavoritesGamePageDraftSelection.filter(t => t !== title);
            }
            cqRenderFavoritesGamePageModal();
        }

        function cqConfirmFavoritesGamePageSelection() {
            cqSaveFavorites(cqFavoritesGamePageDraftSelection);
            cqCloseFavoritesGamePageModal();
            cqUpdateFavoriteButtonState('both');
            if (typeof cqRenderUserFavorites === 'function') cqRenderUserFavorites();
        }

        function openSettings() {
            playSound('modal-open');
            document.getElementById('modal-settings-landing').classList.add('hidden');
            document.getElementById('modal-settings-guest').classList.add('hidden');
            document.getElementById('modal-settings-user').classList.add('hidden');
            document.getElementById('modal-settings-admin').classList.add('hidden');

            // En mode invité, toujours afficher la modale invité indépendamment de l'état de connexion en arrière-plan
            if (isGuestMode) {
                document.getElementById('modal-settings-guest').classList.remove('hidden');
            } else if (AuthService.getCurrentUser()) {
                document.getElementById('modal-settings-user').classList.remove('hidden');
            } else {
                document.getElementById('modal-settings-guest').classList.remove('hidden');
            }
            document.getElementById('main-content').classList.add('blur-bg');
        }

        function openAdminSettings() {
            playSound('modal-open');
            document.getElementById('modal-settings-admin').classList.remove('hidden');
            document.getElementById('main-content').classList.add('blur-bg');
        }

        function closeAdminSettings() {
            playSound('modal-close');
            document.getElementById('modal-settings-admin').classList.add('hidden');
            document.getElementById('main-content').classList.remove('blur-bg');
        }

        const CQ_PREFS_KEY = 'cq_prefs';

        function cqLoadVolumePrefs() {
            try {
                const raw = localStorage.getItem(CQ_PREFS_KEY);
                if (!raw) return 80; // valeur par défaut
                const prefs = JSON.parse(raw);
                return (typeof prefs.volume === 'number') ? Math.round(prefs.volume * 100) : 80;
            } catch (_) { return 80; }
        }

        function cqSaveVolumePrefs(sliderValue) {
            try {
                const existing = JSON.parse(localStorage.getItem(CQ_PREFS_KEY) || '{}');
                existing.volume = parseInt(sliderValue, 10) / 100;
                localStorage.setItem(CQ_PREFS_KEY, JSON.stringify(existing));
            } catch (_) {}
        }

        function synchronizeVolumeSliders() {
            const sliders = Array.from(document.querySelectorAll('.volume-slider'));
            if (!sliders.length) return;

            // Restaurer la valeur persistée
            const savedValue = cqLoadVolumePrefs();
            sliders.forEach(s => { s.value = savedValue; });

            // Synchroniser AudioManager si disponible
            if (typeof AudioManager !== 'undefined') {
                AudioManager.setVolume(savedValue / 100);
            }

            const syncValue = (source) => {
                sliders.forEach((slider) => {
                    if (slider !== source) slider.value = source.value;
                });
                cqSaveVolumePrefs(source.value);
                if (typeof AudioManager !== 'undefined') {
                    AudioManager.setVolume(parseInt(source.value, 10) / 100);
                }
            };

            sliders.forEach((slider) => {
                slider.addEventListener('input', () => syncValue(slider));
            });
        }

        document.addEventListener('DOMContentLoaded', synchronizeVolumeSliders);
        document.addEventListener('DOMContentLoaded', () => {
            if (typeof updateNotifBadges === 'function') updateNotifBadges();
        });

        function openLandingSettings() {
            playSound('modal-open');
            document.getElementById('modal-settings-guest').classList.add('hidden');
            document.getElementById('modal-settings-user').classList.add('hidden');
            document.getElementById('modal-settings-landing').classList.remove('hidden');
            document.getElementById('main-content').classList.add('blur-bg');
        }

        function closeSettings() {
            playSound('modal-close');
            closeAdminAccess();
            closeDeleteAccountConfirm();
            closeAdminSettings();
            document.getElementById('modal-settings-guest').classList.add('hidden');
            document.getElementById('modal-settings-landing').classList.add('hidden');
            document.getElementById('modal-settings-user').classList.add('hidden');
            document.getElementById('modal-settings-admin').classList.add('hidden');
            document.getElementById('main-content').classList.remove('blur-bg');
        }

        function openDeleteAccountConfirm() {
            playSound('modal-open');
            document.getElementById('modal-delete-account').classList.remove('hidden');
        }

        function closeDeleteAccountConfirm() {
            document.getElementById('modal-delete-account').classList.add('hidden');
        }

        function logoutUser() {
            // Logout and clear persistent session
            AuthService.logout();
            localStorage.removeItem('coasterquiz_persistent_session');
            closeSettings();
            showView('view-landing');
            updateHeaderAuthState();
        }

        async function confirmDeleteAccount() {
            const user = AuthService.getCurrentUser();
            if (!user) return;

            playSound('action-delete');
            await AuthService.deleteAccount(user.id);
            localStorage.removeItem('coasterquiz_persistent_session');
            closeSettings();
            showView('view-landing');
            // Update header after account deletion / logout
            updateHeaderAuthState();
        }

        /* --- FONCTIONS PROFIL --- */
        function loadProfileData() {
            const user = AuthService.getCurrentUser();
            if (!user) return;

            document.getElementById('profile-pseudo').textContent = user.pseudo;

            // Récupérer le mot de passe depuis la session persistante
            const profilePassInput = document.getElementById('profile-password');
            let realPassword = '';
            try {
                const persistentSession = localStorage.getItem('coasterquiz_persistent_session');
                if (persistentSession) {
                    const parsed = JSON.parse(persistentSession);
                    realPassword = parsed.password || '';
                }
            } catch(e) {}
            if (profilePassInput) {
                profilePassInput.value = realPassword || '••••••••';
                profilePassInput.type = 'password';
            }
            profilePasswordVisible = false;

            // Calculer et afficher le Score Total (somme des meilleurs scores par quiz)
            const totalScoreEl = document.getElementById('profile-total-score-value');
            if (totalScoreEl) {
                const user = AuthService.getCurrentUser();
                let total = 0;
                if (user) {
                    const all = cqGetAllBestScores();
                    const userScores = all[user.id] || {};
                    for (const quizId in userScores) {
                        const scores = userScores[quizId];
                        if (Array.isArray(scores) && scores.length > 0) {
                            total += Math.max(...scores);
                        }
                    }
                }
                totalScoreEl.textContent = total;
            }

            // Charger l'avatar
            renderProfileAvatar(user);
            loadProfileExtras();
        }

        /* --- PROFIL : MES INFOS --- */
        function getProfileExtras(userId) {
            try {
                return JSON.parse(localStorage.getItem('cq_profile_extras_' + userId) || '{}');
            } catch(e) { return {}; }
        }
        function saveProfileExtras(userId, data) {
            localStorage.setItem('cq_profile_extras_' + userId, JSON.stringify(data));
        }
        function loadProfileExtras() {
            const user = AuthService.getCurrentUser();
            if (!user) return;
            const extras = getProfileExtras(user.id);
            const descEl = document.getElementById('profile-description');
            if (descEl) {
                descEl.value = extras.description || '';
                document.getElementById('profile-desc-count').textContent = (extras.description || '').length;
            }
            const modelEl = document.getElementById('profile-fav-model');
            if (modelEl) modelEl.value = extras.favModel || '';
            const mfEl = document.getElementById('profile-fav-manufacturer');
            if (mfEl) mfEl.value = extras.favManufacturer || '';
            const ttEl = document.getElementById('profile-fav-traintype');
            if (ttEl) ttEl.value = extras.favTrainType || '';
            const coasterInput = document.getElementById('profile-fav-coaster-input');
            if (coasterInput) {
                coasterInput.value = extras.favCoaster || '';
                const clearBtn = document.getElementById('profile-fav-coaster-clear');
                if (clearBtn) clearBtn.style.display = extras.favCoaster ? 'block' : 'none';
            }
        }
        function saveProfileDescription() {
            const user = AuthService.getCurrentUser();
            if (!user) return;
            const descEl = document.getElementById('profile-description');
            const val = descEl ? descEl.value : '';
            const extras = getProfileExtras(user.id);
            extras.description = val;
            saveProfileExtras(user.id, extras);
            const savedEl = document.getElementById('profile-desc-saved');
            if (savedEl) {
                savedEl.classList.remove('hidden');
                setTimeout(() => savedEl.classList.add('hidden'), 2500);
            }
        }
        function saveProfilePreference(key, value) {
            const user = AuthService.getCurrentUser();
            if (!user) return;
            const extras = getProfileExtras(user.id);
            extras[key] = value;
            saveProfileExtras(user.id, extras);
        }

        // --- Coaster préféré : base de données & autocomplete ---
        const COASTERS_DB = ["10 Inversion Roller Coaster","Abismo","Abyssus","Acorn Adventure","Acrobat","Adventure Express","Afterburn","Aftershock","All American Triple Loop","Alpenexpress Enzian","Alpengeist","Alpina Blitz","Alpine Bobsled","Alpine Coaster","Altair","American Eagle","American Thunder","Anaconda","Anubis The Ride","Apocalypse","Apollo's Chariot","Apple Zapple","Aquaman: Power Wave","Arashi","ArieForce One","Arkansas Twister","Arthur","Atlantis Adventure","Autoberg","Avalanche","Avatar Airbender","Avengers Assemble: Flight Force","Aztec","Baby Coaster","Back at the Barnyard Hayride","Backlot Stunt Coaster (Canada's Wonderland)","Backlot Stunt Coaster (Kings Dominion)","Backlot Stunt Coaster (Kings Island)","Balder","Bandit (Movie Park Germany)","Bandit (Yomiuriland)","Banshee","Barnstormer","Baron 1898","Bat-Hatari","Batman: Gotham City Escape","Batman The Ride (Six Flags Discovery Kingdom)","Batman The Ride (Six Flags Fiesta Texas)","Batman The Ride (Six Flags Great Adventure)","Batman The Ride (Six Flags Great America)","Batman The Ride (Six Flags Magic Mountain)","Batman The Ride (Six Flags Mexico)","Batman The Ride (Six Flags Over Georgia)","Batman The Ride (Six Flags Over Texas)","Batman The Ride (Six Flags St. Louis)","Battlestar Galactica (Cylon)","Battlestar Galactica (Human)","Batwing","Behemoth","Berg- og dalbane","Big Bad Wolf","Big Bear Mountain","Big Bend","Big Dipper (Blackpool Pleasure Beach)","Big Dipper (Geauga Lake)","Big Grizzly Mountain Runaway Mine Cars","Big Loop","Big Thunder Mountain (Disneyland Paris)","Big Thunder Mountain Railroad (Disneyland)","Big Thunder Mountain Railroad (Magic Kingdom)","Black Hole Coaster","Black Mamba","Blue Fire Megacoaster","Blue Streak","Blue Tornado","Boardwalk Bullet","Bobbaan","Booster Bike","Boulder Dash","Bumeran","Cagliostro","Calamity Mine","Camelback Coaster","Candymonium","Cannibal","Cannon Ball","Canobie Corkscrew","Canopy Flyer","Canyon Blaster","Capitol Bullet Train","Casey Jr. - Le Petit Train du Cirque","Cataratas","Catwoman Whip","Cedar Creek Mine Ride","Cheetah Hunt","Choco Chip Creek","Ciclón","Cliff Hanger","Cliffhanger","Coaster","Coaster Through the Clouds","Coaster-Express","Cobra (Conny-Land)","Cobra (Paultons Park)","Cobra's Curse","Colossos - Kampf der Giganten","Colossus","Colossus the Fire Dragon","Colorado Adventure","Comet (Great Escape)","Comet (Hersheypark)","Comet (Waldameer)","Condor","Copperhead Strike","Corkscrew (Cedar Point)","Corkscrew (Nagashima Spa Land)","Cornball Express","Correcaminos Bip Bip","Cosmic Coaster","Crazy Bats","Crazy Mouse","Crossbow","Crush's Coaster","Crystal Wing","Cú Chulainn Coaster","Cumbre","Daidarasaurus","Dark Knight","DarKoaster","Dauling Dragon","DC Rivals Hypercoaster","Decepticoaster","Defiance","Deja Vu","Der Schwur des Kärnan","Desafío","Desert Race","Desert Storm","Desmo Race","Desperado","Devil's Loop","Diamondback","Diavlo","Dino Dash","Dino Valley","Dinoconda","Disaster Transport","Dive Coaster","Divertical","Diving Coaster","Do-Dodonpa","Dominator","Doo Wopper","Dr. Diabolical's Cliffhanger","Drachen Fire","DrageKongen","Dragão","Dragon (Fårup Sommerland)","Dragon (Plopsaland De Panne)","Dragon Challenge (Chinese Fireball)","Dragon Challenge (Hungarian Horntail)","Dragon Coaster","Dragon Gliders","Dragon in Clouds","Dragon Khan","Dragon Mountain","Dragon Roller Coaster","Dragon Slayer","Dragon's Cave","Dragon's Run","Draken (Energylandia)","Draken (Fårup Sommerland)","Dream Catcher","Dream Hunters Society","Dum-Dum","Dwervelwind","Dynamite","Dynamite Express","Dæmonen","Eagle Coaster","Eejanaika","El Diablo - Tren de la Mina","El Toro","El Vigía","Eldorado","Emperor","Enchanted Airways","Energuś Roller Coaster","Euro-Mir","Eurosat - CanCan Coaster","Excalibur","Expedition Everest","Expedition GeForce","Exterminator","Extreme Rusher","F.L.Y.","Fahrenheit","Falcon (Duinrell)","Falcon (Nagashima Spa Land)","Falcon (Wanda Theme Park)","Falcon's Flight (Six Flags Qiddiya)","Falken","Family Coaster","Fairly Odd Coaster","Farmyard Flyer","Fast & Furious","Feng Shen Coaster","Fiorano GT Challenge","Fire in the Hole","Fire Mountain","Firebird","Fireball","FireWhip","Flashback","Flight Deck","Flight of Fear (Kings Dominion)","Flight of Fear (Kings Island)","Flight of the Hippogriff (Universal Orlando)","Flight of the Hippogriff (Universal Studios Hollywood)","Flight of the Pterosaur","Flounder's Flying Fish Coaster","Flug der Dämonen","Flucht von Novgorod","Fly Over Mediterranean","Flying Aces","Flying Dinosaur","Flying Fish","Flying School Bus","Flying Turns","Flying Viking","Flying Wing Coaster","Formula","Formula Rossa","Formule X","Frankie's Mine Train","Freedom Flyer","Frida","Fujiyama","Full Throttle","Furius Baco","Fury","Fury 325","Fønix","Fēnix","Gadget's Go Coaster","Galactica / Air","GaleForce","Gao","GateKeeper","Gauntlet","Gaz Express","Gemini (Blue)","Gemini (Red)","Ghost Chasers","GhostRider","Giant Digger","Giant Dipper (Belmont Park)","Giant Dipper (Santa Cruz Beach Boardwalk)","Godoforum","Gold Rush","Gold Striker","Golden Sky Coaster","Golden Wings in Snowfield","Goliath (La Ronde)","Goliath (Six Flags Great America)","Goliath (Six Flags Magic Mountain)","Goliath (Six Flags Over Georgia)","Goliath (Walibi Belgium)","Goliath (Walibi Holland)","Good Gravy!","Goofy's Sky School","Goudurix","Gran Montserrat","Grand Canyon Express","Grand National","Great Bear","Great Chase","Great Desert Rally","Great Nor'Easter","Great Pumpkin Coaster","Great White (Morey's Piers)","Great White (SeaWorld San Antonio)","Green Hornet: High Speed Chase","Green Lantern Coaster","Greezed Lightnin'","Griffon","Grizzly","Grottenblitz","G'sengte Sau","Guardians of the Galaxy : Cosmic Rewind","Gwazi","Hagrid's Magical Creatures Motorbike Adventure","Hair Raiser","Hakugei","Half Pipe (Chimelong Paradise)","Half Pipe (Särkänniemi)","Hals-über-Kopf","Halvar","HangTime","Happy Loops","Harvest Time","Heidi The Ride","Hello Kitty Angel Coaster","Helix","Hero","Hidden Dragon","High Roller","High Speed Roller Coaster","Himalayan Eagle Roller Coaster","Hip Hop Coaster","Hollywood Dream: The Ride","Hollywood Dream: The Ride - Backdrop","Hollywood Rip Ride Rockit","Honey Harbour","Hoosier Hurricane","Howler","Hugin og Munin","Huracan","Hurricane","Hydra The Revenge","Hype","Hyperia","Hyperion","Hypersonic XLC","Hyperspace Mountain","Ice Breaker","Icon","Impulse","Incredible Hulk Coaster","Incredicoaster","Indiana Jones et le Temple du Péril","Inferno","Infusion","Insane","Intimidator / Thunder Striker","Intimidator 305 / Project 305","Invertigo","Invadr","Iron Dragon","Iron Gwazi","Iron Menace","Iron Rattler","ISpeed","Jack Rabbit","Jamm","Jersey Devil Coaster","Jet Coaster","Jet Rescue","Jetline","Jimmy Neutron's Atomic Flyer","John Wick: Open Contract","Joker","Joker's Jinx","Joris en de Draak (Vuur)","Joris en de Draak (Water)","Journey to Atlantis","Joyride","Jubilee","Judge Roy Scream","Jungle Trailblazer (Fantawild Dreamland Zhengzhou)","Jungle Trailblazer (Fantawild Oriental Heritage Ningbo)","Jungle Trailblazer (Fantawild Oriental Heritage Wuhu)","Jungle Trailblazer (Fantawild Oriental Heritage Xiamen)","Jungle Trailblazer (Fantawild Oriental Heritage Zhuzhou)","Junker","Juvelen","K3 Rollerskater","Kamelen","Kanonen","Karacho","Katapul","Katun","Kawasemi","Kentucky Flyer","Kentucky Rumbler","Kikkerachtbaan","Kingda Ka","Kirnu","Kondaa","Krampus Expédition","Kraken","Krake","Krater","Kumba","Kumali","Kung Fu Panda Master","Kvastingen","Labyrinth","Le Monstre","Le Twist","Leaping Polar Bear","Lech Coaster","Leviathan","Light Explorers","Lightning","Lightning Racer (Lightning)","Lightning Racer (Thunder)","Lightning Rod","Lightning Run","Limit / Toxic Garden","Linnunrata eXtra","Lisebergbanan","Loch Ness Monster","Loop Coaster","Loopen","Lost Coaster of Superstition Mountain","Lost Gravity","Loup-Garou","Lynet","Madagascar Mad Pursuit!","Mad Mouse (Iowa State Fair)","Mad Mouse (Valleyfair)","Magnum XL-200","Mahuka","Mako","Mamba","Mammut (Gardaland)","Mammut (Tripsdrill)","Manhattan Express","Manta (SeaWorld Orlando)","Manta (SeaWorld San Diego)","Master Thai","Matterhorn Blitz","Matterhorn Bobsleds (Left)","Matterhorn Bobsleds (Right)","Maverick","Max & Moritz (Max)","Max & Moritz (Moritz)","Maxx Force","Maya Adventure","Mayhem","Medusa","Medusa Steel Coaster","Mega Coaster","Megafobia","Megaton","Meteor","Millennium Force","Milky Way","Mindbender","Mine Blower","Mine Coaster","Mine Expressen","Mine Train (Attractiepark Slagharen)","Mine Train (Attractiepark Toverland)","Mining Town","Mini Mine Train","Mission Ferrari","Monster (Adventureland)","Monster (Gröna Lund)","Monster (Walygator Grand Est)","Montaña Rusa","Monte Carlo Racetrack","Montemakani","Montezooma's Revenge","Montezum","Montu","Motocoaster","MotoGee","Mount Makiling","Movie Park Studio Tour","MP-Xpress","Mr. Freeze","Mr. Freeze: Reverse Blast","Mumbo Jumbo","Muntanya Russa","Music Coaster","Mystic","Mystic Timbers","Na Fianna Force","Naga Bay","Nefeskesen","Nemesis","Nemesis Inferno","Nemesis Reborn","Neo's Twister","Nessie","New Texas Giant","Nickelodeon Streak","Ninja (Six Flags Magic Mountain)","Ninja (Six Flags St. Louis)","Nio","Nitro","Noisette Express","Now You See Me: High Roller","Objectif Mars","Oblivion","Oblivion: The Black Hole","Octonauts Roller Coaster","Odinexpressen","Oki Doki","Orient Express","Orion","Orkanen","Orochi","Outlaw","Outlaw Run","OzIris","Pandemonium (Six Flags Fiesta Texas)","Pandemonium (Six Flags St. Louis)","Panic Coaster Back Daan","Panic Drive","Pantheon","Parrot Coaster","Patriot (Castles N' Coasters)","Patriot (Worlds of Fun)","Pegase Express","Penguin Coaster","Pepsi Orange Streak","Peter Pan Coaster","Phaethon","Phantom's Revenge","Phobia Phear Coaster","Phoenix","Pipeline: The Surf Coaster","Piraten","Pitts Special","Polar Coaster","Polar Explorer","Poltergeist","Poseidon","Possessed","PowderKeg","Predator","Primordial","Prowler","Psyké Underground","Pulsar","Puss in Boots' Giant Journey","Pyrenees","Python","Queen Cobra","Rabalder","Racer 75","Racing","Raging Bull","Raging Spirits","Ragin' Cajun","RailBlazer","Raik","Rampage","Raptor (Cedar Point)","Raptor (Gardaland)","Ratón Loco","Ravine Flyer II","RC Racer","Red Force","Renegade","Revenge of the Mummy (Universal Studios Florida)","Revenge of the Mummy (Universal Studios Hollywood)","Revenge of the Mummy (Universal Studios Singapore)","Revolution (Blackpool Pleasure Beach)","Revolution (Six Flags Magic Mountain)","Revolution / Mount Mara","Rex's Racer","Riddler's Revenge","Rita","River King Mine Train","Road Runner Express","Road Runner Roller Coaster","Roar","Roaring Timbers","Roar-O-Saurus","Robin Hood","Rock 'N Roll Duncan","Rock 'n' Roller Coaster","Rock 'n' Roller Coaster starring Aerosmith","Rocket","Roller Coaster (Legendia)","Roller Coaster (Wiener Prater)","Roller Coaster Mayan","Roller Skater","Rollies Coaster","Rougarou","Royal Scotsman","Runaway Mine Train (Alton Towers)","Runaway Mine Train (Six Flags Over Texas)","Runaway Mountain","Runaway Tram","Rutschebanen (Bakken)","Rutschebanen (Tivoli Gardens)","Salama","Samba Gliders","Saw - The Ride","Saven","Scary Toys Factory","Schlange von Midgard","Schweizer Bobbahn","Scooby-Doo Spooky Coaster","Scorpion","Scream!","Screamin' Eagle","Sea Serpent","Sea Viper","Seven Dwarfs Mine Train (Magic Kingdom)","Seven Dwarfs Mine Train (Shanghai Disneyland)","Shadows of Arkham / Batman la Fuga","Shaman","Shambhala","Shenzhou Coaster","SheiKra","Shivering Timbers","Shock","Shockwave (Six Flags Great America)","Shockwave (Six Flags Over Texas)","Shuttle Loop","Sidewinder / Jolly Rancher Remix","Sierra Sidewinder","Sik","Silver Bullet","Silver Star","Skatteøen","Sky Coaster","Sky Rocket","Sky Scream","Skyrush","Slinky Dog Dash","Smiler","Snoopy's Great Race","Snow Mountain Flying Dragon","Soaring with Dragon","Son of Beast","Sooperdooperlooper","Space Express","Space Fantasy: The Ride","Space Mountain (Disneyland)","Space Mountain (Disneyland Paris)","Space Mountain (Disneyworld) (Alpha)","Space Mountain (Disneyworld) (Omega)","Space Mountain (Tokyo Disneyland)","Space Mountain: Mission 2","Space Shuttle","Space Vehicle","Spatial Experience","Speed","Speed Coaster","Speed Monster","Speed of Sound","Speed Water Coaster","Speed: No Limits","Speedwave","Speedy Bob","Spider-Man Doc Ock's Revenge","Spin Runway","Spinball Whizzer","Spinning Dragons","Spinning Mouse","SpongeBob SquarePants Rock Bottom Plunge","SpongeBob's Boating School Blast","Stampbanan","Stampida (Blue)","Stampida (Red)","Stardust Racers (Green)","Stardust Racers (Yellow)","Star Flyer","Star Mountain","Star Trek: Operation Enterprise","Stealth","Steam Racers","Steampunk Coaster Iron Bull","Steel Curtain","Steel Dragon 2000","Steel Eel","Steel Force","Steel Hawg","Steel Phantom","Steel Taipan","Steel Venom","Steel Vengeance","Steamin' Demon","Stellar Shuttle","Storm - The Dragon Legend","Storm Chaser","Storm Coaster (Dubai Hills Mall)","Storm Coaster (Sea World Australia)","Storm Runner","Stress Express","Stunt Fall","Stunt Pilot","Super Flight","Super Spider","Super Tornado","Superman El Último Escape","Superman Escape","Superman Krypton Coaster","Superman The Ride","Superman Ultimate Flight (Six Flags Great Adventure)","Superman Ultimate Flight (Six Flags Great America)","Superman Ultimate Flight (Six Flags Over Georgia)","Superman: Escape from Krypton","Superman: La Atracción de Acero","Superman: Ride of Steel","SuperSplash","Supersonic Odyssey","Svalbard Ekspressen","Swiss Toboggan","T Express","T3","Taiga","Tatsu","Takabisha","Talon","Tarantula","Taron","Teletren","Tempesto","Texas Cyclone","Texas Giant","Texas Stingray","TH13TEEN","The Bat","The Beast","The Big One","The Boss","The Demon","The Gold Coaster / Cyclone","The Legend","The Quest","The Racer","The Raven","The Ride to Happiness by Tomorrowland","The Swarm","The Voyage","Thor's Hammer","Thunder Dolphin","Thunder Run","Thunderation","Thunderbird","ThunderCoaster","Thunderhawk","Thunderbolt","Tig'rr Coaster","Tigor Mountain","Tigris","Tiki-Waka","Time Traveler","Timber Terror","Timber Wolf","Titan","Titan MAX","TMNT Shellraiser","Tomahawk","Tonnerre 2 Zeus","Tonnerre de Zeus","Toos-Express","Top Thrill 2","Top Thrill Dragster","Tormenta Rampaging Run","Tornado (Bakken)","Tornado (Särkänniemi)","Toutatis","Tower of Terror II","Trace du Hourra","Trailblazer","Tremors","Triops","TRON Lightcycle Power Run","Tron Lightcycle / Run","Tropical Storm","Troy","Tulireki","Turbo Track","Twisted Colossus","Twisted Timbers","Twister","Typhoon","Ukko","Ultra Twister","Underground","Untamed","V2: Vertical Velocity","Valkyria","Valravn","Vampire (Chessington World of Adventures)","Vampire (Walibi Belgium)","Van Helsing's Factory","Vanish","VelociCoaster","Velociraptor","Velocity","Venus GP","Verbolten","Vertigo","Vicky The Ride","Viking Roller Coaster","Vilda Musen","Vilde Mus","Villain","Viper (Six Flags Great America)","Viper (Six Flags Magic Mountain)","Vliegende Hollander","Vogel Rok","Vol D'Icare","Volcano: The Blast Coaster","Volldampf","Voltron Nevera","Vortex (Canada's Wonderland)","Vortex (Kings Island)","Vuoristorata","Wacky Worm","Walrus Splash","Wan-Wan Coaster Wandaras","Wave Breaker","West Coast Racers","Western-Expressen","Whirlwind","White Lightning","Whizzer","Wicked","Wicked Cyclone","Wicker Man","Wild Eagle","Wild Lightnin'","Wild Mouse","Wild One","Wild Thing","Wild Waves","Wild West Express","WildCat","Wildcat's Revenge","Wildfire","Wile E. Coyote's Grand Canyon Blaster","Wilkołak","Winja's Fear","Winja's Force","Wodan - Timburcoaster","Wolverine Wildcat","Wonder Woman Coaster","Wonder Woman Flight of Courage","Wonder Woman Golden Lasso","Wood Coaster","Wooden Coaster","Wooden Coaster - Fireball","Wood Express","Woodstock Express","Wrath of Zeus","X2","X-Coaster","Xcelerator","X-Flight","Xpress: Platform 13","Yamisok","Yankee Cannonball","Young Star Coaster","YOY (Chill)","YOY (Thrill)","Yuke","Yukon Quad","Yukon Striker","Zadra","Zambezi Zinger","Zokkon","Zoomerang"];

        let _coasterSearchSelected = false;

        function coasterSearchInput(val) {
            _coasterSearchSelected = false;
            const dropdown = document.getElementById('coaster-search-dropdown');
            const clearBtn = document.getElementById('profile-fav-coaster-clear');
            if (clearBtn) clearBtn.style.display = val ? 'block' : 'none';
            if (!dropdown) return;
            if (val.length < 3) { dropdown.classList.add('hidden'); dropdown.innerHTML = ''; return; }
            const q = val.toLowerCase();
            const matches = COASTERS_DB.filter(c => c.toLowerCase().includes(q));
            dropdown.innerHTML = '';
            if (matches.length > 0) {
                matches.slice(0, 20).forEach(c => {
                    const item = document.createElement('div');
                    item.className = 'coaster-search-item';
                    item.textContent = c;
                    item.onmousedown = () => coasterSearchSelect(c);
                    dropdown.appendChild(item);
                });
            }
            // Option texte libre si pas de correspondance exacte
            if (!matches.includes(val)) {
                const item = document.createElement('div');
                item.className = 'coaster-search-item coaster-search-item-custom';
                item.style.fontStyle = 'italic';
                item.textContent = val;
                item.onmousedown = () => coasterSearchSelect(val);
                if (matches.length === 0) dropdown.appendChild(item);
                else {
                    const sep = document.createElement('div');
                    sep.className = 'coaster-search-sep';
                    dropdown.appendChild(sep);
                    dropdown.appendChild(item);
                }
            }
            dropdown.classList.remove('hidden');
        }

        function coasterSearchSelect(val) {
            _coasterSearchSelected = true;
            const input = document.getElementById('profile-fav-coaster-input');
            if (input) input.value = val;
            document.getElementById('coaster-search-dropdown').classList.add('hidden');
            const clearBtn = document.getElementById('profile-fav-coaster-clear');
            if (clearBtn) clearBtn.style.display = val ? 'block' : 'none';
            saveProfilePreference('favCoaster', val);
            const savedEl = document.getElementById('profile-fav-coaster-saved');
            if (savedEl) { savedEl.classList.remove('hidden'); setTimeout(() => savedEl.classList.add('hidden'), 2500); }
        }

        function coasterSearchHide() {
            document.getElementById('coaster-search-dropdown').classList.add('hidden');
        }

        function coasterSearchClear() {
            const input = document.getElementById('profile-fav-coaster-input');
            if (input) input.value = '';
            document.getElementById('coaster-search-dropdown').classList.add('hidden');
            const clearBtn = document.getElementById('profile-fav-coaster-clear');
            if (clearBtn) clearBtn.style.display = 'none';
            saveProfilePreference('favCoaster', '');
        }

        function coasterSearchKeydown(e) {
            const dropdown = document.getElementById('coaster-search-dropdown');
            const items = dropdown ? dropdown.querySelectorAll('.coaster-search-item') : [];
            let active = dropdown ? dropdown.querySelector('.coaster-search-item.active') : null;
            if (e.key === 'ArrowDown') {
                e.preventDefault();
                if (!active && items.length) { items[0].classList.add('active'); }
                else if (active) { active.classList.remove('active'); const next = active.nextElementSibling; if (next && next.classList.contains('coaster-search-item')) next.classList.add('active'); }
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                if (active) { active.classList.remove('active'); const prev = active.previousElementSibling; if (prev && prev.classList.contains('coaster-search-item')) prev.classList.add('active'); }
            } else if (e.key === 'Enter') {
                e.preventDefault();
                if (active) active.onmousedown();
            } else if (e.key === 'Escape') {
                dropdown.classList.add('hidden');
            }
        }

        function renderMyScores() {
            const user = AuthService.getCurrentUser();
            if (!user) return;

            // Score Total
            const totalEl = document.getElementById('my-scores-total-value');
            const all = cqGetAllBestScores();
            const userScores = all[user.id] || {};
            let total = 0;
            for (const quizId in userScores) {
                const scores = userScores[quizId];
                if (Array.isArray(scores) && scores.length > 0) {
                    total += Math.max(...scores);
                }
            }
            if (totalEl) totalEl.textContent = total.toLocaleString('fr-FR');

            // Liste par quiz
            const list = document.getElementById('my-scores-quiz-list');
            if (!list) return;
            const quizIds = Object.keys(userScores);
            if (quizIds.length === 0) {
                list.innerHTML = '<p class="text-sm opacity-50 font-button">Aucun quiz joué pour le moment.</p>';
                return;
            }

            const games = typeof cqGetQuizzes === 'function' ? cqGetQuizzes() : [];
            list.innerHTML = quizIds.map(quizId => {
                const scores = userScores[quizId];
                const best = Array.isArray(scores) && scores.length > 0 ? Math.max(...scores) : 0;
                const plays = Array.isArray(scores) ? scores.length : 0;
                const game = games.find(g => g.id === quizId);
                const quizName = game ? game.title : quizId;
                return `<div style="display:flex;align-items:center;justify-content:space-between;background:rgba(0,0,0,0.06);border-radius:0.75rem;padding:0.875rem 1.25rem;">
                    <div>
                        <div style="font-family:'Tektur',sans-serif;font-weight:800;font-size:0.9rem;">${quizName}</div>
                        <div style="font-family:'Datatype',monospace;font-size:0.7rem;font-weight:700;text-transform:uppercase;opacity:0.55;margin-top:0.2rem;">${plays} partie${plays > 1 ? 's' : ''}</div>
                    </div>
                    <div style="text-align:right;">
                        <div style="font-family:'Datatype',monospace;font-size:0.65rem;font-weight:700;text-transform:uppercase;opacity:0.55;margin-bottom:0.15rem;">Meilleur score</div>
                        <div style="font-family:'Tektur',sans-serif;font-weight:900;font-size:1.75rem;line-height:1;color:#660000;">${best.toLocaleString('fr-FR')}</div>
                    </div>
                </div>`;
            }).join('');
        }

        function generateAvatarColor(pseudo) {
            let hash = 0;
            for (let i = 0; i < pseudo.length; i++) {
                hash = pseudo.charCodeAt(i) + ((hash << 5) - hash);
            }
            const colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#FFA07A', '#98D8C8', '#F7DC6F', '#BB8FCE', '#85C1E2'];
            return colors[Math.abs(hash) % colors.length];
        }

        /* --- AVATAR PERSONNALISÉ --- */
        function getCustomAvatar(userId) {
            return localStorage.getItem('cq_avatar_' + userId) || null;
        }
        function setCustomAvatar(userId, dataUrl) {
            localStorage.setItem('cq_avatar_' + userId, dataUrl);
        }
        function removeCustomAvatar(userId) {
            localStorage.removeItem('cq_avatar_' + userId);
        }

        function renderProfileAvatar(user) {
            const avatarEl = document.getElementById('profile-avatar');
            if (!avatarEl) return;
            const deleteBtn = document.getElementById('profile-avatar-delete-btn');
            const customAvatar = getCustomAvatar(user.id);

            if (customAvatar) {
                avatarEl.style.backgroundImage = `url(${customAvatar})`;
                avatarEl.style.backgroundSize = 'cover';
                avatarEl.style.backgroundPosition = 'center';
                avatarEl.style.backgroundColor = '';
                avatarEl.textContent = '';
                if (deleteBtn) deleteBtn.classList.remove('hidden');
            } else {
                avatarEl.style.backgroundImage = '';
                avatarEl.style.backgroundColor = generateAvatarColor(user.pseudo);
                avatarEl.textContent = user.pseudo.charAt(0).toUpperCase();
                avatarEl.style.display = 'flex';
                avatarEl.style.alignItems = 'center';
                avatarEl.style.justifyContent = 'center';
                avatarEl.style.fontSize = '1.5rem';
                avatarEl.style.fontWeight = '800';
                avatarEl.style.color = '#fff';
                avatarEl.style.fontFamily = 'Tektur, sans-serif';
                if (deleteBtn) deleteBtn.classList.add('hidden');
            }
        }

        function profileAvatarClick() {
            const input = document.getElementById('profile-avatar-input');
            if (input) { input.value = ''; input.click(); }
        }

        function handleProfileAvatarUpload(input) {
            const file = input.files[0];
            if (!file) return;
            const user = AuthService.getCurrentUser();
            if (!user) return;
            const reader = new FileReader();
            reader.onload = function(e) {
                setCustomAvatar(user.id, e.target.result);
                renderProfileAvatar(user);
            };
            reader.readAsDataURL(file);
        }

        function openDeleteAvatarConfirm() {
            playSound('modal-open');
            document.getElementById('modal-delete-avatar').classList.remove('hidden');
        }
        function closeDeleteAvatarConfirm() {
            playSound('modal-close');
            document.getElementById('modal-delete-avatar').classList.add('hidden');
        }
        function confirmDeleteAvatar() {
            const user = AuthService.getCurrentUser();
            if (!user) return;
            removeCustomAvatar(user.id);
            renderProfileAvatar(user);
            closeDeleteAvatarConfirm();
        }

        /* --- MODALE CONSULTATION PROFIL CENTRALISÉE --- */

        function openProfileModal(userId, forceModal) {
            // Récupérer l'utilisateur cible
            let users = [];
            try { users = JSON.parse(localStorage.getItem('cq_users') || '[]'); } catch(e) {}
            const targetUser = users.find(u => u.id === userId);
            if (!targetUser) return;

            // Si connecté et c'est son propre profil → rediriger vers Mon Profil (sauf si forceModal)
            if (!forceModal) {
                const currentUser = AuthService.getCurrentUser();
                if (currentUser && currentUser.id === userId && !isGuestMode) {
                    showView('view-user-profile');
                    return;
                }
            }

            // Remplir la modale
            _fillProfileModal(targetUser);
            playSound('modal-open');
            document.getElementById('modal-view-profile').classList.remove('hidden');
        }

        function openProfileModalByPseudo(pseudo, forceModal) {
            let users = [];
            try { users = JSON.parse(localStorage.getItem('cq_users') || '[]'); } catch(e) {}
            const targetUser = users.find(u => u.pseudo === pseudo);
            if (!targetUser) return;

            if (!forceModal) {
                const currentUser = AuthService.getCurrentUser();
                if (currentUser && currentUser.id === targetUser.id && !isGuestMode) {
                    showView('view-user-profile');
                    return;
                }
            }

            _fillProfileModal(targetUser);
            playSound('modal-open');
            document.getElementById('modal-view-profile').classList.remove('hidden');
        }

        function _fillProfileModal(user) {
            // Avatar
            const avatarEl = document.getElementById('modal-profile-avatar');
            if (avatarEl) {
                const customAvatar = getCustomAvatar(user.id);
                if (customAvatar) {
                    avatarEl.style.backgroundImage = `url(${customAvatar})`;
                    avatarEl.style.backgroundSize = 'cover';
                    avatarEl.style.backgroundPosition = 'center';
                    avatarEl.style.backgroundColor = '';
                    avatarEl.textContent = '';
                } else {
                    avatarEl.style.backgroundImage = '';
                    avatarEl.style.backgroundColor = generateAvatarColor(user.pseudo);
                    avatarEl.textContent = user.pseudo.charAt(0).toUpperCase();
                }
            }

            // Pseudo
            const pseudoEl = document.getElementById('modal-profile-pseudo');
            if (pseudoEl) pseudoEl.textContent = user.pseudo || '-';

            // Date de création
            const createdEl = document.getElementById('modal-profile-created');
            if (createdEl) {
                createdEl.textContent = user.createdAt
                    ? new Date(user.createdAt).toLocaleDateString('fr-FR', { year:'numeric', month:'long', day:'numeric' })
                    : '-';
            }

            // Score total
            const scoreEl = document.getElementById('modal-profile-total-score');
            if (scoreEl) {
                let total = 0;
                try {
                    const allScores = JSON.parse(localStorage.getItem('cq_best_scores_v1') || '{}');
                    const userScores = allScores[user.id] || {};
                    for (const quizId in userScores) {
                        const arr = userScores[quizId];
                        if (Array.isArray(arr) && arr.length > 0) total += Math.max(...arr);
                    }
                } catch(e) {}
                scoreEl.textContent = total.toLocaleString('fr-FR');
            }

            // Extras (description, préférences)
            const extras = getProfileExtras(user.id);

            const descEl = document.getElementById('modal-profile-description');
            if (descEl) descEl.textContent = extras.description || '—';

            const modelEl = document.getElementById('modal-profile-model');
            const modelRow = document.getElementById('modal-profile-model-row');
            if (modelEl) {
                if (extras.favModel) {
                    modelEl.textContent = extras.favModel;
                    if (modelRow) modelRow.style.display = '';
                } else {
                    if (modelRow) modelRow.style.display = 'none';
                }
            }

            const mfEl = document.getElementById('modal-profile-manufacturer');
            const mfRow = document.getElementById('modal-profile-manufacturer-row');
            if (mfEl) {
                if (extras.favManufacturer) {
                    mfEl.textContent = extras.favManufacturer;
                    if (mfRow) mfRow.style.display = '';
                } else {
                    if (mfRow) mfRow.style.display = 'none';
                }
            }

            const ttEl = document.getElementById('modal-profile-traintype');
            const ttRow = document.getElementById('modal-profile-traintype-row');
            if (ttEl) {
                if (extras.favTrainType) {
                    ttEl.textContent = extras.favTrainType;
                    if (ttRow) ttRow.style.display = '';
                } else {
                    if (ttRow) ttRow.style.display = 'none';
                }
            }

            const coasterEl = document.getElementById('modal-profile-coaster');
            const coasterRow = document.getElementById('modal-profile-coaster-row');
            if (coasterEl) {
                if (extras.favCoaster) {
                    coasterEl.textContent = extras.favCoaster;
                    if (coasterRow) coasterRow.style.display = '';
                } else {
                    if (coasterRow) coasterRow.style.display = 'none';
                }
            }
        }

        function closeProfileModal() {
            playSound('modal-close');
            document.getElementById('modal-view-profile').classList.add('hidden');
        }

        let profilePasswordVisible = false;

        const EYE_OPEN_SVG = '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="w-4 h-4"><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /><path stroke-linecap="round" stroke-linejoin="round" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" /></svg>';
        const EYE_CLOSED_SVG = '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="w-4 h-4"><path stroke-linecap="round" stroke-linejoin="round" d="M3.98 8.223A10.477 10.477 0 001.934 12C3.226 16.338 7.244 19.5 12 19.5c.993 0 1.953-.138 2.863-.395M6.228 6.228A10.45 10.45 0 0112 4.5c4.756 0 8.773 3.162 10.065 7.498a10.523 10.523 0 01-4.293 5.774M6.228 6.228L3 3m3.228 3.228l3.65 3.65m7.894 7.894L21 21m-3.228-3.228l-3.65-3.65m0 0a3 3 0 10-4.243-4.243m4.242 4.242L9.88 9.88" /></svg>';

        function toggleProfilePasswordVisibility() {
            const passwordInput = document.getElementById('profile-password');
            if (!passwordInput) return;
            const wrapper = passwordInput.closest('.password-input-wrapper');
            const button = wrapper ? wrapper.querySelector('button') : null;

            profilePasswordVisible = !profilePasswordVisible;

            passwordInput.type = profilePasswordVisible ? 'text' : 'password';
            if (button) {
                button.innerHTML = profilePasswordVisible ? EYE_CLOSED_SVG : EYE_OPEN_SVG;
            }
        }

        // Track visible passwords for form fields
        const visiblePasswords = {};

        function toggleFormPasswordVisibility(fieldId, e) {
            const field = document.getElementById(fieldId);
            if (!field) return;

            visiblePasswords[fieldId] = !visiblePasswords[fieldId];

            let button = null;
            if (e && e.target && e.target.closest) {
                button = e.target.closest('button');
            }
            if (!button && field.parentElement) {
                button = field.parentElement.querySelector('button');
            }

            if (visiblePasswords[fieldId]) {
                field.type = 'text';
                if (button) {
                    button.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="w-4 h-4"><path stroke-linecap="round" stroke-linejoin="round" d="M3.98 8.223A10.477 10.477 0 001.934 12C3.226 16.338 7.244 19.5 12 19.5c.993 0 1.953-.138 2.863-.395M6.228 6.228A10.45 10.45 0 0112 4.5c4.756 0 8.773 3.162 10.065 7.498a10.523 10.523 0 01-4.293 5.774M6.228 6.228L3 3m3.228 3.228l3.65 3.65m7.894 7.894L21 21m-3.228-3.228l-3.65-3.65m0 0a3 3 0 10-4.243-4.243m4.242 4.242L9.88 9.88" /></svg>';
                }
            } else {
                field.type = 'password';
                if (button) {
                    button.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="w-4 h-4"><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /><path stroke-linecap="round" stroke-linejoin="round" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" /></svg>';
                }
            }
        }

        function openChangePassword() {
            playSound('modal-open');
            document.getElementById('change-old-password').value = '';
            document.getElementById('change-new-password').value = '';
            document.getElementById('change-confirm-password').value = '';
            document.getElementById('change-password-error').textContent = '';
            document.getElementById('change-password-strength-wrap').classList.add('hidden');
            document.getElementById('change-password-strength-fill').style.width = '0%';
            document.getElementById('change-password-strength-label').textContent = '';
            document.getElementById('modal-change-password').classList.remove('hidden');
        }

        function closeChangePassword() {
            playSound('modal-close');
            document.getElementById('modal-change-password').classList.add('hidden');
        }

        function closeChangePasswordConfirm() {
            playSound('modal-close');
            document.getElementById('modal-change-password-confirm').classList.add('hidden');
        }

        let cqPendingPseudoChange = null;

        function openChangePseudo() {
            playSound('modal-open');
            const input = document.getElementById('change-pseudo-input');
            const err = document.getElementById('change-pseudo-error');
            const user = AuthService.getCurrentUser();
            
            if (input) input.value = user?.pseudo || '';
            if (err) {
                err.textContent = '';
                err.classList.add('hidden');
            }
            
            const modal = document.getElementById('modal-change-pseudo');
            if (modal) modal.classList.remove('hidden');
        }

        function closeChangePseudo() {
            playSound('modal-close');
            const modal = document.getElementById('modal-change-pseudo');
            if (modal) modal.classList.add('hidden');
        }

        function submitChangePseudo() {
            const input = document.getElementById('change-pseudo-input');
            const err = document.getElementById('change-pseudo-error');
            const user = AuthService.getCurrentUser();
            
            if (!input || !user) return;
            
            const newPseudo = input.value.trim();
            
            if (!newPseudo) {
                if (err) {
                    err.textContent = 'Veuillez saisir un pseudo.';
                    err.classList.remove('hidden');
                }
                return;
            }
            
            if (newPseudo === user.pseudo) {
                closeChangePseudo();
                return;
            }
            
            AuthService.isPseudoAvailable(newPseudo).then(available => {
                if (!available) {
                    if (err) {
                        err.textContent = 'Ce pseudo est déjà pris.';
                        err.classList.remove('hidden');
                    }
                    return;
                }
                
                cqPendingPseudoChange = newPseudo;
                closeChangePseudo();
                openChangePseudoConfirm();
            });
        }

        function openChangePseudoConfirm() {
            const modal = document.getElementById('modal-change-pseudo-confirm');
            if (modal) { playSound('modal-open'); modal.classList.remove('hidden'); }
        }

        function closeChangePseudoConfirm() {
            const modal = document.getElementById('modal-change-pseudo-confirm');
            if (modal) { playSound('modal-close'); modal.classList.add('hidden'); }
            cqPendingPseudoChange = null;
        }

        function confirmChangePseudo() {
            const user = AuthService.getCurrentUser();
            if (!user || !cqPendingPseudoChange) return;
            
            // Mettre à jour le pseudo dans localStorage
            const users = JSON.parse(localStorage.getItem('cq_users') || '[]');
            const idx = users.findIndex(u => u.id === user.id);
            
            if (idx > -1) {
                users[idx].pseudo = cqPendingPseudoChange;
                users[idx].pseudoNormalized = cqPendingPseudoChange.trim().toLowerCase();
                localStorage.setItem('cq_users', JSON.stringify(users));
                
                // Mettre à jour la session
                sessionStorage.setItem('cq_user_session', JSON.stringify({
                    id: user.id,
                    pseudo: cqPendingPseudoChange
                }));

                // Mettre à jour la session persistante si elle existe
                try {
                    const persistentSession = localStorage.getItem('coasterquiz_persistent_session');
                    if (persistentSession) {
                        const parsed = JSON.parse(persistentSession);
                        parsed.pseudo = cqPendingPseudoChange;
                        localStorage.setItem('coasterquiz_persistent_session', JSON.stringify(parsed));
                    }
                } catch(e) {}
                
                loadProfileData();
                closeChangePseudoConfirm();
            }
        }

        function updateChangePasswordStrength() {
            const password = document.getElementById('change-new-password').value;
            const wrap = document.getElementById('change-password-strength-wrap');
            const fill = document.getElementById('change-password-strength-fill');
            const label = document.getElementById('change-password-strength-label');

            if (!password) {
                wrap.classList.add('hidden');
                fill.style.width = '0%';
                label.textContent = '';
                return;
            }

            const { score, label: strengthLabel, color } = computePasswordStrength(password);
            wrap.classList.remove('hidden');
            fill.style.width = `${score}%`;
            fill.style.backgroundColor = color;
            label.textContent = `Complexité : ${strengthLabel}`;
        }

        async function submitChangePassword() {
            const oldPassword = document.getElementById('change-old-password').value;
            const newPassword = document.getElementById('change-new-password').value;
            const confirmPassword = document.getElementById('change-confirm-password').value;
            const errorEl = document.getElementById('change-password-error');

            errorEl.textContent = '';

            const user = AuthService.getCurrentUser();
            if (!user) {
                errorEl.textContent = 'Erreur: utilisateur non trouvé.';
                return;
            }

            // Vérifier l'ancien mot de passe via son hash (ne jamais comparer en clair)
            const users = JSON.parse(localStorage.getItem('cq_users') || '[]');
            const storedUser = users.find(u => u.id === user.id);
            if (!storedUser) {
                errorEl.textContent = 'Erreur: utilisateur non trouvé.';
                return;
            }
            const oldHash = await sha256Hex(oldPassword);
            if (!secureCompare(oldHash, storedUser.passwordHash)) {
                errorEl.textContent = 'L\'ancien mot de passe est incorrect.';
                return;
            }

            if (!newPassword) {
                errorEl.textContent = 'Veuillez choisir un nouveau mot de passe.';
                return;
            }

            if (newPassword !== confirmPassword) {
                errorEl.textContent = 'Les mots de passe ne correspondent pas.';
                return;
            }

            if (newPassword === oldPassword) {
                errorEl.textContent = 'Le nouveau mot de passe doit être différent de l\'ancien.';
                return;
            }

            // Stocker le nouveau mot de passe temporairement pour confirmation
            window.pendingPasswordChange = newPassword;
            
            closeChangePassword();
            playSound('modal-open');
            document.getElementById('modal-change-password-confirm').classList.remove('hidden');
        }

        async function confirmChangePassword() {
            const user = AuthService.getCurrentUser();
            if (!user || !window.pendingPasswordChange) return;

            const result = await AuthService.changePassword(user.id, window.pendingPasswordChange);
            
            closeChangePasswordConfirm();
            window.pendingPasswordChange = null;

            if (result.success) {
                // Recharger les données du profil
                loadProfileData();
                // Optionnel: afficher un message de succès
            }
        }

        function openAdminAccess() {
            playSound('modal-open');
            document.getElementById('admin-password-input').value = '';
            document.getElementById('admin-password-error').textContent = '';
            document.getElementById('modal-admin-access').classList.remove('hidden');
        }

        function closeAdminAccess() {
            playSound('modal-close');
            document.getElementById('modal-admin-access').classList.add('hidden');
            document.getElementById('admin-password-input').value = '';
            document.getElementById('admin-password-error').textContent = '';
        }

        function submitAdminPassword(event) {
            event.preventDefault();
            const input = document.getElementById('admin-password-input');
            const error = document.getElementById('admin-password-error');
            const submitBtn = event.target.querySelector('button[type="submit"]');

            error.textContent = '';
            submitBtn.disabled = true;

            verifyAdminPassword(input.value).then(valid => {
                submitBtn.disabled = false;
                if (valid) {
                    grantAdminSession().then(() => {
                        closeSettings();
                        showView('view-admin-creation-quiz');
                    });
                    return;
                }
                error.textContent = 'Mot de passe incorrect.';
                input.focus();
            }).catch(() => {
                submitBtn.disabled = false;
                error.textContent = 'Erreur de vérification.';
            });
        }

        /* --- ADMIN CREATION TOOL FUNCTIONS --- */

        // Utilitaire d'échappement HTML pour prévenir les injections XSS lors des rendus innerHTML
        function escapeHtml(str) {
            return String(str ?? '')
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#039;');
        }

        // Génère un pseudo cliquable ouvrant la modale de profil (réutilise openProfileModalByPseudo)
        // isGuest : si true (Invité), retourne un simple span non cliquable
        function clickablePseudoHtml(pseudo, isGuest, extraStyle, forceModal) {
            const escaped = escapeHtml(pseudo || '?');
            if (isGuest || !pseudo || pseudo === 'Invité' || pseudo === '?') {
                return `<span${extraStyle ? ' style="' + extraStyle + '"' : ''}>${escaped}</span>`;
            }
            const _forceArg = forceModal ? ', true' : '';
            return `<span class="pseudo-clickable"${extraStyle ? ' style="' + extraStyle + '"' : ''} onclick="openProfileModalByPseudo('${escapeHtml(pseudo)}'${_forceArg})" title="Voir le profil de ${escaped}">${escaped}</span>`;
        }

        /* ============================================================
           PAGE BANNI
           ============================================================ */
        let _currentBanInfo = null;

        function showBannedPage(banInfo) {
            _currentBanInfo = banInfo;
            const view = document.getElementById('view-banned');
            if (!view) return;
            document.querySelectorAll('div[id^="view-"]').forEach(v => v.classList.add('hidden'));
            view.classList.remove('hidden');

            const msgEl = document.getElementById('banned-message');
            const reasonEl = document.getElementById('banned-reason');
            const durationEl = document.getElementById('banned-duration');

            if (reasonEl) reasonEl.textContent = banInfo.reason || 'Aucune raison fournie.';
            if (durationEl) {
                if (banInfo.type === 'temporary' && banInfo.daysLeft != null) {
                    durationEl.textContent = `Durée restante : ${banInfo.daysLeft} jour${banInfo.daysLeft > 1 ? 's' : ''}`;
                } else {
                    durationEl.textContent = 'Bannissement définitif';
                }
            }
        }

        function openBanContest() {
            const modal = document.getElementById('modal-ban-contest');
            if (modal) {
                playSound('modal-open');
                const ta = document.getElementById('ban-contest-message');
                if (ta) ta.value = '';
                modal.classList.remove('hidden');
            }
        }

        function closeBanContest() {
            const modal = document.getElementById('modal-ban-contest');
            if (modal) { playSound('modal-close'); modal.classList.add('hidden'); }
        }

        function submitBanContest() {
            // Message envoyé sans destination pour l'instant
            closeBanContest();
        }

        /* ============================================================
           MODERATION ADMIN
           ============================================================ */
        let _banModalData = null; // { userId, pseudo }
        let _banFormValues = null; // sauvegarde pour retour depuis confirmation

        function cqRenderModeration(query) {
            const container = document.getElementById('cq-moderation-list');
            if (!container) return;

            let users = [];
            try { users = JSON.parse(localStorage.getItem('cq_users') || '[]'); } catch(e) {}

            if (query && query.trim()) {
                const q = cqNormalizeSearch(query);
                users = users.filter(u => cqNormalizeSearch(u.pseudo || '').includes(q));
            }

            if (!users.length) {
                container.innerHTML = `<p class="cqcat-empty-hint text-center py-8">Aucun compte trouvé.</p>`;
                return;
            }

            const plays = cqGetGamePlays();

            container.innerHTML = users.map(u => {
                const isBanned = !!u.banned;
                const banLabel = isBanned
                    ? (u.banned.type === 'temporary'
                        ? `<span class="mod-badge mod-badge-temp">Banni temp.</span>`
                        : `<span class="mod-badge mod-badge-perm">Banni déf.</span>`)
                    : '';

                // Avatar couleur
                let hash = 0;
                for (let i = 0; i < (u.pseudo||'').length; i++) hash = u.pseudo.charCodeAt(i) + ((hash << 5) - hash);
                const colors = ['#FF6B6B','#4ECDC4','#45B7D1','#FFA07A','#98D8C8','#F7DC6F','#BB8FCE','#85C1E2'];
                const avatarColor = colors[Math.abs(hash) % colors.length];
                const avatarLetter = (u.pseudo || '?').charAt(0).toUpperCase();

                let favs = [];
                try { const raw = localStorage.getItem(`cq_favorites_${u.id}`); favs = raw ? JSON.parse(raw) : []; } catch(e) {}
                if (!Array.isArray(favs)) favs = [];
                const favsHtml = favs.length ? favs.map(f => `<span class="mod-fav-chip">${escapeHtml(f)}</span>`).join('') : '<span class="opacity-50 text-xs">Aucun favori</span>';

                const bugReports = u.bugReports || 0;
                const createdAt = u.createdAt ? new Date(u.createdAt).toLocaleDateString('fr-FR') : '-';
                const lastLogin = u.lastLogin ? new Date(u.lastLogin).toLocaleString('fr-FR') : '-';

                return `
                <div class="mod-user-card">
                    <div class="mod-user-main">
                        <div class="mod-avatar" style="background:${avatarColor}">${escapeHtml(avatarLetter)}</div>
                        <div class="mod-user-info">
                            <div class="mod-user-pseudo">${clickablePseudoHtml(u.pseudo || '-', false, undefined, true)} ${banLabel}</div>
                            <div class="mod-user-meta">Créé le ${escapeHtml(createdAt)} · Dernière connexion : ${escapeHtml(lastLogin)}</div>
                            <div class="mod-user-meta">🚩 ${escapeHtml(String(bugReports))} bug${bugReports !== 1 ? 's' : ''} signalé${bugReports !== 1 ? 's' : ''}</div>
                            <div class="mod-user-favs">Favoris : ${favsHtml}</div>
                        </div>
                    </div>
                    <div class="mod-user-actions">
                        <button type="button" class="mod-btn-ban" data-uid="${escapeHtml(u.id)}" data-pseudo="${escapeHtml(u.pseudo)}"
                            onclick="openBanModal(this.dataset.uid, this.dataset.pseudo)" title="Bannir">
                            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2.5" stroke="currentColor" width="14" height="14"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z" /></svg>
                        </button>
                        <button type="button" class="mod-btn-delete" data-uid="${escapeHtml(u.id)}" data-pseudo="${escapeHtml(u.pseudo)}" data-banned="${isBanned ? '1' : '0'}"
                            onclick="openDeleteUserModal(this.dataset.uid, this.dataset.pseudo, this.dataset.banned === '1')" title="Supprimer">
                            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" width="14" height="14"><path stroke-linecap="round" stroke-linejoin="round" d="m14.74 9-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 0 1-2.244 2.077H8.084a2.25 2.25 0 0 1-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 0 0-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 0 1 3.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 0 0-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 0 0-7.5 0" /></svg>
                        </button>
                    </div>
                </div>`;
            }).join('');
        }

        /* --- Modale Bannissement --- */
        function openBanModal(userId, pseudo, savedValues) {
            playSound('modal-open');
            _banModalData = { userId, pseudo };
            // Réinitialiser ou restaurer les valeurs
            const typeRadios = document.querySelectorAll('input[name="ban-type"]');
            const daysWrap = document.getElementById('ban-days-wrap');
            const daysInput = document.getElementById('ban-days-input');
            const reasonInput = document.getElementById('ban-reason-input');
            const errorEl = document.getElementById('ban-modal-error');

            if (savedValues) {
                // Restaurer les valeurs après retour depuis confirmation
                typeRadios.forEach(r => { r.checked = r.value === savedValues.type; });
                if (daysInput) daysInput.value = savedValues.days || '';
                if (reasonInput) reasonInput.value = savedValues.reason || '';
                if (daysWrap) daysWrap.classList.toggle('hidden', savedValues.type !== 'temporary');
            } else {
                typeRadios.forEach(r => { r.checked = r.value === 'temporary'; });
                if (daysInput) daysInput.value = '';
                if (reasonInput) reasonInput.value = '';
                if (daysWrap) daysWrap.classList.remove('hidden');
            }
            if (errorEl) errorEl.textContent = '';

            const pseudoEl = document.getElementById('ban-modal-pseudo');
            if (pseudoEl) pseudoEl.textContent = pseudo;

            document.getElementById('modal-ban').classList.remove('hidden');
        }

        function closeBanModal() {
            playSound('modal-close');
            document.getElementById('modal-ban').classList.add('hidden');
            _banModalData = null;
            _banFormValues = null;
        }

        function toggleBanDaysField() {
            const selected = document.querySelector('input[name="ban-type"]:checked');
            const wrap = document.getElementById('ban-days-wrap');
            if (wrap) wrap.classList.toggle('hidden', selected?.value !== 'temporary');
        }

        function submitBanForm() {
            const type = document.querySelector('input[name="ban-type"]:checked')?.value;
            const days = document.getElementById('ban-days-input')?.value;
            const reason = document.getElementById('ban-reason-input')?.value?.trim();
            const errorEl = document.getElementById('ban-modal-error');

            if (!reason) {
                if (errorEl) errorEl.textContent = 'La raison est obligatoire.';
                return;
            }
            if (type === 'temporary' && (!days || parseInt(days) < 1)) {
                if (errorEl) errorEl.textContent = 'Veuillez saisir un nombre de jours valide.';
                return;
            }
            if (errorEl) errorEl.textContent = '';

            // Sauvegarder les valeurs pour pouvoir revenir
            _banFormValues = { type, days, reason };

            // Fermer la modale ban et ouvrir la confirmation
            document.getElementById('modal-ban').classList.add('hidden');

            const confirmPseudoEl = document.getElementById('ban-confirm-pseudo');
            if (confirmPseudoEl) confirmPseudoEl.textContent = _banModalData?.pseudo || '';
            playSound('modal-open');
            document.getElementById('modal-ban-confirm').classList.remove('hidden');
        }

        function closeBanConfirm() {
            playSound('modal-close');
            document.getElementById('modal-ban-confirm').classList.add('hidden');
            // Revenir à la première modale avec les valeurs sauvegardées
            if (_banModalData && _banFormValues) {
                openBanModal(_banModalData.userId, _banModalData.pseudo, _banFormValues);
            }
        }

        function executeBan() {
            if (!_banModalData || !_banFormValues) return;
            const { userId } = _banModalData;
            const { type, days, reason } = _banFormValues;

            let users = [];
            try { users = JSON.parse(localStorage.getItem('cq_users') || '[]'); } catch(e) {}
            const idx = users.findIndex(u => u.id === userId);
            if (idx === -1) return;

            const banData = { type, reason };
            if (type === 'temporary') {
                const until = new Date();
                until.setDate(until.getDate() + parseInt(days));
                banData.until = until.toISOString();
                banData.daysGranted = parseInt(days);
            }
            users[idx].banned = banData;
            localStorage.setItem('cq_users', JSON.stringify(users));

            document.getElementById('modal-ban-confirm').classList.add('hidden');
            _banModalData = null;
            _banFormValues = null;
            playSound('action-confirm');
            cqRenderModeration(document.getElementById('mod-search-input')?.value || '');
        }

        /* --- Suppression d'un compte --- */
        let _deleteUserData = null;

        function openDeleteUserModal(userId, pseudo, isBanned) {
            playSound('modal-open');
            _deleteUserData = { userId, pseudo };
            if (!isBanned) {
                // Compte actif : impossible de supprimer
                document.getElementById('modal-delete-user-active').classList.remove('hidden');
            } else {
                // Compte banni : demander confirmation
                const pseudoEl = document.getElementById('delete-user-confirm-pseudo');
                if (pseudoEl) pseudoEl.textContent = pseudo;
                document.getElementById('modal-delete-user-confirm').classList.remove('hidden');
            }
        }

        function closeDeleteUserActive() {
            playSound('modal-close');
            document.getElementById('modal-delete-user-active').classList.add('hidden');
            _deleteUserData = null;
        }

        function closeDeleteUserConfirm() {
            playSound('modal-close');
            document.getElementById('modal-delete-user-confirm').classList.add('hidden');
            _deleteUserData = null;
        }

        function executeDeleteUser() {
            if (!_deleteUserData) return;
            const { userId } = _deleteUserData;
            let users = [];
            try { users = JSON.parse(localStorage.getItem('cq_users') || '[]'); } catch(e) {}
            users = users.filter(u => u.id !== userId);
            localStorage.setItem('cq_users', JSON.stringify(users));

            document.getElementById('modal-delete-user-confirm').classList.add('hidden');
            _deleteUserData = null;
            playSound('action-delete');
            cqRenderModeration(document.getElementById('mod-search-input')?.value || '');
        }

        // CLÉ V2 : Éradique tous les anciens faux quiz bloqués dans la mémoire du navigateur
        // IMPORTANT: doit être défini AVANT cqGetQuizzes() et tout appel à cqGetQuizzes().
        const CQ_ADMIN_QUIZZES_STORAGE_KEY = 'cq_admin_quizzes_V2';

        // Auto-sync wrapper pour les quizzes
        const _origLocalStorageSetItem = localStorage.setItem;
        let _syncTimeout;
        localStorage.setItem = function(key, value) {
            _origLocalStorageSetItem.call(this, key, value);

            // Si c'est les quizzes, sync avec Firestore en arrière-plan
            if (key === CQ_ADMIN_QUIZZES_STORAGE_KEY) {
                clearTimeout(_syncTimeout);
                _syncTimeout = setTimeout(() => {
                    try {
                        const quizzes = JSON.parse(value);
                        FirestoreSync.save(quizzes).catch(err =>
                            console.warn("[Sync] Erreur:", err)
                        );
                    } catch (e) {
                        console.warn("[Sync] Erreur parse:", e);
                    }
                }, 1000); // Attendre 1s avant sync pour éviter trop de requêtes
            }
        };

        let cqSelectedModeVal = null;
        let cqGameToDelete = null;
        let cqSortCriteria = 'date';
        let cqSortDirection = 'desc';
        let cqIsModifyingExisting = false;
        let cqPendingNewQuiz = null;
        let cqOriginalQuizTitle = '';
        let cqSelectedDifficulty = 0;
        let cqModifyDifficulty = 0;

        function cqRenderStars(containerId, selectedVal) {
            const container = document.getElementById(containerId);
            if (!container) return;
            container.querySelectorAll('.cq-star-btn').forEach(btn => {
                const v = parseInt(btn.dataset.val);
                btn.classList.toggle('active', v <= selectedVal);
            });
        }

        function cqSetDifficulty(val) {
            cqSelectedDifficulty = (cqSelectedDifficulty === val) ? 0 : val;
            cqRenderStars('cq-difficulty-stars', cqSelectedDifficulty);
        }

        function cqSetModifyDifficulty(val) {
            cqModifyDifficulty = (cqModifyDifficulty === val) ? 0 : val;
            cqRenderStars('cq-modify-difficulty-stars', cqModifyDifficulty);
        }

        function cqSaveModifyMeta() {
            const title = cqOriginalQuizTitle;
            if (!title) return;
            const quizzes = cqGetQuizzes();
            const idx = quizzes.findIndex(q => q.title === title);
            if (idx === -1) return;
            quizzes[idx].difficulty = cqModifyDifficulty;
            const descInput = document.getElementById('cq-modify-description-input');
            if (descInput) quizzes[idx].description = descInput.value.trim();
            localStorage.setItem(CQ_ADMIN_QUIZZES_STORAGE_KEY, JSON.stringify(quizzes));
            const saved = document.getElementById('cq-modify-meta-saved');
            if (saved) {
                saved.classList.remove('hidden');
                setTimeout(() => saved.classList.add('hidden'), 2000);
            }
        }

        // CQ quizzes utils (source unique de vérité)
        let _quizzesLoadedFromFirestore = false;
        function cqGetQuizzes() {
            // Charger depuis Firestore une seule fois au démarrage
            if (!_quizzesLoadedFromFirestore && window.firebaseDB) {
                _quizzesLoadedFromFirestore = true;
                FirestoreSync.load().then(firestoreQuizzes => {
                    if (firestoreQuizzes && firestoreQuizzes.length > 0) {
                        console.log("[CQ] Quizzes chargés depuis Firestore:", firestoreQuizzes.length);
                        localStorage.setItem(CQ_ADMIN_QUIZZES_STORAGE_KEY, JSON.stringify(firestoreQuizzes));
                        // Rafraîchir l'affichage
                        if (typeof cqRenderQuizzes === 'function') {
                            cqRenderQuizzes();
                        }
                    }
                }).catch(err => console.warn("[CQ] Erreur chargement Firestore:", err));
            }

            let stored = localStorage.getItem(CQ_ADMIN_QUIZZES_STORAGE_KEY);
            if (!stored) {
                const defaults = [];
                localStorage.setItem(CQ_ADMIN_QUIZZES_STORAGE_KEY, JSON.stringify(defaults));
                return defaults;
            }
            return JSON.parse(stored);
        }

        function cqRenderQuizzes() {
            const list = document.getElementById('cq-admin-existing-list');
            if (!list) return;
            let quizzes = cqGetQuizzes();
            
            quizzes.sort((a, b) => {
                let comparison = 0;
                if (cqSortCriteria === 'date') comparison = (a.date || '').localeCompare(b.date || '');
                else if (cqSortCriteria === 'alphabetical') comparison = (a.title || '').trim().toLowerCase().localeCompare((b.title || '').trim().toLowerCase());
                else if (cqSortCriteria === 'type') comparison = (a.type || '').trim().toLowerCase().localeCompare((b.type || '').trim().toLowerCase());
                
                if (comparison === 0) comparison = (a.title || '').trim().toLowerCase().localeCompare((b.title || '').trim().toLowerCase());
                return cqSortDirection === 'asc' ? comparison : -comparison;
            });

            if (quizzes.length === 0) {
                list.innerHTML = `<div class="flex items-center justify-center h-full py-12"><p class="text-sm font-button font-medium opacity-40 italic">C'est bien vide ici...</p></div>`;
                return;
            }

            list.innerHTML = quizzes.map(q => {
                const isOnline = q.status === 'online';
                const isTemp = q.status === 'temp';
                const dotClass = isOnline ? 'cq-admin-online-dot' : (isTemp ? 'cq-admin-temp-dot' : 'cq-admin-offline-dot');
                const statusText = isOnline ? 'En ligne' : (isTemp ? 'Fermeture temp.' : 'Hors ligne');
                const safeTitle = escapeHtml(q.title).replace(/'/g, "\\'");
                
                return `
                    <div class="cq-admin-quiz-item p-3 mb-2 rounded-xl bg-white/5 border border-black/5 hover:bg-white/10 hover:border-black/10 transition relative group cursor-pointer" onclick="cqOpenQuizForEditOrView('${safeTitle}')">
                        <div class="block w-full">
                            <div class="cq-admin-quiz-item-top flex justify-between items-start gap-2">
                                <div class="cq-admin-quiz-title font-bold text-xs max-w-[70%] text-[var(--banner-text)]">${escapeHtml(q.title)}</div>
                                <div class="cq-admin-quiz-date text-[9px] opacity-60 font-medium whitespace-nowrap">${escapeHtml(q.date)}</div>
                            </div>
                            <div class="cq-admin-quiz-bottom flex justify-between items-center mt-3">
                                <div class="cq-admin-type-badge">${escapeHtml(q.type || 'QCM')}</div>
                                <div class="flex items-center gap-2">
                                    <div class="cq-admin-online-row flex items-center gap-1">
                                        <span class="${dotClass}"></span>
                                        <span class="cq-admin-online-text text-[8px] font-bold uppercase tracking-wider">${escapeHtml(statusText)}</span>
                                    </div>
                                    <button type="button" 
                                        class="text-[#ef4444] hover:text-red-400 transition p-1 relative z-10" 
                                        data-title="${escapeHtml(q.title)}"
                                        onclick="event.stopPropagation(); cqConfirmDeleteGame(this.dataset.title, event)">
                                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" class="w-3.5 h-3.5">
                                            <path stroke-linecap="round" stroke-linejoin="round" d="m14.74 9-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 0 1-2.244 2.077H8.084a2.25 2.25 0 0 1-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 0 0-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 0 1 3.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0" />
                                        </svg>
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                `;
            }).join('');
        }

        /* --- NOUVELLE FONCTION : Gérer les jeux (Vue liste complète avec status modifier) --- */
        function cqRenderManageGames() {
            const list = document.getElementById('cq-admin-manage-list');
            if (!list) return;

            let quizzes = cqGetQuizzes();
            // Même tri que ci-dessus (allégé visuellement)
            quizzes.sort((a, b) => {
                let comparison = cqSortCriteria === 'date' ? (a.date || '').localeCompare(b.date || '') : 
                                 cqSortCriteria === 'alphabetical' ? (a.title || '').trim().toLowerCase().localeCompare((b.title || '').trim().toLowerCase()) : 
                                 (a.type || '').trim().toLowerCase().localeCompare((b.type || '').trim().toLowerCase());
                if (comparison === 0) comparison = (a.title || '').trim().toLowerCase().localeCompare((b.title || '').trim().toLowerCase());
                return cqSortDirection === 'asc' ? comparison : -comparison;
            });

            if (quizzes.length === 0) {
                list.innerHTML = `<div class="flex items-center justify-center h-full py-12"><p class="text-sm font-button font-medium opacity-40 italic">C'est bien vide ici...</p></div>`;
                return;
            }

            list.innerHTML = quizzes.map((q, idx) => {
                const isOnline = q.status === 'online';
                const isTemp = q.status === 'temp';
                const dotClass = isOnline ? 'cq-admin-online-dot' : (isTemp ? 'cq-admin-temp-dot' : 'cq-admin-offline-dot');
                const statusText = isOnline ? 'En ligne' : (isTemp ? 'Fermeture temporaire' : 'Hors ligne');
                const selectId = `status-select-${idx}`;

                // PLUS DE CLASSE 'cq-admin-quiz-item' ICI = PLUS D'ANIMATION AU SURVOL !
                return `
                    <div class="p-4 mb-3 rounded-xl bg-white/5 border border-black/5 relative flex justify-between items-center flex-wrap gap-4">
                        <div class="flex flex-col gap-2">
                            <div class="flex items-center gap-3">
                                <div class="font-bold text-base text-[var(--banner-text)]">${escapeHtml(q.title)}</div>
                                <div class="cq-admin-type-badge">${escapeHtml(q.type || 'QCM')}</div>
                            </div>
                            <div class="text-[10px] opacity-60 font-medium whitespace-nowrap text-left">Créé le : ${escapeHtml(q.date)}</div>
                        </div>

                        <div class="flex items-center gap-5 flex-wrap">
                            <div class="flex items-center gap-1.5 w-36">
                                <span class="${dotClass}"></span>
                                <span class="cq-admin-online-text text-[9px] font-bold uppercase tracking-wider">${escapeHtml(statusText)}</span>
                            </div>

                            <div class="flex items-center gap-2">
                                <select id="${selectId}" class="bg-[#E8F3ED] border border-[#13211C]/20 rounded-lg px-2 py-1.5 text-xs outline-none font-button font-medium focus:border-red-500 transition text-[#13211C]">
                                    <option value="online" ${isOnline ? 'selected' : ''}>En ligne</option>
                                    <option value="temp" ${isTemp ? 'selected' : ''}>Fermeture temporaire</option>
                                    <option value="offline" ${!isOnline && !isTemp ? 'selected' : ''}>Hors ligne</option>
                                </select>
                                <button type="button" data-title="${escapeHtml(q.title)}" data-select="${selectId}" onclick="cqChangeGameStatus(this.dataset.title, this.dataset.select)" class="bg-[#660000] text-white px-3 py-1.5 rounded-lg text-xs font-bold uppercase font-button transition hover:bg-[#800000]">Valider</button>
                            </div>

                            <button type="button" class="text-[#ef4444] hover:text-red-400 transition p-2 bg-white/5 rounded-lg" data-title="${escapeHtml(q.title)}" onclick="cqConfirmDeleteGame(this.dataset.title, event)">
                                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" class="w-4 h-4"><path stroke-linecap="round" stroke-linejoin="round" d="m14.74 9-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 0 1-2.244 2.077H8.084a2.25 2.25 0 0 1-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 0 0-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 0 1 3.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0" /></svg>
                            </button>
                        </div>
                    </div>
                `;
            }).join('');
        }

        let cqPendingStatusChange = null;

        function cqStatusLabel(status) {
            if (status === 'online') return 'En ligne';
            if (status === 'temp') return 'Fermeture temporaire';
            return 'Hors ligne';
        }

        function cqStatusBadgeHtml(status) {
            const dotClass = status === 'online' ? 'cq-admin-online-dot' : (status === 'temp' ? 'cq-admin-temp-dot' : 'cq-admin-offline-dot');
            const label = cqStatusLabel(status);
            return `<span class="${dotClass}" style="display:inline-block;margin-right:0.35rem;"></span><span class="font-bold text-xs uppercase" style="font-family:'Datatype',monospace;letter-spacing:0.04em;">${label}</span>`;
        }

        function cqChangeGameStatus(title, selectId) {
            const selectEl = document.getElementById(selectId);
            if (!selectEl) return;
            const newStatus = selectEl.value;

            const quizzes = cqGetQuizzes();
            const idx = quizzes.findIndex(q => q.title === title);
            if (idx === -1) return;

            const currentStatus = quizzes[idx].status;
            if (currentStatus === newStatus) return;

            cqPendingStatusChange = { title, newStatus, selectId };

            // Remplir la modale dédiée
            const nameEl = document.getElementById('change-status-quiz-name');
            if (nameEl) nameEl.textContent = title;

            const fromBadge = document.getElementById('change-status-from-badge');
            if (fromBadge) fromBadge.innerHTML = cqStatusBadgeHtml(currentStatus);

            const toBadge = document.getElementById('change-status-to-badge');
            if (toBadge) toBadge.innerHTML = cqStatusBadgeHtml(newStatus);

            const descEl = document.getElementById('change-status-description');
            if (descEl) {
                const descs = {
                    'online': 'Le quiz sera visible et jouable par tous les joueurs.',
                    'temp': 'Le quiz sera visible mais affiché comme temporairement fermé.',
                    'offline': 'Le quiz sera masqué et inaccessible aux joueurs.'
                };
                descEl.textContent = descs[newStatus] || '';
            }

            const modal = document.getElementById('modal-change-status-confirm');
            if (modal) { modal.classList.remove('hidden'); playSound('modal-open'); }
            const mainContent = document.getElementById('main-content');
            if (mainContent) mainContent.classList.add('blur-bg');
        }

        function closeChangeStatusConfirm() {
            playSound('modal-close');
            const modal = document.getElementById('modal-change-status-confirm');
            if (modal) modal.classList.add('hidden');
            const mainContent = document.getElementById('main-content');
            if (mainContent) mainContent.classList.remove('blur-bg');
            cqPendingStatusChange = null;
        }

        function executeChangeStatus() {
            if (!cqPendingStatusChange) return;
            const { title, newStatus } = cqPendingStatusChange;
            const quizzes = cqGetQuizzes();
            const idx = quizzes.findIndex(q => q.title === title);
            if (idx > -1) {
                quizzes[idx].status = newStatus;
                localStorage.setItem(CQ_ADMIN_QUIZZES_STORAGE_KEY, JSON.stringify(quizzes));
                playSound('action-confirm');
                cqRenderManageGames();
                cqRenderQuizzes();
                cqSyncPlayerViews();
            }
            closeChangeStatusConfirm();
        }

        function executeDeleteGame() {
            if (!cqGameToDelete) return;
            const quizzes = cqGetQuizzes();
            const quiz = quizzes.find(q => q.title === cqGameToDelete);
            
            if (quiz?.status === 'online') {
                const modal = document.getElementById('modal-cq-delete-online');
                if (modal) { playSound('modal-open'); modal.classList.remove('hidden'); }
                return;
            }

            const updated = quizzes.filter(q => q.title !== cqGameToDelete);
            localStorage.setItem(CQ_ADMIN_QUIZZES_STORAGE_KEY, JSON.stringify(updated));
            cqRemoveQuizFromAllCategories(cqGameToDelete);

            cqRenderQuizzes();
            cqRenderManageGames();
            closeDeleteGameConfirm();
        }

        function cqInitCreationRightCard() {
            try {
                console.log('[CQ] cqInitCreationRightCard()');
                const list = document.getElementById('cq-admin-existing-list');
                if (list) list.classList.remove('hidden');
                cqRenderQuizzes();

                const titleInput = document.getElementById('cq-game-title-input');
                if (titleInput && !titleInput.dataset.bound) titleInput.dataset.bound = '1';

                document.getElementById('cq-right-newgame')?.classList.remove('hidden');
                document.getElementById('cq-right-newgame').style.display = 'flex';

                ['cq-right-coming', 'cq-right-modify', 'cq-right-characteristics', 'cq-right-editor'].forEach(id => {
                    const el = document.getElementById(id);
                    if (el) { el.classList.add('hidden'); el.style.display = 'none'; }
                });
            } catch (err) {
                console.error('[CQ] cqInitCreationRightCard() failed:', err);
            }
        }

        function cqStartNewGameCreation() {
            try {
                console.log('[CQ] cqStartNewGameCreation() click');
                const input = document.getElementById('cq-game-title-input');
                if (input) input.value = '';
                document.getElementById('cq-game-title-placeholder')?.classList.remove('hidden');
                document.getElementById('cq-game-title-error')?.classList.add('hidden');

                cqSelectedModeVal = null;
                cqSelectedDifficulty = 0;
                cqRenderStars('cq-difficulty-stars', 0);
                const descCreate = document.getElementById('cq-game-description-input');
                if (descCreate) descCreate.value = '';
                const label = document.getElementById('cq-mode-dropdown-label');
                if (label) label.textContent = 'Choisir un mode de jeu';

                // Montre uniquement l’écran "caractéristiques" (formulaire)
                ['cq-right-newgame', 'cq-right-coming', 'cq-right-modify', 'cq-right-editor'].forEach(id => {
                    const el = document.getElementById(id);
                    if (el) { el.classList.add('hidden'); el.style.display = 'none'; }
                });

                const characteristics = document.getElementById('cq-right-characteristics');
                if (characteristics) {
                    characteristics.classList.remove('hidden');
                    characteristics.style.display = 'flex';
                } else {
                    const newgame = document.getElementById('cq-right-newgame');
                    if (newgame) {
                        newgame.classList.remove('hidden');
                        newgame.style.display = 'flex';
                    }
                }

                cqValidateFormState();
            } catch (err) {
                console.error('[CQ] cqStartNewGameCreation() failed:', err);
            }
        }

        function cqSaveDraft() {
            if (!cqValidateDraft(true)) return;

            const title = cqGetCurrentEditingQuizTitle();
            if (!title) return;

            const quizzes = cqGetQuizzes();

            if (!cqIsModifyingExisting && cqPendingNewQuiz) {
                // Première validation : on crée réellement l'entrée maintenant.
                const dup = quizzes.some(q => (q.title || '').trim().toLowerCase() === cqPendingNewQuiz.title.toLowerCase());
                if (dup) return;

                const today = new Date().toISOString().split('T')[0];
                quizzes.unshift({
                    title: cqPendingNewQuiz.title,
                    date: today,
                    status: 'offline',
                    type: cqPendingNewQuiz.type,
                    difficulty: cqPendingNewQuiz.difficulty || 0,
                    description: cqPendingNewQuiz.description || '',
                    content: { slides: cqQuizDraft.slides }
                });
                cqPendingNewQuiz = null;
            } else {
                const idx = quizzes.findIndex(q => q.title === title);
                if (idx === -1) return;

                quizzes[idx].content = { slides: cqQuizDraft.slides };
                if (!quizzes[idx].status || quizzes[idx].status === 'online') {
                    quizzes[idx].status = 'offline';
                }
            }

            localStorage.setItem(CQ_ADMIN_QUIZZES_STORAGE_KEY, JSON.stringify(quizzes));

            cqRenderQuizzes();
            cqRenderManageGames();

            // Retour à l'écran d'accueil de la carte de création
            const editor = document.getElementById('cq-right-editor');
            if (editor) {
                editor.classList.add('hidden');
                editor.style.display = 'none';
            }
            const coming = document.getElementById('cq-right-coming');
            if (coming) {
                coming.classList.remove('hidden');
                coming.style.display = 'flex';
            }

            cqSetCurrentEditingQuizTitle(null);
        }

        function cqToggleModeDropdown() {
            const menu = document.getElementById('cq-mode-dropdown-menu');
            const chevron = document.getElementById('cq-mode-dropdown-chevron');
            if (menu) {
                if (menu.style.display === 'block') {
                    menu.style.display = 'none';
                    if (chevron) chevron.classList.remove('rotate-180');
                } else {
                    menu.style.display = 'block';
                    if (chevron) chevron.classList.add('rotate-180');
                }
            }
        }

        const CQ_WIP_MODES = ['Quiz Images', 'Quiz Audio'];
        // Question Rédaction and JetPunk are NOT in WIP — they are functional modes.

        function cqSelectMode(mode) {
            // 'Quiz Rédaction' is the display name for the 'Question Rédaction' mode
            const displayMode = mode;
            if (mode === 'Quiz Rédaction') mode = 'Question Rédaction';
            cqSelectedModeVal = mode;
            const label = document.getElementById('cq-mode-dropdown-label');
            if (label) {
                label.textContent = displayMode;
            }
            const menu = document.getElementById('cq-mode-dropdown-menu');
            const chevron = document.getElementById('cq-mode-dropdown-chevron');
            if (menu) {
                menu.style.display = 'none';
            }
            if (chevron) {
                chevron.classList.remove('rotate-180');
            }
            const wipMsg = document.getElementById('cq-mode-wip-message');
            if (wipMsg) {
                if (CQ_WIP_MODES.includes(mode)) {
                    wipMsg.classList.remove('hidden');
                } else {
                    wipMsg.classList.add('hidden');
                }
            }
            cqValidateFormState();
        }

        function cqUpdateTitlePlaceholder() {
            const input = document.getElementById('cq-game-title-input');
            const placeholder = document.getElementById('cq-game-title-placeholder');
            if (input && placeholder) {
                if (input.value.length > 0) {
                    placeholder.classList.add('hidden');
                } else {
                    placeholder.classList.remove('hidden');
                }
            }
            cqValidateFormState();
        }

        function cqValidateFormState() {
            const input = document.getElementById('cq-game-title-input');
            const btn = document.getElementById('cq-valider-btn');
            const errorEl = document.getElementById('cq-game-title-error');
            
            if (!input || !btn) return;
            
            const titleVal = input.value.trim();
            const modeSelected = cqSelectedModeVal !== null;
            
            const quizzes = cqGetQuizzes();
            const existingTitles = quizzes.map(q => q.title.trim().toLowerCase());
            const isDuplicate = existingTitles.includes(titleVal.toLowerCase());
            
            const isWipMode = cqSelectedModeVal !== null && CQ_WIP_MODES.includes(cqSelectedModeVal);
            const isValid = titleVal.length > 0 && !isDuplicate && modeSelected && !isWipMode;
            
            if (errorEl) {
                if (titleVal.length > 0 && isDuplicate) {
                    errorEl.classList.remove('hidden');
                } else {
                    errorEl.classList.add('hidden');
                }
            }
            
            if (isValid) {
                btn.removeAttribute('disabled');
                btn.classList.remove('opacity-50', 'cursor-not-allowed');
                btn.classList.add('hover:bg-[#800000]', 'cursor-pointer');
            } else {
                btn.setAttribute('disabled', 'true');
                btn.classList.add('opacity-50', 'cursor-not-allowed');
                btn.classList.remove('hover:bg-[#800000]', 'cursor-pointer');
            }
        }

        function cqCloseDeleteOnlineModal() {
            playSound('modal-close');
            const modal = document.getElementById('modal-cq-delete-online');
            if (modal) modal.classList.add('hidden');
            const mainContent = document.getElementById('main-content');
            if (mainContent) mainContent.classList.remove('blur-bg');
        }

        function cqConfirmDeleteGame(title, event) {
            if (event) {
                event.preventDefault();
                event.stopPropagation();
            }
            cqGameToDelete = title;

            const quizzes = cqGetQuizzes();
            const quiz = quizzes.find(q => q.title === title);
            const isOnline = quiz?.status === 'online';

            if (isOnline) {
                const modal = document.getElementById('modal-cq-delete-online');
                if (modal) { playSound('modal-open'); modal.classList.remove('hidden'); }
                const mainContent = document.getElementById('main-content');
                if (mainContent) mainContent.classList.add('blur-bg');
                return;
            }

            const textEl = document.getElementById('delete-game-confirm-text');
            if (textEl) {
                textEl.textContent = `Voulez-vous vraiment supprimer le jeu "${title}" ? Cette action est irréversible.`;
            }
            const modal = document.getElementById('modal-delete-game-confirm');
            if (modal) {
                playSound('modal-open');
                modal.classList.remove('hidden');
            }
            const mainContent = document.getElementById('main-content');
            if (mainContent) {
                mainContent.classList.add('blur-bg');
            }
        }

        function closeDeleteGameConfirm() {
            playSound('modal-close');
            cqGameToDelete = null;
            const modal = document.getElementById('modal-delete-game-confirm');
            if (modal) {
                modal.classList.add('hidden');
            }
            const mainContent = document.getElementById('main-content');
            if (mainContent) {
                mainContent.classList.remove('blur-bg');
            }
        }

        function executeDeleteGame() {
            if (!cqGameToDelete) return;
            const quizzes = cqGetQuizzes();
            const quiz = quizzes.find(q => q.title === cqGameToDelete);
            
            if (quiz?.status === 'online') {
                const modal = document.getElementById('modal-cq-delete-online');
                if (modal) { playSound('modal-open'); modal.classList.remove('hidden'); }
                return;
            }

            const updated = quizzes.filter(q => q.title !== cqGameToDelete);
            localStorage.setItem(CQ_ADMIN_QUIZZES_STORAGE_KEY, JSON.stringify(updated));
            cqRemoveQuizFromAllCategories(cqGameToDelete);

            cqRenderQuizzes();
            cqRenderManageGames();
            closeDeleteGameConfirm();
        }

        function cqExitModifyToComing() {
            document.getElementById('cq-right-modify').classList.add('hidden');
            document.getElementById('cq-right-modify').style.display = 'none';

            const coming = document.getElementById('cq-right-coming');
            if (coming) {
                coming.classList.remove('hidden');
                coming.style.display = 'flex';
            }
            cqSetCurrentEditingQuizTitle(null);
        }

        function cqOpenQuizForEditOrView(title) {
            const quiz = cqFindQuizByTitle(title);
            if (!quiz) return;

            ['cq-right-newgame', 'cq-right-coming', 'cq-right-characteristics', 'cq-right-editor'].forEach(id => {
                const el = document.getElementById(id);
                if (el) { el.classList.add('hidden'); el.style.display = 'none'; }
            });

            const modify = document.getElementById('cq-right-modify');
            if (modify) {
                modify.classList.remove('hidden');
                modify.style.display = 'flex';
            }

            const titleInput = document.getElementById('cq-modify-title-input');
            if (titleInput) titleInput.value = quiz.title || '';

            // On réinitialise les messages d'erreur/blocage à chaque ouverture :
            // ils ne doivent apparaître que lorsque l'action correspondante est tentée.
            const onlineBlocked = document.getElementById('cq-modify-online-rename-blocked');
            if (onlineBlocked) onlineBlocked.classList.add('hidden');

            const renameErr = document.getElementById('cq-modify-rename-error');
            if (renameErr) renameErr.classList.add('hidden');

            const editBlocked = document.getElementById('cq-modify-online-edit-blocked');
            if (editBlocked) editBlocked.classList.add('hidden');

            cqSetCurrentEditingQuizTitle(quiz.title);
            cqOriginalQuizTitle = quiz.title;
            cqBindEditorEventsOnce();

            // Charger difficulté et description
            cqModifyDifficulty = quiz.difficulty || 0;
            cqRenderStars('cq-modify-difficulty-stars', cqModifyDifficulty);
            const descInput = document.getElementById('cq-modify-description-input');
            if (descInput) descInput.value = quiz.description || '';
            const saved = document.getElementById('cq-modify-meta-saved');
            if (saved) saved.classList.add('hidden');
        }

        function cqRenameFromModify() {
            const quiz = cqFindQuizByTitle(cqOriginalQuizTitle);
            if (!quiz) return;

            const onlineBlocked = document.getElementById('cq-modify-online-rename-blocked');

            if (quiz.status === 'online') {
                if (onlineBlocked) onlineBlocked.classList.remove('hidden');
                return;
            }
            if (onlineBlocked) onlineBlocked.classList.add('hidden');

            const input = document.getElementById('cq-modify-title-input');
            const errEl = document.getElementById('cq-modify-rename-error');
            const newTitle = input.value.trim();
            
            if (!newTitle || newTitle === cqOriginalQuizTitle) {
                if (errEl) errEl.classList.add('hidden');
                return;
            }

            const quizzes = cqGetQuizzes();
            const lower = newTitle.toLowerCase();
            const duplicate = quizzes.some(q => (q.title || '').trim().toLowerCase() === lower);
            
            if (duplicate) {
                if (errEl) {
                    errEl.textContent = 'Ce titre existe déjà.';
                    errEl.classList.remove('hidden');
                }
                return;
            }
            if (errEl) errEl.classList.add('hidden');

            const idx = quizzes.findIndex(q => q.title === cqOriginalQuizTitle);
            if (idx > -1) {
                const previousTitle = cqOriginalQuizTitle;
                quizzes[idx].title = newTitle;
                localStorage.setItem(CQ_ADMIN_QUIZZES_STORAGE_KEY, JSON.stringify(quizzes));
                cqRenameQuizInCategories(previousTitle, newTitle);
                
                cqOriginalQuizTitle = newTitle;
                cqSetCurrentEditingQuizTitle(newTitle);
                
                cqRenderQuizzes();
                cqRenderManageGames();
            }
        }

        function cqOpenEditorFromModify() {
            const title = cqGetCurrentEditingQuizTitle();
            const quiz = cqFindQuizByTitle(title);
            if (!quiz) return;

            if (quiz.status === 'online') {
                const err = document.getElementById('cq-modify-online-edit-blocked');
                if (err) err.classList.remove('hidden');
                return;
            }

            document.getElementById('cq-right-modify').classList.add('hidden');
            document.getElementById('cq-right-modify').style.display = 'none';

            const editor = document.getElementById('cq-right-editor');
            if (editor) {
                editor.classList.remove('hidden');
                editor.style.display = 'flex';
            }

            // Réinitialiser le quiz en attente pour que cqGetCurrentEditingMode()
            // retourne le type du quiz existant (ex: JetPunk) et non celui d'un
            // nouveau quiz abandonné en cours de création.
            cqPendingNewQuiz = null;

            cqLoadQuizIntoDraft(quiz);
            cqIsModifyingExisting = true;
            cqSetEditorMode('offline_edit');
            cqRenderAllEditor();
        }

        // Close dropdown when clicking outside
        window.addEventListener('click', (event) => {
            const trigger = document.getElementById('cq-mode-dropdown-trigger');
            const menu = document.getElementById('cq-mode-dropdown-menu');
            const chevron = document.getElementById('cq-mode-dropdown-chevron');
            if (menu && menu.style.display === 'block') {
                if (trigger && !trigger.contains(event.target) && !menu.contains(event.target)) {
                    menu.style.display = 'none';
                    if (chevron) chevron.classList.remove('rotate-180');
                }
            }
        });

        function cqOpenFilterModal() {
            playSound('modal-open');
            const criteriaSelect = document.getElementById('cq-filter-criteria');
            const directionSelect = document.getElementById('cq-filter-direction');
            if (criteriaSelect) criteriaSelect.value = cqSortCriteria;
            if (directionSelect) directionSelect.value = cqSortDirection;

            const modal = document.getElementById('modal-cq-filter');
            if (modal) modal.classList.remove('hidden');
            const mainContent = document.getElementById('main-content');
            if (mainContent) mainContent.classList.add('blur-bg');
        }

        function closeCqFilterModal() {
            playSound('modal-close');
            const modal = document.getElementById('modal-cq-filter');
            if (modal) modal.classList.add('hidden');
            const mainContent = document.getElementById('main-content');
            if (mainContent) mainContent.classList.remove('blur-bg');
        }

        function cqApplyFilters() {
            const criteriaSelect = document.getElementById('cq-filter-criteria');
            const directionSelect = document.getElementById('cq-filter-direction');
            if (criteriaSelect) cqSortCriteria = criteriaSelect.value;
            if (directionSelect) cqSortDirection = directionSelect.value;
            
            cqRenderQuizzes();
            cqRenderManageGames();
            closeCqFilterModal();
        }

        // Initial header state sync
        updateHeaderAuthState();

        /* =========================
           CQ ADMIN - QUIZ CREATION (CONTENT / DRAFT / EDITOR)
           ========================= */

        const CQ_ADMIN_QUIZ_CONTENT_KEY = 'content';

        // In-memory draft
        // slides: [{ questionText: string, answers: [{ text: string, isCorrect: boolean }] }]
        let cqQuizDraft = {
            slides: [],
            slideIndex: 0,
        };

        function cqDefaultSlide() {
            return {
                questionText: '',
                questionImage: null,
                questionAudio: null,
                answers: [
                    { text: '', isCorrect: false, imageData: null, audioData: null },
                    { text: '', isCorrect: false, imageData: null, audioData: null }
                ]
            };
        }

        function cqGetCurrentEditingMode() {
            // Returns the type (e.g. 'QCM', 'Quiz Images') of the quiz being edited/created.
            if (cqPendingNewQuiz && cqPendingNewQuiz.type) return cqPendingNewQuiz.type;
            const title = cqGetCurrentEditingQuizTitle();
            if (title) {
                const q = cqFindQuizByTitle(title);
                if (q && q.type) return q.type;
            }
            return cqSelectedModeVal || 'QCM';
        }

        function cqDraftReset() {
            cqQuizDraft = {
                slides: [cqDefaultSlide()],
                slideIndex: 0
            };
        }

        function cqDraftClamp() {
            if (!Array.isArray(cqQuizDraft.slides)) cqQuizDraft.slides = [];
            if (cqQuizDraft.slides.length === 0) cqQuizDraft.slides = [cqDefaultSlide()];
            if (typeof cqQuizDraft.slideIndex !== 'number') cqQuizDraft.slideIndex = 0;
            cqQuizDraft.slideIndex = Math.max(0, Math.min(cqQuizDraft.slideIndex, cqQuizDraft.slides.length - 1));
        }

        function cqDraftGetCurrentSlide() {
            cqDraftClamp();
            return cqQuizDraft.slides[cqQuizDraft.slideIndex];
        }

        function cqNormalizeQuizContent(maybeContent) {
            // Migration à la volée if missing
            if (!maybeContent || typeof maybeContent !== 'object') {
                return { slides: [cqDefaultSlide()] };
            }

            let slides = Array.isArray(maybeContent.slides) ? maybeContent.slides : null;
            if (!slides || slides.length === 0) slides = [cqDefaultSlide()];

            // Ensure shape for each slide
            const normalizedSlides = slides.map(s => {
                const qText = typeof s?.questionText === 'string' ? s.questionText : '';
                let answers = Array.isArray(s?.answers) ? s.answers : null;
                const hasExistingContent = answers && answers.length > 0 && answers.some(a => (a.text || '').trim() || a.isCorrect);
                if (!answers || (answers.length < 2 && !hasExistingContent)) {
                    answers = [
                        { text: '', isCorrect: false },
                        { text: '', isCorrect: false }
                    ];
                }
                // clamp answers to 6, minimum 2 (only pad if no meaningful content)
                answers = answers.slice(0, 6);
                if (!hasExistingContent) {
                    while (answers.length < 2) answers.push({ text: '', isCorrect: false });
                }

                // normalize each answer
                const normalizedAnswers = answers.map(a => ({
                    text: typeof a?.text === 'string' ? a.text : '',
                    isCorrect: !!a?.isCorrect,
                    imageData: (typeof a?.imageData === 'string' && a.imageData) ? a.imageData : null,
                    audioData: (typeof a?.audioData === 'string' && a.audioData) ? a.audioData : null
                }));

                return {
                    questionText: qText,
                    questionImage: (typeof s?.questionImage === 'string' && s.questionImage) ? s.questionImage : null,
                    questionAudio: (typeof s?.questionAudio === 'string' && s.questionAudio) ? s.questionAudio : null,
                    answers: normalizedAnswers
                };
            });

            return { slides: normalizedSlides };
        }

        // (cqGetQuizzes unifié plus haut)

        // Override previous cqGetQuizzes() usage by ensuring function exists now.
        // (script already declared cqGetQuizzes earlier; this will overwrite in the same scope if later.)
        // eslint-disable-next-line no-inner-declarations
        const _cqOldCqGetQuizzes = null;

        function cqGetCurrentEditingQuizTitle() {
            return sessionStorage.getItem('cq_admin_current_edit_title') || null;
        }

        function cqSetCurrentEditingQuizTitle(title) {
            if (!title) sessionStorage.removeItem('cq_admin_current_edit_title');
            else sessionStorage.setItem('cq_admin_current_edit_title', title);
        }

        function cqExitEditorToComing() {
            const coming = document.getElementById('cq-right-coming');
            if (coming) {
                coming.classList.remove('hidden');
                coming.style.display = 'flex';
            }

            const ed = document.getElementById('cq-right-editor');
            if (ed) {
                ed.classList.add('hidden');
                ed.style.display = 'none';
            }
            cqPendingNewQuiz = null;
            cqSetCurrentEditingQuizTitle(null);
        }

        function cqSetEditorMode(mode) {
            // mode: 'offline_edit' | 'online_lock' | 'draft_only'
            const isLocked = mode === 'online_lock';

            const lockBadge = document.getElementById('cq-editor-lock-badge');
            const deleteBtn = document.getElementById('cq-delete-current-diapo-btn');
            const addAnswerBtn = document.getElementById('cq-add-answer-btn');
            const addDiapoBtn = document.getElementById('cq-add-diapo-btn');
            const createBtn = document.getElementById('cq-create-quiz-btn');
            const questionInput = document.getElementById('cq-question-text-input');

            if (lockBadge) lockBadge.classList.toggle('hidden', !isLocked);

            if (deleteBtn) deleteBtn.classList.toggle('hidden', isLocked);
            if (addAnswerBtn) addAnswerBtn.disabled = isLocked;
            if (addDiapoBtn) addDiapoBtn.disabled = isLocked;

            if (questionInput) questionInput.disabled = isLocked;

            // always disable all inputs in answers list when locked
            document.querySelectorAll('#cq-answers-list input, #cq-answers-list button').forEach(el => {
                el.disabled = isLocked;
            });

            // create button only for editable offline draft
            if (createBtn) createBtn.disabled = isLocked;
        }

        function cqRenderSlidesStrip() {
            const strip = document.getElementById('cq-slides-strip');
            const hint = document.getElementById('cq-slides-empty-hint');
            if (!strip) return;

            cqDraftClamp();
            const slides = cqQuizDraft.slides;

            if (!slides.length) {
                if (hint) hint.classList.remove('hidden');
                strip.innerHTML = '';
                return;
            }
            if (hint) hint.classList.add('hidden');

            strip.innerHTML = slides.map((s, idx) => {
                const active = idx === cqQuizDraft.slideIndex;
                const label = (s.questionText || '').trim() ? (s.questionText || '').trim() : `Diapo ${idx + 1}`;
                const safeLabel = escapeHtml(label);

                return `
                    <button
                        type="button"
                        class="cq-slide-chip ${active ? 'cq-slide-chip-active' : ''}"
                        data-slide-index="${idx}"
                        onclick="cqSelectSlide(${idx})"
                        draggable="true"
                        ondragstart="cqOnSlideDragStart(event, ${idx})"
                        ondragover="cqOnSlideDragOver(event)"
                        ondrop="cqOnSlideDrop(event, ${idx})"
                    >
                        <span class="cq-slide-chip-label">${safeLabel}</span>
                        <span class="cq-slide-chip-index">#${idx + 1}</span>
                    </button>
                `;
            }).join('');
        }

        function cqToggleCorrectAnswer(answerIndex) {
            const slide = cqDraftGetCurrentSlide();
            // On inverse juste la valeur, SANS forcer à un seul choix
            slide.answers[answerIndex].isCorrect = !slide.answers[answerIndex].isCorrect;
            cqRenderAnswersEditor();
        }
        
        function cqAskDeleteAnswer(answerIndex) {
            const slide = cqDraftGetCurrentSlide();
            if (slide.answers.length <= 2) return;
            slide.answers.splice(answerIndex, 1);
            cqRenderAnswersEditor();
        }

        function cqRenderAnswersEditor() {
            const slide = cqDraftGetCurrentSlide();
            const list = document.getElementById('cq-answers-list');
            if (!list) return;

            const questionInput = document.getElementById('cq-question-text-input');
            if (questionInput && questionInput.value !== slide.questionText) {
                questionInput.value = slide.questionText || '';
            }

            const locked = document.getElementById('cq-add-answer-btn')?.disabled;

            // --- Question media section ---
            const qMediaContainer = document.getElementById('cq-question-media-editor');
            if (qMediaContainer) {
                const hasQImg = !!slide.questionImage;
                const hasQAudio = !!slide.questionAudio;
                qMediaContainer.innerHTML = `
                    <div class="cqed-question-media-row">
                        <div class="cqed-question-media-item">
                            <span class="cqed-label" style="font-size:0.65rem;">Image question</span>
                            ${hasQImg ? `<img src="${slide.questionImage}" class="cqed-question-img-preview" alt="Image question">` : ''}
                            <div class="cqed-question-media-actions">
                                <button type="button" class="cqed-answer-img-upload-btn" onclick="document.getElementById('cq-question-img-input').click()" ${locked ? 'disabled' : ''}>${hasQImg ? 'Remplacer' : 'Ajouter une image'}</button>
                                ${hasQImg ? `<button type="button" class="cqed-answer-img-remove-btn" onclick="cqRemoveQuestionImage()" ${locked ? 'disabled' : ''}>Supprimer</button>` : ''}
                            </div>
                            <input type="file" accept="image/*" class="hidden" id="cq-question-img-input" onchange="cqHandleQuestionImageUpload(this)">
                        </div>
                        <div class="cqed-question-media-item">
                            <span class="cqed-label" style="font-size:0.65rem;">Audio question</span>
                            ${hasQAudio ? `<div class="cqed-audio-preview"><audio controls src="${slide.questionAudio}" style="height:28px;width:100%;"></audio></div>` : ''}
                            <div class="cqed-question-media-actions">
                                <button type="button" class="cqed-answer-img-upload-btn" onclick="document.getElementById('cq-question-audio-input').click()" ${locked ? 'disabled' : ''}>${hasQAudio ? 'Remplacer' : 'Ajouter un audio'}</button>
                                ${hasQAudio ? `<button type="button" class="cqed-answer-img-remove-btn" onclick="cqRemoveQuestionAudio()" ${locked ? 'disabled' : ''}>Supprimer</button>` : ''}
                            </div>
                            <input type="file" accept="audio/*" class="hidden" id="cq-question-audio-input" onchange="cqHandleQuestionAudioUpload(this)">
                        </div>
                    </div>
                `;
            }

            list.innerHTML = slide.answers.map((a, idx) => {
                const isCorrect = !!a.isCorrect;
                const deleteBtn = idx >= 2 ? `
                    <button type="button" class="cqed-answer-delete" onclick="cqAskDeleteAnswer(${idx})" title="Supprimer cette réponse" ${locked ? 'disabled' : ''}>✕</button>` : '';
                const toggleBtn = `
                    <button type="button" class="cqed-answer-toggle ${isCorrect ? 'is-correct' : ''}" onclick="cqToggleCorrectAnswer(${idx})" title="Marquer comme bonne réponse" ${locked ? 'disabled' : ''}>
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="3" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12.75l6 6 9-13.5" /></svg>
                    </button>`;

                // QCM unifié : texte + image + audio (tous optionnels mais au moins un requis)
                const safeText = escapeHtml(a.text);
                const hasImg = !!a.imageData;
                const hasAudio = !!a.audioData;
                return `
                    <div class="cqed-answer-card ${isCorrect ? 'is-correct' : ''}" data-answer-index="${idx}">
                        <div class="cqed-answer-main-row">
                            ${toggleBtn}
                            <input type="text" class="cqed-answer-input" value="${safeText}" placeholder="Réponse ${idx + 1}" oninput="cqUpdateAnswerText(${idx}, this.value)" ${locked ? 'disabled' : ''} />
                            ${deleteBtn}
                        </div>
                        <div class="cqed-answer-media-row">
                            <div class="cqed-answer-media-item">
                                ${hasImg ? `<img src="${a.imageData}" class="cqed-answer-media-preview-img" alt="">` : ''}
                                <div class="cqed-answer-media-actions">
                                    <button type="button" class="cqed-answer-media-btn" onclick="document.getElementById('cq-answer-img-input-${idx}').click()" ${locked ? 'disabled' : ''}>🖼 ${hasImg ? 'Remplacer' : 'Image'}</button>
                                    ${hasImg ? `<button type="button" class="cqed-answer-media-btn cqed-answer-media-btn-del" onclick="cqRemoveAnswerImage(${idx})" ${locked ? 'disabled' : ''}>✕</button>` : ''}
                                </div>
                                <input type="file" accept="image/*" class="hidden" id="cq-answer-img-input-${idx}" onchange="cqHandleAnswerImageUpload(${idx}, this)">
                            </div>
                            <div class="cqed-answer-media-item">
                                ${hasAudio ? `<audio controls src="${a.audioData}" style="height:24px;width:100%;margin-top:2px;"></audio>` : ''}
                                <div class="cqed-answer-media-actions">
                                    <button type="button" class="cqed-answer-media-btn" onclick="cqTriggerAnswerAudioUpload(${idx})" ${locked ? 'disabled' : ''}>🔊 ${hasAudio ? 'Remplacer' : 'Audio'}</button>
                                    ${hasAudio ? `<button type="button" class="cqed-answer-media-btn cqed-answer-media-btn-del" onclick="cqRemoveAnswerAudio(${idx})" ${locked ? 'disabled' : ''}>✕</button>` : ''}
                                </div>
                                <input type="file" accept="audio/*" class="hidden" id="cq-answer-audio-input-${idx}" onchange="cqHandleAnswerAudioUpload(${idx}, this)">
                            </div>
                        </div>
                    </div>
                `;
            }).join('');
            
            // Mise à jour du texte du bouton principal selon le mode
            const btn = document.getElementById('cq-create-quiz-btn');
            if (btn) {
                btn.textContent = cqIsModifyingExisting ? 'Valider les modifications' : 'Créer le quiz';
            }

            cqUpdateEditorCreateButtonState();
        }

        // --- Question media handlers ---
        function cqHandleQuestionImageUpload(input) {
            const file = input.files && input.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = (e) => {
                const slide = cqDraftGetCurrentSlide();
                slide.questionImage = e.target.result;
                cqRenderAnswersEditor();
            };
            reader.readAsDataURL(file);
        }
        function cqRemoveQuestionImage() {
            const slide = cqDraftGetCurrentSlide();
            slide.questionImage = null;
            cqRenderAnswersEditor();
        }
        function cqHandleQuestionAudioUpload(input) {
            const file = input.files && input.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = (e) => {
                const slide = cqDraftGetCurrentSlide();
                slide.questionAudio = e.target.result;
                cqRenderAnswersEditor();
            };
            reader.readAsDataURL(file);
        }
        function cqRemoveQuestionAudio() {
            const slide = cqDraftGetCurrentSlide();
            slide.questionAudio = null;
            cqRenderAnswersEditor();
        }

        // --- Answer audio handlers ---
        function cqTriggerAnswerAudioUpload(idx) {
            const input = document.getElementById(`cq-answer-audio-input-${idx}`);
            if (input) input.click();
        }
        function cqHandleAnswerAudioUpload(idx, input) {
            const file = input.files && input.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = (e) => {
                const slide = cqDraftGetCurrentSlide();
                if (slide.answers[idx]) {
                    slide.answers[idx].audioData = e.target.result;
                    cqRenderAnswersEditor();
                }
            };
            reader.readAsDataURL(file);
        }
        function cqRemoveAnswerAudio(idx) {
            const slide = cqDraftGetCurrentSlide();
            if (slide.answers[idx]) {
                slide.answers[idx].audioData = null;
                cqRenderAnswersEditor();
            }
        }

        function cqTriggerAnswerImageUpload(idx) {
            const input = document.getElementById(`cq-answer-img-input-${idx}`);
            if (input) input.click();
        }

        function cqHandleAnswerImageUpload(idx, input) {
            const file = input.files && input.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = (e) => {
                const slide = cqDraftGetCurrentSlide();
                if (slide.answers[idx]) {
                    slide.answers[idx].imageData = e.target.result;
                    cqRenderAnswersEditor();
                }
            };
            reader.readAsDataURL(file);
        }

        function cqRemoveAnswerImage(idx) {
            const slide = cqDraftGetCurrentSlide();
            if (slide.answers[idx]) {
                slide.answers[idx].imageData = null;
                cqRenderAnswersEditor();
            }
        }

        function cqUpdateEditorCreateButtonState() {
            const btn = document.getElementById('cq-create-quiz-btn');
            const hint = document.getElementById('cq-validation-hint');
            if (!btn || !hint) return;

            const ok = cqValidateDraft(true);
            btn.disabled = !ok;
            hint.classList.toggle('hidden', ok);
        }

        function cqValidateDraft(showHints) {
            cqDraftClamp();
            const slides = cqQuizDraft.slides;

            let allOk = true;
            if (slides.length < 1) allOk = false;

            for (let i = 0; i < slides.length; i++) {
                const slide = slides[i];
                const qText = (slide.questionText || '').trim();
                const answers = Array.isArray(slide.answers) ? slide.answers : [];

                // Question : texte obligatoire
                if (!qText) allOk = false;

                if (answers.length < 2 || answers.length > 6) allOk = false;

                let correctCount = 0;
                for (let a of answers) {
                    // Réponse valide si au moins un élément parmi texte, image ou audio
                    const hasText = (a?.text || '').trim() !== '';
                    const hasImg = !!(a?.imageData);
                    const hasAudio = !!(a?.audioData);
                    if (!hasText && !hasImg && !hasAudio) allOk = false;
                    if (a?.isCorrect) correctCount++;
                }
                if (correctCount < 1) allOk = false;
            }

            if (showHints) {
                const hint = document.getElementById('cq-validation-hint');
                if (!hint) return allOk;

                if (allOk) {
                    hint.textContent = '';
                    return true;
                }

                hint.textContent = 'Vérifiez : chaque diapo doit avoir un texte de question, entre 2 et 6 réponses (chacune avec au minimum un texte, une image ou un audio), et au moins 1 réponse correcte.';
            }

            return allOk;
        }

        function cqInitEditorUI() {
            const edBuilder = document.getElementById('cq-editor-builder');
            if (!edBuilder) return;

            edBuilder.classList.remove('hidden');
            edBuilder.style.display = 'flex';

            cqDraftReset();
            cqDraftClamp();

            cqRenderSlidesStrip();
            cqSelectSlide(0, true);
            cqUpdateEditorCreateButtonState();
        }

        function cqRenderAllEditor() {
            cqDraftClamp();
            cqRenderSlidesStrip();
            cqRenderAnswersEditor();
        }

        function cqSelectSlide(index, skipRenderBadge) {
            cqQuizDraft.slideIndex = index;
            cqRenderSlidesStrip();
            cqRenderAnswersEditor();

            const deleteBtn = document.getElementById('cq-delete-current-diapo-btn');
            if (deleteBtn) {
                deleteBtn.classList.toggle('hidden', cqQuizDraft.slides.length <= 1 || document.getElementById('cq-delete-current-diapo-btn')?.disabled);
            }

            const lockBadge = document.getElementById('cq-editor-lock-badge');
            if (!skipRenderBadge && lockBadge) {
                // keep as-is by cqSetEditorMode
            }
        }

        function cqAddDiapo() {
            if (!cqQuizDraft.slides) cqQuizDraft.slides = [];
            if (cqQuizDraft.slides.length >= 10) return; // soft cap
            cqQuizDraft.slides.push(cqDefaultSlide());
            cqQuizDraft.slideIndex = cqQuizDraft.slides.length - 1;
            cqRenderAllEditor();
        }

        let cqPendingDeleteDiapoIndex = null;

        function cqAskDeleteCurrentDiapo() {
            if (cqQuizDraft.slides.length <= 1) return;
            cqPendingDeleteDiapoIndex = cqQuizDraft.slideIndex;

            const modal = document.getElementById('modal-cq-confirm-delete-diapo');
            if (modal) { playSound('modal-open'); modal.classList.remove('hidden'); }

            const textEl = document.getElementById('cq-confirm-delete-diapo-text');
            if (textEl) textEl.textContent = 'Cette action est irréversible.';
        }

        function cqCloseConfirmDeleteDiapo() {
            playSound('modal-close');
            cqPendingDeleteDiapoIndex = null;
            if (typeof _gcrPendingDelete !== 'undefined') _gcrPendingDelete = false;
            const modal = document.getElementById('modal-cq-confirm-delete-diapo');
            if (modal) modal.classList.add('hidden');
        }

        function cqConfirmDeleteDiapo() {
            // GCR mode delete
            if (typeof _gcrPendingDelete !== 'undefined' && _gcrPendingDelete) {
                _gcrPendingDelete = false;
                const modal = document.getElementById('modal-cq-confirm-delete-diapo');
                if (modal) { playSound('modal-close'); modal.classList.add('hidden'); }
                const slides = _gcrGetSlides();
                slides.splice(_gcrEdCurrentDiapoIdx, 1);
                cqGcrLoadDiapoIntoEditor(Math.max(0, _gcrEdCurrentDiapoIdx - 1));
                return;
            }
            if (cqPendingDeleteDiapoIndex == null) return;
            cqQuizDraft.slides.splice(cqPendingDeleteDiapoIndex, 1);
            if (cqQuizDraft.slideIndex > cqQuizDraft.slides.length - 1) {
                cqQuizDraft.slideIndex = cqQuizDraft.slides.length - 1;
            }
            cqCloseConfirmDeleteDiapo();
            cqRenderAllEditor();
        }

        let cqPendingDeleteAnswerIndex = null;

        function cqAddAnswer() {
            const slide = cqDraftGetCurrentSlide();
            if (slide.answers.length >= 6) return;
            slide.answers.push({ text: '', isCorrect: false, imageData: null, audioData: null });
            cqRenderAnswersEditor();
        }

        function cqUpdateAnswerText(answerIndex, value) {
            const slide = cqDraftGetCurrentSlide();
            slide.answers[answerIndex].text = value;
            cqUpdateEditorCreateButtonState();
        }

        function cqUpdateQuestionText(value) {
            const slide = cqDraftGetCurrentSlide();
            slide.questionText = value;
            cqRenderAllEditor();
        }

        let cqConfirmCreateQuizMode = null;

        function cqOpenConfirmCreateQuiz() {
            const modal = document.getElementById('modal-cq-confirm-create');
            if (modal) {
                playSound('modal-open');
                modal.classList.remove('hidden');
            }
        }

        function cqCloseConfirmCreateQuiz() {
            playSound('modal-close');
            const modal = document.getElementById('modal-cq-confirm-create');
            if (modal) modal.classList.add('hidden');
        }

        function cqOpenConfirmRenameQuiz() {}

        function cqConfirmCreateQuiz() {
            const ok = cqValidateDraft(false);
            if (!ok) {
                const err = document.getElementById('cq-confirm-create-error');
                if (err) {
                    err.textContent = 'Validation échouée.';
                    err.classList.remove('hidden');
                }
                return;
            }

            const titleInput = document.getElementById('cq-game-title-input');
            const title = titleInput ? titleInput.value.trim() : null;
            if (!title) return;

            const quizzes = cqGetQuizzes();
            const idx = quizzes.findIndex(q => (q.title || '').trim().toLowerCase() === title.toLowerCase());
            if (idx === -1) return;

            quizzes[idx].content = { slides: cqQuizDraft.slides };
            quizzes[idx].status = 'offline';

            localStorage.setItem(CQ_ADMIN_QUIZZES_STORAGE_KEY, JSON.stringify(quizzes));

            cqCloseConfirmCreateQuiz();

            cqRenderQuizzes();
            cqRenderManageGames();

            // go back to coming
            const coming = document.getElementById('cq-right-coming');
            if (coming) {
                coming.classList.remove('hidden');
                coming.style.display = 'flex';
            }
            const editor = document.getElementById('cq-editor-builder');
            if (editor) editor.classList.add('hidden');

            cqSetCurrentEditingQuizTitle(null);
        }

        function cqBindEditorEventsOnce() {
            const questionInput = document.getElementById('cq-question-text-input');
            if (questionInput && !questionInput.dataset.bound) {
                questionInput.dataset.bound = '1';
                questionInput.addEventListener('input', (e) => {
                    const slide = cqDraftGetCurrentSlide();
                    slide.questionText = e.target.value;
                    cqRenderSlidesStrip();
                    cqUpdateEditorCreateButtonState();
                });
            }

            const addAnswerBtn = document.getElementById('cq-add-answer-btn');
            if (addAnswerBtn && !addAnswerBtn.dataset.bound) {
                addAnswerBtn.dataset.bound = '1';
                // click is inline onclick already, no-op
            }
        }

        // Drag & drop
        let cqSlideDragFromIndex = null;

        function cqOnSlideDragStart(event, fromIndex) {
            cqSlideDragFromIndex = fromIndex;
            try { event.dataTransfer.effectAllowed = 'move'; } catch {}
        }

        function cqOnSlideDragOver(event) {
            event.preventDefault();
            try { event.dataTransfer.dropEffect = 'move'; } catch {}
        }

        function cqOnSlideDrop(event, toIndex) {
            event.preventDefault();
            if (cqSlideDragFromIndex == null) return;
            if (cqSlideDragFromIndex === toIndex) return;

            const slides = cqQuizDraft.slides;
            const [moved] = slides.splice(cqSlideDragFromIndex, 1);
            slides.splice(toIndex, 0, moved);

            cqSlideDragFromIndex = null;
            // update slideIndex to moved element position
            cqQuizDraft.slideIndex = toIndex;

            cqRenderAllEditor();
        }

        // Rename modals
        let cqPendingRenameTitle = null;
        let cqRenameQuizOriginalTitle = null;

        function cqAskRenameQuiz(title) {
            cqRenameQuizOriginalTitle = title;
            cqPendingRenameTitle = null;

            const input = document.getElementById('cq-rename-input');
            const err = document.getElementById('cq-rename-error');
            if (input) input.value = '';
            if (err) {
                err.textContent = '';
                err.classList.add('hidden');
            }

            const modal = document.getElementById('modal-cq-confirm-rename');
            if (modal) { playSound('modal-open'); modal.classList.remove('hidden'); }
        }

        function cqCloseRenameModal() {
            playSound('modal-close');
            cqPendingRenameTitle = null;
            cqRenameQuizOriginalTitle = null;
            const modal = document.getElementById('modal-cq-confirm-rename');
            if (modal) modal.classList.add('hidden');
        }

        function cqConfirmRenameQuiz() {
            const input = document.getElementById('cq-rename-input');
            const err = document.getElementById('cq-rename-error');
            const newTitle = (input?.value || '').trim();

            if (!cqRenameQuizOriginalTitle || !newTitle) {
                if (err) {
                    err.textContent = 'Veuillez saisir un nouveau nom.';
                    err.classList.remove('hidden');
                }
                return;
            }

            const quizzes = cqGetQuizzes();
            const lower = newTitle.toLowerCase();
            const duplicate = quizzes.some(q => (q.title || '').trim().toLowerCase() === lower && (q.title !== cqRenameQuizOriginalTitle));
            if (duplicate) {
                if (err) {
                    err.textContent = 'Ce titre existe déjà.';
                    err.classList.remove('hidden');
                }
                return;
            }

            const idx = quizzes.findIndex(q => q.title === cqRenameQuizOriginalTitle);
            if (idx === -1) return;

            quizzes[idx].title = newTitle;

            localStorage.setItem(CQ_ADMIN_QUIZZES_STORAGE_KEY, JSON.stringify(quizzes));
            cqRenameQuizInCategories(cqRenameQuizOriginalTitle, newTitle);

            cqCloseRenameModal();
            cqRenderQuizzes();
            cqRenderManageGames();
        }

        // Load existing quiz on click (offline editable, online lock)
        function cqFindQuizByTitle(title) {
            const quizzes = cqGetQuizzes();
            return quizzes.find(q => q.title === title) || null;
        }

        function cqLoadQuizIntoDraft(quiz) {
            cqQuizDraft = {
                slides: cqNormalizeQuizContent(quiz?.content)?.slides || [cqDefaultSlide()],
                slideIndex: 0
            };
            cqDraftClamp();
            cqRenderAllEditor();
            cqUpdateEditorCreateButtonState();
        }

        // Bind click events on quiz list items (created by cqRenderQuizzes)
        function cqBindExistingListClickOnce() {
            const list = document.getElementById('cq-admin-existing-list');
            if (!list || list.dataset.bound) return;
            list.dataset.bound = '1';

            // capture events
            list.addEventListener('click', (e) => {
                const card = e.target.closest('.cq-admin-quiz-item');
                if (!card) return;
                // ignore delete button clicks
                const del = e.target.closest('.cq-admin-delete-btn');
                if (del) return;

                const titleEl = card.querySelector('.cq-admin-quiz-title');
                const title = titleEl?.textContent || null;
                if (!title) return;

                // if status online/temp => lock (TODO says online => blocked, offline editable)
                cqOpenQuizForEditOrView(title);
            });

            list.addEventListener('contextmenu', (e) => {
                const card = e.target.closest('.cq-admin-quiz-item');
                if (!card) return;
                e.preventDefault();
                const titleEl = card.querySelector('.cq-admin-quiz-title');
                const title = titleEl?.textContent || null;
                if (!title) return;
                cqAskRenameQuiz(title);
            });
        }


        // NOTE:
        // IMPORTANT: Ne pas redéfinir cqInitCreationRightCard() ici.
        // Une redéfinition “patch” répétée peut désynchroniser l’affichage
        // (ex: masquer cq-right-newgame / le bouton “+”).

        // Patch cqValidateNewGame to initialize editor builder + draft after click
        function cqValidateNewGame() {
            // On ne crée pas encore le jeu dans "Jeux existants" : on mémorise juste
            // le titre/type choisis, et on ne créera réellement l'entrée qu'au moment
            // où l'utilisateur validera le quiz à la fin (cqSaveDraft).
            const input = document.getElementById('cq-game-title-input');
            if (!input) return;
            const title = input.value.trim();
            if (!title) return;

            const quizzes = cqGetQuizzes();
            const dup = quizzes.some(q => (q.title || '').trim().toLowerCase() === title.toLowerCase());
            if (dup) return;

            const descInput = document.getElementById('cq-game-description-input');
            cqPendingNewQuiz = {
                title,
                type: cqSelectedModeVal || 'QCM',
                difficulty: cqSelectedDifficulty,
                description: descInput ? descInput.value.trim() : ''
            };

            // switch UI to editor
            const characteristics = document.getElementById('cq-right-characteristics');
            if (characteristics) {
                characteristics.classList.add('hidden');
                characteristics.style.display = 'none';
            }

            const coming = document.getElementById('cq-right-coming');
            if (coming) {
                coming.classList.add('hidden');
                coming.style.display = 'none';
            }

            const editor = document.getElementById('cq-right-editor');
            if (editor) {
                editor.classList.remove('hidden');
                editor.style.display = 'flex';
            }

            cqSetCurrentEditingQuizTitle(title);
            cqIsModifyingExisting = false;
            const pendingType = cqPendingNewQuiz && cqPendingNewQuiz.type;
            if (pendingType === 'JetPunk') {
                cqQuizDraft.slides = [{
                    questionText: '',
                    questionImage: null,
                    questionAudio: null,
                    answers: [
                        { text: '', isCorrect: true, jpHints: [] },
                        { text: '', isCorrect: true, jpHints: [] }
                    ]
                }];
            } else if (pendingType === 'Quiz Map') {
                cqQuizDraft.slides = [cqQmDefaultSlide()];
            } else {
                cqQuizDraft.slides = [cqDefaultSlide()];
            }
            cqQuizDraft.slideIndex = 0;

            cqSetEditorMode('offline_edit');
            cqRenderAllEditor();
            cqBindEditorEventsOnce();
            cqUpdateEditorCreateButtonState();
        }

        // After initial load, bind question input and editor
        cqBindEditorEventsOnce();

        /* ============================================================
           RECHERCHE DE JEUX (header guest/user + headers admin)
           - Recherche partielle, insensible à la casse
           - Guest/User : redirige vers la page du jeu (cqOnPublicQuizCardClick)
           - Admin : redirige vers la page de test admin (cqStartAdminTestQuiz)
           ============================================================ */

        function cqNormalizeSearch(str) {
            return (str || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').trim();
        }

        function cqGetSearchResults(query, adminMode) {
            const q = cqNormalizeSearch(query);
            if (!q) return [];

            const quizzes = cqGetQuizzes();
            return quizzes.filter(quiz => {
                if (!adminMode && quiz.status !== 'online' && quiz.status !== 'temp') return false;
                return cqNormalizeSearch(quiz.title).includes(q);
            }).slice(0, 8);
        }

        function cqRenderSearchDropdown(dropdownId, results, adminMode) {
            const dropdown = document.getElementById(dropdownId);
            if (!dropdown) return;

            if (!results.length) {
                dropdown.innerHTML = '<div class="cq-search-dropdown-empty">Aucun résultat</div>';
                dropdown.classList.remove('hidden');
                return;
            }

            dropdown.innerHTML = results.map(quiz => {
                const statusDot = adminMode ? `<span class="${cqQuizStatusDotClass(quiz.status)}" style="display:inline-block;margin-right:5px;vertical-align:middle;"></span>` : '';
                return `<button type="button" class="cq-search-dropdown-item"
                    data-title="${escapeHtml(quiz.title)}"
                    data-admin="${adminMode ? '1' : '0'}"
                    onmousedown="cqSearchSelectResult(event, this.dataset.title, this.dataset.admin === '1')">
                    ${statusDot}${escapeHtml(quiz.title)}
                </button>`;
            }).join('');

            dropdown.classList.remove('hidden');
        }

        function cqSearchGuest(value) {
            const results = cqGetSearchResults(value, false);
            if (!value.trim()) {
                cqSearchBlur('search-guest-dropdown');
                return;
            }
            cqRenderSearchDropdown('search-guest-dropdown', results, false);
        }

        function cqSearchAdmin(value) {
            // Trouve le dropdown actif (celui dont l'input a le focus)
            const activeInput = document.activeElement;
            if (!activeInput || !activeInput.id || !activeInput.id.startsWith('search-admin-')) return;
            const dropdownId = activeInput.id + '-dropdown';
            const results = cqGetSearchResults(value, true);
            if (!value.trim()) {
                const dd = document.getElementById(dropdownId);
                if (dd) dd.classList.add('hidden');
                return;
            }
            cqRenderSearchDropdown(dropdownId, results, true);
        }

        function cqSearchSelectResult(event, title, adminMode) {
            event.preventDefault();
            // Fermer tous les dropdowns
            document.querySelectorAll('.cq-search-dropdown').forEach(d => d.classList.add('hidden'));
            // Vider tous les inputs de recherche
            document.querySelectorAll('#search-guest, [id^="search-admin-"]').forEach(inp => {
                if (!inp.id.endsWith('-dropdown')) inp.value = '';
            });

            if (adminMode) {
                cqStartAdminTestQuiz(title);
            } else {
                cqOnPublicQuizCardClick(title);
            }
        }

        function cqSearchBlur(dropdownId) {
            setTimeout(() => {
                const dropdown = document.getElementById(dropdownId);
                if (dropdown) dropdown.classList.add('hidden');
            }, 150);
        }

        function cqSearchKeydown(event, dropdownId, adminMode) {
            const dropdown = document.getElementById(dropdownId);
            if (!dropdown || dropdown.classList.contains('hidden')) return;

            const items = dropdown.querySelectorAll('.cq-search-dropdown-item');
            if (!items.length) return;

            const focused = dropdown.querySelector('.cq-search-focused');
            let idx = Array.from(items).indexOf(focused);

            if (event.key === 'ArrowDown') {
                event.preventDefault();
                if (focused) focused.classList.remove('cq-search-focused');
                idx = (idx + 1) % items.length;
                items[idx].classList.add('cq-search-focused');
            } else if (event.key === 'ArrowUp') {
                event.preventDefault();
                if (focused) focused.classList.remove('cq-search-focused');
                idx = idx <= 0 ? items.length - 1 : idx - 1;
                items[idx].classList.add('cq-search-focused');
            } else if (event.key === 'Enter') {
                event.preventDefault();
                if (focused) {
                    const title = focused.dataset.title;
                    cqSearchSelectResult(event, title, adminMode);
                }
            } else if (event.key === 'Escape') {
                dropdown.classList.add('hidden');
            }
        }

        // --- Plein écran jeu ---
        function toggleGameFullscreen() {
            const card = document.getElementById('game-card-main');
            if (!card) return;
            if (!document.fullscreenElement && !document.webkitFullscreenElement) {
                const req = card.requestFullscreen ? card.requestFullscreen() : card.webkitRequestFullscreen ? card.webkitRequestFullscreen() : null;
            } else {
                const ex = document.exitFullscreen ? document.exitFullscreen() : document.webkitExitFullscreen ? document.webkitExitFullscreen() : null;
            }
        }

        function _updateFullscreenIcon() {
            const enter = document.getElementById('icon-fullscreen-enter');
            const exit = document.getElementById('icon-fullscreen-exit');
            if (!enter || !exit) return;
            const isFs = !!(document.fullscreenElement || document.webkitFullscreenElement);
            enter.style.display = isFs ? 'none' : '';
            exit.style.display = isFs ? '' : 'none';
        }

        document.addEventListener('fullscreenchange', _updateFullscreenIcon);
        document.addEventListener('webkitfullscreenchange', _updateFullscreenIcon);

        // ============================================================

        // ============================================================
        // MESSAGERIE
        // Messages stored as array: { id, convId (= userId), sender ('user'|'admin'), senderLabel, pseudo, content, date, replyTo }
        // convId is always the logged-in user's id so user+admin messages share same conv.
        // ============================================================
        const MSG_STORAGE_KEY = 'cq_messages_admin';

        function msgGetMessages() {
            try { return JSON.parse(localStorage.getItem(MSG_STORAGE_KEY) || '[]'); }
            catch(e) { return []; }
        }

        function msgSaveMessages(msgs) {
            localStorage.setItem(MSG_STORAGE_KEY, JSON.stringify(msgs));
        }

        function msgGenerateId() {
            return Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
        }

        function msgFormatDate(iso) {
            const d = new Date(iso);
            return d.toLocaleDateString('fr-FR', {day:'2-digit',month:'2-digit',year:'numeric'}) + ' ' +
                   d.toLocaleTimeString('fr-FR', {hour:'2-digit',minute:'2-digit'});
        }

        function msgEscapeHtml(str) {
            return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
        }

        // --- Tab switching (user) ---
        function msgSwitchTab(tab) {
            const classicPanel = document.getElementById('msg-classic-panel');
            const adminPanel = document.getElementById('msg-admin-panel');
            const tabClassic = document.getElementById('msg-tab-classic');
            const tabAdmin = document.getElementById('msg-tab-admin');
            if (!classicPanel) return;
            if (tab === 'classic') {
                classicPanel.classList.remove('hidden');
                adminPanel.classList.add('hidden');
                tabClassic.classList.add('msg-tab-active');
                tabAdmin.classList.remove('msg-tab-active');
                gcRenderMessages('msg-classic-chat-messages', false);
            } else {
                classicPanel.classList.add('hidden');
                adminPanel.classList.remove('hidden');
                tabClassic.classList.remove('msg-tab-active');
                tabAdmin.classList.add('msg-tab-active');
                msgRenderUserChat();
                // Son de réception si messages admin non lus
                if (notifCountUserUnreadAdmin() > 0) playSound('msg-receive');
                notifMarkUserAdminRead();
            }
        }

        // --- Render user chat ---
        let msgUserReplyTo = null;

        function msgRenderUserChat() {
            const container = document.getElementById('msg-admin-chat-messages');
            if (!container) return;
            const user = AuthService.getCurrentUser();
            if (!user) return;
            const msgs = msgGetMessages().filter(m => m.convId === user.id);
            container.innerHTML = '';
            msgs.forEach(m => {
                container.appendChild(msgBuildBubble(m, m.sender === 'admin'));
            });
            container.scrollTop = container.scrollHeight;
        }

        function msgBuildBubble(msg, isAdmin) {
            const div = document.createElement('div');
            // isAdmin=true means the message is FROM admin (incoming for user), false = outgoing (sent by user)
            div.className = 'msg-bubble-wrap ' + (isAdmin ? 'msg-bubble-left' : 'msg-bubble-right');
            let replyHtml = '';
            if (msg.replyTo) {
                const orig = msgGetMessages().find(m => m.id === msg.replyTo);
                if (orig) {
                    replyHtml = `<div class="msg-reply-ref">↩ <span style="font-weight:bold">${orig.senderLabel}</span> : ${msgEscapeHtml(orig.content.slice(0, 80))}${orig.content.length > 80 ? '…' : ''}</div>`;
                }
            }
            const bubbleClass = isAdmin ? 'msg-bubble-incoming' : 'msg-bubble-outgoing';
            const msgUserAvatar = (msg.sender !== 'admin') ? buildChatAvatarHtml(msg.senderLabel, 'msg-chat-avatar') : '';
            div.innerHTML = `
                <div class="msg-bubble ${bubbleClass}">
                    <div class="msg-bubble-header">
                        ${msgUserAvatar}<span class="msg-bubble-sender">${clickablePseudoHtml(msg.senderLabel)}</span>
                        <span class="msg-bubble-date">${msgFormatDate(msg.date)}</span>
                    </div>
                    ${replyHtml}
                    <div class="msg-bubble-content">${msgEscapeHtml(msg.content)}</div>
                    <button class="msg-reply-btn" onclick="msgSetReplyUser('${msg.id}')">Répondre</button>
                </div>`;
            return div;
        }

        function msgSetReplyUser(msgId) {
            msgUserReplyTo = msgId;
            const orig = msgGetMessages().find(m => m.id === msgId);
            const preview = document.getElementById('msg-admin-reply-preview');
            if (preview && orig) {
                preview.classList.remove('hidden');
                preview.innerHTML = `<span>↩ Réponse à <b>${orig.senderLabel}</b> : ${msgEscapeHtml(orig.content.slice(0,60))}${orig.content.length>60?'…':''}</span> <button onclick="msgCancelReplyUser()" class="msg-cancel-reply">✕</button>`;
            }
        }

        function msgCancelReplyUser() {
            msgUserReplyTo = null;
            const preview = document.getElementById('msg-admin-reply-preview');
            if (preview) { preview.classList.add('hidden'); preview.innerHTML = ''; }
        }

        function msgSendUser() {
            const input = document.getElementById('msg-admin-input');
            const user = AuthService.getCurrentUser();
            if (!input || !user) return;
            const content = input.value.trim();
            if (!content) return;
            const msgs = msgGetMessages();
            msgs.push({
                id: msgGenerateId(),
                convId: user.id,
                pseudo: user.pseudo,
                sender: 'user',
                senderLabel: user.pseudo,
                content,
                date: new Date().toISOString(),
                replyTo: msgUserReplyTo || null
            });
            msgSaveMessages(msgs);
            input.value = '';
            msgCancelReplyUser();
            msgUpdateCounter('msg-admin-input', 'msg-admin-counter');
            msgRenderUserChat();
            playSound('msg-send');
            if (typeof updateNotifBadges === 'function') updateNotifBadges();
        }

        // ============================================================
        // CHAT CLASSIQUE GLOBAL
        // ============================================================
        const GLOBAL_CHAT_KEY = 'cq_global_chat';

        function gcGetMessages() {
            try { return JSON.parse(localStorage.getItem(GLOBAL_CHAT_KEY) || '[]'); }
            catch(e) { return []; }
        }

        function gcSaveMessages(msgs) {
            localStorage.setItem(GLOBAL_CHAT_KEY, JSON.stringify(msgs));
        }

        let gcUserReplyTo = null;
        let gcAdminReplyTo = null;

        function gcRenderMessages(containerId, isAdminView) {
            const container = document.getElementById(containerId);
            if (!container) return;
            const msgs = gcGetMessages();
            container.innerHTML = '';
            // Determine current user identity for alignment
            let currentLabel = null;
            if (isAdminView) {
                currentLabel = 'admin'; // admin sender key
            } else {
                const user = AuthService.getCurrentUser();
                if (user) currentLabel = user.pseudo;
            }
            msgs.forEach(m => {
                container.appendChild(gcBuildBubble(m, isAdminView, currentLabel));
            });
            container.scrollTop = container.scrollHeight;
        }

        function gcBuildBubble(msg, isAdminView, currentLabel) {
            const isAdminMsg = msg.sender === 'admin';
            const isMine = isAdminView ? isAdminMsg : (msg.senderLabel === currentLabel);
            const div = document.createElement('div');
            div.className = 'msg-bubble-wrap gc-bubble-wrap ' + (isMine ? 'msg-bubble-right' : 'msg-bubble-left');
            let replyHtml = '';
            if (msg.replyTo) {
                const orig = gcGetMessages().find(m => m.id === msg.replyTo);
                if (orig) {
                    replyHtml = `<div class="msg-reply-ref">↩ <span style="font-weight:bold">${orig.senderLabel}</span> : ${msgEscapeHtml(orig.content.slice(0,80))}${orig.content.length>80?'…':''}</div>`;
                }
            }
            const reportBtn = (!isAdminView && !isAdminMsg)
                ? `<button class="gc-report-btn" title="Signaler ce message" onclick="gcReportMessage('${msg.id}')">🚩</button>`
                : (!isAdminView && isAdminMsg ? `<button class="gc-report-btn" title="Signaler ce message" onclick="gcReportMessage('${msg.id}')">🚩</button>` : '');
            const replyFn = isAdminView ? `gcSetReplyAdmin('${msg.id}')` : `gcSetReplyUser('${msg.id}')`;
            // Colored pseudo only for incoming messages from other users (not admin, not mine)
            const userColor = (!isAdminMsg && !isMine) ? getUserColor(msg.senderLabel) : null;
            const senderStyle = userColor ? ` style="color:${userColor};opacity:1;"` : '';
            // Bubble class: admin has its own style, others use outgoing/incoming
            let bubbleClass;
            if (isAdminMsg) {
                bubbleClass = 'gc-bubble-admin';
            } else if (isMine) {
                bubbleClass = 'msg-bubble-outgoing';
            } else {
                bubbleClass = 'msg-bubble-incoming';
            }
            const senderAvatar = (!isAdminMsg) ? buildChatAvatarHtml(msg.senderLabel, 'msg-chat-avatar') : '';
            div.innerHTML = `
                <div class="msg-bubble ${bubbleClass}">
                    ${isAdminMsg ? '<div class="gc-admin-badge">⭐ ADMIN</div>' : ''}
                    <div class="msg-bubble-header">
                        ${senderAvatar}${isAdminMsg ? '<span class="msg-bubble-sender"' + senderStyle + '>' + msgEscapeHtml(msg.senderLabel) + '</span>' : '<span class="msg-bubble-sender"' + senderStyle + '>' + clickablePseudoHtml(msg.senderLabel, false, undefined, true) + '</span>'}
                        <span class="msg-bubble-date">${msgFormatDate(msg.date)}</span>
                    </div>
                    ${replyHtml}
                    <div class="msg-bubble-content">${msgEscapeHtml(msg.content)}</div>
                    <div class="gc-bubble-actions">
                        <button class="msg-reply-btn" onclick="${replyFn}">Répondre</button>
                        ${reportBtn}
                    </div>
                </div>`;
            return div;
        }

        // --- User side ---
        function gcSetReplyUser(msgId) {
            gcUserReplyTo = msgId;
            const orig = gcGetMessages().find(m => m.id === msgId);
            const preview = document.getElementById('msg-classic-reply-preview');
            if (preview && orig) {
                preview.classList.remove('hidden');
                preview.innerHTML = `<span>↩ Réponse à <b>${msgEscapeHtml(orig.senderLabel)}</b> : ${msgEscapeHtml(orig.content.slice(0,60))}${orig.content.length>60?'…':''}</span> <button onclick="gcCancelReplyUser()" class="msg-cancel-reply">✕</button>`;
            }
        }

        function gcCancelReplyUser() {
            gcUserReplyTo = null;
            const preview = document.getElementById('msg-classic-reply-preview');
            if (preview) { preview.classList.add('hidden'); preview.innerHTML = ''; }
        }

        function msgSendGlobal() {
            const input = document.getElementById('msg-classic-input');
            const user = AuthService.getCurrentUser();
            if (!input || !user) return;
            const content = input.value.trim();
            if (!content) return;
            const msgs = gcGetMessages();
            msgs.push({
                id: msgGenerateId(),
                sender: 'user',
                senderLabel: user.pseudo,
                content,
                date: new Date().toISOString(),
                replyTo: gcUserReplyTo || null
            });
            gcSaveMessages(msgs);
            input.value = '';
            gcCancelReplyUser();
            msgUpdateCounter('msg-classic-input','msg-classic-counter');
            gcRenderMessages('msg-classic-chat-messages', false);
            playSound('msg-send');
        }

        // --- Admin side ---
        function gcSetReplyAdmin(msgId) {
            gcAdminReplyTo = msgId;
            const orig = gcGetMessages().find(m => m.id === msgId);
            const preview = document.getElementById('msg-admin-classic-reply-preview');
            if (preview && orig) {
                preview.classList.remove('hidden');
                preview.innerHTML = `<span>↩ Réponse à <b>${msgEscapeHtml(orig.senderLabel)}</b> : ${msgEscapeHtml(orig.content.slice(0,60))}${orig.content.length>60?'…':''}</span> <button onclick="gcCancelReplyAdmin()" class="msg-cancel-reply">✕</button>`;
            }
        }

        function gcCancelReplyAdmin() {
            gcAdminReplyTo = null;
            const preview = document.getElementById('msg-admin-classic-reply-preview');
            if (preview) { preview.classList.add('hidden'); preview.innerHTML = ''; }
        }

        function msgSendGlobalAdmin() {
            const input = document.getElementById('msg-admin-classic-input');
            if (!input) return;
            const content = input.value.trim();
            if (!content) return;
            const msgs = gcGetMessages();
            msgs.push({
                id: msgGenerateId(),
                sender: 'admin',
                senderLabel: 'Admin',
                content,
                date: new Date().toISOString(),
                replyTo: gcAdminReplyTo || null
            });
            gcSaveMessages(msgs);
            input.value = '';
            gcCancelReplyAdmin();
            msgUpdateCounter('msg-admin-classic-input','msg-admin-classic-counter');
            gcRenderMessages('msg-admin-classic-messages', true);
            playSound('msg-send');
        }

        // --- Report message chat ---
        let _gcPendingReportMsgId = null;

        function gcReportMessage(msgId) {
            const user = AuthService.getCurrentUser();
            if (!user) return;
            _gcPendingReportMsgId = msgId;
            playSound('modal-open');
            document.getElementById('modal-chat-report-confirm').classList.remove('hidden');
        }

        function gcCancelChatReport() {
            _gcPendingReportMsgId = null;
            playSound('modal-close');
            document.getElementById('modal-chat-report-confirm').classList.add('hidden');
        }

        function gcConfirmChatReport() {
            if (!_gcPendingReportMsgId) return;
            const user = AuthService.getCurrentUser();
            if (!user) { gcCancelChatReport(); return; }
            const msg = gcGetMessages().find(m => m.id === _gcPendingReportMsgId);
            if (!msg) { gcCancelChatReport(); return; }

            const report = {
                id: 'rpt_' + Date.now(),
                type: 'chat_message',
                title: 'Message problématique',
                sender: user.pseudo,
                date: new Date().toISOString(),
                chatMessage: {
                    id: msg.id,
                    content: msg.content,
                    date: msg.date,
                    senderLabel: msg.senderLabel,
                    sender: msg.sender,
                    isAdminMsg: msg.sender === 'admin',
                    replyTo: msg.replyTo || null
                }
            };

            try {
                const existing = JSON.parse(localStorage.getItem('cq_reports') || '[]');
                existing.push(report);
                localStorage.setItem('cq_reports', JSON.stringify(existing));
            } catch(e) {}

            _gcPendingReportMsgId = null;
            document.getElementById('modal-chat-report-confirm').classList.add('hidden');
            playSound('action-confirm');
            if (typeof updateNotifBadges === 'function') updateNotifBadges();
        }

        // --- Réinitialisation (admin) ---
        function openGlobalChatResetConfirm() {
            playSound('modal-open');
            document.getElementById('modal-global-chat-reset').classList.remove('hidden');
        }

        function closeGlobalChatResetConfirm() {
            playSound('modal-close');
            document.getElementById('modal-global-chat-reset').classList.add('hidden');
        }

        function executeGlobalChatReset() {
            gcSaveMessages([]);
            closeGlobalChatResetConfirm();
            gcRenderMessages('msg-admin-classic-messages', true);
        }

        function msgUpdateCounter(inputId, counterId) {
            const inp = document.getElementById(inputId);
            const cnt = document.getElementById(counterId);
            if (inp && cnt) cnt.textContent = inp.value.length + '/300';
        }

        // --- Tab switching (admin) ---
        let msgAdminCurrentConv = null;
        let msgAdminReplyTo = null;

        function msgAdminSwitchTab(tab) {
            const classicPanel = document.getElementById('msg-admin-classic-panel');
            const chatPanel = document.getElementById('msg-admin-chat-panel');
            const reportsPanel = document.getElementById('msg-admin-reports-panel');
            const tabClassic = document.getElementById('msg-admin-tab-classic');
            const tabChat = document.getElementById('msg-admin-tab-chat');
            const tabReports = document.getElementById('msg-admin-tab-reports');
            if (!classicPanel) return;
            // Hide all
            classicPanel.classList.add('hidden');
            chatPanel.classList.add('hidden');
            if (reportsPanel) reportsPanel.classList.add('hidden');
            tabClassic.classList.remove('msg-tab-active');
            tabChat.classList.remove('msg-tab-active');
            if (tabReports) tabReports.classList.remove('msg-tab-active');
            if (tab === 'classic') {
                classicPanel.classList.remove('hidden');
                tabClassic.classList.add('msg-tab-active');
                gcRenderMessages('msg-admin-classic-messages', true);
            } else if (tab === 'reports') {
                if (reportsPanel) reportsPanel.classList.remove('hidden');
                if (tabReports) tabReports.classList.add('msg-tab-active');
                reportAdminRenderList();
            } else {
                chatPanel.classList.remove('hidden');
                tabChat.classList.add('msg-tab-active');
                msgAdminShowList();
            }
            if (typeof updateNotifBadges === 'function') updateNotifBadges();
        }

        // ============================================================
        // SIGNALEMENTS ADMIN
        // ============================================================
        let _reportDeletePendingId = null;

        function reportAdminGetAll() {
            try { return JSON.parse(localStorage.getItem('cq_reports') || '[]'); } catch(e) { return []; }
        }

        function reportAdminSaveAll(reports) {
            localStorage.setItem('cq_reports', JSON.stringify(reports));
        }

        function reportAdminRenderList() {
            const listView = document.getElementById('msg-admin-reports-list-view');
            const detailView = document.getElementById('msg-admin-reports-detail-view');
            if (!listView) return;
            listView.classList.remove('hidden');
            if (detailView) { detailView.classList.add('hidden'); detailView.classList.remove('flex'); }
            const list = document.getElementById('msg-admin-reports-list');
            if (!list) return;
            const reports = reportAdminGetAll();
            if (!reports.length) {
                list.innerHTML = '<p class="text-xs" style="opacity:0.5;font-family:Datatype,monospace;">Aucun signalement</p>';
                return;
            }
            list.innerHTML = '';
            // Sort newest first
            const seenReports = notifGetReportsSeen();
            [...reports].reverse().forEach(r => {
                const card = document.createElement('div');
                card.className = 'report-admin-card';
                card.style.position = 'relative';
                card.onclick = (e) => { if (!e.target.closest('.report-admin-trash')) reportAdminOpenDetail(r.id); };
                const isGuest = (!r.sender || r.sender === 'Invité');
                const senderHtml = isGuest
                    ? `<span class="report-admin-sender">${escapeHtml(r.sender || 'Invité')}</span>`
                    : `<span class="report-admin-sender">${clickablePseudoHtml(r.sender || 'Inconnu', false, undefined, true)}</span>`;
                const isUnread = !seenReports.includes(r.id);
                const unreadDot = isUnread ? `<span class="report-unread-dot">!</span>` : '';
                card.innerHTML = `
                    ${unreadDot}
                    <div class="report-admin-card-title">${escapeHtml(r.title || 'Sans titre')}</div>
                    ${senderHtml}
                    <div class="report-admin-date">${msgFormatDate(r.date)}</div>
                    <button class="report-admin-trash" title="Supprimer" onclick="event.stopPropagation();reportAdminAskDelete('${r.id}')">🗑</button>`;
                list.appendChild(card);
            });
        }

        function reportAdminOpenDetail(id) {
            const reports = reportAdminGetAll();
            const r = reports.find(x => x.id === id);
            if (!r) return;
            if (typeof notifMarkReportSeen === 'function') notifMarkReportSeen(id);
            const listView = document.getElementById('msg-admin-reports-list-view');
            const detailView = document.getElementById('msg-admin-reports-detail-view');
            if (!listView || !detailView) return;
            listView.classList.add('hidden');
            detailView.classList.remove('hidden');
            detailView.classList.add('flex');

            const isGuest = (!r.sender || r.sender === 'Invité');
            const senderHtml = isGuest
                ? `<span class="report-admin-sender">${escapeHtml(r.sender || 'Invité')}</span>`
                : `<span class="report-admin-sender-tooltip-wrap">${clickablePseudoHtml(r.sender || 'Inconnu', false, undefined, true)} <span class="report-admin-sender report-admin-sender-link" onclick="reportAdminGoToChat('${escapeHtml(r.sender || '')}')" title="Discuter avec l'expéditeur">✉</span></span>`;

            if (r.type === 'chat_message' && r.chatMessage) {
                const cm = r.chatMessage;
                const isAdminMsg = cm.isAdminMsg;
                const isMine = false; // admin view: messages are never "mine" in this context
                const msgAuthorPseudo = escapeHtml(cm.senderLabel || 'Inconnu');
                const msgAuthorKey = cm.senderLabel || '';
                const adminBadge = isAdminMsg ? '<div class="gc-admin-badge">⭐ ADMIN</div>' : '';
                // Title (pseudo of message sender) is clickable
                const titleHtml = (msgAuthorKey && msgAuthorKey !== 'Invité')
                    ? `${clickablePseudoHtml(msgAuthorKey, false, undefined, true)} <span class="report-admin-sender-link" onclick="reportAdminGoToChat('${escapeHtml(msgAuthorKey)}')" title="Discuter avec l'utilisateur">✉</span>`
                    : `<span>${msgAuthorPseudo}</span>`;

                // Reconstruct reply ref if any
                let replyHtml = '';
                if (cm.replyTo) {
                    const orig = gcGetMessages().find(m => m.id === cm.replyTo);
                    if (orig) {
                        replyHtml = `<div class="msg-reply-ref">↩ <span style="font-weight:bold">${msgEscapeHtml(orig.senderLabel)}</span> : ${msgEscapeHtml(orig.content.slice(0,80))}${orig.content.length>80?'…':''}</div>`;
                    }
                }

                detailView.innerHTML = `
                    <div class="flex items-center gap-3 mb-4 shrink-0">
                        <button class="msg-back-btn" onclick="reportAdminRenderList()">← Retour</button>
                        <div class="flex-1"></div>
                        <div class="flex flex-col items-end gap-1 text-right">
                            ${senderHtml}
                            <span class="report-admin-date">${msgFormatDate(r.date)}</span>
                        </div>
                        <button class="report-admin-trash" title="Supprimer" onclick="reportAdminAskDelete('${r.id}')">🗑</button>
                    </div>
                    <h2 class="text-xl font-black font-title mb-4">${titleHtml}</h2>
                    <div class="msg-bubble-wrap gc-bubble-wrap msg-bubble-left">
                        <div class="msg-bubble ${isAdminMsg ? 'gc-bubble-admin' : 'msg-bubble-user'}">
                            ${adminBadge}
                            <div class="msg-bubble-header">
                                <span class="msg-bubble-sender">${msgEscapeHtml(cm.senderLabel)}</span>
                                <span class="msg-bubble-date">${msgFormatDate(cm.date)}</span>
                            </div>
                            ${replyHtml}
                            <div class="msg-bubble-content">${msgEscapeHtml(cm.content)}</div>
                        </div>
                    </div>`;
            } else {
                const imgsHtml = (r.images && r.images.length)
                    ? `<div class="report-admin-images-grid">${r.images.map((img, i) =>
                        `<div class="report-admin-img-wrap">
                            <img src="${img.dataUrl}" alt="${escapeHtml(img.name)}" class="report-admin-img" onclick="reportOpenLightbox('${id}',${i})" title="Voir en grand">
                            <a href="${img.dataUrl}" download="${escapeHtml(img.name)}" class="report-admin-img-dl" title="Télécharger">⬇</a>
                        </div>`).join('')}</div>`
                    : '';

                detailView.innerHTML = `
                    <div class="flex items-center gap-3 mb-4 shrink-0">
                        <button class="msg-back-btn" onclick="reportAdminRenderList()">← Retour</button>
                        <div class="flex-1"></div>
                        <div class="flex flex-col items-end gap-1 text-right">
                            ${senderHtml}
                            <span class="report-admin-date">${msgFormatDate(r.date)}</span>
                        </div>
                        <button class="report-admin-trash" title="Supprimer" onclick="reportAdminAskDelete('${r.id}')">🗑</button>
                    </div>
                    <h2 class="text-xl font-black font-title mb-3">${escapeHtml(r.title || 'Sans titre')}</h2>
                    <p class="text-sm opacity-80 mb-4 whitespace-pre-wrap">${escapeHtml(r.description || '')}</p>
                    ${imgsHtml}`;
            }
        }

        function reportOpenLightbox(reportId, imgIdx) {
            const reports = reportAdminGetAll();
            const r = reports.find(x => x.id === reportId);
            if (!r || !r.images || !r.images[imgIdx]) return;
            const img = r.images[imgIdx];
            const lb = document.getElementById('modal-report-lightbox');
            const lbImg = document.getElementById('modal-report-lightbox-img');
            const lbDl = document.getElementById('modal-report-lightbox-dl');
            if (!lb || !lbImg) return;
            lbImg.src = img.dataUrl;
            lbImg.alt = img.name;
            if (lbDl) { lbDl.href = img.dataUrl; lbDl.download = img.name; }
            lb.classList.remove('hidden');
        }

        function reportCloseLightbox() {
            const lb = document.getElementById('modal-report-lightbox');
            if (lb) lb.classList.add('hidden');
        }

        function reportAdminAskDelete(id) {
            playSound('modal-open');
            _reportDeletePendingId = id;
            document.getElementById('modal-report-delete-confirm').classList.remove('hidden');
        }

        function reportDeleteCancel() {
            playSound('modal-close');
            _reportDeletePendingId = null;
            document.getElementById('modal-report-delete-confirm').classList.add('hidden');
        }

        function reportDeleteConfirm() {
            if (!_reportDeletePendingId) return;
            const reports = reportAdminGetAll().filter(r => r.id !== _reportDeletePendingId);
            reportAdminSaveAll(reports);
            if (typeof updateNotifBadges === 'function') updateNotifBadges();
            _reportDeletePendingId = null;
            playSound('action-delete');
            document.getElementById('modal-report-delete-confirm').classList.add('hidden');
            // Return to list view
            const detailView = document.getElementById('msg-admin-reports-detail-view');
            if (detailView && !detailView.classList.contains('hidden')) {
                reportAdminRenderList();
            } else {
                reportAdminRenderList();
            }
        }

        function reportAdminGoToChat(pseudo) {
            if (!pseudo || pseudo === 'Invité') return;
            // Find user by pseudo
            let users = [];
            try { users = JSON.parse(localStorage.getItem('cq_users') || '[]'); } catch(e) {}
            const user = users.find(u => u.pseudo === pseudo);
            let convId;
            if (user) {
                convId = user.id;
            } else {
                // Use pseudo as convId fallback (create new)
                convId = pseudo;
            }
            // Switch to Chat Admin tab
            msgAdminSwitchTab('admin');
            // Open or create conversation
            setTimeout(() => { msgAdminOpenConv(convId); }, 50);
        }

        // ============================================================
        // RECHERCHE COMPTES DANS CHAT ADMIN
        // ============================================================
        function msgAdminSearchUsers(query) {
            const resultsEl = document.getElementById('msg-admin-search-results');
            if (!resultsEl) return;
            const q = (query || '').trim().toLowerCase();
            if (!q) { resultsEl.classList.add('hidden'); return; }
            let users = [];
            try { users = JSON.parse(localStorage.getItem('cq_users') || '[]'); } catch(e) {}
            const matches = users.filter(u => u.pseudo && u.pseudo.toLowerCase().includes(q));
            if (!matches.length) {
                resultsEl.innerHTML = '<div class="px-3 py-2 text-xs opacity-50">Aucun compte trouvé</div>';
                resultsEl.classList.remove('hidden');
                return;
            }
            resultsEl.innerHTML = '';
            matches.forEach(u => {
                const item = document.createElement('button');
                item.className = 'w-full text-left px-3 py-2 text-xs font-medium hover:bg-black/5 transition rounded-lg';
                item.textContent = u.pseudo;
                item.onmousedown = (e) => {
                    e.preventDefault();
                    const input = document.getElementById('msg-admin-user-search');
                    if (input) input.value = '';
                    resultsEl.classList.add('hidden');
                    msgAdminOpenConv(u.id);
                };
                resultsEl.appendChild(item);
            });
            resultsEl.classList.remove('hidden');
        }

        function msgAdminShowList() {
            msgAdminCurrentConv = null;
            const usersBar = document.getElementById('msg-admin-users-bar');
            const convPanel = document.getElementById('msg-admin-conv-panel');
            if (usersBar) usersBar.classList.remove('hidden');
            if (convPanel) convPanel.classList.add('hidden');
            msgAdminRenderUsersList();
        }

        function msgAdminOpenConv(cid) {
            msgAdminCurrentConv = cid;
            const usersBar = document.getElementById('msg-admin-users-bar');
            const convPanel = document.getElementById('msg-admin-conv-panel');
            if (usersBar) usersBar.classList.add('hidden');
            if (convPanel) convPanel.classList.remove('hidden');
            msgAdminRenderConversation();
            if (typeof notifAdminMarkConvRead === 'function') notifAdminMarkConvRead(cid);
        }

        function msgGetPseudoForConv(convId, msgs) {
            // Try to find pseudo from messages in this conversation
            const convMsgs = msgs.filter(m => m.convId === convId);
            let pseudo = null;
            for (const m of convMsgs) {
                if (m.pseudo && m.pseudo !== m.convId) { pseudo = m.pseudo; break; }
            }
            // If still not found or looks like an ID, try from localStorage users
            if (!pseudo || /^[a-f0-9-]{20,}$/i.test(pseudo)) {
                try {
                    const users = JSON.parse(localStorage.getItem('cq_users') || '[]');
                    const u = users.find(u => u.id === convId);
                    if (u && u.pseudo) pseudo = u.pseudo;
                } catch(e) {}
            }
            return pseudo || convId;
        }

                function msgAdminRenderUsersList() {
            const list = document.getElementById('msg-admin-users-list');
            if (!list) return;
            const msgs = msgGetMessages();
            // Get unique convIds and their pseudo
            const convMap = {};
            msgs.forEach(m => {
                if (!convMap[m.convId]) convMap[m.convId] = null;
            });
            Object.keys(convMap).forEach(cid => { convMap[cid] = msgGetPseudoForConv(cid, msgs); });
            list.innerHTML = '';
            const convIds = Object.keys(convMap);
            if (!convIds.length) {
                list.innerHTML = '<p class="text-xs" style="opacity:0.5;font-family:Datatype,monospace;">Aucun message reçu</p>';
                return;
            }
            const unreadPerConv = (typeof notifAdminCountUnreadPerConv === 'function') ? notifAdminCountUnreadPerConv() : {};
            convIds.forEach(cid => {
                const btn = document.createElement('button');
                btn.className = 'msg-user-btn';
                btn.style.position = 'relative';
                const pseudoLabel = convMap[cid];
                const pseudoSpan = document.createElement('span');
                pseudoSpan.className = 'pseudo-clickable';
                pseudoSpan.textContent = pseudoLabel;
                pseudoSpan.title = 'Voir le profil de ' + pseudoLabel;
                pseudoSpan.onclick = (e) => { e.stopPropagation(); openProfileModalByPseudo(pseudoLabel, true); };
                btn.appendChild(pseudoSpan);
                const unread = unreadPerConv[cid] || 0;
                if (unread > 0) {
                    const badge = document.createElement('span');
                    badge.className = 'notif-conv-badge';
                    badge.textContent = unread > 99 ? '99+' : String(unread);
                    btn.appendChild(badge);
                }
                btn.onclick = () => { msgAdminOpenConv(cid); };
                list.appendChild(btn);
            });
        }

        function msgAdminDeleteConversation() {
            if (!msgAdminCurrentConv) return;
            playSound('modal-open');
            document.getElementById('modal-msg-admin-delete-conv').classList.remove('hidden');
        }

        function msgAdminDeleteConvCancel() {
            playSound('modal-close');
            document.getElementById('modal-msg-admin-delete-conv').classList.add('hidden');
        }

        function msgAdminDeleteConvConfirm() {
            playSound('action-delete');
            document.getElementById('modal-msg-admin-delete-conv').classList.add('hidden');
            if (!msgAdminCurrentConv) return;
            const msgs = msgGetMessages().filter(m => m.convId !== msgAdminCurrentConv);
            msgSaveMessages(msgs);
            msgAdminShowList();
        }

        function msgAdminRenderConversation() {
            const container = document.getElementById('msg-admin-side-messages');
            const label = document.getElementById('msg-admin-selected-user');
            if (!container || !msgAdminCurrentConv) return;
            const msgs = msgGetMessages().filter(m => m.convId === msgAdminCurrentConv);
            const pseudo = msgGetPseudoForConv(msgAdminCurrentConv, msgs);
            if (label) label.textContent = 'Conversation avec ' + pseudo;
            container.innerHTML = '';
            msgs.forEach(m => {
                container.appendChild(msgBuildBubbleAdmin(m));
            });
            container.scrollTop = container.scrollHeight;
        }

        function msgBuildBubbleAdmin(msg) {
            const isAdminMsg = msg.sender === 'admin';
            const div = document.createElement('div');
            // Admin view: admin messages are outgoing (right), user messages are incoming (left)
            div.className = 'msg-bubble-wrap ' + (isAdminMsg ? 'msg-bubble-right' : 'msg-bubble-left');
            let replyHtml = '';
            if (msg.replyTo) {
                const orig = msgGetMessages().find(m => m.id === msg.replyTo);
                if (orig) {
                    replyHtml = `<div class="msg-reply-ref">↩ <span style="font-weight:bold">${orig.senderLabel}</span> : ${msgEscapeHtml(orig.content.slice(0, 80))}${orig.content.length > 80 ? '…' : ''}</div>`;
                }
            }
            const bubbleClass = isAdminMsg ? 'msg-bubble-outgoing' : 'msg-bubble-incoming';
            const adminBubbleAvatar = (!isAdminMsg) ? buildChatAvatarHtml(msg.senderLabel, 'msg-chat-avatar') : '';
            div.innerHTML = `
                <div class="msg-bubble ${bubbleClass}">
                    <div class="msg-bubble-header">
                        ${adminBubbleAvatar}${isAdminMsg ? '<span class="msg-bubble-sender">' + msgEscapeHtml(msg.senderLabel) + '</span>' : '<span class="msg-bubble-sender">' + clickablePseudoHtml(msg.senderLabel, false, undefined, true) + '</span>'}
                        <span class="msg-bubble-date">${msgFormatDate(msg.date)}</span>
                    </div>
                    ${replyHtml}
                    <div class="msg-bubble-content">${msgEscapeHtml(msg.content)}</div>
                    <button class="msg-reply-btn" onclick="msgSetReplyAdmin('${msg.id}')">Répondre</button>
                </div>`;
            return div;
        }

        function msgSetReplyAdmin(msgId) {
            msgAdminReplyTo = msgId;
            const orig = msgGetMessages().find(m => m.id === msgId);
            const preview = document.getElementById('msg-admin-side-reply-preview');
            if (preview && orig) {
                preview.classList.remove('hidden');
                preview.innerHTML = `<span>↩ Réponse à <b>${orig.senderLabel}</b> : ${msgEscapeHtml(orig.content.slice(0,60))}${orig.content.length>60?'…':''}</span> <button onclick="msgCancelReplyAdmin()" class="msg-cancel-reply">✕</button>`;
            }
        }

        function msgCancelReplyAdmin() {
            msgAdminReplyTo = null;
            const preview = document.getElementById('msg-admin-side-reply-preview');
            if (preview) { preview.classList.add('hidden'); preview.innerHTML = ''; }
        }

        function msgSendAdmin() {
            if (!msgAdminCurrentConv) return;
            const input = document.getElementById('msg-admin-side-input');
            if (!input) return;
            const content = input.value.trim();
            if (!content) return;
            const msgs = msgGetMessages();
            // Get pseudo from existing messages in this conv
            const convMsgs = msgs.filter(m => m.convId === msgAdminCurrentConv);
            const pseudo = msgGetPseudoForConv(msgAdminCurrentConv, msgs);
            msgs.push({
                id: msgGenerateId(),
                convId: msgAdminCurrentConv,
                pseudo,
                sender: 'admin',
                senderLabel: 'Admin',
                content,
                date: new Date().toISOString(),
                replyTo: msgAdminReplyTo || null
            });
            msgSaveMessages(msgs);
            input.value = '';
            msgCancelReplyAdmin();
            msgUpdateCounter('msg-admin-side-input', 'msg-admin-side-counter');
            msgAdminRenderConversation();
            playSound('msg-send');
            if (typeof updateNotifBadges === 'function') updateNotifBadges();
        }

        /* ============================================================
           SYSTÈME DE SIGNALEMENT
        ============================================================ */

        let _reportImages = [];

        function openReportModal() {
            playSound('modal-open');
            document.getElementById('modal-report').classList.remove('hidden');
        }

        function closeReportModal() {
            playSound('modal-close');
            document.getElementById('modal-report').classList.add('hidden');
        }

        function closeReportConfirm() {
            playSound('modal-close');
            document.getElementById('modal-report-confirm').classList.add('hidden');
        }

        function updateReportSendBtn() {
            const title = document.getElementById('report-title-input').value.trim();
            const desc = document.getElementById('report-desc-input').value.trim();
            const btn = document.getElementById('report-send-btn');
            const countEl = document.getElementById('report-desc-count');
            if (countEl) countEl.textContent = document.getElementById('report-desc-input').value.length;
            const valid = title.length > 0 && desc.length > 0;
            btn.disabled = !valid;
            btn.classList.toggle('opacity-40', !valid);
            btn.classList.toggle('cursor-not-allowed', !valid);
        }

        function handleReportFiles(files) {
            if (!files || files.length === 0) return;
            for (const file of files) {
                if (!file.type.startsWith('image/')) continue;
                const reader = new FileReader();
                reader.onload = (e) => {
                    _reportImages.push({ name: file.name, dataUrl: e.target.result });
                    renderReportImagePreviews();
                };
                reader.readAsDataURL(file);
            }
            // Reset file input so same file can be re-added if needed
            document.getElementById('report-file-input').value = '';
        }

        function renderReportImagePreviews() {
            const container = document.getElementById('report-images-preview');
            container.innerHTML = '';
            _reportImages.forEach((img, idx) => {
                const wrap = document.createElement('div');
                wrap.className = 'relative w-16 h-16 rounded-xl overflow-hidden border border-black/10';
                wrap.innerHTML = `<img src="${img.dataUrl}" class="w-full h-full object-cover">
                    <button type="button" onclick="removeReportImage(${idx})" class="absolute top-0.5 right-0.5 bg-black/60 text-white rounded-full w-4 h-4 flex items-center justify-center text-[10px] leading-none font-bold hover:bg-black/80 transition">✕</button>`;
                container.appendChild(wrap);
            });
            // Add "+" button
            const addBtn = document.createElement('button');
            addBtn.type = 'button';
            addBtn.className = 'report-add-image-btn w-16 h-16 rounded-xl border-2 border-dashed border-black/20 flex items-center justify-center text-3xl text-black/30 hover:border-black/40 hover:text-black/50 transition bg-black/5';
            addBtn.textContent = '+';
            addBtn.onclick = () => document.getElementById('report-file-input').click();
            container.appendChild(addBtn);
        }

        function removeReportImage(idx) {
            _reportImages.splice(idx, 1);
            renderReportImagePreviews();
        }

        function openReportConfirm() {
            const title = document.getElementById('report-title-input').value.trim();
            const desc = document.getElementById('report-desc-input').value.trim();
            if (!title || !desc) return;
            playSound('modal-open');
            document.getElementById('modal-report-confirm').classList.remove('hidden');
        }

        function submitReport() {
            const title = document.getElementById('report-title-input').value.trim();
            const desc = document.getElementById('report-desc-input').value.trim();
            const now = new Date();
            const user = AuthService.getCurrentUser();
            const sender = (isGuestMode || !user) ? 'Invité' : (user.pseudo || 'Inconnu');
            const gameTitle = (currentGame && currentGame.quiz && currentGame.quiz.title) ? currentGame.quiz.title : 'Inconnu';

            const report = {
                id: 'rpt_' + Date.now(),
                title,
                description: desc,
                images: _reportImages.map(i => ({ name: i.name, dataUrl: i.dataUrl })),
                game: gameTitle,
                date: now.toISOString(),
                sender
            };

            // Sauvegarde locale (pour future intégration admin)
            try {
                const existing = JSON.parse(localStorage.getItem('cq_reports') || '[]');
                existing.push(report);
                localStorage.setItem('cq_reports', JSON.stringify(existing));
            } catch(e) {}

            // Réinitialisation
            document.getElementById('report-title-input').value = '';
            document.getElementById('report-desc-input').value = '';
            _reportImages = [];
            renderReportImagePreviews();
            updateReportSendBtn();

            document.getElementById('modal-report-confirm').classList.add('hidden');
            document.getElementById('modal-report').classList.add('hidden');
            playSound('action-confirm');
            if (typeof updateNotifBadges === 'function') updateNotifBadges();
        }

        // ============================================================
        // NOTIFICATION SYSTEM
        // ============================================================

        const NOTIF_USER_READ_TS_KEY = 'cq_notif_user_admin_read_ts';
        const NOTIF_ADMIN_CONV_READ_KEY = 'cq_notif_admin_conv_read'; // JSON obj { convId: lastReadMsgId }
        const NOTIF_REPORTS_SEEN_KEY = 'cq_notif_reports_seen'; // JSON array of seen report ids

        // ---- Helpers ----

        function notifGetAdminConvRead() {
            try { return JSON.parse(localStorage.getItem(NOTIF_ADMIN_CONV_READ_KEY) || '{}'); } catch(e) { return {}; }
        }
        function notifSaveAdminConvRead(obj) {
            localStorage.setItem(NOTIF_ADMIN_CONV_READ_KEY, JSON.stringify(obj));
        }
        function notifGetReportsSeen() {
            try { return JSON.parse(localStorage.getItem(NOTIF_REPORTS_SEEN_KEY) || '[]'); } catch(e) { return []; }
        }
        function notifSaveReportsSeen(arr) {
            localStorage.setItem(NOTIF_REPORTS_SEEN_KEY, JSON.stringify(arr));
        }

        // ---- Count unread admin messages for the logged-in user ----
        function notifCountUserUnreadAdmin() {
            const user = AuthService.getCurrentUser();
            if (!user) return 0;
            const readTs = localStorage.getItem(NOTIF_USER_READ_TS_KEY) || '0';
            const msgs = msgGetMessages().filter(m => m.convId === user.id && m.sender === 'admin' && m.date > readTs);
            return msgs.length;
        }

        // Mark admin chat as read for connected user (called when tab is opened)
        function notifMarkUserAdminRead() {
            localStorage.setItem(NOTIF_USER_READ_TS_KEY, new Date().toISOString());
            updateNotifBadges();
        }

        // ---- Count unread admin messages per conversation (admin view) ----
        function notifAdminCountUnreadPerConv() {
            const msgs = msgGetMessages();
            const convRead = notifGetAdminConvRead();
            const result = {};
            const convIds = [...new Set(msgs.map(m => m.convId))];
            convIds.forEach(cid => {
                const convMsgs = msgs.filter(m => m.convId === cid && m.sender === 'user');
                const lastReadId = convRead[cid];
                if (!lastReadId) {
                    result[cid] = convMsgs.length;
                } else {
                    const lastReadIdx = convMsgs.findIndex(m => m.id === lastReadId);
                    result[cid] = lastReadIdx === -1 ? convMsgs.length : convMsgs.length - lastReadIdx - 1;
                }
            });
            return result;
        }

        function notifAdminTotalUnreadChat() {
            const perConv = notifAdminCountUnreadPerConv();
            return Object.values(perConv).reduce((a, b) => a + b, 0);
        }

        // Mark a conversation as fully read (admin opens conversation)
        function notifAdminMarkConvRead(convId) {
            const msgs = msgGetMessages().filter(m => m.convId === convId && m.sender === 'user');
            if (!msgs.length) return;
            const convRead = notifGetAdminConvRead();
            convRead[convId] = msgs[msgs.length - 1].id;
            notifSaveAdminConvRead(convRead);
            updateNotifBadges();
        }

        // ---- Reports ----
        function notifReportsCount() {
            return reportAdminGetAll().length;
        }

        function notifReportsAllSeen() {
            const reports = reportAdminGetAll();
            if (!reports.length) return true;
            const seen = notifGetReportsSeen();
            return reports.every(r => seen.includes(r.id));
        }

        function notifMarkReportSeen(id) {
            const seen = notifGetReportsSeen();
            if (!seen.includes(id)) { seen.push(id); notifSaveReportsSeen(seen); }
            updateNotifBadges();
        }

        // ---- Update all badge UI ----
        function notifSetBadge(el, count, colorClass) {
            if (!el) return;
            if (!count || count <= 0) {
                el.classList.add('hidden');
                el.textContent = '';
                return;
            }
            el.classList.remove('hidden', 'notif-badge-gold', 'notif-badge-blue', 'notif-badge-gray');
            el.classList.add(colorClass);
            el.textContent = count > 99 ? '99+' : String(count);
        }

        function updateNotifBadges() {
            const isAdmin = typeof hasAdminSession === 'function';

            // ---- USER SESSION ----
            const userBadge = document.getElementById('notif-badge-user-msg');
            const userTabBadge = document.getElementById('notif-tab-user-admin');
            if (userBadge || userTabBadge) {
                const unread = notifCountUserUnreadAdmin();
                notifSetBadge(userBadge, unread, 'notif-badge-gold');
                // Tab badge: only show on tab when user is NOT on admin tab
                const adminTab = document.getElementById('msg-tab-admin');
                const isOnAdminTab = adminTab && adminTab.classList.contains('msg-tab-active');
                notifSetBadge(userTabBadge, isOnAdminTab ? 0 : unread, 'notif-badge-gold');
            }

            // ---- ADMIN SESSION ----
            // Check if admin UI elements are present
            const adminChatBadges = document.querySelectorAll('.notif-admin-chat');
            const adminReportBadges = document.querySelectorAll('.notif-admin-reports');

            if (adminChatBadges.length || adminReportBadges.length) {
                const totalUnreadChat = notifAdminTotalUnreadChat();
                const reportsCount = notifReportsCount();
                const reportsSeen = notifReportsAllSeen();
                const reportColorClass = (reportsCount > 0 && reportsSeen) ? 'notif-badge-gray' : 'notif-badge-blue';

                // Nav buttons (multiple, from different headers)
                adminChatBadges.forEach(el => notifSetBadge(el, totalUnreadChat, 'notif-badge-gold'));
                adminReportBadges.forEach(el => {
                    if (!el) return;
                    if (!reportsCount) { el.classList.add('hidden'); return; }
                    el.classList.remove('hidden', 'notif-badge-gold', 'notif-badge-blue', 'notif-badge-gray');
                    el.classList.add(reportColorClass);
                    el.textContent = reportsCount > 99 ? '99+' : String(reportsCount);
                });

                // Admin messaging page tab badges
                const tabChatBadge = document.getElementById('notif-tab-admin-chat');
                const tabReportsBadge = document.getElementById('notif-tab-admin-reports');
                const tabChat = document.getElementById('msg-admin-tab-chat');
                const tabReports = document.getElementById('msg-admin-tab-reports');
                const isOnChatTab = tabChat && tabChat.classList.contains('msg-tab-active');
                const isOnReportsTab = tabReports && tabReports.classList.contains('msg-tab-active');

                notifSetBadge(tabChatBadge, isOnChatTab ? 0 : totalUnreadChat, 'notif-badge-gold');
                if (tabReportsBadge) {
                    if (!reportsCount || isOnReportsTab) { tabReportsBadge.classList.add('hidden'); }
                    else {
                        tabReportsBadge.classList.remove('hidden', 'notif-badge-gold', 'notif-badge-blue', 'notif-badge-gray');
                        tabReportsBadge.classList.add(reportColorClass);
                        tabReportsBadge.textContent = reportsCount > 99 ? '99+' : String(reportsCount);
                    }
                }
            }
        }


        /* ============================================================
           MODES QUESTION RÉDACTION & JETPUNK — logique complète
           ============================================================ */

        // ---- Helpers ----
        function _normalize(str) {
            return (str || '').toLowerCase().replace(/\s+/g, '')
                .normalize('NFD').replace(/[\u0300-\u036f]/g, '');
        }

        function _matchAnswer(input, correct) {
            const a = _normalize(input);
            const b = _normalize(correct);
            return a === b;
        }

        // ---- Mode detection ----
        function cqGetGameMode() {
            const quiz = currentGame && currentGame.quiz;
            return (quiz && quiz.type) || 'QCM';
        }

        // ---- Override renderQuestion to handle new modes ----
        const _origRenderQuestion = renderQuestion;
        renderQuestion = function() {
            const mode = cqGetGameMode();
            if (mode === 'Question Rédaction') {
                renderRedactionQuestion();
            } else if (mode === 'JetPunk') {
                renderJetPunkGame();
            } else {
                _origRenderQuestion();
            }
        };

        // ---- QUESTION RÉDACTION ----
        function renderRedactionQuestion() {
            const question = currentGame.quiz.questions[currentGame.currentQIndex];
            if (!question) { finishQuiz(); return; }

            _gameStopCurrentAudio();

            document.getElementById('game-question-num').textContent =
                `${currentGame.currentQIndex + 1}/${currentGame.quiz.questions.length}`;
            document.getElementById('game-question-text').textContent = question.text;
            _renderQuestionMedia(question);

            const grid = document.getElementById('game-answers-grid');
            grid.innerHTML = '';
            grid.classList.remove('quiz-images-grid', 'quiz-audio-grid');
            grid.style.display = 'none';

            const redArea = document.getElementById('game-redaction-area');
            const jpArea = document.getElementById('game-jetpunk-area');
            if (redArea) { redArea.classList.remove('hidden'); redArea.style.display = 'flex'; }
            if (jpArea) { jpArea.classList.add('hidden'); jpArea.style.display = 'none'; }

            const input = document.getElementById('game-redaction-input');
            const feedback = document.getElementById('game-redaction-feedback');
            if (input) { input.value = ''; input.disabled = false; input.className = input.className.replace('redaction-error','').trim(); setTimeout(() => input.focus(), 80); }
            if (feedback) { feedback.className = feedback.className.replace(/\s*(visible|feedback-correct|feedback-wrong)/g,'').trim(); feedback.style.display = 'none'; feedback.textContent = ''; }

            const skipBtn = document.getElementById('game-redaction-skip-btn');
            if (skipBtn) skipBtn.style.display = '';

            startQuestionTimer(question.time || 20);
        }

        function handleRedactionValidate() {
            if (!currentGame.canAnswer) return;
            const input = document.getElementById('game-redaction-input');
            const question = currentGame.quiz.questions[currentGame.currentQIndex];
            if (!input || !question) return;
            const userVal = input.value;
            const correctAnswer = question.answers.find(a => a.isCorrect);
            const correct = correctAnswer ? correctAnswer.text : '';
            if (_matchAnswer(userVal, correct)) {
                // Correct
                currentGame.canAnswer = false;
                stopGameTimers();
                currentGame.score += cqNoTimerMode ? BASE_POINTS : computeQuestionPoints();
                updateScoreDisplay();
                playSound('quiz-correct');
                _showRedactionFeedback(true, correct);
                input.disabled = true;
                const skipBtn = document.getElementById('game-redaction-skip-btn');
                if (skipBtn) skipBtn.style.display = 'none';
                scheduleNextQuestion();
            } else {
                // Wrong — flash red, keep timer
                playSound('quiz-wrong');
                _flashRedactionError(input);
                _showRedactionFeedback(false, null);
                input.value = '';
            }
        }

        function _flashRedactionError(input) {
            if (!input) return;
            input.classList.add('redaction-error');
            setTimeout(() => { if (input) input.classList.remove('redaction-error'); }, 500);
        }

        function _showRedactionFeedback(isCorrect, correctText) {
            const feedback = document.getElementById('game-redaction-feedback');
            if (!feedback) return;
            feedback.className = 'visible ' + (isCorrect ? 'feedback-correct' : 'feedback-wrong');
            feedback.style.display = 'block';
            if (isCorrect) {
                feedback.textContent = '✓ Correct !';
            } else {
                feedback.textContent = '✗ Incorrect — réessayez';
                setTimeout(() => {
                    if (feedback) { feedback.style.display = 'none'; feedback.textContent = ''; }
                }, 500);
            }
        }

        function handleRedactionSkip() {
            if (!currentGame.canAnswer) return;
            currentGame.canAnswer = false;
            stopGameTimers();
            const question = currentGame.quiz.questions[currentGame.currentQIndex];
            const correctAnswer = question && question.answers.find(a => a.isCorrect);
            const correct = correctAnswer ? correctAnswer.text : '?';
            const feedback = document.getElementById('game-redaction-feedback');
            if (feedback) {
                feedback.className = 'visible feedback-wrong';
                feedback.style.display = 'block';
                feedback.textContent = `Réponse : ${correct}`;
            }
            const input = document.getElementById('game-redaction-input');
            if (input) input.disabled = true;
            const skipBtn = document.getElementById('game-redaction-skip-btn');
            if (skipBtn) skipBtn.style.display = 'none';
            playSound('quiz-timeout');
            scheduleNextQuestion();
        }

        // Override handleTimeUp to handle redaction
        const _origHandleTimeUp = handleTimeUp;
        handleTimeUp = function() {
            const mode = cqGetGameMode();
            if (mode === 'Question Rédaction') {
                if (!currentGame.canAnswer) return;
                currentGame.canAnswer = false;
                _gameStopCurrentAudio();
                playSound('quiz-timeout');
                const question = currentGame.quiz.questions[currentGame.currentQIndex];
                const correctAnswer = question && question.answers.find(a => a.isCorrect);
                const correct = correctAnswer ? correctAnswer.text : '?';
                const feedback = document.getElementById('game-redaction-feedback');
                if (feedback) {
                    feedback.className = 'visible feedback-wrong';
                    feedback.style.display = 'block';
                    feedback.textContent = `Temps écoulé ! Réponse : ${correct}`;
                }
                const input = document.getElementById('game-redaction-input');
                if (input) input.disabled = true;
                const skipBtn = document.getElementById('game-redaction-skip-btn');
                if (skipBtn) skipBtn.style.display = 'none';
                scheduleNextQuestion();
            } else {
                _origHandleTimeUp();
            }
        };

        // ---- JETPUNK ----
        let _jpState = null; // { items: [{answer, hints, found}], foundCount, total }

        function renderJetPunkGame() {
            const question = currentGame.quiz.questions[0]; // JetPunk = 1 slide
            if (!question) { finishQuiz(); return; }

            _gameStopCurrentAudio();

            document.getElementById('game-question-num').textContent = '1/1';
            document.getElementById('game-question-text').textContent = question.text || 'Retrouvez toutes les réponses';
            _renderQuestionMedia(question);

            const grid = document.getElementById('game-answers-grid');
            grid.innerHTML = '';
            grid.classList.remove('quiz-images-grid', 'quiz-audio-grid');
            grid.style.display = 'none';

            const redArea = document.getElementById('game-redaction-area');
            const jpArea = document.getElementById('game-jetpunk-area');
            if (redArea) { redArea.classList.add('hidden'); redArea.style.display = 'none'; }
            if (jpArea) { jpArea.classList.remove('hidden'); jpArea.style.display = 'flex'; }

            // Build state from answers
            const items = (question.answers || []).map(a => ({
                answer: a.text || '',
                hints: Array.isArray(a.jpHints) ? a.jpHints : [],
                found: false
            }));
            _jpState = { items, foundCount: 0, total: items.length };

            const input = document.getElementById('game-jetpunk-input');
            if (input) { input.value = ''; setTimeout(() => input.focus(), 80); }

            _renderJpList();
            startQuestionTimer(question.time || 120);
        }

        function _renderJpList() {
            if (!_jpState) return;
            const list = document.getElementById('game-jetpunk-list');
            if (!list) return;

            const progressHtml = `<div class="jp-progress-bar">
                <span>${_jpState.foundCount}/${_jpState.total}</span>
                <div class="jp-progress-track"><div class="jp-progress-fill" style="width:${_jpState.total ? (_jpState.foundCount/_jpState.total*100) : 0}%"></div></div>
            </div>`;

            const itemsHtml = _jpState.items.map((item, idx) => {
                const foundClass = item.found ? 'jp-found' : '';
                const checkContent = item.found ? '✓' : '';
                const labelContent = item.found ? escapeHtml(item.answer) : '&nbsp;';

                // Hints (shown always in text, image shown as small preview)
                let hintsHtml = '';
                if (item.hints && item.hints.length > 0) {
                    hintsHtml = '<div class="jp-answer-hint">';
                    item.hints.forEach(h => {
                        if (h.type === 'text') hintsHtml += `<span>${escapeHtml(h.value || '')}</span>`;
                        else if (h.type === 'image' && h.value) hintsHtml += `<img src="${h.value}" class="jp-hint-img" alt="Indice">`;
                        else if (h.type === 'audio' && h.value) hintsHtml += `<button type="button" onclick="(function(){var a=new Audio('${h.value.replace(/'/g,"\\'")}');a.volume=AudioManager.getVolume();a.play().catch(()=>{});})()">🔊</button>`;
                    });
                    hintsHtml += '</div>';
                }

                return `<div class="jp-answer-row ${foundClass}" data-jp-idx="${idx}">
                    <div class="jp-answer-check">${checkContent}</div>
                    <div class="jp-answer-label">${labelContent}</div>
                    ${!item.found ? hintsHtml : ''}
                </div>`;
            }).join('');

            list.innerHTML = progressHtml + itemsHtml;
        }

        function handleJetPunkInput(value) {
            if (!currentGame.canAnswer || !_jpState) return;
            const trimmed = value.trim();
            if (!trimmed) return;
            let found = false;
            for (let i = 0; i < _jpState.items.length; i++) {
                const item = _jpState.items[i];
                if (!item.found && _matchAnswer(trimmed, item.answer)) {
                    item.found = true;
                    _jpState.foundCount++;
                    found = true;
                    // Clear input
                    const input = document.getElementById('game-jetpunk-input');
                    if (input) input.value = '';
                    playSound('quiz-correct');
                    currentGame.score += cqNoTimerMode ? BASE_POINTS : Math.round(computeQuestionPoints() / _jpState.total);
                    updateScoreDisplay();
                    _renderJpList();
                    // Check if all found
                    if (_jpState.foundCount >= _jpState.total) {
                        currentGame.canAnswer = false;
                        stopGameTimers();
                        playSound('quiz-finish');
                        setTimeout(() => finishQuiz(), 800);
                    }
                    break;
                }
            }
        }

        // Override handleTimeUp for JetPunk
        const _origHandleTimeUpRef = handleTimeUp;
        handleTimeUp = function() {
            const mode = cqGetGameMode();
            if (mode === 'JetPunk') {
                if (!currentGame.canAnswer) return;
                currentGame.canAnswer = false;
                _gameStopCurrentAudio();
                playSound('quiz-timeout');
                // Reveal all unfound answers
                if (_jpState) {
                    _jpState.items.forEach(i => { i.found = true; });
                    _renderJpList();
                }
                setTimeout(() => finishQuiz(), 1500);
            } else {
                _origHandleTimeUpRef();
            }
        };

        // ---- Cleanup in-game areas when switching modes ----
        const _origBeginQuiz = beginQuiz;
        beginQuiz = function() {
            _hideSpecialGameAreas();
            _origBeginQuiz();
        };
        const _origBeginQuizNoTimer = beginQuizNoTimer;
        beginQuizNoTimer = function() {
            _hideSpecialGameAreas();
            _origBeginQuizNoTimer();
        };
        function _hideSpecialGameAreas() {
            const redArea = document.getElementById('game-redaction-area');
            const jpArea = document.getElementById('game-jetpunk-area');
            if (redArea) { redArea.classList.add('hidden'); redArea.style.display = 'none'; }
            if (jpArea) { jpArea.classList.add('hidden'); jpArea.style.display = 'none'; }
            const grid = document.getElementById('game-answers-grid');
            if (grid) grid.style.display = '';
        }

        // ---- startQuiz: normalize JetPunk (1 slide only, no shuffle of answers) ----
        const _origStartQuiz = startQuiz;
        startQuiz = function(quizOrId, noTimer) {
            let quiz = null;
            if (!quizOrId) return;
            if (typeof quizOrId === 'string') quiz = QUIZ_REGISTRY[quizOrId] || null;
            else if (typeof quizOrId === 'object') quiz = quizOrId;
            if (!quiz) { _origStartQuiz(quizOrId, noTimer); return; }

            if (quiz.type === 'JetPunk') {
                // For JetPunk: don't shuffle answers, keep 1 slide as question
                cqNoTimerMode = !!noTimer;
                stopGameTimers();
                currentGame = {
                    quiz: quiz,
                    currentQIndex: 0,
                    score: 0,
                    timerInterval: null,
                    transitionTimeout: null,
                    timeLeft: 0,
                    totalTime: 0,
                    canAnswer: false
                };
                document.getElementById('game-quiz-title').textContent = quiz.title || 'Quiz';
                const testBanner = document.getElementById('cq-admin-test-banner');
                if (testBanner) testBanner.classList.toggle('hidden', !cqAdminTestMode);
                updateScoreDisplay();
                const descEl = document.getElementById('game-description');
                if (descEl) {
                    if (quiz.description) { descEl.textContent = quiz.description; descEl.classList.remove('hidden'); }
                    else descEl.classList.add('hidden');
                }
                showPreGameScreen(quiz);
                showView('view-game');
                cqUpdateFavoriteButtonState('game');
                if (quiz.id) cqRenderQuizLeaderboard(quiz.id);
                else { const s = document.getElementById('quiz-leaderboard-section'); if (s) s.classList.add('hidden'); }
            } else {
                _origStartQuiz(quizOrId, noTimer);
            }
        };

        // ---- EDITOR: mode-aware rendering ----

        // Override cqRenderAllEditor to switch panels
        const _origCqRenderAllEditor = cqRenderAllEditor;
        cqRenderAllEditor = function() {
            const mode = cqGetCurrentEditingMode();
            const bodyQcm = document.getElementById('cqed-body-qcm');
            const bodyJp = document.getElementById('cqed-body-jetpunk');
            const slidesCard = bodyQcm ? bodyQcm.querySelector('.cqed-slides-card') : null;
            const addDiapoBtn = document.getElementById('cq-add-diapo-btn');
            const deleteDiapoBtn = document.getElementById('cq-delete-current-diapo-btn');

            if (mode === 'JetPunk') {
                if (bodyQcm) { bodyQcm.classList.add('hidden'); bodyQcm.style.display = 'none'; }
                if (bodyJp) { bodyJp.classList.remove('hidden'); bodyJp.style.display = 'flex'; }
                if (addDiapoBtn) addDiapoBtn.style.display = 'none';
                cqJpRenderEditor();
            } else {
                if (bodyQcm) { bodyQcm.classList.remove('hidden'); bodyQcm.style.display = ''; }
                if (bodyJp) { bodyJp.classList.add('hidden'); bodyJp.style.display = 'none'; }
                if (addDiapoBtn) addDiapoBtn.style.display = '';
                if (mode === 'Question Rédaction') {
                    // Single correct answer mode: label change + hide add-answer if already has one
                    const label = document.getElementById('cq-answers-section-label');
                    if (label) label.textContent = 'Réponse correcte';
                    const addBtn = document.getElementById('cq-add-answer-btn');
                    if (addBtn) addBtn.style.display = 'none';
                    // Also hide slides panel for simplicity (multiple slides are ok)
                } else {
                    const label = document.getElementById('cq-answers-section-label');
                    if (label) label.textContent = 'Réponses';
                    const addBtn = document.getElementById('cq-add-answer-btn');
                    if (addBtn) addBtn.style.display = '';
                }
                _origCqRenderAllEditor();
            }
        };

        // Override cqValidateDraft to handle new modes
        const _origCqValidateDraft = cqValidateDraft;
        cqValidateDraft = function(showHints) {
            const mode = cqGetCurrentEditingMode();
            if (mode === 'JetPunk') {
                return cqJpValidate(showHints);
            } else if (mode === 'Question Rédaction') {
                return cqRedactionValidateDraft(showHints);
            }
            return _origCqValidateDraft(showHints);
        };

        // ---- Question Rédaction draft validation ----
        function cqRedactionValidateDraft(showHints) {
            cqDraftClamp();
            const slides = cqQuizDraft.slides;
            let allOk = slides.length >= 1;
            for (const slide of slides) {
                if (!(slide.questionText || '').trim()) allOk = false;
                const answers = slide.answers || [];
                const hasCorrect = answers.some(a => a.isCorrect && (a.text || '').trim());
                if (!hasCorrect) allOk = false;
            }
            if (showHints) {
                const hint = document.getElementById('cq-validation-hint');
                if (hint) {
                    if (!allOk) hint.textContent = 'Chaque diapo doit avoir une question et une réponse correcte renseignée.';
                    hint.classList.toggle('hidden', allOk);
                }
            }
            return allOk;
        }

        // Also customize cqRenderAnswersEditor for Rédaction mode: force 1 answer, no toggle
        const _origCqRenderAnswersEditor = cqRenderAnswersEditor;
        cqRenderAnswersEditor = function() {
            const mode = cqGetCurrentEditingMode();
            if (mode === 'Question Rédaction') {
                const slide = cqDraftGetCurrentSlide();
                // Ensure exactly 1 answer
                if (!slide.answers || slide.answers.length === 0) {
                    slide.answers = [{ text: '', isCorrect: true, imageData: null, audioData: null }];
                }
                // Force isCorrect on first
                slide.answers[0].isCorrect = true;
                // Trim to 1 answer
                slide.answers = slide.answers.slice(0, 1);

                const questionInput = document.getElementById('cq-question-text-input');
                if (questionInput && questionInput.value !== slide.questionText) questionInput.value = slide.questionText || '';

                const qMediaContainer = document.getElementById('cq-question-media-editor');
                if (qMediaContainer) {
                    const hasQImg = !!slide.questionImage, hasQAudio = !!slide.questionAudio;
                    const locked = false;
                    qMediaContainer.innerHTML = `<div class="cqed-question-media-row">
                        <div class="cqed-question-media-item">
                            <span class="cqed-label" style="font-size:0.65rem;">Image question</span>
                            ${hasQImg ? `<img src="${slide.questionImage}" class="cqed-question-img-preview" alt="">` : ''}
                            <div class="cqed-question-media-actions">
                                <button type="button" class="cqed-answer-img-upload-btn" onclick="document.getElementById('cq-question-img-input').click()">${hasQImg ? 'Remplacer' : 'Ajouter une image'}</button>
                                ${hasQImg ? `<button type="button" class="cqed-answer-img-remove-btn" onclick="cqRemoveQuestionImage()">Supprimer</button>` : ''}
                            </div>
                            <input type="file" accept="image/*" class="hidden" id="cq-question-img-input" onchange="cqHandleQuestionImageUpload(this)">
                        </div>
                        <div class="cqed-question-media-item">
                            <span class="cqed-label" style="font-size:0.65rem;">Audio question</span>
                            ${hasQAudio ? `<div class="cqed-audio-preview"><audio controls src="${slide.questionAudio}" style="height:28px;width:100%;"></audio></div>` : ''}
                            <div class="cqed-question-media-actions">
                                <button type="button" class="cqed-answer-img-upload-btn" onclick="document.getElementById('cq-question-audio-input').click()">${hasQAudio ? 'Remplacer' : 'Ajouter un audio'}</button>
                                ${hasQAudio ? `<button type="button" class="cqed-answer-img-remove-btn" onclick="cqRemoveQuestionAudio()">Supprimer</button>` : ''}
                            </div>
                            <input type="file" accept="audio/*" class="hidden" id="cq-question-audio-input" onchange="cqHandleQuestionAudioUpload(this)">
                        </div>
                    </div>`;
                }

                const list = document.getElementById('cq-answers-list');
                if (list) {
                    const a = slide.answers[0];
                    list.innerHTML = `<div class="cqed-answer-card is-correct" style="border:2px solid rgba(34,197,94,0.4);">
                        <div class="cqed-answer-main-row">
                            <div style="font-size:0.7rem;font-weight:700;font-family:'Plus Jakarta Sans',sans-serif;opacity:0.6;min-width:3rem;">Réponse</div>
                            <input type="text" class="cqed-answer-input" value="${escapeHtml(a.text || '')}" placeholder="Réponse correcte" oninput="cqUpdateAnswerText(0,this.value)" />
                        </div>
                    </div>`;
                }

                const btn = document.getElementById('cq-create-quiz-btn');
                if (btn) btn.textContent = cqIsModifyingExisting ? 'Valider les modifications' : 'Créer le quiz';
                cqUpdateEditorCreateButtonState();
            } else {
                _origCqRenderAnswersEditor();
            }
        };

        // ---- JetPunk editor logic ----
        // JetPunk stores data in a single slide with:
        //   slide.questionText = title/consigne
        //   slide.questionImage / questionAudio = media for title
        //   slide.answers = [{text: 'answer', isCorrect: true, jpHints: [{type:'text'|'image'|'audio', value:'...'}]}]

        function cqJpGetSlide() {
            cqDraftClamp();
            const slide = cqQuizDraft.slides[0];
            if (!Array.isArray(slide.answers)) slide.answers = [];
            return slide;
        }

        function cqJpUpdateTitle(val) {
            const slide = cqQuizDraft.slides[0];
            if (slide) { slide.questionText = val; }
            cqUpdateEditorCreateButtonState();
        }

        function cqJpAddItem() {
            const slide = cqJpGetSlide();
            slide.answers.push({ text: '', isCorrect: true, jpHints: [] });
            cqJpRenderEditor();
            cqUpdateEditorCreateButtonState();
        }

        function cqJpDeleteItem(idx) {
            const slide = cqJpGetSlide();
            slide.answers.splice(idx, 1);
            cqJpRenderEditor();
            cqUpdateEditorCreateButtonState();
        }

        function cqJpUpdateItemAnswer(idx, val) {
            const slide = cqJpGetSlide();
            if (slide.answers[idx]) slide.answers[idx].text = val;
            cqUpdateEditorCreateButtonState();
        }

        function cqJpAddHint(itemIdx) {
            const slide = cqJpGetSlide();
            const item = slide.answers[itemIdx];
            if (!item) return;
            if (!Array.isArray(item.jpHints)) item.jpHints = [];
            if (item.jpHints.length >= 3) return;
            item.jpHints.push({ type: 'text', value: '' });
            cqJpRenderEditor();
        }

        function cqJpRemoveHint(itemIdx, hintIdx) {
            const slide = cqJpGetSlide();
            const item = slide.answers[itemIdx];
            if (!item || !Array.isArray(item.jpHints)) return;
            item.jpHints.splice(hintIdx, 1);
            cqJpRenderEditor();
        }

        function cqJpUpdateHintType(itemIdx, hintIdx, type) {
            const slide = cqJpGetSlide();
            const item = slide.answers[itemIdx];
            if (!item || !item.jpHints[hintIdx]) return;
            item.jpHints[hintIdx].type = type;
            item.jpHints[hintIdx].value = '';
            cqJpRenderEditor();
        }

        function cqJpUpdateHintText(itemIdx, hintIdx, val) {
            const slide = cqJpGetSlide();
            const item = slide.answers[itemIdx];
            if (!item || !item.jpHints[hintIdx]) return;
            item.jpHints[hintIdx].value = val;
        }

        function cqJpTriggerHintFile(itemIdx, hintIdx, accept) {
            const id = `cq-jp-hint-file-${itemIdx}-${hintIdx}`;
            const input = document.getElementById(id);
            if (input) input.click();
        }

        function cqJpHandleHintFile(itemIdx, hintIdx, input) {
            const file = input && input.files && input.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = (e) => {
                const slide = cqJpGetSlide();
                const item = slide.answers[itemIdx];
                if (!item || !item.jpHints[hintIdx]) return;
                item.jpHints[hintIdx].value = e.target.result;
                cqJpRenderEditor();
            };
            reader.readAsDataURL(file);
        }

        function cqJpRenderEditor() {
            const slide = cqJpGetSlide();

            const titleInput = document.getElementById('cq-jp-title-input');
            if (titleInput && titleInput.value !== slide.questionText) titleInput.value = slide.questionText || '';

            // Title media
            const qMedia = document.getElementById('cq-jp-title-media-editor');
            if (qMedia) {
                const hasImg = !!slide.questionImage, hasAudio = !!slide.questionAudio;
                qMedia.innerHTML = `<div class="cqed-question-media-row">
                    <div class="cqed-question-media-item">
                        <span class="cqed-label" style="font-size:0.6rem;">Image consigne</span>
                        ${hasImg ? `<img src="${slide.questionImage}" class="cqed-question-img-preview" alt="">` : ''}
                        <div class="cqed-question-media-actions">
                            <button type="button" class="cqed-answer-img-upload-btn" onclick="document.getElementById('cq-jp-consigne-img').click()">${hasImg ? 'Remplacer' : 'Ajouter'}</button>
                            ${hasImg ? `<button type="button" class="cqed-answer-img-remove-btn" onclick="cqJpRemoveConsigneImg()">Supprimer</button>` : ''}
                        </div>
                        <input type="file" accept="image/*" class="hidden" id="cq-jp-consigne-img" onchange="cqJpHandleConsigneImg(this)">
                    </div>
                    <div class="cqed-question-media-item">
                        <span class="cqed-label" style="font-size:0.6rem;">Audio consigne</span>
                        ${hasAudio ? `<audio controls src="${slide.questionAudio}" style="height:24px;width:100%;margin-top:2px;"></audio>` : ''}
                        <div class="cqed-question-media-actions">
                            <button type="button" class="cqed-answer-img-upload-btn" onclick="document.getElementById('cq-jp-consigne-audio').click()">${hasAudio ? 'Remplacer' : 'Ajouter'}</button>
                            ${hasAudio ? `<button type="button" class="cqed-answer-img-remove-btn" onclick="cqJpRemoveConsigneAudio()">Supprimer</button>` : ''}
                        </div>
                        <input type="file" accept="audio/*" class="hidden" id="cq-jp-consigne-audio" onchange="cqJpHandleConsigneAudio(this)">
                    </div>
                </div>`;
            }

            const list = document.getElementById('cq-jp-items-list');
            if (!list) return;

            list.innerHTML = (slide.answers || []).map((item, idx) => {
                const hints = Array.isArray(item.jpHints) ? item.jpHints : [];
                const canAddHint = hints.length < 3;

                const hintsHtml = hints.map((h, hIdx) => {
                    const isText = h.type === 'text';
                    const isImage = h.type === 'image';
                    const isAudio = h.type === 'audio';
                    const accept = isImage ? 'image/*' : 'audio/*';
                    const fileId = `cq-jp-hint-file-${idx}-${hIdx}`;
                    let valueHtml = '';
                    if (isText) {
                        valueHtml = `<input type="text" class="cq-jp-hint-text-input" value="${escapeHtml(h.value||'')}" placeholder="Texte de l'indice" oninput="cqJpUpdateHintText(${idx},${hIdx},this.value)">`;
                    } else {
                        const previewHtml = h.value ? (isImage ? `<img src="${h.value}" style="max-height:1.5rem;border-radius:0.2rem;">` : `<audio controls src="${h.value}" style="height:22px;"></audio>`) : '';
                        valueHtml = `${previewHtml}<button type="button" class="cq-jp-hint-file-btn" onclick="cqJpTriggerHintFile(${idx},${hIdx},'${accept}')">${h.value ? 'Remplacer' : 'Choisir un fichier'}</button>
                        <input type="file" accept="${accept}" class="hidden" id="${fileId}" onchange="cqJpHandleHintFile(${idx},${hIdx},this)">`;
                    }
                    return `<div class="cq-jp-hint-entry">
                        <select class="cq-jp-hint-type-select" onchange="cqJpUpdateHintType(${idx},${hIdx},this.value)">
                            <option value="text" ${isText?'selected':''}>Texte</option>
                            <option value="image" ${isImage?'selected':''}>Image</option>
                            <option value="audio" ${isAudio?'selected':''}>Audio</option>
                        </select>
                        ${valueHtml}
                        <button type="button" class="cq-jp-hint-remove" onclick="cqJpRemoveHint(${idx},${hIdx})" title="Supprimer cet indice">✕</button>
                    </div>`;
                }).join('');

                return `<div class="cq-jp-item-card">
                    <div class="cq-jp-item-row">
                        <span class="cq-jp-item-num">${idx + 1}</span>
                        <input type="text" class="cq-jp-item-answer-input" value="${escapeHtml(item.text||'')}" placeholder="Réponse à trouver…" oninput="cqJpUpdateItemAnswer(${idx},this.value)">
                        <button type="button" class="cq-jp-item-delete" onclick="cqJpDeleteItem(${idx})">✕</button>
                    </div>
                    ${hints.length > 0 || canAddHint ? `<div class="cq-jp-hint-row">
                        <span class="cq-jp-hint-label">Indices (${hints.length}/3)</span>
                        ${hintsHtml}
                        ${canAddHint ? `<button type="button" class="cq-jp-add-hint-btn" onclick="cqJpAddHint(${idx})">+ Indice</button>` : ''}
                    </div>` : ''}
                </div>`;
            }).join('');

            cqUpdateEditorCreateButtonState();
        }

        function cqJpHandleConsigneImg(input) {
            const file = input && input.files && input.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = e => { const s = cqJpGetSlide(); s.questionImage = e.target.result; cqJpRenderEditor(); };
            reader.readAsDataURL(file);
        }
        function cqJpRemoveConsigneImg() { const s = cqJpGetSlide(); s.questionImage = null; cqJpRenderEditor(); }
        function cqJpHandleConsigneAudio(input) {
            const file = input && input.files && input.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = e => { const s = cqJpGetSlide(); s.questionAudio = e.target.result; cqJpRenderEditor(); };
            reader.readAsDataURL(file);
        }
        function cqJpRemoveConsigneAudio() { const s = cqJpGetSlide(); s.questionAudio = null; cqJpRenderEditor(); }

        function cqJpValidate(showHints) {
            const slide = cqJpGetSlide();
            const ok = !!(slide.questionText || '').trim() &&
                Array.isArray(slide.answers) &&
                slide.answers.length >= 2 &&
                slide.answers.every(a => (a.text || '').trim());
            if (showHints) {
                const hint = document.getElementById('cq-validation-hint');
                if (hint) {
                    hint.classList.toggle('hidden', ok);
                    if (!ok) hint.textContent = 'JetPunk : saisissez une consigne et au moins 2 réponses (toutes renseignées).';
                }
            }
            return ok;
        }

        // Adapt cqNormalizeQuizContent to preserve jpHints
        const _origNormalize = cqNormalizeQuizContent;
        cqNormalizeQuizContent = function(maybeContent) {
            const result = _origNormalize(maybeContent);
            // Re-pass jpHints from original if present + GeoCoast'R properties
            if (maybeContent && Array.isArray(maybeContent.slides)) {
                result.slides = result.slides.map((s, i) => {
                    const orig = maybeContent.slides[i];
                    if (!orig) return s;
                    // Preserve JetPunk hints
                    s.answers = s.answers.map((a, j) => {
                        const origA = orig.answers && orig.answers[j];
                        if (origA && Array.isArray(origA.jpHints)) a.jpHints = origA.jpHints;
                        return a;
                    });
                    // Preserve GeoCoast'R properties
                    if (orig.gcrTarget) s.gcrTarget = orig.gcrTarget;
                    if (orig.gcrView) s.gcrView = orig.gcrView;
                    if (orig.gcrMaxDist) s.gcrMaxDist = orig.gcrMaxDist;
                    if (orig.gcrTime) s.gcrTime = orig.gcrTime;
                    return s;
                });
            }
            return result;
        };

        // Adapt quiz conversion for game play: convert slides→questions for JetPunk
        const _origStartQuizRef = startQuiz;
        // Patch the quiz object build for non-registry quizzes (from cqGetQuizzes)
        // The existing cqOnPublicQuizCardClick / cqAdminTestGame convert quiz to startQuiz format
        // We need to ensure JetPunk slides → questions properly
        // This is done in cqBuildQuizForPlay below (patch existing function if it exists)
        if (typeof cqBuildQuizForPlay === 'function') {
            const _origBuild = cqBuildQuizForPlay;
            cqBuildQuizForPlay = function(quiz) {
                if (quiz.type === 'JetPunk') return cqBuildJetPunkForPlay(quiz);
                return _origBuild(quiz);
            };
        }

        function cqBuildJetPunkForPlay(quiz) {
            const slides = quiz.content && quiz.content.slides ? quiz.content.slides : [];
            const slide = slides[0] || { questionText: '', answers: [] };
            // Single question with all answers as "correct"
            const questions = [{
                text: slide.questionText || quiz.title,
                time: 120,
                questionImage: slide.questionImage || null,
                questionAudio: slide.questionAudio || null,
                answers: (slide.answers || []).map(a => ({
                    text: a.text,
                    isCorrect: true,
                    jpHints: Array.isArray(a.jpHints) ? a.jpHints : []
                }))
            }];
            return Object.assign({}, quiz, { questions });
        }

        // Patch wherever quiz content is built for play
        // Look for cqOnPublicQuizCardClick or similar and intercept building
        // The existing flow uses cqGetQuizzes -> finds quiz -> calls startQuiz(builtQuiz)
        // We patch the build helper if found, else patch the conversion point
        // Safe fallback: override startQuiz to auto-convert content→questions when needed
        const _finalStartQuiz = startQuiz;
        startQuiz = function(quizOrId, noTimer) {
            let quiz = quizOrId;
            if (typeof quizOrId === 'string') quiz = QUIZ_REGISTRY[quizOrId] || null;
            if (quiz && quiz.type === 'JetPunk' && quiz.content && !quiz.questions) {
                quiz = cqBuildJetPunkForPlay(quiz);
            } else if (quiz && quiz.type === 'Question Rédaction' && quiz.content && !quiz.questions) {
                quiz = cqBuildRedactionForPlay(quiz);
            }
            _finalStartQuiz(quiz, noTimer);
        };

        function cqBuildRedactionForPlay(quiz) {
            const slides = quiz.content && quiz.content.slides ? quiz.content.slides : [];
            const questions = slides.map(slide => ({
                text: slide.questionText || '',
                time: 20,
                questionImage: slide.questionImage || null,
                questionAudio: slide.questionAudio || null,
                answers: (slide.answers || []).map(a => ({
                    text: a.text,
                    isCorrect: !!a.isCorrect
                }))
            }));
            return Object.assign({}, quiz, { questions });
        }


        // When opening JetPunk quiz in editor, ensure JP panel is init properly
        const _origCqLoadQuizIntoDraft = cqLoadQuizIntoDraft;
        cqLoadQuizIntoDraft = function(quiz) {
            _origCqLoadQuizIntoDraft(quiz);
            // If JetPunk, ensure jpHints survive normalization
            if (quiz && quiz.type === 'JetPunk' && quiz.content && Array.isArray(quiz.content.slides)) {
                const origSlide = quiz.content.slides[0];
                const draftSlide = cqQuizDraft.slides[0];
                if (origSlide && draftSlide && Array.isArray(origSlide.answers)) {
                    draftSlide.answers = origSlide.answers.map(a => ({
                        text: a.text || '',
                        isCorrect: true,
                        jpHints: Array.isArray(a.jpHints) ? JSON.parse(JSON.stringify(a.jpHints)) : []
                    }));
                }
            }
        };

        // Ensure cqSaveDraft saves JP answers correctly
        const _origCqSaveDraft = cqSaveDraft;
        cqSaveDraft = function() {
            const mode = cqGetCurrentEditingMode();
            if (mode === 'JetPunk') {
                // Sync title from input before validation
                const titleInputEl = document.getElementById('cq-jp-title-input');
                if (titleInputEl && cqQuizDraft.slides[0]) {
                    cqQuizDraft.slides[0].questionText = titleInputEl.value;
                }
                // Sync answer texts from inputs before validation
                const answerInputs = document.querySelectorAll('#cq-jp-items-list .cq-jp-item-answer-input');
                const slide = cqQuizDraft.slides[0];
                if (slide && slide.answers) {
                    answerInputs.forEach((inp, i) => {
                        if (slide.answers[i]) slide.answers[i].text = inp.value;
                    });
                }
                if (!cqJpValidate(true)) return;
                const title = cqGetCurrentEditingQuizTitle();
                if (!title) return;
                const quizzes = cqGetQuizzes();
                if (!cqIsModifyingExisting && cqPendingNewQuiz) {
                    const dup = quizzes.some(q => (q.title||'').trim().toLowerCase() === cqPendingNewQuiz.title.toLowerCase());
                    if (dup) return;
                    const today = new Date().toISOString().split('T')[0];
                    quizzes.unshift({
                        title: cqPendingNewQuiz.title,
                        date: today,
                        status: 'offline',
                        type: 'JetPunk',
                        difficulty: cqPendingNewQuiz.difficulty || 0,
                        description: cqPendingNewQuiz.description || '',
                        content: { slides: JSON.parse(JSON.stringify(cqQuizDraft.slides)) }
                    });
                    cqPendingNewQuiz = null;
                } else {
                    const idx = quizzes.findIndex(q => q.title === title);
                    if (idx === -1) return;
                    quizzes[idx].content = { slides: JSON.parse(JSON.stringify(cqQuizDraft.slides)) };
                    quizzes[idx].status = 'offline';
                }
                localStorage.setItem(CQ_ADMIN_QUIZZES_STORAGE_KEY, JSON.stringify(quizzes));
                cqRenderQuizzes();
                cqRenderManageGames();
                const editor = document.getElementById('cq-right-editor');
                if (editor) { editor.classList.add('hidden'); editor.style.display = 'none'; }
                const coming = document.getElementById('cq-right-coming');
                if (coming) { coming.classList.remove('hidden'); coming.style.display = 'flex'; }
                const characteristics = document.getElementById('cq-right-characteristics');
                if (characteristics) { characteristics.classList.add('hidden'); characteristics.style.display = 'none'; }
                cqSetCurrentEditingQuizTitle(null);
            } else {
                _origCqSaveDraft();
            }
        };

        // Hide add-diapo button in JetPunk mode, restore for other modes
        const _origCqSetEditorMode = cqSetEditorMode;
        cqSetEditorMode = function(mode) {
            _origCqSetEditorMode(mode);
            const editMode = cqGetCurrentEditingMode();
            const addDiapoBtn = document.getElementById('cq-add-diapo-btn');
            const deleteDiapoBtn = document.getElementById('cq-delete-current-diapo-btn');
            if (editMode === 'JetPunk') {
                if (addDiapoBtn) addDiapoBtn.style.display = 'none';
                if (deleteDiapoBtn) deleteDiapoBtn.style.display = 'none';
            } else {
                if (addDiapoBtn) addDiapoBtn.style.display = '';
            }
        };


// ═══════════════════════════════════════════════════════════════════
// GEOCOAST'R — Mode carte mondiale (Leaflet + OpenStreetMap)
// ═══════════════════════════════════════════════════════════════════

// ── Constantes ──
const GCR_PRESETS_KEY = 'cq_gcr_presets'; // localStorage key pour centrages enregistrés
const GCR_MAX_DIST_PTS = 5000;            // points max distance par question

// GeoCoast'R est un mode disponible

// ══════════════════════════════════════
// ÉDITEUR
// ══════════════════════════════════════

let _gcrEdMap = null;          // instance Leaflet éditeur
let _gcrEdTargetMarker = null; // marqueur point cible
let _gcrEdCurrentDiapoIdx = 0;
let _gcrEdPresets = [];        // [{name, lat, lng, zoom}]

function _gcrEdLoadPresets() {
    try { _gcrEdPresets = JSON.parse(localStorage.getItem(GCR_PRESETS_KEY) || '[]'); } catch(_) { _gcrEdPresets = []; }
}
function _gcrEdSavePresets() {
    localStorage.setItem(GCR_PRESETS_KEY, JSON.stringify(_gcrEdPresets));
}

function _gcrGetSlides() {
    return cqQuizDraft && cqQuizDraft.slides ? cqQuizDraft.slides : [];
}
function _gcrGetSlide(idx) {
    const slides = _gcrGetSlides();
    return slides[idx] || null;
}
function _gcrCurrentSlide() {
    return _gcrGetSlide(_gcrEdCurrentDiapoIdx);
}

let _gcrEdClickTimeout = null; // pour distinguer simple-clic et double-clic

function cqGcrInitEditor() {
    _gcrEdLoadPresets();
    _gcrEdCurrentDiapoIdx = 0;

    const mapEl = document.getElementById('cq-gcr-editor-map');
    if (!mapEl) return;

    // Si la carte existe déjà, on la réutilise en forçant le recalcul de taille
    if (_gcrEdMap) {
        setTimeout(() => { if (_gcrEdMap) _gcrEdMap.invalidateSize(); }, 0);
        setTimeout(() => { if (_gcrEdMap) _gcrEdMap.invalidateSize(); }, 200);
        cqGcrRenderPresetSelect();
        cqGcrRenderSlidesStrip();
        if (_gcrGetSlides().length === 0) cqGcrAddDiapo();
        else { _gcrEdCurrentDiapoIdx = 0; cqGcrLoadDiapoIntoEditor(0); }
        return;
    }

    _gcrEdMap = L.map('cq-gcr-editor-map', {
        center: [20, 10],
        zoom: 2,
        minZoom: 1,
        maxZoom: 18,
        doubleClickZoom: false
    });
    L.tileLayer('https://basemap.nationalmap.gov/arcgis/rest/services/USGSTopo/MapServer/tile/{z}/{y}/{x}', {
        attribution: '&copy; <a href="https://www.usgs.gov/">USGS</a>',
        maxZoom: 16,
        crossOrigin: true
    }).addTo(_gcrEdMap);
    setTimeout(() => { if (_gcrEdMap) _gcrEdMap.invalidateSize(); }, 100);
    setTimeout(() => { if (_gcrEdMap) _gcrEdMap.invalidateSize(); }, 400);

    // Clic simple = point cible (avec délai pour laisser le dblclick annuler)
    _gcrEdMap.on('click', function(e) {
        if (_gcrEdClickTimeout) { clearTimeout(_gcrEdClickTimeout); _gcrEdClickTimeout = null; }
        _gcrEdClickTimeout = setTimeout(() => {
            _gcrEdClickTimeout = null;
            _gcrEdSetTarget(e.latlng.lat, e.latlng.lng);
        }, 250);
    });
    // Double-clic = marquer centrage actuel (annule le clic simple en cours)
    _gcrEdMap.on('dblclick', function(e) {
        if (_gcrEdClickTimeout) { clearTimeout(_gcrEdClickTimeout); _gcrEdClickTimeout = null; }
        const center = _gcrEdMap.getCenter();
        const zoom = _gcrEdMap.getZoom();
        _gcrEdSetView(center.lat, center.lng, zoom);
    });

    cqGcrRenderPresetSelect();
    cqGcrRenderSlidesStrip();
    if (_gcrGetSlides().length === 0) cqGcrAddDiapo();
    else { _gcrEdCurrentDiapoIdx = 0; cqGcrLoadDiapoIntoEditor(0); }
}

function _gcrEdSetTarget(lat, lng) {
    const slide = _gcrCurrentSlide();
    if (!slide) return;
    slide.gcrTarget = { lat, lng };
    _gcrEdRefreshTargetMarker(lat, lng);
    _gcrEdUpdateInfos();
    cqGcrRenderSlidesStrip();
    cqGcrUpdateCreateBtnState();
}

function _gcrEdSetView(lat, lng, zoom) {
    const slide = _gcrCurrentSlide();
    if (!slide) return;
    slide.gcrView = { lat, lng, zoom };
    _gcrEdUpdateInfos();
    cqGcrRenderSlidesStrip();
    cqGcrUpdateCreateBtnState();
}

function _gcrEdRefreshTargetMarker(lat, lng) {
    if (!_gcrEdMap) return;
    if (_gcrEdTargetMarker) { _gcrEdMap.removeLayer(_gcrEdTargetMarker); _gcrEdTargetMarker = null; }
    if (lat == null) return;
    const icon = L.divIcon({ className: '', html: '<div class="gcr-target-icon"></div>', iconSize: [24,24], iconAnchor: [12,12] });
    _gcrEdTargetMarker = L.marker([lat, lng], { icon, draggable: true }).addTo(_gcrEdMap);
    _gcrEdTargetMarker.on('dragend', function(e) {
        const pos = e.target.getLatLng();
        const slide = _gcrCurrentSlide();
        if (slide) slide.gcrTarget = { lat: pos.lat, lng: pos.lng };
        _gcrEdUpdateInfos();
        cqGcrRenderSlidesStrip();
        cqGcrUpdateCreateBtnState();
    });
}

function _gcrEdUpdateInfos() {
    const slide = _gcrCurrentSlide();
    const tEl = document.getElementById('cq-gcr-target-info');
    const vEl = document.getElementById('cq-gcr-view-info');
    if (tEl) {
        if (slide && slide.gcrTarget) {
            tEl.textContent = `${slide.gcrTarget.lat.toFixed(4)}, ${slide.gcrTarget.lng.toFixed(4)}`;
        } else tEl.textContent = 'Non défini';
    }
    if (vEl) {
        if (slide && slide.gcrView) {
            vEl.textContent = `${slide.gcrView.lat.toFixed(4)}, ${slide.gcrView.lng.toFixed(4)} / zoom ${slide.gcrView.zoom}`;
        } else vEl.textContent = 'Non définie (monde entier)';
    }
}

function cqGcrLoadDiapoIntoEditor(idx) {
    _gcrEdCurrentDiapoIdx = idx;
    const slide = _gcrGetSlide(idx);
    if (!slide) return;

    const qInput = document.getElementById('cq-gcr-question-input');
    if (qInput) qInput.value = slide.questionText || '';

    const timeInput = document.getElementById('cq-gcr-time-input');
    if (timeInput) timeInput.value = slide.gcrTime || 30;

    const maxDistInput = document.getElementById('cq-gcr-maxdist-input');
    if (maxDistInput) maxDistInput.value = slide.gcrMaxDist || 2000;

    _gcrEdUpdateInfos();
    _gcrEdRenderMediaEditor(slide);

    // Repositionner carte
    if (_gcrEdMap) {
        if (slide.gcrView) {
            _gcrEdMap.setView([slide.gcrView.lat, slide.gcrView.lng], slide.gcrView.zoom);
        } else {
            _gcrEdMap.setView([20, 10], 2);
        }
        if (slide.gcrTarget) {
            _gcrEdRefreshTargetMarker(slide.gcrTarget.lat, slide.gcrTarget.lng);
        } else {
            if (_gcrEdTargetMarker) { _gcrEdMap.removeLayer(_gcrEdTargetMarker); _gcrEdTargetMarker = null; }
        }
        setTimeout(() => { if (_gcrEdMap) _gcrEdMap.invalidateSize(); }, 150);
        setTimeout(() => { if (_gcrEdMap) _gcrEdMap.invalidateSize(); }, 400);
    }

    // Delete btn visibility
    const delBtn = document.getElementById('cq-gcr-delete-diapo-btn');
    if (delBtn) delBtn.classList.toggle('hidden', _gcrGetSlides().length <= 1);

    cqGcrRenderSlidesStrip();
    cqGcrUpdateCreateBtnState();
}

function _gcrEdRenderMediaEditor(slide) {
    const container = document.getElementById('cq-gcr-question-media-editor');
    if (!container) return;
    const hasImg = !!slide.questionImage;
    const hasAudio = !!slide.questionAudio;
    container.innerHTML = `<div class="cqed-question-media-row">
        <div class="cqed-question-media-item">
            <span class="cqed-label" style="font-size:0.65rem;">Image question</span>
            ${hasImg ? `<img src="${slide.questionImage}" class="cqed-question-img-preview" alt="">` : ''}
            <div class="cqed-question-media-actions">
                <button type="button" class="cqed-answer-img-upload-btn" onclick="document.getElementById('cq-gcr-img-input').click()">${hasImg ? 'Remplacer' : 'Ajouter une image'}</button>
                ${hasImg ? `<button type="button" class="cqed-answer-img-remove-btn" onclick="cqGcrRemoveQImg()">Supprimer</button>` : ''}
            </div>
            <input type="file" accept="image/*" class="hidden" id="cq-gcr-img-input" onchange="cqGcrHandleQImg(this)">
        </div>
        <div class="cqed-question-media-item">
            <span class="cqed-label" style="font-size:0.65rem;">Audio question</span>
            ${hasAudio ? `<div class="cqed-audio-preview"><audio controls src="${slide.questionAudio}" style="height:28px;width:100%;"></audio></div>` : ''}
            <div class="cqed-question-media-actions">
                <button type="button" class="cqed-answer-img-upload-btn" onclick="document.getElementById('cq-gcr-audio-input').click()">${hasAudio ? 'Remplacer' : 'Ajouter un audio'}</button>
                ${hasAudio ? `<button type="button" class="cqed-answer-img-remove-btn" onclick="cqGcrRemoveQAudio()">Supprimer</button>` : ''}
            </div>
            <input type="file" accept="audio/*" class="hidden" id="cq-gcr-audio-input" onchange="cqGcrHandleQAudio(this)">
        </div>
    </div>`;
}

function cqGcrHandleQImg(input) {
    if (!input.files[0]) return;
    const reader = new FileReader();
    reader.onload = e => {
        const slide = _gcrCurrentSlide();
        if (slide) { slide.questionImage = e.target.result; _gcrEdRenderMediaEditor(slide); }
    };
    reader.readAsDataURL(input.files[0]);
}
function cqGcrRemoveQImg() {
    const slide = _gcrCurrentSlide();
    if (slide) { slide.questionImage = null; _gcrEdRenderMediaEditor(slide); }
}
function cqGcrHandleQAudio(input) {
    if (!input.files[0]) return;
    const reader = new FileReader();
    reader.onload = e => {
        const slide = _gcrCurrentSlide();
        if (slide) { slide.questionAudio = e.target.result; _gcrEdRenderMediaEditor(slide); }
    };
    reader.readAsDataURL(input.files[0]);
}
function cqGcrRemoveQAudio() {
    const slide = _gcrCurrentSlide();
    if (slide) { slide.questionAudio = null; _gcrEdRenderMediaEditor(slide); }
}

function cqGcrUpdateQuestion(val) {
    const slide = _gcrCurrentSlide();
    if (slide) slide.questionText = val;
    cqGcrRenderSlidesStrip();
    cqGcrUpdateCreateBtnState();
}
function cqGcrUpdateTime(val) {
    const slide = _gcrCurrentSlide();
    if (slide) slide.gcrTime = parseInt(val) || 30;
}
function cqGcrUpdateMaxDist(val) {
    const slide = _gcrCurrentSlide();
    if (slide) slide.gcrMaxDist = parseInt(val) || 2000;
}

function cqGcrAddDiapo() {
    const slides = _gcrGetSlides();
    slides.push({ questionText: '', questionImage: null, questionAudio: null, gcrTarget: null, gcrView: null, gcrTime: 30, gcrMaxDist: 2000 });
    cqGcrLoadDiapoIntoEditor(slides.length - 1);
}

let _gcrPendingDelete = false;

function cqGcrAskDeleteDiapo() {
    if (_gcrGetSlides().length <= 1) return;
    _gcrPendingDelete = true;
    const modal = document.getElementById('modal-cq-confirm-delete-diapo');
    if (modal) { playSound('modal-open'); modal.classList.remove('hidden'); }
    const textEl = document.getElementById('cq-confirm-delete-diapo-text');
    if (textEl) textEl.textContent = 'Cette action est irréversible.';
}

function cqGcrRenderSlidesStrip() {
    const strip = document.getElementById('cq-gcr-slides-strip');
    const hint = document.getElementById('cq-gcr-slides-empty-hint');
    const slides = _gcrGetSlides();
    if (!strip) return;
    if (slides.length === 0) {
        strip.innerHTML = '';
        if (hint) hint.classList.remove('hidden');
        return;
    }
    if (hint) hint.classList.add('hidden');
    strip.innerHTML = slides.map((s, i) => {
        const hasTarget = !!(s.gcrTarget);
        const label = (s.questionText || '').trim() || `Diapo ${i+1}`;
        const badgeHtml = hasTarget
            ? `<span class="gcr-diapo-badge ok" style="font-size:0.52rem;padding:1px 5px;border-radius:4px;align-self:flex-end;">✓ cible</span>`
            : `<span class="gcr-diapo-badge missing" style="font-size:0.52rem;padding:1px 5px;border-radius:4px;align-self:flex-end;">! cible</span>`;
        return `<button type="button" class="cq-slide-chip ${i === _gcrEdCurrentDiapoIdx ? 'cq-slide-chip-active' : ''}" onclick="cqGcrLoadDiapoIntoEditor(${i})">
            <span class="cq-slide-chip-label">${escapeHtml(label)}</span>
            <div style="display:flex;justify-content:space-between;align-items:flex-end;width:100%;">
                ${badgeHtml}
                <span class="cq-slide-chip-index">#${i+1}</span>
            </div>
        </button>`;
    }).join('');
}

// ── Centrages enregistrés ──
function cqGcrRenderPresetSelect() {
    _gcrEdLoadPresets();
    const sel = document.getElementById('cq-gcr-preset-select');
    if (!sel) return;
    sel.innerHTML = '<option value="">— Centrage personnalisé —</option>' +
        _gcrEdPresets.map((p, i) => `<option value="${i}">${escapeHtml(p.name)}</option>`).join('');
    sel.value = '';
}

function cqGcrApplyPreset(val) {
    if (val === '') return;
    const p = _gcrEdPresets[parseInt(val)];
    if (!p || !_gcrEdMap) return;
    _gcrEdMap.setView([p.lat, p.lng], p.zoom);
    _gcrEdSetView(p.lat, p.lng, p.zoom);
}

function cqGcrSavePreset() {
    if (!_gcrEdMap) return;
    const name = prompt('Nom du centrage :');
    if (!name || !name.trim()) return;
    const center = _gcrEdMap.getCenter();
    const zoom = _gcrEdMap.getZoom();
    _gcrEdLoadPresets();
    _gcrEdPresets.push({ name: name.trim(), lat: center.lat, lng: center.lng, zoom });
    _gcrEdSavePresets();
    cqGcrRenderPresetSelect();
    _gcrEdSetView(center.lat, center.lng, zoom);
}

function cqGcrDeletePreset() {
    const sel = document.getElementById('cq-gcr-preset-select');
    if (!sel || sel.value === '') { alert('Sélectionnez un centrage à supprimer.'); return; }
    const idx = parseInt(sel.value);
    if (!confirm(`Supprimer le centrage "${_gcrEdPresets[idx].name}" ?`)) return;
    _gcrEdPresets.splice(idx, 1);
    _gcrEdSavePresets();
    cqGcrRenderPresetSelect();
}

// ── Validation & save ──
function cqGcrValidateDraft(showHints) {
    const slides = _gcrGetSlides();
    let allOk = slides.length >= 1;
    for (const s of slides) {
        if (!(s.questionText || '').trim()) allOk = false;
        if (!s.gcrTarget) allOk = false;
    }
    if (showHints) {
        const hint = document.getElementById('cq-validation-hint');
        if (hint) {
            hint.textContent = 'Chaque diapo doit avoir une question et un point cible défini (cliquez sur la carte).';
            hint.classList.toggle('hidden', allOk);
        }
    }
    return allOk;
}

function cqGcrUpdateCreateBtnState() {
    const btn = document.getElementById('cq-create-quiz-btn');
    if (!btn) return;
    const ok = cqGcrValidateDraft(false);
    btn.disabled = !ok;
    btn.classList.toggle('opacity-50', !ok);
    btn.classList.toggle('cursor-not-allowed', !ok);
}

function cqGcrSaveDraft() {
    // Sync champs en cours
    const qInput = document.getElementById('cq-gcr-question-input');
    const slide = _gcrCurrentSlide();
    if (qInput && slide) slide.questionText = qInput.value;

    console.log('💾 cqGcrSaveDraft - Avant validation:', cqQuizDraft.slides.map(s => ({ txt: s.questionText?.slice(0,20), target: s.gcrTarget, view: s.gcrView })));

    if (!cqGcrValidateDraft(true)) return;
    const title = cqGetCurrentEditingQuizTitle();
    if (!title) return;
    const quizzes = cqGetQuizzes();
    if (!cqIsModifyingExisting && cqPendingNewQuiz) {
        const dup = quizzes.some(q => (q.title||'').trim().toLowerCase() === cqPendingNewQuiz.title.toLowerCase());
        if (dup) return;
        const today = new Date().toISOString().split('T')[0];
        const slidesToSave = JSON.parse(JSON.stringify(cqQuizDraft.slides));
        console.log('💾 Slides à sauvegarder:', slidesToSave.map(s => ({ txt: s.questionText?.slice(0,20), target: s.gcrTarget, view: s.gcrView })));
        quizzes.unshift({
            title: cqPendingNewQuiz.title,
            date: today,
            status: 'offline',
            type: "GeoCoast'R",
            difficulty: cqPendingNewQuiz.difficulty || 0,
            description: cqPendingNewQuiz.description || '',
            content: { slides: slidesToSave }
        });
        console.log('✅ Quiz créé et sauvegardé dans localStorage');
        cqPendingNewQuiz = null;
    } else {
        const idx = quizzes.findIndex(q => q.title === title);
        if (idx === -1) return;
        quizzes[idx].content = { slides: JSON.parse(JSON.stringify(cqQuizDraft.slides)) };
        quizzes[idx].status = 'offline';
    }
    localStorage.setItem(CQ_ADMIN_QUIZZES_STORAGE_KEY, JSON.stringify(quizzes));
    cqRenderQuizzes();
    cqRenderManageGames();
    const editor = document.getElementById('cq-right-editor');
    if (editor) { editor.classList.add('hidden'); editor.style.display = 'none'; }
    const coming = document.getElementById('cq-right-coming');
    if (coming) { coming.classList.remove('hidden'); coming.style.display = 'flex'; }
    const characteristics = document.getElementById('cq-right-characteristics');
    if (characteristics) { characteristics.classList.add('hidden'); characteristics.style.display = 'none'; }
    cqSetCurrentEditingQuizTitle(null);
}

// ── Override cqRenderAllEditor pour GeoCoast'R ──
const _origCqRenderAllEditorGcr = cqRenderAllEditor;
cqRenderAllEditor = function() {
    const mode = cqGetCurrentEditingMode();
    const bodyQcm = document.getElementById('cqed-body-qcm');
    const bodyJp = document.getElementById('cqed-body-jetpunk');
    const bodyGcr = document.getElementById('cqed-body-geocoastr');
    const addDiapoBtn = document.getElementById('cq-add-diapo-btn');

    if (mode === "GeoCoast'R") {
        if (bodyQcm) { bodyQcm.classList.add('hidden'); bodyQcm.style.display = 'none'; }
        if (bodyJp) { bodyJp.classList.add('hidden'); bodyJp.style.display = 'none'; }
        if (bodyGcr) { bodyGcr.classList.remove('hidden'); bodyGcr.style.display = 'flex'; }
        if (addDiapoBtn) addDiapoBtn.style.display = 'none';
        // Laisser le navigateur peindre le container AVANT d'initialiser Leaflet
        requestAnimationFrame(() => {
            requestAnimationFrame(() => {
                cqGcrInitEditor();
            });
        });
    } else {
        if (bodyGcr) { bodyGcr.classList.add('hidden'); bodyGcr.style.display = 'none'; }
        _origCqRenderAllEditorGcr();
    }
};

// ── Override cqValidateDraft ──
const _origCqValidateDraftGcr = cqValidateDraft;
cqValidateDraft = function(showHints) {
    if (cqGetCurrentEditingMode() === "GeoCoast'R") return cqGcrValidateDraft(showHints);
    return _origCqValidateDraftGcr(showHints);
};

// ── Override cqSaveDraft ──
const _origCqSaveDraftGcr = cqSaveDraft;
cqSaveDraft = function() {
    if (cqGetCurrentEditingMode() === "GeoCoast'R") { cqGcrSaveDraft(); return; }
    _origCqSaveDraftGcr();
};

// ── Override cqLoadQuizIntoDraft pour GeoCoast'R ──
const _origCqLoadQuizIntoDraftGcr = cqLoadQuizIntoDraft;
cqLoadQuizIntoDraft = function(quiz) {
    console.log('📂 cqLoadQuizIntoDraft appelée, type:', quiz?.type);
    _origCqLoadQuizIntoDraftGcr(quiz);
    if (quiz && quiz.type === "GeoCoast'R" && quiz.content && Array.isArray(quiz.content.slides)) {
        console.log('📂 Avant: cqQuizDraft.slides:', cqQuizDraft.slides.map(s => ({ txt: s.questionText?.slice(0,20), target: s.gcrTarget })));
        cqQuizDraft.slides = JSON.parse(JSON.stringify(quiz.content.slides));
        console.log('📂 Après: cqQuizDraft.slides:', cqQuizDraft.slides.map(s => ({ txt: s.questionText?.slice(0,20), target: s.gcrTarget })));
    }
};

// ══════════════════════════════════════
// JEU
// ══════════════════════════════════════

let _gcrGameMap = null;
let _gcrGamePopupTimer = null;
let _gcrGameNextTimer = null;
// Coordonnées géo des pins (null = non placé)
let _gcrPinGuess = null;   // {lat, lng}
let _gcrPinTarget = null;  // {lat, lng}

/* ── Overlay : synchronise SVG + divs avec la carte ── */
function _gcrOverlayUpdate() {
    if (!_gcrGameMap) return;
    const svg  = document.getElementById('game-gcr-svg');
    const lineEl = document.getElementById('game-gcr-line');
    const pinG = document.getElementById('game-gcr-pin-guess');
    const pinT = document.getElementById('game-gcr-pin-target');
    if (!svg || !lineEl || !pinG || !pinT) {
        console.warn('❌ Éléments overlay manquants:', { svg: !!svg, lineEl: !!lineEl, pinG: !!pinG, pinT: !!pinT });
        return;
    }
    console.log('🗺️ Overlay Update:', { pinGuess: _gcrPinGuess, pinTarget: _gcrPinTarget });

    function latLngToPx(lat, lng) {
        const p = _gcrGameMap.latLngToContainerPoint(L.latLng(lat, lng));
        return { x: p.x, y: p.y };
    }

    if (_gcrPinGuess) {
        const pg = latLngToPx(_gcrPinGuess.lat, _gcrPinGuess.lng);
        pinG.style.left = pg.x + 'px';
        pinG.style.top  = pg.y + 'px';
        pinG.style.display = 'block';
        console.log('📍 Pin Guess visible:', pg);
    } else {
        pinG.style.display = 'none';
    }

    if (_gcrPinTarget) {
        const pt = latLngToPx(_gcrPinTarget.lat, _gcrPinTarget.lng);
        pinT.style.left = pt.x + 'px';
        pinT.style.top  = pt.y + 'px';
        pinT.style.display = 'block';
        console.log('🎯 Pin Target visible:', pt);
    } else {
        pinT.style.display = 'none';
    }

    if (_gcrPinGuess && _gcrPinTarget) {
        const pg = latLngToPx(_gcrPinGuess.lat, _gcrPinGuess.lng);
        const pt = latLngToPx(_gcrPinTarget.lat, _gcrPinTarget.lng);
        lineEl.setAttribute('x1', pg.x); lineEl.setAttribute('y1', pg.y);
        lineEl.setAttribute('x2', pt.x); lineEl.setAttribute('y2', pt.y);
        lineEl.style.visibility = 'visible';
    } else {
        lineEl.style.visibility = 'hidden';
    }
}

function _gcrOverlayClear() {
    _gcrPinGuess = null;
    _gcrPinTarget = null;
    _gcrOverlayUpdate();
}

// Build quiz pour le jeu
function cqBuildGeoCoastrForPlay(quiz) {
    let slides = quiz.content && quiz.content.slides ? quiz.content.slides : [];

    // Migration: ajouter les propriétés manquantes aux vieux quiz
    slides = slides.map(s => ({
        ...s,
        gcrTarget: s.gcrTarget || null,
        gcrView: s.gcrView || null,
        gcrMaxDist: s.gcrMaxDist || 2000,
        gcrTime: s.gcrTime || 30
    }));

    const questions = slides.map(s => ({
        text: s.questionText || '',
        time: s.gcrTime || 30,
        questionImage: s.questionImage || null,
        questionAudio: s.questionAudio || null,
        gcrTarget: s.gcrTarget || null,
        gcrView: s.gcrView || null,
        gcrMaxDist: s.gcrMaxDist || 2000
    }));
    return Object.assign({}, quiz, { questions });
}

// Override startQuiz pour GeoCoast'R
const _finalStartQuizGcr = startQuiz;
startQuiz = function(quizOrId, noTimer) {
    let quiz = quizOrId;
    if (typeof quizOrId === 'string') quiz = QUIZ_REGISTRY[quizOrId] || null;
    if (quiz && quiz.type === "GeoCoast'R" && quiz.content && !quiz.questions) {
        quiz = cqBuildGeoCoastrForPlay(quiz);
    }
    _finalStartQuizGcr(quiz, noTimer);
};

// Override renderQuestion pour GeoCoast'R
const _origRenderQuestionGcr = renderQuestion;
renderQuestion = function() {
    if (cqGetGameMode() === "GeoCoast'R") {
        renderGeoCoastrQuestion();
    } else {
        _origRenderQuestionGcr();
    }
};

function renderGeoCoastrQuestion() {
    const question = currentGame.quiz.questions[currentGame.currentQIndex];
    if (!question) { finishQuiz(); return; }

    _gameStopCurrentAudio();

    document.getElementById('game-question-num').textContent =
        `${currentGame.currentQIndex + 1}/${currentGame.quiz.questions.length}`;
    document.getElementById('game-question-text').textContent = question.text || '';
    _renderQuestionMedia(question);

    // Masquer toutes les autres zones de réponse
    const grid = document.getElementById('game-answers-grid');
    if (grid) { grid.innerHTML = ''; grid.style.display = 'none'; }
    const redArea = document.getElementById('game-redaction-area');
    if (redArea) { redArea.classList.add('hidden'); redArea.style.display = 'none'; }
    const jpArea = document.getElementById('game-jetpunk-area');
    if (jpArea) { jpArea.classList.add('hidden'); jpArea.style.display = 'none'; }

    // Afficher zone carte
    const gcrArea = document.getElementById('game-geocoastr-area');
    if (gcrArea) { gcrArea.classList.remove('hidden'); gcrArea.style.display = 'flex'; }

    // Init/reset carte jeu — délai suffisant pour que le DOM soit peint
    setTimeout(() => _gcrGameInitMap(question), 120);

    startQuestionTimer(question.time || 30);
}

function _gcrGameInitMap(question) {
    const mapEl = document.getElementById('game-gcr-map');
    if (!mapEl) return;

    // Reset overlay et popup
    _gcrGameHidePopup();
    _gcrOverlayClear();

    // Nettoyer ancienne carte
    if (_gcrGameMap) {
        _gcrGameMap.remove();
        _gcrGameMap = null;
    }

    const view = question.gcrView;
    const initCenter = view ? [view.lat, view.lng] : [20, 10];
    const initZoom = view ? view.zoom : 2;

    _gcrGameMap = L.map('game-gcr-map', {
        center: initCenter,
        zoom: initZoom,
        minZoom: 1,
        maxZoom: 18,
        doubleClickZoom: false
    });
    L.tileLayer('https://basemap.nationalmap.gov/arcgis/rest/services/USGSTopo/MapServer/tile/{z}/{y}/{x}', {
        attribution: '&copy; <a href="https://www.usgs.gov/">USGS</a>',
        maxZoom: 16,
        crossOrigin: true
    }).addTo(_gcrGameMap);

    // Resynchroniser l'overlay à chaque mouvement/zoom
    _gcrGameMap.on('move zoom viewreset', _gcrOverlayUpdate);

    _gcrGameMap.on('click', function(e) {
        if (!currentGame.canAnswer) return;
        _gcrGameHandleClick(e.latlng, question);
    });

    _gcrGameMap.invalidateSize();
    setTimeout(() => { if (_gcrGameMap) _gcrGameMap.invalidateSize(); }, 150);
    setTimeout(() => { if (_gcrGameMap) _gcrGameMap.invalidateSize(); }, 400);
    setTimeout(() => { if (_gcrGameMap) _gcrGameMap.invalidateSize(); }, 800);
}

function _gcrGameHandleClick(latlng, question) {
    if (!currentGame.canAnswer) return;
    currentGame.canAnswer = false;
    stopGameTimers();
    if (_gcrGamePopupTimer) { clearTimeout(_gcrGamePopupTimer); _gcrGamePopupTimer = null; }
    if (_gcrGameNextTimer) { clearTimeout(_gcrGameNextTimer); _gcrGameNextTimer = null; }

    const target = question.gcrTarget;
    console.log('GCR Click:', { hasTarget: !!target, question, latlng });
    if (!target) { console.warn('❌ Pas de gcrTarget dans la question'); scheduleNextQuestion(); return; }

    // Placer les pins via l'overlay site
    _gcrPinGuess  = { lat: latlng.lat, lng: latlng.lng };
    _gcrPinTarget = { lat: target.lat, lng: target.lng };

    // Mise à jour immédiate de l'overlay avec les pins
    _gcrOverlayUpdate();

    // Zoom pour voir les deux points, puis mettre à jour l'overlay une fois animé
    const b1 = L.latLng(latlng.lat, latlng.lng);
    const b2 = L.latLng(target.lat, target.lng);
    if (Math.abs(latlng.lat - target.lat) < 0.0001 && Math.abs(latlng.lng - target.lng) < 0.0001) {
        _gcrGameMap.setView(b1, 10);
    } else {
        _gcrGameMap.fitBounds([b1, b2], { padding: [50, 50], maxZoom: 10 });
    }
    // Forcer la mise à jour de l'overlay après la fin de l'animation fitBounds (~400ms)
    setTimeout(_gcrOverlayUpdate, 50);
    setTimeout(_gcrOverlayUpdate, 200);
    setTimeout(_gcrOverlayUpdate, 450);

    // Calcul distance (Haversine)
    const distKm = _gcrHaversine(latlng.lat, latlng.lng, target.lat, target.lng);
    const maxDist = question.gcrMaxDist || 2000;
    const pts = _gcrComputePoints(distKm, maxDist);
    currentGame.score += pts;
    updateScoreDisplay();

    if (pts > 0) playSound('quiz-correct'); else playSound('quiz-wrong');

    // Pop-up résultat après 2s
    _gcrGamePopupTimer = setTimeout(() => {
        _gcrGameShowPopup(distKm, pts);
    }, 2000);

    // Passage question suivante après 3s
    _gcrGameNextTimer = setTimeout(() => {
        _gcrGameHidePopup();
        currentGame.currentQIndex++;
        renderQuestion();
    }, 3000);
}

function _gcrHaversine(lat1, lng1, lat2, lng2) {
    const R = 6371;
    const dLat = (lat2 - lat1) * Math.PI / 180;
    const dLng = (lng2 - lng1) * Math.PI / 180;
    const a = Math.sin(dLat/2)**2 + Math.cos(lat1*Math.PI/180) * Math.cos(lat2*Math.PI/180) * Math.sin(dLng/2)**2;
    return R * 2 * Math.asin(Math.sqrt(a));
}

function _gcrComputePoints(distKm, maxDistKm) {
    if (distKm >= maxDistKm) return 0;
    return Math.round(GCR_MAX_DIST_PTS * (1 - distKm / maxDistKm));
}


function _gcrGameShowPopup(distKm, pts) {
    const popup = document.getElementById('game-gcr-result-popup');
    const distEl = document.getElementById('game-gcr-result-dist');
    const ptsEl  = document.getElementById('game-gcr-result-pts');
    if (!popup) return;
    const distStr = distKm < 1 ? `${Math.round(distKm * 1000)} m` : `${Math.round(distKm)} km`;
    if (distEl) distEl.textContent = `📍 ${distStr}`;
    if (ptsEl)  ptsEl.textContent  = `+${pts} pts distance`;
    popup.style.display = 'block';
}

function _gcrGameHidePopup() {
    const popup = document.getElementById('game-gcr-result-popup');
    if (popup) popup.style.display = 'none';
    if (_gcrGamePopupTimer) { clearTimeout(_gcrGamePopupTimer); _gcrGamePopupTimer = null; }
    if (_gcrGameNextTimer)  { clearTimeout(_gcrGameNextTimer);  _gcrGameNextTimer = null; }
}

// Override handleTimeUp pour GeoCoast'R
const _origHandleTimeUpGcr = handleTimeUp;
handleTimeUp = function() {
    if (cqGetGameMode() === "GeoCoast'R") {
        if (!currentGame.canAnswer) return;
        currentGame.canAnswer = false;
        stopGameTimers();
        _gameStopCurrentAudio();
        playSound('quiz-timeout');
        // Révéler le point cible via l'overlay
        const question = currentGame.quiz.questions[currentGame.currentQIndex];
        if (question && question.gcrTarget && _gcrGameMap) {
            _gcrPinTarget = { lat: question.gcrTarget.lat, lng: question.gcrTarget.lng };
            _gcrGameMap.setView([question.gcrTarget.lat, question.gcrTarget.lng], 5);
            setTimeout(_gcrOverlayUpdate, 50);
            setTimeout(_gcrOverlayUpdate, 300);
        }
        // Afficher popup "temps écoulé" après 2s
        if (_gcrGamePopupTimer) { clearTimeout(_gcrGamePopupTimer); _gcrGamePopupTimer = null; }
        if (_gcrGameNextTimer) { clearTimeout(_gcrGameNextTimer); _gcrGameNextTimer = null; }
        _gcrGamePopupTimer = setTimeout(() => {
            const popup = document.getElementById('game-gcr-result-popup');
            const distEl = document.getElementById('game-gcr-result-dist');
            const ptsEl2 = document.getElementById('game-gcr-result-pts');
            if (popup) {
                if (distEl) distEl.textContent = '⏱ Temps écoulé';
                if (ptsEl2) ptsEl2.textContent = '0 pts distance';
                popup.style.display = 'block';
            }
        }, 2000);
        _gcrGameNextTimer = setTimeout(() => {
            _gcrGameHidePopup();
            currentGame.currentQIndex++;
            renderQuestion();
        }, 3000);
    } else {
        _origHandleTimeUpGcr();
    }
};

// Nettoyage à la fin du quiz
const _origFinishQuizGcr = finishQuiz;
finishQuiz = function() {
    _gcrOverlayClear();
    if (_gcrGameMap) {
        _gcrGameMap.remove();
        _gcrGameMap = null;
    }
    if (_gcrGameNextTimer) { clearTimeout(_gcrGameNextTimer); _gcrGameNextTimer = null; }
    _gcrGameHidePopup();
    const gcrArea = document.getElementById('game-geocoastr-area');
    if (gcrArea) { gcrArea.classList.add('hidden'); gcrArea.style.display = 'none'; }
    _origFinishQuizGcr();
};

// S'assurer que la zone carte est masquée au démarrage d'autres modes
const _origBeginQuizGcr = beginQuiz;
beginQuiz = function() {
    if (cqGetGameMode() !== "GeoCoast'R") {
        const gcrArea = document.getElementById('game-geocoastr-area');
        if (gcrArea) { gcrArea.classList.add('hidden'); gcrArea.style.display = 'none'; }
    }
    _origBeginQuizGcr();
};

// ══════════════════════════════════════════════════════════════════
// QUIZ MAP - NEW MODE
// ══════════════════════════════════════════════════════════════════

function cqQmDefaultSlide() {
    return {
        questionText: '',
        questionImage: null,
        questionAudio: null,
        qmImageData: null,
        qmZones: [{
            points: [
                { x: 0.2, y: 0.2 },
                { x: 0.8, y: 0.2 },
                { x: 0.8, y: 0.8 },
                { x: 0.2, y: 0.8 }
            ]
        }],
        qmTime: 30
    };
}

let _qmCurrentEditingImage = null;
let _qmCurrentEditingZones = [];
let _qmEditingZoneIndex = -1;
let _qmMouseDown = false;
let _qmDraggedZoneIdx = -1;
let _qmDraggedVertexIdx = -1;
let _qmCanvasScale = 1;
let _qmCanvasOffsetX = 0;
let _qmCanvasOffsetY = 0;
let _qmImageWidth = 0;
let _qmImageHeight = 0;

function cqQmUpdateQuestion(text) {
    const slide = cqDraftGetCurrentSlide();
    if (slide) slide.questionText = text;
}

function cqQmUpdateTime(val) {
    const slide = cqDraftGetCurrentSlide();
    if (slide) slide.qmTime = parseInt(val) || 30;
}

function cqQmLoadImage(file) {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
        const img = new Image();
        img.onload = () => {
            const slide = cqDraftGetCurrentSlide();
            if (!slide) return;
            slide.qmImageData = e.target.result;
            _qmCurrentEditingImage = img;
            _qmCurrentEditingZones = (slide.qmZones && JSON.parse(JSON.stringify(slide.qmZones))) || [];

            // Recalculate centered square based on image and display area
            const container = document.getElementById('cq-qm-editor-canvas')?.parentElement;
            if (container && img.width > 0 && img.height > 0) {
                const scale = Math.min(container.offsetWidth / img.width, container.offsetHeight / img.height);
                const squareSize = 0.6; // 60% of display area
                _qmCurrentEditingZones = [{
                    points: [
                        { x: (1 - squareSize) / 2, y: (1 - squareSize) / 2 },
                        { x: (1 + squareSize) / 2, y: (1 - squareSize) / 2 },
                        { x: (1 + squareSize) / 2, y: (1 + squareSize) / 2 },
                        { x: (1 - squareSize) / 2, y: (1 + squareSize) / 2 }
                    ]
                }];
                // Save zones to slide so they persist when changing slides
                slide.qmZones = JSON.parse(JSON.stringify(_qmCurrentEditingZones));
            }

            cqQmRenderEditor();
        };
        img.src = e.target.result;
    };
    reader.readAsDataURL(file);
}

function cqQmRenderEditor() {
    const placeholder = document.getElementById('cq-qm-image-placeholder');
    const preview = document.getElementById('cq-qm-image-preview');
    const canvas = document.getElementById('cq-qm-editor-canvas');
    const hint = document.getElementById('cq-qm-no-image-hint');
    const mediaContainer = document.getElementById('cq-qm-question-media-editor');

    const slide = cqDraftGetCurrentSlide();
    cqQmRenderMediaEditor(slide);

    if (!slide || !slide.qmImageData) {
        if (placeholder) placeholder.style.display = 'flex';
        if (preview) preview.style.display = 'none';
        if (canvas) canvas.style.display = 'none';
        if (hint) hint.style.display = 'flex';
        return;
    }

    if (placeholder) placeholder.style.display = 'none';
    if (preview) {
        preview.src = slide.qmImageData;
        preview.style.display = 'block';
    }
    if (hint) hint.style.display = 'none';

    if (canvas) {
        canvas.style.display = 'block';
        canvas.dataset.qmListenerBound = '';
        setTimeout(() => cqQmDrawCanvas(), 50);
    }
}

function cqQmRenderMediaEditor(slide) {
    const container = document.getElementById('cq-qm-question-media-editor');
    if (!container || !slide) return;

    const hasQImg = !!slide.questionImage;
    const hasQAudio = !!slide.questionAudio;
    container.innerHTML = `
        <div class="cqed-question-media-row">
            <div class="cqed-question-media-item">
                <span class="cqed-label" style="font-size:0.65rem;">Image question</span>
                ${hasQImg ? `<img src="${slide.questionImage}" class="cqed-question-img-preview" alt="Image question">` : ''}
                <div class="cqed-question-media-actions">
                    <button type="button" class="cqed-answer-img-upload-btn" onclick="document.getElementById('cq-qm-question-img-input').click()">${hasQImg ? 'Remplacer' : 'Ajouter une image'}</button>
                    ${hasQImg ? `<button type="button" class="cqed-answer-img-remove-btn" onclick="cqQmRemoveQuestionImage()">Supprimer</button>` : ''}
                </div>
                <input type="file" accept="image/*" class="hidden" id="cq-qm-question-img-input" onchange="cqQmHandleQuestionImageUpload(this)">
            </div>
            <div class="cqed-question-media-item">
                <span class="cqed-label" style="font-size:0.65rem;">Audio question</span>
                ${hasQAudio ? `<div class="cqed-audio-preview"><audio controls src="${slide.questionAudio}" style="height:28px;width:100%;"></audio></div>` : ''}
                <div class="cqed-question-media-actions">
                    <button type="button" class="cqed-answer-img-upload-btn" onclick="document.getElementById('cq-qm-question-audio-input').click()">${hasQAudio ? 'Remplacer' : 'Ajouter un audio'}</button>
                    ${hasQAudio ? `<button type="button" class="cqed-answer-img-remove-btn" onclick="cqQmRemoveQuestionAudio()">Supprimer</button>` : ''}
                </div>
                <input type="file" accept="audio/*" class="hidden" id="cq-qm-question-audio-input" onchange="cqQmHandleQuestionAudioUpload(this)">
            </div>
        </div>
    `;
}

function cqQmHandleQuestionImageUpload(input) {
    if (!input.files.length) return;
    const reader = new FileReader();
    reader.onload = (e) => {
        const slide = cqDraftGetCurrentSlide();
        if (slide) {
            slide.questionImage = e.target.result;
            cqQmRenderMediaEditor(slide);
        }
    };
    reader.readAsDataURL(input.files[0]);
    input.value = '';
}

function cqQmHandleQuestionAudioUpload(input) {
    if (!input.files.length) return;
    const reader = new FileReader();
    reader.onload = (e) => {
        const slide = cqDraftGetCurrentSlide();
        if (slide) {
            slide.questionAudio = e.target.result;
            cqQmRenderMediaEditor(slide);
        }
    };
    reader.readAsDataURL(input.files[0]);
    input.value = '';
}

function cqQmRemoveQuestionImage() {
    const slide = cqDraftGetCurrentSlide();
    if (slide) {
        slide.questionImage = null;
        cqQmRenderMediaEditor(slide);
    }
}

function cqQmRemoveQuestionAudio() {
    const slide = cqDraftGetCurrentSlide();
    if (slide) {
        slide.questionAudio = null;
        cqQmRenderMediaEditor(slide);
    }
}

function cqQmApplyImageToAllSlides() {
    const currentSlide = cqDraftGetCurrentSlide();
    if (!currentSlide || !currentSlide.qmImageData) return;

    const imageToCopy = currentSlide.qmImageData;
    if (!cqQuizDraft.slides) return;

    cqQuizDraft.slides.forEach(slide => {
        slide.qmImageData = imageToCopy;
    });

    playSound('quiz-correct');
}

function cqQmDrawCanvas() {
    const canvas = document.getElementById('cq-qm-editor-canvas');
    if (!canvas || !_qmCurrentEditingImage) return;

    const container = canvas.parentElement;
    canvas.width = container.offsetWidth;
    canvas.height = container.offsetHeight;

    const ctx = canvas.getContext('2d');
    const img = _qmCurrentEditingImage;

    const scale = Math.min(canvas.width / img.width, canvas.height / img.height);
    const offsetX = (canvas.width - img.width * scale) / 2;
    const offsetY = (canvas.height - img.height * scale) / 2;

    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.drawImage(img, offsetX, offsetY, img.width * scale, img.height * scale);

    // Store image dimensions for coordinate conversion
    _qmImageWidth = img.width;
    _qmImageHeight = img.height;

    _qmCurrentEditingZones.forEach((zone) => {
        const pts = zone.points.map(p => ({ x: offsetX + p.x * _qmImageWidth * scale, y: offsetY + p.y * _qmImageHeight * scale }));
        if (pts.length < 2) return;

        ctx.fillStyle = 'rgba(128, 128, 128, 0.15)';
        ctx.strokeStyle = '#999999';
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.moveTo(pts[0].x, pts[0].y);
        for (let i = 1; i < pts.length; i++) ctx.lineTo(pts[i].x, pts[i].y);
        ctx.closePath();
        ctx.fill();
        ctx.stroke();

        pts.forEach((p) => {
            ctx.fillStyle = '#6366f1';
            ctx.beginPath();
            ctx.arc(p.x, p.y, 5, 0, Math.PI * 2);
            ctx.fill();
            ctx.strokeStyle = '#fff';
            ctx.lineWidth = 2;
            ctx.stroke();
        });
    });

    canvas.dataset.qmScale = scale;
    canvas.dataset.qmOffsetX = offsetX;
    canvas.dataset.qmOffsetY = offsetY;

    if (!canvas.dataset.qmListenerBound) {
        canvas.dataset.qmListenerBound = '1';
        canvas.addEventListener('mousedown', cqQmCanvasClickHandler);
        canvas.addEventListener('contextmenu', (e) => e.preventDefault());
    }
}

function cqQmCanvasClickHandler(e) {
    const canvas = e.currentTarget;
    const scale = parseFloat(canvas.dataset.qmScale) || 1;
    const offsetX = parseFloat(canvas.dataset.qmOffsetX) || 0;
    const offsetY = parseFloat(canvas.dataset.qmOffsetY) || 0;

    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;
    const ix = (mx - offsetX) / scale / _qmImageWidth;
    const iy = (my - offsetY) / scale / _qmImageHeight;

    if (e.button === 2) {
        e.preventDefault();
        cqQmHandleRightClick(ix, iy, scale, offsetX, offsetY);
        cqQmDrawCanvas();
    } else if (e.button === 0) {
        cqQmStartDrag(ix, iy, scale, offsetX, offsetY);
    }
}

function cqQmStartDrag(ix, iy, scale, offsetX, offsetY) {
    _qmMouseDown = true;
    _qmDraggedZoneIdx = -1;
    _qmDraggedVertexIdx = -1;

    for (let z = 0; z < _qmCurrentEditingZones.length; z++) {
        const zone = _qmCurrentEditingZones[z];
        for (let v = 0; v < zone.points.length; v++) {
            const p = zone.points[v];
            if (Math.hypot(p.x - ix, p.y - iy) < 0.05) {
                _qmDraggedZoneIdx = z;
                _qmDraggedVertexIdx = v;
                cqQmBindDragEvents(scale, offsetX, offsetY);
                return;
            }
        }
    }
}

function cqQmBindDragEvents(scale, offsetX, offsetY) {
    const canvas = document.getElementById('cq-qm-editor-canvas');
    if (!canvas) return;

    const onMouseMove = (e) => {
        if (!_qmMouseDown || _qmDraggedZoneIdx < 0 || _qmDraggedVertexIdx < 0) return;
        const rect = canvas.getBoundingClientRect();
        const mx = e.clientX - rect.left;
        const my = e.clientY - rect.top;
        const ix = (mx - offsetX) / scale / _qmImageWidth;
        const iy = (my - offsetY) / scale / _qmImageHeight;

        const zone = _qmCurrentEditingZones[_qmDraggedZoneIdx];
        if (zone) {
            zone.points[_qmDraggedVertexIdx] = { x: ix, y: iy };
            cqQmDrawCanvas();
        }
    };

    const onMouseUp = () => {
        _qmMouseDown = false;
        _qmDraggedZoneIdx = -1;
        _qmDraggedVertexIdx = -1;
        document.removeEventListener('mousemove', onMouseMove);
        document.removeEventListener('mouseup', onMouseUp);
    };

    document.addEventListener('mousemove', onMouseMove);
    document.addEventListener('mouseup', onMouseUp);
}

function cqQmHandleRightClick(ix, iy, scale, offsetX, offsetY) {
    const vertexThreshold = 0.05;
    const edgeThreshold = 0.02;

    for (let z = 0; z < _qmCurrentEditingZones.length; z++) {
        const zone = _qmCurrentEditingZones[z];

        for (let v = 0; v < zone.points.length; v++) {
            const p = zone.points[v];
            if (Math.hypot(p.x - ix, p.y - iy) < vertexThreshold) {
                if (zone.points.length > 3) {
                    zone.points.splice(v, 1);
                }
                return;
            }
        }

        for (let v = 0; v < zone.points.length; v++) {
            const p1 = zone.points[v];
            const p2 = zone.points[(v + 1) % zone.points.length];
            const dx = p2.x - p1.x;
            const dy = p2.y - p1.y;
            const len = Math.hypot(dx, dy);
            if (len === 0) continue;

            const t = ((ix - p1.x) * dx + (iy - p1.y) * dy) / (len * len);
            if (t >= 0 && t <= 1) {
                const closestX = p1.x + t * dx;
                const closestY = p1.y + t * dy;
                const dist = Math.hypot(closestX - ix, closestY - iy);

                if (dist < edgeThreshold) {
                    zone.points.splice(v + 1, 0, { x: ix, y: iy });
                    return;
                }
            }
        }
    }
}

function cqQmResetZones() {
    _qmCurrentEditingZones = [{
        points: [
            { x: 0.2, y: 0.2 },
            { x: 0.8, y: 0.2 },
            { x: 0.8, y: 0.8 },
            { x: 0.2, y: 0.8 }
        ]
    }];
    cqQmDrawCanvas();
}

function cqQmAddDiapo() {
    const slide = cqQmDefaultSlide();
    if (!cqQuizDraft.slides) cqQuizDraft.slides = [];

    // If there's an image in the current slide, copy it to the new one and recalculate zones
    const currentSlide = cqQuizDraft.slides[cqQuizDraft.slideIndex];
    if (currentSlide && currentSlide.qmImageData) {
        slide.qmImageData = currentSlide.qmImageData;
        const container = document.getElementById('cq-qm-editor-canvas')?.parentElement;
        if (_qmCurrentEditingImage && container) {
            const squareSize = 0.6;
            slide.qmZones = [{
                points: [
                    { x: (1 - squareSize) / 2, y: (1 - squareSize) / 2 },
                    { x: (1 + squareSize) / 2, y: (1 - squareSize) / 2 },
                    { x: (1 + squareSize) / 2, y: (1 + squareSize) / 2 },
                    { x: (1 - squareSize) / 2, y: (1 + squareSize) / 2 }
                ]
            }];
        }
    }

    cqQuizDraft.slides.push(slide);
    cqQuizDraft.slideIndex = cqQuizDraft.slides.length - 1;
    cqQmRenderAllEditor();
}

function cqQmAskDeleteDiapo() {
    if (cqQuizDraft.slides.length <= 1) return;
    const modal = document.getElementById('modal-cq-confirm-delete-diapo');
    if (modal) {
        playSound('modal-open');
        modal.classList.remove('hidden');
    }
    const textEl = document.getElementById('cq-confirm-delete-diapo-text');
    if (textEl) textEl.textContent = 'Cette action est irréversible.';
    const pendingDeleteIdx = cqQuizDraft.slideIndex;
    const originalConfirmDelete = window.cqConfirmDeleteDiapo;
    window.cqConfirmDeleteDiapo = function() {
        cqQuizDraft.slides.splice(pendingDeleteIdx, 1);
        if (cqQuizDraft.slideIndex >= cqQuizDraft.slides.length) {
            cqQuizDraft.slideIndex = Math.max(0, cqQuizDraft.slides.length - 1);
        }
        cqQmRenderAllEditor();
        const m = document.getElementById('modal-cq-confirm-delete-diapo');
        if (m) m.classList.add('hidden');
        window.cqConfirmDeleteDiapo = originalConfirmDelete;
    };
}

function cqQmValidateDraft() {
    const slides = cqQuizDraft.slides || [];
    for (let slide of slides) {
        if (!slide.questionText.trim()) return false;
        if (!slide.qmImageData) return false;
        if (!slide.qmZones || slide.qmZones.length === 0) return false;
    }
    return true;
}

function cqQmSaveDraft() {
    const currentSlide = cqDraftGetCurrentSlide();
    if (currentSlide && _qmCurrentEditingZones.length > 0) {
        currentSlide.qmZones = JSON.parse(JSON.stringify(_qmCurrentEditingZones));
    }

    if (!cqQmValidateDraft()) return;

    const title = cqGetCurrentEditingQuizTitle();
    if (!title) return;

    const quizzes = cqGetQuizzes();
    const slidesToSave = cqQuizDraft.slides.map(s => ({
        ...s,
        qmZones: s.qmZones && s.qmZones.length > 0 ? s.qmZones : []
    }));

    if (!cqIsModifyingExisting && cqPendingNewQuiz) {
        const dup = quizzes.some(q => (q.title || '').trim().toLowerCase() === cqPendingNewQuiz.title.toLowerCase());
        if (dup) return;
        const today = new Date().toISOString().split('T')[0];
        quizzes.unshift({
            title: cqPendingNewQuiz.title,
            date: today,
            status: 'offline',
            type: 'Quiz Map',
            difficulty: cqPendingNewQuiz.difficulty || 0,
            description: cqPendingNewQuiz.description || '',
            content: { slides: slidesToSave }
        });
        cqPendingNewQuiz = null;
    } else {
        const idx = quizzes.findIndex(q => q.title === title);
        if (idx === -1) return;
        quizzes[idx].content = { slides: slidesToSave };
        quizzes[idx].status = 'offline';
    }

    localStorage.setItem(CQ_ADMIN_QUIZZES_STORAGE_KEY, JSON.stringify(quizzes));
    cqRenderQuizzes();
    cqRenderManageGames();

    const editor = document.getElementById('cq-right-editor');
    if (editor) {
        editor.classList.add('hidden');
        editor.style.display = 'none';
    }
    const coming = document.getElementById('cq-right-coming');
    if (coming) {
        coming.classList.remove('hidden');
        coming.style.display = 'flex';
    }
    cqSetCurrentEditingQuizTitle(null);
}

function cqQmRenderAllEditor() {
    const mode = cqGetCurrentEditingMode();
    const bodyQcm = document.getElementById('cqed-body-qcm');
    const bodyJp = document.getElementById('cqed-body-jetpunk');
    const bodyGcr = document.getElementById('cqed-body-geocoastr');
    const bodyQm = document.getElementById('cqed-body-quizmap');

    if (mode === 'Quiz Map') {
        if (bodyQcm) { bodyQcm.classList.add('hidden'); bodyQcm.style.display = 'none'; }
        if (bodyJp) { bodyJp.classList.add('hidden'); bodyJp.style.display = 'none'; }
        if (bodyGcr) { bodyGcr.classList.add('hidden'); bodyGcr.style.display = 'none'; }
        if (bodyQm) { bodyQm.classList.remove('hidden'); bodyQm.style.display = 'flex'; }
        cqRenderSlidesStripQm();
        cqQmRenderEditor();
    }
}

function cqRenderSlidesStripQm() {
    const strip = document.getElementById('cq-qm-slides-strip');
    const hint = document.getElementById('cq-qm-slides-empty-hint');
    if (!strip) return;

    const slides = cqQuizDraft.slides || [];
    if (!slides.length) {
        if (hint) hint.classList.remove('hidden');
        strip.innerHTML = '';
        return;
    }
    if (hint) hint.classList.add('hidden');

    strip.innerHTML = slides.map((s, idx) => {
        const active = idx === cqQuizDraft.slideIndex;
        const label = (s.questionText || '').trim() ? (s.questionText || '').trim() : `Diapo ${idx + 1}`;
        const safeLabel = escapeHtml(label);
        return `
            <button
                type="button"
                class="cq-slide-chip ${active ? 'cq-slide-chip-active' : ''}"
                data-slide-index="${idx}"
                onclick="cqQmSelectSlide(${idx})"
            >
                <span class="cq-slide-chip-label">${safeLabel}</span>
                <span class="cq-slide-chip-index">#${idx + 1}</span>
            </button>
        `;
    }).join('');
}

function cqQmSelectSlide(idx) {
    if (idx < 0 || idx >= (cqQuizDraft.slides || []).length) return;
    const prevSlide = cqQuizDraft.slides[cqQuizDraft.slideIndex];
    if (prevSlide && _qmCurrentEditingZones.length > 0) {
        prevSlide.qmZones = JSON.parse(JSON.stringify(_qmCurrentEditingZones));
    }

    const slide = cqQuizDraft.slides[idx];
    _qmCurrentEditingImage = null;
    _qmCurrentEditingZones = [];

    if (slide.qmImageData) {
        const img = new Image();
        img.onload = () => {
            _qmCurrentEditingImage = img;
            _qmCurrentEditingZones = (slide.qmZones && JSON.parse(JSON.stringify(slide.qmZones))) || [];
            cqQmRenderEditor();
        };
        img.src = slide.qmImageData;
    }

    cqQuizDraft.slideIndex = idx;
    document.getElementById('cq-qm-question-input').value = slide.questionText || '';
    document.getElementById('cq-qm-time-input').value = slide.qmTime || 30;

    cqRenderSlidesStripQm();
    cqQmRenderEditor();

    const deleteBtn = document.getElementById('cq-qm-delete-diapo-btn');
    if (deleteBtn) {
        deleteBtn.classList.toggle('hidden', cqQuizDraft.slides.length <= 1);
    }
}

// Override pour Quiz Map
const _origCqRenderAllEditorQm = cqRenderAllEditor;
cqRenderAllEditor = function() {
    const mode = cqGetCurrentEditingMode();
    const bodyQm = document.getElementById('cqed-body-quizmap');
    if (mode === 'Quiz Map') {
        cqQmRenderAllEditor();
    } else {
        if (bodyQm) { bodyQm.classList.add('hidden'); bodyQm.style.display = 'none'; }
        _origCqRenderAllEditorQm();
    }
};

const _origCqValidateDraftQm = cqValidateDraft;
cqValidateDraft = function(showHints) {
    if (cqGetCurrentEditingMode() === 'Quiz Map') return cqQmValidateDraft();
    return _origCqValidateDraftQm(showHints);
};

const _origCqSaveDraftQm = cqSaveDraft;
cqSaveDraft = function() {
    if (cqGetCurrentEditingMode() === 'Quiz Map') { cqQmSaveDraft(); return; }
    _origCqSaveDraftQm();
};

const _origCqLoadQuizIntoDraftQm = cqLoadQuizIntoDraft;
cqLoadQuizIntoDraft = function(quiz) {
    _origCqLoadQuizIntoDraftQm(quiz);
    if (quiz && quiz.type === 'Quiz Map' && quiz.content && Array.isArray(quiz.content.slides)) {
        cqQuizDraft.slides = JSON.parse(JSON.stringify(quiz.content.slides));
    }
};

function cqBuildQuizMapForPlay(quiz) {
    let slides = quiz.content && quiz.content.slides ? quiz.content.slides : [];
    const questions = slides.map(s => ({
        text: s.questionText || '',
        time: s.qmTime || 30,
        questionImage: s.questionImage || null,
        questionAudio: s.questionAudio || null,
        qmImageData: s.qmImageData || null,
        qmZones: s.qmZones || []
    }));
    return Object.assign({}, quiz, { questions });
}

const _origStartQuizQm = startQuiz;
startQuiz = function(quizOrId, noTimer) {
    let quiz = quizOrId;
    if (typeof quizOrId === 'string') quiz = QUIZ_REGISTRY[quizOrId] || null;
    if (quiz && quiz.type === 'Quiz Map' && quiz.content && !quiz.questions) {
        quiz = cqBuildQuizMapForPlay(quiz);
    }
    _origStartQuizQm(quiz, noTimer);
};

const _origRenderQuestionQm = renderQuestion;
renderQuestion = function() {
    if (cqGetGameMode() === 'Quiz Map') {
        renderQuizMapQuestion();
    } else {
        _origRenderQuestionQm();
    }
};

let _qmGameAttempts = 0;
let _qmGameClickDisabled = false;
let _qmGameCorrectZone = -1;

function renderQuizMapQuestion() {
    const question = currentGame.quiz.questions[currentGame.currentQIndex];
    if (!question) { finishQuiz(); return; }

    _gameStopCurrentAudio();

    document.getElementById('game-question-num').textContent =
        `${currentGame.currentQIndex + 1}/${currentGame.quiz.questions.length}`;
    document.getElementById('game-question-text').textContent = question.text || '';
    _renderQuestionMedia(question);

    const grid = document.getElementById('game-answers-grid');
    if (grid) { grid.innerHTML = ''; grid.style.display = 'none'; }
    const redArea = document.getElementById('game-redaction-area');
    if (redArea) { redArea.classList.add('hidden'); redArea.style.display = 'none'; }
    const jpArea = document.getElementById('game-jetpunk-area');
    if (jpArea) { jpArea.classList.add('hidden'); jpArea.style.display = 'none'; }

    const qmArea = document.getElementById('game-quizmap-area');
    if (qmArea) { qmArea.classList.remove('hidden'); qmArea.style.display = 'flex'; }

    _qmGameAttempts = 0;
    _qmGameClickDisabled = false;
    _qmGameCorrectZone = -1;

    setTimeout(() => cqQmGameRender(question), 120);
    startQuestionTimer(question.time || 30);
}

function cqQmGameRender(question) {
    const canvas = document.getElementById('game-qm-canvas');
    if (!canvas || !question.qmImageData) return;

    const wrapper = canvas.parentElement;
    canvas.width = wrapper.offsetWidth;
    canvas.height = wrapper.offsetHeight;

    const img = new Image();
    img.onload = () => {
        const ctx = canvas.getContext('2d');
        const scale = Math.min(canvas.width / img.width, canvas.height / img.height);
        const offsetX = (canvas.width - img.width * scale) / 2;
        const offsetY = (canvas.height - img.height * scale) / 2;

        cqQmDrawDesaturated(ctx, img, offsetX, offsetY, scale);
        cqQmDrawZones(ctx, question.qmZones, offsetX, offsetY, scale, true);

        canvas.addEventListener('mousemove', (e) => cqQmGameMouseMove(e, canvas, img, offsetX, offsetY, scale, question));
        canvas.addEventListener('click', (e) => cqQmGameClick(e, canvas, question, offsetX, offsetY, scale));
    };
    img.src = question.qmImageData;
}

function cqQmDrawDesaturated(ctx, img, x, y, scale) {
    ctx.drawImage(img, x, y, img.width * scale, img.height * scale);
    const imgData = ctx.getImageData(0, 0, ctx.canvas.width, ctx.canvas.height);
    const data = imgData.data;
    for (let i = 0; i < data.length; i += 4) {
        const r = data[i], g = data[i + 1], b = data[i + 2];
        const gray = r * 0.299 + g * 0.587 + b * 0.114;
        data[i] = gray * 0.7;
        data[i + 1] = gray * 0.7;
        data[i + 2] = gray * 0.7;
    }
    ctx.putImageData(imgData, 0, 0);
}

function cqQmDrawZones(ctx, zones, offsetX, offsetY, scale, forGame = false) {
    if (!zones) return;
    zones.forEach((zone, zoneIdx) => {
        if (!zone.points || zone.points.length < 3) return;

        const pts = zone.points.map(p => ({ x: offsetX + p.x * _qmImageWidth * scale, y: offsetY + p.y * _qmImageHeight * scale }));
        ctx.fillStyle = forGame ? 'rgba(150, 150, 150, 0.15)' : 'rgba(150, 150, 255, 0.2)';
        ctx.strokeStyle = forGame ? 'rgba(100, 100, 100, 0.3)' : '#6366f1';
        ctx.lineWidth = forGame ? 1 : 2;
        ctx.beginPath();
        ctx.moveTo(pts[0].x, pts[0].y);
        for (let i = 1; i < pts.length; i++) ctx.lineTo(pts[i].x, pts[i].y);
        ctx.closePath();
        ctx.fill();
        ctx.stroke();
    });
}

function cqQmGameMouseMove(e, canvas, img, offsetX, offsetY, scale, question) {
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;
    const ix = (mx - offsetX) / scale / img.width;
    const iy = (my - offsetY) / scale / img.height;

    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    cqQmDrawDesaturated(ctx, img, offsetX, offsetY, scale);

    let hoveredZone = -1;
    (question.qmZones || []).forEach((zone, zoneIdx) => {
        if (cqQmPointInZone(ix, iy, zone)) {
            hoveredZone = zoneIdx;
        }
    });

    (question.qmZones || []).forEach((zone, zoneIdx) => {
        if (!zone.points || zone.points.length < 3) return;
        const pts = zone.points.map(p => ({ x: offsetX + p.x * _qmImageWidth * scale, y: offsetY + p.y * _qmImageHeight * scale }));

        if (zoneIdx === hoveredZone) {
            ctx.fillStyle = 'rgba(100, 100, 255, 0.4)';
            ctx.strokeStyle = '#4f46e5';
            ctx.lineWidth = 2;
        } else {
            ctx.fillStyle = 'rgba(100, 100, 100, 0.15)';
            ctx.strokeStyle = 'rgba(100, 100, 100, 0.3)';
            ctx.lineWidth = 1;
        }

        ctx.beginPath();
        ctx.moveTo(pts[0].x, pts[0].y);
        for (let i = 1; i < pts.length; i++) ctx.lineTo(pts[i].x, pts[i].y);
        ctx.closePath();
        ctx.fill();
        ctx.stroke();
    });

    canvas.style.cursor = hoveredZone >= 0 ? 'pointer' : 'default';
}

function cqQmGameClick(e, canvas, question, offsetX, offsetY, scale) {
    if (!currentGame.canAnswer || _qmGameClickDisabled) return;

    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;
    const ix = (mx - offsetX) / scale / _qmImageWidth;
    const iy = (my - offsetY) / scale / _qmImageHeight;

    const clickedZone = (question.qmZones || []).findIndex(z => cqQmPointInZone(ix, iy, z));

    if (clickedZone < 0) return;

    _qmGameAttempts++;
    _qmGameClickDisabled = true;

    if (_qmGameCorrectZone < 0) {
        _qmGameCorrectZone = 0;
    }

    if (clickedZone === _qmGameCorrectZone) {
        currentGame.canAnswer = false;
        stopGameTimers();
        currentGame.score += cqNoTimerMode ? BASE_POINTS : computeQuestionPoints();
        updateScoreDisplay();
        playSound('quiz-correct');

        cqQmFlashZone(canvas, question, offsetX, offsetY, scale, clickedZone, 'green', 2000);
    } else {
        playSound('quiz-wrong');
        cqQmFlashZone(canvas, question, offsetX, offsetY, scale, clickedZone, 'red', 500);

        if (_qmGameAttempts >= 3) {
            currentGame.canAnswer = false;
            stopGameTimers();
            cqQmFlashZone(canvas, question, offsetX, offsetY, scale, _qmGameCorrectZone, 'green', 2000);
        } else {
            setTimeout(() => {
                _qmGameClickDisabled = false;
                cqQmGameRender(question);
            }, 500);
        }
    }
}

function cqQmPointInZone(x, y, zone) {
    if (!zone.points || zone.points.length < 3) return false;
    let inside = false;
    for (let i = 0, j = zone.points.length - 1; i < zone.points.length; j = i++) {
        const pi = zone.points[i], pj = zone.points[j];
        if ((pi.y > y) !== (pj.y > y) && x < (pj.x - pi.x) * (y - pi.y) / (pj.y - pi.y) + pi.x) {
            inside = !inside;
        }
    }
    return inside;
}

function cqQmFlashZone(canvas, question, offsetX, offsetY, scale, zoneIdx, color, duration) {
    if (!canvas || !question.qmZones || !question.qmZones[zoneIdx]) {
        scheduleNextQuestion(duration);
        return;
    }

    const ctx = canvas.getContext('2d');
    const img = new Image();
    img.onload = () => {
        const startTime = Date.now();
        const interval = setInterval(() => {
            const elapsed = Date.now() - startTime;
            const progress = Math.min(elapsed / duration, 1);

            ctx.clearRect(0, 0, canvas.width, canvas.height);
            cqQmDrawDesaturated(ctx, img, offsetX, offsetY, scale);

            const zone = question.qmZones[zoneIdx];
            if (zone.points && zone.points.length >= 3) {
                const pts = zone.points.map(p => ({ x: offsetX + p.x * _qmImageWidth * scale, y: offsetY + p.y * _qmImageHeight * scale }));
                const colorMap = color === 'green' ? 'rgba(34, 197, 94, 0.6)' : 'rgba(239, 68, 68, 0.6)';
                ctx.fillStyle = colorMap;
                ctx.strokeStyle = color === 'green' ? '#22c55e' : '#ef4444';
                ctx.lineWidth = 2;
                ctx.beginPath();
                ctx.moveTo(pts[0].x, pts[0].y);
                for (let i = 1; i < pts.length; i++) ctx.lineTo(pts[i].x, pts[i].y);
                ctx.closePath();
                ctx.fill();
                ctx.stroke();
            }

            if (progress >= 1) {
                clearInterval(interval);
                scheduleNextQuestion(0);
            }
        }, 16);
    };
    img.src = question.qmImageData;
}

// Override handleTimeUp pour Quiz Map
const _origHandleTimeUpQm = handleTimeUp;
handleTimeUp = function() {
    if (cqGetGameMode() === 'Quiz Map') {
        currentGame.canAnswer = false;
        scheduleNextQuestion();
    } else {
        _origHandleTimeUpQm();
    }
};

// Override beginQuiz pour Quiz Map
const _origBeginQuizQm = beginQuiz;
beginQuiz = function() {
    if (cqGetGameMode() !== 'Quiz Map') {
        const qmArea = document.getElementById('game-quizmap-area');
        if (qmArea) { qmArea.classList.add('hidden'); qmArea.style.display = 'none'; }
    }
    _origBeginQuizQm();
};




