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

        const MAX_POINTS_PER_QUESTION = 1000;
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

                const user = {
                    id: crypto.randomUUID(),
                    pseudo: trimmed,
                    pseudoNormalized: this._normalizePseudo(trimmed),
                    passwordHash: await this.hashPassword(password),
                    createdAt: new Date().toISOString(),
                    lastLogin: new Date().toISOString(),
                    bugReports: 0,
                    favorites: []
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
            const userViews = ['view-user-home', 'view-user-profile', 'view-my-scores'];
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

                // Si on affiche l'accueil connecté, charger pseudo + à la une + favoris
                if (viewId === 'view-user-home') {
                    cqInitUserHome();
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

            cqNoTimerMode = !!noTimer;
            stopGameTimers();
            currentGame = {
                quiz,
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
                    <span class="cq-dash-row-main">${escapeHtml(u.pseudo || '-')}</span>
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
            cqCategoryPendingDeleteId = null;
            cqRenderCategoriesModal();
            const modal = document.getElementById('modal-cq-categories');
            if (modal) modal.classList.remove('hidden');
            const mainContent = document.getElementById('main-content');
            if (mainContent) mainContent.classList.add('blur-bg');
        }

        function cqCloseCategoriesModal() {
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
        function cqBuildPlayableQuizFromAdminQuiz(q) {
            const slides = q?.content?.slides;
            const questions = cqAdminSlidesToQuestions(slides);
            if (!questions.length) return null;

            return {
                id: q.title,
                title: q.title || 'Quiz',
                difficulty: q.difficulty || 0,
                description: q.description || '',
                questions
            };
        }

        function cqAdminSlidesToQuestions(slides) {
            if (!Array.isArray(slides)) return [];
            return slides.map(s => {
                const questionText = typeof s?.questionText === 'string' ? s.questionText : '';
                const answersRaw = Array.isArray(s?.answers) ? s.answers : [];

                const answers = answersRaw.map(a => ({
                    text: typeof a?.text === 'string' ? a.text : '',
                    isCorrect: !!a?.isCorrect
                }));

                return {
                    text: questionText,
                    time: 20,
                    answers
                };
            });
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

        function cqInitUserHome() {
            const user = AuthService.getCurrentUser();
            const pseudoEl = document.getElementById('user-home-pseudo');
            if (pseudoEl) pseudoEl.textContent = user?.pseudo || '-';

            cqRenderFeaturedBannerInto('user-featured-quizzes-grid');
            cqRenderUserFavorites();
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
            if (modal) modal.classList.remove('hidden');
            const mainContent = document.getElementById('main-content');
            if (mainContent) mainContent.classList.add('blur-bg');
        }

        function cqCloseFavoritesModal() {
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
            renderQuestion();
        }

        function beginQuizNoTimer() {
            cqNoTimerMode = true;
            document.getElementById('game-prestart').classList.add('hidden');
            const playArea = document.getElementById('game-play-area');
            playArea.classList.remove('hidden');
            playArea.style.display = 'flex';
            // Masquer le score en mode sans chrono
            const scoreEl = document.getElementById('game-score');
            if (scoreEl) scoreEl.style.display = 'none';
            // Masquer le timer
            const timerTrack = document.querySelector('.game-timer-track');
            if (timerTrack) timerTrack.style.display = 'none';
            renderQuestion();
        }

        function updateScoreDisplay() {
            document.getElementById('game-score').textContent = currentGame.score;
        }

        function getCorrectIndex(question) {
            return question.answers.findIndex(a => a.isCorrect);
        }

        function computeQuestionPoints() {
            if (currentGame.totalTime <= 0) return 0;
            return Math.round(MAX_POINTS_PER_QUESTION * (currentGame.timeLeft / currentGame.totalTime));
        }

        function isMultipleAnswerQuestion(question) {
            if (!question || !Array.isArray(question.answers)) return false;
            return question.answers.filter(a => a.isCorrect).length > 1;
        }

        function renderQuestion() {
            const question = currentGame.quiz.questions[currentGame.currentQIndex];
            if (!question) {
                finishQuiz();
                return;
            }

            document.getElementById('game-question-num').textContent =
                `${currentGame.currentQIndex + 1}/${currentGame.quiz.questions.length}`;
            document.getElementById('game-question-text').textContent = question.text;

            const isMulti = isMultipleAnswerQuestion(question);
            const grid = document.getElementById('game-answers-grid');

            if (isMulti) {
                // Mode multi-réponses : cases à cocher, pas de validation auto
                grid.innerHTML = question.answers.map((answer, index) => `
                    <button type="button" class="answer-card answer-multi" data-index="${index}" data-selected="0"
                        onclick="handleMultiAnswerToggle(${index})">
                        ${escapeHtml(answer.text)}
                    </button>
                `).join('') + `
                    <div class="col-span-full flex justify-center mt-2">
                        <button type="button" id="multi-validate-btn" onclick="handleMultiValidate()"
                            class="bg-[#660000] text-white px-8 py-3 rounded-xl font-bold font-button text-sm hover:bg-[#800000] transition">
                            Valider
                        </button>
                    </div>
                `;
            } else {
                grid.innerHTML = question.answers.map((answer, index) => `
                    <button type="button" class="answer-card" data-index="${index}" onclick="handleAnswer(${index})">
                        ${escapeHtml(answer.text)}
                    </button>
                `).join('');
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

            if (isAllCorrect && !cqNoTimerMode) {
                currentGame.score += computeQuestionPoints();
                updateScoreDisplay();
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
                return; // Pas de timer, pas de score
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
            stopGameTimers();

            const question = currentGame.quiz.questions[currentGame.currentQIndex];
            const correctIndex = getCorrectIndex(question);
            const isCorrect = index === correctIndex;

            if (isCorrect && !cqNoTimerMode) {
                currentGame.score += computeQuestionPoints();
                updateScoreDisplay();
            }

            setAnswersDisabled();
            revealAnswers(index);
            scheduleNextQuestion();
        }

        function handleTimeUp() {
            if (!currentGame.canAnswer) return;

            currentGame.canAnswer = false;
            setAnswersDisabled();
            revealAnswers(-1);
            scheduleNextQuestion();
        }

        function finishQuiz() {
            stopGameTimers();
            // Restaurer le timer et le score si masqués
            const scoreEl = document.getElementById('game-score');
            if (scoreEl) scoreEl.style.display = '';
            const timerTrack = document.querySelector('.game-timer-track');
            if (timerTrack) timerTrack.style.display = '';

            if (cqNoTimerMode) {
                document.getElementById('results-final-score').textContent = '—';
            } else {
                document.getElementById('results-final-score').textContent = currentGame.score;
            }
            if (!cqAdminTestMode && !cqNoTimerMode && currentGame.quiz && currentGame.quiz.title) {
                cqRecordGamePlay(currentGame.quiz.title);
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
                    const resultsCard = document.getElementById('results-game-card-wrap');
                    if (resultsCard) {
                        const req = resultsCard.requestFullscreen ? resultsCard.requestFullscreen() : resultsCard.webkitRequestFullscreen ? resultsCard.webkitRequestFullscreen() : null;
                    }
                }).catch(() => showView('view-results'));
            } else {
                showView('view-results');
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
            if (modal) modal.classList.remove('hidden');
            const mainContent = document.getElementById('main-content');
            if (mainContent) mainContent.classList.add('blur-bg');
        }

        function cqCloseFavoritesGamePageModal() {
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
            document.getElementById('modal-settings-admin').classList.remove('hidden');
            document.getElementById('main-content').classList.add('blur-bg');
        }

        function closeAdminSettings() {
            document.getElementById('modal-settings-admin').classList.add('hidden');
            document.getElementById('main-content').classList.remove('blur-bg');
        }

        function synchronizeVolumeSliders() {
            const sliders = Array.from(document.querySelectorAll('.volume-slider'));
            if (!sliders.length) return;

            const syncValue = (source) => {
                sliders.forEach((slider) => {
                    if (slider !== source) {
                        slider.value = source.value;
                    }
                });
            };

            sliders.forEach((slider) => {
                slider.addEventListener('input', () => syncValue(slider));
            });
        }

        document.addEventListener('DOMContentLoaded', synchronizeVolumeSliders);

        function openLandingSettings() {
            document.getElementById('modal-settings-guest').classList.add('hidden');
            document.getElementById('modal-settings-user').classList.add('hidden');
            document.getElementById('modal-settings-landing').classList.remove('hidden');
            document.getElementById('main-content').classList.add('blur-bg');
        }

        function closeSettings() {
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

            // Charger l'avatar
            const avatarEl = document.getElementById('profile-avatar');
            avatarEl.style.backgroundColor = generateAvatarColor(user.pseudo);
            avatarEl.textContent = user.pseudo.charAt(0).toUpperCase();
            avatarEl.style.display = 'flex';
            avatarEl.style.alignItems = 'center';
            avatarEl.style.justifyContent = 'center';
            avatarEl.style.fontSize = '1.5rem';
            avatarEl.style.fontWeight = '800';
            avatarEl.style.color = '#fff';
            avatarEl.style.fontFamily = 'Tektur, sans-serif';
        }

        function generateAvatarColor(pseudo) {
            let hash = 0;
            for (let i = 0; i < pseudo.length; i++) {
                hash = pseudo.charCodeAt(i) + ((hash << 5) - hash);
            }
            const colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#FFA07A', '#98D8C8', '#F7DC6F', '#BB8FCE', '#85C1E2'];
            return colors[Math.abs(hash) % colors.length];
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
            document.getElementById('modal-change-password').classList.add('hidden');
        }

        function closeChangePasswordConfirm() {
            document.getElementById('modal-change-password-confirm').classList.add('hidden');
        }

        let cqPendingPseudoChange = null;

        function openChangePseudo() {
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
            if (modal) modal.classList.remove('hidden');
        }

        function closeChangePseudoConfirm() {
            const modal = document.getElementById('modal-change-pseudo-confirm');
            if (modal) modal.classList.add('hidden');
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
            document.getElementById('admin-password-input').value = '';
            document.getElementById('admin-password-error').textContent = '';
            document.getElementById('modal-admin-access').classList.remove('hidden');
        }

        function closeAdminAccess() {
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
                const ta = document.getElementById('ban-contest-message');
                if (ta) ta.value = '';
                modal.classList.remove('hidden');
            }
        }

        function closeBanContest() {
            const modal = document.getElementById('modal-ban-contest');
            if (modal) modal.classList.add('hidden');
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

                const favs = Array.isArray(u.favorites) ? u.favorites : [];
                const favsHtml = favs.length ? favs.map(f => `<span class="mod-fav-chip">${escapeHtml(f)}</span>`).join('') : '<span class="opacity-50 text-xs">Aucun favori</span>';

                const bugReports = u.bugReports || 0;
                const createdAt = u.createdAt ? new Date(u.createdAt).toLocaleDateString('fr-FR') : '-';
                const lastLogin = u.lastLogin ? new Date(u.lastLogin).toLocaleString('fr-FR') : '-';

                return `
                <div class="mod-user-card">
                    <div class="mod-user-main">
                        <div class="mod-avatar" style="background:${avatarColor}">${escapeHtml(avatarLetter)}</div>
                        <div class="mod-user-info">
                            <div class="mod-user-pseudo">${escapeHtml(u.pseudo || '-')} ${banLabel}</div>
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
            document.getElementById('modal-ban-confirm').classList.remove('hidden');
        }

        function closeBanConfirm() {
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

            cqRenderModeration(document.getElementById('mod-search-input')?.value || '');
        }

        /* --- Suppression d'un compte --- */
        let _deleteUserData = null;

        function openDeleteUserModal(userId, pseudo, isBanned) {
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
            document.getElementById('modal-delete-user-active').classList.add('hidden');
            _deleteUserData = null;
        }

        function closeDeleteUserConfirm() {
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

            cqRenderModeration(document.getElementById('mod-search-input')?.value || '');
        }

        // CLÉ V2 : Éradique tous les anciens faux quiz bloqués dans la mémoire du navigateur
        // IMPORTANT: doit être défini AVANT cqGetQuizzes() et tout appel à cqGetQuizzes().
        const CQ_ADMIN_QUIZZES_STORAGE_KEY = 'cq_admin_quizzes_V2';

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
        function cqGetQuizzes() {
            let stored = localStorage.getItem(CQ_ADMIN_QUIZZES_STORAGE_KEY);
            if (!stored) {
                const defaults = []; // Plus aucun faux quiz ici !
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
            if (modal) modal.classList.remove('hidden');
            const mainContent = document.getElementById('main-content');
            if (mainContent) mainContent.classList.add('blur-bg');
        }

        function closeChangeStatusConfirm() {
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
                if (modal) modal.classList.remove('hidden');
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
                quizzes[idx].status = 'offline';
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

        function cqSelectMode(mode) {
            cqSelectedModeVal = mode;
            const label = document.getElementById('cq-mode-dropdown-label');
            if (label) {
                label.textContent = mode;
            }
            const menu = document.getElementById('cq-mode-dropdown-menu');
            const chevron = document.getElementById('cq-mode-dropdown-chevron');
            if (menu) {
                menu.style.display = 'none';
            }
            if (chevron) {
                chevron.classList.remove('rotate-180');
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
            
            const isValid = titleVal.length > 0 && !isDuplicate && modeSelected;
            
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
                if (modal) modal.classList.remove('hidden');
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
                modal.classList.remove('hidden');
            }
            const mainContent = document.getElementById('main-content');
            if (mainContent) {
                mainContent.classList.add('blur-bg');
            }
        }

        function closeDeleteGameConfirm() {
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
                if (modal) modal.classList.remove('hidden');
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
                answers: [
                    { text: '', isCorrect: false },
                    { text: '', isCorrect: false }
                ]
            };
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
                if (!answers || answers.length < 2) {
                    answers = [
                        { text: '', isCorrect: false },
                        { text: '', isCorrect: false }
                    ];
                }
                // clamp answers to 6, minimum 2
                answers = answers.slice(0, 6);
                while (answers.length < 2) answers.push({ text: '', isCorrect: false });

                // normalize each answer
                const normalizedAnswers = answers.map(a => ({
                    text: typeof a?.text === 'string' ? a.text : '',
                    isCorrect: !!a?.isCorrect
                }));

                return { questionText: qText, answers: normalizedAnswers };
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

            list.innerHTML = slide.answers.map((a, idx) => {
                const isCorrect = !!a.isCorrect;
                const safeText = escapeHtml(a.text);
                const placeholder = `Réponse ${idx + 1}`;
                const locked = document.getElementById('cq-add-answer-btn')?.disabled;

                return `
                    <div class="cqed-answer-card ${isCorrect ? 'is-correct' : ''}" data-answer-index="${idx}">
                        <button type="button"
                            class="cqed-answer-toggle ${isCorrect ? 'is-correct' : ''}"
                            onclick="cqToggleCorrectAnswer(${idx})"
                            title="Marquer comme bonne réponse"
                            ${locked ? 'disabled' : ''}>
                            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="3" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12.75l6 6 9-13.5" /></svg>
                        </button>
                        <input
                            type="text"
                            class="cqed-answer-input"
                            value="${safeText}"
                            placeholder="${placeholder}"
                            oninput="cqUpdateAnswerText(${idx}, this.value)"
                            ${locked ? 'disabled' : ''}
                        />
                        ${idx >= 2 ? `
                        <button type="button"
                            class="cqed-answer-delete"
                            onclick="cqAskDeleteAnswer(${idx})"
                            title="Supprimer cette réponse"
                            ${locked ? 'disabled' : ''}>
                            ✕
                        </button>` : ''}
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

                if (!qText) allOk = false;

                if (answers.length < 2 || answers.length > 6) allOk = false;

                let correctCount = 0;
                for (let a of answers) {
                    if ((a?.text || '').trim() === '') allOk = false;
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

                hint.textContent = 'Vérifiez : chaque diapo doit avoir un texte de question, entre 2 et 6 réponses remplies, et au moins 1 réponse correcte.';
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
            if (modal) modal.classList.remove('hidden');

            const textEl = document.getElementById('cq-confirm-delete-diapo-text');
            if (textEl) textEl.textContent = 'Cette action est irréversible.';
        }

        function cqCloseConfirmDeleteDiapo() {
            cqPendingDeleteDiapoIndex = null;
            const modal = document.getElementById('modal-cq-confirm-delete-diapo');
            if (modal) modal.classList.add('hidden');
        }

        function cqConfirmDeleteDiapo() {
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
            slide.answers.push({ text: '', isCorrect: false });
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
                modal.classList.remove('hidden');
            }
        }

        function cqCloseConfirmCreateQuiz() {
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
            if (modal) modal.classList.remove('hidden');
        }

        function cqCloseRenameModal() {
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
            cqQuizDraft.slides = [cqDefaultSlide()];
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
