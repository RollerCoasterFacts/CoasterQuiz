// Firebase Configuration
(async () => {
  const firebaseConfig = {
    apiKey: "AIzaSyB6CcjbibxW5OymcvHcliz2fOgPTuGuaUk",
    authDomain: "coasterquiz-13534.firebaseapp.com",
    projectId: "coasterquiz-13534",
    storageBucket: "coasterquiz-13534.firebasestorage.app",
    messagingSenderId: "9495944351",
    appId: "1:9495944351:web:50f79c39bfa6e0a30396aa"
  };

  // Initialize Firebase (globals loaded from CDN)
  const app = firebase.initializeApp(firebaseConfig);
  const auth = firebase.auth();
  const db = firebase.firestore();

  // Auth anonyme au démarrage
  try {
    const result = await auth.signInAnonymously();
    console.log("[Firebase] Utilisateur anonyme connecté:", result.user.uid);
    window.firebaseUser = result.user;
    window.firebaseDB = db;
    window.firebaseAuth = auth;
  } catch (error) {
    console.error("[Firebase] Erreur auth anonyme:", error);
  }
})();
