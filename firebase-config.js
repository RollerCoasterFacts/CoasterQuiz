// Firebase Configuration
// Wait for Firebase SDK to load from CDN
window.addEventListener('DOMContentLoaded', () => {
  const firebaseConfig = {
    apiKey: "AIzaSyB6CcjbibxW5OymcvHcliz2fOgPTuGuaUk",
    authDomain: "coasterquiz-13534.firebaseapp.com",
    projectId: "coasterquiz-13534",
    storageBucket: "coasterquiz-13534.firebasestorage.app",
    messagingSenderId: "9495944351",
    appId: "1:9495944351:web:50f79c39bfa6e0a30396aa"
  };

  if (typeof firebase === 'undefined') {
    console.warn("[Firebase] SDK not loaded yet, retrying...");
    setTimeout(() => window.dispatchEvent(new Event('DOMContentLoaded')), 100);
    return;
  }

  try {
    // Initialize Firebase
    const app = firebase.initializeApp(firebaseConfig);
    const auth = firebase.auth();
    const db = firebase.firestore();

    // Auth anonyme
    auth.signInAnonymously().then((result) => {
      console.log("[Firebase] Utilisateur anonyme connecté:", result.user.uid);
      window.firebaseUser = result.user;
      window.firebaseDB = db;
      window.firebaseAuth = auth;
    }).catch((error) => {
      console.error("[Firebase] Erreur auth anonyme:", error);
    });
  } catch (error) {
    console.error("[Firebase] Erreur initialisation:", error);
  }
});
