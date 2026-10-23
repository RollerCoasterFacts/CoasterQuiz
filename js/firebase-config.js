(function () {
    if (typeof firebase === "undefined") {
        console.warn("[Firebase] SDK non chargé");
        return;
    }

    firebase.initializeApp({
        apiKey: "AIzaSyDiIdJONmWLOuksdD3zrx24BXkbxMX9hvU",
        authDomain: "coasterquiz-3628b.firebaseapp.com",
        projectId: "coasterquiz-3628b",
        storageBucket: "coasterquiz-3628b.firebasestorage.app",
        messagingSenderId: "1037250532627",
        appId: "1:1037250532627:web:93283cff30f52a2b59f6e6"
    });

    const auth = firebase.auth();

    auth.onAuthStateChanged((user) => {
        if (!user) {
            auth.signInAnonymously().catch((err) => console.warn("[Firebase] connexion anonyme échouée", err));
            return;
        }
        window.firebaseUser = user;
        window.firebaseDB = firebase.firestore();
        window.dispatchEvent(new Event("firebase-ready"));
    });
})();
