(function () {
    if (typeof firebase === "undefined") {
        console.warn("[Firebase] SDK non chargé");
        return;
    }

    firebase.initializeApp({
        apiKey: "AIzaSyB6CcjbibxW5OymcvHcliz2fOgPTuGuaUk",
        authDomain: "coasterquiz-13534.firebaseapp.com",
        projectId: "coasterquiz-13534",
        storageBucket: "coasterquiz-13534.firebasestorage.app",
        messagingSenderId: "9495944351",
        appId: "1:9495944351:web:50f79c39bfa6e0a30396aa"
    });

    firebase.auth().signInAnonymously()
        .then((cred) => {
            window.firebaseUser = cred.user;
            window.firebaseDB = firebase.firestore();
            window.dispatchEvent(new Event("firebase-ready"));
        })
        .catch((err) => console.warn("[Firebase] connexion anonyme échouée", err));
})();
