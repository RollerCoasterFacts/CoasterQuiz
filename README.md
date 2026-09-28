# CoasterQuiz 🎢

Application web interactive de création et de jeu de quiz avec plusieurs modes de questions.

## Fonctionnalités

- **Modes de quiz** : QCM, Localisation (GeoCoast'R), JetPunk, Quiz Map
- **Éditeur visuel** : Interface drag-and-drop pour créer des questions
- **Jeu interactif** : Système de scoring avec feedback immédiat
- **Persistance** : Sauvegarde locale des quiz et des scores
- **Responsive** : Compatible desktop et mobile

## Utilisation

1. Ouvrir `index.html` dans un navigateur
2. Créer un compte ou se connecter
3. Créer un nouveau quiz ou éditer un existant
4. Jouer et voir les résultats

## Structure

- `index.html` - Interface utilisateur
- `script.js` - Logique applicative
- `styles.css` - Styles (Tailwind CSS)
- `audio/` - Fichiers audio (optionnel)
- `rollercoaster.png` - Image de fond

## Technologies

- HTML5
- JavaScript (vanilla)
- Tailwind CSS
- Leaflet.js (pour les cartes)
- Web Storage API

## Hébergement

Déployé sur [GitHub Pages](https://github.com/username/coasterquiz)

## Développement

### Cloner le repo
```bash
git clone https://github.com/username/coasterquiz.git
cd coasterquiz
```

### Serveur local (optionnel)
```bash
python -m http.server 8000
# Accéder à http://localhost:8000
```

## Notes

- Les quiz sont stockés dans le localStorage du navigateur
- Les données audio des questions sont stockées en base64 dans localStorage
- Pas d'API backend nécessaire

## Licence

Libre d'utilisation
