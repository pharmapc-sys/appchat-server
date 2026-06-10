# AppChat — Serveur de chat privé

Serveur WebSocket avec **comptes utilisateurs** et **messages privés 1-à-1** :

- Inscription avec pseudo, mot de passe (haché scrypt) et numéro de téléphone
  **France (+33)** ou **Liban (+961)**, normalisé en E.164, unique par compte.
- Recherche d'un utilisateur **par numéro de téléphone** (seul moyen de découverte).
- Les messages ne sont délivrés et rejoués **qu'aux deux participants**, avec un
  numéro de séquence pour resynchroniser l'historique après une coupure.

## Lancer

```bash
cd server
npm install        # installe 'ws'
npm start          # écoute sur ws://0.0.0.0:8080
```

Changer le port : `PORT=9000 npm start`

## Persistance de l'historique

Deux modes, choisis automatiquement au démarrage :

- **Postgres** si la variable `DATABASE_URL` est définie — l'historique survit
  aux redémarrages et redéploiements, même sur un hébergeur à disque éphémère.
- **Fichier** `messages.jsonl` (à côté de `server.js`) sinon.

### Base de données gratuite (recommandé)

Sur les hébergeurs gratuits (Render, Railway, Fly…), le fichier `messages.jsonl`
est **effacé à chaque redéploiement**. Une base Postgres gratuite règle ça :

- **Neon** — <https://neon.tech> : créer un projet, copier la « connection string ».
- **Supabase** — <https://supabase.com> : Project Settings → Database →
  Connection string (URI).

Puis :

```bash
DATABASE_URL='postgresql://user:motdepasse@hôte/dbname' npm start
```

La table `messages` est créée automatiquement au premier démarrage.
(Postgres local sans TLS : ajouter `PGSSLMODE=disable`.)

## Rendre accessible depuis internet

L'app a besoin d'une URL `ws://` ou `wss://` joignable depuis les téléphones.

- **Test rapide (sans serveur)** : avec [ngrok](https://ngrok.com) →
  `ngrok http 8080` puis utilise l'URL `https://xxxx.ngrok-free.app` en
  remplaçant `https` par `wss` dans l'app : `wss://xxxx.ngrok-free.app`.
- **VPS / cloud** : lance `npm start` sur le serveur, ouvre le port 8080,
  et mets `ws://IP_DU_SERVEUR:8080` dans l'app.
- **Production (recommandé)** : mets un reverse-proxy HTTPS (Caddy/Nginx)
  devant le serveur et utilise `wss://ton-domaine`. Android exige `wss://`
  (TLS) si tu veux éviter d'autoriser le trafic en clair.

### Hébergement gratuit avec URL stable (Render)

Contrairement au tunnel localhost.run intégré à l'app (URL qui change à chaque
redémarrage), ceci donne une URL **permanente** avec historique conservé :

1. Pousser le dossier `server/` dans un dépôt GitHub.
2. Sur <https://render.com> (plan gratuit) : New → Web Service → connecter le
   dépôt ; Build : `npm install` ; Start : `npm start`.
3. Dans Environment, ajouter `DATABASE_URL` (la chaîne Neon/Supabase ci-dessus).
4. Render fournit `https://xxx.onrender.com` → dans l'app, saisir
   `wss://xxx.onrender.com` comme serveur relais.

> Note : le plan gratuit de Render endort le service après ~15 min d'inactivité ;
> la première connexion suivante prend quelques secondes (l'app se reconnecte seule).

## Renseigner l'URL dans l'app

Sur l'écran de connexion/inscription, champ **« Serveur »**
(ex. `wss://xxx.onrender.com` ou `ws://192.168.1.42:8080` en local).

## Protocole

Client → serveur (authentification, obligatoire en premier) :
- `{"t":"register","user","pass","phone"}` — crée un compte (téléphone FR/LB).
- `{"t":"login","user","pass"}` ou `{"t":"auth","token"}` (reconnexion).

Réponse : `{"t":"auth_ok","uid","user","phone","token"}` ou `{"t":"error","code","msg"}`.

Client → serveur (après authentification) :
- `{"t":"hello","since":<dernier seq reçu>}` — rejoue mes messages manqués.
- `{"t":"find","phone"}` → `{"t":"found","phone","user":{uid,user,phone}|null}`.
- `{"t":"msg","to":<uid>,"mid","text","ts"}` — message privé.

Serveur → client :
- `{"t":"msg","from","fromName","to","mid","text","ts","seq"}` (backfill + temps réel,
  uniquement aux deux participants).

Tests : `node test-private.js` (serveur local sur le port 18099).
