# LAB 3 - OBSERVATION DU TRAFIC HTTP(S) ANDROID AVEC BURP SUITE

**Rapport de Sécurité Mobile - Analyse du Trafic Réseau**

**Étudiant(e):** Fatima Ezzahra El Boudhiri  
**Date:** 05 mai 2026  
**Cible Autorisée:** http://example.com, https://example.com, services Google  
**Environnement:** Burp Suite Community Edition v2026.3.3 | Android Emulator Pixel 6 (API 34)

---

## 1. PÉRIMÈTRE ET OBJECTIFS

### 1.1 Périmètre du Test
- **Appareil testée:** Émulateur Android Pixel 6 (API 34)
- **Adresse locale Burp:** 127.0.0.1:8080 (listener initial)
- **Adresse locale Burp (réseau):** 0.0.0.0:8081 (accessible depuis l'émulateur)
- **Adresse hôte (emulator):** 192.168.100.44
- **Proxy configuré sur Android:** Manual - 192.168.100.44:8081
- **Domaines testés:** example.com, www.google.com, connectivitycheck.gstatic.com
- **Protocoles:** HTTP et HTTPS

### 1.2 Objectifs Réalisés
✓ Vérifier que l'émulateur Android envoie son trafic via Burp Suite  
✓ Identifier les éléments des requêtes HTTP (headers, méthodes, paramètres)  
✓ Comprendre la différence entre HTTP et HTTPS  
✓ Documenter le rôle du certificat CA dans le décryptage HTTPS  
✓ Produire une trace d'audit complète avec preuves

---

## 2. CONFIGURATION TECHNIQUE DÉTAILLÉE

### 2.1 Burp Suite - Configuration du Proxy

**Étape 1: Initialisation du Projet**
- Ouverture de Burp Suite Community Edition v2026.3.3
- Création d'un nouveau projet: "LAB-3-SECURITY"
- Accès à l'onglet Proxy pour configuration des listeners

**Étape 2: Listeners de Proxy**

Deux listeners ont été configurés:

| Paramètre | Listener 1 | Listener 2 |
|-----------|-----------|-----------|
| Adresse de liaison | 127.0.0.1 | 0.0.0.0 (Tous les interfaces) |
| Port | 8080 | 8081 |
| Statut | En cours d'exécution | En cours d'exécution ✓ |
| Certificat | Per-host | Per-host |
| Protocoles TLS | Default | Default |
| Support HTTP/2 | Activé ✓ | Activé ✓ |

**Justification:** Le listener 1 sur localhost n'était pas accessible depuis l'émulateur Android. Le listener 2 sur "Tous les interfaces" (0.0.0.0) à permet la connexion depuis l'adresse IP 192.168.100.44 du réseau local.

**Étape 3: Configuration Initiale d'Interception**
- Intercept: OFF (important pour capturer le trafic sans pause)
- HTTP History: Activé et prêt à enregistrer les requêtes
- WebSockets History: Activé

### 2.2 Android Emulator - Configuration du Proxy

**Appareil:** Pixel 6 (API 34) avec Android 15  
**Réseau:** AndroidWifi (connecté)

**Configuration Réseau:**
```
Réseau: AndroidWifi
Mode Proxy: Manual (après configuration)
Hostname du proxy: 192.168.100.44
Port du proxy: 8081
Encodage accepté: gzip, deflate, br
```

**Étapes de Configuration:**
1. Paramètres → Réseau et Internet → Wi-Fi
2. Long-appui sur "AndroidWifi" → Modifier le réseau
3. Options avancées → Proxy: Manuel
4. Saisie du hostname: 192.168.100.44
5. Saisie du port: 8081
6. Sauvegarde

---

## 3. CAPTURE ET ANALYSE DU TRAFIC

### 3.1 Trafic HTTP - Premières Captures

**Test Initial:** Navigation vers http://example.com

**Résultats de Capture:**
- Nombre de requêtes capturées: 22+ requêtes
- Statut: HTTP history non vide ✓
- Preuves visuelles: Screenshot montrant 22 lignes de requêtes

**Requêtes Principales Capturées:**

| # | Hôte | Méthode | URL | Statut | MIME | Timestamp |
|---|------|---------|-----|--------|------|-----------|
| 1 | example.com | GET | / | 200 | HTML | 08:36:16 |
| 4 | connectivitycheck.gstatic.com | GET | /generate_204 | 204 | (vide) | 12:33:51 |
| 5 | www.google.com | GET | /gen_204 | 200 | HTML | 12:33:54 |
| 11 | www.google.com | GET | /gen_204 | 200 | HTML | 12:25:23 |

### 3.2 Analyse Détaillée des Requêtes HTTP

#### Requête 1: Connectivity Check - HTTP

**Type de Requête:** Android Connectivity Check

```
GET /generate_204 HTTP/1.1
Connection: keep-alive
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 
            (KHTML, like Gecko) Chrome/60.0.3112.32 Safari/537.36
Host: connectivitycheck.gstatic.com
Accept-Encoding: gzip, deflate, br
```

**Réponse HTTP/1.1:**
```
HTTP/1.1 204 No Content
Content-Length: 0
Cross-Origin-Resource-Policy: cross-origin
Date: Tue, 05 May 2026 11:24:59 GMT
```

**Analyse Technique:**

| Élément | Valeur | Interprétation |
|---------|--------|-----------------|
| Méthode HTTP | GET | Requête de récupération de ressource |
| Status Code | 204 | Succès - Pas de contenu (réponse vide intentionnelle) |
| Host Header | connectivitycheck.gstatic.com | Vérification de connectivité par Android |
| User-Agent | Chrome 60.0 | Navigateur Chrome sur Linux (identification de l'appareil) |
| Content-Length | 0 | Aucun corps de réponse (attendu pour 204) |
| CORS Header | cross-origin | Permet les requêtes cross-origin |

**Découverte de Sécurité:**
- Android effectue des vérifications automatiques de connectivité
- Ces requêtes révèlent la version du navigateur (Chrome/60.0.3112.32)
- Le User-Agent expose l'OS (Linux x86_64) et la plateforme

#### Requête 2: Google Search - HTTP

**Type de Requête:** Recherche Google

```
GET /gen_204 HTTP/1.1
Connection: keep-alive
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 
            (KHTML, like Gecko) Chrome/60.0.3112.32 Safari/537.36
Host: www.google.com
Accept-Encoding: gzip, deflate, br
```

**Réponse HTTP/1.1:**
```
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
Content-Security-Policy: object-src 'none';base-uri 'self';script-src 
                         'nonce-X1FTqiQWrTDoI728N€-XRg' 'strict-dynamic'...
Permissions-Policy: upload=()
Date: Tue, 05 May 2026 11:25:12 GMT
Server: gws (Google Web Server)
X-XSS-Protection: 0
X-Frame-Options: SAMEORIGIN
Content-Length: 0
```

**Analyse des Headers de Sécurité:**

| Header | Valeur | Objectif |
|--------|--------|----------|
| Content-Security-Policy (CSP) | object-src 'none'; base-uri 'self'; script-src 'nonce-...' | Prévient les injections de contenu et les attaques XSS |
| X-XSS-Protection | 0 | Désactive le filtre XSS (s'appuie sur CSP) |
| X-Frame-Options | SAMEORIGIN | Prévient le clickjacking (cadrage dans même origine) |
| Permissions-Policy | upload=() | Désactive l'upload de fichiers via le navigateur |
| Server | gws | Identifie le serveur (Google Web Server) |

**Observations Importantes:**
- La CSP utilise des nonces aléatoires pour valider les scripts
- Le header X-XSS-Protection est désactivé car CSP est plus robuste
- SAMEORIGIN protège contre l'attaque de clickjacking
- Le serveur identifié comme "gws" confirme Google

### 3.3 Trafic HTTPS - Après Installation du Certificat CA

**Test HTTPS:** Navigation vers https://example.com

**Données Capturées:**

```
GET /complete/search?client=chrome&gs_ri=chrome-mobile-ext-ansg&ossi=t&q=...
Host: www.google.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36...
Accept-Encoding: gzip, deflate, br
```

**Réponse HTTPS Décryptée:**
```
HTTP/1.1 200 OK
Content-Type: application/json
Content-Security-Policy: object-src 'none';...
Transfer-Encoding: chunked
Date: Tue, 05 May 2026 12:25:12 GMT
Server: gws
```

**Contenu Décrypté (JSON):**
Données de suggestions de recherche incluant:
- "festival magazine"
- "gitea casablanca"  
- "seturf saint cloud"
- "retail holding"

**Analyse de Sécurité HTTPS:**

| Aspect | Observation | Risque |
|--------|-------------|--------|
| Chiffrement | TLS/SSL nécessaire pour HTTPS | Protégé ✓ |
| Certificat | Installé comme CA Burp (test uniquement) | Visible dans ce contexte de lab |
| Headers | Mêmes protections que HTTP | Sécurisé ✓ |
| Contenu | Données de recherche sensibles visibles | Exposé via proxy (contexte lab) |

---

## 4. DIFFÉRENCES HTTP vs HTTPS OBSERVÉES

### 4.1 HTTP (Plaintext)
- Requêtes visibles en clair dans Burp HTTP History
- Headers lisibles immédiatement
- Pas de négociation de certificat
- Vitesse de transmission plus rapide mais non sécurisée

### 4.2 HTTPS (Encrypted)
- Requêtes chiffrées par TLS
- Certificat de serveur vérifié avant communication
- Burp doit décrypter via CA Certificate
- Contenu visible uniquement après installation du certificat CA de Burp

### 4.3 Rôle du Certificat CA

**Contexte Lab:**
Le certificat CA de Burp Suite est spécifiquement conçu pour la phase de test. Dans ce lab, nous avons:

1. **Exporté** le certificat CA de Burp depuis Proxy → Options → CA certificate
2. **Format:** PEM (également disponible en DER)
3. **Installation:** Accès Android → Settings → Security & privacy → Encryption & credentials → Install a certificate → CA certificate
4. **Résultat:** Android accepte les certificats auto-signés par Burp pour ce test

**Processus Technique:**
```
Client (Android) <--TLS--> Burp Proxy <--TLS--> Serveur
                 (certificat Burp)  (certificat réel)
```

Burp intercepte, décrypte, puis re-chiffre avec son propre certificat CA.

**Implications de Sécurité:**
- Le certificat ne doit être installé QUE pour les tests autorisés
- Installation dans le système signifie tous les HTTPS passent par Burp
- Risque: Un attaquant utilisant ce certificat pourrait lire tout le trafic HTTPS

---

## 5. CONFIGURATION DES LISTENERS ET TROUBLESHOOTING

### 5.1 Problème Initial: Port 8080 Non Accessible

**Symptôme:** Proxy configuré sur Android (192.168.1.11:8080) mais requêtes non capturées.

**Cause Root:** Le listener 127.0.0.1:8080 était limité à localhost. L'émulateur Android, bien que sur la même machine, ne peut pas atteindre 127.0.0.1 car ce n'est pas une interface réseau réelle.

**Solution Appliquée:**
1. Création d'un second listener sur port 8081
2. Configuration: Bind to address = "All interfaces" (0.0.0.0)
3. Mise à jour Android proxy vers 192.168.100.44:8081
4. Redémarrage de la vérification: ✓ Requêtes capturées

### 5.2 Changement d'Adresse IP Hôte

**Situation:** Lors du changement de localisation (Marrakesh → autre), l'adresse IP Wi-Fi a changé:
- Ancienne: 192.168.1.11
- Nouvelle: 192.168.100.44

**Actions Prises:**
1. Exécution de `ipconfig` pour identifier la nouvelle IP
2. Mise à jour du proxy Android: 192.168.100.44:8081
3. Re-test: ✓ Trafic capturé avec succès

### 5.3 Erreur Certificate Trust

**Symptôme:** Navigateur affiche "NET::ERR_CERT_AUTHORITY_INVALID" ou "Your connection is not private"

**Cause:** Certificat CA de Burp non reconnu par Android

**Résolution:**
1. Export du certificat Burp au format PEM
2. Transfer via ADB: `adb push burp_ca.pem /sdcard/`
3. Installation dans Settings → Security & privacy → Encryption & credentials → Install a certificate → CA certificate
4. Sélection: CA certificate (pas Wi-Fi certificate)
5. Redémarrage du navigateur: ✓ Certificat accepté

---

## 6. PREUVES DE RÉUSSITE (CHECKPOINTS)

| Checkpoint | Description | Statut | Preuve |
|-----------|-------------|--------|--------|
| 1 | Burp capture ≥1 requête | ✓ Réussi | 22+ requêtes visibles |
| 2 | Listener actif + documenté | ✓ Réussi | 0.0.0.0:8081 running |
| 3 | Android proxy Manual + IP:PORT | ✓ Réussi | 192.168.100.44:8081 configuré |
| 4 | Intercept OFF après démo | ✓ Réussi | Intercept: OFF |
| 5 | Rapport produit | ✓ Réussi | Ce document |
| 6 | Nettoyage (proxy désactivé) | ✓ Réussi | Proxy: None |
| 7 | Certificat supprimé | ✓ Réussi | Clear credentials exécuté |
| 8 | HTTP history non vide | ✓ Réussi | 22+ requêtes documentées |
| 9 | HTTPS traffic décrypté | ✓ Réussi | Contenu JSON visible |

---

## 7. SÉCURITÉ - RECOMMANDATIONS ET DÉCOUVERTES

### 7.1 Révélations de la Mise en Proxy

**1. User-Agent Information Leakage**
- Le User-Agent expose: OS (Linux x86_64), navigateur (Chrome 60.0.3112.32), plateforme (KHTML)
- **Risque:** Profiling des versions de navigateur pour identifier les vulnérabilités
- **Recommandation:** Minimiser les informations dans User-Agent ou utiliser des valeurs génériques

**2. Connectivity Check Patterns**
- Android effectue des requêtes GET /gen_204 et /generate_204 automatiquement
- Ces requêtes révèlent quand l'appareil se connecte au Wi-Fi
- **Risque:** Tracking des événements de connectivité
- **Recommandation:** Chiffrer ou masquer les métadonnées de connectivité

**3. Headers de Sécurité Présents mais Incomplets**
- Google utilise CSP + X-Frame-Options + X-XSS-Protection
- Cependant, Content-Length: 0 indique des réponses vides intentionnelles
- **Recommandation:** Vérifier la cohérence des headers avec le contenu

**4. CORS Accessible Globalement**
- Header: "Cross-Origin-Resource-Policy: cross-origin"
- **Risque:** Permet les requêtes cross-origin depuis n'importe quel domaine
- **Recommandation:** Restreindre à des origines spécifiques si possible

### 7.2 Chaîne de Confiance Certificat (HTTPS)

**Modèle Observé:**
```
Android → [TLS] → Burp Suite → [TLS] → Serveur Google
         (Cert CA Burp)      (Cert Réel)
```

**Implications:**
- Android accepte le certificat CA Burp parce qu'il a été installé manuellement
- En production, Android rejette les certificats non signés par une CA de confiance
- **Sécurité Lab:** Acceptable pour tests autorisés uniquement
- **Sécurité Production:** Ne jamais installer de certificats non-officiels

### 7.3 Données Sensibles Observées

Pendant les tests HTTPS, les éléments suivants ont été décryptés:
- Requêtes de recherche Google (sujet de recherche de l'utilisateur)
- Identifiant du client (client=chrome)
- Paramètres de recherche détaillés
- Suggestions de recherche (json payload)

**Contexte:** Ces données sont normalement chiffrées HTTPS et invisibles sans la clé privée du serveur. L'accès via Burp simule un scénario d'attaque man-in-the-middle si le certificat n'était pas de confiance.

---

## 8. NETTOYAGE ET FERMETURE

### 8.1 Désactivation du Proxy Android

**Processus:**
1. Settings → Network & internet → Wi-Fi
2. Long-press AndroidWifi → Modify network
3. Proxy: Manual → **None**
4. Save
5. Vérification: Proxy field affiche "None" ✓

### 8.2 Suppression du Certificat CA

**Processus:**
1. Settings → Security & privacy → Encryption & credentials
2. Clear credentials (button)
3. Confirmation: "Remove all certificates?"
4. Confirmation dialog: OK
5. Vérification: "Trusted credentials" vide ✓

**Raison:** Les certificats de test ne doivent pas persister au-delà du lab

### 8.3 Fermeture de Burp Suite

- Fermeture du projet LAB-3-SECURITY
- Arrêt des listeners de proxy
- Fermeture de l'application Burp

---

## 9. CHRONOLOGIE DÉTAILLÉE DES TESTS

| Heure | Étape | Résultat |
|------|-------|---------|
| 10:15 | Burp Suite ouvert | Projet créé |
| 10:30 | Listener 8080 configuré | 127.0.0.1:8080 running |
| 10:45 | Android proxy 192.168.1.11:8080 | Pas de capture |
| 11:00 | Identification IP hôte: 192.168.1.11 | Trouvée via ipconfig |
| 11:30 | Changement localisation (Marrakesh) | IP change → 192.168.100.44 |
| 11:45 | Listener 8081 créé (0.0.0.0) | 0.0.0.0:8081 running |
| 12:00 | Android proxy mise à jour 192.168.100.44:8081 | Configuré ✓ |
| 12:15 | Navigation http://example.com | 22+ requêtes capturées ✓ |
| 12:30 | Analyse requête GET /generate_204 | Headers documentés ✓ |
| 12:45 | Export certificat CA (PEM) | burp_ca.pem created |
| 13:00 | Transfer via ADB | Certificate pushé à /sdcard/ |
| 13:15 | Installation certificat CA | CA certificate installé ✓ |
| 13:30 | Navigation https://example.com | HTTPS décrypté ✓ |
| 13:45 | Analyse requête Google Search | JSON payload visible ✓ |
| 14:00 | Démonstration Interception | Intercept ON/OFF ✓ |
| 14:15 | Suppression certificat | Clear credentials ✓ |
| 14:30 | Désactivation proxy Android | Proxy: None ✓ |
| 14:45 | Fermeture Burp | Nettoyage complet ✓ |

---

## 10. CONCLUSION

### 10.1 Objectifs Atteints

✓ **Objectif 1:** Vérifier Android envoie trafic via Burp  
Réalisé: 22+ requêtes capturées et documentées

✓ **Objectif 2:** Identifier éléments requête HTTP  
Réalisé: Headers, User-Agent, Host, Methods, Status codes analysés

✓ **Objectif 3:** Comprendre HTTP vs HTTPS  
Réalisé: Différences observées et documentées

✓ **Objectif 4:** Expliquer rôle certificat CA  
Réalisé: Export, installation, et impact documentés

✓ **Objectif 5:** Produire trace d'audit  
Réalisé: Ce rapport avec preuves (screenshots)

### 10.2 Apprentissages Clés

1. **Configuration Réseau:** Localhost (127.0.0.1) n'est pas accessible depuis l'émulateur Android - utiliser 0.0.0.0 ou une adresse IP réelle

2. **Interception HTTPS:** Nécessite installation du certificat CA du proxy dans le système d'exploitation cible

3. **Android Connectivity Checks:** L'OS effectue des requêtes automatiques qui révèlent des métadonnées

4. **Security Headers:** Même HTTP basique inclut CORS, CSP, et X-Frame-Options pour la protection

5. **Man-in-the-Middle Simulation:** Burp Suite simule une attaque MITM contrôlée pour l'analyse

### 10.3 Mesures de Sécurité Appliquées

- ✓ Certificat CA installé temporairement et supprimé après test
- ✓ Proxy désactivé après observations
- ✓ Cible autorisée (example.com) utilisée pour tous les tests
- ✓ Pas d'accès à comptes personnels ou données sensibles réelles
- ✓ Toutes les configurations ont été nettoyées

### 10.4 Prochaines Étapes Recommandées

Pour des labs avancés:
- Utiliser le Repeater de Burp pour modifier et rejouer des requêtes
- Analyser les réponses avec l'Inspector pour détecter des vulnérabilités
- Tester des endpoints API avec d'autres paramètres
- Effectuer une analyse automatisée avec Scanner (version Pro)

---

## ANNEXE A: FICHIERS GÉNÉRÉS

```
certificate: burp_ca.pem (exporté et transféré via ADB)
project: LAB-3-SECURITY (Burp Suite project file)
output: HTTP history avec 22+ requêtes
```

## ANNEXE B: COMMANDES ADB UTILISÉES

```bash
adb devices
# Output: emulator-5554   device

adb -s emulator-5554 push "C:\Users\LENOVO\OneDrive\Bureau\burp_ca.pem" /sdcard/
# Output: burp_ca.pem (939 bytes in 0.014s)
```

## ANNEXE C: INFORMATIONS SYSTÈME

**Host (Tester):**
- OS: Windows (PowerShell utilisé)
- Adresse IP Wi-Fi: 192.168.100.44 (finale) / 192.168.1.11 (initiale)
- Burp Suite: Community Edition v2026.3.3

**Target (Emulator):**
- Device: Android Emulator - Pixel 6
- API Level: 34 (Android 15)
- Network: AndroidWifi (192.168.100.0/24)
- Proxy Port: 8081

---

**Report Generated:** 2026-05-05 14:45  
**Status:** LAB COMPLETED ✓  
**All Checkpoints Passed:** 9/9
