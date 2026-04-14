# NetSentinel - Network Log Analyzer & Intrusion Detection System

Analyseur de logs Apache et système de détection d'intrusions (IDS) écrit en Java.

## Prérequis

- **Java 17+**
- Fichiers logs Apache Combined Format
- Aucune dépendance externe

## Détecteurs Disponibles

- **SQL Injection**: Détecte les patterns SQL malveillants
- **Vulnerability Scan**: Repère les scans de vulnérabilités
- **Brute Force**: Alerte sur les tentatives de connexion répétées (>10 échecs)
- **DDoS**: Détecte les pics de requêtes anormaux
- **Correlation**: Élève la gravité des alertes multiples

## Format des Logs

NetSentinel supporte le format **Apache Combined Format** :

```
172.16.1.19 - - [15/Mar/2025:06:00:06 +0100] "GET /api/v1/stats HTTP/1.1" 200 1063 "https://t.co/abcdef" "Mozilla/5.0..."
```

Champs parsés :
- **IP Address** - Adresse IP source
- **Username** - Utilisateur authentifié (le `-` si non authentifié)
- **Timestamp** - Date et heure de la requête
- **HTTP Method** - GET, POST, PUT, DELETE, etc.
- **Request URL** - Chemin de la ressource demandée
- **Protocol** - Version HTTP (HTTP/1.1, HTTP/2, etc.)
- **Status Code** - Code de réponse (200, 404, 500, etc.)
- **Response Size** - Taille en bytes de la réponse (ou `-` si 0)
- **Referer** - URL de provenance de la requête
- **User-Agent** - Type de navigateur/client

## Configuration

### Ajout des logs

Placez vos logs dans le dossier `in`, dans le dossier du repository téléchargé depuis GitHub.

### Liste blanche

Éditer `whitelist.txt` pour ajouter les IPs de confiance (une par ligne):
```
192.168.1.1
10.0.0.5
172.16.1.0
```

Ces IPs seront exclues de l'analyse.

## Compilation et Lancement

Ouvrez un terminal à la racine du dossier du repository, puis exécutez les commandes suivantes :

### Compiler (une seule fois)

    javac -d bin src/models/*.java src/detectors/*.java src/utils/*.java src/*.java

### Lancer le programme

    java -cp bin Main

Tous les rapports de sortie vont, si créés, dans le dossier `out` du projet.
