#define _XOPEN_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <sys/stat.h>
#include <crypt.h>
#include <ctype.h>

#define PORT 50370
#define MAX 4096
#define SID "1023"
#define BASE_DIR "/srv/ie2102/IT24102370"
#define LOG_FILE "server_IT24102370.log"

#define RATE_LIMIT_SEC 1
#define MAX_FAILURES 3
#define LOCKOUT_SEC 30
#define SESSION_TIMEOUT 300

void reap(int sig) {
    (void)sig;
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

void log_event(char *ip, int port, int pid, char *user, char *cmd, char *res) {
    FILE *fp = fopen(LOG_FILE, "a");
    if (!fp) return;
    time_t now = time(NULL);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "[%Y-%m-%d %H:%M:%S]", localtime(&now));
    fprintf(fp, "%s IP:%s:%d PID:%d USER:%s CMD:%s RES:%s\n",
        time_str, ip, port, pid, strlen(user) ? user : "-", cmd, res);
    fclose(fp);
}

int is_valid_username(char *user) {
    if (strlen(user) < 3 || strlen(user) > 20) return 0;
    for (int i = 0; user[i]; i++) {
        if (!isalnum(user[i])) return 0;
    }
    return 1;
}

int register_user(char *user, char *pass) {
    if (!is_valid_username(user)) return -1;
    char path[512], file[1024]; 
    snprintf(path, sizeof(path), "%s/%s", BASE_DIR, user);
    
    if (access(path, F_OK) == 0) return 0; 
    
    mkdir("/srv/ie2102", 0777);
    mkdir(BASE_DIR, 0777);
    mkdir(path, 0777);
    
    snprintf(file, sizeof(file), "%s/pass.txt", path);
    FILE *fp = fopen(file, "w");
    if (!fp) return -2;
    
    char salt[] = "$6$DinethWifySalt$"; 
    char *hash = crypt(pass, salt);
    fprintf(fp, "%s", hash);
    fclose(fp);
    return 1;
}

int login_user(char *user, char *pass) {
    char file[512]; 
    snprintf(file, sizeof(file), "%s/%s/pass.txt", BASE_DIR, user);
    
    FILE *fp = fopen(file, "r");
    if (!fp) return 0;
    
    char stored[256];
    if (!fgets(stored, sizeof(stored), fp)) {
        fclose(fp);
        return 0;
    }
    fclose(fp);
    
    char salt[] = "$6$DinethWifySalt$";
    char *hash = crypt(pass, salt);
    return strcmp(stored, hash) == 0;
}

void handle_client(int sock, char *ip, int port) {
    char user[50] = "";
    char token[50] = "";
    time_t last_req = 0;
    time_t last_activity = time(NULL);
    int failed_logins = 0;
    time_t lockout_end = 0;

    while (1) {
        char header[20] = {0};
        int h_bytes = recv(sock, header, 4, MSG_PEEK);
        if (h_bytes <= 0) break;

        if (strncmp(header, "LEN:", 4) != 0) {
            send(sock, "ERR 400 SID:1023 Invalid Framing\n", 33, 0);
            char trash[MAX]; 
            recv(sock, trash, MAX, 0); 
            continue;
        }

        int i = 0;
        char c;
        while (recv(sock, &c, 1, 0) > 0 && c != '\n' && i < 19) {
            header[i++] = c;
        }
        header[i] = '\0';

        int len = atoi(header + 4);
        if (len <= 0 || len > MAX) {
            send(sock, "ERR 413 SID:1023 Payload Too Large\n", 37, 0);
            continue;
        }

        char *payload = malloc(len + 1);
        int total_read = 0;
        while (total_read < len) {
            int b = recv(sock, payload + total_read, len - total_read, 0);
            if (b <= 0) break;
            total_read += b;
        }
        payload[total_read] = '\0';

        time_t now = time(NULL);
        if (now - last_req < RATE_LIMIT_SEC) {
            send(sock, "ERR 429 SID:1023 Slow Down\n", 27, 0);
            free(payload);
            continue;
        }
        last_req = now;

        if (strlen(token) > 0 && (now - last_activity > SESSION_TIMEOUT)) {
            token[0] = '\0';
            user[0] = '\0';
            send(sock, "ERR 401 SID:1023 Session Expired\n", 33, 0);
        }
        last_activity = now;

        char cmd[50] = {0}, u[50] = {0}, p[50] = {0};
        int parsed = sscanf(payload, "%s %s %s", cmd, u, p);
        char response[MAX];

        if (strcmp(cmd, "REGISTER") == 0 && parsed >= 3) {
            int reg = register_user(u, p);
            if (reg == 1) snprintf(response, sizeof(response), "OK 200 SID:%s Registered\n", SID);
            else if (reg == 0) snprintf(response, sizeof(response), "ERR 409 SID:%s Exists\n", SID);
            else snprintf(response, sizeof(response), "ERR 400 SID:%s Invalid Username\n", SID);
        }
        else if (strcmp(cmd, "LOGIN") == 0 && parsed >= 3) {
            if (now < lockout_end) {
                snprintf(response, sizeof(response), "ERR 423 SID:%s Locked. Try later.\n", SID);
            } else if (login_user(u, p)) {
                strcpy(user, u);
                snprintf(token, sizeof(token), "T%ld%d", time(NULL), rand() % 1000);
                failed_logins = 0;
                snprintf(response, sizeof(response), "OK 200 SID:%s TOKEN:%s\n", SID, token);
            } else {
                failed_logins++;
                if (failed_logins >= MAX_FAILURES) {
                    lockout_end = now + LOCKOUT_SEC;
                    snprintf(response, sizeof(response), "ERR 423 SID:%s Locked out\n", SID);
                } else {
                    snprintf(response, sizeof(response), "ERR 401 SID:%s Login Fail\n", SID);
                }
            }
        }
        else if (strcmp(cmd, "LOGOUT") == 0) {
            user[0] = '\0';
            token[0] = '\0';
            snprintf(response, sizeof(response), "OK 200 SID:%s Logout\n", SID);
        }
        else if (strcmp(cmd, "WHOAMI") == 0 && parsed >= 2) {
            if (strcmp(u, token) == 0 && strlen(token) > 0) {
                snprintf(response, sizeof(response), "OK 200 SID:%s User:%s\n", SID, user);
            } else {
                snprintf(response, sizeof(response), "ERR 403 SID:%s Invalid Token\n", SID);
            }
        }
        else if (strcmp(cmd, "PING") == 0 && parsed >= 2) {
            if (strcmp(u, token) == 0 && strlen(token) > 0) {
                snprintf(response, sizeof(response), "OK 200 SID:%s PONG\n", SID);
            } else {
                snprintf(response, sizeof(response), "ERR 403 SID:%s Invalid Token\n", SID);
            }
        }
        else if (strcmp(cmd, "STORE") == 0 && parsed >= 2) {
            if (strcmp(u, token) == 0 && strlen(token) > 0) {
                snprintf(response, sizeof(response), "OK 200 SID:%s Stored successfully\n", SID);
            } else {
                snprintf(response, sizeof(response), "ERR 403 SID:%s Invalid Token\n", SID);
            }
        }
        else {
            snprintf(response, sizeof(response), "ERR 400 SID:%s Unknown\n", SID);
        }

        send(sock, response, strlen(response), 0);
        log_event(ip, port, getpid(), user, payload, response);
        free(payload);
    }
    close(sock);
    exit(0);
}

int main() {
    signal(SIGCHLD, reap);
    int server_fd, new_socket;
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, 10);

    printf("Server running on %d...\n", PORT);
    mkdir("/srv/ie2102", 0777);
    mkdir(BASE_DIR, 0777);

    while (1) {
        new_socket = accept(server_fd, (struct sockaddr *)&address, &addrlen);
        if (fork() == 0) {
            close(server_fd);
            handle_client(new_socket, inet_ntoa(address.sin_addr), ntohs(address.sin_port));
        } else {
            close(new_socket);
        }
    }
}
