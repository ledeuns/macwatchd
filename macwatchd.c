#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <net/route.h>
#include <poll.h>
#include <err.h>
#include <sys/types.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/if_dl.h>
#include <arpa/inet.h>
#include <netdb.h>

void		sighdlr(int);
__dead void	usage(void);
void		processrtmsg(struct rt_msghdr *, int);
void		get_addr(char *, int, int);
int		main(int, char *[]);

volatile sig_atomic_t	 quit, reconfig;
struct rt_msghdr	*rtmsg;

struct macwatch {
	struct ether_addr	mac;
	int			count;
	struct sockaddr		sa[];
};

#define ROUNDUP(a) \
        ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
#define ADVANCE(x, n) (x += ROUNDUP((n)->sa_len))

#define SOCKET_NAME "/var/run/macwatchd.sock"

void
sighdlr(int sig)
{
        switch (sig) {
        case SIGTERM:
        case SIGINT: 
                quit = 1;
                break;
        case SIGHUP:
                reconfig = 1;
                break;
        }
}

__dead void
usage(void)
{
        extern char *__progname;

        fprintf(stderr, "usage: %s [-dnv] [-f file]\n", __progname);
        exit(1);
}

int
main(int argc, char *argv[])
{
	int		debug = 0, ch;
	unsigned int	filter = 0;
	int		s;
	int		n;
	char		msg[2048];
	struct pollfd	pfd[1];


	while ((ch = getopt(argc, argv, "d")) != -1) {
		switch (ch) {
		case 'd':
			debug = 1;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	if (!debug)
		daemon(1, 0);

	signal(SIGTERM, sighdlr);
	signal(SIGINT, sighdlr);
	signal(SIGHUP, sighdlr);
	signal(SIGPIPE, SIG_IGN);

        s = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC);
        if (s == -1)
                err(1, "socket");

	filter = ROUTE_FILTER(RTM_RESOLVE) | ROUTE_FILTER(RTM_DELETE);
	if (setsockopt(s, AF_ROUTE, ROUTE_MSGFILTER, &filter,
	    sizeof(filter)) == -1)
               	err(1, "setsockopt(ROUTE_MSGFILTER)");

	pfd[0].fd = s;
	pfd[0].events = POLLIN;

	while (quit == 0) {
		n = poll(pfd, 1, 60 * 1000);
		if (n == -1)
			err(1, "poll");
		if ((pfd[0].revents & (POLLERR|POLLNVAL)))
			errx(1, "bad fd %d", pfd[0].fd);
		if ((pfd[0].revents & (POLLIN|POLLHUP))) {
			if ((n = read(s, msg, sizeof(msg))) == -1) {
				if (errno == EINTR)
					continue;
				err(1, "read");
			}
			processrtmsg((struct rt_msghdr *)msg, n);
		}
	}
}

void
processrtmsg(struct rt_msghdr *rtm, int len)
{
        if (rtm->rtm_version != RTM_VERSION) {
                warnx("routing message version %d not understood",
                    rtm->rtm_version);
                return;
        }
        switch (rtm->rtm_type) {
	case RTM_RESOLVE:
		get_addr(((char *)rtm + rtm->rtm_hdrlen), rtm->rtm_addrs, RTA_GATEWAY);
		get_addr(((char *)rtm + rtm->rtm_hdrlen), rtm->rtm_addrs, RTA_DST);
		fprintf(stdout, "RTM_RESOLVE\n");
		break;
	case RTM_DELETE:
		get_addr(((char *)rtm + rtm->rtm_hdrlen), rtm->rtm_addrs, RTA_GATEWAY);
		get_addr(((char *)rtm + rtm->rtm_hdrlen), rtm->rtm_addrs, RTA_DST);
		fprintf(stdout, "RTM_DELETE\n");
		break;
	default:
		break;
	}
}

static inline struct sockaddr_dl *
satosdl(struct sockaddr *sa)
{
        return ((struct sockaddr_dl *)(sa));
}

void
get_addr(char *p, int addrs, int rt)
{
	char *t = p;
	struct sockaddr *sa = NULL;
	char hbuf[NI_MAXHOST];
	int error;

	if (addrs != 0) {
		addrs = addrs & rt;
		while (addrs) {
			addrs >>= 1;
			sa = (struct sockaddr *)t;
			ADVANCE(t, sa);
		}
		if (sa == NULL)
			return;

		switch(sa->sa_family) {
		case AF_LINK:
			printf("LL: %s, ", ether_ntoa((struct ether_addr *)LLADDR(satosdl(sa))));
			break;
		case AF_INET:
		case AF_INET6:
			error = getnameinfo(sa, sa->sa_len, hbuf, sizeof(hbuf), NULL, 0, NI_NUMERICHOST);
			if (error)
				printf("IP: error, ");
			else
				printf("IP: %s, ", hbuf);
			break;
		default:
               		err(1, "Unsupported AF");
			break;
		}
	}
}
