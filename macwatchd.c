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
#include <string.h>
#include <sys/sysctl.h>
#include <sys/queue.h>
#include <net/pfvar.h>
#include <fcntl.h>
#include <sys/ioctl.h>

enum {  PFRB_TABLES = 1, PFRB_TSTATS, PFRB_ADDRS, PFRB_ASTATS,
        PFRB_IFACES, PFRB_TRANS, PFRB_MAX };
struct pfr_buffer {
        int      pfrb_type;     /* type of content, see enum above */
        int      pfrb_size;     /* number of objects in buffer */
        int      pfrb_msize;    /* maximum number of objects in buffer */
        void    *pfrb_caddr;    /* malloc'ated memory area */
};

void		sighdlr(int);
__dead void	usage(void);
void		processrtmsg(struct rt_msghdr *, int);
struct macwatch	*get_addr(char *, int);
int		buf_grow(struct pfr_buffer *, int);
void		get_entries(void);
struct macwatch *find_entry(struct macwatch *);
void		print_list(void);
void		print_entry(struct macwatch *);
int		add_prefixes(struct pfr_buffer *);
int		main(int, char *[]);

volatile sig_atomic_t	 quit, reconfig;
struct rt_msghdr	*rtmsg;
struct ether_addr	*mac;
char			*pf_device = "/dev/pf";

LIST_HEAD(macwatch_head, macwatch) macwatch_h;

struct macwatch {
	LIST_ENTRY(macwatch)	entries;
	struct ether_addr	mac;
	struct sockaddr		sa;
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

        fprintf(stderr, "usage: %s [-d] [-m macaddress] [-p pfdev] -t tablename\n", __progname);
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
	struct macwatch *mw;
	struct pfr_table table;
	struct pfioc_table io;
	int		 dev = -1;

	memset(&table, 0, sizeof(struct pfr_table));

	while ((ch = getopt(argc, argv, "dm:p:t:")) != -1) {
		switch (ch) {
		case 'd':
			debug = 1;
			break;
		case 'm':
			mac = ether_aton(optarg);
			if (mac == NULL)
				errx(1, "invalid mac");
			break;
		case 'p':
			pf_device = optarg;
			break;
		case 't':
			if (strlen(optarg) >= PF_TABLE_NAME_SIZE ||
			    strlen(optarg) < 1)
				usage();
			if (strlcpy(table.pfrt_name, optarg, sizeof(table.pfrt_name)) >= sizeof(table.pfrt_name))
				errx(1, "pfctl_table: strlcpy");
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

/* Init */
	LIST_INIT(&macwatch_h);
	get_entries();
	print_list();

	struct pfr_buffer b;
	int size;

	memset(&b, 0, sizeof(struct pfr_buffer));
	memset(&io, 0, sizeof(struct pfioc_table));

	dev = open(pf_device, O_RDWR);
	if (dev == -1)
		err(1, "%s", pf_device);

	b.pfrb_type = PFRB_ADDRS;
	size = add_prefixes(&b);
	printf("%d", size);
        io.pfrio_flags = 0;
        io.pfrio_table = table;
        io.pfrio_buffer = b.pfrb_caddr;
        io.pfrio_esize = sizeof(struct pfr_addr);
        io.pfrio_size = size;
        if (ioctl(dev, DIOCRADDADDRS, &io))
                err(1, "DIOCRADDADDRS");

/* Main loop */
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
	print_list();
	if(!LIST_EMPTY(&macwatch_h)) {
		mw = LIST_FIRST(&macwatch_h);
		LIST_REMOVE(mw, entries);
		free(mw);
	}
	printf("Done!\n");
}

struct macwatch *
find_entry(struct macwatch *mw)
{
	struct macwatch *found;

	if (mw == NULL)
		return (NULL);

	LIST_FOREACH(found, &macwatch_h, entries) {
		if (!memcmp(&mw->mac, &found->mac, sizeof(struct ether_addr)) &&
		    !memcmp(&mw->sa, &found->sa, sizeof(struct sockaddr)))
			return (found);
	}
	return (NULL);
}

void
processrtmsg(struct rt_msghdr *rtm, int len)
{
	struct macwatch  *mw, *found;

        if (rtm->rtm_version != RTM_VERSION) {
                warnx("routing message version %d not understood",
                    rtm->rtm_version);
                return;
        }
        switch (rtm->rtm_type) {
	case RTM_RESOLVE:
		mw = get_addr(((char *)rtm + rtm->rtm_hdrlen), rtm->rtm_addrs);
		if (mw)
			LIST_INSERT_HEAD(&macwatch_h, mw, entries);
		quit = 1;
		break;
	case RTM_DELETE:
		mw = get_addr(((char *)rtm + rtm->rtm_hdrlen), rtm->rtm_addrs);
		if ((found = find_entry(mw))) {
			LIST_REMOVE(found, entries);
			free(mw);
		}
		break;
	default:
		break;
	}
}

void
print_entry(struct macwatch *mw)
{
	int error;
	char hbuf[NI_MAXHOST];

	if (mw == NULL)
		return;

	error = getnameinfo(&mw->sa, mw->sa.sa_len, hbuf, sizeof(hbuf), NULL, 0, NI_NUMERICHOST);
	if (error) {
		warnx("error print_list()\n");
		return;
	}
	printf("IP: %s, MAC: %s\n", hbuf, ether_ntoa(&mw->mac));
}

void
print_list(void)
{
	struct macwatch *mw;

	printf("In list:\n");
	LIST_FOREACH(mw, &macwatch_h, entries) {
		print_entry(mw);
	}
}

static inline struct sockaddr_dl *
satosdl(struct sockaddr *sa)
{
        return ((struct sockaddr_dl *)(sa));
}

struct macwatch *
get_addr(char *p, int addrs)
{
	char *t = p;
	struct sockaddr *sa;
	struct macwatch  *mw = NULL;
	struct ether_addr *ea;
	int lla, ipa;

	if (addrs != 0) {
		sa = NULL;
		lla = addrs & RTA_GATEWAY;
		while (lla) {
			lla >>= 1;
			sa = (struct sockaddr *)t;
			ADVANCE(t, sa);
		}
		if (sa == NULL || sa->sa_family != AF_LINK)
			return (NULL);

		ea = (struct ether_addr *)LLADDR(satosdl(sa));
		if (mac && !memcmp(ea, mac, sizeof(struct ether_addr)))
			printf("macmatch! ");

		sa = NULL;
		t = p;
		ipa = addrs & RTA_DST;
		while (ipa) {
			ipa >>= 1;
			sa = (struct sockaddr *)t;
			ADVANCE(t, sa);
		}
		if (sa == NULL || (sa->sa_family != AF_INET && sa->sa_family != AF_INET6))
			return (NULL);

		mw = malloc(sizeof(struct macwatch));
		if (mw == NULL) {
			printf("malloc()\n");
			return (mw);
		}

		memcpy(&mw->mac, ea, sizeof(struct ether_addr));
		switch (sa->sa_family) {
		case AF_INET:
			memcpy(&mw->sa, sa, sizeof(struct sockaddr_in));
			break;
		case AF_INET6:
			memcpy(&mw->sa, sa, sizeof(struct sockaddr_in6));
			break;
		default:
			warn("unsupported AF");
		}
	}
	return (mw);
}

void
get_entries(void)
{
	int			 mib[7];
        size_t			 needed;
        char			*lim, *buf = NULL, *next;
        struct rt_msghdr	*rtm;
	struct macwatch		*mw;

	memset(mib, 0, sizeof(mib));
	mib[0] = CTL_NET;
        mib[1] = PF_ROUTE;
        mib[2] = 0;
        mib[3] = AF_UNSPEC;
        mib[4] = NET_RT_FLAGS;
        mib[5] = RTF_LLINFO;
        while (1) {
                if (sysctl(mib, 7, NULL, &needed, NULL, 0) == -1)
                        err(1, "route-sysctl-estimate");
                if (needed == 0)
                        return;
                if ((buf = realloc(buf, needed)) == NULL)
                        err(1, "malloc");
                if (sysctl(mib, 7, buf, &needed, NULL, 0) == -1) {
                        if (errno == ENOMEM)
                                continue;
                        err(1, "actual retrieval of routing table");
                }
                lim = buf + needed;
                break;
        }
	
        for (next = buf; next < lim; next += rtm->rtm_msglen) {
                rtm = (struct rt_msghdr *)next;
                if (rtm->rtm_version != RTM_VERSION)
                        continue;
		mw = get_addr(((char *)rtm + rtm->rtm_hdrlen), rtm->rtm_addrs);
		if (mw)
			LIST_INSERT_HEAD(&macwatch_h, mw, entries);
        }
        free(buf);
}

int
add_prefixes(struct pfr_buffer *b)
{
	struct pfr_addr	 addr;
	struct macwatch *mw;
	struct sockaddr_in sa;
	struct sockaddr_in6 sa6;

        LIST_FOREACH(mw, &macwatch_h, entries) {
		memset(&addr, 0, sizeof(struct pfr_addr));
		addr.pfra_af = mw->sa.sa_family;

		switch (addr.pfra_af) {
		case AF_INET:
			memcpy(&sa, &mw->sa, sizeof(struct sockaddr_in));
			addr.pfra_ip4addr.s_addr = sa.sin_addr.s_addr;
			addr.pfra_net = 32;
			break;
		case AF_INET6:
			memcpy(&sa6, &mw->sa, sizeof(struct sockaddr_in6));
			memcpy(&addr.pfra_ip6addr, &sa6.sin6_addr.s6_addr, sizeof(struct in6_addr));
			addr.pfra_net = 128;
			break;
		default:
			errx(1, "Unsupported AF");
		}

		if (b->pfrb_msize == b->pfrb_size)
			if (buf_grow(b, 0))
				return (-1);

		memcpy(((caddr_t)b->pfrb_caddr) + sizeof(struct pfr_addr) * b->pfrb_size, &addr, sizeof(struct pfr_addr));
		b->pfrb_size++;
        }
	return (b->pfrb_size);
}

int
buf_grow(struct pfr_buffer *b, int minsize)
{
        caddr_t p;
        size_t bs;

        if (b == NULL) {
                errno = EINVAL;
                return (-1);
        }
        if (minsize != 0 && minsize <= b->pfrb_msize)
                return (0);
        bs = sizeof(struct pfr_addr);
        if (!b->pfrb_msize) {
                if (minsize < 10)
                        minsize = 10;
        }
        if (minsize == 0)
                minsize = b->pfrb_msize * 2;
        p = reallocarray(b->pfrb_caddr, minsize, bs);
        if (p == NULL)
                return (-1);
        bzero(p + b->pfrb_msize * bs, (minsize - b->pfrb_msize) * bs);
        b->pfrb_caddr = p;
        b->pfrb_msize = minsize;
        return (0);
}

