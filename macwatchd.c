#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
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
#include <net/if_types.h>
#include <net/if_dl.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/queue.h>
#include <net/pfvar.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include "log.h"

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
struct macwatch	*fill_macwatch(char *, int);
int		buf_grow(struct pfr_buffer *, int);
void		get_entries(void);
int		extract_addr(char *, int, struct sockaddr **, struct ether_addr **);
struct macwatch *find_entrybyip(struct sockaddr *);
struct macwatch *find_entrybymac(struct ether_addr *);
void		print_list(void);
void		print_entry(struct macwatch *);
int		insert_addr(struct pfr_buffer *, struct sockaddr *);
int		remove_addr(struct pfr_buffer *, struct sockaddr *);
int		table_insert(struct pfr_table, struct pfr_buffer);
int		table_remove(struct pfr_table, struct pfr_buffer);
struct ether_addr *get_etheraddr(struct sockaddr *);
const char	*log_addr(struct sockaddr *);
int		main(int, char *[]);

volatile sig_atomic_t	 quit, reconfig;
struct rt_msghdr	*rtmsg;
struct ether_addr	*mac;
struct			 pfr_table table;
char			*pf_device = "/dev/pf";

LIST_HEAD(macwatch_head, macwatch) macwatch_h;

struct macwatch {
	LIST_ENTRY(macwatch)	entries;
	int			intable;
	struct ether_addr	mac;
	struct pfr_buffer	addrlist;
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
	int		s, f;
	int		n;
	char		msg[2048];
	struct pollfd	pfd[2];
	struct macwatch *mw;

        log_init(1, LOG_DAEMON);        /* log to stderr until daemonized */
        log_setverbose(1);

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

        log_init(debug, LOG_DAEMON);
        log_setverbose(debug);

	if (!debug)
		daemon(1, 0);

	log_info("startup");

	signal(SIGTERM, sighdlr);
	signal(SIGINT, sighdlr);
	signal(SIGPIPE, SIG_IGN);

/* Init */
	LIST_INIT(&macwatch_h);

	get_entries();

/* Control socket */

	mkfifo(SOCKET_NAME, S_IRUSR|S_IWUSR);
	chmod(SOCKET_NAME, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);
	f = open(SOCKET_NAME, O_RDWR | O_NONBLOCK, 0);
	pfd[0].fd = f;
	pfd[0].events = POLLIN;

/* Main loop */
        s = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC);
        if (s == -1)
                fatal("socket");

	filter = ROUTE_FILTER(RTM_RESOLVE) | ROUTE_FILTER(RTM_DELETE) | ROUTE_FILTER(RTM_ADD);
	if (setsockopt(s, AF_ROUTE, ROUTE_MSGFILTER, &filter,
	    sizeof(filter)) == -1)
               	fatal("setsockopt(ROUTE_MSGFILTER)");

	pfd[1].fd = s;
	pfd[1].events = POLLIN;

	while (quit == 0) {
		n = poll(pfd, 2, 60 * 1000);
		if (n == -1)
			fatal("poll");
		if ((pfd[1].revents & (POLLERR|POLLNVAL)))
			fatalx("bad fd %d", pfd[1].fd);
		if ((pfd[1].revents & (POLLIN|POLLHUP))) {
			if ((n = read(s, msg, sizeof(msg))) == -1) {
				if (errno == EINTR)
					continue;
				fatal("read");
			}
			processrtmsg((struct rt_msghdr *)msg, n);
		}

		if ((pfd[0].revents & (POLLERR|POLLNVAL)))
			fatalx("bad fd %d", pfd[0].fd);
		if ((pfd[0].revents & (POLLIN|POLLHUP))) {
			if ((n = read(f, msg, sizeof(msg))) == -1) {
				if (errno == EINTR)
					continue;
				fatal("read");
			}
			char arg[49];
			struct addrinfo hints, *res;
			int add;

			add = 0;
			if (sscanf(msg, "a %48s", arg) == 1)
				add = 1;
			else if (sscanf(msg, "d %48s", arg) == 1)
				add = -1;

			if (add) {
				memset(&hints, 0, sizeof(hints));
				hints.ai_family = AF_UNSPEC;
				hints.ai_flags = AI_NUMERICHOST;
				hints.ai_socktype = SOCK_DGRAM;
				if (getaddrinfo(arg, "0", &hints, &res) != 0)
					log_warnx("%s: bad value", arg);
				if ((mw = find_entrybyip(res->ai_addr)) != NULL) {
					if (add == 1)
						mw->intable += table_insert(table, mw->addrlist);
					else
						mw->intable -= table_remove(table, mw->addrlist);
				}
				freeaddrinfo(res);
			} else
				print_list();
	
		}
		
	}
	if(!LIST_EMPTY(&macwatch_h)) {
		mw = LIST_FIRST(&macwatch_h);
		LIST_REMOVE(mw, entries);
		table_remove(table, mw->addrlist);
		free(mw->addrlist.pfrb_caddr);
		free(mw);
	}

	log_info("terminating");
	return (0);
}

int
table_insert(struct pfr_table tbl, struct pfr_buffer pfrb)
{
	struct pfioc_table io;
	int		 dev = -1;

	dev = open(pf_device, O_RDWR);
	if (dev == -1)
		err(1, "%s", pf_device);

	memset(&io, 0, sizeof(struct pfioc_table));
        io.pfrio_flags = 0;
        io.pfrio_table = tbl;
        io.pfrio_buffer = pfrb.pfrb_caddr;
        io.pfrio_esize = sizeof(struct pfr_addr);
        io.pfrio_size = pfrb.pfrb_size;
        if (ioctl(dev, DIOCRADDADDRS, &io))
                err(1, "DIOCRADDADDRS");

	close(dev);
	return (io.pfrio_nadd);
}

int
table_remove(struct pfr_table tbl, struct pfr_buffer pfrb)
{
	struct pfioc_table io;
	int		 dev = -1;

	dev = open(pf_device, O_RDWR);
	if (dev == -1)
		err(1, "%s", pf_device);

	memset(&io, 0, sizeof(struct pfioc_table));
        io.pfrio_flags = 0;
        io.pfrio_table = tbl;
        io.pfrio_buffer = pfrb.pfrb_caddr;
        io.pfrio_esize = sizeof(struct pfr_addr);
        io.pfrio_size = pfrb.pfrb_size;
        if (ioctl(dev, DIOCRDELADDRS, &io))
                err(1, "DIOCRDELADDRS");

	close(dev);
	return (io.pfrio_ndel);
}

struct macwatch *
find_entrybymac(struct ether_addr *ea)
{
	struct macwatch *found;

	if (ea == NULL)
		return (NULL);

	LIST_FOREACH(found, &macwatch_h, entries) {
		if (memcmp(ea, &found->mac, sizeof(struct ether_addr)) == 0)
			return (found);
	}
	return (NULL);
}

void
processrtmsg(struct rt_msghdr *rtm, int len)
{
	struct sockaddr		*sa;
	struct macwatch		*mw = NULL, *previous_mw;
	struct ether_addr	*ea;
	int			 n;
	struct pfr_buffer	 buf;

        if (rtm->rtm_version != RTM_VERSION) {
                log_warnx("routing message version %d not understood",
                    rtm->rtm_version);
                return;
        }

        if (extract_addr(((char *)rtm + rtm->rtm_hdrlen), rtm->rtm_addrs, &sa, &ea))
                return;

        mw = find_entrybymac(ea);
        previous_mw = mw;

        switch (rtm->rtm_type) {
	case RTM_ADD:
		get_entries();
		mw = find_entrybyip(sa);
        	previous_mw = mw;
		if (mw == NULL)
			break;
	case RTM_RESOLVE:
		if (mw == NULL) {
			mw = malloc(sizeof(struct macwatch));
			if (mw == NULL)
				err(1, "%s: ", __func__);
			memset(mw, 0, sizeof(struct macwatch));
			memcpy(&mw->mac, ea, sizeof(struct ether_addr));
		}
		if (insert_addr(&mw->addrlist, sa))
			break;
		log_info("RESOLVE: %s as %s", log_addr(sa), ether_ntoa(&mw->mac));
		if (previous_mw)
                	LIST_REMOVE(previous_mw, entries);
		LIST_INSERT_HEAD(&macwatch_h, mw, entries);
		if (mw->intable)
			mw->intable += table_insert(table, mw->addrlist);
		break;
	case RTM_DELETE:
		if (mw == NULL)	/* Don't try to remove from non-existent list */
			break;		
               	LIST_REMOVE(previous_mw, entries);
		n = remove_addr(&mw->addrlist, sa);
		log_info("DELETE: %s as %s", log_addr(sa), ether_ntoa(&mw->mac));
		memset(&buf, 0, sizeof(struct pfr_buffer));
		if (insert_addr(&buf, sa)) {
			errx(1, "%s: insert_addr() failed", __func__);
		}
		mw->intable -= table_remove(table, buf);
		free(buf.pfrb_caddr);
		if (mw->addrlist.pfrb_caddr)
			LIST_INSERT_HEAD(&macwatch_h, mw, entries);
		else
			free(mw);
		break;
	default:
		errx(1, "%s: Unsupported msg", __func__);
	}
}

void
print_entry(struct macwatch *mw)
{
	int 			 i;
	struct pfr_addr		*pfra;
	static char		 buf[48];

	if (mw == NULL)
		return;

	printf("MAC: %s :\n", ether_ntoa(&mw->mac));

	pfra = (struct pfr_addr *)mw->addrlist.pfrb_caddr;
	for (i = 0; i < mw->addrlist.pfrb_size; i++) {
		pfra = (struct pfr_addr *)(((caddr_t)mw->addrlist.pfrb_caddr) + sizeof(struct pfr_addr) * i);
		switch (pfra->pfra_af) {
		case AF_INET:
			printf("-> IPv4: %s\n", inet_ntop(pfra->pfra_af, &pfra->pfra_ip4addr, buf, sizeof(buf)));
			break;
		case AF_INET6:
			printf("-> IPv6: %s\n", inet_ntop(pfra->pfra_af, &pfra->pfra_ip6addr, buf, sizeof(buf)));
			break;
		default:
			errx(1, "unsupported AF");
		}
	}
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

struct macwatch *
find_entrybyip(struct sockaddr *sa)
{
	struct macwatch		*mw;
	int			 i;
	struct pfr_addr		 addr;
	struct sockaddr_in	 sa4;
	struct sockaddr_in6	 sa6;
	struct pfr_addr		*pfra;

	if (sa == NULL)
		return (NULL);

	memset(&addr, 0, sizeof(struct pfr_addr));
	addr.pfra_af = sa->sa_family;
	switch (addr.pfra_af) {
	case AF_INET:
		memcpy(&sa4, sa, sizeof(struct sockaddr_in));
		addr.pfra_ip4addr.s_addr = sa4.sin_addr.s_addr;
		addr.pfra_net = 32;
		break;
	case AF_INET6:
		memcpy(&sa6, sa, sizeof(struct sockaddr_in6));
		memcpy(&addr.pfra_ip6addr, &sa6.sin6_addr.s6_addr, sizeof(struct in6_addr));
		addr.pfra_net = 128;
		break;
	default:
		errx(1, "%s: Unsupported AF", __func__);
	}

	LIST_FOREACH(mw, &macwatch_h, entries) {
		for (i = 0; i < mw->addrlist.pfrb_size; i++) {
			pfra = (struct pfr_addr *)(((caddr_t)mw->addrlist.pfrb_caddr) + sizeof(struct pfr_addr) * i);
			if (pfra->pfra_af == addr.pfra_af)
				if(memcmp(pfra, &addr, sizeof(struct pfr_addr)) == 0)
					return (mw);
		}
	}
	return (NULL);
}

static inline struct sockaddr_dl *
satosdl(struct sockaddr *sa)
{
        return ((struct sockaddr_dl *)(sa));
}

int
extract_addr(char *p, int addrs, struct sockaddr **s, struct ether_addr **e)
{
	int			 search;
	char			*t = p;
	struct sockaddr		*sa;
	struct ether_addr	*ea, nullea;

	if (addrs == 0)
		return (-1);

	sa = NULL;
	search = addrs & RTA_GATEWAY;
	while (search) {
		search >>= 1;
		sa = (struct sockaddr *)t;
		ADVANCE(t, sa);
	}
	if (sa == NULL || sa->sa_family != AF_LINK)
		return (-1);

	ea = (struct ether_addr *)LLADDR(satosdl(sa));
	memset(&nullea, 0, sizeof(struct ether_addr));
	if (memcmp(ea, &nullea,  sizeof(struct ether_addr)))
		*e = ea;
	else
		*e = NULL;

	sa = NULL;
	t = p;
	search = addrs & RTA_DST;
	while (search) {
		search >>= 1;
		sa = (struct sockaddr *)t;
		ADVANCE(t, sa);
	}
	if (sa == NULL || (sa->sa_family != AF_INET && sa->sa_family != AF_INET6))
		return (-1);

	*s = sa;
	return (0);
}

struct macwatch *
fill_macwatch(char *p, int addrs)
{
	struct sockaddr *sa;
	struct macwatch  *mw = NULL, *previous_mw;
	struct ether_addr *ea;

	if(extract_addr(p, addrs, &sa, &ea))
		return (NULL);

	if (ea == NULL)
		return (NULL);

	mw = find_entrybymac(ea);
	previous_mw = mw;
	if (mw == NULL) {
		mw = malloc(sizeof(struct macwatch));
		if (mw == NULL) {
			log_warnx("%s:malloc()\n", __func__);
			return (NULL);
		}
		memset(mw, 0, sizeof(struct macwatch));
		memcpy(&mw->mac, ea, sizeof(struct ether_addr));
	}

	if (insert_addr(&mw->addrlist, sa)) {
		return (NULL);
	}
	log_info("ADD: %s as %s", log_addr(sa), ether_ntoa(&mw->mac));

	if (previous_mw)
		LIST_REMOVE(previous_mw, entries);

	return (mw);
}

int
insert_addr(struct pfr_buffer *b, struct sockaddr *sa)
{
	int			i, size;
	struct pfr_addr		addr;
	struct sockaddr_in	sa4;
	struct sockaddr_in6	sa6;
	struct pfr_addr		*pfra;

	memset(&addr, 0, sizeof(struct pfr_addr));
	addr.pfra_af = sa->sa_family;
	switch (addr.pfra_af) {
	case AF_INET:
		memcpy(&sa4, sa, sizeof(struct sockaddr_in));
		addr.pfra_ip4addr.s_addr = sa4.sin_addr.s_addr;
		addr.pfra_net = 32;
		break;
	case AF_INET6:
		memcpy(&sa6, sa, sizeof(struct sockaddr_in6));
		memcpy(&addr.pfra_ip6addr, &sa6.sin6_addr.s6_addr, sizeof(struct in6_addr));
		addr.pfra_net = 128;
		break;
	default:
		errx(1, "%s: Unsupported AF", __func__);
	}

	if (b->pfrb_msize == b->pfrb_size)
		if (buf_grow(b, 0))
			return (-1);

	size = b->pfrb_size;
	for (i = 0; i < size; i++) {
		pfra = (struct pfr_addr *)(((caddr_t)b->pfrb_caddr) + sizeof(struct pfr_addr) * i);
		if (pfra->pfra_af == addr.pfra_af)
			if(memcmp(pfra, &addr, sizeof(struct pfr_addr)) == 0)
				return (0); /* do not insert duplicates */
	}

	memcpy(((caddr_t)b->pfrb_caddr) + sizeof(struct pfr_addr) * b->pfrb_size, &addr, sizeof(struct pfr_addr));
	b->pfrb_size++;

	return (0);
}

int
remove_addr(struct pfr_buffer *b, struct sockaddr *sa)
{
	int			 i, size;
	struct pfr_addr		 addr;
	struct sockaddr_in	 sa4;
	struct sockaddr_in6	 sa6;
	struct pfr_addr		*pfra;

	memset(&addr, 0, sizeof(struct pfr_addr));
	addr.pfra_af = sa->sa_family;
	switch (addr.pfra_af) {
	case AF_INET:
		memcpy(&sa4, sa, sizeof(struct sockaddr_in));
		addr.pfra_ip4addr.s_addr = sa4.sin_addr.s_addr;
		addr.pfra_net = 32;
		break;
	case AF_INET6:
		memcpy(&sa6, sa, sizeof(struct sockaddr_in6));
		memcpy(&addr.pfra_ip6addr, &sa6.sin6_addr.s6_addr, sizeof(struct in6_addr));
		addr.pfra_net = 128;
		break;
	default:
		errx(1, "%s: Unsupported AF", __func__);
	}

	size = b->pfrb_size;
	for (i = 0; i < size; i++) {
		pfra = (struct pfr_addr *)(((caddr_t)b->pfrb_caddr) + sizeof(struct pfr_addr) * i);
		if (pfra->pfra_af == addr.pfra_af) {
			if(memcmp(pfra, &addr, sizeof(struct pfr_addr)) == 0) {
				memmove(pfra, ((caddr_t)pfra + sizeof(struct pfr_addr)), sizeof(struct pfr_addr)*(size-i-1));
				b->pfrb_size--;
			}
		}
	}
	if (b->pfrb_size == 0) {
		free(b->pfrb_caddr);
		b->pfrb_msize = 0;
		b->pfrb_caddr = NULL;
	}

	return (b->pfrb_size);
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
		mw = fill_macwatch(((char *)rtm + rtm->rtm_hdrlen), rtm->rtm_addrs);
		if (mw) {
			LIST_INSERT_HEAD(&macwatch_h, mw, entries);
		}
        }
        free(buf);
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

const char *
log_addr(struct sockaddr *sa)
{
	static char		buf[48];
	struct sockaddr_in	sa4;
	struct sockaddr_in6	sa6;

	memset(buf, 0, sizeof(buf));

	switch (sa->sa_family) {
	case AF_INET:
		memcpy(&sa4, sa, sizeof(struct sockaddr_in));
		inet_ntop(AF_INET, &sa4.sin_addr, buf, sizeof(buf));
		return (buf);
	case AF_INET6:
		memcpy(&sa6, sa, sizeof(struct sockaddr_in6));
		inet_ntop(AF_INET6, &sa6.sin6_addr, buf, sizeof(buf));
		return (buf);
	default:
		break;
	}
	return ("???");
}
