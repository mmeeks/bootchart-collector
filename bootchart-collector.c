/* bootchart-collector
 *
 * Copyright © 2009 Canonical Ltd.
 * Author: Scott James Remnant <scott@netsplit.com>.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Copyright 2009 Novell, Inc.
 * 
 * URK ! - GPLv2 - code from Linux kernel.
 */

/* getdelays.c
 *
 * Utility to get per-pid and per-tgid delay accounting statistics
 * Also illustrates usage of the taskstats interface
 *
 * Copyright (C) Shailabh Nagar, IBM Corp. 2005
 * Copyright (C) Balbir Singh, IBM Corp. 2006
 * Copyright (c) Jay Lan, SGI. 2006
 */

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/resource.h>
#include <sys/socket.h>

#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <assert.h>
#include <dirent.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include <linux/genetlink.h>
#include <linux/taskstats.h>
#include <linux/cgroupstats.h>

#define BUFSIZE 524288

typedef struct {
	pid_t pid;
	pid_t ppid;
	__u64 time_total;
} PidEntry;

static PidEntry *get_pid_entry (pid_t pid)
{
	static PidEntry *pids = NULL;
	static pid_t     pids_size = 0;

	if (pid >= pids_size) {
		pids_size = pid + 512;
		pids = realloc (pids, sizeof (PidEntry) * pids_size);
	}
	return pids + pid;
}

int append_buf (const char *str, size_t len,
		int outfd, char *outbuf, size_t *outlen);
int copy_buf (int fd, int outfd, char *outbuf, size_t *outlen);
int flush_buf (int outfd, char *outbuf, size_t *outlen);

int read_file (int fd, const char *uptime, size_t uptimelen,
	       int outfd, char *outbuf, size_t *outlen);
int read_proc (DIR *proc, const char *uptime, size_t uptimelen,
	       int outfd, char *outbuf, size_t *outlen);
int read_proc (DIR *proc, const char *uptime, size_t uptimelen,
	       int outfd, char *outbuf, size_t *outlen);

unsigned long get_uptime (int fd);
void sig_handler (int signum);


int
append_buf (const char *str,
	    size_t      len,
	    int         outfd,
	    char       *outbuf,
	    size_t     *outlen)
{
	assert (len <= BUFSIZE);

	if (*outlen + len > BUFSIZE)
		if (flush_buf (outfd, outbuf, outlen) < 0)
			return -1;

	memcpy (outbuf + *outlen, str, len);
	*outlen += len;

	return 0;
}

int
copy_buf (int     fd,
	  int     outfd,
	  char   *outbuf,
	  size_t *outlen)
{
	for (;;) {
		ssize_t len;

		if (*outlen == BUFSIZE)
			if (flush_buf (outfd, outbuf, outlen) < 0)
				return -1;

		len = read (fd, outbuf + *outlen, BUFSIZE - *outlen);
		if (len < 0) {
			perror ("read");
			return -1;
		} else if (len == 0)
			break;

		*outlen += len;
	}

	return 0;
}

int
flush_buf (int     outfd,
	   char   *outbuf,
	   size_t *outlen)
{
	size_t writelen = 0;

	while (writelen < *outlen) {
		ssize_t len;

		len = write (outfd, outbuf + writelen, *outlen - writelen);
		if (len < 0) {
			perror ("write");
			exit (1);
		}

		writelen += len;
	}

	*outlen = 0;

	return 0;
}


int
read_file (int         fd,
	   const char *uptime,
	   size_t      uptimelen,
	   int         outfd,
	   char       *outbuf,
	   size_t     *outlen)
{
	lseek (fd, SEEK_SET, 0);

	if (append_buf (uptime, uptimelen, outfd, outbuf, outlen) < 0)
		return -1;

	if (copy_buf (fd, outfd, outbuf, outlen) < 0)
		return -1;

	if (append_buf ("\n", 1, outfd, outbuf, outlen) < 0)
		return -1;

	return 0;
}

/* Netlink socket-set bits */
static int   netlink_socket = -1;
static __u16 netlink_taskstats_id;

#define GENLMSG_DATA(glh)	((void *)(NLMSG_DATA(glh) + GENL_HDRLEN))
#define GENLMSG_PAYLOAD(glh)	(NLMSG_PAYLOAD(glh, 0) - GENL_HDRLEN)
#define NLA_DATA(na)		((void *)((char*)(na) + NLA_HDRLEN))
#define NLA_PAYLOAD(len)	(len - NLA_HDRLEN)

/* Maximum size of response requested or message sent */
#define MAX_MSG_SIZE	1024

struct msgtemplate {
	struct nlmsghdr n;
	struct genlmsghdr g;
	char buf[MAX_MSG_SIZE];
};

extern int dbg;
#define PRINTF(fmt, arg...) {			\
    fprintf(stderr, fmt, ##arg);			\
	}

static int send_cmd(int sd, __u16 nlmsg_type, __u32 nlmsg_pid,
	     __u8 genl_cmd, __u16 nla_type,
	     void *nla_data, int nla_len)
{
	struct nlattr *na;
	struct sockaddr_nl nladdr;
	int r, buflen;
	char *buf;

	struct msgtemplate msg;

	msg.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	msg.n.nlmsg_type = nlmsg_type;
	msg.n.nlmsg_flags = NLM_F_REQUEST;
	msg.n.nlmsg_seq = 0;
	msg.n.nlmsg_pid = nlmsg_pid;
	msg.g.cmd = genl_cmd;
	msg.g.version = 0x1;
	na = (struct nlattr *) GENLMSG_DATA(&msg);
	na->nla_type = nla_type;
	na->nla_len = nla_len + 1 + NLA_HDRLEN;
	memcpy(NLA_DATA(na), nla_data, nla_len);
	msg.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	buf = (char *) &msg;
	buflen = msg.n.nlmsg_len ;
	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	while ((r = sendto(sd, buf, buflen, 0, (struct sockaddr *) &nladdr,
			   sizeof(nladdr))) < buflen) {
		if (r > 0) {
			buf += r;
			buflen -= r;
		} else if (errno != EAGAIN)
			return -1;
	}
	return 0;
}

static struct taskstats *
wait_taskstats (void)
{
  struct msgtemplate msg;
  int rep_len;

  for (;;) {

    while ((rep_len = recv(netlink_socket, &msg, sizeof(msg), 0)) < 0 && errno == EINTR);
  
    if (msg.n.nlmsg_type == NLMSG_ERROR ||
	!NLMSG_OK((&msg.n), rep_len)) {
      /* process died before we got to it or somesuch */
      /* struct nlmsgerr *err = NLMSG_DATA(&msg);
	 fprintf (stderr, "fatal reply error,  errno %d\n", err->error); */
      return NULL;
    }
  
    int rep_len = GENLMSG_PAYLOAD(&msg.n);
    struct nlattr *na = (struct nlattr *) GENLMSG_DATA(&msg);
    int len = 0;
  
    while (len < rep_len) {
      len += NLA_ALIGN(na->nla_len);
      switch (na->nla_type) {
      case TASKSTATS_TYPE_AGGR_PID:
	{
	  int aggr_len = NLA_PAYLOAD(na->nla_len);
	  int len2 = 0;

	  /* For nested attributes, na follows */
	  na = (struct nlattr *) NLA_DATA(na);

	  /* find the record we care about */
	  while (na->nla_type != TASKSTATS_TYPE_STATS) {
	    len2 += NLA_ALIGN(na->nla_len);

	    if (len2 >= aggr_len)
	      goto next_attr;
	    na = (struct nlattr *) ((char *) na + len2);
	  }
	  return (struct taskstats *) NLA_DATA(na);
	}
      }
    next_attr:
      na = (struct nlattr *) (GENLMSG_DATA(&msg) + len);
    }
  }
}

/*
 * Linux exports one set of quite good data in:
 *   /proc/./stat: linux/fs/proc/array.c (do_task_stat)
 * and another high-res (but different) set of data in:
 *   linux/kernel/tsacct.c
 *   linux/kernel/delayacct.c // needs delay accounting enabled
 */
int
read_taskstat (DIR        *proc,
	       const char *uptime,
	       size_t      uptimelen,
	       int         outfd,
	       char       *outbuf,
	       size_t     *outlen)
{
	struct dirent *ent;

	rewinddir (proc);

	if (append_buf (uptime, uptimelen, outfd, outbuf, outlen) < 0)
		return -1;

	/* for each pid */
	while ((ent = readdir (proc)) != NULL) {
		__u32 pid;
		struct taskstats *ts;
		int output_len;
		char output_line[1024];
		PidEntry *entry;
		__u64 time_total;

		if (!isdigit (ent->d_name[0]))
			continue;
		pid = atoi (ent->d_name);

		/* set_pid */
		int rc = send_cmd (netlink_socket, netlink_taskstats_id, 0,
				   TASKSTATS_CMD_GET, TASKSTATS_CMD_ATTR_PID,
				   &pid, sizeof(__u32));
		if (rc < 0)
			continue;

		/* get reply */
		ts = wait_taskstats ();
		    
		if (!ts)
		  continue;

		if (ts->ac_pid != pid) {
		  fprintf (stderr, "Serious error got data for wrong pid: %d %d\n",
			   (int)ts->ac_pid, (int)pid);
		  continue;
		}

		/* reduce the amount of parsing we have to do later */
		entry = get_pid_entry (ts->ac_pid);
		time_total = (ts->cpu_run_real_total + ts->blkio_delay_total +
			      ts->swapin_delay_total);
		if (entry->time_total == time_total && entry->ppid == ts->ac_ppid)
		  continue;
		entry->time_total = time_total;

		output_len = snprintf (output_line, 1024, "%d %d %s %lld %lld %lld\n",
				       ts->ac_pid, ts->ac_ppid, ts->ac_comm,
				       (long long)ts->cpu_run_real_total,
				       (long long)ts->blkio_delay_total,
				       (long long)ts->swapin_delay_total);
		if (output_len < 0)
		  continue;

//		fprintf (stderr, "%s", output_line);
		append_buf (output_line, output_len, outfd, outbuf, outlen);

		// FIXME - can we get better stats on what is waiting for what ?
		// 'blkio_count / blkio_delay_total' ... [etc.]
		// 'delay waiting for CPU while runnable' ... [!] fun :-)
		
		/* The data we get from /proc is: */
		/*
		  opid, cmd, state, ppid = float(tokens[0]), ' '.join(tokens[1:2+offset]), tokens[2+offset], int(tokens[3+offset])
		  userCpu, sysCpu, stime= int(tokens[13+offset]), int(tokens[14+offset]), int(tokens[21+offset]) */
		
		/* opid - our pid - ac_pid easy */
		/* cmd - easy */
		/* synthetic state ? ... - can we get something better ? */
		/* 'state' - 'S' or ... */
			/* instead we really want the I/O delay rendered I think */
			/* Grief - how reliable & rapidly updated is the "state" information ? */
//				+ ho hum ! + - the big flaw ?
		/* ppid - parent pid - ac_ppid easy */
		/* userCpu, sysCPU - we can only get the sum of these: cpu_run_real_total in ns */
			/* though we could - approximate this with ac_utime / ac_stime in 'usec' */
			/* just output 0 for sysCPU ? */
		/* 'stime' - nothing doing ... - no start time data here ... */
		

	}
	append_buf ("\n", 1, outfd, outbuf, outlen);
	return 0;
}
		
int
read_proc (DIR        *proc,
	   const char *uptime,
	   size_t      uptimelen,
	   int         outfd,
	   char       *outbuf,
	   size_t     *outlen)
{
	struct dirent *ent;

	rewinddir (proc);

	if (append_buf (uptime, uptimelen, outfd, outbuf, outlen) < 0)
		return -1;

	while ((ent = readdir (proc)) != NULL) {
		char filename[PATH_MAX];
		int  fd;

		if ((ent->d_name[0] < '0') || (ent->d_name[0] > '9'))
			continue;

		sprintf (filename, "/proc/%s/stat", ent->d_name);

		fd = open (filename, O_RDONLY);
		if (fd < 0)
			continue;

		if (copy_buf (fd, outfd, outbuf, outlen) < 0)
			;

		if (close (fd) < 0)
			continue;
	}

	if (append_buf ("\n", 1, outfd, outbuf, outlen) < 0)
		return -1;

	return 0;
}


unsigned long
get_uptime (int fd)
{
	char          buf[80];
	ssize_t       len;
	unsigned long u1, u2;

	lseek (fd, SEEK_SET, 0);

	len = read (fd, buf, sizeof buf);
	if (len < 0) {
		perror ("read");
		return 0;
	}

	buf[len] = '\0';

	if (sscanf (buf, "%lu.%lu", &u1, &u2) != 2) {
		perror ("sscanf");
		return 0;
	}

	return u1 * 100 + u2;
}


void
sig_handler (int signum)
{
}

/*
 * Probe the controller in genetlink to find the family id
 * for the TASKSTATS family
 */
static int get_family_id(int sd)
{
	struct {
		struct nlmsghdr n;
		struct genlmsghdr g;
		char buf[256];
	} ans;

	int id = 0, rc;
	struct nlattr *na;
	int rep_len;

        char name[100];
	strcpy(name, TASKSTATS_GENL_NAME);
	rc = send_cmd (sd, GENL_ID_CTRL, getpid(), CTRL_CMD_GETFAMILY,
			CTRL_ATTR_FAMILY_NAME, (void *)name,
			strlen(TASKSTATS_GENL_NAME)+1);

	rep_len = recv(sd, &ans, sizeof(ans), 0);
	if (ans.n.nlmsg_type == NLMSG_ERROR ||
	    (rep_len < 0) || !NLMSG_OK((&ans.n), rep_len))
		return 0;

	na = (struct nlattr *) GENLMSG_DATA(&ans);
	na = (struct nlattr *) ((char *) na + NLA_ALIGN(na->nla_len));
	if (na->nla_type == CTRL_ATTR_FAMILY_ID) {
		id = *(__u16 *) NLA_DATA(na);
	}
	return id;
}

int
init_taskstat (void)
{
	struct sockaddr_nl addr;

	netlink_socket = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (netlink_socket < 0)
		goto error;

	memset (&addr, 0, sizeof (addr));
	addr.nl_family = AF_NETLINK;

	if (bind (netlink_socket, (struct sockaddr *) &addr, sizeof (addr)) < 0)
		goto error;

	netlink_taskstats_id = get_family_id (netlink_socket);

	return 1;
error:
	if (netlink_socket >= 0)
		close (netlink_socket);

	return 0;
}

int
main (int   argc,
      char *argv[])
{
	struct sigaction  act;
	sigset_t          mask, oldmask;
	struct rlimit     rlim;
	struct timespec   timeout;
	const char       *output_dir = ".";
	char              filename[PATH_MAX];
	int               sfd, dfd, ufd;
	DIR              *proc;
	int               statfd, diskfd, procfd = -1, taskfd = -1;
	char              statbuf[BUFSIZE], diskbuf[BUFSIZE], procbuf[BUFSIZE], taskbuf[BUFSIZE];
	size_t            statlen = 0, disklen = 0, proclen = 0, tasklen = 0;
	unsigned long     reltime = 0;
	int               arg = 1, rel = 0;
	int		  use_taskstat;

	if ((argc > arg) && (! strcmp (argv[arg], "-r"))) {
		rel = 1;
		arg++;
	}

	if (argc <= arg) {
		fprintf (stderr, "Usage: %s [-r] HZ [DIR]\n", argv[0]);
		exit (1);
	}

	if (argc > arg) {
		unsigned long  hz;
		char          *endptr;

		hz = strtoul (argv[arg], &endptr, 10);
		if (*endptr) {
			fprintf (stderr, "%s: HZ not an integer\n", argv[0]);
			exit (1);
		}

		if (hz > 1) {
			timeout.tv_sec = 0;
			timeout.tv_nsec = 1000000000 / hz;
		} else {
			timeout.tv_sec = 1;
			timeout.tv_nsec = 0;
		}

		arg++;
	}

	if (argc > arg) {
		output_dir = argv[arg];
		arg++;
	}


	sigemptyset (&mask);
	sigaddset (&mask, SIGTERM);
	sigaddset (&mask, SIGINT);

	if (sigprocmask (SIG_BLOCK, &mask, &oldmask) < 0) {
		perror ("sigprocmask");
		exit (1);
	}

	act.sa_handler = sig_handler;
	act.sa_flags = 0;
	sigemptyset (&act.sa_mask);

	if (sigaction (SIGTERM, &act, NULL) < 0) {
		perror ("sigaction SIGTERM");
		exit (1);
	}

	if (sigaction (SIGINT, &act, NULL) < 0) {
		perror ("sigaction SIGINT");
		exit (1);
	}

	/* Drop cores if we go wrong */
	//	if (chdir ("/"))
	//		;

	rlim.rlim_cur = RLIM_INFINITY;
	rlim.rlim_max = RLIM_INFINITY;

	setrlimit (RLIMIT_CORE, &rlim);


	proc = opendir ("/proc");
	if (! proc) {
		perror ("opendir /proc");
		exit (1);
	}

	sfd = open ("/proc/stat", O_RDONLY);
	if (sfd < 0) {
		perror ("open /proc/stat");
		exit (1);
	}

	dfd = open ("/proc/diskstats", O_RDONLY);
	if (dfd < 0) {
		perror ("open /proc/diskstats");
		exit (1);
	}

	ufd = open ("/proc/uptime", O_RDONLY);
	if (ufd < 0) {
		perror ("open /proc/uptime");
		exit (1);
	}


	sprintf (filename, "%s/proc_stat.log", output_dir);
	statfd = open (filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (statfd < 0) {
		perror ("open proc_stat.log");
		exit (1);
	}

	sprintf (filename, "%s/proc_diskstats.log", output_dir);
	diskfd = open (filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (diskfd < 0) {
		perror ("open proc_diskstats.log");
		exit (1);
	}

	if ( (use_taskstat = init_taskstat()) ) {
		sprintf (filename, "%s/taskstats.log", output_dir);
		taskfd = open (filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (taskfd < 0) {
			perror ("open taskstats.log");
			exit (1);
		}
	} else {
		sprintf (filename, "%s/proc_ps.log", output_dir);
		procfd = open (filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (procfd < 0) {
			perror ("open proc_ps.log");
			exit (1);
		}
	}

	if (rel) {
		reltime = get_uptime (ufd);
		if (! reltime)
			exit (1);
	}

	for (;;) {
		char          uptime[80];
		size_t        uptimelen;
		unsigned long u;

		u = get_uptime (ufd);
		if (! u)
			exit (1);

		uptimelen = sprintf (uptime, "%lu\n", u - reltime);


		if (read_file (sfd, uptime, uptimelen,
			       statfd, statbuf, &statlen) < 0)
			exit (1);

		if (read_file (dfd, uptime, uptimelen,
			       diskfd, diskbuf, &disklen) < 0)
			exit (1);

		if (use_taskstat) {
			if (read_taskstat (proc, uptime, uptimelen,
					   taskfd, taskbuf, &tasklen) < 0)
				exit (1);
		} else {
			if (read_proc (proc, uptime, uptimelen,
				       procfd, procbuf, &proclen) < 0)
				exit (1);
		}

		if (pselect (0, NULL, NULL, NULL, &timeout, &oldmask) < 0) {
			if (errno == EINTR) {
				break;
			} else {
				perror ("pselect");
				exit (1);
			}
		}
	}


	if (flush_buf (statfd, statbuf, &statlen) < 0)
		exit (1);
	if (close (statfd) < 0) {
		perror ("close proc_stat.log");
		exit (1);
	}

	if (flush_buf (diskfd, diskbuf, &disklen) < 0)
		exit (1);
	if (close (diskfd) < 0) {
		perror ("close proc_diskstats.log");
		exit (1);
	}

	if (use_taskstat) {
		if (flush_buf (taskfd, taskbuf, &tasklen) < 0)
			exit (1);
		if (close (taskfd) < 0) {
			perror ("close taskstats.log");
			exit (1);
		}
		if (close (netlink_socket) < 0) {
			perror ("failed to close netlink socket");
			exit (1);
		}

	} else {
		if (flush_buf (procfd, procbuf, &proclen) < 0)
			exit (1);
		if (close (procfd) < 0) {
			perror ("close proc_ps.log");
			exit (1);
		}
	}


	if (close (ufd) < 0) {
		perror ("close /proc/uptime");
		exit (1);
	}

	if (close (dfd) < 0) {
		perror ("close /proc/diskstats");
		exit (1);
	}

	if (close (sfd) < 0) {
		perror ("close /proc/stat");
		exit (1);
	}

	if (closedir (proc) < 0) {
		perror ("close /proc");
		exit (1);
	}

	return 0;
}
