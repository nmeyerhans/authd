/*
 * Copyright 2009 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that the above copyright notice appear in all
 * copies and that both that copyright notice and this permission
 * notice appear in supporting documentation, and that the name of
 * M.I.T. not be used in advertising or publicity pertaining to
 * distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original
 * M.I.T. software.  M.I.T. makes no representations about the
 * suitability of this software for any purpose.  It is provided "as
 * is" without express or implied warranty.
 *
 */


/* @(#)authd.c
 * Author: Noah Meyerhans <noahm@csail.mit.edu>
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <libgen.h>
#include <signal.h>

#define LOOP_INTERVAL 60
#define KINIT_INTERVAL 3600

/* if name is given, make and return a new pid file (rooted in a
   tmp directory).
   If name is null, return the current pid file name. */
char *pidfilename(char *name) {
    static char pidfile[PATH_MAX];
    char *dir, *logname;
    if(!name)
	return pidfile;
    if(!(logname = getenv("LOGNAME")))
	return 0;
    snprintf(pidfile, PATH_MAX, "/tmp/authd-%s/%s", logname, name);
    return pidfile;
}

/* create a file with the given name in /tmp/$LOGNAME.  Create
   /tmp/$LOGNAME if necessary.
   Returns 0 if our pid was successfully written to the file.
   Returns -1 if an unexpected error happened.
   Other non-zero return values are errno values.
*/
int write_pidfile(const char *file) {
    char *nam, *dir, *path, *pidstr;
    int fd, pid;
    path = strdup(file); // dirname will want to modify this
    nam = getenv("LOGNAME");
    if(!nam)
	return -1;
    dir = dirname(path);
    if(mkdir(dir, 0700) == -1) {
	if(errno != EEXIST) {
	    perror(dir);
	    return -1;
	}
    }
    if((fd = open(file, O_CREAT|O_EXCL|O_WRONLY, 0600)) == -1) {
	if(errno == EEXIST) {
	    // a pid already exists at the given path
	    return errno;
	}
	perror(path);
	return -1;
    }
    pid = getpid();
    asprintf(&pidstr, "%d\n", pid);
    write(fd, pidstr, strlen(pidstr));
    close(fd);
    free(path);
    free(pidstr);
    return 0;
}

/* return the pid stored in the given pid file */
int read_pidfile(char *file) {
    char *line;
    int pid, read_sz, len;
    FILE *f;

    line = NULL;
    len = 0;
    f = fopen(file, "r");
    if(!f)
	return -1;
    read_sz = getline(&line, &len, f);
    if(read_sz < 0)
	return -2;
    pid = atoi(line);
    return pid;
}

/* remove the pid file, and maybe the directory */
void destroy_pidfile() {
    char *pidfile = pidfilename(0);
    char *dir;
    dir = strdup(pidfile);
    dir = dirname(dir);
    unlink(pidfile);
    rmdir(dir);
}

/* print a usage message, either to stdout or stderr */
void usage(int err) {
    FILE *out = stdout;
    if(err)
	out = stderr;
    fprintf(out, "Usage:\n");
    fprintf(out, "  authd\n");
    fprintf(out, "authd is a daemon responsible for keeping kerberos ");
    fprintf(out, "and AFS tokens\nfresh for the duration of their ");
    fprintf(out, "lifetime or the session, whichever\nis shorter.\n");
}

/* try to figure out of the given pid and command still refer to
   the same process */
int check_parent(int gp_pid, char *cmdline) {
    char seen_cmdline[1000];
    char path[1024];
    int fd;

    if(kill(gp_pid, 0) == -1)
	return 0; /* no process, or it's not ours */
    snprintf(path, 1024, "/proc/%d/cmdline", gp_pid);
    fd = open(path, O_RDONLY);
    if(fd == -1)
	return 0;
    read(fd, seen_cmdline, 1000);
    close(fd);
    if(strcmp(cmdline, seen_cmdline)) {
	// the command lines don't seem to match
	return 0;
    }
    return 1;
}

/* loop forever, making sure that our parent is still around.  Renew
   credentials periodically.  break if either the kinit call fails
   or the parent is no longer present */
void child_loop(int gp_pid, char *cmdline) {
    int loop_count = 0;
    while(1) {
	if(loop_count * LOOP_INTERVAL >= KINIT_INTERVAL) {
	    loop_count = 0;
	    if(system("kinit -R > /dev/null") == 0) {
		system("aklog > /dev/null");
	    }
	}
	if(!check_parent(gp_pid, cmdline))
	    break;
	loop_count++;
	sleep(LOOP_INTERVAL);
    }
}

/* read /proc/x/cmdline for the given pid */
void read_ppid_cmdline(int pid, char *buf, int bufsz) {
    char path[1024];
    int fd;
    sprintf(path, "/proc/%d/cmdline", pid);
    fd = open(path, O_RDONLY);

    if(fd < 0) {
	perror("open");
	exit(1);
    }
    if(read(fd, buf, bufsz) < 0) {
	perror("read");
	exit(1);
    }
}

void *sig_handler(int sig) {
    destroy_pidfile();
    exit(0);
}

int main(int argc, char **argv) {
    int other_pid, ppid, child_pid;
    int sh_type;
    char cmdline[1000];
    char *pidstr;

    if(argc > 1) {
	if(!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
	    usage(0);
	    exit(0);
	}
    }

    if((ppid = getsid(0)) == -1) {
	perror("getsid()");
	exit(1);
    }
    asprintf(&pidstr, "%d", ppid);

    read_ppid_cmdline(ppid, cmdline, 1000);

    if(child_pid = fork()) {
	// parent
	if(child_pid < 0) {
	    perror("fork");
	    exit(1);
	}
    }
    else {
	//child
	int rv;
	signal(SIGHUP, SIG_IGN);
	signal(SIGTERM, (void*)sig_handler);
	signal(SIGINT, (void*)sig_handler);
	if((rv = write_pidfile(pidfilename(pidstr))) == 0) {
	    printf("authd is running as %d ", getpid());
	    printf("in session %d\n", ppid);
	    close(0); close(1); close(2);
	    child_loop(ppid, cmdline);
	    destroy_pidfile();
	} else if(rv > 0) {
	    int other_pid;
	    other_pid = read_pidfile(pidfilename(NULL));
	    fprintf(stderr, "authd appears to already be running ");
	    fprintf(stderr, "in this session with pid %d\n", other_pid);
	    exit(1);
	} else {
	    fprintf(stderr, "Aborting after something unexpected happened.\n");
	    exit(1);
	}
    }
}
