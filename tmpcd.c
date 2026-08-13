/*
 * tmpcd path command args
 *
 * Create a tmpdir, chdir to it, and run the command
 *
 * Usage: tmpcd [-m mountpoint] directory command args...
 *
 * If a mountpoint is given, then a private namespace is created
 * and the temp directory is mounted on that mountpoint in the
 * private namespace.  When the process exist, the namespace will
 * be torn down, the temp directory automatically unmounted, and
 * so the directory tree will get cleaned up.
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <sched.h>

#define O_TMPDIR (__O_TMPFILE | O_DIRECTORY | O_CREAT | O_RDWR)

int main(int argc, char *argv[])
{
	char *mountpoint = NULL;
	int fd;

	if (argc < 3) {
		fprintf(stderr, "Usage: tmpcd [-m mountpoint] directory command [args...]\n");
		exit(2);
	}
	if (argc > 4 && strcmp(argv[1], "-m") == 0) {
		mountpoint = argv[2];
		argv += 2;
	}
	fd = open(argv[1], O_TMPDIR | O_CLOEXEC, 0700);
	if (fd < 0) {
		perror("open tmp dir");
		exit(1);
	}
	if (mountpoint) {
		/* check it is a directory */
		if (chdir(mountpoint) < 0) {
			perror(mountpoint);
			exit(1);
		}
	}
	if (fchdir(fd) < 0) {
		perror("fchdir");
		exit(1);
	}
	if (mountpoint) {
		unshare(CLONE_NEWNS | CLONE_NEWUSER);
		mount(".", mountpoint, NULL, MS_BIND, NULL);
		chdir(mountpoint);
	}
	execv(argv[2], argv+2);
	perror("exec failed");
	exit(1);
}
