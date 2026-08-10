/*
 * tmpcd path command args
 *
 * Create a tmpdir, chdir to it, and run the command
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>

#define O_TMPDIR (__O_TMPFILE | O_DIRECTORY | O_CREAT | O_RDWR)

int main(int argc, char *argv[])
{
	int fd;

	if (argc < 3) {
		fprintf(stderr, "Usage: tmpcd directory command [args...]\n");
		exit(2);
	}
	fd = open(argv[1], O_TMPDIR, 0700);
	if (fd < 0) {
		perror("open tmp dir");
		exit(1);
	}
	if (fchdir(fd) < 0) {
		perror("fchdir");
		exit(1);
	}
	execv(argv[2], argv+2);
	perror("exec failed");
	exit(1);
}
