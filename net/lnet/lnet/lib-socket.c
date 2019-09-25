// SPDX-License-Identifier: GPL-2.0
/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Seagate, Inc.
 */
#define DEBUG_SUBSYSTEM S_LNET

#include <linux/if.h>
#include <linux/in.h>
#include <linux/net.h>
#include <linux/file.h>
#include <linux/pagemap.h>
/* For sys_open & sys_close */
#include <linux/syscalls.h>
#include <net/sock.h>

#include <linux/lnet/lib-lnet.h>

int
lnet_sock_write(struct socket *sock, void *buffer, int nob, int timeout)
{
	int rc;
	long jiffies_left = timeout * HZ;
	unsigned long then;
	struct timeval tv;
	struct __kernel_sock_timeval ktv;
	struct kvec iov = {
		.iov_base = buffer,
		.iov_len = nob
	};
	struct msghdr msg = { NULL, };

	LASSERT(nob > 0);
	/*
	 * Caller may pass a zero timeout if she thinks the socket buffer is
	 * empty enough to take the whole message immediately
	 */
	iov_iter_kvec(&msg.msg_iter, WRITE, &iov, 1, nob);
	for (;;) {
		msg.msg_flags = !timeout ? MSG_DONTWAIT : 0;
		if (timeout) {
			/* Set send timeout to remaining time */
			jiffies_to_timeval(jiffies_left, &tv);
			ktv.tv_sec = tv.tv_sec;
			ktv.tv_usec = tv.tv_usec;
			rc = kernel_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO_NEW,
					       (char *)&ktv, sizeof(ktv));
			if (rc) {
				CERROR("Can't set socket send timeout %ld.%06d: %d\n",
				       (long)tv.tv_sec, (int)tv.tv_usec, rc);
				return rc;
			}
		}

		then = jiffies;
		rc = kernel_sendmsg(sock, &msg, &iov, 1, nob);
		jiffies_left -= jiffies - then;

		if (rc < 0)
			return rc;

		if (!rc) {
			CERROR("Unexpected zero rc\n");
			return -ECONNABORTED;
		}

		if (!msg_data_left(&msg))
			break;

		if (jiffies_left <= 0)
			return -EAGAIN;
	}
	return 0;
}
EXPORT_SYMBOL(lnet_sock_write);

int
lnet_sock_read(struct socket *sock, void *buffer, int nob, int timeout)
{
	int rc;
	long jiffies_left = timeout * HZ;
	unsigned long then;
	struct timeval tv;
	struct __kernel_sock_timeval ktv;
	struct kvec iov = {
		.iov_base = buffer,
		.iov_len = nob
	};
	struct msghdr msg = {
		.msg_flags = 0
	};

	LASSERT(nob > 0);
	LASSERT(jiffies_left > 0);

	iov_iter_kvec(&msg.msg_iter, READ, &iov, 1, nob);

	for (;;) {
		/* Set receive timeout to remaining time */
		jiffies_to_timeval(jiffies_left, &tv);
		ktv.tv_sec = tv.tv_sec;
		ktv.tv_usec = tv.tv_usec;
		rc = kernel_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO_NEW,
				       (char *)&ktv, sizeof(ktv));
		if (rc) {
			CERROR("Can't set socket recv timeout %ld.%06d: %d\n",
			       (long)tv.tv_sec, (int)tv.tv_usec, rc);
			return rc;
		}

		then = jiffies;
		rc = sock_recvmsg(sock, &msg, 0);
		jiffies_left -= jiffies - then;

		if (rc < 0)
			return rc;

		if (!rc)
			return -ECONNRESET;

		if (!msg_data_left(&msg))
			return 0;

		if (jiffies_left <= 0)
			return -ETIMEDOUT;
	}
}
EXPORT_SYMBOL(lnet_sock_read);

static int
lnet_sock_create(struct socket **sockp, int *fatal, u32 local_ip,
		 int local_port, struct net *ns)
{
	struct sockaddr_in locaddr;
	struct socket *sock;
	int rc;
	int option;

	/* All errors are fatal except bind failure if the port is in use */
	*fatal = 1;

	rc = sock_create_kern(ns, PF_INET, SOCK_STREAM, 0, &sock);
	*sockp = sock;
	if (rc) {
		CERROR("Can't create socket: %d\n", rc);
		return rc;
	}

	option = 1;
	rc = kernel_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
			       (char *)&option, sizeof(option));
	if (rc) {
		CERROR("Can't set SO_REUSEADDR for socket: %d\n", rc);
		goto failed;
	}

	if (local_ip || local_port) {
		memset(&locaddr, 0, sizeof(locaddr));
		locaddr.sin_family = AF_INET;
		locaddr.sin_port = htons(local_port);
		if (!local_ip)
			locaddr.sin_addr.s_addr = htonl(INADDR_ANY);
		else
			locaddr.sin_addr.s_addr = htonl(local_ip);

		rc = kernel_bind(sock, (struct sockaddr *)&locaddr,
				 sizeof(locaddr));
		if (rc == -EADDRINUSE) {
			CDEBUG(D_NET, "Port %d already in use\n", local_port);
			*fatal = 0;
			goto failed;
		}
		if (rc) {
			CERROR("Error trying to bind to port %d: %d\n",
			       local_port, rc);
			goto failed;
		}
	}
	return 0;

failed:
	sock_release(sock);
	return rc;
}

int
lnet_sock_setbuf(struct socket *sock, int txbufsize, int rxbufsize)
{
	int option;
	int rc;

	if (txbufsize) {
		option = txbufsize;
		rc = kernel_setsockopt(sock, SOL_SOCKET, SO_SNDBUF,
				       (char *)&option, sizeof(option));
		if (rc) {
			CERROR("Can't set send buffer %d: %d\n",
			       option, rc);
			return rc;
		}
	}

	if (rxbufsize) {
		option = rxbufsize;
		rc = kernel_setsockopt(sock, SOL_SOCKET, SO_RCVBUF,
				       (char *)&option, sizeof(option));
		if (rc) {
			CERROR("Can't set receive buffer %d: %d\n",
			       option, rc);
			return rc;
		}
	}
	return 0;
}
EXPORT_SYMBOL(lnet_sock_setbuf);

int
lnet_sock_getaddr(struct socket *sock, bool remote, u32 *ip, int *port)
{
	struct sockaddr_in sin;
	int rc;

	if (remote)
		rc = kernel_getpeername(sock, (struct sockaddr *)&sin);
	else
		rc = kernel_getsockname(sock, (struct sockaddr *)&sin);
	if (rc < 0) {
		CERROR("Error %d getting sock %s IP/port\n",
		       rc, remote ? "peer" : "local");
		return rc;
	}

	if (ip)
		*ip = ntohl(sin.sin_addr.s_addr);

	if (port)
		*port = ntohs(sin.sin_port);

	return 0;
}
EXPORT_SYMBOL(lnet_sock_getaddr);

int
lnet_sock_getbuf(struct socket *sock, int *txbufsize, int *rxbufsize)
{
	if (txbufsize)
		*txbufsize = sock->sk->sk_sndbuf;

	if (rxbufsize)
		*rxbufsize = sock->sk->sk_rcvbuf;

	return 0;
}
EXPORT_SYMBOL(lnet_sock_getbuf);

int
lnet_sock_listen(struct socket **sockp, u32 local_ip, int local_port,
		 int backlog, struct net *ns)
{
	int fatal;
	int rc;

	rc = lnet_sock_create(sockp, &fatal, local_ip, local_port, ns);
	if (rc) {
		if (!fatal)
			CERROR("Can't create socket: port %d already in use\n",
			       local_port);
		return rc;
	}

	rc = kernel_listen(*sockp, backlog);
	if (!rc)
		return 0;

	CERROR("Can't set listen backlog %d: %d\n", backlog, rc);
	sock_release(*sockp);
	return rc;
}

int
lnet_sock_connect(struct socket **sockp, int *fatal, u32 local_ip,
		  int local_port, u32 peer_ip, int peer_port,
		  struct net *ns)
{
	struct sockaddr_in srvaddr;
	int rc;

	rc = lnet_sock_create(sockp, fatal, local_ip, local_port, ns);
	if (rc)
		return rc;

	memset(&srvaddr, 0, sizeof(srvaddr));
	srvaddr.sin_family = AF_INET;
	srvaddr.sin_port = htons(peer_port);
	srvaddr.sin_addr.s_addr = htonl(peer_ip);

	rc = kernel_connect(*sockp, (struct sockaddr *)&srvaddr,
			    sizeof(srvaddr), 0);
	if (!rc)
		return 0;

	/*
	 * EADDRNOTAVAIL probably means we're already connected to the same
	 * peer/port on the same local port on a differently typed
	 * connection.  Let our caller retry with a different local
	 * port...
	 */
	*fatal = !(rc == -EADDRNOTAVAIL);

	CDEBUG_LIMIT(*fatal ? D_NETERROR : D_NET,
		     "Error %d connecting %pI4h/%d -> %pI4h/%d\n", rc,
		     &local_ip, local_port, &peer_ip, peer_port);

	sock_release(*sockp);
	return rc;
}
