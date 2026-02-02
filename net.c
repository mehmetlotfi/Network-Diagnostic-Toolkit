/*
 *  Network Diagnostic Toolkit
 *  Copyright (C) 2026  Mehmet Lotfi
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef INCLUDED_H
#define INCLUDED_H

/* Standard C */
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "unistd.h"
#include "time.h"

/* Sockets & Networking */
#include "sys/types.h"
#include "sys/socket.h"
#include "netdb.h"
#include "arpa/inet.h"

/* ICMP */
#include "netinet/ip.h"
#include "netinet/ip_icmp.h"

/* DNS */
#include "resolv.h"

/* ARP & RAW SOCKET */
#include "net/if.h"
#include "sys/ioctl.h"
#include "netpacket/packet.h"
#include "net/ethernet.h"
#include "netinet/if_ether.h"

/* Signals */
#include "signal.h"

/* Interface enumeration */
#include "ifaddrs.h"

/* Project header */
#include "functions.h"
#endif

int main ()
{
	setup_signals ();
	main_menu ();
	return 0;
}
