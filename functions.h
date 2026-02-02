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

int tcp_test ();
int udp_test ();
int icmp_test ();
int open_port ();
int dns_tools ();
int find_mac ();

void clrscr ()
{
    system ("clear");
}

int main_menu ()
{
    clrscr ();
    printf ("Welcome to the Connection test Program.\n\n");
    printf ("1- TCP Connection test\n");
    printf ("2- UDP Connection test\n");
    printf ("3- ICMP Connection test\n");
    printf ("4- Test Connection to a specific port\n");
    printf ("5- DNS Question\n");
    printf ("6- Find the MAC address of a device on your network\n");
    printf ("7- Exit\n");
    printf ("[-] Select the option number you want: ");

    int opt;
    scanf ("%d" , &opt);

    switch (opt)
    {
        case 1:
            tcp_test ();
            sleep (2);
            return main_menu();

        case 2:
            udp_test ();
            sleep (2);
            return main_menu();

        case 3:
            icmp_test ();
            sleep (2);
            return main_menu ();

        case 4:
            open_port ();
            sleep (2);
            return main_menu ();

        case 5:
            dns_tools ();
            sleep (2);
            return main_menu ();

        case 6:
            find_mac ();
            sleep (2);
            return main_menu ();

        case 7:
            return 0;

        default:
            printf ("[-] Please enter a number between 1 and 7...\n");
            printf ("[-] Restarting menu...\n");
            for (int i = 3; i > 0; i--) {
                printf ("%d\n", i);
                sleep (1);
            }
            return main_menu ();
    }
}

void signal_handler (int sig)
{
    printf ("\n[!] Signal %d blocked. Use option 7 to exit.\n" , sig);
    main_menu ();
}

void setup_signals ()
{
    signal (SIGINT , signal_handler);
    signal (SIGTSTP , signal_handler);
    signal (SIGQUIT , signal_handler);
    signal (SIGHUP , signal_handler);
    signal (SIGTERM , signal_handler);
}

int tcp_test ()
{
    clrscr ();
    char host [256];
    char choice [16];
    char port [16];
    printf ("[-] Enter IP or Domain: ");
    scanf ("%255s", host);
    printf ("\nSelect connection type:\n");
    printf ("1- HTTP\n");
    printf ("2- HTTPS\n");
    printf ("3- DEFAULT (manual port)\n");
    printf ("4- back\n");
    printf ("Enter choice (1/2/3): ");
    scanf ("%15s", choice);
    if (strcmp (choice , "1") == 0)
    {
        strcpy (port , "80");
    }
    else if (strcmp (choice , "2") == 0)
    {
        strcpy (port , "443");
    }
    else if (strcmp (choice , "3") == 0)
    {
        printf ("[-] Enter port: ");
        scanf ("%15s" , port);
    }
    else if (strcmp (choice , "4") == 0)
    {
        main_menu ();
    }
    else
    {
        printf ("[!] Invalid choice\n");
        return -1;
    }
    struct addrinfo hints , *res;
    int sockfd , status;
    memset(&hints , 0 , sizeof (hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if ((status = getaddrinfo (host , port , &hints , &res)) != 0)
    {
        printf ("[!] getaddrinfo error: %s\n" , gai_strerror (status));
        return -1;
    }
    sockfd = socket (res -> ai_family , res -> ai_socktype , res -> ai_protocol);
    if (sockfd < 0) 
    {
        fprintf (stderr , "[-] ERROR in socket.\n");
        freeaddrinfo (res);
        return -1;
    }
    printf ("[*] Trying to connect to %s:%s ...\n" , host , port);
    if (connect (sockfd , res -> ai_addr , res -> ai_addrlen) == 0)
        printf ("[+] Connection successful!\n");
    else
        printf ("[-] Connection failed\n");
    close (sockfd);
    freeaddrinfo (res);
    sleep (2);
    return 0;
}

int udp_test ()
{
    clrscr ();
    char host [256];
    char port [16];
    printf ("[-] Enter IP or Domain: ");
    scanf ("%255s", host);
    printf ("[-] Enter UDP port: ");
    scanf ("%15s", port);
    struct addrinfo hints , *res;
    int sockfd , status;
    memset (&hints , 0 , sizeof (hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    if ((status = getaddrinfo (host , port , &hints , &res)) != 0)
    {
        printf ("[!] getaddrinfo error: %s\n" , gai_strerror (status));
        return -1;
    }
    sockfd = socket (res -> ai_family , res -> ai_socktype , res -> ai_protocol);
    if (sockfd < 0)
    {
        fprintf (stderr , "[-] ERROR in socket.\n");
        freeaddrinfo (res);
        return -1;
    }
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt (sockfd , SOL_SOCKET , SO_RCVTIMEO , &tv , sizeof (tv));
    char msg [] = "udp_test";
    sendto (sockfd , msg , sizeof (msg) , 0 , res -> ai_addr , res -> ai_addrlen);
    char buf [128];
    socklen_t len = res -> ai_addrlen;
    printf("[*] Waiting for UDP response...\n");
    if (recvfrom (sockfd , buf , sizeof (buf) , 0 , res -> ai_addr , &len) >= 0)
        printf ("[+] UDP response received!\n");
    else
        printf ("[-] No response (timeout)\n");
    close (sockfd);
    freeaddrinfo (res);
    sleep (2);
    return 0;
}

unsigned short checksum (void * b , int len)
{
	unsigned short * buf = b;
	unsigned int sum = 0;
	unsigned short result;
	for (sum = 0 ; len > 1 ; len -= 2)
		sum += *buf++;
	if (len == 1)
		sum += *(unsigned char *) buf;
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	result = ~sum;
	return result;
}

void send_icmp (int sockfd , struct sockaddr_in * dest , int seq)
{
	char packet [64];
	struct icmphdr * icmp = (struct icmphdr *) packet;
	memset (packet , 0 , sizeof (packet));
	icmp -> type = ICMP_ECHO;
	icmp -> code = 0;
	icmp -> un.echo.id = htons (getpid () & 0xFFFF);
	icmp -> un.echo.sequence = htons (seq);
	icmp -> checksum = 0;
	icmp -> checksum = checksum (packet , sizeof (packet));
	if (sendto (sockfd , packet , sizeof (packet) , 0 , (struct sockaddr *) dest , sizeof(*dest)) < 0) 
		fprintf (stderr , "[-] ERROR in sendto function\n");
	else
		printf ("Sent ICMP Echo Request (seq=%d)\n", seq);
}

int icmp_test ()
{
    clrscr ();
    char host [256];
    int count;
    printf ("[-] Enter IP or Domain: ");
    scanf ("%255s", host);
    printf ("[-] Number of ICMP packets: ");
    scanf ("%d", &count);
    struct addrinfo hints , *res;
    memset (&hints , 0 , sizeof (hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_RAW;
    hints.ai_protocol = IPPROTO_ICMP;
    int status = getaddrinfo (host , NULL , &hints , &res);
    if (status != 0)
    {
        printf ("[!] getaddrinfo error: %s\n" , gai_strerror (status));
        return -1;
    }
    int sockfd = socket (AF_INET , SOCK_RAW , IPPROTO_ICMP);
    if (sockfd < 0)
    {
        fprintf (stderr , "[-] ERROR: Making RAW socket failed\n[-] run this program with root access\n");
        freeaddrinfo (res);
        return -1;
    }
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt (sockfd , SOL_SOCKET , SO_RCVTIMEO , &tv , sizeof (tv));
    struct sockaddr_in dest;
    memcpy (&dest , res -> ai_addr , sizeof (dest));
    int sent = 0, received = 0;
    for (int i=1 ; i <= count ; i++)
    {
        send_icmp (sockfd , &dest , i);
        sent++;
        char buf [1024];
        struct sockaddr_in reply_addr;
        socklen_t addr_len = sizeof (reply_addr);
        int r = recvfrom (sockfd , buf , sizeof (buf) , 0 , (struct sockaddr *) &reply_addr , &addr_len);
        if (r > 0)
        {
            struct iphdr *ip = (struct iphdr *) buf;
            int iphdr_len = ip -> ihl * 4;
            struct icmphdr * icmp = (struct icmphdr *) (buf + iphdr_len);
            if (icmp -> type == ICMP_ECHOREPLY && ntohs (icmp -> un.echo.id) == (getpid () & 0xFFFF))
            {
                printf ("[+] ICMP Echo Reply received (seq=%d)\n" , i);
                received++;
            }
        }
        else
            printf ("[-] Timeout (seq=%d)\n" , i);
        usleep (500000);
    }
    freeaddrinfo (res);
    close (sockfd);
    float rate = 0;
    if (sent > 0)
        rate = (received * 100.0f) / sent;
    printf ("\nSent: %d , Received: %d , Success: %.2f%%\n" , sent , received , rate);
    sleep (3);
    return 0;
}

int open_port ()
{
    clrscr ();
    char host [256];
    char port [16];
    printf ("[-] Enter IP or Domain: ");
    scanf ("%255s" , host);
    printf ("[-] Enter Port: ");
    scanf ("%15s", port);
    struct addrinfo hints , *res;
    memset (&hints , 0 , sizeof (hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    int status = getaddrinfo (host , port , &hints , &res);
    if (status != 0)
    {
        printf ("[!] getaddrinfo error: %s\n" , gai_strerror (status));
        return -1;
    }
    int tcp_sock = socket (res -> ai_family , res -> ai_socktype , res -> ai_protocol);
    if (tcp_sock < 0)
    {
        fprintf (stderr , "[-] ERROR in socket.\n");
        freeaddrinfo (res);
        return -1;
    }
    printf ("[*] Testing TCP %s:%s ...\n" , host , port);
    if (connect (tcp_sock , res -> ai_addr , res -> ai_addrlen) == 0)
        printf ("[+] TCP port open\n");
    else
        printf ("[-] TCP port closed\n");
    close (tcp_sock);
    int udp_sock = socket (res -> ai_family , SOCK_DGRAM , 0);
    if (udp_sock < 0)
    {
        fprintf (stderr , "[-] ERROR in socket.\n");
        freeaddrinfo (res);
        return -1;
    }
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt (udp_sock , SOL_SOCKET , SO_RCVTIMEO , &tv , sizeof (tv));
    printf ("[*] Testing UDP %s:%s ...\n" , host , port);
    char msg [] = "udp_test";
    sendto (udp_sock , msg , sizeof (msg) , 0 , res -> ai_addr , res -> ai_addrlen);
    char buf [256];
    socklen_t len = res -> ai_addrlen;
    int r = recvfrom (udp_sock , buf , sizeof (buf) , 0 , res -> ai_addr , &len);
    if (r > 0)
        printf ("[+] UDP port open (response received)\n");
    else
        printf ("[-] UDP port filtered or closed (no response)\n");
    close (udp_sock);
    freeaddrinfo (res);
    sleep (3);
    return 0;
}

int dns_tools ()
{
    clrscr ();
    int mode;
    printf ("1- Domain Lookup (A, AAAA, MX, NS)\n");
    printf ("2- Reverse Lookup (PTR)\n");
    printf ("3- back\n");
    printf ("Enter choice: ");
    scanf ("%d", &mode);
    if (mode == 3)
        main_menu ();
    else if (mode != 1 || mode != 2 || mode != 3)
    {
        printf ("[-] Please enter a number between 1 and 3...");
        sleep (2);
        dns_tools ();
    } 
    int dns_mode;
    clrscr ();
    printf ("1- Use system DNS\n");
    printf ("2- Use custom DNS\n");
    printf ("Enter choice: ");
    scanf ("%d" , &dns_mode);
    if (dns_mode != 1 || dns_mode != 2)
    {
        printf ("[-] Please enter a number between 1 and 2...");
        sleep (2);
        main_menu ();
    }
    char dns_ip [64];
    if (dns_mode == 2)
    {
        printf ("Enter DNS server IP: ");
        scanf ("%63s", dns_ip);
    }
    res_state statp = malloc (sizeof (struct __res_state));
    memset (statp , 0 , sizeof (struct __res_state));
    res_ninit (statp);
    if (dns_mode == 2)
    {
        statp -> nscount = 1;
        statp -> nsaddr_list [0].sin_family = AF_INET;
        statp -> nsaddr_list [0].sin_port = htons (53);
        inet_pton(AF_INET , dns_ip , &statp -> nsaddr_list [0].sin_addr);
    }
    if (mode == 1)
    {
        char domain [256];
        printf ("Enter domain: ");
        scanf ("%255s" , domain);
        unsigned char answer [4096];
        int len = res_nquery (statp , domain , ns_c_in , ns_t_a , answer , sizeof (answer));
        if (len > 0)
        {
            ns_msg msg;
            ns_initparse (answer , len , &msg);
            int count = ns_msg_count (msg , ns_s_an);
            for (int i=0 ; i<count ; i++)
            {
                ns_rr rr;
                ns_parserr (&msg , ns_s_an , i , &rr);
                if (ns_rr_type (rr) == ns_t_a)
                {
                    struct in_addr a;
                    memcpy (&a , ns_rr_rdata (rr) , 4);
                    printf ("A: %s\n" , inet_ntoa (a));
                }
            }
        }
        len = res_nquery (statp , domain , ns_c_in , ns_t_aaaa , answer , sizeof (answer));
        if (len > 0)
        {
            ns_msg msg;
            ns_initparse (answer , len , &msg);
            int count = ns_msg_count (msg , ns_s_an);
            for (int i=0 ; i<count ; i++)
            {
                ns_rr rr;
                ns_parserr (&msg , ns_s_an , i , &rr);
                if (ns_rr_type (rr) == ns_t_aaaa)
                {
                    char buf [64];
                    inet_ntop (AF_INET6 , ns_rr_rdata (rr) , buf , sizeof (buf));
                    printf ("AAAA: %s\n" , buf);
                }
            }
        }
        len = res_nquery (statp , domain , ns_c_in , ns_t_mx , answer , sizeof (answer));
        if (len > 0)
        {
            ns_msg msg;
            ns_initparse (answer , len , &msg);
            int count = ns_msg_count (msg , ns_s_an);
            for (int i=0 ; i<count ; i++)
            {
                ns_rr rr;
                ns_parserr (&msg , ns_s_an , i , &rr);
                if (ns_rr_type (rr) == ns_t_mx)
                {
                    const unsigned char *r = ns_rr_rdata (rr);
                    int pref = (r [0] << 8) | r [1];
                    char mx [256];
                    dn_expand (answer , answer + len , r + 2 , mx , sizeof (mx));
                    printf ("MX: %s (pref=%d)\n" , mx , pref);
                }
            }
        }
        len = res_nquery (statp , domain , ns_c_in , ns_t_ns , answer , sizeof (answer));
        if (len > 0)
        {
            ns_msg msg;
            ns_initparse (answer , len , &msg);
            int count = ns_msg_count (msg , ns_s_an);
            for (int i=0 ; i<count ; i++)
            {
                ns_rr rr;
                ns_parserr (&msg , ns_s_an , i , &rr);
                if (ns_rr_type (rr) == ns_t_ns)
                {
                    char nsd [256];
                    dn_expand (answer , answer + len , ns_rr_rdata (rr) , nsd , sizeof (nsd));
                    printf ("NS: %s\n" , nsd);
                }
            }
        }
    }
    if (mode == 2)
    {
        char ip [64];
        printf ("Enter IP: ");
        scanf ("%63s", ip);
        struct in_addr addr;
        inet_pton (AF_INET , ip , &addr);
        unsigned char answer [4096];
        char ptr [256];
        sprintf (ptr , "%d.%d.%d.%d.in-addr.arpa" , (addr.s_addr >> 24) & 0xFF , (addr.s_addr >> 16) & 0xFF , (addr.s_addr >> 8) & 0xFF , addr.s_addr & 0xFF);
        int len = res_nquery (statp , ptr , ns_c_in , ns_t_ptr , answer , sizeof (answer));
        if (len > 0)
        {
            ns_msg msg;
            ns_initparse (answer , len , &msg);
            int count = ns_msg_count (msg , ns_s_an);
            for (int i=0 ; i<count ; i++)
            {
                ns_rr rr;
                ns_parserr (&msg , ns_s_an , i , &rr);
                if (ns_rr_type (rr) == ns_t_ptr)
                {
                    char out [256];
                    dn_expand (answer , answer + len , ns_rr_rdata (rr) , out , sizeof (out));
                    printf ("PTR: %s\n" , out);
                }
            }
        }
    }
    res_nclose (statp);
    free (statp);
    sleep (3);
    return 0;
}

int find_mac ()
{
    clrscr ();

    struct ifaddrs * ifaddr , * ifa;
    int idx = 0;
    char iface_list [20] [IFNAMSIZ];
    char ip_list [20] [64];
    if (getifaddrs (&ifaddr) == -1)
    {
        printf ("[-] ERROR: getifaddrs failed\n");
        return -1;
    }
    printf ("Available interfaces:\n\n");
    for (ifa = ifaddr ; ifa != NULL ; ifa = ifa -> ifa_next)
    {
        if (!ifa -> ifa_addr)
            continue;
        if (ifa -> ifa_addr -> sa_family != AF_INET)
            continue;
        strncpy (iface_list [idx] , ifa -> ifa_name , IFNAMSIZ);
        struct sockaddr_in * sa = (struct sockaddr_in *) ifa -> ifa_addr;
        inet_ntop (AF_INET , &sa -> sin_addr , ip_list [idx] , sizeof (ip_list [idx]));
        printf ("%d- %s (IP: %s)\n" , idx + 1 , iface_list [idx] , ip_list [idx]);
        idx++;
    }
    if (idx == 0)
    {
        printf ("[-] No usable interfaces found.\n");
        freeifaddrs (ifaddr);
        return -1;
    }
    printf ("\n[-] Select interface number: ");
    int choice;
    scanf ("%d" , &choice);
    if (choice < 1 || choice > idx)
    {
        printf ("[-] Invalid selection.\n");
        freeifaddrs (ifaddr);
        return -1;
    }
    char iface [IFNAMSIZ];
    strcpy (iface , iface_list [choice - 1]);
    freeifaddrs (ifaddr);
    char target_ip_str [64];
    printf ("[-] Enter target IP: ");
    scanf ("%63s", target_ip_str);
    int sock = socket (AF_PACKET , SOCK_RAW , htons (ETH_P_ARP));
    if (sock < 0)
    {
        fprintf (stderr , "[-] ERROR: Making RAW socket failed\n[-] run this program with root access\n");
        return -1;
    }
    struct ifreq ifr;
    strncpy (ifr.ifr_name , iface , IFNAMSIZ - 1);
    if (ioctl (sock , SIOCGIFHWADDR , &ifr) < 0)
    {
        printf ("[-] Failed to get MAC of interface\n");
        close (sock);
        return -1;
    }
    unsigned char src_mac [6];
    memcpy(src_mac , ifr.ifr_hwaddr.sa_data , 6);
    if (ioctl (sock , SIOCGIFADDR , &ifr) < 0)
    {
        printf ("[-] Failed to get IP of interface\n");
        close (sock);
        return -1;
    }
    struct sockaddr_in * ipaddr = (struct sockaddr_in *) &ifr.ifr_addr;
    unsigned char src_ip [4];
    memcpy (src_ip , &ipaddr -> sin_addr , 4);
    struct in_addr target_ip;
    if (!inet_aton (target_ip_str , &target_ip))
    {
        printf ("[-] Invalid target IP\n");
        close (sock);
        return -1;
    }
    unsigned char dst_ip [4];
    memcpy (dst_ip , &target_ip , 4);
    unsigned char packet [42];
    memset (packet , 0xff , 6);
    memcpy (packet + 6 , src_mac , 6);
    packet [12] = 0x08;
    packet [13] = 0x06;
    packet [14] = 0x00;
    packet [15] = 0x01;
    packet [16] = 0x08;
    packet [17] = 0x00;
    packet [18] = 6;
    packet [19] = 4;
    packet [20] = ARPOP_REQUEST;
    memcpy (packet + 22 , src_mac , 6);
    memcpy (packet + 28 , src_ip , 4);
    memset (packet + 32 , 0x00 , 6);
    memcpy (packet + 38 , dst_ip , 4);
    struct sockaddr_ll sa;
    memset (&sa , 0 , sizeof (sa));
    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = if_nametoindex (iface);
    sa.sll_halen = ETH_ALEN;
    memset (sa.sll_addr , 0xff , 6);
    sendto(sock , packet , 42 , 0 , (struct sockaddr *)&sa , sizeof (sa));
    fd_set fds;
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    FD_ZERO (&fds);
    FD_SET (sock , &fds);
    int r = select (sock + 1 , &fds , NULL , NULL , &tv);
    if (r <= 0)
    {
        printf ("[-] No ARP reply received. Host may be offline.\n");
        close (sock);
        return 0;
    }
    while (1)
    {
        unsigned char buf [1500];
        ssize_t len = recv (sock , buf , sizeof (buf) , 0);
        if (len < 0)
            break;
        if (buf [12] == 0x08 && buf [13] == 0x06 && buf [20] == ARPOP_REPLY && memcmp (buf + 28 , dst_ip , 4) == 0)
        {
            printf ("[+] MAC of %s is: " , target_ip_str);
            for (int i = 0; i < 6; i++)
            {
                printf ("%02x" , buf [22 + i]);
                if (i != 5)
                    printf (":");
            }
            printf ("\n");
            break;
        }
    }
    close (sock);
    return 0;
}