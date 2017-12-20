/*
 * Copyright 2017 Kristian Evensen <kristian.evensen@gmail.com>
 *
 * This file is part of TCP closer. TCP closer is free software: you can
 * redistribute it and/or modify it under the terms of the Lesser GNU General
 * Public License as published by the Free Software Foundation, either version 3
 * of the License, or (at your option) any later version.
 *
 * Usb Montior is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * TCP closer. If not, see http://www.gnu.org/licenses/.
 */

#ifndef TCP_CLOSER_H
#define TCP_CLOSER_H

struct inet_diag_bc_op;

//This is an artifical limitation introduced by me, but is large enough for at
//least my use-cases. Since there is no EQ operator, we need to check a port for
//both LE and GE. In case of a match, we also need to be able to jump directly
//to destination ports/end. This means that one port requires five op-structs
//and will consume 20 bytes.
//
//The correct limit is something closer to 0xFFFF/20 source and destination
//ports, with some adjustmenets for the first and last operation. The value used
//to store the offset to jump to is a short, so maximum offset from any op is
//0xFFFF
#define MAX_NUM_PORTS 256

//There are currently 11 states, but the first state is stored in pos. 1.
//Therefore, I need a 12 bit bitmask
#define TCPF_ALL 0xFFF

//Copied from libmnl source
//TODO: Consider if making use of libmnl makes sense
#define SOCKET_BUFFER_SIZE (getpagesize() < 8192L ? getpagesize() : 8192L)

//Kernel TCP states. /include/net/tcp_states.h
enum{
    TCP_ESTABLISHED = 1,
    TCP_SYN_SENT,
    TCP_SYN_RECV,
    TCP_FIN_WAIT1,
    TCP_FIN_WAIT2,
    TCP_TIME_WAIT,
    TCP_CLOSE,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
    TCP_LISTEN,
    TCP_CLOSING
};

static const char* tcp_states_map[]={
    [TCP_ESTABLISHED] = "ESTABLISHED",
    [TCP_SYN_SENT] = "SYN-SENT",
    [TCP_SYN_RECV] = "SYN-RECV",
    [TCP_FIN_WAIT1] = "FIN-WAIT-1",
    [TCP_FIN_WAIT2] = "FIN-WAIT-2",
    [TCP_TIME_WAIT] = "TIME-WAIT",
    [TCP_CLOSE] = "CLOSE",
    [TCP_CLOSE_WAIT] = "CLOSE-WAIT",
    [TCP_LAST_ACK] = "LAST-ACK",
    [TCP_LISTEN] = "LISTEN",
    [TCP_CLOSING] = "CLOSING"
};

static char *inet_diag_op_code_str[] = {
	"INET_DIAG_BC_NOP",
	"INET_DIAG_BC_JMP",
	"INET_DIAG_BC_S_GE",
	"INET_DIAG_BC_S_LE",
	"INET_DIAG_BC_D_GE",
	"INET_DIAG_BC_D_LE",
	"INET_DIAG_BC_AUTO",
	"INET_DIAG_BC_S_COND",
	"INET_DIAG_BC_D_COND",
	"INET_DIAG_BC_DEV_COND",
	"INET_DIAG_BC_MARK_COND"
};

struct tcp_closer_ctx {
    struct inet_diag_bc_op *diag_filter;

    uint32_t diag_filter_len;
    int32_t diag_dump_socket;
    int32_t diag_req_socket;

    bool verbose_mode;
    bool use_netlink;
};

#endif
