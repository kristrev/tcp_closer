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
};

#endif
