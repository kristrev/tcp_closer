#ifndef TCP_CLOSER_NETLINK_H
#define TCP_CLOSER_NETLINK_H

//There are currently 11 states, but the first state is stored in pos. 1.
//Therefore, I need a 12 bit bitmask
#define TCPF_ALL 0xFFF

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

struct tcp_closer_ctx;
struct inet_diag_msg;

int send_diag_msg(struct tcp_closer_ctx *ctx);
void destroy_socket(struct tcp_closer_ctx *ctx, struct inet_diag_msg *diag_msg);
int32_t recv_diag_msg(struct tcp_closer_ctx *ctx);

#endif
