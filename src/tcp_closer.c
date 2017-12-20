#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include <linux/in.h>
#include <linux/sock_diag.h>
#include <pwd.h>
#include <linux/tcp.h>

#include "tcp_closer.h"

static int send_diag_msg(struct tcp_closer_ctx *ctx)
{
    struct msghdr msg = {0};
    struct nlmsghdr nlh = {0};
    struct inet_diag_req_v2 conn_req = {0};
    struct sockaddr_nl sa = {0};
    struct iovec iov[4];
    int retval = 0;
    struct rtattr rta = {0};

    //No need to specify groups or pid. This message only has one receiver and
    //pid 0 is kernel
    sa.nl_family = AF_NETLINK;

    //TODO: Provide this as a flag to the application, 4, 6 or both
    conn_req.sdiag_family = AF_INET;
    //We only care about TCP
    conn_req.sdiag_protocol = IPPROTO_TCP;

    //We are only interested in established connections
    conn_req.idiag_states = 1 << TCP_ESTABLISHED;

    //Request extended TCP information (it is the tcp_info struct)
    conn_req.idiag_ext |= (1 << (INET_DIAG_INFO - 1));

    nlh.nlmsg_len = NLMSG_LENGTH(sizeof(conn_req));
    nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST | NLM_F_ACK;
    nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;

    memset(&rta, 0, sizeof(rta));
    rta.rta_type = INET_DIAG_REQ_BYTECODE;
    rta.rta_len = RTA_LENGTH(ctx->diag_filter_len);
    nlh.nlmsg_len += rta.rta_len;

    iov[0] = (struct iovec) {&nlh, sizeof(nlh)};
    iov[1] = (struct iovec) {&conn_req, sizeof(conn_req)};
    iov[2] = (struct iovec) {&rta, sizeof(rta)};
    iov[3] = (struct iovec) {ctx->diag_filter, ctx->diag_filter_len};

    msg.msg_name = (void*) &sa;
    msg.msg_namelen = sizeof(sa);
    msg.msg_iov = iov;
    msg.msg_iovlen = 4;

    retval = sendmsg(ctx->diag_dump_socket, &msg, 0);

    return retval;
}

static void destroy_socket(struct tcp_closer_ctx *ctx, struct inet_diag_msg *diag_msg)
{
    struct msghdr msg = {0};
    struct nlmsghdr nlh = {0};
    struct inet_diag_req_v2 destroy_req = {0};
    struct sockaddr_nl sa = {0};
    struct iovec iov[2];

    nlh.nlmsg_type = SOCK_DESTROY;
    //Destroying a socket is best-effort only, so no need for ACK
    nlh.nlmsg_flags = NLM_F_REQUEST;
    nlh.nlmsg_len = NLMSG_LENGTH(sizeof(destroy_req));

    //TODO: Add 4/6 flag to command line
    destroy_req.sdiag_family = diag_msg->idiag_family;
    destroy_req.sdiag_protocol = IPPROTO_TCP;

    //Copy ID from kernel message
    destroy_req.id = diag_msg->id;

    sa.nl_family = AF_NETLINK;

    iov[0] = (struct iovec) {&nlh, sizeof(nlh)};
    iov[1] = (struct iovec) {&destroy_req, sizeof(destroy_req)};

    msg.msg_name = (void*) &sa;
    msg.msg_namelen = sizeof(sa);
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;

    sendmsg(ctx->diag_req_socket, &msg, 0);
}

static void parse_diag_msg(struct tcp_closer_ctx *ctx, struct inet_diag_msg *diag_msg, int rtalen)
{
    struct rtattr *attr;
    struct tcp_info *tcpi;
    char local_addr_buf[INET6_ADDRSTRLEN];
    char remote_addr_buf[INET6_ADDRSTRLEN];
    struct passwd *uid_info = NULL;

    memset(local_addr_buf, 0, sizeof(local_addr_buf));
    memset(remote_addr_buf, 0, sizeof(remote_addr_buf));

    //(Try to) Get user info
    uid_info = getpwuid(diag_msg->idiag_uid);

    if(diag_msg->idiag_family == AF_INET){
        inet_ntop(AF_INET, (struct in_addr*) &(diag_msg->id.idiag_src), 
            local_addr_buf, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, (struct in_addr*) &(diag_msg->id.idiag_dst), 
            remote_addr_buf, INET_ADDRSTRLEN);
    } else if(diag_msg->idiag_family == AF_INET6){
        inet_ntop(AF_INET6, (struct in_addr6*) &(diag_msg->id.idiag_src),
                local_addr_buf, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, (struct in_addr6*) &(diag_msg->id.idiag_dst),
                remote_addr_buf, INET6_ADDRSTRLEN);
    } else {
        fprintf(stderr, "Unknown family\n");
        return;
    }

    if(local_addr_buf[0] == 0 || remote_addr_buf[0] == 0){
        fprintf(stderr, "Could not get required connection information\n");
        return;
    } else {
        fprintf(stdout, "User: %s (UID: %u) Src: %s:%d Dst: %s:%d\n", 
                uid_info == NULL ? "Not found" : uid_info->pw_name,
                diag_msg->idiag_uid,
                local_addr_buf, ntohs(diag_msg->id.idiag_sport), 
                remote_addr_buf, ntohs(diag_msg->id.idiag_dport));
    }

    attr = (struct rtattr*) (diag_msg+1);

    while(RTA_OK(attr, rtalen)){
        if (attr->rta_type != INET_DIAG_INFO) {
            attr = RTA_NEXT(attr, rtalen); 
            continue;
        }

        //The payload of this attribute is a tcp_info-struct, so it is
        //ok to cast
        tcpi = (struct tcp_info*) RTA_DATA(attr);

        //Output some sample data
        fprintf(stdout, "\tState: %s RTT: %gms (var. %gms) "
                "Recv. RTT: %gms Snd_cwnd: %u/%u "
                "Last_data_recv: %.2fsec ago Last_ack_recv %.2fsec ago\n",
                tcp_states_map[tcpi->tcpi_state],
                (double) tcpi->tcpi_rtt/1000,
                (double) tcpi->tcpi_rttvar/1000,
                (double) tcpi->tcpi_rcv_rtt/1000,
                tcpi->tcpi_unacked,
                tcpi->tcpi_snd_cwnd,
                (double) tcpi->tcpi_last_data_recv/1000,
                (double) tcpi->tcpi_last_ack_recv/1000);
        break;
    }

    destroy_socket(ctx, diag_msg);
}

static int32_t recv_diag_msg(struct tcp_closer_ctx *ctx)
{
    struct nlmsghdr *nlh;
    struct nlmsgerr *err;
    uint8_t recv_buf[SOCKET_BUFFER_SIZE];
    struct inet_diag_msg *diag_msg;
    int32_t numbytes, rtalen;

    while(1){
        numbytes = recv(ctx->diag_dump_socket, recv_buf, sizeof(recv_buf), 0);
        nlh = (struct nlmsghdr*) recv_buf;

        while(NLMSG_OK(nlh, numbytes)){
            if(nlh->nlmsg_type == NLMSG_DONE) {
                return 0;
            }

            if(nlh->nlmsg_type == NLMSG_ERROR){
                err = NLMSG_DATA(nlh);

                if (err->error) {
                    fprintf(stderr, "Error in netlink message: %s (%u)\n",
                            strerror(-err->error), -err->error);
                    return 1;
                }
            }

            diag_msg = (struct inet_diag_msg*) NLMSG_DATA(nlh);
            rtalen = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*diag_msg));
            parse_diag_msg(ctx, diag_msg, rtalen);

            nlh = NLMSG_NEXT(nlh, numbytes);
        }
    }
}

static void output_filter(struct tcp_closer_ctx *ctx)
{
    uint16_t num_ops = ctx->diag_filter_len / sizeof(struct inet_diag_bc_op);
    uint16_t i;

    fprintf(stdout, "Content of INET_DIAG filter:\n");
    for (i = 0; i < num_ops; i++) {
        fprintf(stdout, "diag_filter[%u]->code = %s\n", i,
                inet_diag_op_code_str[ctx->diag_filter[i].code]);
        fprintf(stdout, "diag_filter[%u]->yes = %u\n", i,
                ctx->diag_filter[i].yes);
        fprintf(stdout, "diag_filter[%u]->no = %u\n", i,
                ctx->diag_filter[i].no);
        fprintf(stdout, "\n");
    }
}

static void create_filter(int argc, char *argv[], struct tcp_closer_ctx *ctx,
                          uint16_t num_sport, uint16_t num_dport)
{
    //Destination ports are always stored after source ports in our buffer
    struct inet_diag_bc_op *diag_sports = ctx->diag_filter;
    struct inet_diag_bc_op *diag_dports = ctx->diag_filter +
                                          (num_sport ? ((num_sport - 1) * 5) + 4 : 0);

    uint16_t diag_sports_idx = 0, diag_dports_idx = 0, diag_sports_num = 1,
             diag_dports_num = 1;

    //Value used by the generic part of the function
    struct inet_diag_bc_op *diag_cur_ops;
    uint16_t *diag_cur_idx, *diag_cur_num, diag_cur_count, left_of_filter;
    uint8_t code_ge, code_le;

    int opt;
    struct option long_options[] = {
        {"sport",   required_argument, NULL,   's'},
        {"dport",   required_argument, NULL,   'd'},
        {0,         0,                  0,       0 }
    };

    //According to the getopt man-page, this is the correct way to trigger a
    //reset of the variables/values used by getopt_long.
    optind = 0;
    //Do not log errors. We only care about sport/dport here, so there might be
    //"unknown" options that will trigger ouput and confuse user. We also know
    //all options are correct, parse_cmdargs() does the validation
    opterr = 0;

    while ((opt = getopt_long(argc, argv, "s:d:", long_options, NULL)) != -1) {
        if (opt != 's' && opt != 'd') {
            continue;
        }

        if (opt == 's') {
            code_ge = INET_DIAG_BC_S_GE;
            code_le = INET_DIAG_BC_S_LE;
            diag_cur_ops = diag_sports;
            diag_cur_idx = &diag_sports_idx;
            diag_cur_num = &diag_sports_num;
            diag_cur_count = num_sport;
        } else {
            code_ge = INET_DIAG_BC_D_GE;
            code_le = INET_DIAG_BC_D_LE;
            diag_cur_ops = diag_dports;
            diag_cur_idx = &diag_dports_idx;
            diag_cur_num = &diag_dports_num;
            diag_cur_count = num_dport;
        }

        //Create the greater than operation. The only interesting thing
        //going on is the value of no. If this is the last sport and
        //we don't match, we should abort loop. Thus, we set it to 0xFFFF to
        //ensure that len will be negative
        diag_cur_ops[*diag_cur_idx].code = code_ge;
        diag_cur_ops[*diag_cur_idx].yes = sizeof(struct inet_diag_bc_op) * 2;
        diag_cur_ops[*diag_cur_idx].no = *diag_cur_num == diag_cur_count ?
                                         0 :
                                         sizeof(struct inet_diag_bc_op) * 5;
        diag_cur_ops[(*diag_cur_idx) + 1].code = INET_DIAG_BC_NOP;
        diag_cur_ops[(*diag_cur_idx) + 1].yes = sizeof(struct inet_diag_bc_op);
        diag_cur_ops[(*diag_cur_idx) + 1].no = atoi(optarg);

        //Same as above. Here, yes is interesting. We can jump straight to
        //dports. This means offset is sizeof() * 2 to pass this block.
        //Then, we add sizeof() * 4 * (num_sport - diag_sports_num) to pass
        //rest of sport comparisons
        diag_cur_ops[(*diag_cur_idx) + 2].code = code_le;
        diag_cur_ops[(*diag_cur_idx) + 2].yes = sizeof(struct inet_diag_bc_op) * 2;
        diag_cur_ops[(*diag_cur_idx) + 2].no = *diag_cur_num == diag_cur_count ?
                                               0 :
                                               sizeof(struct inet_diag_bc_op) * 3;
        diag_cur_ops[(*diag_cur_idx) + 3].code = INET_DIAG_BC_NOP;
        diag_cur_ops[(*diag_cur_idx) + 3].yes = sizeof(struct inet_diag_bc_op);
        diag_cur_ops[(*diag_cur_idx) + 3].no = atoi(optarg);

        if (*diag_cur_num != diag_cur_count) {
            diag_cur_ops[(*diag_cur_idx) + 4].code = INET_DIAG_BC_JMP;
            diag_cur_ops[(*diag_cur_idx) + 4].yes = sizeof(struct inet_diag_bc_op);

            //Logic behind this calculation is as follows. If we hit a JMP, we
            //want to skip all the remaining operations of this type. All
            //comparisons block, except the last one, contains a JMP op. The
            //last block does not need a JMP op, since we will either fail and
            //jump to the end (no can have any offset) or continue with
            //comparisons/finish if we match.
            //
            //The offset for any jump block is sizeof() * (num_left - 1) * 5 +
            //sizeof() * 4 + sizeof(). First part all all normal blocks, second
            //is the size of the last block and third is this struct
            diag_cur_ops[(*diag_cur_idx) + 4].no = sizeof(struct inet_diag_bc_op) +
                                                   ((diag_cur_count - *diag_cur_num - 1) * sizeof(struct inet_diag_bc_op) * 5) +
                                                   sizeof(struct inet_diag_bc_op) * 4;
            (*diag_cur_idx) += 5;
        } else {
            (*diag_cur_idx) += 4;
        }

        (*diag_cur_num) += 1;
    }

    if (num_sport) {
        diag_sports_idx -= 4;
        if (num_dport) {
            left_of_filter = ((num_dport - 1) * sizeof(struct inet_diag_bc_op) * 5) +
                             sizeof(struct inet_diag_bc_op) * 4;
        } else {
            left_of_filter = 0;
        }

        diag_sports[diag_sports_idx].no = left_of_filter +
                                          sizeof(struct inet_diag_bc_op) * 4
                                          + 4;
        diag_sports[diag_sports_idx + 2].no = left_of_filter +
                                              sizeof(struct inet_diag_bc_op) * 2
                                              + 4;
    }

    if (num_dport) {
        diag_dports_idx -= 4;

        diag_dports[diag_dports_idx].no = (sizeof(struct inet_diag_bc_op) * 4) + 4;
        diag_dports[diag_dports_idx + 2].no = (sizeof(struct inet_diag_bc_op) * 2) + 4;
    }
}

//Counts config ports and returns false if any unknown options is found
static bool parse_cmdargs(int argc, char *argv[], uint16_t *num_sport,
                          uint16_t *num_dport, struct tcp_closer_ctx *ctx)
{
    int opt, option_index;
    bool error = false;

    struct option long_options[] = {
        {"sport",       required_argument,  NULL,   's'},
        {"dport",       required_argument,  NULL,   'd'},
        {"verbose",     no_argument,        NULL,   'v'},
        {"help",        required_argument,  NULL,   'h'},
        {"kill_only",   no_argument,        NULL,    0 },   
        {0,             0,                  0,       0 }
    };

    while (!error && (opt = getopt_long(argc, argv, "s:d:vh", long_options,
                                        &option_index)) != -1) {
        switch (opt) {
        case 0:
            fprintf(stdout, "Got option %s\n", long_options[option_index].name);
            break;
        case 's':
            if (!atoi(optarg)) {
                fprintf(stderr, "Found invalid source port (value %s)\n",
                        optarg);
                error = true;
            } else {
                (*num_sport)++;
            }
            break;
        case 'd':
            if (!atoi(optarg)) {
                fprintf(stderr, "Found invalid destination port (value %s)\n",
                        optarg);
                error = true;
            } else {
                (*num_dport)++;
            }
            break;
        case 'v':
            ctx->verbose_mode = true;
            break;
        case 'h':
        default:
            error = true;
            break;
        }

        //Perform limit check here to prevent a potential overflow when we
        //create the buffers. A malicious user could for example provide 0xFFFF
        //+ 1 source ports. If we do the check after loop, we would read number
        //of source ports as one. However, when we create the filter, we will
        //iterate over the arguments again and would then try to fit comparing
        //0xFFFF + 1 ports into a buffer meant for one
        if ((*num_sport + *num_dport) > MAX_NUM_PORTS) {
            fprintf(stderr, "Number of ports (%u) exceeded limit (%u)\n",
                *num_sport + *num_dport, MAX_NUM_PORTS);
            error = true;
            break;
        }
    }

    return !error;
}

static void show_help()
{
    fprintf(stdout, "Following arguments are supported:\n");
    fprintf(stdout, "\t-s/--sport : source port to match\n");
    fprintf(stdout, "\t-d/--dport : destionation port to match\n");
    fprintf(stdout, "\t-v/--verbose : More verbose output\n");
    fprintf(stdout, "\t-h/--help : This output\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "At least one source or destination port must be given.\n"
                    "We will kill connections where the source port is one of\n"
                    "the given source port(s) (if any), and the destination\n"
                    "port one of the given destination port(s) (if any).\n\n");
    fprintf(stdout, "Maximum number of ports (combined) is %u.\n",
            MAX_NUM_PORTS);
}

int main(int argc, char *argv[])
{
    struct tcp_closer_ctx *ctx = NULL;
    uint16_t num_sport = 0, num_dport = 0;

    //Parse options, so far it just to get sport and dport
    if (argc < 2) {
        show_help();
        return 1;
    }

    ctx = calloc(sizeof(struct tcp_closer_ctx), 1);
    if (!ctx) {
        fprintf(stderr, "Failed to allocate memory for context-object\n");
        return 1;
    }

    //Parse options and count number of source ports/destination ports. We need
    //to know the count before we create the filter, so that we can compute the
    //correct offset for the different operations, etc.
    if (!parse_cmdargs(argc, argv, &num_sport, &num_dport, ctx)) {
        show_help();
        return 1;
    }

    if (!num_sport && !num_dport) {
        fprintf(stderr, "No ports given\n");
        return 1;
    }

    fprintf(stdout, "# source ports: %u # destination ports: %u\n", num_sport,
            num_dport);

    if((ctx->diag_dump_socket = socket(AF_NETLINK, SOCK_DGRAM,
                                       NETLINK_INET_DIAG)) == -1) {
        fprintf(stderr, "Creating dump socket failed with error %s (%u)\n",
                strerror(errno), errno);
        return 1;
    }

    if((ctx->diag_req_socket = socket(AF_NETLINK, SOCK_DGRAM,
                                      NETLINK_INET_DIAG)) == -1) {
        fprintf(stderr, "Creating request socket failed with error %s (%u)\n",
                strerror(errno), errno);
        return 1;
    }

    //Since there is no equal operator, a port comparison will requires five
    //bc_op-structs. Two for LE (since ports is kept in a second struct), two
    //for GE and one for JMP

    if (num_sport) {
        ctx->diag_filter_len += sizeof(struct inet_diag_bc_op) * 5 * (num_sport - 1) +
                                sizeof(struct inet_diag_bc_op) * 4;
    }

    if (num_dport) {
        ctx->diag_filter_len += sizeof(struct inet_diag_bc_op) * 5 * (num_dport - 1) +
                                sizeof(struct inet_diag_bc_op) * 4;
    }

    ctx->diag_filter = calloc(ctx->diag_filter_len, 1);
    if (!ctx->diag_filter) {
        fprintf(stderr, "Failed to allocate memory for filter\n");
        return 1;
    }

    create_filter(argc, argv, ctx, num_sport, num_dport);

    if (ctx->verbose_mode) {
        output_filter(ctx);
    }

    if (send_diag_msg(ctx) < 0) {
        fprintf(stderr, "Sending diag message failed with %s (%u)\n",
                strerror(errno), errno);
        return 1;
    }

    return recv_diag_msg(ctx);
}
