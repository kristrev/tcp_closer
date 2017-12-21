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
#include <dirent.h>
#include <signal.h>

#include <libmnl/libmnl.h>

#include "tcp_closer.h"

static int send_diag_msg(struct tcp_closer_ctx *ctx)
{
    uint8_t diag_buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;
    struct inet_diag_req_v2 *diag_req;

    nlh = mnl_nlmsg_put_header(diag_buf);
    nlh->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
    nlh->nlmsg_type = SOCK_DIAG_BY_FAMILY;

    diag_req = mnl_nlmsg_put_extra_header(nlh, sizeof(struct inet_diag_req_v2));
    //TODO: Add a -4/-6 command line option
    diag_req->sdiag_family = AF_INET;
    diag_req->sdiag_protocol = IPPROTO_TCP;

    //We are only interested in established connections and need the tcp-info
    //struct
    diag_req->idiag_ext |= (1 << (INET_DIAG_INFO - 1));
    diag_req->idiag_states = 1 << TCP_ESTABLISHED;

    mnl_attr_put(nlh, INET_DIAG_REQ_BYTECODE, ctx->diag_filter_len, ctx->diag_filter);

    return mnl_socket_sendto(ctx->diag_dump_socket, diag_buf, nlh->nlmsg_len);
}

static void destroy_socket(struct tcp_closer_ctx *ctx, struct inet_diag_msg *diag_msg)
{
    uint8_t destroy_buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;
    struct inet_diag_req_v2 *destroy_req;

    nlh = mnl_nlmsg_put_header(destroy_buf);
    nlh->nlmsg_type = SOCK_DESTROY;
    //TODO: Add ACK so we can output some sensible error messages
    nlh->nlmsg_flags = NLM_F_REQUEST;

    destroy_req = mnl_nlmsg_put_extra_header(nlh, sizeof(struct inet_diag_req_v2));
    //TODO: Add 4/6 flag to command line
    destroy_req->sdiag_family = diag_msg->idiag_family;
    destroy_req->sdiag_protocol = IPPROTO_TCP;

    //Copy ID from diag_msg returned by kernel
    destroy_req->id = diag_msg->id;

    mnl_socket_sendto(ctx->diag_destroy_socket, destroy_buf, nlh->nlmsg_len);
}

static void destroy_socket_proc(uint32_t inode_org)
{
    //Length of /proc/strlen(uint64_max)/fd/d_name (d_name is 256, inc. \0)
    char dir_buf[286];
    char link_buf[255] = {0};
    char *inode_str;
    struct dirent *lDirEnt;
    DIR *lProcDir, *lProcFdDir;
    uint64_t pid;
    uint32_t inode;

    lProcDir = opendir("/proc");

    if (!lProcDir) {
        fprintf(stderr, "Failed to open /proc\n");
        return;
    }

    while ((lDirEnt = readdir(lProcDir))) {
        pid = (uint64_t) atoll(lDirEnt->d_name);

        if (!pid) {
            continue;
        }

        snprintf(dir_buf, sizeof(dir_buf), "/proc/%lu/fd", pid);

        lProcFdDir = opendir(dir_buf);

        if (!lProcFdDir) {
            fprintf(stderr, "Failed to open: %s. Error: %s (%d)\n", dir_buf,
                    strerror(errno), errno);
            continue;
        }

        while ((lDirEnt = readdir(lProcFdDir))) {
            if (lDirEnt->d_type != DT_LNK) {
                continue;
            }

            snprintf(dir_buf, sizeof(dir_buf), "/proc/%lu/fd/%s", pid,
                    lDirEnt->d_name);

            memset(link_buf, 0, sizeof(link_buf));
            if (readlink(dir_buf, link_buf, sizeof(link_buf)) <= 0) {
                fprintf(stderr, "Failed to read link %s. Error: %s (%d)\n",
                        dir_buf, strerror(errno), errno);
                continue;
            }

            //All sockets start with socket
            if (strncmp(link_buf, "socket", strlen("socket"))) {
                continue;
            }

            //we know that format is socket:[<inode>]
            inode_str = strstr(link_buf, "[") + 1;
            link_buf[strlen(link_buf) - 1] = '\0';

            inode = atoi(inode_str);

            if (inode != inode_org) {
                continue;
            }

            fprintf(stdout, "Will kill PID %lu\n", pid);
            kill(pid, SIGKILL);

            //No need to check any other link in this folder, we have killed
            //the process
            break;
        }

        closedir(lProcFdDir);
    }

    closedir(lProcDir);
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
    } else {
        inet_ntop(AF_INET6, (struct in_addr6*) &(diag_msg->id.idiag_src),
                local_addr_buf, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, (struct in_addr6*) &(diag_msg->id.idiag_dst),
                remote_addr_buf, INET6_ADDRSTRLEN);
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
        break;
    }

    //No need to check for tcpi, if it could not be attached then message would
    //not be send from kernel

    if (ctx->verbose_mode) {
        fprintf(stdout, "Found connection:\nUser: %s (UID: %u) Src: %s:%d Dst: %s:%d\n",
                uid_info == NULL ? "Not found" : uid_info->pw_name,
                diag_msg->idiag_uid, local_addr_buf, ntohs(diag_msg->id.idiag_sport),
                remote_addr_buf, ntohs(diag_msg->id.idiag_dport));
        fprintf(stdout, "\tState: %s RTT: %gms (var. %gms) "
                "Recv. RTT: %gms Snd_cwnd: %u/%u "
                "Last_data_recv: %ums ago\n",
                tcp_states_map[tcpi->tcpi_state],
                (double) tcpi->tcpi_rtt/1000,
                (double) tcpi->tcpi_rttvar/1000,
                (double) tcpi->tcpi_rcv_rtt/1000,
                tcpi->tcpi_unacked,
                tcpi->tcpi_snd_cwnd,
                tcpi->tcpi_last_data_recv);
    }

    //tcp_last_ack_recv can be updated by for example a proxy replying to TCP
    //keep-alives, so we only check tcpi_last_data_recv. This timer keeps track
    //of actual data going through the connection
    if (ctx->idle_time && tcpi->tcpi_last_data_recv < ctx->idle_time) {
        return;
    }

    fprintf(stdout, "Will destroy src: %s:%d dst: %s:%d last_data_recv: %ums\n",
            local_addr_buf, ntohs(diag_msg->id.idiag_sport),  remote_addr_buf,
            ntohs(diag_msg->id.idiag_dport), tcpi->tcpi_last_data_recv);

    if (ctx->use_netlink) {
        destroy_socket(ctx, diag_msg);
    } else {
        destroy_socket_proc(diag_msg->idiag_inode);
    }
}

static int32_t recv_diag_msg(struct tcp_closer_ctx *ctx)
{
    struct nlmsghdr *nlh;
    struct nlmsgerr *err;
    uint8_t recv_buf[MNL_SOCKET_BUFFER_SIZE];
    struct inet_diag_msg *diag_msg;
    int32_t numbytes, rtalen;

    while(1){
        numbytes = mnl_socket_recvfrom(ctx->diag_dump_socket, recv_buf, sizeof(recv_buf));
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
        {"idle_time",   required_argument,  NULL,   't'},
        {"verbose",     no_argument,        NULL,   'v'},
        {"help",        required_argument,  NULL,   'h'},
        {"use_proc",    no_argument,        NULL,    0 },
        {0,             0,                  0,       0 }
    };

    while (!error && (opt = getopt_long(argc, argv, "s:d:t:vh", long_options,
                                        &option_index)) != -1) {
        switch (opt) {
        case 0:
            //TODO: When we add more arguments with only a long option, we will
            //split handling long options into a separate function
            if (!strcmp("use_proc", long_options[option_index].name)) {
                ctx->use_netlink = false;
            }
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
        case 't':
            if (!atoi(optarg)) {
                fprintf(stderr, "Found invalid idle time (value %s)\n",
                        optarg);
                error = true;
            } else {
                ctx->idle_time = atoi(optarg);
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
    fprintf(stdout, "\t-t/--idle_time : limit for time since connection last received data (in ms)."
            " Defaults to 0, which means that all connections matching sport/dport will be "
            "destroyed\n");
    fprintf(stdout, "\t-v/--verbose : More verbose output\n");
    fprintf(stdout, "\t-h/--help : This output\n");
    fprintf(stdout, "\t--use_proc : Find inode in proc + kill instead of using SOCK_DESTROY\n");
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

    ctx->use_netlink = true;

    if (!(ctx->diag_dump_socket = mnl_socket_open(NETLINK_INET_DIAG))) {
        fprintf(stderr, "Failed to create inet_diag dump socket. Error: %s (%u)\n",
                strerror(errno), errno);
        return 1;
    }

    if (!(ctx->diag_destroy_socket = mnl_socket_open(NETLINK_INET_DIAG))) {
        fprintf(stderr, "Failed to create inet_diag dump socket. Error: %s (%u)\n",
                strerror(errno), errno);
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

    fprintf(stdout, "# source ports: %u # destination ports: %u idle time: %ums\n", num_sport,
            num_dport, ctx->idle_time);

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
