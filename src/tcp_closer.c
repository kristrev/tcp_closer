/*
 * Copyright 2017 Kristian Evensen <kristian.evensen@gmail.com>
 *
 * This file is part of TCP closer. TCP closer is free software: you can
 * redistribute it and/or modify it under the terms of the Lesser GNU General
 * Public License as published by the Free Software Foundation, either version 3
 * of the License, or (at your option) any later version.
 *
 * TCP closer is distributed in the hope that it will be useful, but WITHOUT ANY
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
#include <linux/inet_diag.h>
#include <libmnl/libmnl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/file.h>

#include "tcp_closer.h"
#include "tcp_closer_netlink.h"
#include "backend_event_loop.h"
#include "tcp_closer_log.h"

static void show_help();

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

static void dump_timeout_cb(void *ptr)
{
    struct tcp_closer_ctx *ctx = ptr;

    //Check if dump is in progress

    if (ctx->dump_in_progress) {
        TCP_CLOSER_PRINT_SYSLOG(ctx, LOG_INFO, "Dump in progress\n");
        //Start some shorter interval?
        return;
    }

    if (send_diag_msg(ctx) < 0) {
        TCP_CLOSER_PRINT_SYSLOG(ctx, LOG_ERR, "Sending diag message failed "
                                "with %s (%u)\n", strerror(errno), errno);
        //Start some shorter interval?
    }

    ctx->dump_in_progress = true;
}

static void output_filter(struct tcp_closer_ctx *ctx)
{
    uint16_t num_ops = ctx->diag_filter_len / sizeof(struct inet_diag_bc_op);
    uint16_t i;

    TCP_CLOSER_PRINT_SYSLOG(ctx, LOG_DEBUG, "Content of INET_DIAG filter:\n");
    for (i = 0; i < num_ops; i++) {
        TCP_CLOSER_PRINT_SYSLOG(ctx, LOG_DEBUG, "diag_filter[%u]->code = %s\n",
                                i,
                                inet_diag_op_code_str[ctx->diag_filter[i].code]);
        TCP_CLOSER_PRINT_SYSLOG(ctx, LOG_DEBUG, "diag_filter[%u]->yes = %u\n",
                                i, ctx->diag_filter[i].yes);
        TCP_CLOSER_PRINT_SYSLOG(ctx, LOG_DEBUG, "diag_filter[%u]->no = %u\n", i,
                                ctx->diag_filter[i].no);
        TCP_CLOSER_PRINT_SYSLOG(ctx, LOG_DEBUG, "\n");
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
        {"sport",           required_argument,  NULL,   's'},
        {"dport",           required_argument,  NULL,   'd'},
        {"idle_time",       required_argument,  NULL,   't'},
        {"interval",        required_argument,  NULL,   'i'},
        {"verbose",         no_argument,        NULL,   'v'},
        {"help",            required_argument,  NULL,   'h'},
        {"use_proc",        no_argument,        NULL,    0 },
        {"disable_syslog",  no_argument,        NULL,    0 },
        {0,                 0,                  0,       0 }
    };

    while (!error && (opt = getopt_long(argc, argv, "s:d:t:i:vh", long_options,
                                        &option_index)) != -1) {
        switch (opt) {
        case 0:
            //TODO: When we add more arguments with only a long option, we will
            //split handling long options into a separate function
            if (!strcmp("use_proc", long_options[option_index].name)) {
                ctx->use_netlink = false;
            } else if (!strcmp("disable_syslog",
                               long_options[option_index].name)) {
                ctx->use_syslog = false;
            }

            break;
        case 's':
            if (!atoi(optarg)) {
                TCP_CLOSER_PRINT_SYSLOG(ctx, LOG_ERR, "Found invalid source "
                                        "port (value %s)\n", optarg);
                error = true;
            } else {
                (*num_sport)++;
            }
            break;
        case 'd':
            if (!atoi(optarg)) {
                TCP_CLOSER_PRINT_SYSLOG(ctx, LOG_ERR, "Found invalid "
                                        "destination port (value %s)\n",
                                        optarg);
                error = true;
            } else {
                (*num_dport)++;
            }
            break;
        case 't':
            if (!atoi(optarg)) {
                TCP_CLOSER_PRINT_SYSLOG(ctx, LOG_ERR, "Found invalid idle time "
                                        "(value %s)\n", optarg);
                error = true;
            } else {
                ctx->idle_time = atoi(optarg);
            }
            break;
        case 'i':
            if (!atoi(optarg)) {
                TCP_CLOSER_PRINT_SYSLOG(ctx, LOG_ERR, "Found invalid dump "
                                        "interval (value %s)\n", optarg);
            } else {
                ctx->dump_interval = atoi(optarg);
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
            TCP_CLOSER_PRINT_SYSLOG(ctx, LOG_ERR, "Number of ports (%u) "
                                    "exceeded limit (%u)\n", 
                                    *num_sport + *num_dport, MAX_NUM_PORTS);
            error = true;
            break;
        }
    }

    return !error;
}

static bool configure(struct tcp_closer_ctx *ctx, int argc, char *argv[])
{
    uint16_t num_sport = 0, num_dport = 0;

    if (!(ctx->event_loop = backend_event_loop_create())) {
        TCP_CLOSER_PRINT_SYSLOG(ctx, LOG_ERR, "Failed to create event loop\n");
        return false;
    }

    if (!(ctx->diag_dump_socket = mnl_socket_open(NETLINK_INET_DIAG))) {
        TCP_CLOSER_PRINT_SYSLOG(ctx, LOG_ERR, "Failed to create inet_diag dump "
                                "socket. Error: %s (%u)\n", strerror(errno),
                                errno);
        return false;
    }

    if (!(ctx->diag_destroy_socket = mnl_socket_open(NETLINK_INET_DIAG))) {
        TCP_CLOSER_PRINT_SYSLOG(ctx, LOG_ERR, "Failed to create inet_diag dump "
                                "socket. Error: %s (%u)\n", strerror(errno),
                                errno);
        return false;
    }

    mnl_socket_bind(ctx->diag_dump_socket, 0, MNL_SOCKET_AUTOPID);
    mnl_socket_bind(ctx->diag_destroy_socket, 0, MNL_SOCKET_AUTOPID);

    if (!(ctx->dump_handle = backend_create_epoll_handle(ctx,
                                                         mnl_socket_get_fd(ctx->diag_dump_socket),
                                                         recv_diag_msg))) {
        TCP_CLOSER_PRINT_SYSLOG(ctx, LOG_ERR, "Failed to create diag dump "
                                "epoll handle\n");
        return false;
    }

    //Set clock to 0 so we send first dump request right away
    if (!(ctx->dump_timeout = backend_event_loop_create_timeout(0,
                                                                dump_timeout_cb,
                                                                ctx, 0))) {
        TCP_CLOSER_PRINT_SYSLOG(ctx, LOG_ERR, "Failed to create dump "
                                "timeout\n");
        return false;
    }
    backend_insert_timeout(ctx->event_loop, ctx->dump_timeout);

    if (!(ctx->destroy_handle = backend_create_epoll_handle(ctx,
                                                            mnl_socket_get_fd(ctx->diag_destroy_socket),
                                                            recv_destroy_msg))) {
        TCP_CLOSER_PRINT_SYSLOG(ctx, LOG_ERR, "Failed to create diag dump "
                                "epoll handle\n");
        return false;
    }

    //Parse options and count number of source ports/destination ports. We need
    //to know the count before we create the filter, so that we can compute the
    //correct offset for the different operations, etc.
    if (!parse_cmdargs(argc, argv, &num_sport, &num_dport, ctx)) {
        show_help();
        return false;
    }

    if (!num_sport && !num_dport) {
        TCP_CLOSER_PRINT_SYSLOG(ctx, LOG_ERR, "No ports given\n");
        return false;
    }

    if (ctx->dump_interval) {
        ctx->dump_timeout->intvl = ctx->dump_interval * 1000;
    }

    TCP_CLOSER_PRINT_SYSLOG(ctx, LOG_INFO, "# source ports: %u # destination "
                            "ports: %u idle time: %ums interval: %usec\n",
                            num_sport, num_dport, ctx->idle_time,
                            ctx->dump_interval);

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
        TCP_CLOSER_PRINT_SYSLOG(ctx, LOG_ERR, "Failed to allocate memory for "
                                "filter\n");
        return false;
    }

    create_filter(argc, argv, ctx, num_sport, num_dport);

    return true;
}

static void show_help()
{
    fprintf(stdout, "Following arguments are supported:\n");
    fprintf(stdout, "\t-s/--sport : source port to match\n");
    fprintf(stdout, "\t-d/--dport : destionation port to match\n");
    fprintf(stdout, "\t-t/--idle_time : limit for time since connection last "
            "received data (in ms). Defaults to 0, which means that all "
            "connections matching sport/dport will be destroyed\n");
    fprintf(stdout, "\t-i/--interval : how often to poll for sockets matching "
            "sport(s)/dport(s) (in sec). If not provded, sockets will be polled "
            "once and then tcp_closer will exit\n");
    fprintf(stdout, "\t-v/--verbose : More verbose output\n");
    fprintf(stdout, "\t-h/--help : This output\n");
    fprintf(stdout, "\t--use_proc : Find inode in proc + kill instead of using "
            "SOCK_DESTROY\n");
    fprintf(stdout, "\t--disable_syslog : Do not write log messages to syslog\n");
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
    ctx->logfile = stderr;
    ctx->use_syslog = true;

    if (!configure(ctx, argc, argv)) {
        return 1;
    }

    if (ctx->verbose_mode) {
        output_filter(ctx);
    }

    backend_event_loop_update(ctx->event_loop, EPOLLIN, EPOLL_CTL_ADD,
                              mnl_socket_get_fd(ctx->diag_dump_socket),
                              ctx->dump_handle);

    backend_event_loop_update(ctx->event_loop, EPOLLIN, EPOLL_CTL_ADD,
                              mnl_socket_get_fd(ctx->diag_destroy_socket),
                              ctx->destroy_handle);

    backend_event_loop_run(ctx->event_loop);
}
