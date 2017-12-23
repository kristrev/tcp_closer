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
#include <string.h>
#include <errno.h>
#include <libmnl/libmnl.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <pwd.h>
#include <linux/tcp.h>

#include "tcp_closer_netlink.h"
#include "tcp_closer_proc.h"
#include "tcp_closer.h"
#include "backend_event_loop.h"
#include "tcp_closer_log.h"

static const char* tcp_states_map[] = {
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

int send_diag_msg(struct tcp_closer_ctx *ctx)
{
    uint8_t diag_buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;
    struct inet_diag_req_v2 *diag_req;

    memset(diag_buf, 0, sizeof(diag_buf));

    nlh = mnl_nlmsg_put_header(diag_buf);
    nlh->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_type = SOCK_DIAG_BY_FAMILY;
    nlh->nlmsg_pid = mnl_socket_get_portid(ctx->diag_dump_socket);

    diag_req = mnl_nlmsg_put_extra_header(nlh, sizeof(struct inet_diag_req_v2));
    //TODO: Add a -4/-6 command line option
    diag_req->sdiag_family = ctx->socket_family;
    diag_req->sdiag_protocol = IPPROTO_TCP;

    //We are only interested in established connections and need the tcp-info
    //struct
    diag_req->idiag_ext |= (1 << (INET_DIAG_INFO - 1));
    diag_req->idiag_states = 1 << TCP_ESTABLISHED;

    mnl_attr_put(nlh, INET_DIAG_REQ_BYTECODE, ctx->diag_filter_len,
                 ctx->diag_filter);

    return mnl_socket_sendto(ctx->diag_dump_socket, diag_buf, nlh->nlmsg_len);
}

static void destroy_socket(struct tcp_closer_ctx *ctx,
                           struct inet_diag_msg *diag_msg)
{
#ifndef NO_SOCK_DESTROY
    uint8_t destroy_buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;
    struct inet_diag_req_v2 *destroy_req;

    memset(destroy_buf, 0, sizeof(destroy_buf));

    nlh = mnl_nlmsg_put_header(destroy_buf);
    nlh->nlmsg_pid = mnl_socket_get_portid(ctx->diag_destroy_socket);
    nlh->nlmsg_type = SOCK_DESTROY;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

    destroy_req = mnl_nlmsg_put_extra_header(nlh,
                                             sizeof(struct inet_diag_req_v2));
    //TODO: Add 4/6 flag to command line
    destroy_req->sdiag_family = diag_msg->idiag_family;
    destroy_req->sdiag_protocol = IPPROTO_TCP;

    //Copy ID from diag_msg returned by kernel
    destroy_req->id = diag_msg->id;

    mnl_socket_sendto(ctx->diag_destroy_socket, destroy_buf, nlh->nlmsg_len);
#endif
}

static void parse_diag_msg(struct tcp_closer_ctx *ctx,
                           struct inet_diag_msg *diag_msg,
                           int payload_len)
{
    struct nlattr *attr;
    struct tcp_info *tcpi = NULL;
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

    attr = (struct nlattr*) (diag_msg+1);
    payload_len -= sizeof(struct inet_diag_msg);

    while(mnl_attr_ok(attr, payload_len)){
        if (attr->nla_type != INET_DIAG_INFO) {
            payload_len -= attr->nla_len;
            attr = mnl_attr_next(attr);
            continue;
        }

        tcpi = (struct tcp_info*) mnl_attr_get_payload(attr);
        break;
    }

    //No need to check for tcpi, if it could not be attached then message would
    //not be send from kernel

    if (ctx->verbose_mode) {
        TCP_CLOSER_PRINT_SYSLOG(ctx, LOG_DEBUG, "Found connection:\n");
        TCP_CLOSER_PRINT_SYSLOG(ctx, LOG_DEBUG, "User: %s (UID: %u) Src: %s:%d "
                                "Dst: %s:%d\n",
                                uid_info == NULL ? "Not found" : 
                                                    uid_info->pw_name,
                                diag_msg->idiag_uid, local_addr_buf,
                                ntohs(diag_msg->id.idiag_sport),
                                remote_addr_buf,
                                ntohs(diag_msg->id.idiag_dport));
        TCP_CLOSER_PRINT_SYSLOG(ctx, LOG_DEBUG, "\tState: %s RTT: %gms "
                                "(var. %gms) Recv. RTT: %gms Snd_cwnd: %u/%u "
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

    if (ctx->last_data_recv_limit && tcpi->tcpi_last_data_recv >=
        ctx->last_data_recv_limit) {
        return;
    }

    TCP_CLOSER_PRINT_SYSLOG(ctx, LOG_INFO, "Will destroy src: %s:%d dst: %s:%d "
                            "last_data_recv: %ums\n", local_addr_buf,
                            ntohs(diag_msg->id.idiag_sport), remote_addr_buf,
                            ntohs(diag_msg->id.idiag_dport),
                            tcpi->tcpi_last_data_recv);

    if (ctx->use_netlink) {
        destroy_socket(ctx, diag_msg);
    } else {
        destroy_socket_proc(ctx, diag_msg->idiag_inode);
    }
}

void recv_diag_msg(void *data, int32_t fd, uint32_t events)
{
    struct tcp_closer_ctx *ctx = data;
    struct nlmsghdr *nlh;
    struct nlmsgerr *err;
    uint8_t recv_buf[MNL_SOCKET_BUFFER_SIZE];
    struct inet_diag_msg *diag_msg;
    int32_t numbytes, payload_len;

    numbytes = mnl_socket_recvfrom(ctx->diag_dump_socket, recv_buf,
                                   sizeof(recv_buf));
    nlh = (struct nlmsghdr*) recv_buf;

    while(mnl_nlmsg_ok(nlh, numbytes)){
        if(nlh->nlmsg_type == NLMSG_DONE) {
            ctx->dump_in_progress = false;
            if (!ctx->dump_interval) {
                backend_event_loop_stop(ctx->event_loop);
            }
            break;
        }

        if(nlh->nlmsg_type == NLMSG_ERROR){
            ctx->dump_in_progress = false;
            err = mnl_nlmsg_get_payload(nlh);

            if (err->error) {
                TCP_CLOSER_PRINT_SYSLOG(ctx, LOG_ERR, "Error in netlink "
                                        "message (on dump): %s (%u)\n",
                                        strerror(-err->error), -err->error);

                //Only time we can get a netlink error here, is if there is
                //something wrong with our request. Thus, we should stop loop if
                //no interval is set
                if (!ctx->dump_interval) {
                    backend_event_loop_stop(ctx->event_loop);
                }
            }

            nlh = mnl_nlmsg_next(nlh, &numbytes);
            continue;
        }

        //TODO: Switch these to mnl too
        diag_msg = mnl_nlmsg_get_payload(nlh);
        payload_len = mnl_nlmsg_get_payload_len(nlh);
        parse_diag_msg(ctx, diag_msg, payload_len);

        nlh = mnl_nlmsg_next(nlh, &numbytes);
    }
}

void recv_destroy_msg(void *data, int32_t fd, uint32_t events)
{
    struct tcp_closer_ctx *ctx = data;
    struct nlmsghdr *nlh;
    struct nlmsgerr *err;
    uint8_t recv_buf[MNL_SOCKET_BUFFER_SIZE];
    int32_t numbytes;

    numbytes = mnl_socket_recvfrom(ctx->diag_destroy_socket, recv_buf,
                                   sizeof(recv_buf));
    nlh = (struct nlmsghdr*) recv_buf;

    while(mnl_nlmsg_ok(nlh, numbytes)){
        if(nlh->nlmsg_type == NLMSG_DONE) {
            break;
        } else if (nlh->nlmsg_type != NLMSG_ERROR) {
            TCP_CLOSER_PRINT_SYSLOG(ctx, LOG_DEBUG, "Received unexpected type "
                                    "%u on destroy socket\n", nlh->nlmsg_type);
            nlh = mnl_nlmsg_next(nlh, &numbytes);
            continue;
        }

        err = mnl_nlmsg_get_payload(nlh);

        if (err->error) {
            TCP_CLOSER_PRINT_SYSLOG(ctx, LOG_ERR, "Destroying socket failed. "
                                    "Reason: %s (%u)\n", strerror(-err->error),
                                    -err->error);
            break;
        }

        nlh = mnl_nlmsg_next(nlh, &numbytes);
    }
}
