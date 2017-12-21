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
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <signal.h>
#include <unistd.h>

#include "tcp_closer_proc.h"

void destroy_socket_proc(uint32_t inode_org)
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

