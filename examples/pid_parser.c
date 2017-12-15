#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    //Length of /proc/strlen(uint64_max)/fd/d_name (d_name is 256, inc. \0)
    char dir_buf[286];
    char link_buf[255] = {0};
    char *inode_str;
    uint64_t pid_to_find = atoll(argv[1]), pid;
    struct dirent *lDirEnt;
    DIR *lProcDir, *lProcFdDir;
    uint64_t inode;

    if (strlen(argv[1]) > 20 || !pid_to_find) {
        fprintf(stderr, "Invalid pid given\n");
        return 0;
    }

    lProcDir = opendir("/proc");

    if (!lProcDir) {
        fprintf(stderr, "Failed to open /proc\n");
        return 1;
    }

    while ((lDirEnt = readdir(lProcDir))) {
        pid = (uint64_t) atoll(lDirEnt->d_name);

        if (pid == pid_to_find) {
            break;
        }
    }

    if (pid != pid_to_find) {
        fprintf(stderr, "PID not found\n");
        closedir(lProcDir);
        return 1;
    }

    snprintf(dir_buf, sizeof(dir_buf), "/proc/%lu/fd", pid);

    lProcFdDir = opendir(dir_buf);

    if (!lProcFdDir) {
        fprintf(stderr, "Failed to open: %s. Error: %s (%d)\n", dir_buf,
                strerror(errno), errno);
        closedir(lProcDir);
        return 1;
    }

    while ((lDirEnt = readdir(lProcFdDir))) {
        if (lDirEnt->d_type != DT_LNK) {
            continue;
        }

        //fprintf(stdout, "Name %s Type %u\n", lDirEnt->d_name, lDirEnt->d_type);

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

        inode = atoll(inode_str);

        fprintf(stdout, "Pid %lu Socket Inode %lu\n", pid, inode);
    }

    closedir(lProcFdDir);
    closedir(lProcDir);
    return 0;
}
