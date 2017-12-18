#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

#include "tcp_closer.h"

static bool parse_config_ports(int argc, char *argv[], uint16_t num_sport,
                               uint16_t num_dport)
{
    return false;
}

//Counts config ports and returns false if any unknown options is found
static bool count_config_ports(int argc, char *argv[], uint16_t *num_sport,
                               uint16_t *num_dport)
{
    int opt;
    bool error = false;

    while (!error && (opt = getopt(argc, argv, "s:d:h")) != -1) {
        switch (opt) {
        case 's':
            (*num_sport)++;
            break;
        case 'd':
            (*num_dport)++;
            break;
        case 'h':
            //Not really an error, but treat as such so that we call show_help()
            error = true;
            break;
        default:
            fprintf(stderr, "Got unknown option %c\n", opt);
            error = true;
            break;
        } 
    }

    return !error;
}

static void show_help()
{
    fprintf(stdout, "Following arguments are supported:\n");
    fprintf(stdout, "\t-s : source port to match\n");
    fprintf(stdout, "\t-d : destionation port to match\n\n");
    fprintf(stdout, "At least one source or destination port must be given.\n"
                    "We will kill connections where the source port is one of\n"
                    "the given source port(s) (if any), and the destination\n"
                    "port one of the given destination port(s) (if any).\n\n");
    fprintf(stdout, "Maximum number of ports (combined) is %u\n",
            MAX_NUM_PORTS);
}

int main(int argc, char *argv[])
{
    uint16_t num_sport = 0, num_dport = 0;

    //Parse options, so far it just to get sport and dport
    if (argc < 2) {
        show_help();
        return 1;
    }

    if (!count_config_ports(argc, argv, &num_sport, &num_dport)) {
        show_help();
        return 1;
    }

    fprintf(stdout, "# source ports: %u # destination ports: %u\n", num_sport,
            num_dport);

    return 0;
}
