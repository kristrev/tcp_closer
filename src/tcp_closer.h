#ifndef TCP_CLOSER_H
#define TCP_CLOSER_H

struct inet_diag_bc_op;

//When the kernel processes a filter (inet_diag_bc_run() in
//net/ipv4/inet_diag.c), the first step is to read the length of the filter
//(sizeof(struct inet_diag_bc_op) * num_elements_in_filter). The kernel then
//checks the bc_ops one by one, and the only way to abot the loop is to make
//the length-variable used in the loop negative.
//
//The value used when updating len is either yes or no in inet_diag_bc_op. yes
//is uint8_t and will (in our case) always be the length of the command and its
//arguments (we don't use arguments). No is a uint16_t and is the offset to jump
//to if a comparison fails. In order to ensure that we can always abort the
//loop, we must be able to jump past all pending inet_diag_bc_op-structs.
//
//The maximum offset that can be specified by one bc_op is 0xFFFF. To ensure
//that we can always skip all pending bc_ops, the maximum length of the whole
//filter is 0xFFFF - 1. One bc_op-struct is 4 bytes and, since there is no equal
//code, we need to check both LE and GE for every port. Finally, each comparison
//operation consists of two bc-op-structs, since the port is kept in a second
//bc_op-struct. Thus, comparing one port consumes 16 bytes. The maximum number
//of bc_ops in our filter is therefore (0xFFFF - 1) / 16 = 4095.
//
//The limit can be solved in smarter ways, since we only need to be able to
//abort the loop from the last member in the destination/source port sets.
//However, that is an improvement for another day. 4000 ports is enough for
//now.
#define MAX_NUM_PORTS 4095

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

    bool verbose_mode;
};

#endif
