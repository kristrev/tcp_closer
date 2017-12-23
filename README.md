# tcp_closer

tcp\_closer is a command line Linux-tool for closing (destroying) TCP
connections to/from given ports. The motivation for developing this tool was
that I started seeing several established, but "dead" TCP connections to servers
I am working with. Two culprits stuck out when debugging the issue - 1) broken
application-layer keep-alive protocols, and 2) middleboxes breaking the
keep-alive protocols.

Solving the root-cause (fixing proprietary applications or third-party
middleboxes) is impossible. Killing the dead TCP connection(s) is one way to
work-around the issue (in most cases). When a connection is killed, the
application will (should) detect that a socket has failed and react accordingly.

tcp\_closer is built upon the INET\_DIAG functionality provided by the kernel.
In order to fetch the sockets to kill, we first create a filter. This filter is
passed to the kernel and the kernel returns a list of matching connections. In
order to destroy the connections, we send a SOCK\_DESTROY message. SOCK\_DESTROY
lets a privileged app/user kill the sockets/connections belonging to other
applications. If SOCK\_DESTROY is not supported by the current kernel,
tcp\_closer can fall back to searching through /proc for the socket inode and
kill any process that references the inode.

## Compile

tcp\_closer can be compiled using CMake. Create a directory that you will use
for building, enter this directory and run `cmake .. && make`. If you want to
build a Debian-package, you can run `make package` instead. The only dependency
of tcp\_closer is libmnl.

On machines without SOCK\_DESTROY, NO\_SOCK\_DESTROY must be set to one when
running cmake. I.e., the command will typically be `cmake ..
-DNO_SOCK_DESTROY=1`.

## How to run

tcp\_closer must be run as root in order for destroying sockets to work, and the
application supports the following command line arguments:

* -4/-6 : Match IPv4/v6 sockets (default v4).
* -s/--sport : source port to match.
* -d/--dport : destination port to match.
* -t/--idle\_time : limit for time since connection last received data (in ms).
  Defaults to 0, which means that all connections matching sport/dport will be
  destroyed.
* -i/--interval : how often to poll for sockets matching sport(s)/dport(s) (in
  sec). If not provided, sockets will be polled once and then tcp\_closer will
  exit.
* -f/--logfile : Path to logfile (default is stderr).
* -v/--verbose : More verbose output.
* -h/--help : Show supporter command line arguments.
* --use\_proc : Find inode in proc + kill instead of using SOCK\_DESTROY.
* --disable\_syslog : Do not write log messages to syslog.
* --last\_recv\_limit : Upper limit for last data received (in ms). Defaults to 0
  and is used to filter out recently established connections. Before data is
  received, a connection contains a bogus last data received timestamp.
    
At least one source or destination port must be given. We will kill connections
where the source port is one of the given source port(s) (if any), and the
destination port one of the given destination port(s) (if any).
