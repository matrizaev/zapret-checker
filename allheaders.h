#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <endian.h>

//#include <linux/netfilter.h>
//#include <netinet/in.h>
//#include <arpa/inet.h>
//#include <netdb.h>

#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <signal.h>
#include <stdarg.h>
#include <dirent.h>
#include <time.h>
#include <math.h>
#include <stdint.h>
#include <dlfcn.h>

#include "dbg.h"