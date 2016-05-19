//
// Created by srbvsr on 4/14/16.
//

#ifndef ISECVPN_COMMON_H
#define ISECVPN_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#define PERROR(x) do { perror(x); exit(1); } while (0)
#define CHK_ERR_EXIT(x, s) if (x <= 0) { perror(s); exit(1); }

#endif //ISECVPN_COMMON_H
