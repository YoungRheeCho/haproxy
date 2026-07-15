#ifndef SHARED_TYPES_H
#define SHARED_TYPES_H

#include <stdatomic.h>

#define MAX_SERVERS 128

typedef enum {
    SERVER_STATUS_DOWN = 0,
    SERVER_STATUS_UP   = 1
} ServerStatus;

typedef struct {
    char ip[16];
    int port;
    atomic_int status;
} ServerSlot;

#endif