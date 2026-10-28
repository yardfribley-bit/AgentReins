#pragma once
#include <stdint.h>

/* Map a loopback TCP client port to the owning process via libproc.
   client_port and server_port are host byte order.
   Returns 1 when a peer was found, 0 when none matched, -1 on error.
   out_path is NUL-terminated (empty if proc_pidpath fails). */
int agentreins_lookup_tcp_peer(uint16_t client_port, uint16_t server_port,
                               int32_t *out_pid, uint32_t *out_uid,
                               char *out_path, int path_cap);
