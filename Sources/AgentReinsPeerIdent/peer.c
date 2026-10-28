#include "agentreins_peer.h"

#include <arpa/inet.h>
#include <libproc.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc_info.h>
#include <sys/socket.h>
#include <unistd.h>

/* insi_lport / insi_fport are copied from inp_lport / inp_fport (network byte order).
   A second compare against the raw low 16 bits covers any SDK that already
   converted them, without matching a socket under mixed interpretations. */

static int ports_match(const struct in_sockinfo *ini, uint16_t client_port, uint16_t server_port) {
    uint16_t local_raw = (uint16_t)ini->insi_lport;
    uint16_t foreign_raw = (uint16_t)ini->insi_fport;
    if (ntohs(local_raw) == client_port && ntohs(foreign_raw) == server_port) return 1;
    if (local_raw == client_port && foreign_raw == server_port) return 1;
    return 0;
}

int agentreins_lookup_tcp_peer(uint16_t client_port, uint16_t server_port,
                               int32_t *out_pid, uint32_t *out_uid,
                               char *out_path, int path_cap) {
    if (!out_pid || !out_uid || !out_path || path_cap < 2 || client_port == 0 || server_port == 0) {
        return -1;
    }
    out_path[0] = '\0';
    *out_pid = 0;
    *out_uid = 0;

    int bytes = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
    if (bytes <= 0) return -1;
    if (bytes > 1024 * 1024) bytes = 1024 * 1024;
    pid_t *pids = malloc((size_t)bytes);
    if (!pids) return -1;
    bytes = proc_listpids(PROC_ALL_PIDS, 0, pids, bytes);
    if (bytes <= 0) {
        free(pids);
        return -1;
    }
    int count = bytes / (int)sizeof(pid_t);
    pid_t self = getpid();
    int found = 0;

    for (int i = 0; i < count && !found; i++) {
        pid_t pid = pids[i];
        if (pid <= 0 || pid == self) continue;

        int fb = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
        if (fb <= 0) continue;
        if (fb > 1024 * 1024) fb = 1024 * 1024;
        struct proc_fdinfo *fds = malloc((size_t)fb);
        if (!fds) continue;
        fb = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, fb);
        if (fb <= 0) {
            free(fds);
            continue;
        }
        int nf = fb / (int)sizeof(struct proc_fdinfo);
        for (int j = 0; j < nf; j++) {
            if (fds[j].proc_fdtype != PROX_FDTYPE_SOCKET) continue;
            struct socket_fdinfo info;
            memset(&info, 0, sizeof(info));
            int nb = proc_pidfdinfo(pid, fds[j].proc_fd, PROC_PIDFDSOCKETINFO, &info, (int)sizeof(info));
            if (nb <= 0) continue;
            if (info.psi.soi_kind != SOCKINFO_TCP) continue;
            if (info.psi.soi_family != AF_INET && info.psi.soi_family != AF_INET6) continue;
            if (info.psi.soi_proto.pri_tcp.tcpsi_state == TSI_S_LISTEN) continue;
            struct in_sockinfo *ini = &info.psi.soi_proto.pri_tcp.tcpsi_ini;
            if (!ports_match(ini, client_port, server_port)) continue;

            struct proc_bsdinfo bsd;
            memset(&bsd, 0, sizeof(bsd));
            if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsd, (int)sizeof(bsd)) <= 0) continue;
            *out_pid = (int32_t)pid;
            *out_uid = (uint32_t)bsd.pbi_uid;
            int n = proc_pidpath((int)pid, out_path, (uint32_t)path_cap);
            if (n <= 0) {
                out_path[0] = '\0';
            } else if (n >= path_cap) {
                out_path[path_cap - 1] = '\0';
            }
            found = 1;
            break;
        }
        free(fds);
    }
    free(pids);
    return found ? 1 : 0;
}
