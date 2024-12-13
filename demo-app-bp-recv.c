#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include "common.h"

#define BUFFER_SIZE 1024
#define AF_BP 28 // Custom socket family identifier

void handle_sigint(int sig)
{
    printf("\nInterrupt received, shutting down...\n");
    exit(1);
}

int main(int argc, char *argv[])
{
    int sfd;
    struct sockaddr_bp addr_bp;
    char buffer[80];
    struct iovec iov[1];
    struct msghdr *msg = (struct msghdr *)malloc(sizeof(struct msghdr));

    signal(SIGINT, handle_sigint);

    // Create the socket
    sfd = socket(AF_BP, SOCK_DGRAM, 1);
    if (sfd < 0)
    {
        perror("socket creation failed");
        return EXIT_FAILURE;
    }
    printf("Socket created.\n");

    addr_bp.bp_family = AF_BP;
    addr_bp.bp_agent_id = 16;
    if (bind(sfd, (struct sockaddr *)&addr_bp, sizeof(addr_bp)) == -1)
    {
        perror("bind sockaddr_bp failed");
        return EXIT_FAILURE;
    }

    memset(iov, 0, sizeof(iov));
    iov[0].iov_base = buffer;
    iov[0].iov_len = sizeof(buffer);
    memset(msg, 0, sizeof(struct msghdr));
    msg->msg_iov = iov;
    msg->msg_iovlen = 1;

    printf("Waiting on recvmsg...\n");
    int ret = recvmsg(sfd, msg, 0);
    if (ret < 0)
    {
        perror("recvmsg() failed");
        close(sfd);
        return EXIT_FAILURE;
    }
    else
    {
        printf("Received message: %s\n", buffer);
    }

    // Cleanup
    free(msg);
    close(sfd);
    printf("Socket closed.\n");

    return EXIT_SUCCESS;
}
