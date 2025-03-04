
#include "config.h"
#include "params.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <libgen.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <libssh/libssh.h>
#include <libssh/sftp.h>

#ifdef HAVE_SYS_XATTR_H
#include <sys/xattr.h>
#endif

#include "log.h"

// gcc -o ssh_test -D_FILE_OFFSET_BITS=64 connect_ssh.c -L/usr/lib/x86_64-linux-gnu -lfuse -lssh

int main()
{

    // setup sftp
    ssh_session session;
    sftp_session sftp;

    session = ssh_new();

    if (session == NULL)
    {
        fprintf(stderr, "Error creating SSH session\n");
        return -1;
    }

    ssh_options_set(session, SSH_OPTIONS_HOST, "crazy-cow.cs.utexas.edu");
    ssh_options_set(session, SSH_OPTIONS_USER, "yrzd");
    ssh_options_set(session, SSH_OPTIONS_IDENTITY, "~/.ssh/utcs");

    if (ssh_connect(session) != SSH_OK)
    {
        fprintf(stderr, "Error connecting to host: %s\n", ssh_get_error(session));
        return -1;
    }

    if (ssh_userauth_publickey_auto(session, NULL, NULL) != SSH_AUTH_SUCCESS)
    {
        fprintf(stderr, "Error authenticating with public key: %s\n", ssh_get_error(session));
        return -1;
    }

    sftp = sftp_new(session);
    if (sftp == NULL)
    {
        fprintf(stderr, "Error starting SFTP session: %s\n", ssh_get_error(session));
        ssh_free(session);
        return -1;
    }
    sftp_init(sftp);

    // turn over control to fuse
    fprintf(stderr, "about to call fuse_main\n");
    // use sftp to read a remote file
    sftp_file file;
    char buffer[1024];
    int nbytes;

    sftp_dir dir = sftp_opendir(sftp, "/tmp");
    if (!dir)
    {
        fprintf(stderr, "Error opening remote directory: %s\n", ssh_get_error(session));
        return -1;
    }

    sftp_attributes attr;
    while ((attr = sftp_readdir(sftp, dir)) != NULL)
    {
        printf("File: %s\n", attr->name);
        sftp_attributes_free(attr);
    }
    sftp_closedir(dir);

    file = sftp_open(sftp, "/tmp/hi.txt", O_RDONLY, 0);
    if (file == NULL)
    {
        fprintf(stderr, "Error opening remote file: %s\n", ssh_get_error(session));
        return -1;
    }
    printf("file opened\n");
    nbytes = sftp_read(file, buffer, sizeof(buffer));
    while (nbytes > 0)
    {
        if (write(1, buffer, nbytes) != nbytes)
        {
            fprintf(stderr, "Error writing to local file: %s\n", strerror(errno));
            return -1;
        }
        nbytes = sftp_read(file, buffer, sizeof(buffer));
    }
    if (nbytes < 0)
    {
        fprintf(stderr, "Error reading remote file: %s\n", ssh_get_error(session));
        return -1;
    }
    sftp_close(file);
    printf("file closed\n");
    printf("buffer: %s\n", buffer);

    // fuse_stat = fuse_main(argc, argv, &bb_oper, bb_data);
    fprintf(stderr, "fuse_main returned %d\n", 0);

    sftp_free(sftp);
    ssh_free(session);

    return 0;
}