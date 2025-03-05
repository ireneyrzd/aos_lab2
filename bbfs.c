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
#include <sys/stat.h>
#include <libssh/libssh.h>
#include <libssh/sftp.h>

#ifdef HAVE_SYS_XATTR_H
#include <sys/xattr.h>
#endif

#include "log.h"

// Global configuration variables
char *remote_rootdir = "/u/yrzd/Downloads/AOS/fuse_remote";
char *remote_ssh = "crazy-cow";
// char *remote_ssh = "yrzd@crazy-cow.cs.utexas.edu";
char *local_rootdir = "fuse_local";
// char *local_rootdir = "/users/yrzd/fuse/src/fuse_local";

// We introduce a structure to keep track of our cached file.
typedef struct
{
    int local_fd;
    char local_path[PATH_MAX];
    char remote_path[PATH_MAX];
    int modified; // flag: 0 = not modified, 1 = modified
} file_handle_t;

// Helper to construct full remote path from a FUSE path.
static void bb_fullpath_remote(char fullpath[PATH_MAX], const char *path, const char *rootdir)
{
    snprintf(fullpath, PATH_MAX, "%s%s", rootdir, path);
    log_msg("    bb_fullpath_remote: rootdir=\"%s\", path=\"%s\", fullpath=\"%s\"\n",
            rootdir, path, fullpath);
}

///////////////////////////////////////////////////////////
// Modified bb_open: Download remote file to a local temp file

int bb_open(const char *path, struct fuse_file_info *fi)
{
    struct bb_state *bb_data = BB_DATA;
    char remote_fullpath[PATH_MAX];
    bb_fullpath_remote(remote_fullpath, path, bb_data->rootdir);

    // Create a temporary file in /tmp to cache the remote file.
    char local_template[] = "/tmp/fusecacheXXXXXX";
    int tmp_fd = mkstemp(local_template);
    if (tmp_fd < 0)
    {
        log_msg("bb_open: mkstemp failed for template \"%s\": %s\n", local_template, strerror(errno));
        return -errno;
    }

    // Open the remote file for reading using SFTP.
    sftp_file remote_file = sftp_open(bb_data->sftp, remote_fullpath, O_RDONLY, 0);
    if (remote_file == NULL)
    {
        log_msg("bb_open: sftp_open failed for \"%s\": %s\n", remote_fullpath, ssh_get_error(bb_data->session));
        close(tmp_fd);
        unlink(local_template);
        return -sftp_get_error(bb_data->sftp);
    }

    // Download the remote file entirely into the temporary file.
    char buffer[8192];
    int n;
    while ((n = sftp_read(remote_file, buffer, sizeof(buffer))) > 0)
    {
        if (write(tmp_fd, buffer, n) != n)
        {
            log_msg("bb_open: write to temp file failed: %s\n", strerror(errno));
            sftp_close(remote_file);
            close(tmp_fd);
            unlink(local_template);
            return -errno;
        }
    }
    if (n < 0)
    {
        log_msg("bb_open: sftp_read failed: %s\n", ssh_get_error(bb_data->session));
        sftp_close(remote_file);
        close(tmp_fd);
        unlink(local_template);
        return -sftp_get_error(bb_data->sftp);
    }
    sftp_close(remote_file);

    // Reset file offset to beginning.
    lseek(tmp_fd, 0, SEEK_SET);

    // Allocate and fill our file handle structure.
    file_handle_t *fh = malloc(sizeof(file_handle_t));
    if (!fh)
    {
        close(tmp_fd);
        unlink(local_template);
        return -ENOMEM;
    }
    fh->local_fd = tmp_fd;
    strncpy(fh->local_path, local_template, PATH_MAX);
    strncpy(fh->remote_path, remote_fullpath, PATH_MAX);
    fh->modified = 0;
    fi->fh = (uint64_t)fh;
    log_msg("bb_open: cached remote file \"%s\" in \"%s\"\n", remote_fullpath, fh->local_path);
    return 0;
}

///////////////////////////////////////////////////////////
// Modified bb_create: Create a new local temp file for a new file

int bb_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    struct bb_state *bb_data = BB_DATA;
    char remote_fullpath[PATH_MAX];
    bb_fullpath_remote(remote_fullpath, path, bb_data->rootdir);

    char local_template[] = "/tmp/fusecacheXXXXXX";
    int tmp_fd = mkstemp(local_template);
    if (tmp_fd < 0)
    {
        log_msg("bb_create: mkstemp failed for template \"%s\": %s\n", local_template, strerror(errno));
        return -errno;
    }

    // For a newly created file, we don’t need to download anything.
    // We mark it as modified so that on close the file gets uploaded.
    file_handle_t *fh = malloc(sizeof(file_handle_t));
    if (!fh)
    {
        close(tmp_fd);
        unlink(local_template);
        return -ENOMEM;
    }
    fh->local_fd = tmp_fd;
    strncpy(fh->local_path, local_template, PATH_MAX);
    strncpy(fh->remote_path, remote_fullpath, PATH_MAX);
    fh->modified = 1; // new file must be uploaded later
    fi->fh = (uint64_t)fh;
    log_msg("bb_create: created new local temp file \"%s\" for remote \"%s\"\n", fh->local_path, fh->remote_path);
    return 0;
}

///////////////////////////////////////////////////////////
// Modified bb_read: Read from the local cache

int bb_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    file_handle_t *fh = (file_handle_t *)fi->fh;
    int res = pread(fh->local_fd, buf, size, offset);
    if (res < 0)
    {
        log_msg("bb_read: pread failed: %s\n", strerror(errno));
        res = -errno;
    }
    log_msg("bb_read: read %d bytes from \"%s\"\n", res, fh->local_path);
    return res;
}

///////////////////////////////////////////////////////////
// Modified bb_write: Write to the local cache and mark modified

int bb_write(const char *path, const char *buf, size_t size, off_t offset,
             struct fuse_file_info *fi)
{
    file_handle_t *fh = (file_handle_t *)fi->fh;
    int res = pwrite(fh->local_fd, buf, size, offset);
    if (res < 0)
    {
        log_msg("bb_write: pwrite failed: %s\n", strerror(errno));
        res = -errno;
    }
    else if (res > 0)
    {
        fh->modified = 1;
    }
    // log_msg("bb_write: wrote %d bytes to \"%s\"\n", res, fh->local_path);
    return res;
}

///////////////////////////////////////////////////////////
// Modified bb_release: If modified, upload the file back to remote, then clean up

int bb_release(const char *path, struct fuse_file_info *fi)
{
    file_handle_t *fh = (file_handle_t *)fi->fh;
    struct bb_state *bb_data = BB_DATA;

    log_msg("bb_release: releasing file \"%s\"\n", fh->local_path);

    // If file was modified, copy it back to the remote server.
    if (fh->modified)
    {
        // Open the remote file for writing (truncate to replace it).
        sftp_file remote_file = sftp_open(bb_data->sftp, fh->remote_path, O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
        if (remote_file == NULL)
        {
            log_msg("bb_release: sftp_open for remote write failed for \"%s\": %s\n",
                    fh->remote_path, ssh_get_error(bb_data->session));
            // Proceed with cleanup even if upload fails.
        }
        else
        {
            // Rewind the local file.
            lseek(fh->local_fd, 0, SEEK_SET);
            char buffer[8192];
            int n;
            while ((n = read(fh->local_fd, buffer, sizeof(buffer))) > 0)
            {
                int written = sftp_write(remote_file, buffer, n);
                if (written < 0)
                {
                    log_msg("bb_release: sftp_write failed for \"%s\": %s\n",
                            fh->remote_path, ssh_get_error(bb_data->session));
                    break;
                }
            }
            sftp_close(remote_file);
            log_msg("bb_release: uploaded modified file \"%s\" to remote \"%s\"\n",
                    fh->local_path, fh->remote_path);
        }
    }

    // Close and remove the local temporary file.
    close(fh->local_fd);
    unlink(fh->local_path);
    free(fh);
    return 0;
}

/*
  The rest of the functions (bb_getattr, bb_mknod, bb_statfs, bb_utimens, etc.)
  remain unchanged from before. They still operate on the remote filesystem
  for metadata operations.
*/

int bb_getattr(const char *path, struct stat *statbuf)
{
    struct bb_state *bb_data = BB_DATA;
    char fullpath[PATH_MAX];
    sftp_attributes attrs = NULL;

    memset(statbuf, 0, sizeof(struct stat));

    if (strcmp(path, "/") == 0)
    {
        statbuf->st_mode = S_IFDIR | 0755;
        statbuf->st_nlink = 2;
        return 0;
    }

    snprintf(fullpath, PATH_MAX, "%s%s", bb_data->rootdir, path);
    attrs = sftp_stat(bb_data->sftp, fullpath);
    if (attrs == NULL)
    {
        log_msg("bb_getattr ERROR: sftp_stat failed for path \"%s\"\n", fullpath);
        return -sftp_get_error(bb_data->sftp);
    }
    statbuf->st_mode = attrs->permissions;
    statbuf->st_nlink = 1;
    statbuf->st_size = attrs->size;
    log_msg("bb_getattr SUCCESS: path=\"%s\"\n", fullpath);
    return 0;
}

int bb_mknod(const char *path, mode_t mode, dev_t dev)
{
    struct bb_state *bb_data = BB_DATA;
    char fullpath[PATH_MAX];

    snprintf(fullpath, PATH_MAX, "%s%s", bb_data->rootdir, path);
    log_msg("bb_mknod(path=\"%s\", mode=%o)\n", fullpath, mode);

    sftp_file file = sftp_open(bb_data->sftp, fullpath, O_CREAT | O_WRONLY, mode);
    if (file == NULL)
    {
        log_msg("bb_mknod ERROR: sftp_open failed: %s\n", ssh_get_error(bb_data->session));
        return -sftp_get_error(bb_data->sftp);
    }
    sftp_close(file);
    return 0;
}

int bb_statfs(const char *path, struct statvfs *statv)
{
    printf("MISSING: bb_statfs\n");
    return -ENOSYS;
}

int bb_utimens(const char *path, const struct timespec ts[2])
{
    struct bb_state *bb_data = BB_DATA;
    char fullpath[PATH_MAX];

    snprintf(fullpath, PATH_MAX, "%s%s", bb_data->rootdir, path);
    log_msg("bb_utimens(path=\"%s\")\n", fullpath);

    sftp_attributes attrs = sftp_stat(bb_data->sftp, fullpath);
    if (attrs == NULL)
    {
        log_msg("ERROR: sftp_stat failed: %s\n", ssh_get_error(bb_data->sftp));
        return -sftp_get_error(bb_data->sftp);
    }
    attrs->mtime = ts[1].tv_sec;
    int ret = sftp_setstat(bb_data->sftp, fullpath, attrs);
    sftp_attributes_free(attrs);

    if (ret != SSH_OK)
    {
        log_msg("ERROR: sftp_setstat failed: %s\n", ssh_get_error(bb_data->sftp));
        return -sftp_get_error(bb_data->sftp);
    }
    log_msg("SUCCESS: Updated timestamps for \"%s\"\n", fullpath);
    return 0;
}

int bb_access(const char *path, int mask)
{
    printf("MISSING: bb_access\n");
    return -ENOSYS;
}

void *bb_init(struct fuse_conn_info *conn)
{
    log_msg("bb_init()\n");
    log_conn(conn);
    log_fuse_context(fuse_get_context());
    return BB_DATA;
}

void bb_destroy(void *userdata)
{
    log_msg("bb_destroy(userdata=%p)\n", userdata);
}

struct fuse_operations bb_oper = {
    .getattr = bb_getattr,
    .readlink = NULL,
    .getdir = NULL,
    .mknod = bb_mknod,
    .mkdir = NULL,
    .unlink = NULL,
    .rmdir = NULL,
    .symlink = NULL,
    .rename = NULL,
    .link = NULL,
    .chmod = NULL,
    .chown = NULL,
    .truncate = NULL,
    .utimens = bb_utimens,
    .open = bb_open,
    .read = bb_read,
    .create = bb_create,
    .write = bb_write,
    .statfs = bb_statfs,
    .flush = NULL,
    .release = bb_release,
    .fsync = NULL,
#ifdef HAVE_SYS_XATTR_H
    .setxattr = NULL,
    .getxattr = NULL,
    .listxattr = NULL,
    .removexattr = NULL,
#endif
    .opendir = NULL,
    .readdir = NULL,
    .releasedir = NULL,
    .fsyncdir = NULL,
    .init = bb_init,
    .destroy = bb_destroy,
    .access = bb_access,
    .ftruncate = NULL,
    .fgetattr = NULL};

void bb_usage()
{
    fprintf(stderr, "usage: bbfs [FUSE and mount options] rootDir mountPoint\n");
    abort();
}

int main()
{
    int fuse_stat;
    struct bb_state *bb_data;

    if ((getuid() == 0) || (geteuid() == 0))
    {
        fprintf(stderr, "Running BBFS as root opens unacceptable security holes\n");
        return 1;
    }

    fprintf(stderr, "Fuse library version %d.%d\n", FUSE_MAJOR_VERSION, FUSE_MINOR_VERSION);

    bb_data = malloc(sizeof(struct bb_state));
    if (bb_data == NULL)
    {
        perror("main calloc");
        abort();
    }

    bb_data->rootdir = remote_rootdir;
    printf("rootdir = %s\n", bb_data->rootdir);
    bb_data->logfile = log_open();

    int argc = 2;
    char *argv[2] = {"./myfs", local_rootdir};

    // setup SFTP over SSH
    ssh_session session = ssh_new();
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

    sftp_session sftp = sftp_new(session);
    if (sftp == NULL)
    {
        fprintf(stderr, "Error starting SFTP session: %s\n", ssh_get_error(session));
        ssh_free(session);
        return -1;
    }
    sftp_init(sftp);

    bb_data->sftp = sftp;
    bb_data->session = session;

    fprintf(stderr, "about to call fuse_main\n");
    fuse_stat = fuse_main(argc, argv, &bb_oper, bb_data);
    fprintf(stderr, "fuse_main returned %d\n", fuse_stat);

    sftp_free(sftp);
    ssh_free(session);

    return fuse_stat;
}
