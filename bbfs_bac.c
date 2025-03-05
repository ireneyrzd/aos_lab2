
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

// define global variable
char *remote_rootdir = "/tmp/irene";
char *remote_ssh = "crazy-cow";
// char *remote_ssh = "yrzd@crazy-cow.cs.utexas.edu";
char *local_rootdir = "fuse_local";
// char *local_rootdir = "/users/yrzd/fuse/src/fuse_local";

//  All the paths I see are relative to the root of the mounted
//  filesystem.  In order to get to the underlying filesystem, I need to
//  have the mountpoint.  I'll save it away early on in main(), and then
//  whenever I need a path for something I'll call this to construct
//  it.
static void bb_fullpath(char fpath[PATH_MAX], const char *path)
{

    strcpy(fpath, BB_DATA->rootdir);
    strncat(fpath, path, PATH_MAX); // ridiculously long paths will
                                    // break here

    log_msg("    bb_fullpath:  rootdir = \"%s\", path = \"%s\", fpath = \"%s\"\n",
            BB_DATA->rootdir, path, fpath);
}

///////////////////////////////////////////////////////////
//
// Prototypes for all these functions, and the C-style comments,
// come from /usr/include/fuse.h
//
/** Get file attributes.
 *
 * Similar to stat().  The 'st_dev' and 'st_blksize' fields are
 * ignored.  The 'st_ino' field is ignored except if the 'use_ino'
 * mount option is given.
 */
int bb_getattr(const char *path, struct stat *statbuf)
{
    struct bb_state *bb_data = BB_DATA;
    char fullpath[PATH_MAX];
    sftp_attributes attrs = NULL;

    // Zero out the stat buffer
    memset(statbuf, 0, sizeof(struct stat));

    // Special case for root directory
    if (strcmp(path, "/") == 0)
    {
        statbuf->st_mode = S_IFDIR | 0755;
        statbuf->st_nlink = 2;
        return 0;
    }

    // Construct the full path using the remote rootdir
    snprintf(fullpath, PATH_MAX, "%s%s", bb_data->rootdir, path);

    // Retrieve attributes from the remote system
    attrs = sftp_stat(bb_data->sftp, fullpath);
    if (attrs == NULL)
    {
        log_msg("bb_getattr ERROR: sftp_stat failed for path \"%s\"\n",
                fullpath);
        return 0;
    }

    // Translate sftp_attributes to a stat struct.
    statbuf->st_mode = attrs->permissions;
    statbuf->st_nlink = 1;
    statbuf->st_size = attrs->size;

    // sftp_attributes_free(attrs);
    log_msg("bb_getattr SUCCESS: path=\"%s\"\n", fullpath);
    return 0;

    // int retstat;
    // char fpath[PATH_MAX];

    // log_msg("\nbb_getattr(path=\"%s\", statbuf=0x%08x)\n",
    //   path, statbuf);
    // bb_fullpath(fpath, path);

    // retstat = log_syscall("lstat", lstat(fpath, statbuf), 0);

    // log_stat(statbuf);

    // return retstat;
}

int bb_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    struct bb_state *bb_data = BB_DATA;
    char fullpath[PATH_MAX];

    log_msg("\nBB_CREATE\n");

    snprintf(fullpath, PATH_MAX, "%s%s", bb_data->rootdir, path);
    log_msg("\nbb_create(path=\"%s\", mode=%o)\n", fullpath, mode);

    // Open file with O_CREAT flag
    sftp_file file = sftp_open(bb_data->sftp, fullpath, O_CREAT | O_WRONLY | O_TRUNC, mode);
    if (file == NULL)
    {
        log_msg("  bb_create ERROR: sftp_open failed: %s\n", ssh_get_error(bb_data->session));
        return -sftp_get_error(bb_data->sftp);
    }

    // Store the file handle in fi->fh
    fi->fh = (uint64_t)file;
    log_msg("  bb_create SUCCESS: file handle = %p\n", file);
    return 0;
}

int bb_mknod(const char *path, mode_t mode, dev_t dev)
{
    struct bb_state *bb_data = BB_DATA;
    char fullpath[PATH_MAX];

    snprintf(fullpath, PATH_MAX, "%s%s", bb_data->rootdir, path);
    log_msg("\nbb_mknod(path=\"%s\", mode=%o)\n", fullpath, mode);

    sftp_file file = sftp_open(bb_data->sftp, fullpath, O_CREAT | O_WRONLY, mode);
    if (file == NULL)
    {
        log_msg("  bb_mknod ERROR: sftp_open failed: %s\n", ssh_get_error(bb_data->session));
        return -sftp_get_error(bb_data->sftp);
    }

    sftp_close(file);
    return 0;
}

/** File open operation
 *
 * No creation, or truncation flags (O_CREAT, O_EXCL, O_TRUNC)
 * will be passed to open().  Open should check if the operation
 * is permitted for the given flags.  Optionally open may also
 * return an arbitrary filehandle in the fuse_file_info structure,
 * which will be passed to all file operations.
 *
 * Changed in version 2.2
 */
int bb_open(const char *path, struct fuse_file_info *fi)
{
    struct bb_state *bb_data = BB_DATA;
    char fullpath[PATH_MAX];

    snprintf(fullpath, PATH_MAX, "%s%s", bb_data->rootdir, path);

    // log_msg("\nbb_open(path=\"%s\", fi=0x%08x)\n", path, fi);

    // Open the remote file in read-write mode
    sftp_file file = sftp_open(bb_data->sftp, fullpath, O_RDWR, S_IRUSR | S_IWUSR);
    if (file == NULL)
    {
        log_msg("  bb_open ERROR: sftp_open failed: %s\n", ssh_get_error(bb_data->session));
        return -sftp_get_error(bb_data->sftp);
    }

    fi->fh = (uint64_t)file;
    // log_msg("  bb_open SUCCESS: file handle = %p\n", file);
    return 0;

    // int retstat = 0;
    // int fd;
    // char fpath[PATH_MAX];

    // log_msg("\nbb_open(path\"%s\", fi=0x%08x)\n",
    //         path, fi);
    // bb_fullpath(fpath, path);

    // // if the open call succeeds, my retstat is the file descriptor,
    // // else it's -errno.  I'm making sure that in that case the saved
    // // file descriptor is exactly -1.
    // fd = log_syscall("open", open(fpath, fi->flags), 0);
    // if (fd < 0)
    //     retstat = log_error("open");

    // fi->fh = fd;

    // log_fi(fi);

    // return retstat;
}

/** Read data from an open file
 *
 * Read should return exactly the number of bytes requested except
 * on EOF or error, otherwise the rest of the data will be
 * substituted with zeroes.  An exception to this is when the
 * 'direct_io' mount option is specified, in which case the return
 * value of the read system call will reflect the return value of
 * this operation.
 *
 * Changed in version 2.2
 */
// I don't fully understand the documentation above -- it doesn't
// match the documentation for the read() system call which says it
// can return with anything up to the amount of data requested. nor
// with the fusexmp code which returns the amount of data also
// returned by read.
int bb_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    sftp_file file = (sftp_file)fi->fh;

    log_msg("\nbb_read(path=\"%s\", size=%zu, offset=%ld, fi=0x%08x)\n",
            path, size, offset, fi);

    // Move to the correct offset before reading
    if (sftp_seek(file, offset) != SSH_OK)
    {
        log_msg("  bb_read ERROR: sftp_seek failed: %s\n", ssh_get_error(BB_DATA->sftp));
        return -sftp_get_error(BB_DATA->sftp);
    }

    // Read data into the buffer
    int bytes_read = sftp_read(file, buf, size);
    if (bytes_read < 0)
    {
        log_msg("  bb_read ERROR: sftp_read failed: %s\n", ssh_get_error(BB_DATA->sftp));
        return -sftp_get_error(BB_DATA->sftp);
    }

    log_msg("  bb_read SUCCESS: read %d bytes\n", bytes_read);
    return bytes_read;

    /* TODO */
    // int retstat = 0;

    // log_msg("\nbb_read(path=\"%s\", buf=0x%08x, size=%d, offset=%lld, fi=0x%08x)\n",
    //         path, buf, size, offset, fi);
    // // no need to get fpath on this one, since I work from fi->fh not the path
    // log_fi(fi);

    // return log_syscall("pread", pread(fi->fh, buf, size, offset), 0);
}

/** Write data to an open file
 *
 * Write should return exactly the number of bytes requested
 * except on error.  An exception to this is when the 'direct_io'
 * mount option is specified (see read operation).
 *
 * Changed in version 2.2
 */
// As  with read(), the documentation above is inconsistent with the
// documentation for the write() system call.
int bb_write(const char *path, const char *buf, size_t size, off_t offset,
             struct fuse_file_info *fi)
{

    sftp_file file = (sftp_file)fi->fh;

    // log_msg("\nbb_write(path=\"%s\", size=%zu, offset=%ld, fi=0x%08x)\n",
    //         path, size, offset, fi);

    // Move to the correct offset before writing
    if (sftp_seek(file, offset) != SSH_OK)
    {
        log_msg("  bb_write ERROR: sftp_seek failed: %s\n", ssh_get_error(BB_DATA->sftp));
        return -sftp_get_error(BB_DATA->sftp);
    }

    // Write data from the buffer to the file
    int bytes_written = sftp_write(file, buf, size);
    if (bytes_written < 0)
    {
        log_msg("  bb_write ERROR: sftp_write failed: %s\n", ssh_get_error(BB_DATA->sftp));
        return -sftp_get_error(BB_DATA->sftp);
    }

    // log_msg("  bb_write SUCCESS: wrote %d bytes\n", bytes_written);
    return bytes_written;

    // TO DO
    // int retstat = 0;

    // log_msg("\nbb_write(path=\"%s\", buf=0x%08x, size=%d, offset=%lld, fi=0x%08x)\n",
    //         path, buf, size, offset, fi);
    // // no need to get fpath on this one, since I work from fi->fh not the path
    // log_fi(fi);

    // return log_syscall("pwrite", pwrite(fi->fh, buf, size, offset), 0);
}

/** Get file system statistics
 *
 * The 'f_frsize', 'f_favail', 'f_fsid' and 'f_flag' fields are ignored
 *
 * Replaced 'struct statfs' parameter with 'struct statvfs' in
 * version 2.5
 */
int bb_statfs(const char *path, struct statvfs *statv)
{
    printf("MISSING: bb_statfs\n");
    int retstat;
    char command[PATH_MAX + 50];
    char temp_file[] = "/tmp/bbfs_statvfs.txt";

    log_msg("\nbb_statfs(path=\"%s\", statv=0x%08x)\n", path, statv);

    // Construct the command to get the statvfs of the remote directory
    snprintf(command, sizeof(command), "ssh %s 'stat -f -c \"%%a %%b %%c %%d %%e %%f %%g %%h %%i %%l %%m %%n %%s %%t %%u\" %s' > %s", remote_ssh, remote_rootdir, temp_file);

    // Execute the command
    retstat = system(command);
    if (retstat != 0)
    {
        log_msg("    ERROR: Failed to fetch statvfs from remote machine\n");
        return -EIO;
    }

    // Read the statvfs information from the temporary file
    FILE *fp = fopen(temp_file, "r");
    if (fp == NULL)
    {
        log_msg("    ERROR: Failed to open temporary statvfs file\n");
        return -EIO;
    }

    if (fscanf(fp, "%lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
               &statv->f_bsize, &statv->f_frsize, &statv->f_blocks, &statv->f_bfree, &statv->f_bavail,
               &statv->f_files, &statv->f_ffree, &statv->f_favail, &statv->f_fsid, &statv->f_flag,
               &statv->f_namemax, &statv->f_fsid, &statv->f_flag, &statv->f_namemax, &statv->f_frsize) != 15)
    {
        log_msg("    ERROR: Failed to read statvfs information\n");
        fclose(fp);
        return -EIO;
    }

    fclose(fp);
    log_statvfs(statv);

    return 0;

    // int retstat = 0;
    // char fpath[PATH_MAX];

    // log_msg("\nbb_statfs(path=\"%s\", statv=0x%08x)\n",
    //         path, statv);
    // bb_fullpath(fpath, path);

    // // get stats for underlying filesystem
    // retstat = log_syscall("statvfs", statvfs(fpath, statv), 0);

    // log_statvfs(statv);

    // return retstat;
}

/** Release an open file
 *
 * Release is called when there are no more references to an open
 * file: all file descriptors are closed and all memory mappings
 * are unmapped.
 *
 * For every open() call there will be exactly one release() call
 * with the same flags and file descriptor.  It is possible to
 * have a file opened more than once, in which case only the last
 * release will mean, that no more reads/writes will happen on the
 * file.  The return value of release is ignored.
 *
 * Changed in version 2.2
 */
int bb_release(const char *path, struct fuse_file_info *fi)
{
    sftp_file file = (sftp_file)fi->fh;

    log_msg("\nbb_release(path=\"%s\", fi=0x%08x)\n", path, fi);

    // Close the remote file
    int ret = sftp_close(file);
    if (ret != SSH_OK)
    {
        log_msg("  bb_release ERROR: sftp_close failed: %s\n", ssh_get_error(BB_DATA->sftp));
        return -sftp_get_error(BB_DATA->sftp);
    }

    log_msg("  bb_release SUCCESS: file closed\n");
    return 0;

    /* TO DO */

    // log_msg("\nbb_release(path=\"%s\", fi=0x%08x)\n",
    //         path, fi);
    // log_fi(fi);

    // // We need to close the file.  Had we allocated any resources
    // // (buffers etc) we'd need to free them here as well.
    // return log_syscall("close", close(fi->fh), 0);
}

/**
 * Initialize filesystem
 *
 * The return value will passed in the private_data field of
 * fuse_context to all file operations and as a parameter to the
 * destroy() method.
 *
 * Introduced in version 2.3
 * Changed in version 2.6
 */
// Undocumented but extraordinarily useful fact:  the fuse_context is
// set up before this function is called, and
// fuse_get_context()->private_data returns the user_data passed to
// fuse_main().  Really seems like either it should be a third
// parameter coming in here, or else the fact should be documented
// (and this might as well return void, as it did in older versions of
// FUSE).
void *bb_init(struct fuse_conn_info *conn)
{
    log_msg("\nbb_init()\n");

    log_conn(conn);
    log_fuse_context(fuse_get_context());

    return BB_DATA;
}

/**
 * Clean up filesystem
 *
 * Called on filesystem exit.
 *
 * Introduced in version 2.3
 */
void bb_destroy(void *userdata)
{
    log_msg("\nbb_destroy(userdata=0x%08x)\n", userdata);
}

int bb_utime(const char *path, struct utimbuf *ubuf)
{
    struct bb_state *bb_data = BB_DATA;
    char fullpath[PATH_MAX];

    snprintf(fullpath, PATH_MAX, "%s%s", bb_data->rootdir, path);
    log_msg("\nbb_utime(path=\"%s\", atime=%ld, mtime=%ld)\n",
            fullpath, ubuf->actime, ubuf->modtime);

    // Retrieve the file attributes
    sftp_attributes attrs = sftp_stat(bb_data->sftp, fullpath);
    if (attrs == NULL)
    {
        log_msg("  ERROR: sftp_stat failed: %s\n", ssh_get_error(bb_data->sftp));
        return -sftp_get_error(bb_data->sftp);
    }

    // Set new access and modification times
    attrs->atime = ubuf->actime;
    attrs->mtime = ubuf->modtime;

    int ret = sftp_setstat(bb_data->sftp, fullpath, attrs);
    sftp_attributes_free(attrs);

    if (ret != SSH_OK)
    {
        log_msg("  ERROR: sftp_setstat failed: %s\n", ssh_get_error(bb_data->sftp));
        return -sftp_get_error(bb_data->sftp);
    }

    log_msg("  SUCCESS: Updated times for \"%s\"\n", fullpath);
    return 0;
}

int bb_utimens(const char *path, const struct timespec ts[2])
{
    struct bb_state *bb_data = BB_DATA;
    char fullpath[PATH_MAX];

    snprintf(fullpath, PATH_MAX, "%s%s", bb_data->rootdir, path);
    log_msg("\nbb_utimens(path=\"%s\")\n", fullpath);

    // Get existing file attributes
    sftp_attributes attrs = sftp_stat(bb_data->sftp, fullpath);
    if (attrs == NULL)
    {
        log_msg("  ERROR: sftp_stat failed: %s\n", ssh_get_error(bb_data->sftp));
        return -sftp_get_error(bb_data->sftp);
    }

    // Modify timestamps
    attrs->mtime = ts[1].tv_sec; // Set new modification time
    int ret = sftp_setstat(bb_data->sftp, fullpath, attrs);
    sftp_attributes_free(attrs);

    if (ret != SSH_OK)
    {
        log_msg("  ERROR: sftp_setstat failed: %s\n", ssh_get_error(bb_data->sftp));
        return -sftp_get_error(bb_data->sftp);
    }

    log_msg("  SUCCESS: Updated timestamps for \"%s\"\n", fullpath);
    return 0;
}

/**
 * Check file access permissions
 *
 * This will be called for the access() system call.  If the
 * 'default_permissions' mount option is given, this method is not
 * called.
 *
 * This method is not called under Linux kernel versions 2.4.x
 *
 * Introduced in version 2.5
 */
int bb_access(const char *path, int mask)
{
    printf("MISSING: bb_access\n");
    return -ENOSYS;
    int retstat = 0;
    char fpath[PATH_MAX];

    log_msg("\nbb_access(path=\"%s\", mask=0%o)\n",
            path, mask);
    bb_fullpath(fpath, path);

    retstat = access(fpath, mask);

    if (retstat < 0)
        retstat = log_error("bb_access access");

    return retstat;
}

struct fuse_operations bb_oper = {
    .getattr = bb_getattr,
    .readlink = NULL,
    // no .getdir -- that's deprecated
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
    /** Just a placeholder, don't set */ // huh???
    .statfs = bb_statfs,
    .flush = NULL,
    .release = bb_release,
    .fsync = NULL,

    // #ifdef HAVE_SYS_XATTR_H
    .setxattr = NULL,
    .getxattr = NULL,
    .listxattr = NULL,
    .removexattr = NULL,
    // #endif

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
    fprintf(stderr, "usage:  bbfs [FUSE and mount options] rootDir mountPoint\n");
    abort();
}

int main()
{
    int fuse_stat;
    struct bb_state *bb_data;

    // bbfs doesn't do any access checking on its own (the comment
    // blocks in fuse.h mention some of the functions that need
    // accesses checked -- but note there are other functions, like
    // chown(), that also need checking!).  Since running bbfs as root
    // will therefore open Metrodome-sized holes in the system
    // security, we'll check if root is trying to mount the filesystem
    // and refuse if it is.  The somewhat smaller hole of an ordinary
    // user doing it with the allow_other flag is still there because
    // I don't want to parse the options string.
    if ((getuid() == 0) || (geteuid() == 0))
    {
        fprintf(stderr, "Running BBFS as root opens unnacceptable security holes\n");
        return 1;
    }

    // See which version of fuse we're running
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

    bb_data->sftp = sftp;
    bb_data->session = session;

    // turn over control to fuse
    fprintf(stderr, "about to call fuse_main\n");
    fuse_stat = fuse_main(argc, argv, &bb_oper, bb_data);
    fprintf(stderr, "fuse_main returned %d\n", fuse_stat);

    sftp_free(sftp);
    ssh_free(session);

    return fuse_stat;
    // // underlying root directory instead of doing the fgetattr().
    // if (!strcmp(path, "/"))
    //     return bb_getattr(path, statbuf);

    // retstat = fstat(fi->fh, statbuf);
    // if (retstat < 0)
    //     retstat = log_error("bb_fgetattr fstat");

    // log_stat(statbuf);

    // return retstat;
}
