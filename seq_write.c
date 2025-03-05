#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>

#define FILE_PATH "fuse_local/foo"
#define SIZE_MB 100
#define BUFFER_SIZE 4096

void benchmark_large_write(const char *path)
{
    int fd = open(path, O_RDWR);
    if (fd < 0)
    {
        perror("open");
        return;
    }

    char buffer[BUFFER_SIZE] = {0};
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < (SIZE_MB * 1024 * 1024) / BUFFER_SIZE; i++)
    {
        write(fd, buffer, BUFFER_SIZE);
    }

    fsync(fd);
    clock_gettime(CLOCK_MONOTONIC, &end);
    close(fd);

    double time_taken = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("Large Write Time: %f seconds\n", time_taken);
}

int main()
{
    benchmark_large_write(FILE_PATH);
    return 0;
}
