#include <unistd.h>
// #include <stat.h>
#include <stdlib.h>
#include <stdio.h>  // 注：代码中使用了printf，实际编译需包含此头文件（截图中未显示但逻辑需要）
#include <fcntl.h>  // 注：O_RDWR/O_CREAT等宏来自此头文件（截图中未显示但逻辑需要）
#include <sys/types.h>
#include <sys/wait.h>

int testflag = 1;

void remap_stdout(char* out_file)
{
    int newfd;
    int fd = open(out_file, O_RDWR | O_CREAT | O_APPEND);
    newfd = dup2(fd, fileno(stdout));

    fflush(stdout);
    if (newfd == -1)
    {
        printf("redirect standard out to %s error", out_file);
    }
    else
    {
        printf("redirect standard out to %s success", out_file);
    }
    close(fd);
}

void remap_stderr(char* out_file)
{
    int newfd;
    int fd = open(out_file, O_RDWR | O_CREAT | O_APPEND);
    newfd = dup2(fd, fileno(stderr));

    fflush(stderr);
    if (newfd == -1)
    {
        printf("redirect standard out to %s error", out_file);
    }
    else
    {
        printf("redirect standard out to %s success", out_file);
    }
    close(fd);
}

int main()
{
    // remap_stdout("/dev/null");
    // remap_stderr("/dev/null");
    // remap_stdout("/dev/pts/3");
    // remap_stderr("/dev/pts/3");
    pid_t pid = fork();
    if(pid != 0)
    {
        exit(0);
    }

    int fd2 = open("/dev/null", O_RDWR | O_CREAT | O_APPEND);

    int fd = open("/dev/pts/1", O_RDWR | O_CREAT | O_APPEND);

    while(1)
    {
        // setsid();
        // // 更改当前工作目录
        // chdir("/");
        // // 设置权限掩码，权限最大
        // umask(0);

        sleep(1);
        if(testflag)
            printf("[%s: %s: L:%d] #####nsqtest222 fd[%d] fd2[%d]\n", __FILE__, __func__, __LINE__, fd, fd2);
        // fflush(stdout);
        // fflush(stderr);
    }
}