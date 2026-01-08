#include <stdio.h>
#include <elf.h>
#include <libelf.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/types.h>
#include <errno.h>
#include <dlfcn.h>

unsigned long lookup_static_symbol(const char* elf_file, const char* symbol_name)
{
    elf_version(EV_CURRENT);

    int fd = open(elf_file, O_RDONLY);
   
    if (fd == -1)
    {
        printf("fd == -1\n");
        return 0;
    }


    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) {
        printf("Error opening ELF file: %s\n", elf_file);
        return 0;
    }
 
    Elf64_Ehdr *ehdr = elf64_getehdr(elf);
    if (!ehdr) {
        printf("Error getting ELF header\n");
        elf_end(elf);
        return 0;
    }
 
    printf("ELF Header:\n");
    printf("  Magic:   ");
    for (int i = 0; i < EI_NIDENT; i++) {
        printf("%02x ", ehdr->e_ident[i]);
    }
    printf("\n");
    printf("  Class:                             %s\n", ehdr->e_ident[EI_CLASS] == ELFCLASS32? "ELF32" : "ELF64");
    printf("  Data:                              %s\n", ehdr->e_ident[EI_DATA] == ELFDATA2LSB? "2's complement, little endian" : "2's complement, big endian");
    printf("  Version:                           %d\n", ehdr->e_ident[EI_VERSION]);
    printf("  OS/ABI:                            %d\n", ehdr->e_ident[EI_OSABI]);
    printf("  ABI Version:                       %d\n", ehdr->e_ident[EI_ABIVERSION]);
    printf("  Type:                              %d\n", ehdr->e_type);
    printf("  Machine:                           %d\n", ehdr->e_machine);
    printf("  Version:                           %d\n", ehdr->e_version);
    printf("  Entry point address:               0x%lx\n", ehdr->e_entry);
    printf("  Start of program headers:          %ld (bytes into file)\n", ehdr->e_phoff);
    printf("  Start of section headers:          %ld (bytes into file)\n", ehdr->e_shoff);
    printf("  Flags:                             0x%x\n", ehdr->e_flags);
    printf("  Size of this header:               %d (bytes)\n", ehdr->e_ehsize);
    printf("  Size of program headers:           %d (bytes)\n", ehdr->e_phentsize);
    printf("  Number of program headers:         %d\n", ehdr->e_phnum);
    printf("  Size of section headers:           %d (bytes)\n", ehdr->e_shentsize);
    printf("  Number of section headers:         %d\n", ehdr->e_shnum);
    printf("  Section header string table index: %d\n", ehdr->e_shstrndx);

    unsigned long sym_addr = 0;
  // 5. 遍历节表，找到符号表（.symtab/.dynsym）
    Elf_Scn *scn = NULL;  // 节对象句柄
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        // 获取节头
        Elf64_Shdr *shdr = elf64_getshdr(scn);
        if (shdr == NULL) continue;

        // 只处理符号表节（SHT_SYMTAB/SHT_DYNSYM）
        if (shdr->sh_type != SHT_SYMTAB && shdr->sh_type != SHT_DYNSYM) {
            continue;
        }

        // 6. 获取符号表数据
        Elf_Data *data = elf_getdata(scn, NULL);
        if (data == NULL) continue;

        // 7. 遍历符号表项
        int sym_count = shdr->sh_size / shdr->sh_entsize;
        Elf64_Sym *symtab = (Elf64_Sym *)data->d_buf;
        // 获取符号字符串表（sh_link指向字符串表节的索引）
        Elf_Scn *str_scn = elf_getscn(elf, shdr->sh_link);
        Elf_Data *str_data = elf_getdata(str_scn, NULL);
        char *strtab = (char *)str_data->d_buf;

        // 8. 查找目标符号
        for (int i = 0; i < sym_count; i++) {
            Elf64_Sym *sym = &symtab[i];
            char *name = strtab + sym->st_name;
            // 空名称跳过
            if (name[0] == '\0') continue;

            int is_func = 1;

            // 匹配符号名 + 类型（函数=STT_FUNC，变量=STT_OBJECT）
            if (strcmp(name, "remap_stdout") == 0) {
                unsigned char sym_type = ELF64_ST_TYPE(sym->st_info);
                if ((is_func && sym_type == STT_FUNC) || (!is_func && sym_type == STT_OBJECT)) {
                    sym_addr = sym->st_value;
                    printf("[INFO] 找到符号%s：类型=%s，地址=0x%lx\n",
                           "remap_stdout", is_func ? "函数" : "变量", sym_addr);
                    
                }
            }
        }
    }

    elf_end(elf);

    return sym_addr;
}

typedef int (*Func) (int , int);

unsigned long lookup_dynamic_symbol(const char* symbol_name)
{
    // void *handle = dlopen("./libc.so.6", RTLD_NOW);
    // if (handle == NULL) {
    //     // 错误检查：必须查dlerror，不能只看NULL
    //     fprintf(stderr, "dlopen失败：%s\n", dlerror());
    //     exit(EXIT_FAILURE);
    // }
    // 4. 查找dup2函数地址（目标进程的libc中）
    void *dup2_addr = dlsym(RTLD_NEXT, symbol_name);
    if (dup2_addr == NULL) {
        fprintf(stderr, "dlsym dup2 failed: %s\n", dlerror());
        return 0;
    }
    unsigned long dup2_ptr = (unsigned long)dup2_addr;

    printf("lookup_dynamic_symbol dup2_ptr [%lx]\n", 0x770c55400000+0x0000000000116990);
    return 0x770c55400000+0x0000000000116990;

    // return dup2_ptr;
}
// pid_t pid = -1;
int is_attached = 0;

// 辅助函数：让目标进程调用open获取/dev/pts/0的FD（解决跨进程FD问题）
unsigned long target_open_fd(pid_t pid, const char *path, int flags, mode_t mode) {
    // 1. 获取目标进程原始寄存器
    printf("enter target_open_fd\n");
    struct user_regs_struct orig_regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &orig_regs) == -1) {
        printf("PTRACE_GETREGS (open) failed\n");
        return -1;
    }

    // 2. 查找目标进程的open函数地址（需提前获取目标进程的open偏移，或用syscall）
    // 简化方案：直接调用open的syscall（x86_64 sys_open的号是2）
    struct user_regs_struct regs = orig_regs;
    regs.rax = 2;                  // x86_64 sys_open的syscall号
    regs.rdi = orig_regs.rsp - 16; // 栈地址：存放path字符串（目标进程栈）
    regs.rsi = flags;              // open的flags
    regs.rdx = mode;               // open的mode

    // 3. 将path字符串写入目标进程栈
    char path_buf[256];
    strncpy(path_buf, path, sizeof(path_buf)-1);
    path_buf[sizeof(path_buf)-1] = '\0';
    for (int i=0; i<strlen(path_buf); i+=8) {
        unsigned long data = 0;
        memcpy(&data, path_buf+i, 8);
        if (ptrace(PTRACE_POKEDATA, pid, regs.rdi+i, data) == -1) {
            printf("PTRACE_POKEDATA (path) failed\n");
            return -1;
        }
    }

    // 4. 设置寄存器，执行sys_open
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1) {
        printf("PTRACE_SETREGS (open) failed\n");
        return -1;
    }
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    waitpid(pid, NULL, WUNTRACED);

    // 5. 获取open的返回值（rax寄存器）
    struct user_regs_struct after_regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &after_regs) == -1) {
        printf("PTRACE_GETREGS (open ret) failed\n");
        return -1;
    }

    // 6. 恢复原始寄存器
    ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs);
    return after_regs.rax; // 返回目标进程中/dev/pts/0的FD
}

int hijack_func(const pid_t pid, const unsigned long func_ptr)
{
    printf("ptrace attach pid[%d], func ptr[%lx]\n", pid, func_ptr);

    // 1. 重新附加进程（若已分离，需重新attach）
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        printf("ptrace attach (cleanup) failed, pid[%d]\n", pid);
        exit(EXIT_FAILURE);
    }
    waitpid(pid, NULL, WUNTRACED); // 等待进程暂停
    is_attached = 1;

    printf("ptrace success\n");

    // 3. 打开/dev/pts/0，获取fd
    int null_fd = 4;
    // int null_fd = open("/dev/pts/0", 2);

    // if (null_fd == -1) {
    //     printf("open /dev/pts/0 failed\n");
    //     // return -1;
    // }
    printf("open /dev/pts/0 fd[%d]\n", null_fd);

    struct user_regs_struct orig_regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &orig_regs) == -1) {
        printf("ptrace getregs failed\n");
        // return -1;
    }

    struct user_regs_struct regs ;
    // if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
    //     printf("ptrace getregs failed\n");
    //     // return -1;
    // }
    // // 5. 设置dup2参数：dup2(null_fd, 1) → stdout
    regs.rdi = null_fd;   // 第一个参数：新fd
    regs.rsi = 1;         // 第二个参数：stdout(1)
    regs.rip = func_ptr;  // 程序计数器指向dup2

    long rsp_signed = (long)orig_regs.rsp;
    regs.rsp = rsp_signed - 8;       // x86_64栈向下生长，预留8字节存返回地址

    printf("调整前rsp：0x%lx，调整后rsp：0x%lx，是否8字节对齐：%s\n",
       orig_regs.rsp, regs.rsp, (regs.rsp % 8 == 0) ? "是" : "否");
    // 将原rip作为返回地址写入栈（调用完dup2后回到原指令）
    if (ptrace(PTRACE_POKEDATA, pid, regs.rsp, orig_regs.rip) == -1) {
        printf("PTRACE_POKEDATA (return addr) failed\n");
    }

    printf("set regs  regs.rdi[%llx], regs.rsi[%llx], regs.rip[%llx]\n",regs.rdi, regs.rsi, regs.rip);

    int ret = ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    if (ret == -1) {
        fprintf(stderr, "SETREGS失败：errno=%d → %s\n", errno, strerror(errno));
        // 关键：根据errno定位原因
        if (errno == EINVAL)  printf("→ 原因：寄存器值非法/进程状态错误/32/64位不匹配\n");
        if (errno == EPERM)   printf("→ 原因：极端权限限制（内核进程/容器/seccomp）\n");
        if (errno == EFAULT)  printf("→ 原因：寄存器结构体地址无效（用户态）\n");
        if (errno == ESRCH)   printf("→ 原因：进程已退出/不存在\n");
    }

    // 6. 单步执行dup2
    // if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) {
    //     printf("ptrace singlestep (cleanup stdout) failed\n");
    //     // return -1;
    // }
    // waitpid(pid, NULL, WUNTRACED);
    // 6. 恢复进程执行（执行dup2）
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
        printf("PTRACE_CONT failed\n");
    }
    // 等待dup2执行完成
    int status;
    pid_t wait_ret = waitpid(pid, &status, WUNTRACED);

    if (wait_ret == -1 || !WIFSTOPPED(status)) {
        fprintf(stderr, "dup2未执行完成！\n");
    } else {
    printf("dup2已执行完成，进程暂停\n");
    // 此时立即查看FD 1（临时验证）
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "ls -l /proc/%d/fd", pid);
    system(cmd); // 若此时FD 1指向/dev/pts/0，说明后续被覆盖
}
    // system("ls -l /proc/232224/fd");
    // 7. 重复步骤，重定向stderr(2)
    // regs.rdi = 2;
    // regs.rsi = null_fd;
    // regs.rip = func_ptr;
    // if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1) {
    //     printf("ptrace setregs (cleanup stderr) failed\n");
    //     // return -1;
    // }
    // if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) {
    //     printf("ptrace singlestep (cleanup stderr) failed\n");
    //     // return -1;
    // }
    // waitpid(pid, NULL, WUNTRACED);
    // 5. （可选）检查dup2的返回值（rax寄存器）
    close(null_fd);

    struct user_regs_struct after_regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &after_regs);
    if (after_regs.rax == -1) { // dup2返回-1表示失败
        fprintf(stderr, "dup2执行失败，errno=%ld\n", after_regs.rdi); // errno存在rdi
    } else {
        printf("dup2执行成功，返回值=%ld\n", after_regs.rax);
    }
    // 8. 恢复原始寄存器，分离进程
    if (ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs) == -1)
    {
        printf("ptrace recover failed\n");
    }
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    printf("[SUCCESS] 进程%d输出已重定向到/dev/pts/0，脚本退出\n", pid);
    return 0;
}

int main(int argc, char *argv[]) {
    // if (argc!= 3) {
    //     printf("Usage: %s <elf_file>\n", argv[0]);
    //     return 1;
    // }

    unsigned long sym_addr = 0;

    if ((sym_addr = lookup_dynamic_symbol("dup2")))
    {
        hijack_func(232224, sym_addr);
    }
    else if ((sym_addr = lookup_static_symbol(argv[1], "dup2")))
    {
        printf("do nothing\n");
    }
    else
    {
        printf("not find symbol\n");
    }
 
    return 0;
}