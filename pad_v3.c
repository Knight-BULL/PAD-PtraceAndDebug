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
#include <stdbool.h>

unsigned long lookup_static_symbol(const pid_t _pid, const char* symbol_name, const bool is_func)
{
    elf_version(EV_CURRENT);
    char* elf_file;
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

// 动态库信息结构体：存储路径+基地址
typedef struct {
    char lib_path[256];  // 动态库绝对路径（如/lib/x86_64-linux-gnu/libc.so.6）
    unsigned long base_addr; // 运行时基地址（十六进制）
} LibInfo;

// 解析/proc/<pid>/maps，获取所有动态库的路径和基地址（去重）
// 参数：pid-目标进程PID，lib_list-输出的动态库信息数组，max_count-数组最大容量
// 返回：成功解析的动态库数量，失败返回-1
int parse_proc_maps(pid_t pid, LibInfo *lib_list, int max_count) {
    if (pid <= 0 || lib_list == NULL || max_count <= 0) {
        fprintf(stderr, "参数无效：pid=%d, lib_list=%p, max_count=%d\n", pid, lib_list, max_count);
        return -1;
    }

    // 拼接/proc/<pid>/maps路径
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    // 打开maps文件
    FILE *fp = fopen(maps_path, "r");
    if (fp == NULL) {
        fprintf(stderr, "打开%s失败：errno=%d → %s\n", maps_path, errno, strerror(errno));
        return -1;
    }

    char line[512];          // 存储maps每行内容
    int lib_count = 0;       // 已解析的动态库数量
    char last_lib_path[256] = {0}; // 上一个解析的库路径（去重）

    // 逐行解析maps
    while (fgets(line, sizeof(line), fp) != NULL && lib_count < max_count) {
        // maps每行格式示例：72fe71c20000-72fe71e00000 r-xp 00000000 103:02 1234 /lib/x86_64-linux-gnu/libc.so.6
        // 提取：基地址（72fe71c20000）、路径（最后一列）
        unsigned long base_addr;
        char perm[8], dev[16], path[256];
        int offset, inode;

        // 解析行内容（重点提取基地址和路径）
        int parsed = sscanf(line, "%lx-%*lx %s %x %s %d %255s", 
                            &base_addr, perm, &offset, dev, &inode, path);
        if (parsed < 6) {
            continue; // 非动态库行（如匿名映射），跳过
        }

        // 过滤：仅保留动态库路径（路径非空且包含.so）
        if (strstr(path, ".so") == NULL) {
            continue;
        }

        // 去重：同一动态库只保留第一个基地址（所有段基地址相同）
        if (strcmp(path, last_lib_path) == 0) {
            continue;
        }

        // 存储到lib_list
        strncpy(lib_list[lib_count].lib_path, path, sizeof(lib_list[lib_count].lib_path)-1);
        lib_list[lib_count].base_addr = base_addr;
        lib_count++;

        // 更新上一个库路径（去重用）
        strncpy(last_lib_path, path, sizeof(last_lib_path)-1);
    }

    fclose(fp);
    return lib_count;
}

// 调用readelf -s解析动态库，获取指定符号的偏移地址
// 参数：lib_path-动态库文件路径，symbol-要查找的符号名（如dup2）
// 返回：符号的十六进制偏移地址，失败返回-1
unsigned long get_symbol_offset(const char *lib_path, const char *symbol) {
    if (lib_path == NULL || symbol == NULL || strlen(symbol) == 0) {
        fprintf(stderr, "参数无效：lib_path=%s, symbol=%s\n", lib_path, symbol);
        return -1;
    }

    // 检查动态库文件是否存在
    if (access(lib_path, F_OK) != 0) {
        fprintf(stderr, "动态库文件不存在：%s\n", lib_path);
        return -1;
    }

    // 构造readelf命令：readelf -s lib_path | grep -w "symbol@@GLIBC_X.X.X"
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "readelf -s %s | grep -w '%s@@'", lib_path, symbol);

    // 执行命令并读取输出
    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        fprintf(stderr, "执行命令失败：%s → errno=%d → %s\n", cmd, errno, strerror(errno));
        return -1;
    }

    char line[512];
    unsigned long sym_offset = -1;

    // 解析readelf输出：示例行（重点提取Value列的偏移）
    //  Num:    Value          Size Type    Bind   Vis      Ndx Name
    //  1234: 00000000000116990   34 FUNC    GLOBAL DEFAULT   14 dup2@@GLIBC_2.2.5
    while (fgets(line, sizeof(line), fp) != NULL) {
        printf("@@line is [%s]\n", line);
        unsigned long value;
        char type[16], bind[16], vis[16], ndx[8], name[64];
        int num, size, indx;

        // 解析Value（偏移）和Name（符号名）
        int parsed = sscanf(line, "%d: %lx    %d %s    %s   %s   %d %63s", 
                            &num, &value, &size, type, bind, vis, &indx, name);
                            // %d: %lx    %d %s    %s   %s   %d %63s
        if (parsed < 8) {
            continue;
        }

        // 匹配符号名（优先带@@的版本符号）
        if (strstr(name, symbol) != NULL && strstr(name, "@@") != NULL) {
            printf("!!!!!!!!!!!!!find it!!!!\n");
            sym_offset = value;
            break;
        }
    }

    pclose(fp);

    // 若未找到带@@的符号，重试不带版本的符号（兼容旧系统）
    if (sym_offset == -1) {
        snprintf(cmd, sizeof(cmd), "readelf -s %s | grep -w '%s'", lib_path, symbol);
        fp = popen(cmd, "r");
        if (fp != NULL) {
            while (fgets(line, sizeof(line), fp) != NULL) {
                printf("line is [%s]\n", line);

                unsigned long value;
                char type[16], bind[16], vis[16], ndx[8], name[64];
                int num, size, indx;
                int parsed = sscanf(line, "  %d: %lx    %d %s    %s   %s   %d %s", 
                                    &num, &value, &size, type, bind, vis, &indx, name);

                // printf("%d: %lx    %d %s    %s   %s   %d %s\n", num, value, size, type, bind, vis, indx, name);
                printf("name:%s, symbol:%s\n", name, symbol);
                
                if ( strstr(name, symbol) != NULL) {
                    sym_offset = value;
                    printf("find u again!!!!!!!!!!!!!!!!!!!!!!!\n");
                    break;
                }
            }
            pclose(fp);
        }
    }

    if (sym_offset == -1) {
        fprintf(stderr, "未找到符号%s在动态库%s中的偏移\n", symbol, lib_path);
    }
    return sym_offset;
}

LibInfo lib_list[32]; 
unsigned long lookup_dynamic_symbol(const pid_t _pid, const char* symbol_name, const is_func)
{
    //获取基地址，从/proc/_pid/maps中获取，前提得直到所在动态库
    //获取偏移地址，从所在动态库readelf获取
    // 最多存储32个动态库
    (void)memset(lib_list, 0x00, sizeof(lib_list));
    int lib_count = parse_proc_maps(_pid, lib_list, sizeof(lib_list)/sizeof(LibInfo));
    if (lib_count <= 0) {
        fprintf(stderr, "解析/proc/%d/maps失败\n", _pid);
        return 0;
    }
    printf("===== 进程%d的动态库及基地址 =====\n", _pid);
    for (int i=0; i<lib_count; i++) {
        printf("动态库：%s\n基地址：0x%lx\n\n", lib_list[i].lib_path, lib_list[i].base_addr);
    }

    // 步骤2：遍历动态库，查找指定符号的偏移，并计算绝对地址
    printf("===== 符号%s的地址信息 =====\n", symbol_name);
    for (int i=0; i<lib_count; i++) {
        // 获取符号在动态库中的偏移
        unsigned long sym_offset = get_symbol_offset(lib_list[i].lib_path, symbol_name);
        if (sym_offset == -1) {
            continue;
        }

        // 计算符号在目标进程中的绝对地址（基地址+偏移）
        unsigned long absolute_addr = lib_list[i].base_addr + sym_offset;

        // 打印结果
        printf("动态库：%s\n", lib_list[i].lib_path);
        printf("符号偏移：0x%lx\n", sym_offset);
        printf("绝对地址：0x%lx\n\n", absolute_addr);

        return absolute_addr;
    }

    return 0;
}

int ptrace_call(const pid_t pid, unsigned long long int func_ptr, int n_args, unsigned long args[])//参数列表
{
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
    regs.rdi = args[0];   // 第一个参数：新fd
    regs.rsi = args[1];         // 第二个参数：stdout(1)
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
    close(args[0]);

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
}

int call_any_func(const pid_t pid, const char* symbol, void* ret, int n_args, unsigned long args[])
{
    unsigned long func_ptr;

    if ((func_ptr = lookup_dynamic_symbol(pid, symbol, true)))
    {
        return ptrace_call(pid, func_ptr, n_args, args);
    }
    else if ((func_ptr =  lookup_dynamic_symbol(pid, symbol, true)))
    {
        return ptrace_call(pid, func_ptr, n_args, args);
    }

    return -1;
}

int call_any_func_independent(const pid_t pid, const char* symbol, void* ret, int n_args, unsigned long args[])
{
    //attach pid
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) 
    {
        printf("ptrace attach (cleanup) failed, pid[%d]\n", pid);
        return -1;
    }
    waitpid(pid, NULL, WUNTRACED); // 等待进程暂停
    struct user_regs_struct orig_regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &orig_regs) == -1) {
        printf("ptrace getregs failed\n");
        // return -1;
    }

    call_any_func(pid, symbol, ret, n_args, args);

    // 8. 恢复原始寄存器，分离进程
    if (ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs) == -1)
    {
        printf("ptrace recover failed\n");
    }
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    printf("[SUCCESS] 进程%d输出已重定向到/dev/pts/0，脚本退出\n", pid);
    //detach pid   
}

// int ptrace_set(const pid_t pid, unsigned long long int var_ptr, int n_args, unsigned long args[])//参数列表
// {

// }

// int set_any_var(const pid_t pid, const char* symbol, int n_args, unsigned long args[])//参数列表
// {
//     if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) 
//     {
//         printf("ptrace attach (cleanup) failed, pid[%d]\n", pid);
//         return -1;
//     }
//     waitpid(pid, NULL, WUNTRACED); // 等待进程暂停

//     unsigned long long int var_ptr;

//     if ((var_ptr = lookup_dynamic_symbol(pid, symbol, false)))
//     {
//         return ptrace_set(pid, var_ptr);
//     }
//     else if ((var_ptr = lookup_static_symbol(pid, symbol, false)))
//     {
//         return ptrace_set(pid, var_ptr);
//     }

//     return -1;
// }

int hijack_func(const pid_t pid, const unsigned long func_ptr)
{
    printf("ptrace attach pid[%d], func ptr[%lx]\n", pid, func_ptr);

    // 1. 重新附加进程（若已分离，需重新attach）
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        printf("ptrace attach (cleanup) failed, pid[%d]\n", pid);
        exit(EXIT_FAILURE);
    }
    waitpid(pid, NULL, WUNTRACED); // 等待进程暂停

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

void remap_output(const pid_t pid, const char* tty)
{
    //attach pid
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) 
    {
        printf("ptrace attach (cleanup) failed, pid[%d]\n", pid);
        return -1;
    }
    waitpid(pid, NULL, WUNTRACED); // 等待进程暂停
    struct user_regs_struct orig_regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &orig_regs) == -1) {
        printf("ptrace getregs failed\n");
        // return -1;
    }

    int fd;
    unsigned long open_args[2];
    // 重定向stdout（dup2(tty_fd, 1)）
    open_args[0] = 2;
    open_args[0] = 2;
    call_any_func(pid, "open", &fd, 2, open_args);

    unsigned long dup2_args[2];
    // 重定向stdout（dup2(tty_fd, 1)）
    dup2_args[0] = fd;
    dup2_args[1] = 1;
    call_any_func(pid, "dup2", NULL, 2, dup2_args);
    dup2_args[0] = fd;
    dup2_args[1] = 2;
    call_any_func(pid, "dup2", NULL, 2, dup2_args);

    call_any_func(pid, "close", NULL, 0, NULL);

    // 8. 恢复原始寄存器，分离进程
    if (ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs) == -1)
    {
        printf("ptrace recover failed\n");
    }
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    printf("[SUCCESS] 进程%d输出已重定向到/dev/pts/0，脚本退出\n", pid);
    //detach pid
}

int main(int argc, char *argv[]) {
    // if (argc!= 3) {
    //     printf("Usage: %s <elf_file>\n", argv[0]);
    //     return 1;
    // }

    unsigned long sym_addr = 0;

    //根据函数名称获取pid
    
    // lookup_dynamic_symbol(232224, "dup2", true);
    unsigned long dup2_args[2];
    // 重定向stdout（dup2(tty_fd, 1)）
    dup2_args[0] = 3;
    dup2_args[1] = 1;
    // call_any_func_independent(232224, "dup2", NULL, 2, dup2_args);
    remap_output(232224, "/dev/pts/4");
    // const char *curr_tty;
    // //重定向输出
    // remap_output(target_pid, curr_tty);//将输出重定位到当前终端
 
    // while (1)//不断监测输入命令
    // {
    //     scanf();//获取命令
    //     //解析命令，只支持两种：1.函数调用，2，参数修改
    //     //如果是函数调用：call_any_func_independent
    //     //如果是参数修改：set_any_var
    //     //退出当前控制进程需要保证命令执行完毕
    // }

    return 0;
}