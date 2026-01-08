#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <errno.h>
#include <stdarg.h>

// 最大支持的参数个数（可扩展）
#define MAX_ARGS 16
// x86_64栈对齐要求（16字节）
#define STACK_ALIGN 16

// 目标进程内存写入：将数据写入目标进程的指定内存地址
// 返回：成功返回0，失败返回-1
int write_to_target(pid_t pid, unsigned long addr, const void *data, size_t len) {
    if (pid <= 0 || addr == 0 || data == NULL || len == 0) {
        fprintf(stderr, "write_to_target参数无效\n");
        return -1;
    }

    const unsigned char *buf = (const unsigned char *)data;
    size_t i = 0;
    // ptrace_pokedata按word（8字节）写入，不足补0
    while (i < len) {
        unsigned long word = 0;
        memcpy(&word, buf + i, (len - i) >= 8 ? 8 : (len - i));
        
        if (ptrace(PTRACE_POKEDATA, pid, addr + i, word) == -1) {
            fprintf(stderr, "写入目标内存失败：addr=0x%lx, errno=%d → %s\n",
                    addr + i, errno, strerror(errno));
            return -1;
        }
        i += 8;
    }
    return 0;
}

// 目标进程内存读取：从目标进程指定地址读取数据
// 返回：成功返回0，失败返回-1
int read_from_target(pid_t pid, unsigned long addr, void *data, size_t len) {
    if (pid <= 0 || addr == 0 || data == NULL || len == 0) {
        fprintf(stderr, "read_from_target参数无效\n");
        return -1;
    }

    unsigned char *buf = (unsigned char *)data;
    size_t i = 0;
    // ptrace_peekdata按word（8字节）读取
    while (i < len) {
        unsigned long word = ptrace(PTRACE_PEEKDATA, pid, addr + i, NULL);
        if (word == (unsigned long)-1 && errno != 0) {
            fprintf(stderr, "读取目标内存失败：addr=0x%lx, errno=%d → %s\n",
                    addr + i, errno, strerror(errno));
            return -1;
        }
        memcpy(buf + i, &word, (len - i) >= 8 ? 8 : (len - i));
        i += 8;
    }
    return 0;
}

// 分配目标进程栈空间（简化版：基于原rsp向下预留空间）
// 返回：分配的栈起始地址，失败返回0
unsigned long alloc_stack_space(pid_t pid, struct user_regs_struct *orig_regs, size_t size) {
    if (pid <= 0 || orig_regs == NULL || size == 0) {
        return 0;
    }

    // 1. 计算需要预留的栈空间（向上取整到16字节对齐）
    size_t stack_size = ((size + STACK_ALIGN - 1) / STACK_ALIGN) * STACK_ALIGN;
    // 2. 新rsp = 原rsp - 栈空间 - 返回地址（8字节），并保证16字节对齐
    unsigned long new_rsp = orig_regs->rsp - stack_size - 8;
    new_rsp = (new_rsp / STACK_ALIGN) * STACK_ALIGN; // 强制16字节对齐

    return new_rsp;
}

/**
 * 通用ptrace函数调用接口
 * @param pid: 目标进程PID
 * @param func_addr: 要调用的函数地址（基地址+偏移）
 * @param ret_val: 输出参数，存储函数返回值（NULL则不获取）
 * @param arg_count: 函数参数个数
 * @param ...: 函数参数列表（所有参数统一用unsigned long传递，字符串/结构体传指针）
 * @return: 成功返回0，失败返回-1
 */
int ptrace_call_function(pid_t pid, unsigned long func_addr, 
                         unsigned long *ret_val, int arg_count, ...) {
    if (pid <= 0 || func_addr == 0 || arg_count < 0 || arg_count > MAX_ARGS) {
        fprintf(stderr, "ptrace_call_function参数无效\n");
        return -1;
    }

    // 步骤1：Attach目标进程并保存原始寄存器
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        fprintf(stderr, "Attach进程失败：errno=%d → %s\n", errno, strerror(errno));
        return -1;
    }

    // 等待进程暂停
    int status;
    waitpid(pid, &status, WUNTRACED);
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "进程未暂停：status=0x%x\n", status);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    // 保存原始寄存器
    struct user_regs_struct orig_regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &orig_regs) == -1) {
        fprintf(stderr, "获取原始寄存器失败：errno=%d → %s\n", errno, strerror(errno));
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    // 步骤2：准备函数调用的寄存器和栈
    struct user_regs_struct new_regs = orig_regs;
    va_list args;
    va_start(args, arg_count);

    // 2.1 处理前6个参数（存入rdi/rsi/rdx/rcx/r8/r9）
    unsigned long regs[6] = {&new_regs.rdi, &new_regs.rsi, &new_regs.rdx,
                             &new_regs.rcx, &new_regs.r8,  &new_regs.r9};
    for (int i = 0; i < arg_count && i < 6; i++) {
        unsigned long arg = va_arg(args, unsigned long);
        *((unsigned long *)regs[i]) = arg;
    }

    // 2.2 处理超过6个的参数（栈传递，从右到左压栈）
    unsigned long stack_addr = 0;
    if (arg_count > 6) {
        // 计算需要的栈空间（超过6个的参数个数 * 8字节）
        size_t stack_size = (arg_count - 6) * 8;
        // 分配栈空间
        stack_addr = alloc_stack_space(pid, &orig_regs, stack_size);
        if (stack_addr == 0) {
            fprintf(stderr, "分配栈空间失败\n");
            goto err_exit;
        }
        new_regs.rsp = stack_addr;

        // 从右到左写入参数（栈地址递增）
        unsigned long *stack_args = malloc(stack_size);
        if (stack_args == NULL) {
            fprintf(stderr, "分配栈参数内存失败\n");
            goto err_exit;
        }

        // 先读取所有超过6个的参数，存入临时数组
        for (int i = arg_count - 1; i >= 6; i--) {
            stack_args[i - 6] = va_arg(args, unsigned long);
        }

        // 写入栈空间
        if (write_to_target(pid, stack_addr, stack_args, stack_size) == -1) {
            free(stack_args);
            goto err_exit;
        }
        free(stack_args);
    }

    // 2.3 设置函数地址和返回地址（栈顶写入原rip，作为返回地址）
    new_regs.rip = func_addr; // 要调用的函数地址
    // 写入返回地址（栈顶 = new_rsp，返回地址=原rip）
    if (write_to_target(pid, new_regs.rsp, &orig_regs.rip, 8) == -1) {
        goto err_exit;
    }
    // 调整rsp：跳过返回地址（8字节），保证栈对齐
    new_regs.rsp -= 8;

    va_end(args);

    // 步骤3：设置新寄存器，执行函数调用
    if (ptrace(PTRACE_SETREGS, pid, NULL, &new_regs) == -1) {
        fprintf(stderr, "设置新寄存器失败：errno=%d → %s\n", errno, strerror(errno));
        goto err_exit;
    }

    // 继续执行进程（调用函数）
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
        fprintf(stderr, "执行函数失败：errno=%d → %s\n", errno, strerror(errno));
        goto err_exit;
    }

    // 等待函数执行完成（进程暂停）
    waitpid(pid, &status, WUNTRACED);
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "函数执行后进程未暂停：status=0x%x\n", status);
        goto err_exit;
    }

    // 步骤4：获取函数返回值（可选）
    if (ret_val != NULL) {
        struct user_regs_struct after_regs;
        if (ptrace(PTRACE_GETREGS, pid, NULL, &after_regs) == -1) {
            fprintf(stderr, "获取返回值失败：errno=%d → %s\n", errno, strerror(errno));
            goto err_exit;
        }
        *ret_val = after_regs.rax; // 返回值存在rax
    }

    // 步骤5：恢复原始寄存器，避免目标进程异常
    if (ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs) == -1) {
        fprintf(stderr, "恢复原始寄存器失败：errno=%d → %s\n", errno, strerror(errno));
        goto err_exit;
    }

    // 步骤6：Detach进程
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    printf("函数调用成功！\n");
    return 0;

err_exit:
    // 异常退出：恢复寄存器+detach
    ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return -1;
}

// ==================== 示例：调用目标进程的printf（字符串参数） ====================
// 步骤1：将字符串写入目标进程的栈空间，获取指针；步骤2：调用printf
int call_printf(pid_t pid, unsigned long printf_addr, const char *fmt, ...) {
    if (pid <= 0 || printf_addr == 0 || fmt == NULL) {
        fprintf(stderr, "call_printf参数无效\n");
        return -1;
    }

    // 步骤1：Attach进程，获取原始寄存器（用于分配栈空间）
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        fprintf(stderr, "Attach失败：%s\n", strerror(errno));
        return -1;
    }
    waitpid(pid, NULL, WUNTRACED);

    struct user_regs_struct orig_regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &orig_regs);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    // 步骤2：分配目标进程栈空间，写入格式化字符串
    size_t fmt_len = strlen(fmt) + 1; // 包含'\0'
    unsigned long fmt_addr = alloc_stack_space(pid, &orig_regs, fmt_len);
    if (fmt_addr == 0) {
        return -1;
    }
    // 写入格式化字符串到目标进程栈
    if (write_to_target(pid, fmt_addr, fmt, fmt_len) == -1) {
        return -1;
    }

    // 步骤3：处理可变参数（简化版：仅支持1个字符串参数）
    va_list args;
    va_start(args, fmt);
    const char *arg_str = va_arg(args, const char *);
    va_end(args);

    unsigned long arg_addr = 0;
    if (arg_str != NULL) {
        // 写入参数字符串到目标进程栈
        size_t arg_len = strlen(arg_str) + 1;
        arg_addr = fmt_addr + fmt_len + 8; // 偏移，避免覆盖
        if (write_to_target(pid, arg_addr, arg_str, arg_len) == -1) {
            return -1;
        }
    }

    // 步骤4：调用printf（参数1：fmt_addr，参数2：arg_addr）
    unsigned long ret_val;
    int ret = ptrace_call_function(pid, printf_addr, &ret_val, 2, fmt_addr, arg_addr);
    if (ret == 0) {
        printf("printf返回值：%ld（输出字符数）\n", ret_val);
    }
    return ret;
}

// ==================== 示例：自定义结构体参数 ====================
// 1. 定义结构体（目标进程和控制进程需一致）
typedef struct {
    int id;
    char name[16];
    unsigned long ptr;
} TestStruct;

// 2. 调用目标进程的自定义函数（参数为TestStruct指针）
int call_custom_func(pid_t pid, unsigned long func_addr, const TestStruct *data) {
    if (pid <= 0 || func_addr == 0 || data == NULL) {
        return -1;
    }

    // 步骤1：Attach获取原始寄存器，分配栈空间
    ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    waitpid(pid, NULL, WUNTRACED);
    struct user_regs_struct orig_regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &orig_regs);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    // 步骤2：写入结构体到目标进程栈
    unsigned long struct_addr = alloc_stack_space(pid, &orig_regs, sizeof(TestStruct));
    if (struct_addr == 0) {
        return -1;
    }
    if (write_to_target(pid, struct_addr, data, sizeof(TestStruct)) == -1) {
        return -1;
    }

    // 步骤3：调用自定义函数（参数为结构体指针）
    unsigned long ret_val;
    return ptrace_call_function(pid, func_addr, &ret_val, 1, struct_addr);
}

// 主函数：演示用法
int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "用法1（调用printf）：%s <PID> <printf地址> printf <格式化字符串> <参数>\n", argv[0]);
        fprintf(stderr, "用法2（调用自定义函数）：%s <PID> <自定义函数地址> custom\n", argv[0]);
        return -1;
    }

    pid_t pid = atoi(argv[1]);
    unsigned long func_addr = strtoul(argv[2], NULL, 16);
    const char *type = argv[3];

    if (strcmp(type, "printf") == 0) {
        // 示例1：调用printf
        if (argc < 5) {
            fprintf(stderr, "缺少printf参数：%s <PID> <printf地址> printf \"hello %s\" \"world\"\n", argv[0]);
            return -1;
        }
        const char *fmt = argv[4];
        const char *arg = argv[5];
        call_printf(pid, func_addr, fmt, arg);
    } else if (strcmp(type, "custom") == 0) {
        // 示例2：调用自定义结构体参数函数
        TestStruct data = {
            .id = 100,
            .name = "test",
            .ptr = 0x12345678
        };
        call_custom_func(pid, func_addr, &data);
    } else {
        fprintf(stderr, "不支持的类型：%s\n", type);
        return -1;
    }

    return 0;
}