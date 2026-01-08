#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <errno.h>
#include <stddef.h>

// ==================== 核心定义 ====================
// 参数类型枚举（覆盖所有需要的类型）
typedef enum {
    ARG_TYPE_INT,          // 普通整数/指针（unsigned long）
    ARG_TYPE_STRING,       // 字符串（自动写入目标进程内存，传指针）
    ARG_TYPE_STRUCT_VAL,   // 结构体值传递（≤16字节，拆分到寄存器）
    ARG_TYPE_STRUCT_HIDDEN // 大结构体值传递（＞16字节，内核隐藏指针，需写内存）
} PtraceArgType;

// 参数结构体（通用，适配所有类型）
typedef struct {
    PtraceArgType type;    // 参数类型
    union {
        unsigned long int_val;          // 对应ARG_TYPE_INT
        const char *str_val;            // 对应ARG_TYPE_STRING
        struct {                        // 对应ARG_TYPE_STRUCT_VAL/STRUCT_HIDDEN
            const void *data;           // 结构体数据指针（控制进程侧）
            size_t size;                // 结构体大小
        } struct_val;
    } val;
} PtraceFuncArg;

// 最大支持6个参数（符合x86_64调用约定）
#define MAX_ARGS 6
// x86_64栈对齐要求（16字节）
#define STACK_ALIGN 16

// ==================== 工具函数 ====================
// 写入数据到目标进程内存（按8字节对齐）
static int write_to_target(pid_t pid, unsigned long addr, const void *data, size_t len) {
    if (pid <= 0 || addr == 0 || data == NULL || len == 0) return -1;

    const unsigned char *buf = (const unsigned char *)data;
    size_t i = 0;
    while (i < len) {
        unsigned long word = 0;
        memcpy(&word, buf + i, (len - i) >= 8 ? 8 : (len - i));
        if (ptrace(PTRACE_POKEDATA, pid, addr + i, word) == -1) {
            fprintf(stderr, "写入目标内存失败: 0x%lx, err=%s\n", addr+i, strerror(errno));
            return -1;
        }
        i += 8;
    }
    return 0;
}

// 分配目标进程栈空间（基于原rsp向下预留，保证16字节对齐）
static unsigned long alloc_stack(pid_t pid, const struct user_regs_struct *orig_regs, size_t need_size) {
    if (pid <= 0 || orig_regs == NULL || need_size == 0) return 0;

    // 计算总需要的栈空间（向上取整到16字节）
    size_t total_size = ((need_size + STACK_ALIGN - 1) / STACK_ALIGN) * STACK_ALIGN;
    // 新rsp = 原rsp - 栈空间 - 返回地址（8字节），强制16字节对齐
    unsigned long new_rsp = orig_regs->rsp - total_size - 8;
    return (new_rsp / STACK_ALIGN) * STACK_ALIGN;
}

// 预处理参数：将字符串/大结构体转为目标进程内存指针（统一为ARG_TYPE_INT）
static int preprocess_args(pid_t pid, const struct user_regs_struct *orig_regs,
                           PtraceFuncArg *args, int arg_count) {
    if (pid <= 0 || orig_regs == NULL || args == NULL || arg_count > MAX_ARGS) return -1;

    for (int i = 0; i < arg_count; i++) {
        switch (args[i].type) {
            case ARG_TYPE_STRING: {
                // 1. 字符串：写入目标进程栈，替换为指针
                const char *str = args[i].val.str_val;
                size_t str_len = strlen(str) + 1; // 包含'\0'
                unsigned long str_addr = alloc_stack(pid, orig_regs, str_len);
                if (str_addr == 0) return -1;
                if (write_to_target(pid, str_addr, str, str_len) == -1) return -1;
                // 转为普通整数参数（指针值）
                args[i].type = ARG_TYPE_INT;
                args[i].val.int_val = str_addr;
                break;
            }
            case ARG_TYPE_STRUCT_HIDDEN: {
                // 2. 大结构体：写入目标进程栈，替换为隐藏指针
                const void *struct_data = args[i].val.struct_val.data;
                size_t struct_size = args[i].val.struct_size;
                unsigned long struct_addr = alloc_stack(pid, orig_regs, struct_size);
                if (struct_addr == 0) return -1;
                if (write_to_target(pid, struct_addr, struct_data, struct_size) == -1) return -1;
                // 转为普通整数参数（隐藏指针值）
                args[i].type = ARG_TYPE_INT;
                args[i].val.int_val = struct_addr;
                break;
            }
            case ARG_TYPE_INT:
            case ARG_TYPE_STRUCT_VAL:
                // 无需预处理（普通参数/小结构体直接处理）
                break;
            default:
                fprintf(stderr, "不支持的参数类型: %d\n", args[i].type);
                return -1;
        }
    }
    return 0;
}

// ==================== 核心调用接口 ====================
/**
 * 通用ptrace函数调用接口（6参数以内）
 * @param pid: 目标进程PID
 * @param func_addr: 要调用的函数地址（运行时绝对地址）
 * @param args: 参数数组（已定义类型和值）
 * @param arg_count: 参数个数（0~6）
 * @param ret_val: 输出参数，函数返回值（NULL则不获取）
 * @return: 成功返回0，失败返回-1
 */
int ptrace_call_func(pid_t pid, unsigned long func_addr,
                     PtraceFuncArg *args, int arg_count, unsigned long *ret_val) {
    // 1. 参数校验
    if (pid <= 0 || func_addr == 0 || arg_count < 0 || arg_count > MAX_ARGS) {
        fprintf(stderr, "参数无效: pid=%d, func=0x%lx, args=%d\n", pid, func_addr, arg_count);
        return -1;
    }

    // 2. Attach进程并保存原始寄存器
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        fprintf(stderr, "Attach失败: %s\n", strerror(errno));
        return -1;
    }
    int status;
    waitpid(pid, &status, WUNTRACED);
    if (!WIFSTOPPED(status)) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        fprintf(stderr, "进程未暂停: status=0x%x\n", status);
        return -1;
    }

    struct user_regs_struct orig_regs, new_regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &orig_regs) == -1) {
        fprintf(stderr, "获取寄存器失败: %s\n", strerror(errno));
        goto err_exit;
    }
    new_regs = orig_regs; // 初始化新寄存器

    // 3. 预处理参数（字符串/大结构体转指针）
    if (arg_count > 0 && preprocess_args(pid, &orig_regs, args, arg_count) == -1) {
        goto err_exit;
    }

    // 4. 填充寄存器（rdi/rsi/rdx/rcx/r8/r9）
    unsigned long *reg_list[] = {&new_regs.rdi, &new_regs.rsi, &new_regs.rdx,
                                 &new_regs.rcx, &new_regs.r8,  &new_regs.r9};
    int reg_idx = 0; // 当前使用的寄存器索引

    for (int i = 0; i < arg_count && reg_idx < MAX_ARGS; i++) {
        if (args[i].type == ARG_TYPE_INT) {
            // 普通参数/字符串/大结构体：直接赋值
            *reg_list[reg_idx++] = args[i].val.int_val;
        } else if (args[i].type == ARG_TYPE_STRUCT_VAL) {
            // 小结构体值传递：拆分到连续寄存器（≤8字节→1个，8~16→2个）
            const void *struct_data = args[i].val.struct_val.data;
            size_t struct_size = args[i].val.struct_size;
            if (struct_size > 16) { // 超出范围，强制转为隐藏指针
                fprintf(stderr, "结构体大小＞16，自动转为隐藏指针\n");
                args[i].type = ARG_TYPE_STRUCT_HIDDEN;
                preprocess_args(pid, &orig_regs, &args[i], 1);
                *reg_list[reg_idx++] = args[i].val.int_val;
                continue;
            }

            // 拆分结构体到寄存器
            unsigned long struct_buf[2] = {0};
            memcpy(struct_buf, struct_data, struct_size);
            *reg_list[reg_idx++] = struct_buf[0]; // 低8字节→第一个寄存器
            if (struct_size > 8 && reg_idx < MAX_ARGS) {
                *reg_list[reg_idx++] = struct_buf[1]; // 高8字节→第二个寄存器
            }
        }
    }

    // 5. 设置函数地址和返回地址
    new_regs.rip = func_addr; // 函数入口地址
    // 栈顶写入返回地址（原rip），保证函数执行后返回原流程
    unsigned long rsp = (orig_regs->rsp & ~0xf) - 8; // 16字节对齐
    write_to_target(pid, rsp, &orig_regs.rip, 8);
    new_regs.rsp = rsp - 8; // 跳过返回地址

    // 6. 执行函数调用
    if (ptrace(PTRACE_SETREGS, pid, NULL, &new_regs) == -1) {
        fprintf(stderr, "设置寄存器失败: %s\n", strerror(errno));
        goto err_exit;
    }
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
        fprintf(stderr, "执行函数失败: %s\n", strerror(errno));
        goto err_exit;
    }
    waitpid(pid, &status, WUNTRACED);
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "函数执行后进程未暂停: 0x%x\n", status);
        goto err_exit;
    }

    // 7. 获取返回值（可选）
    if (ret_val != NULL) {
        struct user_regs_struct after_regs;
        if (ptrace(PTRACE_GETREGS, pid, NULL, &after_regs) != -1) {
            *ret_val = after_regs.rax; // 返回值存在rax
        }
    }

    // 8. 恢复原始寄存器并Detach
    ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    printf("函数调用成功！返回值: %ld\n", ret_val ? *ret_val : -1);
    return 0;

err_exit:
    // 异常退出：强制恢复寄存器+Detach，避免进程崩溃
    ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return -1;
}

// ==================== 示例测试代码 ====================
// 测试用结构体定义（控制+目标进程需一致）
typedef struct {
    int a;     // 4字节
    long b;    // 8字节
    char c;    // 1字节 → 对齐3字节，总16字节
} SmallStruct;

typedef struct {
    int arr[10]; // 40字节＞16
} BigStruct;

// 测试入口：演示不同类型参数的调用
int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "用法: %s <PID> <函数地址> [测试类型]\n", argv[0]);
        fprintf(stderr, "测试类型: 1-普通参数 2-字符串 3-小结构体 4-大结构体\n");
        return -1;
    }

    // 解析输入参数
    pid_t pid = atoi(argv[1]);
    unsigned long func_addr = strtoul(argv[2], NULL, 16);
    int test_type = argc >=4 ? atoi(argv[3]) : 1;

    PtraceFuncArg args[MAX_ARGS] = {0};
    int arg_count = 0;
    unsigned long ret_val = 0;

    // 按测试类型构造参数
    switch (test_type) {
        case 1: // 普通整数参数（如func(int a, long b)）
            args[0] = (PtraceFuncArg){.type=ARG_TYPE_INT, .val.int_val=100};
            args[1] = (PtraceFuncArg){.type=ARG_TYPE_INT, .val.int_val=0x12345678};
            arg_count = 2;
            break;

        case 2: // 字符串参数（如printf("hello %s", "ptrace")）
            args[0] = (PtraceFuncArg){.type=ARG_TYPE_STRING, .val.str_val="hello %s"};
            args[1] = (PtraceFuncArg){.type=ARG_TYPE_STRING, .val.str_val="ptrace"};
            arg_count = 2;
            break;

        case 3: // 小结构体值传递（≤16字节）
            SmallStruct s = {.a=10, .b=100, .c='x'};
            args[0] = (PtraceFuncArg){
                .type=ARG_TYPE_STRUCT_VAL,
                .val.struct_val={.data=&s, .size=sizeof(s)}
            };
            arg_count = 1;
            break;

        case 4: // 大结构体值传递（＞16字节，自动转隐藏指针）
            BigStruct b = {.arr={1,2,3,4,5,6,7,8,9,10}};
            args[0] = (PtraceFuncArg){
                .type=ARG_TYPE_STRUCT_HIDDEN,
                .val.struct_val={.data=&b, .size=sizeof(b)}
            };
            arg_count = 1;
            break;

        default:
            fprintf(stderr, "无效的测试类型\n");
            return -1;
    }

    // 调用函数
    return ptrace_call_func(pid, func_addr, args, arg_count, &ret_val);
}