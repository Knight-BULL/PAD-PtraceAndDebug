#!/bin/bash
# pad.sh - 批量执行gdb命令修改进程变量，自动detach退出，最小化进程暂停
# 用法：sudo ./pad.sh <进程名称>

# 定义颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # 重置颜色

# ====================== 第一步：参数检查 ======================
if [ $# -ne 1 ]; then
    echo -e "${RED}错误：参数数量错误！${NC}"
    echo -e "用法：${GREEN}sudo ./pad.sh <进程名称>${NC}"
    echo -e "示例：sudo ./pad.sh my_app"
    exit 1
fi

PROCESS_NAME=$1

# 检查root权限（附加进程必须root）
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${YELLOW}警告：需要root权限，自动以sudo重新执行...${NC}"
    sudo "$0" "$PROCESS_NAME"
    exit $?
fi

# ====================== 第二步：查找进程PID ======================
# 查找目标进程PID（排除grep/脚本自身）
# PID_LIST=$(ps -ef | grep "$PROCESS_NAME" | grep -v grep | grep -v "$0" | awk '{print $2}' | sort -u)

# 精准匹配进程名（完全一致），提取唯一PID列表
PID_LIST=$(pgrep -x "$PROCESS_NAME" | sort -u)

if [ -z "$PID_LIST" ]; then
    echo -e "${RED}错误：未找到进程「$PROCESS_NAME」！${NC}"
    exit 1
fi

# 多PID选择逻辑
PID_COUNT=$(echo "$PID_LIST" | wc -l)
if [ "$PID_COUNT" -gt 1 ]; then
    echo -e "${YELLOW}找到多个「$PROCESS_NAME」进程，请选择PID：${NC}"
    echo "$PID_LIST" | nl -w2 -s'. '
    read -p "输入序号（1-$PID_COUNT）：" SELECT_NUM
    
    if ! [[ "$SELECT_NUM" =~ ^[0-9]+$ ]] || [ "$SELECT_NUM" -lt 1 ] || [ "$SELECT_NUM" -gt "$PID_COUNT" ]; then
        echo -e "${RED}错误：序号无效！${NC}"
        exit 1
    fi
    
    TARGET_PID=$(echo "$PID_LIST" | sed -n "${SELECT_NUM}p")
else
    TARGET_PID=$PID_LIST
fi

echo -e "${GREEN}已选定进程：PID=$TARGET_PID，进程名=$PROCESS_NAME${NC}"

# ====================== 第三步：收集用户要执行的gdb命令 ======================
echo -e "\n${YELLOW}请输入要执行的gdb命令（每行1条，输入「done」结束）：${NC}"
echo "示例命令："
echo "  set var g_run_flag=0    # 修改变量"
echo "  print g_run_flag       # 验证修改结果"
echo "  set var count=100      # 修改变量"

# 创建临时文件存储gdb命令（避免交互输入丢失）
GDB_CMD_FILE=$(mktemp /tmp/pad_gdb_cmd.XXXXXX)

CURRENT_TTY=$(tty)

function remap_printf()
{
    echo "【信息】待附加的后台进程PID:$TARGET_PID"

    echo "set \$tty_fd = open(\"$1\", 2)" >> "$GDB_CMD_FILE"
    echo "call (int)dup2(\$tty_fd, fileno(stdout))" >> "$GDB_CMD_FILE"
    echo "call (int)dup2(\$tty_fd, fileno(stderr))" >> "$GDB_CMD_FILE"
    echo "call close(\$tty_fd)" >> "$GDB_CMD_FILE"
    echo "detach" >> "$GDB_CMD_FILE"
    echo "quit" >> "$GDB_CMD_FILE"

    cat "$GDB_CMD_FILE"

    # 检查是否输入了有效命令
    if [ ! -s "$GDB_CMD_FILE" ]; then
        echo -e "${RED}错误：未输入任何有效gdb命令！${NC}"
        rm -f "$GDB_CMD_FILE" #删除空临时文件
        exit 1
    fi

    # 第四步：通过GDB无交互附加进程，并重定向输出到当前终端
    echo " 【信息】正在附加进程PID=$TARGET_PID，稍后..."
    sudo gdb --batch --quiet -n -p $TARGET_PID -x "$GDB_CMD_FILE" 1>/dev/null 2>&1

    rm -f "$GDB_CMD_FILE"
}

remap_printf $CURRENT_TTY

function exec_gdb() {
    # 检查是否输入了有效命令
    if [ ! -s "$GDB_CMD_FILE" ]; then
        echo -e "${RED}错误：未输入任何有效gdb命令！${NC}"
        rm -f "$GDB_CMD_FILE" # 删除空临时文件
        exit 1
    fi

    # 追加detach和quit命令（自动恢复进程+退出gdb）
    echo "detach" >> "$GDB_CMD_FILE"
    echo "quit" >> "$GDB_CMD_FILE"

    echo -e "\n${GREEN}即将执行以下gdb命令（进程会短暂暂停）：${NC}"
    cat "$GDB_CMD_FILE" | sed '$d;$d' # 打印用户命令（隐藏最后2行的detach/quit）

    # ====================== 第四步：自动执行gdb命令 ======================
    echo -e "\n${YELLOW}开始执行gdb命令，进程PID=$TARGET_PID 短暂暂停...${NC}"

    # 用gdb批处理模式执行命令（--batch 执行完自动退出，--quiet 减少冗余输出）
    sudo gdb --batch --quiet -p "$TARGET_PID" -x "$GDB_CMD_FILE" 1>/dev/null 2>&1

    # 检查gdb执行结果
    if [ $? -eq 0 ]; then
        echo -e "\n${GREEN}✅ 所有命令执行完成！进程PID=$TARGET_PID 已恢复运行${NC}"
    else
        echo -e "\n${RED}❌ gdb命令执行失败！请检查命令是否正确${NC}"
    fi

    # ====================== 清理临时文件 ======================
    rm -f "$GDB_CMD_FILE"

}

function remap_to_null()
{
    # remap_printf "/dev/null"
}

trap "remap_to_null; exit 0" SIGINT SIGTERM EXIT

# 循环读取用户输入，直到输入done
while true; do
    read -p "gdb命令 > " USER_CMD
    
    # 输入done则结束
    if [ "$USER_CMD" = "done" ]; then
        break
    fi
    
    # 空命令跳过
    if echo -n "$USER_CMD"|grep -q $'\n' ; then
         # 将用户命令写入临时文件
        echo "$USER_CMD" >> "$GDB_CMD_FILE"
        exec_gdb
        continue
    fi
    
done
