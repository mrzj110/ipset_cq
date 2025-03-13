#!/bin/bash
set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 检查是否为root用户
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}请使用 root 权限运行此脚本${NC}"
    exit 1
fi

# 检查必要的命令
check_requirements() {
    local missing_tools=()
    for tool in ipset iptables wget awk logger; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done

    if [ ${#missing_tools[@]} -ne 0 ]; then
        echo -e "${RED}缺少必要的工具: ${missing_tools[*]}${NC}"
        echo "请安装缺少的工具："
        echo "Debian/Ubuntu: apt-get install iptables ipset"
        echo "CentOS/RHEL: yum install iptables ipset"
        exit 1
    fi
}

# 初始化防火墙
init_firewall() {
    echo -e "${YELLOW}正在初始化防火墙规则...${NC}"
    
    # 检查并删除已存在的规则
    ipset list whitelist_ips >/dev/null 2>&1 && ipset destroy whitelist_ips
    
    # 创建新的 ipset
    ipset create whitelist_ips hash:net hashsize 65536 maxelem 1000000
    
    # 设置 iptables 规则
    # 创建WHITELIST链
    iptables -N WHITELIST 2>/dev/null || true
    
    # 清除可能存在的旧规则
    iptables -D INPUT -j WHITELIST 2>/dev/null || true
    iptables -F WHITELIST 2>/dev/null || true
    
    # 添加规则：白名单内的IP允许通过
    iptables -A WHITELIST -m set --match-set whitelist_ips src -j ACCEPT
    
    # 添加规则：允许本地回环接口
    iptables -A WHITELIST -i lo -j ACCEPT
    
    # 添加规则：允许已建立的连接和相关连接
    iptables -A WHITELIST -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # 添加规则：所有其他连接默认拒绝
    iptables -A WHITELIST -j DROP
    
    # 将WHITELIST链插入INPUT链的最前面
    iptables -I INPUT -j WHITELIST
    
    echo -e "${GREEN}防火墙规则初始化完成${NC}"
}

# 更新白名单的核心功能
update_whitelist_core() {
    local silent_mode=$1
    cd /root/cron || exit 1

    [[ "$silent_mode" != "silent" ]] && echo "正在下载白名单文件..."
    if ! wget -q "https://raw.githubusercontent.com/mrzj110/ipset_cq/refs/heads/main/CQ?token=GHSAT0AAAAAAC6PMQP7JDPUMUII3TMEXXIKZ6SSGQQ" -O cq_whitelist.txt.tmp; then
        [[ "$silent_mode" != "silent" ]] && echo -e "${RED}下载失败，使用上次的白名单${NC}"
        logger "下载失败，使用上次的白名单"
        return 1
    fi

    if [ ! -s cq_whitelist.txt.tmp ]; then
        [[ "$silent_mode" != "silent" ]] && echo -e "${RED}下载文件为空${NC}"
        logger "下载文件为空，使用上次的白名单"
        rm -f cq_whitelist.txt.tmp
        return 1
    fi

    mv cq_whitelist.txt.tmp cq_whitelist.txt

    [[ "$silent_mode" != "silent" ]] && echo "正在处理 IP 列表..."
    # 检查并删除已存在的临时 ipset
    ipset list whitelist_ips.tmp >/dev/null 2>&1 && ipset destroy whitelist_ips.tmp

    # 创建临时 ipset
    ipset create whitelist_ips.tmp hash:net hashsize 65536 maxelem 1000000

    # 提取有效IP/CIDR到临时文件
    awk '!/^#/ && $1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/ { print $1 }' cq_whitelist.txt > valid_ips.tmp

    # 使用 ipset restore 批量添加
    while read -r ip; do
        echo "add whitelist_ips.tmp $ip"
    done < valid_ips.tmp | ipset restore -!

    # 清理临时文件
    rm -f valid_ips.tmp

    # 原子性地替换 ipset
    ipset swap whitelist_ips.tmp whitelist_ips
    ipset destroy whitelist_ips.tmp

    [[ "$silent_mode" != "silent" ]] && echo -e "${GREEN}IP 白名单更新完成${NC}"
    logger "IP 白名单更新完成"
}

# 命令行模式更新白名单
cli_update() {
    logger "开始更新 IP 白名单"
    update_whitelist_core "silent"
}

# 交互式更新 IP 白名单
update_whitelist() {
    echo -e "${YELLOW}正在更新 IP 白名单...${NC}"
    update_whitelist_core
}

# 创建定时任务脚本
create_cron_scripts() {
    echo -e "${YELLOW}正在创建定时任务脚本...${NC}"
    
    # 创建 whitelist_at_boot.sh
    cat > /root/cron/whitelist_at_boot.sh << 'EOF'
#!/bin/bash
set -e  # 遇到错误立即退出
cd /root/cron || exit 1

# 检查 Docker 是否真正启动
while ! docker info >/dev/null 2>&1; do
    echo "等待 Docker 启动..."
    sleep 2
done

# 检查 ipset 是否已存在，如存在则删除
ipset list whitelist_ips >/dev/null 2>&1 && ipset destroy whitelist_ips

# 创建 ipset 集合
ipset create whitelist_ips hash:net hashsize 65536 maxelem 1000000

# 设置 iptables 规则
iptables -N WHITELIST 2>/dev/null || true
iptables -F WHITELIST
iptables -I INPUT -j WHITELIST
iptables -A WHITELIST -m set --match-set whitelist_ips src -j ACCEPT
iptables -A WHITELIST -i lo -j ACCEPT
iptables -A WHITELIST -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A WHITELIST -j DROP

# 下载并处理 IP 白名单
wget -q "https://raw.githubusercontent.com/mrzj110/ipset_cq/refs/heads/main/CQ?token=GHSAT0AAAAAAC6PMQP7JDPUMUII3TMEXXIKZ6SSGQQ" -O cq_whitelist.txt.tmp

if [ -s cq_whitelist.txt.tmp ]; then
    mv cq_whitelist.txt.tmp cq_whitelist.txt
    awk '!/^#/ && $1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/ { print $1 }' cq_whitelist.txt | while IFS= read -r line; do
        ipset add whitelist_ips "$line"
    done
fi
EOF

    # 创建 whitelist.sh
    cat > /root/cron/whitelist.sh << 'EOF'
#!/bin/bash
set -e
cd /root/cron || exit 1

# 添加日志
logger "开始更新 IP 白名单"

# 下载失败时使用备份文件
if ! wget -q "https://raw.githubusercontent.com/mrzj110/ipset_cq/refs/heads/main/CQ?token=GHSAT0AAAAAAC6PMQP7JDPUMUII3TMEXXIKZ6SSGQQ" -O cq_whitelist.txt.tmp; then
    logger "下载失败，使用上次的白名单"
    exit 1
fi

# 验证下载文件
if [ -s cq_whitelist.txt.tmp ]; then
    mv cq_whitelist.txt.tmp cq_whitelist.txt
else
    logger "下载文件为空，使用上次的白名单"
    rm -f cq_whitelist.txt.tmp
    exit 1
fi

# 创建临时 ipset
ipset create whitelist_ips.tmp hash:net hashsize 65536 maxelem 1000000

# 填充临时 ipset
awk '!/^#/ && $1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/ { print $1 }' cq_whitelist.txt | while IFS= read -r line; do
    ipset add whitelist_ips.tmp "$line"
done

# 原子性地替换 ipset
ipset swap whitelist_ips.tmp whitelist_ips
ipset destroy whitelist_ips.tmp

logger "IP 白名单更新完成"
EOF

    # 设置执行权限
    chmod +x /root/cron/whitelist_at_boot.sh
    chmod +x /root/cron/whitelist.sh
    
    echo -e "${GREEN}定时任务脚本创建完成${NC}"
}

# 设置定时任务
setup_cron() {
    echo -e "${YELLOW}正在设置定时任务...${NC}"
    
    # 首先创建定时任务脚本
    create_cron_scripts
    
    # 检查是否已经存在相关定时任务
    if crontab -l 2>/dev/null | grep -q "/root/cron/whitelist"; then
        echo -e "${RED}定时任务已存在${NC}"
        return 1
    fi
    
    # 添加定时任务
    (crontab -l 2>/dev/null; echo "0 5 * * * /bin/bash /root/cron/whitelist.sh") | crontab -
    (crontab -l 2>/dev/null; echo "@reboot /bin/bash /root/cron/whitelist_at_boot.sh") | crontab -
    
    echo -e "${GREEN}定时任务设置完成${NC}"
}

# 清理所有规则
cleanup_rules() {
    echo -e "${YELLOW}正在清理防火墙规则...${NC}"
    
    iptables -D INPUT -j WHITELIST 2>/dev/null || true
    iptables -F WHITELIST 2>/dev/null || true
    iptables -X WHITELIST 2>/dev/null || true
    ipset destroy whitelist_ips 2>/dev/null || true
    
    echo -e "${GREEN}防火墙规则已清理${NC}"
}

# 测试模式 - 临时应用规则并保持SSH连接
test_mode() {
    echo -e "${YELLOW}正在进入测试模式...${NC}"
    echo -e "${RED}警告: 测试模式将应用白名单规则，但会自动在5分钟后恢复，以防止意外锁定${NC}"
    
    # 确保当前SSH连接不会被断开
    SSH_CLIENT_IP=$(echo $SSH_CLIENT | awk '{print $1}')
    
    if [ -z "$SSH_CLIENT_IP" ]; then
        echo -e "${RED}无法确定您当前的SSH连接IP地址，测试模式取消${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}检测到您当前的SSH连接IP为: ${SSH_CLIENT_IP}${NC}"
    echo -e "将临时将此IP加入白名单以确保连接不会断开"
    
    # 初始化防火墙规则
    init_firewall
    
    # 更新白名单
    update_whitelist_core
    
    # 手动将当前SSH IP加入白名单
    ipset add whitelist_ips "$SSH_CLIENT_IP"
    
    echo -e "${GREEN}防火墙规则已应用，测试模式启动${NC}"
    echo -e "${YELLOW}系统将在5分钟后自动恢复原始设置，以防止意外锁定${NC}"
    
    # 设置一个计时器，5分钟后自动恢复
    (sleep 300; echo -e "\n${YELLOW}测试时间结束，正在恢复原始设置...${NC}"; cleanup_rules; echo -e "${GREEN}原始设置已恢复${NC}") &
    
    # 提示用户可以提前结束测试
    echo -e "\n按任意键提前结束测试并恢复原始设置..."
    read -n 1 -s
    
    # 终止计时器进程
    kill $! 2>/dev/null || true
    
    # 清理规则
    cleanup_rules
    echo -e "${GREEN}测试结束，原始设置已恢复${NC}"
}

# 显示当前状态
show_status() {
    echo -e "${YELLOW}当前状态：${NC}"
    echo "----------------------------------------"
    echo -e "${GREEN}IPSet 规则：${NC}"
    if ipset list whitelist_ips >/dev/null 2>&1; then
        echo "已创建 IPSet 规则"
        echo "当前白名单 IP/网段 数量: $(ipset list whitelist_ips | grep -c "^[0-9]")"
    else
        echo "未创建 IPSet 规则"
    fi
    echo "----------------------------------------"
    echo -e "${GREEN}IPTables 规则：${NC}"
    iptables -L WHITELIST 2>/dev/null || echo "未创建 IPTables 规则"
    echo "----------------------------------------"
    echo -e "${GREEN}定时任务：${NC}"
    crontab -l | grep "/root/cron/whitelist" || echo "未设置定时任务"
    echo "----------------------------------------"
}

# 显示白名单详情
show_whitelist() {
    echo -e "${YELLOW}IP 白名单详情：${NC}"
    if ipset list whitelist_ips >/dev/null 2>&1; then
        local ip_count=$(ipset list whitelist_ips | grep -c "^[0-9]")
        echo -e "${GREEN}当前白名单共有 ${ip_count} 个 IP/网段${NC}"
        
        echo -e "\n是否要查看完整的 IP 列表？[y/N]"
        read -r show_full
        if [[ "$show_full" =~ ^[Yy]$ ]]; then
            echo -e "\n${YELLOW}白名单 IP/网段 列表：${NC}"
            ipset list whitelist_ips | grep "^[0-9]"
        fi
    else
        echo -e "${RED}白名单未创建或为空${NC}"
    fi
}

# 添加单个IP或网段到白名单
add_ip_to_whitelist() {
    echo -e "${YELLOW}添加 IP 或网段到白名单${NC}"
    read -rp "请输入要添加的IP或网段(CIDR格式，例如: 192.168.1.0/24): " ip_to_add
    
    if [[ ! "$ip_to_add" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$ ]]; then
        echo -e "${RED}无效的IP格式${NC}"
        return 1
    fi
    
    # 确保白名单存在
    if ! ipset list whitelist_ips >/dev/null 2>&1; then
        echo -e "${YELLOW}白名单不存在，正在创建...${NC}"
        ipset create whitelist_ips hash:net hashsize 65536 maxelem 1000000
    fi
    
    # 添加IP到白名单
    if ipset add whitelist_ips "$ip_to_add"; then
        echo -e "${GREEN}IP/网段 ${ip_to_add} 添加成功${NC}"
        
        # 如果文件存在，也更新文件
        if [ -f /root/cron/cq_whitelist.txt ]; then
            echo "# 手动添加的IP" >> /root/cron/cq_whitelist.txt
            echo "$ip_to_add" >> /root/cron/cq_whitelist.txt
            echo -e "${GREEN}IP/网段已同时添加到本地文件${NC}"
        fi
    else
        echo -e "${RED}添加失败，请检查IP格式或者该IP是否已存在${NC}"
    fi
}

# 删除单个IP或网段从白名单
remove_ip_from_whitelist() {
    echo -e "${YELLOW}从白名单删除 IP 或网段${NC}"
    read -rp "请输入要删除的IP或网段(CIDR格式): " ip_to_remove
    
    if [[ ! "$ip_to_remove" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$ ]]; then
        echo -e "${RED}无效的IP格式${NC}"
        return 1
    fi
    
    # 检查白名单是否存在
    if ! ipset list whitelist_ips >/dev/null 2>&1; then
        echo -e "${RED}白名单不存在${NC}"
        return 1
    fi
    
    # 从白名单删除IP
    if ipset del whitelist_ips "$ip_to_remove" 2>/dev/null; then
        echo -e "${GREEN}IP/网段 ${ip_to_remove} 删除成功${NC}"
        
        # 如果文件存在，也更新文件
        if [ -f /root/cron/cq_whitelist.txt ]; then
            sed -i "\|^$ip_to_remove$|d" /root/cron/cq_whitelist.txt
            echo -e "${GREEN}IP/网段已同时从本地文件删除${NC}"
        fi
    else
        echo -e "${RED}删除失败，此IP可能不在白名单中${NC}"
    fi
}

# 主菜单
show_menu() {
    while true; do
        echo -e "\n${YELLOW}=== IP 白名单防火墙管理系统 ===${NC}"
        echo "1. 初始化"
        echo "2. 更新"
        echo "3. 定时任务"
        echo "4. 清理"
        echo "5. 显示状态"
        echo "6. IP白名单详情"
        echo "7. 添加IP到白名单"
        echo "8. 从白名单删除IP"
        echo "9. 测试模式(自动5分钟后恢复)"
        echo "0. 退出"
        
        read -rp "请选择操作 [0-9]: " choice
        
        case $choice in
            1) init_firewall ;;
            2) update_whitelist ;;
            3) setup_cron ;;
            4) cleanup_rules ;;
            5) show_status ;;
            6) show_whitelist ;;
            7) add_ip_to_whitelist ;;
            8) remove_ip_from_whitelist ;;
            9) test_mode ;;
            0) echo -e "${GREEN}再见！${NC}"; exit 0 ;;
            *) echo -e "${RED}无效的选择${NC}" ;;
        esac
        
        echo -e "\n按回车键继续..."
        read -r
    done
}

# 主程序
main() {
    # 检查是否有命令行参数
    if [ "$1" = "update" ]; then
        cli_update
        exit 0
    fi

    # 创建必要的目录
    mkdir -p /root/cron
    
    # 检查必要的命令
    check_requirements
    
    # 显示菜单
    show_menu
}

main "$@"
