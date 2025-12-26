# AVVERIFIER 地址验证漏洞检测器实验复现

## 项目简介

AVVERIFIER 是一个用于检测智能合约中**地址验证漏洞 (Address Validation Vulnerability)** 的静态分析工具，基于论文 "All Your Tokens are Belong to Us" 实现。

### 漏洞背景

地址验证漏洞是 DeFi 合约中常见的安全问题。当合约允许用户传入任意 token 地址，但未验证该地址是否为预期的合法 token 合约时，攻击者可以传入恶意合约地址作为 token 参数，当受害合约调用该恶意合约的 `transferFrom`、`transfer` 等函数时，恶意合约可以回调受害合约，造成重入攻击或其他漏洞利用。

---

## 核心实现

### 项目结构

```
avverifier/
├── AVVERIFIER/                 # 核心检测引擎
│   ├── solstatic.py           # 主要检测器实现
│   └── stack.py               # EVM 栈/内存/存储模拟
├── benchmark/                  # 10 个测试样例
│   ├── AAVE/
│   ├── AnyswapRouter/
│   ├── CErc20/
│   ├── OlympusDAO/
│   ├── Paraluni/
│   ├── Rdnt/
│   ├── SellToken/
│   ├── Templedao/
│   ├── Venus/
│   └── Visor/
└── analyze.py                  # 测试脚本
```

### 核心模块说明

#### 1. `AVVERIFIER/solstatic.py` - 主检测器

**Disassembly 类**：核心分析引擎

```python
class Disassembly(object):
    def __init__(self, code: str):
        self.bytecode = code                    # 原始字节码
        self.instruction_list = []              # 反汇编指令列表
        self.func_hashes = []                   # 函数选择器列表
        self.function_name_to_address = {}      # 函数名 -> 地址映射
        self.block_list = []                    # 基本块列表
        self.issue_list = []                    # 检测到的漏洞列表
```

**主要功能**：

| 方法 | 功能 |
|------|------|
| `remove_constructor()` | 移除构造函数字节码，只保留 runtime bytecode |
| `divide_into_basic_blocks()` | 将指令序列划分为基本块 (Basic Blocks) |
| `assign_bytecode()` | 解析函数选择器和跳转表 |
| `run()` | 构建控制流图 (CFG) |
| `execute_block()` | 符号执行单个基本块 |
| `get_issue()` | 检测是否存在地址验证漏洞 |
| `process_and_disassemble_bytecode()` | 主入口，完成完整分析流程 |

**漏洞检测逻辑** (`get_issue` 方法)：

```python
def get_issue(self, instruction, evmstack, stack_end_flag, memory):
    # 检查条件：
    # 1. CALLDATALOAD 的数据未经过 SHA3 哈希处理（未查白名单）
    # 2. 该数据用于 CALL 指令的地址参数
    # 3. 没有检查 msg.sender (CALLER)
    
    for id in evmstack.calldataload_list:
        if id not in evmstack.sha3_list:  # 未经白名单验证
            evmstack.uncheck_list.append(id)
    
    if len(evmstack.uncheck_list) > 0 and not evmstack.check_caller:
        # 检查是否在 CALL 之前使用了未验证的地址
        for unckecked_id in evmstack.uncheck_list:
            if unckecked_id < reserve_control_dict["CALL"]:
                return True  # 发现漏洞
    return False
```

#### 2. `AVVERIFIER/stack.py` - EVM 模拟器

模拟 EVM 的运行时环境：

```python
class EVMStack:
    def __init__(self):
        self.stack = []                 # 操作数栈
        self.calldataload_list = []     # CALLDATALOAD 追踪
        self.sha3_list = []             # SHA3 哈希追踪（白名单查询）
        self.call_list = []             # CALL 指令追踪
        self.check_caller = False       # 是否检查了 msg.sender
        self.control_dict = {}          # 控制流依赖

class EVMMemory:
    # 内存模拟
    
class EVMStorage:
    # 存储模拟
    
class SymbolicValue:
    # 符号值，用于污点追踪
```

### 检测原理

1. **字节码反汇编**：将 EVM bytecode 转换为操作码序列
2. **基本块划分**：根据 JUMPDEST、JUMP、JUMPI 等指令划分基本块
3. **控制流图构建**：建立基本块之间的跳转关系
4. **符号执行**：模拟执行每个函数，追踪数据流
5. **污点分析**：标记来自 CALLDATALOAD 的用户输入
6. **漏洞检测**：检查用户输入是否未经验证直接用于 CALL

---

## Benchmark 数据集

### 样例概览

| 合约 | 链 | 漏洞函数 | 原始状态 | 说明 |
|------|-----|---------|----------|------|
| AAVE | ETH | deposit | SAFE | LendingPoolCore |
| AnyswapRouter | ETH | anySwapOutUnderlyingWithPermit | VULNERABLE | 跨链路由 |
| CErc20 | ETH | liquidateBorrow | SAFE | Compound cToken |
| OlympusDAO | ETH | redeem | VULNERABLE | 债券赎回 |
| Paraluni | BSC | depositByAddLiquidity | VULNERABLE | 流动性挖矿 |
| Rdnt | ARB | deposit | SAFE | Radiant 借贷 |
| SellToken | BSC | addLiquidity | VULNERABLE | 质押奖励 |
| Templedao | ETH | migrateStake | VULNERABLE | 质押迁移 |
| Venus | BSC | enterMarkets | SAFE | 借贷市场 |
| Visor | ETH | deposit | VULNERABLE | Hypervisor 存款 |

### 样例结构

每个 benchmark 目录包含：

```
benchmark/<合约名>/
├── <主合约>.sol           # 原始合约源码
├── contract_info.json     # 合约元信息
├── FixedFunction.sol      # 修复后的函数（可选）
└── VulnerableInjection.sol # 注入漏洞的函数（可选）
```

---

## 测试脚本构建

### `analyze.py` 实现思路

测试脚本 `analyze.py` 封装了 AVVERIFIER 的使用流程：

```python
# 1. 获取字节码

# 2. 调用 AVVERIFIER 分析
dis = Disassembly.process_and_disassemble_bytecode(bytecode)
issues = dis.issue_list  # 漏洞函数选择器列表

# 3. 解析结果
if len(issues) > 0:
    print("VULNERABLE")
    for selector in issues:
        print(f"问题函数: {selector_to_name(selector)}")
else:
    print("SAFE")
```

---

## 使用方法

### 环境配置

```bash
cd avverifier
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 命令行使用

```bash
# 查看帮助
python3 analyze.py

# 分析所有 benchmark
python3 analyze.py all

# 分析单个 benchmark
python3 analyze.py OlympusDAO
python3 analyze.py AnyswapRouter
python3 analyze.py Visor

# 分析本地 Solidity 文件
python3 analyze.py benchmark/CErc20/CErc20.sol

# 分析 bytecode 文件
python3 analyze.py contract.bin
```

### 输出示例

```
======================================================================
分析 Benchmark: OlympusDAO
======================================================================
   合约文件: BondFixedExpiryTeller.sol
   漏洞函数: redeem
   预期结果: VULNERABLE
   链: ETH
   地址: 0x007FE7c498A2Cf30971ad8f2cbC36bd14Ac51156

合约: OlympusDAO::BondFixedExpiryTeller.sol
   字节码长度: 28872 字符
get issue:      0x1e9a6950
   VULNERABLE - 检测到地址验证漏洞
   问题函数:
      - redeem(address,uint256) (0x1e9a6950)
   匹配预期漏洞函数: redeem
```

### 批量检测结果

```
======================================================================
检测结果汇总
======================================================================
合约                   预期              检测结果            状态        
----------------------------------------------------------------------
AAVE                 SAFE            SAFE            ✓ 正确
AnyswapRouter        VULNERABLE      VULNERABLE      ✓ 正确
CErc20               SAFE            SAFE            ✓ 正确
OlympusDAO           VULNERABLE      VULNERABLE      ✓ 正确
Paraluni             VULNERABLE      VULNERABLE      ✓ 正确
Rdnt                 SAFE            SAFE            ✓ 正确
SellToken            VULNERABLE      VULNERABLE      ✓ 正确
Templedao            VULNERABLE      VULNERABLE      ✓ 正确
Venus                SAFE            SAFE            ✓ 正确
Visor                VULNERABLE      VULNERABLE      ✓ 正确
----------------------------------------------------------------------
准确率: 10/10 = 100.0%
```
