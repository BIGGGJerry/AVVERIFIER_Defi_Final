#!/usr/bin/env python3
"""
支持:
1. 直接分析bytecode hex文件
2. 通过以太坊RPC获取链上bytecode
3. 编译本地Solidity文件 (需要依赖完整)
"""

import os
import sys
import json
import re
from pathlib import Path

# 添加AVVERIFIER到Python路径
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "AVVERIFIER"))

from solstatic import Disassembly

# ANSI颜色
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
CYAN = '\033[96m'
BOLD = '\033[1m'
RESET = '\033[0m'

# 链的RPC端点
RPC_ENDPOINTS = {
    "eth": "https://eth.llamarpc.com",
    "bsc": "https://bsc-dataseed1.binance.org",
    "arb": "https://arb1.arbitrum.io/rpc",
}

# Benchmark 合约信息
BENCHMARKS = {
    "AAVE": {
        "chain": "eth",
        "address": "0x085E34722e04567Df9E6d2c32e82fd74f3342e79",
        "contract": "LendingPoolCore.sol",
        "vulnerable_function": "deposit",
        "expected": "SAFE"
    },
    "AnyswapRouter": {
        "chain": "eth", 
        "address": "0x6b7a87899490EcE95443e979cA9485CBE7E71522",
        "contract": "AnyswapV4Router.sol",
        "vulnerable_function": "anySwapOutUnderlyingWithPermit",
        "expected": "VULNERABLE"
    },
    "CErc20": {
        "chain": "eth",
        "address": "",  # 无链上地址
        "contract": "CErc20.sol",
        "vulnerable_function": "liquidateBorrow",
        "expected": "SAFE"
    },
    "OlympusDAO": {
        "chain": "eth",
        "address": "0x007FE7c498A2Cf30971ad8f2cbC36bd14Ac51156",
        "contract": "BondFixedExpiryTeller.sol",
        "vulnerable_function": "redeem",
        "expected": "VULNERABLE"
    },
    "Paraluni": {
        "chain": "bsc",
        "address": "0xA386F30853A7EB7E6A25eC8389337a5C6973421D",
        "contract": "MasterChef.sol",
        "vulnerable_function": "depositByAddLiquidity",
        "expected": "VULNERABLE"
    },
    "Rdnt": {
        "chain": "arb",
        "address": "0xd1B589C00C940C4C3F7b25e53c8d921C44eF9140",
        "contract": "lending.sol",
        "vulnerable_function": "deposit",
        "expected": "SAFE"  # 原始版本是安全的
    },
    "SellToken": {
        "chain": "bsc",
        "address": "0x274b3e185c9c8f4ddEF79cb9A8dC0D94f73A7675",
        "contract": "StakingRewards.sol",
        "vulnerable_function": "addLiquidity",
        "expected": "VULNERABLE"
    },
    "Templedao": {
        "chain": "eth",
        "address": "0xd2869042E12a3506100af1D192b5b04D65137941",
        "contract": "StaxLPStaking.sol",
        "vulnerable_function": "migrateStake",
        "expected": "VULNERABLE"
    },
    "Venus": {
        "chain": "bsc",
        "address": "0xAd69AA3811fE0EE7dBd4e25C4bae40e6422c76C8",
        "contract": "MarketFacet.sol",
        "vulnerable_function": "enterMarkets",
        "expected": "SAFE"  # 原始版本是安全的
    },
    "Visor": {
        "chain": "eth",
        "address": "0xC9f27A50f82571C1C8423A42970613b8dBDA14ef",
        "contract": "RewardsHypervisor.sol",
        "vulnerable_function": "deposit",
        "expected": "VULNERABLE"
    }
}


def fetch_bytecode_from_chain(address, chain="eth"):
    """从区块链获取合约bytecode"""
    import urllib.request
    
    rpc_url = RPC_ENDPOINTS.get(chain, RPC_ENDPOINTS["eth"])
    
    payload = json.dumps({
        "jsonrpc": "2.0",
        "method": "eth_getCode",
        "params": [address, "latest"],
        "id": 1
    })
    
    req = urllib.request.Request(
        rpc_url,
        data=payload.encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            result = json.loads(response.read().decode('utf-8'))
            bytecode = result.get('result', '0x')
            if bytecode and bytecode != '0x' and len(bytecode) > 10:
                return bytecode
    except Exception as e:
        print(f"   {YELLOW} 网络请求失败: {e}{RESET}")
    
    return None


def run_avverifier(bytecode):
    """
    运行AVVERIFIER检测
    返回: (is_vulnerable, issue_list, func_hashes, dis)
    """
    try:
        dis = Disassembly.process_and_disassemble_bytecode(bytecode)
        issues = getattr(dis, 'issue_list', [])
        func_hashes = getattr(dis, 'func_hashes', [])
        return len(issues) > 0, issues, func_hashes, dis
    except Exception as e:
        print(f"   {RED} AVVERIFIER 分析错误: {e}{RESET}")
        return None, [], [], None


# 常见函数选择器到函数名的映射 (从 4bytes.directory 等来源)
KNOWN_SELECTORS = {
    # OlympusDAO
    "0x1e9a6950": "redeem(address,uint256)",
    "0x2e2d2984": "deposit(uint256,address)",
    # AnyswapRouter
    "0xd8b9f610": "anySwapOutUnderlyingWithPermit(address,address,address,uint256,uint256,uint8,bytes32,bytes32,uint256)",
    "0xedbdf5e2": "anySwapOutUnderlyingWithTransferPermit(address,address,address,uint256,uint256,uint8,bytes32,bytes32,uint256)",
    "0xc8e174f6": "anySwapIn(bytes32,address,address,uint256,uint256)",
    "0x99cd84b5": "anySwapOut(address,address,uint256,uint256)",
    "0x9aa1ac61": "anySwapOutUnderlying(address,address,uint256,uint256)",
    "0x8d7d3eea": "anySwapOutNative(address,address,uint256)",
    "0x6a453972": "anySwapInUnderlying(bytes32,address,address,uint256,uint256)",
    "0x4d93bb94": "anySwapInAuto(bytes32,address,address,uint256,uint256)",
    # Paraluni
    "0xff09731b": "depositByAddLiquidity(uint256,address[],uint256[])",
    # SellToken
    "0xe4a76726": "addLiquidity(address,address)",
    # Templedao
    "0xbdcd9c80": "migrateStake(address,uint256)",
    # Visor
    "0x2e2d2984": "deposit(uint256,address)",
    # AAVE
    "0x47e7ef24": "deposit(address,uint256)",
    "0xe8eda9df": "deposit(address,uint256,address,uint16)",
    # CErc20 / Compound
    "0xf5e3c462": "liquidateBorrow(address,uint256,address)",
    "0xb2a02ff1": "seize(address,address,uint256)",
    "0xa0712d68": "mint(uint256)",
    "0xdb006a75": "redeem(uint256)",
    "0x852a12e3": "redeemUnderlying(uint256)",
    "0xc5ebeaec": "borrow(uint256)",
    "0x0e752702": "repayBorrow(uint256)",
    "0x1be19560": "sweepToken(address)",
    # Common ERC20
    "0xa9059cbb": "transfer(address,uint256)",
    "0x23b872dd": "transferFrom(address,address,uint256)",
    "0x095ea7b3": "approve(address,uint256)",
}


def selector_to_name(selector):
    """将函数选择器转换为函数名"""
    if selector in KNOWN_SELECTORS:
        return KNOWN_SELECTORS[selector]
    return selector  # 如果未知，返回原选择器


def analyze_bytecode(bytecode, name="Unknown", expected_func=None):
    """分析bytecode并打印结果"""
    print(f"\n合约: {BOLD}{name}{RESET}")
    print(f"   字节码长度: {len(bytecode)} 字符")
    
    is_vulnerable, issues, func_hashes, dis = run_avverifier(bytecode)
    
    if is_vulnerable is None:
        return None
    
    if is_vulnerable:
        print(f"   {RED}VULNERABLE - 检测到地址验证漏洞{RESET}")
        if issues:
            print(f"   {YELLOW}问题函数:{RESET}")
            for selector in issues:
                func_name = selector_to_name(selector)
                if func_name == selector:
                    # 未知选择器，显示选择器
                    print(f"      - {CYAN}{selector}{RESET}")
                else:
                    # 已知函数名
                    print(f"      - {CYAN}{func_name}{RESET} ({selector})")
            
            # 如果有预期的漏洞函数，检查是否匹配
            if expected_func:
                matched = any(expected_func.lower() in selector_to_name(s).lower() for s in issues)
                if matched:
                    print(f"   {GREEN}匹配预期漏洞函数: {expected_func}{RESET}")
    else:
        print(f"   {GREEN}未检测到漏洞{RESET}")
    
    return is_vulnerable


def analyze_benchmark(name):
    """分析单个benchmark"""
    if name not in BENCHMARKS:
        print(f"{RED}未知的 benchmark: {name}{RESET}")
        print(f"   可用的 benchmarks: {', '.join(BENCHMARKS.keys())}")
        return
    
    info = BENCHMARKS[name]
    vuln_func = info['vulnerable_function']
    
    print(f"\n{'='*70}")
    print(f"{BOLD}{CYAN}分析 Benchmark: {name}{RESET}")
    print(f"{'='*70}")
    print(f"   合约文件: {info['contract']}")
    print(f"   漏洞函数: {vuln_func}")
    print(f"   预期结果: {info['expected']}")
    print(f"   链: {info['chain'].upper()}")
    
    address = info.get('address', '')
    if not address:
        print(f"   {YELLOW}此合约无链上地址，尝试本地编译...{RESET}")
        # 尝试本地编译
        sol_file = ROOT / "benchmark" / name / info['contract']
        if sol_file.exists():
            bytecode = compile_solidity(sol_file)
            if bytecode:
                result = analyze_bytecode(bytecode, f"{name}::{info['contract']}", vuln_func)
                return result
        print(f"   {RED}本地编译失败{RESET}")
        return None
    
    print(f"   地址: {address}")
    
    # 从链上获取bytecode
    print(f"\n   从 {info['chain'].upper()} 链获取 bytecode...")
    bytecode = fetch_bytecode_from_chain(address, info['chain'])
    
    if not bytecode:
        print(f"   {RED}无法获取 bytecode{RESET}")
        return None
    
    return analyze_bytecode(bytecode, f"{name}::{info['contract']}", vuln_func)


def compile_solidity(sol_path):
    """尝试编译Solidity文件"""
    try:
        from solcx import compile_source, install_solc, get_installed_solc_versions, set_solc_version
        
        source = sol_path.read_text(encoding='utf-8', errors='ignore')
        
        # 提取版本
        match = re.search(r'pragma\s+solidity\s*[\^>=<]*\s*(\d+\.\d+)(?:\.(\d+))?', source)
        if match:
            ver = match.group(1)
            if match.group(2):
                ver += f".{match.group(2)}"
            else:
                ver += ".0"
        else:
            ver = "0.8.19"
        
        print(f"   Solidity 版本: {ver}")
        
        # 安装solc
        installed = [str(v) for v in get_installed_solc_versions()]
        if ver not in installed:
            print(f"   安装 solc {ver}...")
            install_solc(ver)
        set_solc_version(ver)
        
        compiled = compile_source(
            source,
            output_values=['bin-runtime'],
            optimize=True,
            optimize_runs=200
        )
        
        # 获取第一个合约的bytecode
        for contract_name, contract_data in compiled.items():
            bytecode = contract_data.get('bin-runtime', '')
            if bytecode:
                return '0x' + bytecode
        
    except Exception as e:
        print(f"   {RED}编译错误: {e}{RESET}")
    
    return None


def demo_all_benchmarks():
    """演示所有benchmarks"""
    results = {}
    
    for name in BENCHMARKS:
        try:
            result = analyze_benchmark(name)
            results[name] = result
        except Exception as e:
            print(f"   {RED}分析 {name} 时出错: {e}{RESET}")
            results[name] = None
    
    # 打印汇总
    print("\n" + "="*70)
    print(f"{BOLD}{CYAN}检测结果汇总{RESET}")
    print("="*70)
    print(f"{'合约':<20} {'预期':<15} {'检测结果':<15} {'状态':<10}")
    print("-"*70)
    
    correct = 0
    total = 0
    
    for name, result in results.items():
        expected = BENCHMARKS[name]['expected']
        if result is None:
            detected = "N/A"
            status = f"{YELLOW}跳过{RESET}"
        elif result:
            detected = "VULNERABLE"
            if expected == "VULNERABLE":
                status = f"{GREEN}✓ 正确{RESET}"
                correct += 1
            else:
                status = f"{RED}✗ 误报{RESET}"
            total += 1
        else:
            detected = "SAFE"
            if expected == "SAFE":
                status = f"{GREEN}✓ 正确{RESET}"
                correct += 1
            else:
                status = f"{RED}✗ 漏报{RESET}"
            total += 1
        
        print(f"{name:<20} {expected:<15} {detected:<15} {status}")
    
    print("-"*70)
    if total > 0:
        print(f"准确率: {correct}/{total} = {correct/total*100:.1f}%")


def main():
    """主函数"""
    if len(sys.argv) < 2:
        print("="*50)
        print("\n用法:")
        print(f"  {sys.argv[0]} all                    # 分析所有 benchmarks")
        print(f"  {sys.argv[0]} <benchmark_name>       # 分析单个 benchmark")
        print(f"  {sys.argv[0]} <bytecode_hex_file>    # 分析 bytecode 文件")
        print(f"  {sys.argv[0]} <solidity_file>        # 编译并分析 Solidity")
        print(f"\n可用的 Benchmarks:")
        for name in BENCHMARKS:
            info = BENCHMARKS[name]
            print(f"  - {name}: {info['contract']} ({info['expected']})")
        return
    
    arg = sys.argv[1]
    
    if arg.lower() == 'all':
        demo_all_benchmarks()
    elif arg in BENCHMARKS:
        analyze_benchmark(arg)
    elif os.path.isfile(arg):
        # 文件分析
        path = Path(arg)
        if path.suffix == '.sol':
            print(f"\n编译 Solidity 文件: {path.name}")
            bytecode = compile_solidity(path)
            if bytecode:
                analyze_bytecode(bytecode, path.stem)
        else:
            # 假设是bytecode文件
            print(f"\n读取 bytecode 文件: {path.name}")
            bytecode = path.read_text().strip()
            if not bytecode.startswith('0x'):
                bytecode = '0x' + bytecode
            analyze_bytecode(bytecode, path.stem)
    else:
        # 可能是直接的benchmark名称
        print(f"{RED}参数无效: {arg}{RESET}")
        print(f"   请使用 'all' 或以下 benchmark 名称之一:")
        for name in BENCHMARKS:
            print(f"   - {name}")


if __name__ == "__main__":
    main()
