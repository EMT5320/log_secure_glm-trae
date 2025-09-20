#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
日志风险检测与自动修复系统测试脚本
用于验证系统功能
"""

import os
import sys
import json
import tempfile
from main import LogSecuritySystem


def test_log_parser():
    """测试日志解析器"""
    print("=== 测试日志解析器 ===")
    
    system = LogSecuritySystem()
    
    # 测试解析示例日志文件
    log_file = os.path.join(os.path.dirname(__file__), 'sample_logs.txt')
    if os.path.exists(log_file):
        log_entries = system.parser.parse_file(log_file)
        print(f"成功解析 {len(log_entries)} 条日志记录")
        
        # 打印前3条解析结果
        for i, entry in enumerate(log_entries[:3]):
            print(f"记录 {i+1}:")
            print(f"  时间戳: {entry.get('timestamp', 'N/A')}")
            print(f"  IP地址: {entry.get('ip', 'N/A')}")
            print(f"  内容: {entry.get('content', 'N/A')[:50]}...")
            print(f"  等级: {entry.get('level', 'N/A')}")
            print()
    else:
        print(f"示例日志文件不存在: {log_file}")
    
    print("日志解析器测试完成\n")


def test_risk_detector():
    """测试风险检测器"""
    print("=== 测试风险检测器 ===")
    
    system = LogSecuritySystem()
    
    # 测试解析示例日志文件
    log_file = os.path.join(os.path.dirname(__file__), 'sample_logs.txt')
    if os.path.exists(log_file):
        log_entries = system.parser.parse_file(log_file)
        
        # 检测风险
        risk_detections = system.detector.detect_risks(log_entries)
        print(f"检测到 {len(risk_detections)} 个风险")
        
        # 打印前3个风险检测结果
        for i, detection in enumerate(risk_detections[:3]):
            print(f"风险 {i+1}:")
            print(f"  时间戳: {detection.get('timestamp', 'N/A')}")
            print(f"  IP地址: {detection.get('ip', 'N/A')}")
            print(f"  等级: {detection.get('level', 'N/A')}")
            print(f"  原因: {detection.get('reason', 'N/A')}")
            print()
    else:
        print(f"示例日志文件不存在: {log_file}")
    
    print("风险检测器测试完成\n")


def test_risk_responder():
    """测试风险响应器"""
    print("=== 测试风险响应器 ===")
    
    system = LogSecuritySystem()
    
    # 测试解析示例日志文件
    log_file = os.path.join(os.path.dirname(__file__), 'sample_logs.txt')
    if os.path.exists(log_file):
        log_entries = system.parser.parse_file(log_file)
        
        # 检测风险
        risk_detections = system.detector.detect_risks(log_entries)
        
        # 响应风险
        responses = system.responder.respond_to_risks(risk_detections)
        print(f"生成了 {len(responses)} 个响应")
        
        # 打印前3个响应结果
        for i, response in enumerate(responses[:3]):
            print(f"响应 {i+1}:")
            print(f"  等级: {response.get('level', 'N/A')}")
            print(f"  IP地址: {response.get('ip', 'N/A')}")
            print(f"  动作: {response.get('action', 'N/A')}")
            print(f"  原因: {response.get('reason', 'N/A')}")
            print(f"  原始内容: {response.get('original_content', 'N/A')[:50]}...")
            print(f"  清理后内容: {response.get('sanitized_content', 'N/A')[:50]}...")
            print()
    else:
        print(f"示例日志文件不存在: {log_file}")
    
    print("风险响应器测试完成\n")


def test_system_integration():
    """测试系统集成"""
    print("=== 测试系统集成 ===")
    
    system = LogSecuritySystem()
    
    # 测试处理日志文件
    log_file = os.path.join(os.path.dirname(__file__), 'sample_logs.txt')
    if os.path.exists(log_file):
        # 创建临时输出文件
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as temp_file:
            output_file = temp_file.name
        
        try:
            # 处理日志文件
            result = system.process_log_file(log_file, output_file)
            print(f"处理结果: {json.dumps(result.get('summary', {}), indent=2, ensure_ascii=False)}")
            
            # 检查输出文件是否创建
            if os.path.exists(output_file):
                print(f"输出文件已创建: {output_file}")
                
                # 读取并打印输出文件内容
                with open(output_file, 'r', encoding='utf-8') as f:
                    output_data = json.load(f)
                    print(f"输出文件包含 {len(output_data.get('details', []))} 条详细记录")
            else:
                print("输出文件未创建")
        finally:
            # 删除临时输出文件
            if os.path.exists(output_file):
                os.unlink(output_file)
    else:
        print(f"示例日志文件不存在: {log_file}")
    
    print("系统集成测试完成\n")


def test_ml_model():
    """测试机器学习模型"""
    print("=== 测试机器学习模型 ===")
    
    system = LogSecuritySystem()
    
    # 生成样本日志
    normal_logs, malicious_logs = system.detector.generate_sample_logs(50, 25)
    print(f"生成了 {len(normal_logs)} 条正常日志和 {len(malicious_logs)} 条恶意日志")
    
    # 创建临时文件
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_normal:
        normal_file = temp_normal.name
        for log in normal_logs:
            temp_normal.write(log + '\n')
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_malicious:
        malicious_file = temp_malicious.name
        for log in malicious_logs:
            temp_malicious.write(log + '\n')
    
    try:
        # 训练模型
        print("正在训练模型...")
        result = system.train_model(normal_file, malicious_file)
        print(f"训练结果: {result.get('message', 'N/A')}")
        
        # 评估模型
        evaluation = result.get('evaluation', {})
        if 'accuracy' in evaluation:
            print(f"模型准确率: {evaluation['accuracy']:.2f}")
        
        # 使用训练后的模型检测风险
        log_file = os.path.join(os.path.dirname(__file__), 'sample_logs.txt')
        if os.path.exists(log_file):
            log_entries = system.parser.parse_file(log_file)
            risk_detections = system.detector.detect_risks(log_entries)
            
            # 统计使用机器学习检测到的风险数量
            ml_detections = [d for d in risk_detections if d.get('ml_prediction') is not None]
            print(f"使用机器学习检测到 {len(ml_detections)} 个风险")
    finally:
        # 删除临时文件
        os.unlink(normal_file)
        os.unlink(malicious_file)
    
    print("机器学习模型测试完成\n")


def test_api_endpoints():
    """测试API端点（仅打印测试说明）"""
    print("=== 测试API端点 ===")
    print("要测试API端点，请执行以下步骤：")
    print("1. 在一个终端中启动API服务器: python api.py")
    print("2. 在另一个终端中使用curl或Postman测试以下端点:")
    print("   - 健康检查: curl http://localhost:5000/api/health")
    print("   - 处理日志文件: curl -X POST -F \"file=@sample_logs.txt\" http://localhost:5000/api/process/file")
    print("   - 处理日志文本: curl -X POST -H \"Content-Type: application/json\" -d '{\"text\":\"<日志文本>\"}' http://localhost:5000/api/process/text")
    print("   - 生成样本日志: curl -X POST -H \"Content-Type: application/json\" -d '{\"num_normal\":10,\"num_malicious\":5}' http://localhost:5000/api/sample")
    print("注意：请确保已安装Flask库: pip install flask")
    print("API端点测试说明完成\n")


def main():
    """主测试函数"""
    print("日志风险检测与自动修复系统测试")
    print("=" * 50)
    
    # 测试各个模块
    test_log_parser()
    test_risk_detector()
    test_risk_responder()
    test_system_integration()
    test_ml_model()
    test_api_endpoints()
    
    print("所有测试完成！")


if __name__ == '__main__':
    main()