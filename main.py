#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
日志风险检测与自动修复系统主模块
提供CLI和简单REST API接口
"""

import argparse
import json
import os
import sys
from typing import List, Dict, Any, Optional

from parser import LogParser
from detector import RiskDetector
from responder import RiskResponder


class LogSecuritySystem:
    """日志安全系统主类"""
    
    def __init__(self):
        self.parser = LogParser()
        self.detector = RiskDetector()
        self.responder = RiskResponder()
    
    def process_log_file(self, file_path: str, output_file: Optional[str] = None) -> Dict[str, Any]:
        """
        处理日志文件
        
        Args:
            file_path: 日志文件路径
            output_file: 输出文件路径（可选）
            
        Returns:
            处理结果
        """
        # 解析日志文件
        print(f"正在解析日志文件: {file_path}")
        log_entries = self.parser.parse_file(file_path)
        print(f"解析到 {len(log_entries)} 条日志记录")
        
        if not log_entries:
            return {"error": "无法解析日志文件或文件为空"}
        
        # 检测风险
        print("正在检测风险...")
        risk_detections = self.detector.detect_risks(log_entries)
        print(f"检测到 {len(risk_detections)} 个风险")
        
        if not risk_detections:
            return {"message": "未检测到风险"}
        
        # 响应风险
        print("正在生成响应...")
        responses = self.responder.respond_to_risks(risk_detections)
        
        # 生成报告
        report = self.responder.generate_detailed_report(responses)
        
        # 输出结果
        if output_file:
            self.responder.export_report_to_json(report, output_file)
            print(f"报告已保存到: {output_file}")
        
        return report
    
    def process_log_text(self, log_text: str) -> Dict[str, Any]:
        """
        处理日志文本
        
        Args:
            log_text: 日志文本
            
        Returns:
            处理结果
        """
        # 解析日志文本
        lines = log_text.strip().split('\n')
        log_entries = self.parser.parse_lines(lines)
        
        if not log_entries:
            return {"error": "无法解析日志文本或文本为空"}
        
        # 检测风险
        risk_detections = self.detector.detect_risks(log_entries)
        
        if not risk_detections:
            return {"message": "未检测到风险"}
        
        # 响应风险
        responses = self.responder.respond_to_risks(risk_detections)
        
        # 生成报告
        report = self.responder.generate_detailed_report(responses)
        
        return report
    
    def train_model(self, normal_logs_file: str, malicious_logs_file: str) -> Dict[str, Any]:
        """
        训练机器学习模型
        
        Args:
            normal_logs_file: 正常日志文件路径
            malicious_logs_file: 恶意日志文件路径
            
        Returns:
            训练结果
        """
        # 读取正常日志
        with open(normal_logs_file, 'r', encoding='utf-8') as f:
            normal_logs = [line.strip() for line in f if line.strip()]
        
        # 读取恶意日志
        with open(malicious_logs_file, 'r', encoding='utf-8') as f:
            malicious_logs = [line.strip() for line in f if line.strip()]
        
        print(f"读取到 {len(normal_logs)} 条正常日志和 {len(malicious_logs)} 条恶意日志")
        
        # 训练模型
        print("正在训练模型...")
        self.detector.train_model(normal_logs, malicious_logs)
        
        # 评估模型
        print("正在评估模型...")
        evaluation = self.detector.evaluate_model(normal_logs, malicious_logs)
        
        return {
            "message": "模型训练完成",
            "evaluation": evaluation
        }
    
    def generate_sample_logs(self, normal_file: str, malicious_file: str, 
                           num_normal: int = 100, num_malicious: int = 50) -> Dict[str, Any]:
        """
        生成样本日志文件
        
        Args:
            normal_file: 正常日志文件路径
            malicious_file: 恶意日志文件路径
            num_normal: 正常日志数量
            num_malicious: 恶意日志数量
            
        Returns:
            生成结果
        """
        # 生成样本日志
        normal_logs, malicious_logs = self.detector.generate_sample_logs(num_normal, num_malicious)
        
        # 保存正常日志
        with open(normal_file, 'w', encoding='utf-8') as f:
            for log in normal_logs:
                f.write(log + '\n')
        
        # 保存恶意日志
        with open(malicious_file, 'w', encoding='utf-8') as f:
            for log in malicious_logs:
                f.write(log + '\n')
        
        return {
            "message": "样本日志生成完成",
            "normal_logs": len(normal_logs),
            "malicious_logs": len(malicious_logs),
            "normal_file": normal_file,
            "malicious_file": malicious_file
        }


def create_cli():
    """创建命令行接口"""
    parser = argparse.ArgumentParser(description='日志风险检测与自动修复系统')
    
    subparsers = parser.add_subparsers(dest='command', help='可用命令')
    
    # 处理日志文件命令
    process_parser = subparsers.add_parser('process', help='处理日志文件')
    process_parser.add_argument('file', help='日志文件路径')
    process_parser.add_argument('-o', '--output', help='输出文件路径')
    
    # 处理日志文本命令
    text_parser = subparsers.add_parser('text', help='处理日志文本')
    text_parser.add_argument('text', help='日志文本')
    
    # 训练模型命令
    train_parser = subparsers.add_parser('train', help='训练机器学习模型')
    train_parser.add_argument('normal', help='正常日志文件路径')
    train_parser.add_argument('malicious', help='恶意日志文件路径')
    
    # 生成样本日志命令
    sample_parser = subparsers.add_parser('sample', help='生成样本日志')
    sample_parser.add_argument('normal', help='正常日志输出文件路径')
    sample_parser.add_argument('malicious', help='恶意日志输出文件路径')
    sample_parser.add_argument('--num-normal', type=int, default=100, help='正常日志数量')
    sample_parser.add_argument('--num-malicious', type=int, default=50, help='恶意日志数量')
    
    return parser


def main():
    """主函数"""
    parser = create_cli()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    system = LogSecuritySystem()
    
    try:
        if args.command == 'process':
            result = system.process_log_file(args.file, args.output)
            print(json.dumps(result, ensure_ascii=False, indent=2))
        
        elif args.command == 'text':
            result = system.process_log_text(args.text)
            print(json.dumps(result, ensure_ascii=False, indent=2))
        
        elif args.command == 'train':
            result = system.train_model(args.normal, args.malicious)
            print(json.dumps(result, ensure_ascii=False, indent=2))
        
        elif args.command == 'sample':
            result = system.generate_sample_logs(
                args.normal, args.malicious, 
                args.num_normal, args.num_malicious
            )
            print(json.dumps(result, ensure_ascii=False, indent=2))
    
    except Exception as e:
        print(f"错误: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()