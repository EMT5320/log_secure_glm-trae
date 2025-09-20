#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
修复与响应模块
当检测到风险时，调用修复函数并生成告警信息
"""

import json
import re
from typing import Dict, List, Any, Optional, Union


class RiskResponder:
    """风险响应类，用于处理检测到的风险并生成响应"""
    
    def __init__(self):
        # 定义敏感信息正则表达式
        self.sensitive_patterns = {
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'phone': re.compile(r'\b1[3-9]\d{9}\b'),
            'id_card': re.compile(r'\b\d{17}[\dXx]\b'),
            'credit_card': re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'),
            'password': re.compile(r'(\bpassword\b|\bpwd\b|\bpass\b)[\s:=]+[^\s]+', re.IGNORECASE),
            'token': re.compile(r'(\btoken\b|\bkey\b|\bsecret\b)[\s:=]+[^\s]+', re.IGNORECASE),
            'username': re.compile(r'(\busername\b|\buser\b|\blogin\b)[\s:=]+[^\s]+', re.IGNORECASE)
        }
        
        # 定义响应动作
        self.response_actions = {
            'high': 'blocked',
            'medium': 'monitored',
            'low': 'logged'
        }
    
    def respond_to_risks(self, risk_detections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        对检测到的风险进行响应
        
        Args:
            risk_detections: 风险检测结果列表
            
        Returns:
            响应结果列表
        """
        responses = []
        
        for detection in risk_detections:
            response = self._create_response(detection)
            responses.append(response)
        
        return responses
    
    def _create_response(self, detection: Dict[str, Any]) -> Dict[str, Any]:
        """
        创建单个风险检测的响应
        
        Args:
            detection: 风险检测结果
            
        Returns:
            响应结果
        """
        # 获取风险等级
        level = detection.get('level', 'low')
        
        # 获取IP地址
        ip = detection.get('ip', 'unknown')
        
        # 获取风险原因
        reason = detection.get('reason', 'Unknown risk')
        
        # 确定响应动作
        action = self.response_actions.get(level, 'logged')
        
        # 修复敏感信息
        sanitized_content = self._sanitize_sensitive_data(detection.get('content', ''))
        
        # 创建响应对象
        response = {
            "level": level,
            "ip": ip,
            "action": action,
            "reason": reason,
            "timestamp": detection.get('timestamp', ''),
            "sanitized_content": sanitized_content,
            "original_content": detection.get('content', ''),
            "rule_matches": detection.get('rule_matches', {}),
            "ml_prediction": detection.get('ml_prediction', None)
        }
        
        return response
    
    def _sanitize_sensitive_data(self, content: str) -> str:
        """
        清理敏感数据
        
        Args:
            content: 原始内容
            
        Returns:
            清理后的内容
        """
        sanitized = content
        
        # 清理邮箱
        sanitized = self.sensitive_patterns['email'].sub('***@***.***', sanitized)
        
        # 清理手机号
        sanitized = self.sensitive_patterns['phone'].sub('1**********', sanitized)
        
        # 清理身份证号
        sanitized = self.sensitive_patterns['id_card'].sub('***********', sanitized)
        
        # 清理信用卡号
        sanitized = self.sensitive_patterns['credit_card'].sub('****-****-****-****', sanitized)
        
        # 清理密码
        def replace_password(match):
            key = match.group(1)
            return f"{key}: ***"
        sanitized = self.sensitive_patterns['password'].sub(replace_password, sanitized)
        
        # 清理令牌
        def replace_token(match):
            key = match.group(1)
            return f"{key}: ***"
        sanitized = self.sensitive_patterns['token'].sub(replace_token, sanitized)
        
        # 清理用户名
        def replace_username(match):
            key = match.group(1)
            return f"{key}: ***"
        sanitized = self.sensitive_patterns['username'].sub(replace_username, sanitized)
        
        return sanitized
    
    def generate_alert_json(self, response: Dict[str, Any]) -> str:
        """
        生成告警JSON
        
        Args:
            response: 响应结果
            
        Returns:
            JSON格式的告警信息
        """
        alert = {
            "level": response.get('level', 'low'),
            "ip": response.get('ip', 'unknown'),
            "action": response.get('action', 'logged'),
            "reason": response.get('reason', 'Unknown risk'),
            "timestamp": response.get('timestamp', '')
        }
        
        return json.dumps(alert, ensure_ascii=False, indent=2)
    
    def generate_detailed_report(self, responses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        生成详细报告
        
        Args:
            responses: 响应结果列表
            
        Returns:
            详细报告
        """
        # 统计各风险等级的数量
        level_counts = {
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        # 统计各响应动作的数量
        action_counts = {
            'blocked': 0,
            'monitored': 0,
            'logged': 0
        }
        
        # 统计风险原因
        reason_counts = {}
        
        # 收集所有IP地址
        ips = set()
        
        for response in responses:
            level = response.get('level', 'low')
            action = response.get('action', 'logged')
            reason = response.get('reason', 'Unknown risk')
            ip = response.get('ip', 'unknown')
            
            level_counts[level] += 1
            action_counts[action] += 1
            ips.add(ip)
            
            if reason in reason_counts:
                reason_counts[reason] += 1
            else:
                reason_counts[reason] = 1
        
        # 生成报告
        report = {
            "summary": {
                "total_risks": len(responses),
                "level_distribution": level_counts,
                "action_distribution": action_counts,
                "unique_ips": len(ips),
                "top_reasons": sorted(reason_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            },
            "details": responses
        }
        
        return report
    
    def export_report_to_json(self, report: Dict[str, Any], file_path: str) -> None:
        """
        将报告导出为JSON文件
        
        Args:
            report: 报告数据
            file_path: 文件路径
        """
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
            print(f"报告已导出到 {file_path}")
        except Exception as e:
            print(f"导出报告时出错: {e}")
    
    def export_report_to_csv(self, responses: List[Dict[str, Any]], file_path: str) -> None:
        """
        将报告导出为CSV文件
        
        Args:
            responses: 响应结果列表
            file_path: 文件路径
        """
        try:
            import csv
            
            with open(file_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                # 写入表头
                writer.writerow([
                    'Timestamp', 'Level', 'IP', 'Action', 'Reason', 
                    'Sanitized Content', 'Original Content'
                ])
                
                # 写入数据
                for response in responses:
                    writer.writerow([
                        response.get('timestamp', ''),
                        response.get('level', ''),
                        response.get('ip', ''),
                        response.get('action', ''),
                        response.get('reason', ''),
                        response.get('sanitized_content', ''),
                        response.get('original_content', '')
                    ])
            
            print(f"报告已导出到 {file_path}")
        except Exception as e:
            print(f"导出报告时出错: {e}")
    
    def get_blocked_ips(self, responses: List[Dict[str, Any]]) -> List[str]:
        """
        获取被阻止的IP地址列表
        
        Args:
            responses: 响应结果列表
            
        Returns:
            被阻止的IP地址列表
        """
        blocked_ips = set()
        
        for response in responses:
            if response.get('action') == 'blocked':
                blocked_ips.add(response.get('ip', 'unknown'))
        
        return list(blocked_ips)
    
    def get_monitored_ips(self, responses: List[Dict[str, Any]]) -> List[str]:
        """
        获取被监控的IP地址列表
        
        Args:
            responses: 响应结果列表
            
        Returns:
            被监控的IP地址列表
        """
        monitored_ips = set()
        
        for response in responses:
            if response.get('action') == 'monitored':
                monitored_ips.add(response.get('ip', 'unknown'))
        
        return list(monitored_ips)
    
    def create_firewall_rules(self, responses: List[Dict[str, Any]]) -> List[str]:
        """
        创建防火墙规则（示例）
        
        Args:
            responses: 响应结果列表
            
        Returns:
            防火墙规则列表
        """
        blocked_ips = self.get_blocked_ips(responses)
        rules = []
        
        for ip in blocked_ips:
            if ip != 'unknown':
                # Linux iptables 规则示例
                rule = f"iptables -A INPUT -s {ip} -j DROP"
                rules.append(rule)
                
                # Windows 防火墙规则示例
                rule = f"netsh advfirewall firewall add rule name=\"Block {ip}\" dir=in action=block remoteip={ip}"
                rules.append(rule)
        
        return rules