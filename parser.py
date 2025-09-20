#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
日志解析器模块
从混合格式日志文件中提取关键字段：时间戳、IP地址、请求内容、错误等级
支持JSON、普通文本、半结构化字段等多种格式
"""

import json
import re
import datetime
from typing import Dict, List, Optional, Any, Union


class LogParser:
    """日志解析器类，用于解析多种格式的日志文件"""
    
    def __init__(self):
        # 定义常见日志格式的正则表达式模式
        self.patterns = {
            # JSON格式日志
            'json': re.compile(r'^\s*\{.*\}\s*$'),
            
            # Apache/Nginx访问日志格式
            'apache_common': re.compile(
                r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<timestamp>[^\]]+)\] '
                r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" '
                r'(?P<status>\d+) (?P<size>\d+|-)'
            ),
            
            # 带时间戳和IP的通用格式
            'timestamp_ip': re.compile(
                r'(?P<timestamp>\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}(?:\.\d+)?)'
                r'.*?(?P<ip>\d+\.\d+\.\d+\.\d+).*?'
                r'(?P<content>.*)'
            ),
            
            # 简单错误日志格式
            'error_log': re.compile(
                r'\[(?P<level>ERROR|WARN|INFO|DEBUG)\]'
                r'.*?(?P<timestamp>\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}(?:\.\d+)?)'
                r'.*?(?P<content>.*)'
            ),
            
            # 提取IP地址的通用模式
            'ip_address': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            
            # 提取时间戳的通用模式
            'timestamp': re.compile(
                r'\b\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?\b'
            ),
            
            # 提取错误等级的通用模式
            'log_level': re.compile(r'\b(ERROR|WARN|INFO|DEBUG|FATAL|CRITICAL)\b')
        }
    
    def parse_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        解析日志文件
        
        Args:
            file_path: 日志文件路径
            
        Returns:
            解析后的日志条目列表
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            return self.parse_lines(lines)
        except Exception as e:
            print(f"解析日志文件时出错: {e}")
            return []
    
    def parse_lines(self, lines: List[str]) -> List[Dict[str, Any]]:
        """
        解析多行日志文本
        
        Args:
            lines: 日志行列表
            
        Returns:
            解析后的日志条目列表
        """
        parsed_logs = []
        
        for line in lines:
            line = line.strip()
            if not line:  # 跳过空行
                continue
                
            parsed_entry = self.parse_line(line)
            if parsed_entry:
                parsed_logs.append(parsed_entry)
        
        return parsed_logs
    
    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        解析单行日志
        
        Args:
            line: 单行日志文本
            
        Returns:
            解析后的日志条目字典，解析失败返回None
        """
        try:
            # 尝试解析JSON格式
            if self.patterns['json'].match(line):
                return self._parse_json_log(line)
            
            # 尝试解析Apache/Nginx访问日志
            apache_match = self.patterns['apache_common'].match(line)
            if apache_match:
                return self._parse_apache_log(apache_match)
            
            # 尝试解析带时间戳和IP的通用格式
            timestamp_ip_match = self.patterns['timestamp_ip'].match(line)
            if timestamp_ip_match:
                return self._parse_timestamp_ip_log(timestamp_ip_match, line)
            
            # 尝试解析错误日志格式
            error_match = self.patterns['error_log'].match(line)
            if error_match:
                return self._parse_error_log(error_match, line)
            
            # 如果以上格式都不匹配，尝试通用提取
            return self._parse_generic_log(line)
            
        except Exception as e:
            print(f"解析日志行时出错: {e}")
            return None
    
    def _parse_json_log(self, line: str) -> Dict[str, Any]:
        """解析JSON格式日志"""
        try:
            log_data = json.loads(line)
            
            # 提取关键字段
            result = {
                'timestamp': self._extract_timestamp_from_json(log_data),
                'ip': self._extract_ip_from_json(log_data),
                'content': self._extract_content_from_json(log_data),
                'level': self._extract_level_from_json(log_data),
                'raw': line
            }
            
            return result
        except json.JSONDecodeError:
            return self._parse_generic_log(line)
    
    def _parse_apache_log(self, match: re.Match) -> Dict[str, Any]:
        """解析Apache/Nginx访问日志"""
        return {
            'timestamp': self._normalize_timestamp(match.group('timestamp')),
            'ip': match.group('ip'),
            'content': f"{match.group('method')} {match.group('path')} {match.group('protocol')}",
            'level': 'INFO',  # Apache访问日志默认为INFO级别
            'raw': match.group(0)
        }
    
    def _parse_timestamp_ip_log(self, match: re.Match, line: str) -> Dict[str, Any]:
        """解析带时间戳和IP的通用格式日志"""
        return {
            'timestamp': self._normalize_timestamp(match.group('timestamp')),
            'ip': match.group('ip'),
            'content': match.group('content'),
            'level': self._extract_level_from_text(line),
            'raw': line
        }
    
    def _parse_error_log(self, match: re.Match, line: str) -> Dict[str, Any]:
        """解析错误日志格式"""
        return {
            'timestamp': self._normalize_timestamp(match.group('timestamp')),
            'ip': self._extract_ip_from_text(line),
            'content': match.group('content'),
            'level': match.group('level'),
            'raw': line
        }
    
    def _parse_generic_log(self, line: str) -> Dict[str, Any]:
        """解析通用格式日志"""
        return {
            'timestamp': self._extract_timestamp_from_text(line),
            'ip': self._extract_ip_from_text(line),
            'content': line,
            'level': self._extract_level_from_text(line),
            'raw': line
        }
    
    def _extract_timestamp_from_json(self, log_data: Dict[str, Any]) -> str:
        """从JSON日志中提取时间戳"""
        timestamp_fields = ['timestamp', 'time', 'datetime', '@timestamp', 'log_time']
        for field in timestamp_fields:
            if field in log_data:
                return self._normalize_timestamp(str(log_data[field]))
        return self._extract_timestamp_from_text(json.dumps(log_data))
    
    def _extract_ip_from_json(self, log_data: Dict[str, Any]) -> str:
        """从JSON日志中提取IP地址"""
        ip_fields = ['ip', 'client_ip', 'remote_addr', 'source_ip', 'host']
        for field in ip_fields:
            if field in log_data:
                ip_match = self.patterns['ip_address'].search(str(log_data[field]))
                if ip_match:
                    return ip_match.group(0)
        return self._extract_ip_from_text(json.dumps(log_data))
    
    def _extract_content_from_json(self, log_data: Dict[str, Any]) -> str:
        """从JSON日志中提取内容"""
        content_fields = ['message', 'content', 'request', 'description', 'text']
        for field in content_fields:
            if field in log_data:
                return str(log_data[field])
        return json.dumps(log_data)
    
    def _extract_level_from_json(self, log_data: Dict[str, Any]) -> str:
        """从JSON日志中提取错误等级"""
        level_fields = ['level', 'severity', 'priority', 'log_level']
        for field in level_fields:
            if field in log_data:
                level = str(log_data[field]).upper()
                if level in ['ERROR', 'WARN', 'INFO', 'DEBUG', 'FATAL', 'CRITICAL']:
                    return level
        return self._extract_level_from_text(json.dumps(log_data))
    
    def _extract_timestamp_from_text(self, text: str) -> str:
        """从文本中提取时间戳"""
        timestamp_match = self.patterns['timestamp'].search(text)
        if timestamp_match:
            return self._normalize_timestamp(timestamp_match.group(0))
        return datetime.datetime.now().isoformat()
    
    def _extract_ip_from_text(self, text: str) -> str:
        """从文本中提取IP地址"""
        ip_match = self.patterns['ip_address'].search(text)
        return ip_match.group(0) if ip_match else "unknown"
    
    def _extract_level_from_text(self, text: str) -> str:
        """从文本中提取错误等级"""
        level_match = self.patterns['log_level'].search(text)
        return level_match.group(0) if level_match else "INFO"
    
    def _normalize_timestamp(self, timestamp: str) -> str:
        """标准化时间戳格式"""
        try:
            # 尝试解析各种时间戳格式
            formats = [
                '%Y-%m-%d %H:%M:%S',
                '%Y-%m-%dT%H:%M:%S',
                '%Y-%m-%d %H:%M:%S.%f',
                '%Y-%m-%dT%H:%M:%S.%f',
                '%Y-%m-%d %H:%M:%S %z',
                '%Y-%m-%dT%H:%M:%S %z',
                '%Y-%m-%dT%H:%M:%SZ',
                '%d/%b/%Y:%H:%M:%S %z',
                '%d/%b/%Y:%H:%M:%S'
            ]
            
            for fmt in formats:
                try:
                    dt = datetime.datetime.strptime(timestamp, fmt)
                    return dt.isoformat()
                except ValueError:
                    continue
            
            # 如果所有格式都不匹配，返回原始时间戳
            return timestamp
        except Exception:
            return datetime.datetime.now().isoformat()