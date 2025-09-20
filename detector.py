#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
风险检测模块
实现规则检测和机器学习检测，识别潜在的安全风险
"""

import re
import json
import pickle
import os
from typing import Dict, List, Tuple, Any, Optional
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score


class RiskDetector:
    """风险检测类，用于检测日志中的潜在安全风险"""
    
    def __init__(self):
        # 定义恶意模式正则表达式
        self.malicious_patterns = {
            'sql_injection': [
                r'(DROP\s+TABLE|DELETE\s+FROM|UPDATE\s+.*\s+SET|INSERT\s+INTO)',
                r'(\bSELECT\b.*\bFROM\b|\bUNION\b.*\bSELECT\b)',
                r'(\bOR\b\s+\d+\s*=\s*\d+|\bAND\b\s+\d+\s*=\s*\d+)',
                r'(\bEXEC\b|\bEXECUTE\b|\bXP_CMDShell\b)',
                r'(\bWAITFOR\s+DELAY\b|\bSLEEP\b\s*\()',
                r'(\b;\s*DROP\b|\b;\s*--\b)',
                r'(\b\'\s*OR\s*\'\s*=\s*\'\b|\b"\s*OR\s*"\s*=\s*"\b)'
            ],
            'xss': [
                r'(<script[^>]*>.*?</script>)',
                r'(javascript:|vbscript:|data:)',
                r'(on\w+\s*=)',
                r'(<iframe[^>]*>|<object[^>]*>|<embed[^>]*>)',
                r'(\balert\s*\(|\bconfirm\s*\(|\bprompt\s*\()',
                r'(document\.|window\.|location\.|self\.)',
                r'(eval\s*\(|setTimeout\s*\(|setInterval\s*\()'
            ],
            'sensitive_data': [
                r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # 信用卡号
                r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # 邮箱
                r'\b1[3-9]\d{9}\b',  # 手机号
                r'(\bpassword\b|\bpwd\b|\bpass\b)[\s:=]+[^\s]+',  # 密码
                r'(\btoken\b|\bkey\b|\bsecret\b)[\s:=]+[^\s]+',  # 密钥
                r'(\busername\b|\buser\b|\blogin\b)[\s:=]+[^\s]+'  # 用户名
            ],
            'path_traversal': [
                r'(\.\./|\.\.\\)',
                r'(/etc/passwd|/etc/shadow|C:\\Windows\\System32)',
                r'(\.\./\.\./|\.\.\\\.\.\\)',
                r'(/proc/self/environ|/var/log/auth)'
            ],
            'command_injection': [
                r'(;|\||&|\$\(|`)',
                r'(\bnc\b|\bnetcat\b|\btelnet\b|\bssh\b)',
                r'(\bwget\b|\bcurl\b|\bfetch\b)',
                r'(\bchmod\b|\bchown\b|\bsudo\b|\bsu\b)',
                r'(\brm\s+-rf\b|\bdel\s+/f\b)'
            ]
        }
        
        # 编译正则表达式
        self.compiled_patterns = {}
        for category, patterns in self.malicious_patterns.items():
            self.compiled_patterns[category] = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
        
        # 初始化机器学习模型
        self.model = None
        self.model_path = os.path.join(os.path.dirname(__file__), 'risk_model.pkl')
        self.vectorizer_path = os.path.join(os.path.dirname(__file__), 'vectorizer.pkl')
        
        # 加载已训练的模型（如果存在）
        self._load_model()
    
    def detect_risks(self, log_entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        检测日志中的风险
        
        Args:
            log_entries: 解析后的日志条目列表
            
        Returns:
            检测结果列表，包含风险等级和详细信息
        """
        results = []
        
        for entry in log_entries:
            result = self._detect_single_entry(entry)
            if result:
                results.append(result)
        
        return results
    
    def _detect_single_entry(self, log_entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        检测单个日志条目的风险
        
        Args:
            log_entry: 单个日志条目
            
        Returns:
            风险检测结果，如果没有风险则返回None
        """
        content = log_entry.get('content', '')
        ip = log_entry.get('ip', 'unknown')
        
        # 规则检测
        rule_detections = self._rule_based_detection(content)
        
        # 机器学习检测
        ml_detection = self._ml_based_detection(content)
        
        # 合并检测结果
        if rule_detections or ml_detection:
            # 确定风险等级
            level = self._determine_risk_level(rule_detections, ml_detection)
            
            # 确定风险原因
            reasons = []
            if rule_detections:
                for category, matches in rule_detections.items():
                    reasons.append(f"{category.replace('_', ' ').title()}: {len(matches)} matches")
            
            if ml_detection:
                reasons.append(f"ML Model: {ml_detection['confidence']:.2f} confidence")
            
            return {
                'timestamp': log_entry.get('timestamp', ''),
                'ip': ip,
                'level': level,
                'reason': '; '.join(reasons),
                'content': content,
                'raw': log_entry.get('raw', ''),
                'rule_matches': rule_detections,
                'ml_prediction': ml_detection
            }
        
        return None
    
    def _rule_based_detection(self, content: str) -> Dict[str, List[str]]:
        """
        基于规则的风险检测
        
        Args:
            content: 日志内容
            
        Returns:
            检测到的风险类别和匹配内容
        """
        detections = {}
        
        for category, patterns in self.compiled_patterns.items():
            matches = []
            for pattern in patterns:
                found = pattern.findall(content)
                if found:
                    matches.extend(found)
            
            if matches:
                detections[category] = matches
        
        return detections
    
    def _ml_based_detection(self, content: str) -> Optional[Dict[str, Any]]:
        """
        基于机器学习的风险检测
        
        Args:
            content: 日志内容
            
        Returns:
            机器学习检测结果，如果没有模型则返回None
        """
        if self.model is None:
            return None
        
        try:
            # 预处理文本
            processed_text = self._preprocess_text(content)
            
            # 使用模型进行预测
            prediction = self.model.predict([processed_text])[0]
            probability = self.model.predict_proba([processed_text])[0]
            
            # 获取恶意类别的概率
            malicious_prob = probability[1] if len(probability) > 1 else 0.0
            
            # 如果预测为恶意且概率超过阈值，则返回检测结果
            if prediction == 1 and malicious_prob > 0.7:
                return {
                    'prediction': 'malicious',
                    'confidence': malicious_prob
                }
            
            return None
        except Exception as e:
            print(f"机器学习检测出错: {e}")
            return None
    
    def _preprocess_text(self, text: str) -> str:
        """
        预处理文本用于机器学习模型
        
        Args:
            text: 原始文本
            
        Returns:
            预处理后的文本
        """
        # 转换为小写
        text = text.lower()
        
        # 移除特殊字符，保留字母数字和空格
        text = re.sub(r'[^a-zA-Z0-9\s]', ' ', text)
        
        # 移除多余空格
        text = re.sub(r'\s+', ' ', text).strip()
        
        return text
    
    def _determine_risk_level(self, rule_detections: Dict[str, List[str]], 
                           ml_detection: Optional[Dict[str, Any]]) -> str:
        """
        确定风险等级
        
        Args:
            rule_detections: 规则检测结果
            ml_detection: 机器学习检测结果
            
        Returns:
            风险等级 (high, medium, low)
        """
        # 高风险类别
        high_risk_categories = ['sql_injection', 'command_injection', 'path_traversal']
        
        # 中风险类别
        medium_risk_categories = ['xss']
        
        # 检查高风险类别
        for category in high_risk_categories:
            if category in rule_detections:
                return 'high'
        
        # 检查机器学习检测结果
        if ml_detection and ml_detection['confidence'] > 0.9:
            return 'high'
        elif ml_detection and ml_detection['confidence'] > 0.8:
            return 'medium'
        
        # 检查中风险类别
        for category in medium_risk_categories:
            if category in rule_detections:
                return 'medium'
        
        # 检查敏感数据泄露
        if 'sensitive_data' in rule_detections:
            return 'medium'
        
        # 默认低风险
        return 'low'
    
    def generate_sample_logs(self, num_normal: int = 100, num_malicious: int = 50) -> Tuple[List[str], List[str]]:
        """
        生成样本日志用于训练和测试
        
        Args:
            num_normal: 正常日志数量
            num_malicious: 恶意日志数量
            
        Returns:
            正常日志列表和恶意日志列表
        """
        normal_logs = []
        malicious_logs = []
        
        # 生成正常日志
        normal_templates = [
            "192.168.1.{} - - [10/Oct/2023:13:55:36 +0000] \"GET /api/users HTTP/1.1\" 200 1234",
            "192.168.1.{} - - [10/Oct/2023:13:55:37 +0000] \"POST /api/login HTTP/1.1\" 200 567",
            "192.168.1.{} - - [10/Oct/2023:13:55:38 +0000] \"GET /api/products HTTP/1.1\" 200 8901",
            "192.168.1.{} - - [10/Oct/2023:13:55:39 +0000] \"PUT /api/profile HTTP/1.1\" 200 234",
            "192.168.1.{} - - [10/Oct/2023:13:55:40 +0000] \"DELETE /api/logout HTTP/1.1\" 200 45"
        ]
        
        for i in range(num_normal):
            template = normal_templates[i % len(normal_templates)]
            normal_logs.append(template.format(i % 255))
        
        # 生成恶意日志
        malicious_templates = [
            "192.168.1.{} - - [10/Oct/2023:13:55:36 +0000] \"GET /api/users?id=1' OR '1'='1 HTTP/1.1\" 200 1234",
            "192.168.1.{} - - [10/Oct/2023:13:55:37 +0000] \"POST /api/login HTTP/1.1\" 200 567",
            "192.168.1.{} - - [10/Oct/2023:13:55:38 +0000] \"GET /api/products?q=<script>alert('xss')</script> HTTP/1.1\" 200 8901",
            "192.168.1.{} - - [10/Oct/2023:13:55:39 +0000] \"PUT /api/profile HTTP/1.1\" 200 234",
            "192.168.1.{} - - [10/Oct/2023:13:55:40 +0000] \"GET /api/files?file=../../../etc/passwd HTTP/1.1\" 200 45"
        ]
        
        for i in range(num_malicious):
            template = malicious_templates[i % len(malicious_templates)]
            malicious_logs.append(template.format(i % 255))
        
        return normal_logs, malicious_logs
    
    def train_model(self, normal_logs: List[str], malicious_logs: List[str]) -> None:
        """
        训练机器学习模型
        
        Args:
            normal_logs: 正常日志列表
            malicious_logs: 恶意日志列表
        """
        # 准备训练数据
        X = normal_logs + malicious_logs
        y = [0] * len(normal_logs) + [1] * len(malicious_logs)  # 0: 正常, 1: 恶意
        
        # 预处理文本
        X_processed = [self._preprocess_text(log) for log in X]
        
        # 创建模型管道
        self.model = Pipeline([
            ('tfidf', TfidfVectorizer(max_features=1000, ngram_range=(1, 2))),
            ('classifier', LogisticRegression(random_state=42))
        ])
        
        # 训练模型
        self.model.fit(X_processed, y)
        
        # 保存模型
        self._save_model()
        
        print(f"模型训练完成，训练样本数: {len(X)}")
    
    def evaluate_model(self, normal_logs: List[str], malicious_logs: List[str]) -> Dict[str, Any]:
        """
        评估模型性能
        
        Args:
            normal_logs: 正常日志列表
            malicious_logs: 恶意日志列表
            
        Returns:
            评估结果
        """
        if self.model is None:
            return {"error": "模型未训练"}
        
        # 准备测试数据
        X = normal_logs + malicious_logs
        y = [0] * len(normal_logs) + [1] * len(malicious_logs)
        
        # 预处理文本
        X_processed = [self._preprocess_text(log) for log in X]
        
        # 预测
        y_pred = self.model.predict(X_processed)
        
        # 计算准确率
        accuracy = accuracy_score(y, y_pred)
        
        # 生成分类报告
        report = classification_report(y, y_pred, output_dict=True)
        
        return {
            "accuracy": accuracy,
            "classification_report": report
        }
    
    def _save_model(self) -> None:
        """保存模型到文件"""
        if self.model is None:
            return
        
        try:
            with open(self.model_path, 'wb') as f:
                pickle.dump(self.model, f)
            print(f"模型已保存到 {self.model_path}")
        except Exception as e:
            print(f"保存模型时出错: {e}")
    
    def _load_model(self) -> None:
        """从文件加载模型"""
        try:
            if os.path.exists(self.model_path):
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                print(f"模型已从 {self.model_path} 加载")
        except Exception as e:
            print(f"加载模型时出错: {e}")
            self.model = None