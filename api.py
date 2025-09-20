#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
日志风险检测与自动修复系统 REST API
提供简单的HTTP接口用于日志处理
"""

from flask import Flask, request, jsonify, send_file
import os
import tempfile
import json
from typing import Dict, Any, Optional

from main import LogSecuritySystem


app = Flask(__name__)
system = LogSecuritySystem()


@app.route('/api/health', methods=['GET'])
def health_check():
    """健康检查接口"""
    return jsonify({
        "status": "healthy",
        "service": "Log Security System"
    })


@app.route('/api/process/file', methods=['POST'])
def process_log_file():
    """处理日志文件接口"""
    try:
        # 检查是否有文件上传
        if 'file' not in request.files:
            return jsonify({"error": "没有上传文件"}), 400
        
        file = request.files['file']
        
        # 检查文件名
        if file.filename == '':
            return jsonify({"error": "没有选择文件"}), 400
        
        # 保存上传的文件到临时文件
        with tempfile.NamedTemporaryFile(delete=False, suffix='.log') as temp_file:
            file.save(temp_file.name)
            temp_file_path = temp_file.name
        
        try:
            # 处理日志文件
            result = system.process_log_file(temp_file_path)
            return jsonify(result)
        finally:
            # 删除临时文件
            os.unlink(temp_file_path)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/process/text', methods=['POST'])
def process_log_text():
    """处理日志文本接口"""
    try:
        data = request.get_json()
        
        if not data or 'text' not in data:
            return jsonify({"error": "缺少日志文本"}), 400
        
        log_text = data['text']
        
        # 处理日志文本
        result = system.process_log_text(log_text)
        return jsonify(result)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/train', methods=['POST'])
def train_model():
    """训练模型接口"""
    try:
        # 检查是否有文件上传
        if 'normal_file' not in request.files or 'malicious_file' not in request.files:
            return jsonify({"error": "需要上传正常日志文件和恶意日志文件"}), 400
        
        normal_file = request.files['normal_file']
        malicious_file = request.files['malicious_file']
        
        # 检查文件名
        if normal_file.filename == '' or malicious_file.filename == '':
            return jsonify({"error": "没有选择文件"}), 400
        
        # 保存上传的文件到临时文件
        with tempfile.NamedTemporaryFile(delete=False, suffix='.log') as temp_normal:
            normal_file.save(temp_normal.name)
            normal_file_path = temp_normal.name
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.log') as temp_malicious:
            malicious_file.save(temp_malicious.name)
            malicious_file_path = temp_malicious.name
        
        try:
            # 训练模型
            result = system.train_model(normal_file_path, malicious_file_path)
            return jsonify(result)
        finally:
            # 删除临时文件
            os.unlink(normal_file_path)
            os.unlink(malicious_file_path)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/sample', methods=['POST'])
def generate_sample_logs():
    """生成样本日志接口"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "缺少请求参数"}), 400
        
        num_normal = data.get('num_normal', 100)
        num_malicious = data.get('num_malicious', 50)
        
        # 创建临时文件
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as temp_normal:
            normal_file_path = temp_normal.name
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as temp_malicious:
            malicious_file_path = temp_malicious.name
        
        try:
            # 生成样本日志
            result = system.generate_sample_logs(
                normal_file_path, malicious_file_path,
                num_normal, num_malicious
            )
            
            # 读取生成的日志文件内容
            with open(normal_file_path, 'r', encoding='utf-8') as f:
                normal_logs = f.read().splitlines()
            
            with open(malicious_file_path, 'r', encoding='utf-8') as f:
                malicious_logs = f.read().splitlines()
            
            # 添加日志内容到结果中
            result['normal_logs'] = normal_logs[:10]  # 只返回前10条作为示例
            result['malicious_logs'] = malicious_logs[:10]  # 只返回前10条作为示例
            
            return jsonify(result)
        finally:
            # 删除临时文件
            os.unlink(normal_file_path)
            os.unlink(malicious_file_path)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """获取告警信息接口"""
    try:
        # 这里可以从数据库或文件中获取历史告警信息
        # 为了简单起见，我们返回一个空列表
        return jsonify({
            "alerts": [],
            "message": "此接口需要实现持久化存储"
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/blocked_ips', methods=['GET'])
def get_blocked_ips():
    """获取被阻止的IP地址列表接口"""
    try:
        # 这里可以从数据库或文件中获取被阻止的IP地址
        # 为了简单起见，我们返回一个空列表
        return jsonify({
            "blocked_ips": [],
            "message": "此接口需要实现持久化存储"
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.errorhandler(404)
def not_found(error):
    """404错误处理"""
    return jsonify({"error": "接口不存在"}), 404


@app.errorhandler(500)
def internal_error(error):
    """500错误处理"""
    return jsonify({"error": "服务器内部错误"}), 500


if __name__ == '__main__':
    # 创建必要的目录
    os.makedirs('uploads', exist_ok=True)
    os.makedirs('outputs', exist_ok=True)
    
    # 启动Flask应用
    app.run(host='0.0.0.0', port=5000, debug=True)