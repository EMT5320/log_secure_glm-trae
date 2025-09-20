# 日志风险检测与自动修复系统

## 项目简介

这是一个用于从服务运行日志中检测潜在风险（如SQL注入、敏感信息泄露）并自动触发修复操作的系统。系统具备以下功能：

1. **日志解析器**：从混合格式日志文件中提取关键字段（时间戳、IP地址、请求内容、错误等级）
2. **风险检测模块**：通过规则检测和机器学习检测识别潜在的安全风险
3. **修复与响应**：当检测到风险时，自动触发修复操作并生成告警
4. **系统集成**：提供CLI和REST API接口

## 系统架构

```
日志风险检测与自动修复系统
├── parser.py          # 日志解析器模块
├── detector.py        # 风险检测模块
├── responder.py       # 修复与响应模块
├── main.py            # 主程序和CLI接口
├── api.py             # REST API接口
└── requirements.txt   # 项目依赖
```

## 安装与配置

### 环境要求

- Python 3.7+
- pip

### 安装步骤

1. 克隆或下载项目代码
2. 安装依赖：

```bash
pip install -r requirements.txt
```

## 使用方法

### 命令行界面 (CLI)

#### 1. 处理日志文件

```bash
python main.py process <日志文件路径> [-o <输出文件路径>]
```

示例：

```bash
python main.py process sample.log -o output.json
```

#### 2. 处理日志文本

```bash
python main.py text "<日志文本>"
```

示例：

```bash
python main.py text "192.168.1.1 - - [10/Oct/2023:13:55:36 +0000] \"GET /api/users?id=1' OR '1'='1 HTTP/1.1\" 200 1234"
```

#### 3. 训练机器学习模型

```bash
python main.py train <正常日志文件路径> <恶意日志文件路径>
```

示例：

```bash
python main.py train normal_logs.txt malicious_logs.txt
```

#### 4. 生成样本日志

```bash
python main.py sample <正常日志输出文件路径> <恶意日志输出文件路径> [--num-normal <数量>] [--num-malicious <数量>]
```

示例：

```bash
python main.py sample normal_logs.txt malicious_logs.txt --num-normal 100 --num-malicious 50
```

### REST API

启动API服务器：

```bash
python api.py
```

API将在 `http://localhost:5000` 上运行。

#### API端点

1. **健康检查**

```http
GET /api/health
```

2. **处理日志文件**

```http
POST /api/process/file
Content-Type: multipart/form-data

file: <日志文件>
```

3. **处理日志文本**

```http
POST /api/process/text
Content-Type: application/json

{
  "text": "<日志文本>"
}
```

4. **训练模型**

```http
POST /api/train
Content-Type: multipart/form-data

normal_file: <正常日志文件>
malicious_file: <恶意日志文件>
```

5. **生成样本日志**

```http
POST /api/sample
Content-Type: application/json

{
  "num_normal": 100,
  "num_malicious": 50
}
```

6. **获取告警信息**

```http
GET /api/alerts
```

7. **获取被阻止的IP地址**

```http
GET /api/blocked_ips
```

## 示例输入输出

### 示例输入日志

```
192.168.1.1 - - [10/Oct/2023:13:55:36 +0000] "GET /api/users?id=1' OR '1'='1 HTTP/1.1" 200 1234
192.168.1.2 - - [10/Oct/2023:13:55:37 +0000] "POST /api/login HTTP/1.1" 200 567
192.168.1.3 - - [10/Oct/2023:13:55:38 +0000] "GET /api/products?q=<script>alert('xss')</script> HTTP/1.1" 200 8901
192.168.1.4 - - [10/Oct/2023:13:55:39 +0000] "GET /api/files?file=../../../etc/passwd HTTP/1.1" 200 45
```

### 示例输出

```json
{
  "summary": {
    "total_risks": 3,
    "level_distribution": {
      "high": 2,
      "medium": 1,
      "low": 0
    },
    "action_distribution": {
      "blocked": 2,
      "monitored": 1,
      "logged": 0
    },
    "unique_ips": 3,
    "top_reasons": [
      ["Sql Injection: 1 matches", 1],
      ["Xss: 1 matches", 1],
      ["Path Traversal: 1 matches", 1]
    ]
  },
  "details": [
    {
      "level": "high",
      "ip": "192.168.1.1",
      "action": "blocked",
      "reason": "Sql Injection: 1 matches",
      "timestamp": "2023-10-10T13:55:36",
      "sanitized_content": "192.168.1.1 - - [10/Oct/2023:13:55:36 +0000] \"GET /api/users?id=1' OR '1'='1 HTTP/1.1\" 200 1234",
      "original_content": "192.168.1.1 - - [10/Oct/2023:13:55:36 +0000] \"GET /api/users?id=1' OR '1'='1 HTTP/1.1\" 200 1234",
      "rule_matches": {
        "sql_injection": ["1' OR '1'='1"]
      },
      "ml_prediction": null
    },
    {
      "level": "medium",
      "ip": "192.168.1.3",
      "action": "monitored",
      "reason": "Xss: 1 matches",
      "timestamp": "2023-10-10T13:55:38",
      "sanitized_content": "192.168.1.3 - - [10/Oct/2023:13:55:38 +0000] \"GET /api/products?q=<script>alert('xss')</script> HTTP/1.1\" 200 8901",
      "original_content": "192.168.1.3 - - [10/Oct/2023:13:55:38 +0000] \"GET /api/products?q=<script>alert('xss')</script> HTTP/1.1\" 200 8901",
      "rule_matches": {
        "xss": ["<script>alert('xss')</script>"]
      },
      "ml_prediction": null
    },
    {
      "level": "high",
      "ip": "192.168.1.4",
      "action": "blocked",
      "reason": "Path Traversal: 1 matches",
      "timestamp": "2023-10-10T13:55:39",
      "sanitized_content": "192.168.1.4 - - [10/Oct/2023:13:55:39 +0000] \"GET /api/files?file=../../../etc/passwd HTTP/1.1\" 200 45",
      "original_content": "192.168.1.4 - - [10/Oct/2023:13:55:39 +0000] \"GET /api/files?file=../../../etc/passwd HTTP/1.1\" 200 45",
      "rule_matches": {
        "path_traversal": ["../../../etc/passwd"]
      },
      "ml_prediction": null
    }
  ]
}
```

## 功能模块详解

### 1. 日志解析器 (parser.py)

日志解析器支持多种日志格式：

- **JSON格式**：自动解析JSON格式的日志
- **Apache/Nginx访问日志**：解析标准的Web服务器访问日志
- **带时间戳和IP的通用格式**：提取时间戳和IP地址
- **错误日志格式**：解析带有错误等级的日志
- **通用格式**：对不匹配任何特定格式的日志进行通用解析

解析器会提取以下关键字段：
- 时间戳 (timestamp)
- IP地址 (ip)
- 请求内容 (content)
- 错误等级 (level)

### 2. 风险检测模块 (detector.py)

风险检测模块使用两种方法检测潜在风险：

#### 规则检测

基于预定义的正则表达式模式检测以下风险类型：
- **SQL注入**：检测SQL注入攻击模式
- **XSS攻击**：检测跨站脚本攻击模式
- **敏感数据泄露**：检测邮箱、手机号、身份证号等敏感信息
- **路径遍历**：检测目录遍历攻击模式
- **命令注入**：检测命令注入攻击模式

#### 机器学习检测

使用TF-IDF + Logistic Regression模型区分"正常请求"和"恶意请求"：
- 文本预处理：转换为小写、移除特殊字符、标准化空格
- 特征提取：使用TF-IDF向量化器提取文本特征
- 分类：使用逻辑回归分类器进行分类

### 3. 修复与响应模块 (responder.py)

当检测到风险时，系统会执行以下操作：

#### 敏感信息修复

自动替换日志中的敏感字段：
- 邮箱地址 → ***@***.***
- 手机号 → 1**********
- 身份证号 → ***********
- 信用卡号 → ****-****-****-****
- 密码、令牌、用户名 → ***

#### 告警生成

生成JSON格式的告警信息：

```json
{
  "level": "high",
  "ip": "192.168.0.1",
  "action": "blocked",
  "reason": "SQL Injection"
}
```

#### 风险等级和响应动作

根据风险类型和严重程度，系统会分配不同的风险等级和响应动作：

- **高风险**：SQL注入、命令注入、路径遍历 → 阻止 (blocked)
- **中风险**：XSS攻击、敏感数据泄露 → 监控 (monitored)
- **低风险**：其他风险 → 记录 (logged)

## 扩展功能

### 添加新的风险检测规则

在 `detector.py` 文件中的 `malicious_patterns` 字典中添加新的正则表达式模式：

```python
self.malicious_patterns['new_risk_type'] = [
    r'pattern1',
    r'pattern2',
    # 更多模式...
]
```

### 添加新的敏感信息类型

在 `responder.py` 文件中的 `sensitive_patterns` 字典中添加新的正则表达式模式：

```python
self.sensitive_patterns['new_sensitive_type'] = re.compile(r'pattern')
```

### 自定义响应动作

在 `responder.py` 文件中的 `response_actions` 字典中添加新的响应动作：

```python
self.response_actions['new_level'] = 'new_action'
```

## 性能优化

1. **批量处理**：系统支持批量处理日志文件，提高处理效率
2. **模型缓存**：机器学习模型会被缓存，避免重复训练
3. **正则表达式预编译**：所有正则表达式在初始化时预编译，提高匹配速度

## 注意事项

1. 系统需要足够的内存来处理大型日志文件
2. 机器学习模型的准确性取决于训练数据的质量和数量
3. 在生产环境中使用前，建议先在测试环境中验证系统的性能和准确性
4. 系统目前不支持实时日志流处理，需要离线处理日志文件

## 许可证

本项目采用MIT许可证。详情请参阅LICENSE文件。

## 贡献

欢迎提交问题和拉取请求来改进这个项目。

## 联系方式

如有问题或建议，请通过以下方式联系：

- 邮箱：your.email@example.com
- GitHub Issues：[项目Issues页面]