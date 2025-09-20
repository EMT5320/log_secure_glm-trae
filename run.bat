@echo off
echo 日志风险检测与自动修复系统
echo =============================

echo 检查Python环境...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo 错误: 未找到Python，请确保已安装Python并添加到PATH环境变量中
    pause
    exit /b 1
)

echo 检查依赖库...
pip show scikit-learn >nul 2>&1
if %errorlevel% neq 0 (
    echo 正在安装依赖库...
    pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo 错误: 安装依赖库失败
        pause
        exit /b 1
    )
)

echo.
echo 选择操作:
echo 1. 运行测试
echo 2. 处理示例日志文件
echo 3. 启动API服务器
echo 4. 生成样本日志
echo 5. 训练机器学习模型
echo 6. 退出
echo.

set /p choice=请输入选项 (1-6): 

if "%choice%"=="1" (
    echo 运行测试...
    python test_system.py
    pause
) else if "%choice%"=="2" (
    echo 处理示例日志文件...
    if exist sample_logs.txt (
        python main.py process sample_logs.txt -o output.json
        echo.
        echo 处理结果已保存到 output.json
    ) else (
        echo 错误: 未找到示例日志文件 sample_logs.txt
    )
    pause
) else if "%choice%"=="3" (
    echo 启动API服务器...
    echo API服务器将在 http://localhost:5000 上运行
    echo 按 Ctrl+C 停止服务器
    echo.
    python api.py
    pause
) else if "%choice%"=="4" (
    echo 生成样本日志...
    python main.py sample normal_logs.txt malicious_logs.txt
    echo.
    echo 正常日志已保存到 normal_logs.txt
    echo 恶意日志已保存到 malicious_logs.txt
    pause
) else if "%choice%"=="5" (
    echo 训练机器学习模型...
    if exist normal_logs.txt (
        if exist malicious_logs.txt (
            python main.py train normal_logs.txt malicious_logs.txt
        ) else (
            echo 错误: 未找到恶意日志文件 malicious_logs.txt
            echo 请先生成样本日志
        )
    ) else (
        echo 错误: 未找到正常日志文件 normal_logs.txt
        echo 请先生成样本日志
    )
    pause
) else if "%choice%"=="6" (
    echo 退出
    exit /b 0
) else (
    echo 无效选项
    pause
)