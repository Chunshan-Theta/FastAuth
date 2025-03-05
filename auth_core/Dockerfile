# 使用官方 Python 3.11 映像
FROM python:3.11

# 設定工作目錄
WORKDIR /app

# 複製 requirements.txt 並安裝依賴
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 複製專案所有文件
COPY . .

# 設定環境變數（避免 Python 產生緩存文件）
ENV PYTHONUNBUFFERED=1

# 啟動 FastAPI 應用
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
