#!/bin/bash

# Metis Linux Startup Script
# Fork của MANTIS (https://github.com/fareedfauzi/MANTIS)

echo "Đang khởi động Metis trên Linux..."

# Kiểm tra Python 3
if ! command -v python3 &> /dev/null; then
    echo "Lỗi: python3 chưa được cài đặt. Vui lòng cài Python 3.10+."
    exit 1
fi

# Kiểm tra pip
if ! command -v pip3 &> /dev/null && ! python3 -m pip --version &> /dev/null; then
    echo "Cảnh báo: pip chưa được cài đặt. Cần có pip để cài dependencies."
fi

# Cổng mặc định — override bằng biến môi trường METIS_PORT
METIS_PORT="${METIS_PORT:-${MANTIS_PORT:-9999}}"
METIS_HOST="${METIS_HOST:-${MANTIS_HOST:-127.0.0.1}}"

echo "Đang cài đặt dependencies..."
cd backend || exit

# Kiểm tra nhanh — bỏ qua pip nếu đã có đủ package
if ! python3 -c "import fastapi, uvicorn, requests, pydantic" &>/dev/null; then
    echo "Đang cài packages từ requirements.txt..."
    pip3 install -r requirements.txt
    if [ $? -ne 0 ]; then
        echo "Lỗi: Không thể cài dependencies."
        exit 1
    fi
else
    echo "Dependencies đã có sẵn, bỏ qua bước cài đặt."
fi

# Mở trình duyệt sau 2 giây (không chặn)
(sleep 2 && xdg-open "http://${METIS_HOST}:${METIS_PORT}" 2>/dev/null \
    || open "http://${METIS_HOST}:${METIS_PORT}" 2>/dev/null \
    || echo "Truy cập Metis tại: http://${METIS_HOST}:${METIS_PORT}") &

echo ""
echo "Metis đang chạy tại: http://${METIS_HOST}:${METIS_PORT}"
echo "Nhấn Ctrl+C để dừng."
echo ""

# FastAPI phục vụ cả API lẫn frontend — chỉ cần 1 server duy nhất
# (KHÔNG cần Python HTTP server riêng cho frontend)
if [ -n "$METIS_RELOAD" ] || [ -n "$MANTIS_RELOAD" ]; then
    echo "Chế độ reload bật (dev mode)."
    python3 -m uvicorn main:app --reload --host "$METIS_HOST" --port "$METIS_PORT"
else
    python3 -m uvicorn main:app --host "$METIS_HOST" --port "$METIS_PORT"
fi
