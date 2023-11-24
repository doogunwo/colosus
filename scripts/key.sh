# 패키지 설치 여부 확인
if ! dpkg -l | grep libssl-dev; then
    echo "libssl-dev package not install."
    
    # 패키지 설치
    sudo apt-get update
    sudo apt-get install libssl-dev
else
    echo "libssl-dev package already install."
fi

