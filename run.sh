# Update this file to run your own code

# install dependencies
wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && sudo ./llvm.sh 18
sudo apt-get install libc++-18-dev
python3 -mpip install meson==1.4.0 ninja
sudo apt-get install libsecp256k1-dev -y
git submodule update --init
mkdir subprojects
meson wrap install nlohmann_json

CXX=clang++-18 CC=clang-18 meson setup build && cd build && ninja SoB && ./SoB
