# Update this file to run your own code

# install dependencies
wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && sudo ./llvm.sh 18
sudo apt-get update && sudo apt-get install meson ninja-build libsecp256k1-dev -y

mkdir subprojects
meson wrap install nlohmann_json && meson setup build && cd build && ninja SoB && ./SoB
