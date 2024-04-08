# Update this file to run your own code

# install dependencies
sudo add-apt-repository ppa:ubuntu-toolchain-r/test && sudo apt-get update && sudo apt-get install gcc-13 g++-13 -y
sudo apt-get install meson ninja-build libsecp256k1-dev -y

mkdir subprojects
meson wrap install nlohmann_json && meson setup build && cd build && ninja SoB && ./SoB
