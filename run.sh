# Update this file to run your own code

# install dependencies
apt-get update && apt-get install meson ninja libsecp256k1-dev llvm-18 -y

meson wrap install nlohmann_json
meson setup build
cd build

# compile and execute script
ninja SoB
./SoB
