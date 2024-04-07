# Update this file to run your own code

# install dependencies
meson setup build
meson wrap install nlohmann_json
cd build

# compile and execute script
ninja SoB
./SoB
