## wolfIP demo on raspberry pi pico

### Instructions

- clone pico-sdk

`git clone https://github.com/raspberrypi/pico-sdk.git`

- run CMake from this directory, specitying the FAMILY and PICO_COMPILER variables. Also specify the path where you cloned the pico-sdk in the previous step.

cmake . -DPICO_SDK_PATH=/path/to/src/pico-sdk -DFAMILY=rp2040 -DPICO_COMPILER=arm-none-eabi-gcc

- run make

`make`

- copy the uf2 file to the pico

`cp raspberrypi-pico-usb-server.uf2 /media/$USER/RPI-RP2`

- Assign a static IP to the usb0 interface on the host machine

`sudo ip addr add usb0 192.168.7.1/24`

- Ping the pico board!

`ping 192.168.7.2`


