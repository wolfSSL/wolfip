# wolfIP for STM32 Cube IDE

The wolfIP Cube Pack can be found [here](https://www.wolfssl.com/files/ide/I-CUBE-wolfIP.pack).

1. If you intend to use TLS with wolfIP, the first step is to set up the wolfSSL library in your ST project following the guide here [https://github.com/wolfSSL/wolfssl/blob/master/IDE/STM32Cube/README.md](https://github.com/wolfSSL/wolfssl/blob/master/IDE/STM32Cube/README.md). If not, skip to the next step.

2. Install the wolfIP Cube Pack with the steps below.
    - Run the "STM32CubeMX" tool.
    - Under "Manage software installations" pane on the right, click "INSTALL/REMOVE" button.
    - From Local and choose "I-CUBE-wolfIP.pack".
    - Accept the GPLv3 license. Contact wolfSSL at sales@wolfssl.com for a commercial license and support/maintenance.

3. Create an STM32 project for your board and open the `.ioc` file. Click the `Software Packs` drop down menu and then `Select Components`. Expand the `wolfIP` pack and check the Core component. If you need the embedded HTTP server, check the HTTP component as well. If you intend to use TLS with wolfIP, check the wolfSSL-IO component. This will enforce the dependency to wolfSSL.

4. In the `Software Packs` configuration category of the `.ioc` file, click on the wolfIP pack and enable the library by checking the box.

5. Configure the wolfIP settings in the `.ioc` file as needed (DHCP, DNS, socket pool sizes, MTU, etc.).

6. Save your changes and select yes to the prompt asking about generating code.

7. Build the project.

## Notes
- wolfIP uses zero dynamic memory allocation - all sockets and buffers are pre-allocated at compile time.
- See `src/port/stm32h563/` for a complete bare-metal example targeting the STM32H563 microcontroller.
- For questions please email support@wolfssl.com
