CC ?= arm-none-eabi-gcc
OBJCOPY ?= arm-none-eabi-objcopy

ROOT := ../../..

# Base compiler flags — Cortex-M55 soft-float
CFLAGS := -mcpu=cortex-m55 -mthumb -mfloat-abi=soft -Os -ffreestanding -fdata-sections -ffunction-sections
CFLAGS += -g -ggdb -Wall -Wextra -Werror
CFLAGS += -I. -I$(ROOT) -I$(ROOT)/src -I$(ROOT)/src/port -I$(ROOT)/src/port/stm32
CFLAGS += -DSTM32N6 -DTZEN_ENABLED=0
EXTRA_CFLAGS ?=
CFLAGS += $(EXTRA_CFLAGS)

LDSCRIPT := target.ld
LDFLAGS := -nostdlib -T $(LDSCRIPT) -Wl,-gc-sections

# Source files
SRCS := startup.c ivt.c syscalls.c
SRCS += main.c $(ROOT)/src/port/stm32/stm32_eth.c $(ROOT)/src/wolfip.c

OBJS := $(patsubst %.c,%.o,$(SRCS))

all: app.bin
	@echo "Built STM32N6 wolfIP echo server"

app.elf: $(OBJS) $(LDSCRIPT)
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -Wl,--start-group -lc -lm -lgcc -lnosys -Wl,--end-group -o $@

app.bin: app.elf
	$(OBJCOPY) -O binary $< $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o app.elf app.bin
	rm -f $(ROOT)/src/*.o
	rm -f $(ROOT)/src/port/*.o
	rm -f $(ROOT)/src/port/stm32/*.o

size: app.elf
	@echo "=== Memory Usage ==="
	@arm-none-eabi-size app.elf

flash: app.bin
	bash flash.sh

monitor:
	picocom -b 115200 /dev/ttyACM0

debug: app.elf
	openocd -f openocd.cfg &
	arm-none-eabi-gdb app.elf \
		-ex "target remote :3333" \
		-ex "monitor reset init" \
		-ex "load" \
		-ex "monitor mww 0xE000ED08 0x34000000" \
		-ex "break main" \
		-ex "continue"

.PHONY: all clean size flash monitor debug
