CC=arm-none-eabi-gcc
OBJCOPY ?= arm-none-eabi-objcopy

ROOT := ../../..

CFLAGS := -mcpu=cortex-m33 -mthumb -mcmse -Os -ffreestanding -fdata-sections -ffunction-sections
CFLAGS += -g -ggdb -Wall -Wextra -Werror -Wdeclaration-after-statement
CFLAGS += -I. -I$(ROOT) -I$(ROOT)/src
LDFLAGS := -nostdlib -T target.ld -Wl,-gc-sections

SRCS := startup.c ivt.c syscalls.c main.c stm32h5_eth.c $(ROOT)/src/wolfip.c
OBJS := $(patsubst %.c,%.o,$(SRCS))

all: app.bin

app.elf: $(OBJS) target.ld
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -Wl,--start-group -lc -lm -lgcc -lnosys -Wl,--end-group -o $@

app.bin: app.elf
	$(OBJCOPY) -O binary $< $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) app.elf app.bin

.PHONY: all clean
