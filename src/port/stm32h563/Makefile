CC=arm-none-eabi-gcc
OBJCOPY ?= arm-none-eabi-objcopy

ROOT := ../../..

# TrustZone support: set TZEN=1 for TrustZone enabled builds
# Default is TZEN=0 (TrustZone disabled)
TZEN ?= 0

CFLAGS := -mcpu=cortex-m33 -mthumb -mcmse -Os -ffreestanding -fdata-sections -ffunction-sections
CFLAGS += -g -ggdb -Wall -Wextra -Werror -Wdeclaration-after-statement
CFLAGS += -I. -I$(ROOT) -I$(ROOT)/src

# Select linker script based on TZEN setting
ifeq ($(TZEN),1)
  LDSCRIPT := target_tzen.ld
  CFLAGS += -DTZEN_ENABLED=1
else
  LDSCRIPT := target.ld
  CFLAGS += -DTZEN_ENABLED=0
endif

LDFLAGS := -nostdlib -T $(LDSCRIPT) -Wl,-gc-sections

SRCS := startup.c ivt.c syscalls.c main.c stm32h5_eth.c $(ROOT)/src/wolfip.c
OBJS := $(patsubst %.c,%.o,$(SRCS))

all: app.bin
	@echo "Built with TZEN=$(TZEN) using $(LDSCRIPT)"

app.elf: $(OBJS) $(LDSCRIPT)
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -Wl,--start-group -lc -lm -lgcc -lnosys -Wl,--end-group -o $@

app.bin: app.elf
	$(OBJCOPY) -O binary $< $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) app.elf app.bin

.PHONY: all clean
