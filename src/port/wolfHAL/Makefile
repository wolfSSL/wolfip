ROOT = $(CURDIR)/../../..
PORT_DIR = $(ROOT)/src/port/wolfHAL

BOARD_DIR = $(PORT_DIR)/boards/$(BOARD)

ifeq ($(BOARD),)
  ifeq ($(MAKECMDGOALS),clean)
    clean:
	rm -rf build
    .PHONY: clean
  else
    $(error BOARD is required. Usage: make BOARD=stm32h563zi_nucleo)
  endif
else
include $(BOARD_DIR)/board.mk

SOURCE = $(PORT_DIR)/main.c
SOURCE += $(PORT_DIR)/wolfhal_eth.c
SOURCE += $(ROOT)/src/wolfip.c
SOURCE += $(BOARD_SOURCE)

BUILD_DIR = build/$(BOARD)
OBJECTS = $(patsubst %.c,$(BUILD_DIR)/%.o,$(SOURCE))
DEPENDS = $(OBJECTS:.o=.d)

all: $(BUILD_DIR)/app.bin

$(BUILD_DIR)/%.o: %.c Makefile
	@mkdir -p $(dir $@)
	$(GCC) $(CFLAGS) -c -o $@ $<

.SECONDARY:
$(BUILD_DIR)/%.elf: $(OBJECTS) $(LINKER_SCRIPT)
	@mkdir -p $(dir $@)
	$(GCC) $(CFLAGS) $(LDFLAGS) -T $(LINKER_SCRIPT) -o $@ $(OBJECTS) $(LDLIBS)

$(BUILD_DIR)/%.bin: $(BUILD_DIR)/%.elf
	$(OBJCOPY) $^ -O binary $@

.PHONY: clean size
clean:
	rm -rf build

size: $(BUILD_DIR)/app.elf
	$(GCC_PATH)arm-none-eabi-size $<

-include $(DEPENDS)

endif
