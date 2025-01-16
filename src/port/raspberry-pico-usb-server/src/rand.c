/* rand.c
 *
 * Copyright (C) 2024 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 *
 * wolfIP is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfIP is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */
#include "pico/stdlib.h"
#include "hardware/gpio.h"
#include "hardware/adc.h"
#include <string.h>


#define IN3_PIN 29
#define IN0_PIN 28
#define IN1_PIN 27
#define IN2_PIN 26

const uint32_t IN[4] = {IN0_PIN, IN1_PIN, IN2_PIN, IN3_PIN};
static int adc_initialized = 0;

const int in_a[8] = { 0, 1, 2, 3, 1, 3, 0, 2 };

int custom_random_seed(unsigned char *output, unsigned int sz) {
    uint32_t i;
    uint32_t result = 0;
    uint32_t rd = 0, wsz;

    if (!adc_initialized) {
        adc_init();
        for (i = 0; i < 4; i++) {
            adc_gpio_init(IN[i]);
        }
        adc_initialized = 1;
        sleep_ms(10);
    }

    /* Perform eight 3-bit samples with sources 0-1-2-4 */
    for (i = 0; rd < sz; i = (i + 1) % 8) {
        adc_select_input(in_a[i]);

        /* Read the least significant 3 bits from the ADC */
        result = (result << 3) | (adc_read() & 0x00000007);

        /* Introduce a delay to capture environmental noise */
        sleep_ms(1);

        /* If we've completed eight samples, copy the result to the output */
        if (i == 7) {
            wsz = 3;
            if (wsz > (sz - rd)) {
                wsz = sz - rd;
            }

            memcpy(output + rd, &result, wsz);
            rd += wsz;
            result = 0;
        }
    }

    return 0;
}
