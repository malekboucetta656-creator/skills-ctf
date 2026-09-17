#include "flag.h"
#include <zephyr/kernel.h>

int main()
{
    
    for (char* c = flag; *c; c++)
    {
        for (int i = 0; i < 100000; i++)
        {
            __asm volatile ("nop");
        }

        k_sleep(K_MSEC(*c));
    }

    for (int i = 0; i < 100000; i++)
    {
        __asm volatile ("nop");
    }
}
