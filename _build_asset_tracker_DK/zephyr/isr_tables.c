
/* AUTO-GENERATED by gen_isr_tables.py, do not edit! */

#include <toolchain.h>
#include <linker/sections.h>
#include <sw_isr_table.h>
#include <arch/cpu.h>

#if defined(CONFIG_GEN_SW_ISR_TABLE) && defined(CONFIG_GEN_IRQ_VECTOR_TABLE)
#define ISR_WRAPPER ((u32_t)&_isr_wrapper)
#else
#define ISR_WRAPPER NULL
#endif

u32_t __irq_vector_table _irq_vector_table[65] = {
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	141209,
	261049,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	261083,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
	ISR_WRAPPER,
};
struct _isr_table_entry __sw_isr_table _sw_isr_table[65] = {
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)0x1f765},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x200314e4, (void *)0x3f85b},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)0x1f7e5},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)0x2181d},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
	{(void *)0x0, (void *)&z_irq_spurious},
};
