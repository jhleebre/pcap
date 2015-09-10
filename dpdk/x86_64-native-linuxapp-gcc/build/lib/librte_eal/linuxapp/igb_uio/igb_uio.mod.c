#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x2b22e0c3, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x5d41c87c, __VMLINUX_SYMBOL_STR(param_ops_charp) },
	{ 0xbc3abb13, __VMLINUX_SYMBOL_STR(pci_unregister_driver) },
	{ 0x62d3fd3f, __VMLINUX_SYMBOL_STR(__pci_register_driver) },
	{ 0xe2d5255a, __VMLINUX_SYMBOL_STR(strcmp) },
	{ 0x5721e571, __VMLINUX_SYMBOL_STR(__dynamic_dev_dbg) },
	{ 0x8028e5a5, __VMLINUX_SYMBOL_STR(_dev_info) },
	{ 0xee7ad01b, __VMLINUX_SYMBOL_STR(dev_notice) },
	{ 0x446526d2, __VMLINUX_SYMBOL_STR(pci_intx_mask_supported) },
	{ 0xd977fe00, __VMLINUX_SYMBOL_STR(__uio_register_device) },
	{ 0xb2711b8f, __VMLINUX_SYMBOL_STR(sysfs_create_group) },
	{ 0xb9bdfb84, __VMLINUX_SYMBOL_STR(pci_enable_msix) },
	{ 0xcfc62f27, __VMLINUX_SYMBOL_STR(xen_start_info) },
	{ 0x731dba7a, __VMLINUX_SYMBOL_STR(xen_domain_type) },
	{ 0x7e865717, __VMLINUX_SYMBOL_STR(dma_supported) },
	{ 0x42c8de35, __VMLINUX_SYMBOL_STR(ioremap_nocache) },
	{ 0x4bd6495f, __VMLINUX_SYMBOL_STR(dma_set_mask) },
	{ 0x1a65896c, __VMLINUX_SYMBOL_STR(pci_set_master) },
	{ 0x4ec76535, __VMLINUX_SYMBOL_STR(dev_err) },
	{ 0xaa21e909, __VMLINUX_SYMBOL_STR(pci_request_regions) },
	{ 0xe80ed784, __VMLINUX_SYMBOL_STR(pci_enable_device) },
	{ 0xb153f6c5, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0x2b056eed, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0xfeb28ae8, __VMLINUX_SYMBOL_STR(pci_check_and_mask_intx) },
	{ 0x461c507e, __VMLINUX_SYMBOL_STR(pci_intx) },
	{ 0x82745c2, __VMLINUX_SYMBOL_STR(pci_cfg_access_unlock) },
	{ 0x449242e1, __VMLINUX_SYMBOL_STR(pci_cfg_access_lock) },
	{ 0xddd92967, __VMLINUX_SYMBOL_STR(remap_pfn_range) },
	{ 0xc715d9e0, __VMLINUX_SYMBOL_STR(boot_cpu_data) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x8eff6ef2, __VMLINUX_SYMBOL_STR(pci_disable_msix) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0xace1a41b, __VMLINUX_SYMBOL_STR(dev_set_drvdata) },
	{ 0xa6a7d28, __VMLINUX_SYMBOL_STR(pci_disable_device) },
	{ 0xeb831f3a, __VMLINUX_SYMBOL_STR(pci_release_regions) },
	{ 0xf53725ee, __VMLINUX_SYMBOL_STR(uio_unregister_device) },
	{ 0x8a662e1b, __VMLINUX_SYMBOL_STR(sysfs_remove_group) },
	{ 0xdc0accc3, __VMLINUX_SYMBOL_STR(dev_get_drvdata) },
	{ 0xedc03953, __VMLINUX_SYMBOL_STR(iounmap) },
	{ 0x28318305, __VMLINUX_SYMBOL_STR(snprintf) },
	{ 0x7f483245, __VMLINUX_SYMBOL_STR(pci_enable_sriov) },
	{ 0xfa45ccbe, __VMLINUX_SYMBOL_STR(pci_num_vf) },
	{ 0x4ebb8b82, __VMLINUX_SYMBOL_STR(pci_disable_sriov) },
	{ 0x3c80c06c, __VMLINUX_SYMBOL_STR(kstrtoull) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=uio";


MODULE_INFO(srcversion, "CA181C4E966FF7974598041");
