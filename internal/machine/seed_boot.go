package machine

func (m *Machine) seedBoot(b *builder) {
	p := m.Profile
	b.dir("/boot", 0o755, 0, 0, ageInstall)
	b.dir("/boot/grub", 0o755, 0, 0, ageInstall)
	b.dir("/boot/efi", 0o700, 0, 0, ageInstall)
	b.bin("/boot/vmlinuz-"+p.Kernel, 11534336)
	b.placeholder("/boot/initrd.img-"+p.Kernel, 74184213, "compressed initramfs image", 0o600, 0, 0, ageInstall)
	b.placeholder("/boot/System.map-"+p.Kernel, 8834112, "kernel symbol map", 0o600, 0, 0, ageInstall)
	b.placeholder("/boot/config-"+p.Kernel, 262144, "kernel build config", 0o644, 0, 0, ageInstall)
	b.link("boot/vmlinuz-"+p.Kernel, "/vmlinuz", ageInstall)
	b.link("boot/initrd.img-"+p.Kernel, "/initrd.img", ageInstall)
	b.placeholder("/boot/grub/grub.cfg", 8213, "generated grub.cfg", 0o444, 0, 0, ageInstall)
	b.dir("/boot/grub/x86_64-efi", 0o755, 0, 0, ageInstall)
	b.placeholder("/swap.img", 0, "swap file (empty on this box, swap is off)", 0o600, 0, 0, ageInstall)
}
