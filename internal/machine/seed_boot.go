package machine

func (m *Machine) seedBoot(b *builder) {
	p := m.Profile
	ref := reference()
	b.dir("/boot", 0o755, 0, 0, ageInstall)
	b.dir("/boot/grub", 0o755, 0, 0, ageInstall)
	b.dir("/boot/efi", 0o700, 0, 0, ageInstall)
	b.bin("/boot/vmlinuz-"+p.Kernel, ref.sizes["vmlinuz-"+p.Kernel])
	b.fail(b.fs.Chmod("/boot/vmlinuz-"+p.Kernel, 0o600))
	// the initramfs is a compressed cpio archive: binary on the terminal
	b.bin("/boot/initrd.img-"+p.Kernel, ref.sizes["initrd.img-"+p.Kernel])
	b.fail(b.fs.Chmod("/boot/initrd.img-"+p.Kernel, 0o644))
	b.file("/boot/System.map-"+p.Kernel, string(refFile("kernel-system-map")), 0o600, 0, 0, ageInstall)
	b.file("/boot/config-"+p.Kernel, string(refFile("kernel-config")), 0o644, 0, 0, ageInstall)
	b.link("boot/vmlinuz-"+p.Kernel, "/vmlinuz", ageInstall)
	b.link("boot/initrd.img-"+p.Kernel, "/initrd.img", ageInstall)
	b.file("/boot/grub/grub.cfg", m.grubCfg(), 0o444, 0, 0, ageInstall)
	b.dir("/boot/grub/x86_64-efi", 0o755, 0, 0, ageInstall)
	// swap is off on this box, but the installer's swap file is still there
	b.file("/swap.img", "", 0o600, 0, 0, ageInstall)
}
