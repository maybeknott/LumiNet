package system

import (
	"os"
	"runtime"
	"strings"
)

// IsRunningInVM checks if the application is running inside a Virtual Machine or Emulator.
// It uses file, device, and directory markers across Linux/Android and Windows guest drivers.
func IsRunningInVM() bool {
	switch runtime.GOOS {
	case "windows":
		return isVMWindows()
	case "linux", "android":
		return isVMLinux()
	default:
		return false
	}
}

func isVMLinux() bool {
	// 1. Check DMI product name
	if data, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
		name := strings.ToLower(string(data))
		for _, vm := range []string{"virtualbox", "vmware", "kvm", "qemu", "xen", "hyper-v"} {
			if strings.Contains(name, vm) {
				return true
			}
		}
	}

	// 2. Check DMI sys vendor
	if data, err := os.ReadFile("/sys/class/dmi/id/sys_vendor"); err == nil {
		vendor := strings.ToLower(string(data))
		for _, vm := range []string{"qemu", "oracle", "vmware", "xen"} {
			if strings.Contains(vendor, vm) {
				return true
			}
		}
	}

	// 3. Check cpuinfo for hypervisor flag
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		if strings.Contains(string(data), "hypervisor") {
			return true
		}
	}

	// 4. Android Emulator detection checks (goldfish/qemu)
	for _, dev := range []string{"/dev/socket/qemud", "/dev/qemu_pipe"} {
		if _, err := os.Stat(dev); err == nil {
			return true
		}
	}

	return false
}

func isVMWindows() bool {
	// Check common VM guest driver files
	vmDrivers := []string{
		`C:\Windows\System32\drivers\VBoxMouse.sys`,
		`C:\Windows\System32\drivers\VBoxGuest.sys`,
		`C:\Windows\System32\drivers\vmmouse.sys`,
		`C:\Windows\System32\drivers\vboxsf.sys`,
		`C:\Windows\System32\drivers\vboxvideo.sys`,
	}

	for _, driver := range vmDrivers {
		if _, err := os.Stat(driver); err == nil {
			return true
		}
	}
	return false
}
