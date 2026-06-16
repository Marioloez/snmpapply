package driver

import "strings"

// All returns every supported driver. Order matters only for tie-breaking in
// detection (none currently tie).
func All() []Driver {
	return []Driver{huawei{}, arubacx{}, arubawc{}, ruckus{}, zyxel{}, cisco{}}
}

// ByName resolves a vendor string (including common aliases) to a driver.
func ByName(name string) (Driver, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "huawei", "vrp", "hw":
		return huawei{}, true
	case "aruba-cx", "arubacx", "aoscx", "aos-cx", "cx":
		return arubacx{}, true
	case "aruba-wc", "arubawc", "procurve", "wc", "hp":
		return arubawc{}, true
	case "ruckus", "icx", "ironware", "brocade", "foundry":
		return ruckus{}, true
	case "zyxel", "zynos":
		return zyxel{}, true
	case "cisco", "ios", "ios-xe", "iosxe", "catalyst":
		return cisco{}, true
	}
	return nil, false
}
