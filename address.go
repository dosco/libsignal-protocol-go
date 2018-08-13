package signal

type Address struct {
	name     string
	deviceID uint32
}

func NewAddress(name string, deviceID uint32) *Address {
	return &Address{
		name:     name,
		deviceID: deviceID,
	}
}

func (a *Address) Name() string {
	return a.name
}

func (a *Address) DeviceID() uint32 {
	return a.deviceID
}
