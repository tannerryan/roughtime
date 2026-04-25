package byteorder

import "encoding/binary"

func LEPutUint16(b []byte, v uint16) {
	binary.LittleEndian.PutUint16(b, v)
}
