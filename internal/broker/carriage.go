package broker

// A topic carries the largest record its producers may write, with room for the
// key, the headers and the framing a batch puts around it, and never less than a
// broker takes by default: a smaller batch would only send small records in more
// requests.
const (
	defaultCarriage = 1 << 20
	framing         = 64 << 10
)

func carrying(largest int) int32 {
	return int32(max(defaultCarriage, largest+framing))
}

// A refused record is copied whole, key and value, and the reason travels in
// headers beside it, so a quarantine carries what its stream carries and more.
func quarantining(stream int32) int32 {
	return stream + framing
}
