package injector

// AdmissionError is a bounded field-specific admission failure.
type AdmissionError struct {
	Field  string
	Reason string
}

func (e AdmissionError) Error() string { return e.Field + ": " + e.Reason }
