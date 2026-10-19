package scenario

import "time"

// UploadSettle is how long get_upload_info is asked again.
func UploadSettle() time.Duration { return uploadSettle }

// SetUploadSettle sets how long get_upload_info is asked again, for the
// external tests, and returns a function that restores it.
func SetUploadSettle(d time.Duration) (restore func()) {
	old := uploadSettle
	uploadSettle = d
	return func() { uploadSettle = old }
}
