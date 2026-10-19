package scenario

import "time"

// UploadSettle is the default for how long get_upload_info is asked again,
// when Config.UploadSettle is zero.
func UploadSettle() time.Duration { return uploadSettle }
