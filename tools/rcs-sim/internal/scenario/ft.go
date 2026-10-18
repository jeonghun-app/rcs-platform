package scenario

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/ft"
)

// thumbnailSize is the size of the thumbnail the ft scenario sends.
const thumbnailSize = 2 << 10

// uploadSettle is how long a broken upload may take to show in
// get_upload_info.
const uploadSettle = 3 * time.Second

// maxResumeAttempts bounds the PUTs the resume step sends while the server
// is still storing what it got of the broken upload.
const maxResumeAttempts = 10

// newTID returns a transfer id: 128 random bits, hex.
func (r *run) newTID() (string, error) {
	b, err := r.content(16)
	if err != nil {
		return "", err
	}
	return "sim-" + hex.EncodeToString(b), nil
}

var errNoFTClient = errors.New("no file transfer client configured (-ft-upload-url, -ft-user, RCS_SIM_FT_PASSWORD)")

// fileTransfer is an upload with a thumbnail, then every way a recipient
// fetches it: get_download_info, the whole file, a range, the thumbnail.
// Content is checked by SHA-256 end to end, against the server's ETag too.
func fileTransfer(r *run) error {
	c := r.cfg.FT
	var (
		up  ft.Upload
		doc ft.FileDocument
	)
	if err := r.step("pre-check", func(ctx context.Context) (map[string]int64, error) {
		if c == nil {
			return nil, errNoFTClient
		}
		return nil, c.Precheck(ctx)
	}); err != nil {
		return err
	}
	if err := r.step("upload", func(ctx context.Context) (map[string]int64, error) {
		tid, err := r.newTID()
		if err != nil {
			return nil, err
		}
		data, err := r.content(r.cfg.FileSize)
		if err != nil {
			return nil, err
		}
		thumb, err := r.content(thumbnailSize)
		if err != nil {
			return nil, err
		}
		up = ft.Upload{TID: tid, Name: "photo 1.jpg", ContentType: "image/jpeg", Data: data, Thumbnail: thumb, ThumbnailType: "image/jpeg"}
		doc, err = c.Send(ctx, up)
		if err != nil {
			return nil, err
		}
		return map[string]int64{"bytes": int64(len(data))}, checkDocument(doc, up)
	}); err != nil {
		return err
	}
	if err := r.step("get_download_info", func(ctx context.Context) (map[string]int64, error) {
		again, err := c.DownloadInfo(ctx, up.TID)
		if err != nil {
			return nil, err
		}
		if err := checkDocument(again, up); err != nil {
			return nil, err
		}
		file, _ := again.Info("file")
		first, _ := doc.Info("file")
		if file.Data.URL != first.Data.URL {
			return nil, errors.New("get_download_info names another download link than the upload's answer")
		}
		return nil, nil
	}); err != nil {
		return err
	}
	file, _ := doc.Info("file")
	if err := r.step("download", func(ctx context.Context) (map[string]int64, error) {
		got, err := c.Download(ctx, file.Data.URL, ft.Range{}, int64(len(up.Data)))
		if err != nil {
			return nil, err
		}
		if got.Status != http.StatusOK {
			return nil, fmt.Errorf("download answered %d, want 200", got.Status)
		}
		if err := sameContent(got.Body, up.Data); err != nil {
			return nil, err
		}
		if strings.Trim(got.ETag, `"`) != ft.SHA256(up.Data) {
			return nil, errors.New("the ETag is not the SHA-256 of the content")
		}
		return map[string]int64{"bytes": int64(len(got.Body))}, nil
	}); err != nil {
		return err
	}
	if err := r.step("download-range", func(ctx context.Context) (map[string]int64, error) {
		first, last := int64(len(up.Data)/3), int64(len(up.Data)/3*2)
		got, err := c.Download(ctx, file.Data.URL, ft.Range{First: first, Last: last}, last-first+1)
		if err != nil {
			return nil, err
		}
		if got.Status != http.StatusPartialContent {
			return nil, fmt.Errorf("range download answered %d, want 206", got.Status)
		}
		return map[string]int64{"bytes": int64(len(got.Body))}, sameContent(got.Body, up.Data[first:last+1])
	}); err != nil {
		return err
	}
	return r.step("download-thumbnail", func(ctx context.Context) (map[string]int64, error) {
		thumb, _ := doc.Info("thumbnail")
		got, err := c.Download(ctx, thumb.Data.URL, ft.Range{}, int64(len(up.Thumbnail)))
		if err != nil {
			return nil, err
		}
		return nil, sameContent(got.Body, up.Thumbnail)
	})
}

// fileTransferResumed breaks an upload part-way, as a phone changing
// networks does, and resumes it the way rcsjta does: get_upload_info, a PUT
// of the rest with Content-Range, get_download_info, then the download.
func fileTransferResumed(r *run) error {
	c := r.cfg.FT
	var (
		up   ft.Upload
		info ft.ResumeDocument
		doc  ft.FileDocument
	)
	if err := r.step("pre-check", func(ctx context.Context) (map[string]int64, error) {
		if c == nil {
			return nil, errNoFTClient
		}
		return nil, c.Precheck(ctx)
	}); err != nil {
		return err
	}
	if err := r.step("interrupted-upload", func(ctx context.Context) (map[string]int64, error) {
		tid, err := r.newTID()
		if err != nil {
			return nil, err
		}
		data, err := r.content(r.cfg.ResumeSize)
		if err != nil {
			return nil, err
		}
		up = ft.Upload{TID: tid, Name: "video.mp4", ContentType: "video/mp4", Data: data}
		// Break it near the end, so that every whole part is stored.
		cut := len(data) - len(data)/10
		return map[string]int64{"sent": int64(cut)}, c.SendInterrupted(ctx, up, cut)
	}); err != nil {
		return err
	}
	if err := r.step("get_upload_info", func(ctx context.Context) (map[string]int64, error) {
		// The server stores what arrived only once it notices the break,
		// which can be just after the simulator asks; a 404 is therefore
		// asked again for a moment before it counts.
		settle := time.Now().Add(uploadSettle)
		var err error
		for {
			info, err = c.UploadInfo(ctx, up.TID)
			if !errors.Is(err, ft.ErrNothingHeld) || time.Now().After(settle) {
				break
			}
			select {
			case <-time.After(50 * time.Millisecond):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if errors.Is(err, ft.ErrNothingHeld) {
			return nil, errors.New("the server holds nothing; the file must be larger than FT_PART_SIZE")
		}
		if err != nil {
			return nil, err
		}
		held, _ := info.Held()
		if held >= int64(len(up.Data)) {
			return nil, errors.New("the server holds the whole file of a broken upload")
		}
		return map[string]int64{"held": held}, nil
	}); err != nil {
		return err
	}
	if err := r.step("resume", func(ctx context.Context) (map[string]int64, error) {
		var err error
		for attempt := 1; ; attempt++ {
			doc, err = c.Resume(ctx, info, up.ContentType, up.Data)
			if !ft.IsStatus(err, http.StatusConflict) || attempt == maxResumeAttempts {
				break
			}
			// The server stored more of the broken upload after it
			// answered get_upload_info, being still busy with the break;
			// ask again, as rcsjta does on 409.
			select {
			case <-time.After(50 * time.Millisecond):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			if info, err = c.UploadInfo(ctx, up.TID); err != nil {
				break
			}
		}
		if err != nil {
			return nil, err
		}
		held, _ := info.Held()
		return map[string]int64{"bytes": int64(len(up.Data)) - held}, checkDocument(doc, up)
	}); err != nil {
		return err
	}
	if err := r.step("get_download_info", func(ctx context.Context) (map[string]int64, error) {
		again, err := c.DownloadInfo(ctx, up.TID)
		if err != nil {
			return nil, err
		}
		return nil, checkDocument(again, up)
	}); err != nil {
		return err
	}
	return r.step("download", func(ctx context.Context) (map[string]int64, error) {
		file, _ := doc.Info("file")
		got, err := c.Download(ctx, file.Data.URL, ft.Range{}, int64(len(up.Data)))
		if err != nil {
			return nil, err
		}
		if strings.Trim(got.ETag, `"`) != ft.SHA256(up.Data) {
			return nil, errors.New("the ETag is not the SHA-256 of the content")
		}
		return map[string]int64{"bytes": int64(len(got.Body))}, sameContent(got.Body, up.Data)
	})
}

// checkDocument checks a file-info document against what was uploaded.
func checkDocument(d ft.FileDocument, up ft.Upload) error {
	file, ok := d.Info("file")
	switch {
	case !ok:
		return errors.New("no file-info for the file")
	case file.Size != int64(len(up.Data)):
		return fmt.Errorf("file-size %d, want %d", file.Size, len(up.Data))
	case file.ContentType != up.ContentType:
		return errors.New("content-type differs from the upload's")
	case file.Data.URL == "" || file.Data.Until == "":
		return errors.New("file-info without a download link and validity")
	}
	if up.Thumbnail == nil {
		return nil
	}
	thumb, ok := d.Info("thumbnail")
	if !ok || thumb.Size != int64(len(up.Thumbnail)) || thumb.Data.URL == "" {
		return errors.New("no usable file-info for the thumbnail (size " + strconv.FormatInt(thumb.Size, 10) + ")")
	}
	return nil
}

// sameContent compares what came back with what went out by SHA-256, the
// check a client can make end to end.
func sameContent(got, want []byte) error {
	if len(got) != len(want) {
		return fmt.Errorf("received %d bytes, want %d", len(got), len(want))
	}
	if !bytes.Equal(got, want) || ft.SHA256(got) != ft.SHA256(want) {
		return errors.New("content differs (SHA-256 mismatch)")
	}
	return nil
}
