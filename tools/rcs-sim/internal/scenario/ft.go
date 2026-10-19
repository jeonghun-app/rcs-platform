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

// uploadSettle is how long a broken upload may take to show, unchanging, in
// get_upload_info, and settlePoll how often the simulator asks meanwhile. A
// device asks once it is back on a network, seconds later; the simulator
// asks at once, so it must wait for the server to notice the break.
const (
	uploadSettle = 3 * time.Second
	settlePoll   = 100 * time.Millisecond
)

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
// fetches it: get_download_info, the whole file, a range, the rest of the
// file as rcsjta resumes a download, the thumbnail.
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
		got, err := c.Download(ctx, file.Data.URL, "", int64(len(up.Data)))
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
		return rangeDownload(ctx, c, file.Data.URL, ft.RangeHeader(first, last), up.Data[first:last+1])
	}); err != nil {
		return err
	}
	if err := r.step("download-resume", func(ctx context.Context) (map[string]int64, error) {
		// rcsjta resumes a download with bytes=<received>-<total>, one past
		// the last byte (HttpDownloadManager); RFC 9110 §14.1.2 has the
		// server read that as the rest of the file.
		received := int64(len(up.Data) / 2)
		return rangeDownload(ctx, c, file.Data.URL, "bytes="+strconv.FormatInt(received, 10)+"-"+strconv.Itoa(len(up.Data)), up.Data[received:])
	}); err != nil {
		return err
	}
	return r.step("download-thumbnail", func(ctx context.Context) (map[string]int64, error) {
		thumb, _ := doc.Info("thumbnail")
		got, err := c.Download(ctx, thumb.Data.URL, "", int64(len(up.Thumbnail)))
		if err != nil {
			return nil, err
		}
		return nil, sameContent(got.Body, up.Thumbnail)
	})
}

// rangeDownload fetches link with a Range header and checks that the server
// answers 206 with want.
func rangeDownload(ctx context.Context, c *ft.Client, link, rangeHeader string, want []byte) (map[string]int64, error) {
	got, err := c.Download(ctx, link, rangeHeader, int64(len(want)))
	if err != nil {
		return nil, err
	}
	if got.Status != http.StatusPartialContent {
		return nil, fmt.Errorf("range download answered %d, want 206", got.Status)
	}
	return map[string]int64{"bytes": int64(len(got.Body))}, sameContent(got.Body, want)
}

// fileTransferResumed breaks an upload part-way, as a phone changing
// networks does, and resumes it the way rcsjta does: get_upload_info, a PUT
// of the rest with Content-Range, get_download_info, then the download. As
// in rcsjta, a get_upload_info that holds nothing makes the upload start
// again ("upload-again" instead of "resume"), and a PUT answered other than
// 200 fails the transfer.
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
	held := int64(0)
	if err := r.step("get_upload_info", func(ctx context.Context) (map[string]int64, error) {
		var (
			retries, notHeld int64
			err              error
		)
		info, retries, notHeld, err = settledUploadInfo(ctx, c, up.TID)
		detail := map[string]int64{"retries": retries, "not_held": notHeld}
		switch {
		case errors.Is(err, ft.ErrNothingHeld):
			// rcsjta uploads the file again from the start; so does the
			// next step.
			detail["held"] = 0
			return detail, nil
		case err != nil:
			return detail, err
		}
		held, _ = info.Held()
		detail["held"] = held
		if held >= int64(len(up.Data)) {
			return detail, errors.New("the server holds the whole file of a broken upload")
		}
		return detail, nil
	}); err != nil {
		return err
	}
	if held == 0 {
		if err := r.step("upload-again", func(ctx context.Context) (map[string]int64, error) {
			// rcsjta's uploadFile, from its empty POST on.
			if err := c.Precheck(ctx); err != nil {
				return nil, err
			}
			var err error
			if doc, err = c.Send(ctx, up); err != nil {
				return nil, err
			}
			return map[string]int64{"bytes": int64(len(up.Data))}, checkDocument(doc, up)
		}); err != nil {
			return err
		}
	} else if err := r.step("resume", func(ctx context.Context) (map[string]int64, error) {
		var err error
		doc, err = c.Resume(ctx, info, up.ContentType, up.Data)
		if ft.IsStatus(err, http.StatusConflict) || ft.IsStatus(err, http.StatusServiceUnavailable) {
			// The simulator does not retry: rcsjta ends the transfer on
			// any answer to the PUT but 200.
			return nil, fmt.Errorf("%w; rcsjta fails the transfer on this", err)
		}
		if err != nil {
			return nil, err
		}
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
		got, err := c.Download(ctx, file.Data.URL, "", int64(len(up.Data)))
		if err != nil {
			return nil, err
		}
		if strings.Trim(got.ETag, `"`) != ft.SHA256(up.Data) {
			return nil, errors.New("the ETag is not the SHA-256 of the content")
		}
		return map[string]int64{"bytes": int64(len(got.Body))}, sameContent(got.Body, up.Data)
	})
}

// settledUploadInfo asks get_upload_info until the server has noticed the
// break and stored what it will keep: until two answers in a row name the
// same bytes held. A 404 is asked again until uploadSettle has passed, and
// then returned as ft.ErrNothingHeld. retries counts the answers asked again
// for, notHeld the 404s among them; the scenario reports both, so a server
// that is slow to keep a broken upload shows in the results.
func settledUploadInfo(ctx context.Context, c *ft.Client, tid string) (info ft.ResumeDocument, retries, notHeld int64, err error) {
	deadline := time.Now().Add(uploadSettle)
	last := int64(-1)
	for {
		info, err = c.UploadInfo(ctx, tid)
		held := int64(-1)
		switch {
		case errors.Is(err, ft.ErrNothingHeld):
			notHeld++
		case err != nil:
			return info, retries, notHeld, err
		default:
			held, _ = info.Held()
			if held == last {
				return info, retries, notHeld, nil
			}
		}
		last = held
		if time.Now().After(deadline) {
			return info, retries, notHeld, err
		}
		select {
		case <-time.After(settlePoll):
		case <-ctx.Done():
			return info, retries, notHeld, ctx.Err()
		}
		retries++
	}
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
