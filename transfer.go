package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/schollz/progressbar/v3"
)

const (
	stopSenderIfStuckAdvice = "The sender is likely stuck and if stuck should be manually stopped."
)

const (
	qErrCodeNoErr quic.ApplicationErrorCode = iota
	qErrCodeUnknownErr
)

// sendFile orchestrates the full send flow:
// bind UDP -> hole punch -> QUIC dial -> mutual TLS verify -> stream file
func sendFile(ctx context.Context, key *ecdsa.PrivateKey, filePath, remoteAddr, peerFP string, localPort int) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat file: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory, not a file", filePath)
	}

	conn, err := reuseListenUDP(localPort)
	if err != nil {
		return fmt.Errorf("bind UDP: %w", err)
	}
	defer conn.Close()

	actualPort := conn.LocalAddr().(*net.UDPAddr).Port

	// Punch on a separate socket sharing the same port via SO_REUSEPORT,
	// so we don't race with quic-go's exclusive write access.
	// Only punch when --port was explicitly set for bilateral hole punching.
	var punchCancel context.CancelFunc
	if localPort != 0 {
		fmt.Fprintln(os.Stderr, "Punching NAT...")

		var punchCtx context.Context
		punchCtx, punchCancel = context.WithCancel(ctx)
		defer func() {
			if f := punchCancel; f != nil {
				punchCancel()
			}
		}()

		if err := startPunch(punchCtx, actualPort, remoteAddr); err != nil {
			fmt.Fprintf(os.Stderr, "Punch socket failed: %v (continuing without punch)\n", err)
			if f := punchCancel; f != nil {
				punchCancel = nil
				f()
			}
		}
	}

	tlsConf, err := clientTLSConfig(key, peerFP)
	if err != nil {
		return fmt.Errorf("TLS config: %w", err)
	}

	fmt.Fprintln(os.Stderr, "Establishing QUIC connection...")
	qconn, tr, err := dialQUIC(ctx, 15*time.Second, conn, remoteAddr, tlsConf)
	if f := punchCancel; f != nil {
		punchCancel = nil
		f()
	}
	if err != nil {
		return fmt.Errorf("QUIC dial: %w", err)
	}
	defer tr.Close()
	qErrCode := qErrCodeUnknownErr
	defer func() {
		qconn.CloseWithError(qErrCode, "")
	}()

	fmt.Fprintln(os.Stderr, "Peer identity verified! Sending file...")

	stream, err := qconn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}

	// Wire format: [8 bytes file size] -> [8 bytes offset from receiver] -> [file data from offset]
	var header [8]byte
	binary.BigEndian.PutUint64(header[:], uint64(info.Size()))

	if _, err := stream.Write(header[:]); err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	// Read offset from receiver (resume support)
	var offsetBuf [8]byte
	if _, err := io.ReadFull(stream, offsetBuf[:]); err != nil {
		return fmt.Errorf("read offset: %w", err)
	}
	offset := int64(binary.BigEndian.Uint64(offsetBuf[:]))

	if offset < 0 || offset > info.Size() {
		return fmt.Errorf("invalid offset %d for file of size %d", offset, info.Size())
	}

	if offset > 0 {
		fmt.Fprintf(os.Stderr, "Resuming from byte %d\n", offset)
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return fmt.Errorf("seek: %w", err)
		}
	}

	expected := info.Size() - offset
	bar := progressbar.DefaultBytes(
		expected,
		"uploading",
	)

	written, err := io.Copy(io.MultiWriter(stream, bar), f)
	if err != nil {
		return fmt.Errorf("send data: %w", err)
	}
	if written != expected {
		return fmt.Errorf("file changed during transfer: expected to send %d bytes but read %d (file may have been truncated or modified)", expected, written)
	}

	if err := stream.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Graceful stream close failed, but all data sent without error: %s\n", err.Error())
	}

	// Wait for receiver to ack before tearing down the connection.
	ack := make([]byte, 1)
	n, err := stream.Read(ack)
	if err != nil && (n == 0 || ack[0] != 0x06) {
		return fmt.Errorf("file data sent successfully but receiver sent no ack response: %w", err)
	}

	qErrCode = qErrCodeNoErr

	fmt.Fprintf(os.Stderr, "Sent %d bytes\n", written)
	return nil
}

// receiveFile orchestrates the full receive flow:
// bind UDP -> QUIC listen -> mutual TLS verify -> receive stream -> save file
//
// Invariant: The caller guarantees that the resume flag is only set if the outPath is a file and not stdout.
func receiveFile(ctx context.Context, key *ecdsa.PrivateKey, port int, peerFP, outPath string, mode os.FileMode, senderAddr string, resume bool) error {
	fileSize, err := receiveFileOverNet(ctx, key, port, peerFP, outPath, mode, senderAddr, resume)
	if err != nil {
		return err
	}

	if outPath == "-" {
		return nil
	}

	return finalizeDownload(outPath, fileSize)
}

func receiveFileOverNet(ctx context.Context, key *ecdsa.PrivateKey, port int, peerFP, outPath string, mode os.FileMode, senderAddr string, resume bool) (int64, error) {
	var result int64

	// Pre-flight: validate destination before starting any network I/O.
	if outPath != "-" {
		dir := filepath.Dir(outPath)
		if err := checkDirWritable(dir); err != nil {
			return result, fmt.Errorf("output directory %s: %w", dir, err)
		}
		if info, err := os.Stat(outPath); err == nil {
			if info.Size() == 0 {
				if err := os.Remove(outPath); err != nil {
					return result, fmt.Errorf("failed to remove existing empty file %s: %w", outPath, err)
				}
			} else if err := checkFileRemovable(outPath); err != nil {
				return result, err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return result, fmt.Errorf("failed to read filesystem: %w", err)
		}

		// Check if a previous download already completed but wasn't finalized.
		if resume {
			if st, stErr := readStatus(outPath); stErr == nil && st.ExpectedSize != nil && st.BytesWritten != nil && *st.BytesWritten == *st.ExpectedSize {
				tmpPath := tempFilePath(outPath)
				if tmpInfo, tmpErr := os.Stat(tmpPath); tmpErr == nil && tmpInfo.Size() == *st.ExpectedSize {
					fmt.Fprintf(os.Stderr, "Previous download already complete (%d bytes), finalizing...\n", *st.ExpectedSize)
					result = *st.ExpectedSize
					return result, nil
				}
			}
		}
	}

	conn, err := reuseListenUDP(port)
	if err != nil {
		return result, fmt.Errorf("bind UDP port %d: %w", port, err)
	}
	defer conn.Close()

	if port == 0 {
		port = conn.LocalAddr().(*net.UDPAddr).Port
		if port == 0 {
			return result, fmt.Errorf("receiveFile: could not determine local port")
		}
	}

	var punchCancel context.CancelFunc
	if senderAddr != "" {
		fmt.Fprintf(os.Stderr, "Punching toward sender at %s...\n", senderAddr)
		var punchCtx context.Context
		punchCtx, punchCancel = context.WithCancel(ctx)
		defer func() {
			if f := punchCancel; f != nil {
				punchCancel()
			}
		}()

		if err := startPunch(punchCtx, port, senderAddr); err != nil {
			fmt.Fprintf(os.Stderr, "Punch socket failed: %v (continuing without punch)\n", err)
			if f := punchCancel; f != nil {
				punchCancel = nil
				f()
			}
		}
	}

	fmt.Fprintf(os.Stderr, "Waiting for peer on :%d...\n", port)

	tlsConf, err := serverTLSConfig(key, peerFP)
	if err != nil {
		return result, fmt.Errorf("TLS config: %w", err)
	}

	ln, tr, err := listenQUIC(conn, tlsConf)
	if err != nil {
		return result, fmt.Errorf("QUIC listen: %w", err)
	}
	defer tr.Close()
	defer ln.Close()

	qconn, err := ln.Accept(ctx)
	if f := punchCancel; f != nil {
		punchCancel = nil
		f()
	}
	if err != nil {
		return result, fmt.Errorf("accept connection: %w", err)
	}
	fmt.Fprintln(os.Stderr, "Peer identity verified! Receiving file...")

	qErrCode := qErrCodeUnknownErr
	defer func() {
		qconn.CloseWithError(qErrCode, "")
	}()

	stream, err := qconn.AcceptStream(ctx)
	if err != nil {
		return result, fmt.Errorf("accept stream: %w", err)
	}
	closeStream := stream.Close
	defer func() {
		if f := closeStream; f != nil {
			closeStream = nil
			f()
		}
	}()

	// Read header: [8 bytes file size]
	var fileSize int64
	{
		var tmp uint64
		if err := binary.Read(stream, binary.BigEndian, &tmp); err != nil {
			return result, fmt.Errorf("read file size: %w", err)
		}
		if tmp > uint64(math.MaxInt64) {
			return result, fmt.Errorf("file size %d exceeds maximum supported size", tmp)
		}

		fileSize = int64(tmp)
	}

	// Determine resume offset
	var offset int64
	if resume {
		st, stErr := readStatus(outPath)
		if stErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to read previous status, starting download from beginning: %v\n", stErr)
		} else if st.ExpectedSize == nil {
			fmt.Fprintf(os.Stderr, "Warning: status file has no expected file size, starting download from beginning\n")
		} else if *st.ExpectedSize != fileSize {
			tmpPath := tempFilePath(outPath)
			if tmpInfo, tmpErr := os.Stat(tmpPath); tmpErr != nil {
				if !errors.Is(tmpErr, os.ErrNotExist) {
					return result, fmt.Errorf("failed to read temp file for resume validation: %w", tmpErr)
				}
				fmt.Fprintln(os.Stderr, "Warning: No partial data file exists, starting download from beginning")
			} else if tmpInfo.Size() > 0 {
				return result, fmt.Errorf("sender reports file size %d but status file expects %d; aborting to protect existing partial download", fileSize, *st.ExpectedSize)
			} else {
				fmt.Fprintf(os.Stderr, "Warning: sender file size %d differs from status file expectation %d but no partial data exists, starting download from beginning\n", fileSize, *st.ExpectedSize)
			}
		} else if st.BytesWritten == nil {
			fmt.Fprintf(os.Stderr, "Warning: status file has no bytes written record, starting download from beginning\n")
		} else {
			tmpPath := tempFilePath(outPath)
			tmpInfo, tmpErr := os.Stat(tmpPath)
			if tmpErr != nil || tmpInfo.Size() != *st.BytesWritten {
				fmt.Fprintf(os.Stderr, "Warning: temp file size does not match status file, starting download from beginning\n")
			} else {
				offset = *st.BytesWritten
				fmt.Fprintf(os.Stderr, "Resuming from byte %d of %d\n", offset, fileSize)
			}
		}
	}

	// Send offset to sender
	var offsetBuf [8]byte
	binary.BigEndian.PutUint64(offsetBuf[:], uint64(offset))
	if _, err := stream.Write(offsetBuf[:]); err != nil {
		return result, fmt.Errorf("write offset: %w", err)
	}

	remaining := fileSize - offset
	fmt.Fprintf(os.Stderr, "Receiving %d bytes -> %s\n", remaining, outPath)

	// Open output
	var out io.Writer
	var outFile *os.File
	var closeOutFile func() error
	if outPath == "-" {
		out = os.Stdout
	} else {
		tmpPath := tempFilePath(outPath)

		// Write status before starting download
		if err := writeStatus(outPath, downloadStatus{
			ExpectedSize: int64Ptr(fileSize),
			BytesWritten: int64Ptr(offset),
		}); err != nil {
			return result, fmt.Errorf("write status: %w", err)
		}

		var openFlags int
		if offset > 0 {
			openFlags = os.O_WRONLY
		} else {
			openFlags = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
		}

		outFile, err = os.OpenFile(tmpPath, openFlags, mode)
		if err != nil {
			if errors.Is(err, os.ErrPermission) {
				return result, fmt.Errorf("temp file %s is not writable; delete it or make it writable", tmpPath)
			}
			return result, fmt.Errorf("open temp file: %w", err)
		}
		if err := outFile.Chmod(mode); err != nil {
			return result, fmt.Errorf("set temp file mode: %w", err)
		}
		closeOutFile = outFile.Close
		defer func() {
			if f := closeOutFile; f != nil {
				closeOutFile = nil
				f()
			}
		}()

		if offset > 0 {
			if _, err := outFile.Seek(offset, io.SeekStart); err != nil {
				return result, fmt.Errorf("seek temp file: %w", err)
			}
		}

		bar := progressbar.DefaultBytes(
			remaining,
			"downloading",
		)

		out = io.MultiWriter(outFile, bar)
	}

	written, err := io.Copy(out, io.LimitReader(stream, remaining))
	if err != nil || written != remaining {
		// Record progress for future resume
		if outFile != nil {
			if err := outFile.Sync(); err != nil {
				return result, fmt.Errorf("sync temp file: %w", err)
			}
			if wsErr := writeStatus(outPath, downloadStatus{
				ExpectedSize: int64Ptr(fileSize),
				BytesWritten: int64Ptr(offset + written),
			}); wsErr != nil {
				return result, fmt.Errorf("failed to update status file after interrupted transfer: %w", wsErr)
			}
		}
		if err != nil {
			return result, fmt.Errorf("receive data: %w", err)
		}
		return result, fmt.Errorf("incomplete transfer: got %d of %d bytes", offset+written, fileSize)
	}

	// Ack back to sender so it knows we're done before it closes the connection
	if _, err := stream.Write([]byte{0x06}); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: file received successfully but ack failed to send: %v\n%s\n", err, stopSenderIfStuckAdvice)
	}

	if f := closeStream; f != nil {
		closeStream = nil
		if err := f(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: file received successfully but stream failed to gracefully close: %v\n%s\n", err, stopSenderIfStuckAdvice)
		}
	}

	// Wait for sender to close the connection. This ensures the sender has
	// received our ack before we tear down the connection, avoiding a race
	// where CONNECTION_CLOSE arrives before the ack byte.
	//
	// This also confirms that the sender intends to close responsibly and is
	// not trying to send more than the number of bytes it said it would.
	var discard [1]byte
	if _, err := stream.Read(discard[:]); err != nil {
		if !errors.Is(err, io.EOF) {
			fmt.Fprintf(os.Stderr, "Warning: file received successfully but failed to read until sender closed connection: %v\n%s\n", err, stopSenderIfStuckAdvice)
		}
	} else {
		return result, errors.New("expected sender to close connection after file transfer, but received unexpected data instead")
	}

	// Now actually wait for the sender to close the connection,
	// so our ack is delivered before we send CONNECTION_CLOSE.
	{
		ctx := qconn.Context()
		const closeWaitTimeout = 10 * time.Second

		select {
		case <-ctx.Done():
			if err := context.Cause(ctx); err != nil {
				var appErr *quic.ApplicationError
				if !errors.As(err, &appErr) {
					return result, fmt.Errorf("secure connection closed due to unexpected error: %w", err)
				}
				if appErr.ErrorCode != qErrCodeNoErr {
					return result, fmt.Errorf("secure connection closed due to unexpected application error: %w", appErr)
				}
			}

			// sender closed gracefully after receiving ack
		case <-time.After(closeWaitTimeout):
			return result, fmt.Errorf("Warning: failed to confirm transfer ended at expected position: connection not closed gracefully (hung after timeout of %s)", closeWaitTimeout.String())
		}
	}

	qErrCode = qErrCodeNoErr

	if f := closeOutFile; f != nil {
		closeOutFile = nil
		if err := f(); err != nil {
			return result, fmt.Errorf("failed to close output file: %w", err)
		}
	} else {
		fmt.Fprintf(os.Stderr, "Copied %d bytes to stdout\n", fileSize)
	}

	result = fileSize
	return result, nil
}

func finalizeDownload(outPath string, fileSize int64) error {
	if err := os.Rename(tempFilePath(outPath), outPath); err != nil {
		return fmt.Errorf("rename temp to final: %w", err)
	}
	if err := removeStatusFiles(outPath); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: leftover files remain: %v\n", err)
	}
	fmt.Fprintf(os.Stderr, "Saved: %s (%d bytes)\n", outPath, fileSize)
	return nil
}
