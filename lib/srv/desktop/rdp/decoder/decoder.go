/*
 * Teleport
 * Copyright (C) 2025  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package decoder

/*
#cgo LDFLAGS: -L${SRCDIR}/../../../../../target/release -lrdp_decoder
#include <stdint.h>

typedef struct RdpDecoder RdpDecoder;

RdpDecoder* rdp_decoder_new(uint16_t width, uint16_t height);
void rdp_decoder_free(RdpDecoder* ptr);

int rdp_decoder_resize(RdpDecoder* ptr, uint16_t width, uint16_t height);
int rdp_decoder_process(RdpDecoder* ptr, const uint8_t* data, size_t len);
const uint8_t* rdp_decoder_image_data(RdpDecoder* ptr, size_t* out_len);
*/
import "C"

import (
	"errors"
	"image"
	"unsafe"
)

// TODO: build tag?

type Decoder struct {
	ptr    *C.RdpDecoder
	width  uint16
	height uint16
}

func New(width, height uint16) (*Decoder, error) {
	ptr := C.rdp_decoder_new(C.uint16_t(width), C.uint16_t(height))
	if ptr == nil {
		return nil, errors.New("failed to create decoder")
	}
	return &Decoder{
		ptr:    ptr,
		width:  width,
		height: height,
	}, nil
}

func (d *Decoder) Free() {
	if d.ptr == nil {
		return
	}
	C.rdp_decoder_free(d.ptr)
	d.ptr = nil
}

func (d *Decoder) Resize(width, height uint16) {
	if d.ptr == nil {
		return
	}
	d.width = width
	d.height = height
	C.rdp_decoder_resize(d.ptr, C.uint16_t(width), C.uint16_t(height))
}

func (d *Decoder) Process(frame []byte) {
	if d.ptr == nil {
		return
	}

	data := unsafe.SliceData(frame)
	C.rdp_decoder_process(d.ptr, (*C.uint8_t)(unsafe.Pointer(data)), C.size_t(len(frame)))
}

func (d *Decoder) Image() *image.RGBA {
	if d == nil || d.ptr == nil {
		return nil
	}

	var outLen C.size_t
	data := C.rdp_decoder_image_data(d.ptr, &outLen)
	if data == nil || outLen == 0 {
		return nil
	}

	w := int(d.width)
	h := int(d.height)
	if w == 0 || h == 0 {
		return nil
	}

	rgba := image.NewRGBA(image.Rect(0, 0, w, h))

	// Copy from the Rust-owned memory into Go memory.
	copy(rgba.Pix, unsafe.Slice((*uint8)(unsafe.Pointer(data)), outLen))

	return rgba
}
