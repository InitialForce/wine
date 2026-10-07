/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#define COBJMACROS

#include "objbase.h"
#include "wincodec.h"
#include "wine/test.h"

static const char jpeg_adobe_cmyk_1x5[] =
    "\xff\xd8\xff\xe0\x00\x10\x4a\x46\x49\x46\x00\x01\x01\x01\x01\x2c"
    "\x01\x2c\x00\x00\xff\xee\x00\x0e\x41\x64\x6f\x62\x65\x00\x64\x00"
    "\x00\x00\x00\x02\xff\xfe\x00\x13\x43\x72\x65\x61\x74\x65\x64\x20"
    "\x77\x69\x74\x68\x20\x47\x49\x4d\x50\xff\xdb\x00\x43\x00\x01\x01"
    "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
    "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
    "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
    "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\xff\xdb"
    "\x00\x43\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
    "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
    "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
    "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
    "\x01\x01\x01\xff\xc0\x00\x14\x08\x00\x05\x00\x01\x04\x01\x11\x00"
    "\x02\x11\x01\x03\x11\x01\x04\x11\x00\xff\xc4\x00\x15\x00\x01\x01"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x08"
    "\xff\xc4\x00\x14\x10\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\xff\xc4\x00\x14\x01\x01\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0a\xff\xc4\x00\x14"
    "\x11\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\xff\xda\x00\x0e\x04\x01\x00\x02\x11\x03\x11\x04\x00\x00"
    "\x3f\x00\x40\x44\x02\x1e\xa4\x1f\xff\xd9";

/* 32x16, 4:2:0 subsampled: columns 0-15 are red (200,40,40), 16-31 blue (40,40,200). */
static const char jpeg_ycbcr420_32x16[] =
    "\xff\xd8\xff\xe0\x00\x10\x4a\x46\x49\x46\x00\x01\x01\x00\x00\x01"
    "\x00\x01\x00\x00\xff\xdb\x00\x43\x00\x01\x01\x01\x01\x01\x01\x01"
    "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
    "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
    "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
    "\x01\x01\x01\x01\x01\x01\x01\x01\x01\xff\xdb\x00\x43\x01\x01\x01"
    "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
    "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
    "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
    "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\xff\xc0"
    "\x00\x11\x08\x00\x10\x00\x20\x03\x01\x22\x00\x02\x11\x01\x03\x11"
    "\x01\xff\xc4\x00\x16\x00\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x08\x09\xff\xc4\x00\x14\x10\x01\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff"
    "\xc4\x00\x15\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x0a\x08\xff\xc4\x00\x14\x11\x01\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xda\x00\x0c"
    "\x03\x01\x00\x02\x11\x03\x11\x00\x3f\x00\xcb\xf0\x11\x39\x40\x20"
    "\xf0\x0d\x60\x45\xdf\xff\xd9";

static void test_decode_adobe_cmyk(void)
{
    IWICBitmapDecoder *decoder;
    IWICBitmapFrameDecode *framedecode;
    IWICImagingFactory *factory;
    IWICPalette *palette;
    HRESULT hr;
    HGLOBAL hjpegdata;
    char *jpegdata;
    IStream *jpegstream;
    GUID guidresult;
    UINT count=0, width=0, height=0;
    BYTE imagedata[5 * 4] = {1};
    UINT i;

    const BYTE expected_imagedata[5 * 4] = {
        0x00, 0xb0, 0xfc, 0x6d,
        0x00, 0xb0, 0xfc, 0x6d,
        0x00, 0xb0, 0xfc, 0x6d,
        0x00, 0xb0, 0xfc, 0x6d,
        0x00, 0xb0, 0xfc, 0x6d,
    };

    const BYTE expected_imagedata_24bpp[5 * 4] = {
        0x0d, 0x4b, 0x94, 0x00,
        0x0d, 0x4b, 0x94, 0x00,
        0x0d, 0x4b, 0x94, 0x00,
        0x0d, 0x4b, 0x94, 0x00,
        0x0d, 0x4b, 0x94, 0x00,
    };

    hr = CoCreateInstance(&CLSID_WICJpegDecoder, NULL, CLSCTX_INPROC_SERVER,
        &IID_IWICBitmapDecoder, (void**)&decoder);
    ok(SUCCEEDED(hr), "CoCreateInstance failed, hr=%lx\n", hr);
    if (FAILED(hr)) return;

    hr = CoCreateInstance(&CLSID_WICImagingFactory, NULL, CLSCTX_INPROC_SERVER,
        &IID_IWICImagingFactory, (void **)&factory);
    ok(SUCCEEDED(hr), "CoCreateInstance failed, hr=%lx\n", hr);

    hjpegdata = GlobalAlloc(GMEM_MOVEABLE, sizeof(jpeg_adobe_cmyk_1x5));
    ok(hjpegdata != 0, "GlobalAlloc failed\n");
    if (hjpegdata)
    {
        jpegdata = GlobalLock(hjpegdata);
        memcpy(jpegdata, jpeg_adobe_cmyk_1x5, sizeof(jpeg_adobe_cmyk_1x5));
        GlobalUnlock(hjpegdata);

        hr = CreateStreamOnHGlobal(hjpegdata, FALSE, &jpegstream);
        ok(SUCCEEDED(hr), "CreateStreamOnHGlobal failed, hr=%lx\n", hr);
        if (SUCCEEDED(hr))
        {
            hr = IWICBitmapDecoder_Initialize(decoder, jpegstream, WICDecodeMetadataCacheOnLoad);
            ok(hr == S_OK, "Initialize failed, hr=%lx\n", hr);

            hr = IWICBitmapDecoder_GetContainerFormat(decoder, &guidresult);
            ok(SUCCEEDED(hr), "GetContainerFormat failed, hr=%lx\n", hr);
            ok(IsEqualGUID(&guidresult, &GUID_ContainerFormatJpeg), "unexpected container format\n");

            hr = IWICBitmapDecoder_GetFrameCount(decoder, &count);
            ok(SUCCEEDED(hr), "GetFrameCount failed, hr=%lx\n", hr);
            ok(count == 1, "unexpected count %u\n", count);

            hr = IWICBitmapDecoder_GetFrame(decoder, 0, &framedecode);
            ok(SUCCEEDED(hr), "GetFrame failed, hr=%lx\n", hr);
            if (SUCCEEDED(hr))
            {
                hr = IWICBitmapFrameDecode_GetSize(framedecode, &width, &height);
                ok(SUCCEEDED(hr), "GetSize failed, hr=%lx\n", hr);
                ok(width == 1, "expected width=1, got %u\n", width);
                ok(height == 5, "expected height=5, got %u\n", height);

                hr = IWICBitmapFrameDecode_GetPixelFormat(framedecode, &guidresult);
                ok(SUCCEEDED(hr), "GetPixelFormat failed, hr=%lx\n", hr);
                ok(IsEqualGUID(&guidresult, &GUID_WICPixelFormat32bppCMYK) ||
                    broken(IsEqualGUID(&guidresult, &GUID_WICPixelFormat24bppBGR)), /* xp/2003 */
                    "unexpected pixel format: %s\n", wine_dbgstr_guid(&guidresult));

                /* We want to be sure our state tracking will not impact output
                 * data on subsequent calls */
                for(i=2; i>0; --i)
                {
                    hr = IWICBitmapFrameDecode_CopyPixels(framedecode, NULL, 4, sizeof(imagedata), imagedata);
                    ok(SUCCEEDED(hr), "CopyPixels failed, hr=%lx\n", hr);
                    ok(!memcmp(imagedata, expected_imagedata, sizeof(imagedata)) ||
                            broken(!memcmp(imagedata, expected_imagedata_24bpp, sizeof(expected_imagedata))), /* xp/2003 */
                            "unexpected image data\n");
                }

                hr = IWICImagingFactory_CreatePalette(factory, &palette);
                ok(SUCCEEDED(hr), "CreatePalette failed, hr=%lx\n", hr);

                hr = IWICBitmapDecoder_CopyPalette(decoder, palette);
                ok(hr == WINCODEC_ERR_PALETTEUNAVAILABLE, "Unexpected hr %#lx.\n", hr);

                hr = IWICBitmapFrameDecode_CopyPalette(framedecode, palette);
                ok(hr == WINCODEC_ERR_PALETTEUNAVAILABLE, "Unexpected hr %#lx.\n", hr);

                IWICPalette_Release(palette);

                IWICBitmapFrameDecode_Release(framedecode);
            }
            IStream_Release(jpegstream);
        }
        GlobalFree(hjpegdata);
    }

    IWICBitmapDecoder_Release(decoder);
    IWICImagingFactory_Release(factory);
}

static void test_decode_ycbcr420(void)
{
    static const BYTE red[3] = { 0x28, 0x28, 0xc8 }, blue[3] = { 0xc8, 0x28, 0x28 };
    /* Windows interpolates the chroma between the two samples next to each
     * output pixel, so the colours blend across the edge at x = 16, which is
     * also the edge between two chroma blocks. */
    static const BYTE edge[6] = { 0x58, 0x2f, 0xa8, 0x98, 0x21, 0x48 };
    IWICBitmapDecoder *decoder;
    IWICBitmapFrameDecode *frame;
    IWICImagingFactory *factory;
    IWICStream *stream;
    BYTE expected[32 * 3], imagedata[32 * 3 * 16];
    UINT width, height, x, y, diff;
    GUID format;
    HRESULT hr;

    for (x = 0; x < 15; x++) memcpy(expected + x * 3, red, 3);
    memcpy(expected + 15 * 3, edge, 6);
    for (x = 17; x < 32; x++) memcpy(expected + x * 3, blue, 3);

    hr = CoCreateInstance(&CLSID_WICImagingFactory, NULL, CLSCTX_INPROC_SERVER,
        &IID_IWICImagingFactory, (void **)&factory);
    ok(hr == S_OK, "CoCreateInstance failed, hr=%lx\n", hr);

    hr = IWICImagingFactory_CreateStream(factory, &stream);
    ok(hr == S_OK, "CreateStream failed, hr=%lx\n", hr);
    hr = IWICStream_InitializeFromMemory(stream, (BYTE *)jpeg_ycbcr420_32x16, sizeof(jpeg_ycbcr420_32x16) - 1);
    ok(hr == S_OK, "InitializeFromMemory failed, hr=%lx\n", hr);

    hr = IWICImagingFactory_CreateDecoderFromStream(factory, (IStream *)stream, NULL,
        WICDecodeMetadataCacheOnLoad, &decoder);
    ok(hr == S_OK, "CreateDecoderFromStream failed, hr=%lx\n", hr);

    hr = IWICBitmapDecoder_GetFrame(decoder, 0, &frame);
    ok(hr == S_OK, "GetFrame failed, hr=%lx\n", hr);

    hr = IWICBitmapFrameDecode_GetSize(frame, &width, &height);
    ok(hr == S_OK, "GetSize failed, hr=%lx\n", hr);
    ok(width == 32 && height == 16, "got size %ux%u\n", width, height);

    hr = IWICBitmapFrameDecode_GetPixelFormat(frame, &format);
    ok(hr == S_OK, "GetPixelFormat failed, hr=%lx\n", hr);
    ok(IsEqualGUID(&format, &GUID_WICPixelFormat24bppBGR), "got format %s\n", wine_dbgstr_guid(&format));

    hr = IWICBitmapFrameDecode_CopyPixels(frame, NULL, 32 * 3, sizeof(imagedata), imagedata);
    ok(hr == S_OK, "CopyPixels failed, hr=%lx\n", hr);

    for (y = 0; y < 16; y++)
    {
        for (x = 0, diff = 0; x < 32 * 3; x++)
            if (imagedata[y * 32 * 3 + x] != expected[x]) diff++;
        ok(!diff, "row %u: %u bytes differ, pixels 15 and 16 are %02x%02x%02x %02x%02x%02x\n", y, diff,
            imagedata[y * 96 + 45], imagedata[y * 96 + 46], imagedata[y * 96 + 47],
            imagedata[y * 96 + 48], imagedata[y * 96 + 49], imagedata[y * 96 + 50]);
    }

    IWICBitmapFrameDecode_Release(frame);
    IWICBitmapDecoder_Release(decoder);
    IWICStream_Release(stream);
    IWICImagingFactory_Release(factory);
}

START_TEST(jpegformat)
{
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    test_decode_adobe_cmyk();
    test_decode_ycbcr420();

    CoUninitialize();
}
