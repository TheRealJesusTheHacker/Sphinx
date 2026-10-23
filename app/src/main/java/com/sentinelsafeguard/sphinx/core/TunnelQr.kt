package com.sentinelsafeguard.sphinx.core

import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.LuminanceSource
import com.google.zxing.MultiFormatReader
import com.google.zxing.common.BitMatrix
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeWriter
import java.util.EnumMap
import java.util.EnumSet

/**
 * QR import/export of tunnel profiles — TUNNEL-SPEC: Android
 * QR import accepts exactly the WireGuard config text, carried
 * in a QR code. There is no second format: what [encode] puts
 * in a code is config text, and what [decodeArgb] reads out of
 * one is config text, handed to the same parser as pasted text.
 *
 * Built on ZXing core (com.google.zxing:core, Apache-2.0 —
 * verified from its POM and LICENSE before pinning; attribution
 * ships in assets/third-party). Import arrives as an image the
 * user picks (the system photo/file picker): no camera
 * dependency is bundled, so there is no camera permission to
 * ask for. Export renders the same text as a QR the user shows
 * or shares by their own explicit action.
 *
 * Pure Kotlin/Java — the Bitmap step lives in the UI layer,
 * which hands this object raw ARGB pixels.
 */
object TunnelQr {

    /** Encode config text as a QR bit matrix (true = dark
     *  module), or null when the text cannot be encoded. */
    fun encode(text: String, size: Int = 640): BitMatrix? =
        try {
            QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, size, size)
        } catch (e: Exception) {
            null
        }

    /** Decode a QR code from ARGB pixels (e.g. a picked image's
     *  Bitmap pixels). Returns the carried text, or null when
     *  no QR code can be read — the caller says so plainly and
     *  imports nothing. */
    fun decodeArgb(pixels: IntArray, width: Int, height: Int): String? {
        if (width <= 0 || height <= 0 || pixels.size < width * height) return null
        val gray = ByteArray(width * height)
        for (i in gray.indices) {
            val argb = pixels[i]
            val r = (argb shr 16) and 0xFF
            val g = (argb shr 8) and 0xFF
            val b = argb and 0xFF
            // ITU-R BT.601 luma, the conversion ZXing expects.
            gray[i] = ((r * 299 + g * 587 + b * 114) / 1000).toByte()
        }
        return decodeGray(gray, width, height)
    }

    /** Decode a QR code from a grayscale raster. The reader is
     *  restricted to QR codes: import accepts config text and
     *  nothing else, and an unrestricted reader can hand back a
     *  stray 1-D barcode's digits found inside a busy image
     *  (observed in testing — a config code "decoded" to eight
     *  digits that were never in it). Two reads are tried: the
     *  ordinary read first (picked photos and screenshots, with
     *  their perspective and lighting), then ZXing's
     *  pure-barcode read for clean rendered codes — without it,
     *  the detector can fail to size a dense, perfectly sharp
     *  symbol at all, including this app's own exports. */
    fun decodeGray(gray: ByteArray, width: Int, height: Int): String? {
        if (width <= 0 || height <= 0 || gray.size < width * height) return null
        val source = GrayLuminanceSource(width, height, gray)
        val hints = EnumMap<DecodeHintType, Any>(DecodeHintType::class.java)
        hints[DecodeHintType.POSSIBLE_FORMATS] = EnumSet.of(BarcodeFormat.QR_CODE)
        tryDecode(source, hints)?.let { return it }
        val pureHints = EnumMap<DecodeHintType, Any>(hints)
        pureHints[DecodeHintType.PURE_BARCODE] = true
        return tryDecode(source, pureHints)
    }

    private fun tryDecode(
        source: LuminanceSource,
        hints: Map<DecodeHintType, Any>,
    ): String? =
        try {
            val bitmap = BinaryBitmap(HybridBinarizer(source))
            MultiFormatReader().decode(bitmap, hints).text
        } catch (e: Exception) {
            null
        }

    /** Render a bit matrix into a grayscale raster (dark module
     *  = 0, light = 255), for display layers that draw pixels
     *  and for the encode→decode round-trip test. */
    fun renderGray(matrix: BitMatrix): ByteArray {
        val out = ByteArray(matrix.width * matrix.height)
        for (y in 0 until matrix.height) {
            for (x in 0 until matrix.width) {
                out[y * matrix.width + x] = if (matrix[x, y]) 0 else 255.toByte()
            }
        }
        return out
    }

    private class GrayLuminanceSource(
        width: Int,
        height: Int,
        private val gray: ByteArray,
    ) : LuminanceSource(width, height) {
        override fun getRow(y: Int, row: ByteArray?): ByteArray {
            val out = if (row != null && row.size >= width) row else ByteArray(width)
            System.arraycopy(gray, y * width, out, 0, width)
            return out
        }

        override fun getMatrix(): ByteArray = gray
    }
}
