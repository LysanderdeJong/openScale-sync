/*
 *  Copyright (C) 2025  olie.xdev <olie.xdev@googlemail.com>
 *
 *     This program is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation, either version 3 of the License, or
 *     (at your option) any later version.
 *
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public License
 *     along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */
package com.health.openscale.sync.core.sync

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.time.OffsetDateTime
import java.util.Date

class GarminFitTest {

    private val referenceHex =
        "0c20a708650000002e46495440000000000600010001028402028403048c0404860502840009ff000000785634127862c34300004000001e000b0502840801020a01020b01020002840c02840d0284fd0486010284020284040284008615051907fc1c0000d0007862c343d205d0164a015529"

    private val referenceOrder = listOf(5, 8, 10, 11, 0, 12, 13, 253, 1, 2, 4)

    private val referenceTimestamp: Date =
        Date.from(OffsetDateTime.parse("2026-01-09T08:30:00+01:00").toInstant())

    private fun referenceInput() = GarminWeightScale(
        timestamp = referenceTimestamp,
        weightKg = 74.2,
        percentFat = 14.9,
        percentHydration = 58.4,
        boneMassKg = 3.3,
        muscleMassKg = 55.1,
        visceralFatRating = 7,
        metabolicAge = 25,
        bmi = 20.8,
        physiqueRating = 5,
    )

    @Test
    fun encodeMatchesReferenceBytesExactly() {
        val bytes = GarminFit.encode(referenceInput(), referenceOrder)
        assertEquals(referenceHex, bytes.toHex())
    }

    @Test
    fun crcOverReferenceIncludingTrailerIsZero() {
        val bytes = hexToBytes(referenceHex)
        assertEquals(115, bytes.size)
        assertEquals(0, GarminFit.crc(bytes))
    }

    @Test
    fun publicEncodeWithOnlyWeightIsConsistent() {
        val bytes = GarminFit.encode(GarminWeightScale(referenceTimestamp, 74.2))

        assertEquals(bytes.size - 14, readLe(bytes, 4, 4).toInt())
        assertEquals(".FIT", String(bytes, 8, 4, Charsets.US_ASCII))
        assertEquals(0, GarminFit.crc(bytes))

        val weightScale = decodeWeightScaleValues(bytes)
        assertEquals(7420L, weightScale.getValue(0))
        assertEquals(setOf(0, 12, 253), weightScale.keys)
    }

    @Test
    fun negativeWeightIsRejected() {
        assertThrows(IllegalArgumentException::class.java) {
            GarminFit.encode(GarminWeightScale(referenceTimestamp, -1.0))
        }
    }

    private fun ByteArray.toHex(): String =
        joinToString("") { "%02x".format(it.toInt() and 0xFF) }

    private fun hexToBytes(hex: String): ByteArray =
        ByteArray(hex.length / 2) { i -> hex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }

    private fun readLe(bytes: ByteArray, offset: Int, size: Int): Long {
        var value = 0L
        for (i in 0 until size) value = value or ((bytes[offset + i].toLong() and 0xFF) shl (8 * i))
        return value
    }

    /** Minimal FIT reader: returns raw field values of the weight_scale (global 30) data record. */
    private fun decodeWeightScaleValues(bytes: ByteArray): Map<Int, Long> {
        class Def(val global: Int, val fields: List<IntArray>)

        val defs = HashMap<Int, Def>()
        val values = HashMap<Int, Long>()
        var pos = 12
        val end = bytes.size - 2
        while (pos < end) {
            val header = bytes[pos++].toInt() and 0xFF
            val local = header and 0x0F
            if ((header and 0x40) != 0) {
                val global = readLe(bytes, pos + 2, 2).toInt()
                val count = bytes[pos + 4].toInt() and 0xFF
                val fields = (0 until count).map { i ->
                    val p = pos + 5 + i * 3
                    intArrayOf(bytes[p].toInt() and 0xFF, bytes[p + 1].toInt() and 0xFF)
                }
                defs[local] = Def(global, fields)
                pos += 5 + count * 3
            } else {
                val def = defs.getValue(local)
                var p = pos
                for ((num, size) in def.fields.map { it[0] to it[1] }) {
                    if (def.global == 30) values[num] = readLe(bytes, p, size)
                    p += size
                }
                pos += def.fields.sumOf { it[1] }
            }
        }
        return values
    }
}
