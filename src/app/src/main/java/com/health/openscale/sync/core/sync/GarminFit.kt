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

import java.io.ByteArrayOutputStream

/**
 * One body-composition measurement for the Garmin FIT `weight_scale` message.
 * Units: kg for masses, percent for fat/hydration, kg/m^2 for BMI.
 */
data class GarminWeightScale(
    val timestamp: java.util.Date,
    val weightKg: Double,
    val percentFat: Double? = null,
    val percentHydration: Double? = null,
    val boneMassKg: Double? = null,
    val muscleMassKg: Double? = null,
    val visceralFatRating: Int? = null,
    val metabolicAge: Int? = null,
    val bmi: Double? = null,
    val physiqueRating: Int? = null,
)

/**
 * Minimal FIT encoder: one `file_id` message followed by one `weight_scale` message.
 * Layout and CRC follow the Garmin FIT protocol (header without header CRC, little endian).
 */
object GarminFit {
    private const val PROFILE_VERSION = 2215
    private const val PROTOCOL_VERSION = 0x20
    private const val HEADER_SIZE = 12
    private const val FIT_EPOCH_OFFSET = 631065600L // 1989-12-31T00:00:00Z in Unix seconds
    private const val FILE_ID_MESSAGE = 0
    private const val WEIGHT_SCALE_MESSAGE = 30
    private const val LOCAL_TYPE = 0

    private const val BASE_ENUM = 0x00
    private const val BASE_UINT8 = 0x02
    private const val BASE_UINT16 = 0x84
    private const val BASE_UINT32 = 0x86
    private const val BASE_UINT32Z = 0x8C

    private const val U8_MAX = 254L
    private const val U16_MAX = 65534L

    private const val FIELD_TIMESTAMP = 253

    private val PUBLIC_ORDER = listOf(253, 0, 1, 2, 4, 5, 8, 10, 11, 12, 13)

    private val CRC_TABLE = intArrayOf(
        0x0000, 0xCC01, 0xD801, 0x1400, 0xF001, 0x3C00, 0x2800, 0xE401,
        0xA001, 0x6C00, 0x7800, 0xB401, 0x5000, 0x9C01, 0x8801, 0x4400,
    )

    private class Field(val num: Int, val baseType: Int, val size: Int, val value: Long)

    fun encode(m: GarminWeightScale): ByteArray = encode(m, PUBLIC_ORDER)

    internal fun encode(m: GarminWeightScale, fieldOrder: List<Int>): ByteArray {
        val timestamp = fitTimestamp(m.timestamp)

        val fileIdFields = listOf(
            Field(0, BASE_ENUM, 1, 9),
            Field(1, BASE_UINT16, 2, 255),
            Field(2, BASE_UINT16, 2, 0),
            Field(3, BASE_UINT32Z, 4, 0x12345678L),
            Field(4, BASE_UINT32, 4, timestamp),
            Field(5, BASE_UINT16, 2, 0),
        )
        val weightFields = orderFields(weightScaleFields(m, timestamp), fieldOrder)

        val records = ByteArrayOutputStream()
        writeDefinition(records, FILE_ID_MESSAGE, fileIdFields)
        writeData(records, fileIdFields)
        writeDefinition(records, WEIGHT_SCALE_MESSAGE, weightFields)
        writeData(records, weightFields)

        val recordBytes = records.toByteArray()
        val body = ByteArray(HEADER_SIZE + recordBytes.size + 2)
        body[0] = HEADER_SIZE.toByte()
        body[1] = PROTOCOL_VERSION.toByte()
        body[2] = (PROFILE_VERSION and 0xFF).toByte()
        body[3] = (PROFILE_VERSION shr 8).toByte()
        for (i in 0 until 4) body[4 + i] = ((recordBytes.size.toLong() shr (8 * i)) and 0xFF).toByte()
        ".FIT".toByteArray(Charsets.US_ASCII).copyInto(body, 8)
        recordBytes.copyInto(body, HEADER_SIZE)

        val fileCrc = crc(body, body.size - 2)
        body[body.size - 2] = (fileCrc and 0xFF).toByte()
        body[body.size - 1] = (fileCrc shr 8).toByte()
        return body
    }

    /** FIT CRC-16 (nibble table) over bytes[0 until len]. */
    internal fun crc(bytes: ByteArray, len: Int = bytes.size): Int {
        var crc = 0
        for (i in 0 until len) {
            val b = bytes[i].toInt() and 0xFF
            crc = crcNibble(crc, b and 0x0F)
            crc = crcNibble(crc, (b shr 4) and 0x0F)
        }
        return crc
    }

    private fun crcNibble(crc: Int, nibble: Int): Int {
        val tmp = CRC_TABLE[crc and 0x0F]
        val shifted = (crc shr 4) and 0x0FFF
        return shifted xor tmp xor CRC_TABLE[nibble]
    }

    private fun weightScaleFields(m: GarminWeightScale, timestamp: Long): List<Field> {
        val fields = mutableListOf(
            Field(0, BASE_UINT16, 2, scaled("weightKg", m.weightKg, 100.0, U16_MAX)),
        )
        m.percentFat?.let { fields += Field(1, BASE_UINT16, 2, scaled("percentFat", it, 100.0, U16_MAX)) }
        m.percentHydration?.let { fields += Field(2, BASE_UINT16, 2, scaled("percentHydration", it, 100.0, U16_MAX)) }
        m.boneMassKg?.let { fields += Field(4, BASE_UINT16, 2, scaled("boneMassKg", it, 100.0, U16_MAX)) }
        m.muscleMassKg?.let { fields += Field(5, BASE_UINT16, 2, scaled("muscleMassKg", it, 100.0, U16_MAX)) }
        m.physiqueRating?.let { fields += Field(8, BASE_UINT8, 1, scaled("physiqueRating", it.toDouble(), 1.0, U8_MAX)) }
        m.metabolicAge?.let { fields += Field(10, BASE_UINT8, 1, scaled("metabolicAge", it.toDouble(), 1.0, U8_MAX)) }
        m.visceralFatRating?.let { fields += Field(11, BASE_UINT8, 1, scaled("visceralFatRating", it.toDouble(), 1.0, U8_MAX)) }
        fields += Field(12, BASE_UINT16, 2, 0)
        m.bmi?.let { fields += Field(13, BASE_UINT16, 2, scaled("bmi", it, 10.0, U16_MAX)) }
        fields += Field(FIELD_TIMESTAMP, BASE_UINT32, 4, timestamp)
        return fields
    }

    /** Orders present fields by [fieldOrder]; listed numbers that are absent are skipped. */
    private fun orderFields(fields: List<Field>, fieldOrder: List<Int>): List<Field> {
        val byNum = fields.associateBy { it.num }
        require(byNum.keys.all { it in fieldOrder }) {
            "fieldOrder must list every present field ${byNum.keys}"
        }
        return fieldOrder.filter { it in byNum }.map { byNum.getValue(it) }
    }

    private fun scaled(name: String, value: Double, scale: Double, max: Long): Long {
        require(value.isFinite() && value >= 0.0) { "$name must be a finite, non-negative number (was $value)" }
        val stored = Math.round(value * scale)
        require(stored <= max) { "$name is out of range (scaled value $stored exceeds $max)" }
        return stored
    }

    private fun fitTimestamp(date: java.util.Date): Long {
        val seconds = Math.floorDiv(date.time, 1000L) - FIT_EPOCH_OFFSET
        require(seconds in 0L..0xFFFFFFFFL) { "timestamp is outside the FIT uint32 range (FIT seconds $seconds)" }
        return seconds
    }

    private fun writeDefinition(out: ByteArrayOutputStream, globalMessage: Int, fields: List<Field>) {
        out.write(0x40 or LOCAL_TYPE) // definition record header
        out.write(0) // reserved
        out.write(0) // architecture: little endian
        writeLe(out, globalMessage.toLong(), 2)
        out.write(fields.size)
        for (f in fields) {
            out.write(f.num)
            out.write(f.size)
            out.write(f.baseType)
        }
    }

    private fun writeData(out: ByteArrayOutputStream, fields: List<Field>) {
        out.write(LOCAL_TYPE) // data record header
        for (f in fields) writeLe(out, f.value, f.size)
    }

    private fun writeLe(out: ByteArrayOutputStream, value: Long, size: Int) {
        for (i in 0 until size) out.write(((value ushr (8 * i)) and 0xFF).toInt())
    }
}
