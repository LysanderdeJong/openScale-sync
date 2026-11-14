/*
 *  Copyright (C) 2026  Lysander de Jong
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

import com.health.openscale.sync.core.datatypes.OpenScaleMeasurement
import com.health.openscale.sync.core.datatypes.OpenScaleMeasurementValue
import com.health.openscale.sync.core.service.SyncResult
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import okio.Buffer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Date

/**
 * The Garmin login helpers must produce exactly what health-clis/garmin (Go) sends; the expected
 * strings below are that program's output. The upload is checked against a faked transport.
 */
class GarminSyncTest {

    @Test
    fun `form encoding matches Go url Values Encode`() {
        assertEquals(
            "_csrf=CSRF&embed=true&password=p+w%26x&username=a%40b.c",
            GarminSync.formEncode(mapOf("username" to "a@b.c", "password" to "p w&x", "embed" to "true", "_csrf" to "CSRF"))
        )
        assertEquals("~%2A%27%28%29%21", GarminSync.percentEncode("~*'()!"))
    }

    @Test
    fun `sign-in URL matches the Go client`() {
        assertEquals(
            "https://sso.garmin.com/sso/signin?embedWidget=true&gauthHost=https%3A%2F%2Fsso.garmin.com%2Fsso%2Fembed&id=gauth-widget&redirectAfterAccountCreationUrl=https%3A%2F%2Fsso.garmin.com%2Fsso%2Fembed&redirectAfterAccountLoginUrl=https%3A%2F%2Fsso.garmin.com%2Fsso%2Fembed&service=https%3A%2F%2Fsso.garmin.com%2Fsso%2Fembed&source=https%3A%2F%2Fsso.garmin.com%2Fsso%2Fembed",
            GarminSync.SIGNIN_URL
        )
    }

    @Test
    fun `OAuth1 signature matches the published HMAC-SHA1 example`() {
        // Twitter's "Creating a signature" worked example (RFC 5849 HMAC-SHA1).
        val header = GarminSync.oauthHeader(
            method = "POST",
            url = "https://api.twitter.com/1.1/statuses/update.json",
            cons = "xvz1evFS4wEEPTGEFPHBog" to "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw",
            token = "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb" to "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE",
            extra = mapOf("include_entities" to "true", "status" to "Hello Ladies + Gentlemen, a signed OAuth request!"),
            nonce = "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg",
            timestamp = 1318622958L,
        )
        assertTrue(header, header.contains("oauth_signature=\"hCtSmYh%2BiHYCEqBWrE7C7hYmtUk%3D\""))
        assertTrue(header.startsWith("OAuth oauth_consumer_key=\"xvz1evFS4wEEPTGEFPHBog\", oauth_nonce="))
    }

    @Test
    fun `extracts CSRF token, ticket and MFA challenge from SSO pages`() {
        assertEquals("abc-123", GarminSync.extractCsrf("""<input type="hidden" name="_csrf"  value="abc-123" />"""))
        assertEquals("ST-0123-abc-cas", GarminSync.extractTicket("""var url = "https://sso.garmin.com/sso/embed?ticket=ST-0123-abc-cas";"""))
        assertNull(GarminSync.extractTicket("<html>no ticket</html>"))
        assertTrue(GarminSync.mfaRequired("""<form><input name="mfa-code"></form>"""))
    }

    @Test
    fun `maps openScale values to Garmin body composition in kg`() {
        val m = measurement()
        val w = GarminSync.toWeightScale(m)
        assertEquals(80.0, w.weightKg, 1e-6)
        assertEquals(20.0, w.percentFat!!, 1e-6)
        assertEquals(55.0, w.percentHydration!!, 1e-6)
        assertEquals(3.2, w.boneMassKg!!, 1e-6)      // kg passes through
        assertEquals(40.0, w.muscleMassKg!!, 1e-4)   // 50 % of 80 kg
        assertEquals(7, w.visceralFatRating)
        assertEquals(24.7, w.bmi!!, 1e-4)
        assertNull(w.metabolicAge) // Garmin Connect mis-renders it, so it is never sent
        assertEquals(m.date, w.timestamp)
    }

    @Test
    fun `uploads the FIT file with the stored access token`() = runTest {
        var sent: Request? = null
        val sync = GarminSync(validTokens(), fakeHttp { sent = it; 200 })

        assertEquals(SyncResult.Success(Unit), sync.uploadIfMissing(measurement()))

        val req = sent!!
        assertEquals("https://connectapi.garmin.com/upload-service/upload/.fit", req.url.toString())
        assertEquals("Bearer access-1", req.header("Authorization"))
        assertEquals("NT", req.header("NK"))
        val body = Buffer().also { req.body!!.writeTo(it) }.readByteArray()
        val text = String(body, Charsets.ISO_8859_1)
        assertTrue(text.contains("name=\"file\"; filename=\"body-composition.fit\""))
        assertTrue(text.contains(".FIT"))
    }

    @Test
    fun `a rejected token is reported as permission denied`() = runTest {
        val res = GarminSync(validTokens(), fakeHttp { 401 }).uploadIfMissing(measurement())
        assertEquals(SyncResult.ErrorType.PERMISSION_DENIED, (res as SyncResult.Failure).errorType)
    }

    @Test
    fun `skips the upload when Garmin already has a weigh-in at that second`() = runTest {
        val urls = mutableListOf<String>()
        val dayview = """{"dateWeightList":[{"samplePk":1,"timestampGMT":1767943800000,"weight":80000}]}"""
        val http = OkHttpClient.Builder().addInterceptor { chain ->
            urls += chain.request().url.encodedPath
            Response.Builder().request(chain.request()).protocol(Protocol.HTTP_1_1).code(200).message("x")
                .body(dayview.toResponseBody()).build()
        }.build()

        assertEquals(SyncResult.Success(Unit), GarminSync(validTokens(), http).uploadIfMissing(measurement()))
        assertEquals(listOf("/weight-service/weight/dayview/2026-01-09"), urls)
    }

    @Test
    fun `reads weigh-in times from a dayview response`() {
        assertEquals(
            setOf(1767943800L, 1767950000L),
            GarminSync.weighInSeconds("""{"dateWeightList":[{"timestampGMT":1767943800000},{"timestampGMT":1767950000999},{"timestampGMT":null}]}""")
        )
        assertEquals(emptySet<Long>(), GarminSync.weighInSeconds("{}"))
    }

    private fun measurement() = OpenScaleMeasurement.fromValues(
        1, 1, Date(1_767_943_800_000L), "u",
        listOf(
            OpenScaleMeasurementValue("builtin.weight", "Weight", "kg", false, 80f),
            OpenScaleMeasurementValue("builtin.body_fat", "Fat", "%", false, 20f),
            OpenScaleMeasurementValue("builtin.water", "Water", "%", false, 55f),
            OpenScaleMeasurementValue("builtin.bone", "Bone", "kg", false, 3.2f),
            OpenScaleMeasurementValue("builtin.muscle", "Muscle", "%", false, 50f),
            OpenScaleMeasurementValue("builtin.visceral_fat", "Visceral fat", "", false, 7.4f),
            OpenScaleMeasurementValue("builtin.bmi", "BMI", "kg/m2", true, 24.7f),
            OpenScaleMeasurementValue("ble.metabolic_age", "Metabolic age", "", false, 25f),
            // Not a Garmin field; must not leak into muscle mass.
            OpenScaleMeasurementValue("ble.total_muscle", "Total muscle", "%", false, 80f),
        )
    )

    private fun validTokens() = object : GarminTokenStore {
        override fun load() = GarminTokens("t1", "s1", "access-1", System.currentTimeMillis() + 3_600_000)
        override fun save(tokens: GarminTokens) = error("no refresh expected")
    }

    private fun fakeHttp(respond: (Request) -> Int) = OkHttpClient.Builder().addInterceptor { chain ->
        val code = respond(chain.request())
        Response.Builder().request(chain.request()).protocol(Protocol.HTTP_1_1).code(code).message("x")
            .body("{}".toResponseBody()).build()
    }.build()
}
