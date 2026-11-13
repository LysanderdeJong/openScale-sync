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

import com.google.gson.JsonParser
import com.health.openscale.sync.core.datatypes.OpenScaleMeasurement
import com.health.openscale.sync.core.service.SyncResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Cookie
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.MultipartBody
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import timber.log.Timber
import java.net.URI
import java.net.URLEncoder
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.TimeUnit
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.roundToInt

data class GarminTokens(
    val oauth1Token: String,
    val oauth1Secret: String,
    val accessToken: String,
    val expiresAtMs: Long,
)

interface GarminTokenStore {
    fun load(): GarminTokens?
    fun save(tokens: GarminTokens)
}

/**
 * Garmin Connect login and body-composition upload.
 *
 * Garmin has no public API for this, so this follows the Garmin Connect web/mobile SSO flow that
 * the garth library uses (ported from health-clis/garmin): SSO sign-in (optionally MFA) yields a
 * ticket, the ticket is exchanged for a long-lived OAuth1 token, which mints short-lived OAuth2
 * access tokens. A measurement is uploaded as a FIT weight-scale file, as Garmin's own scale does.
 * ponytail: unofficial flow, it breaks when Garmin changes SSO; the fix lives in [login] only.
 */
class GarminSync(
    private val store: GarminTokenStore,
    private val http: OkHttpClient = defaultClient,
) : SyncInterface() {

    sealed class LoginResult {
        object Success : LoginResult()
        object MfaRequired : LoginResult()
        data class Failure(val message: String) : LoginResult()
    }

    private class PendingMfa(val csrf: String, val cookies: MutableMap<String, String>, val referer: String)

    /** Held between [login] and [verifyMfa]; Garmin expires the challenge after ~10 minutes. */
    private var pendingMfa: PendingMfa? = null

    private val noRedirect: OkHttpClient by lazy { http.newBuilder().followRedirects(false).build() }

    suspend fun login(email: String, password: String): LoginResult = loginStep {
        require(email.isNotBlank() && password.isNotEmpty()) { "email and password are required" }
        val cons = consumer()
        val jar = mutableMapOf<String, String>()
        get(EMBED_URL, jar, null)
        val csrf = extractCsrf(get(SIGNIN_URL, jar, EMBED_URL))
            ?: error("failed to extract Garmin CSRF token")
        val form = mapOf("username" to email, "password" to password, "embed" to "true", "_csrf" to csrf)
        var html = followLocation(postFormManual(SIGNIN_URL, form, jar, SIGNIN_URL), SIGNIN_URL, jar)
        if (mfaRequired(html)) {
            pendingMfa = PendingMfa(extractCsrf(html) ?: error("failed to extract Garmin MFA CSRF token"), jar, SIGNIN_URL)
            return@loginStep LoginResult.MfaRequired
        }
        if (html.contains("var status = \"LOCKED\"")) error("Garmin account is locked")
        finishLogin(html, cons, jar)
    }

    suspend fun verifyMfa(code: String): LoginResult = loginStep {
        val pending = pendingMfa ?: error("no pending Garmin MFA challenge, log in again")
        val cons = consumer()
        val form = mapOf("mfa-code" to code.trim(), "embed" to "true", "_csrf" to pending.csrf, "fromPage" to "setupEnterMfaCode")
        val html = followLocation(postFormManual(MFA_URL, form, pending.cookies, pending.referer), MFA_URL, pending.cookies)
        if (mfaRequired(html) || loginError(html)) error("Garmin MFA verification failed")
        pendingMfa = null
        finishLogin(html, cons, pending.cookies)
    }

    /** Checks the stored session against Garmin, refreshing the access token if needed. */
    suspend fun testConnection(): SyncResult<Unit> = wire {
        val req = Request.Builder().url("$CONNECT_API/userprofile-service/socialProfile")
            .header("Authorization", "Bearer ${accessToken()}").header("User-Agent", USER_AGENT)
            .header("NK", "NT").build()
        http.newCall(req).execute().use { resp -> resultOf(resp, "Garmin profile check") }
    }

    suspend fun upload(measurement: OpenScaleMeasurement): SyncResult<Unit> = wire {
        val fit = GarminFit.encode(toWeightScale(measurement))
        val body = MultipartBody.Builder().setType(MultipartBody.FORM)
            .addFormDataPart("file", "body-composition.fit", fit.toRequestBody("application/octet-stream".toMediaType()))
            .build()
        val req = Request.Builder().url("$CONNECT_API/upload-service/upload/.fit").post(body)
            .header("Authorization", "Bearer ${accessToken()}")
            .header("Accept", "application/json,text/plain,*/*").header("User-Agent", USER_AGENT)
            .header("NK", "NT").header("Origin", "https://sso.garmin.com").build()
        http.newCall(req).execute().use { resp -> resultOf(resp, "Garmin FIT upload") }
    }

    // --- login internals -----------------------------------------------------------------

    private fun finishLogin(html: String, cons: Pair<String, String>, jar: Map<String, String>): LoginResult {
        val ticket = extractTicket(html)
            ?: error(if (loginError(html)) "invalid Garmin credentials" else "failed to extract Garmin login ticket")
        val query = formEncode(mapOf("ticket" to ticket, "login-url" to EMBED_BASE, "accepts-mfa-tokens" to "true"))
        val auth = oauthHeader("GET", PREAUTH_URL, cons, null, mapOf("ticket" to ticket, "login-url" to EMBED_BASE, "accepts-mfa-tokens" to "true"))
        val params = parseForm(oauthRequest("GET", "$PREAUTH_URL?$query", auth, cookieHeader(jar)))
        val token = params["oauth_token"].orEmpty()
        val secret = params["oauth_token_secret"].orEmpty()
        if (token.isEmpty() || secret.isEmpty()) error("Garmin OAuth1 response missing token")
        store.save(exchangeOAuth2(token, secret, cons))
        return LoginResult.Success
    }

    /** Valid OAuth2 access token; mints a new one from the OAuth1 token when it (nearly) expired. */
    private fun accessToken(): String {
        val t = store.load() ?: error("not logged in to Garmin Connect")
        if (t.accessToken.isNotEmpty() && t.expiresAtMs > System.currentTimeMillis() + 60_000) return t.accessToken
        return exchangeOAuth2(t.oauth1Token, t.oauth1Secret, consumer()).also(store::save).accessToken
    }

    private fun exchangeOAuth2(token: String, secret: String, cons: Pair<String, String>): GarminTokens {
        val auth = oauthHeader("POST", EXCHANGE_URL, cons, token to secret, emptyMap())
        val json = JsonParser.parseString(oauthRequest("POST", EXCHANGE_URL, auth, "")).asJsonObject
        val access = json.get("access_token")?.asString.orEmpty()
        if (access.isEmpty()) error("Garmin OAuth2 response missing access token")
        val expiresIn = json.get("expires_in")?.asLong ?: 0L
        return GarminTokens(token, secret, access, System.currentTimeMillis() + expiresIn * 1000)
    }

    /** OAuth1 consumer key/secret that the Garmin Connect app uses, published by garth. */
    private fun consumer(): Pair<String, String> {
        val req = Request.Builder().url(CONSUMER_URL).build()
        val json = http.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) error("Garmin consumer credential fetch failed: HTTP ${resp.code}")
            JsonParser.parseString(resp.body.string()).asJsonObject
        }
        val key = json.get("consumer_key")?.asString.orEmpty()
        val secret = json.get("consumer_secret")?.asString.orEmpty()
        if (key.isEmpty() || secret.isEmpty()) error("Garmin consumer credentials are incomplete")
        return key to secret
    }

    private fun get(url: String, jar: MutableMap<String, String>, referer: String?): String {
        val b = Request.Builder().url(url).header("User-Agent", USER_AGENT)
            .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
        referer?.let { b.header("Referer", it) }
        cookieHeader(jar).takeIf { it.isNotEmpty() }?.let { b.header("Cookie", it) }
        return http.newCall(b.build()).execute().use { resp ->
            addCookies(resp, jar)
            if (!resp.isSuccessful) error("Garmin request failed: HTTP ${resp.code}")
            resp.body.string()
        }
    }

    /** POST without following redirects; returns body and Location. */
    private fun postFormManual(url: String, form: Map<String, String>, jar: MutableMap<String, String>, referer: String): Pair<String, String?> {
        val b = Request.Builder().url(url)
            .post(formEncode(form).toRequestBody("application/x-www-form-urlencoded".toMediaType()))
            .header("User-Agent", USER_AGENT).header("Origin", "https://sso.garmin.com").header("Referer", referer)
        cookieHeader(jar).takeIf { it.isNotEmpty() }?.let { b.header("Cookie", it) }
        return noRedirect.newCall(b.build()).execute().use { resp ->
            addCookies(resp, jar)
            resp.body.string() to resp.header("Location")
        }
    }

    private fun followLocation(result: Pair<String, String?>, base: String, jar: MutableMap<String, String>): String {
        val location = result.second ?: return result.first
        return get(URI(base).resolve(location).toString(), jar, base)
    }

    private fun oauthRequest(method: String, url: String, authHeader: String, cookie: String): String {
        val b = Request.Builder().url(url).header("User-Agent", USER_AGENT).header("Authorization", authHeader)
        if (cookie.isNotEmpty()) b.header("Cookie", cookie)
        if (method == "POST") b.post("".toRequestBody("application/x-www-form-urlencoded".toMediaType()))
        return http.newCall(b.build()).execute().use { resp ->
            val body = resp.body.string()
            if (!resp.isSuccessful) error("Garmin OAuth request failed: HTTP ${resp.code}")
            body
        }
    }

    private suspend fun loginStep(block: suspend () -> LoginResult): LoginResult = withContext(Dispatchers.IO) {
        try {
            block()
        } catch (e: Exception) {
            Timber.w(e, "Garmin login failed")
            LoginResult.Failure(e.message ?: e.javaClass.simpleName)
        }
    }

    private suspend fun wire(block: () -> SyncResult<Unit>): SyncResult<Unit> = withContext(Dispatchers.IO) {
        try {
            block()
        } catch (e: Exception) {
            SyncResult.Failure(SyncResult.ErrorType.UNKNOWN_ERROR, e.message, e)
        }
    }

    private fun resultOf(resp: Response, what: String): SyncResult<Unit> = when {
        resp.isSuccessful -> SyncResult.Success(Unit)
        resp.code == 401 || resp.code == 403 ->
            SyncResult.Failure(SyncResult.ErrorType.PERMISSION_DENIED, "$what: Garmin rejected the login (HTTP ${resp.code})")
        else -> SyncResult.Failure(SyncResult.ErrorType.API_ERROR, "$what failed: HTTP ${resp.code} ${resp.body.string().take(200)}")
    }

    companion object {
        private const val CONNECT_API = "https://connectapi.garmin.com"
        private const val EMBED_BASE = "https://sso.garmin.com/sso/embed"
        private const val PREAUTH_URL = "$CONNECT_API/oauth-service/oauth/preauthorized"
        private const val EXCHANGE_URL = "$CONNECT_API/oauth-service/oauth/exchange/user/2.0"
        private const val CONSUMER_URL = "https://thegarth.s3.amazonaws.com/oauth_consumer.json"
        private const val USER_AGENT =
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

        private val EMBED_URL = "$EMBED_BASE?" + formEncode(mapOf("id" to "gauth-widget", "embedWidget" to "true", "gauthHost" to EMBED_BASE))
        private val SIGNIN_QUERY = formEncode(
            mapOf("id" to "gauth-widget", "embedWidget" to "true", "gauthHost" to EMBED_BASE, "service" to EMBED_BASE,
                "source" to EMBED_BASE, "redirectAfterAccountLoginUrl" to EMBED_BASE, "redirectAfterAccountCreationUrl" to EMBED_BASE)
        )
        internal val SIGNIN_URL = "https://sso.garmin.com/sso/signin?$SIGNIN_QUERY"
        private val MFA_URL = "https://sso.garmin.com/sso/verifyMFA/loginEnterMfaCode?$SIGNIN_QUERY"

        private val defaultClient = OkHttpClient.Builder().callTimeout(30, TimeUnit.SECONDS).build()
        private val random = SecureRandom()

        /** Garmin body composition from an openScale measurement; masses are sent in kg. */
        internal fun toWeightScale(m: OpenScaleMeasurement): GarminWeightScale {
            fun value(key: String) = m.values.firstOrNull { it.isBuiltin(key) }
            fun kg(key: String): Double? {
                val v = value(key) ?: return null
                val x = v.value ?: return null
                return when (v.unit) {
                    "kg" -> x.toDouble()
                    "%" -> x.toDouble() * m.weight / 100.0
                    else -> null
                }
            }
            return GarminWeightScale(
                timestamp = m.date,
                weightKg = m.weight.toDouble(),
                percentFat = m.body_fat?.toDouble(),
                percentHydration = m.water?.toDouble(),
                boneMassKg = kg("BONE"),
                // openScale's MUSCLE is skeletal muscle, which is what Garmin's muscle mass shows.
                muscleMassKg = kg("MUSCLE"),
                visceralFatRating = value("VISCERAL_FAT")?.value?.roundToInt()?.takeIf { it in 1..59 },
                bmi = value("BMI")?.value?.toDouble(),
                // Body age; the identity scale drivers share for it (ble.metabolic_age).
                metabolicAge = m.values.firstOrNull { it.identity == "ble.metabolic_age" }
                    ?.value?.roundToInt()?.takeIf { it in 1..254 },
            )
        }

        /** Go's url.Values.Encode: keys sorted, query-escaped, spaces as '+'. */
        internal fun formEncode(values: Map<String, String>): String =
            values.toSortedMap().entries.joinToString("&") { (k, v) -> queryEscape(k) + "=" + queryEscape(v) }

        /** Go's url.QueryEscape. */
        private fun queryEscape(s: String): String =
            URLEncoder.encode(s, "UTF-8").replace("*", "%2A").replace("%7E", "~")

        /** RFC 3986 encoding for OAuth1 signatures. */
        internal fun percentEncode(s: String): String = queryEscape(s).replace("+", "%20")

        /** OAuth1 HMAC-SHA1 header, as in health-clis' oauthHeader; [nonce]/[timestamp] fixed only in tests. */
        internal fun oauthHeader(
            method: String,
            url: String,
            cons: Pair<String, String>,
            token: Pair<String, String>?,
            extra: Map<String, String>,
            nonce: String = ByteArray(16).also(random::nextBytes).joinToString("") { "%02x".format(it) },
            timestamp: Long = System.currentTimeMillis() / 1000,
        ): String {
            val oauth = sortedMapOf(
                "oauth_consumer_key" to cons.first,
                "oauth_nonce" to nonce,
                "oauth_signature_method" to "HMAC-SHA1",
                "oauth_timestamp" to timestamp.toString(),
                "oauth_version" to "1.0",
            )
            token?.let { oauth["oauth_token"] = it.first }
            val params = (oauth + extra).toSortedMap().entries
                .joinToString("&") { (k, v) -> percentEncode(k) + "=" + percentEncode(v) }
            val base = listOf(method.uppercase(), percentEncode(url), percentEncode(params)).joinToString("&")
            val key = percentEncode(cons.second) + "&" + percentEncode(token?.second.orEmpty())
            val mac = Mac.getInstance("HmacSHA1").apply { init(SecretKeySpec(key.toByteArray(), "HmacSHA1")) }
            oauth["oauth_signature"] = Base64.getEncoder().encodeToString(mac.doFinal(base.toByteArray()))
            return "OAuth " + oauth.entries.joinToString(", ") { (k, v) -> "${percentEncode(k)}=\"${percentEncode(v)}\"" }
        }

        internal fun extractCsrf(html: String): String? =
            Regex("""name="_csrf"\s+value="([^"]+)"""").find(html)?.groupValues?.get(1)

        internal fun extractTicket(html: String): String? =
            Regex("""ticket=([^"&\s]+)""").find(html)?.groupValues?.get(1)

        internal fun mfaRequired(html: String): Boolean {
            val lower = html.lowercase()
            return "multi-factor authentication required" in lower || "enter your verification code" in lower ||
                "loginentermfacode" in lower || "name=\"mfa-code\"" in html
        }

        private fun loginError(html: String): Boolean {
            val lower = html.lowercase()
            return "invalid" in lower || "incorrect" in lower || "username and password did not match" in lower ||
                "name=\"username\"" in html || "name=\"password\"" in html
        }

        private fun parseForm(body: String): Map<String, String> = body.split("&").mapNotNull {
            val i = it.indexOf('=')
            if (i < 0) null else java.net.URLDecoder.decode(it.substring(0, i), "UTF-8") to java.net.URLDecoder.decode(it.substring(i + 1), "UTF-8")
        }.toMap()

        private fun cookieHeader(jar: Map<String, String>): String =
            jar.map { (k, v) -> "$k=$v" }.sorted().joinToString("; ")

        /** Records cookies of the final response only, as health-clis' cookieJar does. */
        private fun addCookies(resp: Response, jar: MutableMap<String, String>) {
            resp.headers("Set-Cookie").mapNotNull { Cookie.parse(resp.request.url, it) }
                .filter { it.name.isNotEmpty() && it.value.isNotEmpty() }
                .forEach { jar[it.name] = it.value }
        }
    }
}
