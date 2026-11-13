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
package com.health.openscale.sync.core.model

import android.content.SharedPreferences
import androidx.core.content.edit
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import com.health.openscale.sync.R
import com.health.openscale.sync.core.sync.GarminTokens
import com.health.openscale.sync.core.sync.GarminTokenStore

/**
 * Garmin Connect settings. Only tokens are stored, never the password: the OAuth1 token is
 * long-lived and mints new OAuth2 access tokens, like the garth library does.
 */
class GarminViewModel(private val sharedPreferences: SharedPreferences) :
    ViewModelInterface(sharedPreferences), GarminTokenStore {

    companion object {
        const val EMAIL = "garmin_email"
        private const val KEY_OAUTH1_TOKEN = "garmin_oauth1_token"
        private const val KEY_OAUTH1_SECRET = "garmin_oauth1_secret"
        private const val KEY_ACCESS = "garmin_oauth2_access_token"
        private const val KEY_ACCESS_EXP_MS = "garmin_oauth2_expires_at_ms"
    }

    private val _email = MutableLiveData(sharedPreferences.getString(EMAIL, "") ?: "")
    val email: LiveData<String> = _email
    private val _loggedIn = MutableLiveData(isLoggedIn())
    val loggedIn: LiveData<Boolean> = _loggedIn

    override fun getName(): String = "Garmin Connect"
    override fun getIcon(): Int = R.drawable.ic_garmin

    fun setEmail(value: String) {
        _email.value = value
        sharedPreferences.edit { putString(EMAIL, value) }
    }

    override fun load(): GarminTokens? {
        val t1 = sharedPreferences.getString(KEY_OAUTH1_TOKEN, null) ?: return null
        val s1 = sharedPreferences.getString(KEY_OAUTH1_SECRET, null) ?: return null
        return GarminTokens(
            oauth1Token = t1,
            oauth1Secret = s1,
            accessToken = sharedPreferences.getString(KEY_ACCESS, "") ?: "",
            expiresAtMs = sharedPreferences.getLong(KEY_ACCESS_EXP_MS, 0L)
        )
    }

    override fun save(tokens: GarminTokens) {
        sharedPreferences.edit {
            putString(KEY_OAUTH1_TOKEN, tokens.oauth1Token)
            putString(KEY_OAUTH1_SECRET, tokens.oauth1Secret)
            putString(KEY_ACCESS, tokens.accessToken)
            putLong(KEY_ACCESS_EXP_MS, tokens.expiresAtMs)
        }
        _loggedIn.postValue(true)
    }

    fun isLoggedIn(): Boolean = load() != null

    fun clearTokens() {
        sharedPreferences.edit {
            remove(KEY_OAUTH1_TOKEN)
            remove(KEY_OAUTH1_SECRET)
            remove(KEY_ACCESS)
            remove(KEY_ACCESS_EXP_MS)
        }
        _loggedIn.postValue(false)
    }
}
