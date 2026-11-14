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
package com.health.openscale.sync.core.service

import android.content.Context
import android.content.SharedPreferences
import androidx.activity.ComponentActivity
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.livedata.observeAsState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.lifecycle.lifecycleScope
import com.health.openscale.sync.R
import com.health.openscale.sync.core.datatypes.OpenScaleMeasurement
import com.health.openscale.sync.core.model.GarminViewModel
import com.health.openscale.sync.core.model.ViewModelInterface
import com.health.openscale.sync.core.sync.GarminSync
import com.health.openscale.sync.gui.components.LocalSnackbar
import com.health.openscale.sync.gui.components.SecretOutlinedTextField
import com.health.openscale.sync.gui.components.UserScopeSection
import kotlinx.coroutines.launch
import timber.log.Timber
import java.util.Date

/**
 * Export-only Garmin Connect backend: every new openScale measurement is uploaded as a FIT
 * weight-scale file, so it shows up in Garmin Connect (and from there in Health Connect).
 */
class GarminService(
    private val context: Context,
    sharedPreferences: SharedPreferences
) : ServiceInterface(context) {
    private val viewModel = GarminViewModel(sharedPreferences)
    // One instance for the whole service: it holds the pending MFA challenge between the steps.
    private val garminSync = GarminSync(viewModel)

    override fun viewModel(): ViewModelInterface = viewModel
    override val retryQueueKey: String get() = "garmin"

    override suspend fun connect() {
        if (!viewModel.syncEnabled.value) return
        if (!viewModel.isLoggedIn()) {
            viewModel.setConnectAvailable(false)
            viewModel.setAllPermissionsGranted(false)
            setErrorMessage(context.getString(R.string.garmin_not_logged_in))
            return
        }
        when (val res = garminSync.testConnection()) {
            is SyncResult.Success -> {
                viewModel.setAllPermissionsGranted(true)
                viewModel.setConnectAvailable(true)
                clearErrorMessage()
                setInfoMessage(context.getString(R.string.garmin_successful_connected_text))
            }
            is SyncResult.Failure -> {
                viewModel.setConnectAvailable(false)
                viewModel.setAllPermissionsGranted(false)
                setErrorMessage(res)
            }
        }
    }

    override suspend fun insert(measurement: OpenScaleMeasurement): SyncResult<Unit> =
        if (viewModel.connectAvailable.value && viewModel.allPermissionsGranted.value)
            garminSync.uploadIfMissing(measurement)
        else SyncResult.Failure(SyncResult.ErrorType.PERMISSION_DENIED)

    // Add-only: an update (incl. a manual full sync) re-adds a weigh-in that is missing on Garmin,
    // e.g. deleted there, but never touches one that exists. Deletes are never mirrored (user choice);
    // so edits in openScale do not replace the Garmin entry either.
    override suspend fun update(measurement: OpenScaleMeasurement): SyncResult<Unit> = insert(measurement)
    override suspend fun delete(userId: Int, date: Date): SyncResult<Unit> = notMirrored("delete")
    override suspend fun clear(userId: Int): SyncResult<Unit> = notMirrored("clear")

    private fun notMirrored(op: String): SyncResult<Unit> {
        Timber.i("Garmin Connect: $op is not mirrored to Garmin")
        return SyncResult.Success(Unit)
    }

    @Composable
    override fun ComposeSettings(activity: ComponentActivity) {
        val showMessage = LocalSnackbar.current
        DetailScaffold(
            activity = activity,
            testConnecting = false,
            onTest = {
                activity.lifecycleScope.launch {
                    connect()
                    if (viewModel.errorMessage.value.isNullOrEmpty())
                        showMessage(context.getString(R.string.service_connection_successful))
                }
            }
        ) {
            val osUsers = remember {
                runCatching { openScaleDataService.getUsers() }.getOrDefault(emptyList())
            }
            UserScopeSection(
                isMultiUser = isMultiUser,
                users = osUsers,
                selectedUserId = viewModel.selectedUserId.value,
                onUserSelected = { viewModel.setSelectedUserId(it.id) },
                enabled = viewModel.syncEnabled.value
            )

            val enabled = viewModel.syncEnabled.value
            val emailState by viewModel.email.observeAsState("")
            val loggedIn by viewModel.loggedIn.observeAsState(false)

            if (loggedIn) {
                Text(stringResource(id = R.string.garmin_logged_in_status, emailState))
                OutlinedButton(
                    enabled = enabled,
                    modifier = Modifier.fillMaxWidth(),
                    onClick = {
                        viewModel.clearTokens()
                        viewModel.setConnectAvailable(false)
                        viewModel.setAllPermissionsGranted(false)
                        clearErrorMessage()
                    }
                ) { Text(stringResource(id = R.string.garmin_logout_button)) }
                return@DetailScaffold
            }

            Text(stringResource(id = R.string.garmin_not_logged_in))
            var email by remember { mutableStateOf(emailState) }
            var password by remember { mutableStateOf("") }
            var mfaRequired by remember { mutableStateOf(false) }
            var mfaCode by remember { mutableStateOf("") }
            var busy by remember { mutableStateOf(false) }

            fun handle(r: GarminSync.LoginResult) {
                when (r) {
                    is GarminSync.LoginResult.Success -> {
                        mfaRequired = false
                        password = ""
                        activity.lifecycleScope.launch { connect() }
                        showMessage(context.getString(R.string.garmin_login_success))
                    }
                    is GarminSync.LoginResult.MfaRequired -> mfaRequired = true
                    is GarminSync.LoginResult.Failure ->
                        setErrorMessage(context.getString(R.string.garmin_login_failed) + " (" + r.message + ")")
                }
                busy = false
            }

            OutlinedTextField(
                enabled = enabled && !busy && !mfaRequired,
                modifier = Modifier.fillMaxWidth(),
                value = email,
                onValueChange = { email = it },
                label = { Text(stringResource(id = R.string.garmin_email_title)) },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email)
            )
            SecretOutlinedTextField(
                value = password,
                onValueChange = { password = it },
                label = stringResource(id = R.string.garmin_password_title),
                enabled = enabled && !busy && !mfaRequired,
                modifier = Modifier.fillMaxWidth()
            )
            if (mfaRequired) {
                OutlinedTextField(
                    enabled = enabled && !busy,
                    modifier = Modifier.fillMaxWidth(),
                    value = mfaCode,
                    onValueChange = { mfaCode = it },
                    label = { Text(stringResource(id = R.string.garmin_mfa_code_title)) },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number)
                )
            }
            Button(
                enabled = enabled && !busy,
                modifier = Modifier.fillMaxWidth(),
                onClick = {
                    busy = true
                    clearErrorMessage()
                    activity.lifecycleScope.launch {
                        if (mfaRequired) handle(garminSync.verifyMfa(mfaCode))
                        else {
                            viewModel.setEmail(email)
                            handle(garminSync.login(email, password))
                        }
                    }
                }
            ) {
                Text(stringResource(id = if (mfaRequired) R.string.garmin_verify_button else R.string.garmin_login_button))
            }
            Text(stringResource(id = R.string.garmin_unofficial_note))
        }
    }
}
