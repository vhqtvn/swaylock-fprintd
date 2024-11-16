/*
 * Based on fprintd util to verify a fingerprint
 * Copyright (C) 2008 Daniel Drake <dsd@gentoo.org>
 * Copyright (C) 2020 Marco Trevisan <marco.trevisan@canonical.com>
 * Copyright (C) 2023 Alexandr Lutsai <s.lyra@ya.ru>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <gio/gio.h>
#include <sys/wait.h>

#include "fingerprint.h"
#include "log.h"

static bool run_main_context(int init_id, struct FingerprintState *state, int timeout)
{
	__time_t start_time = time(NULL);
	while (time(NULL) - start_time < timeout)
	{
		g_main_context_iteration(NULL, TRUE);
		if (state != NULL && init_id != state->init_id)
		{
			return false;
		}
	}
	return true;
}

static void restart_fingerprint_usb_device_(bool full)
{
	if (full)
	{
		system("sudo /usr/local/bin/vh-special-sudo restart-fingerprint full");
	}
	else
	{
		system("sudo /usr/local/bin/vh-special-sudo restart-fingerprint");
	}
}

static int restart_count = 0;
static int last_usb_restart_time = 0;
static int last_usb_full_restart_time = 0;
static void restart_fingerprint_usb_device(bool full, bool wait)
{
	swaylock_log(LOG_DEBUG, "Restarting fingerprint device full=%d", full);
	int current_time = time(NULL);
	if (current_time - last_usb_full_restart_time < 3)
	{
		swaylock_log(LOG_DEBUG, "Skipping fingerprint device restart");
		return;
	}
	if (current_time - last_usb_restart_time < 3 || restart_count >= 1)
	{
		if (!full)
		{
			full = true;
		}
	}
	last_usb_restart_time = current_time;
	if (full)
	{
		last_usb_full_restart_time = current_time;
	}
	restart_count++;
	if (wait)
	{
		restart_fingerprint_usb_device_(full);
	}
	else
	{
		pid_t pid = fork();
		if (pid < 0)
		{
			restart_fingerprint_usb_device_(full);
			return;
		}
		if (pid == 0)
		{
			restart_fingerprint_usb_device_(full);
			exit(0);
		}
		else
		{
			__time_t start_time = time(NULL);
			while (waitpid(pid, NULL, WNOHANG) == 0 && time(NULL) - start_time < 5)
			{
				run_main_context(0, NULL, 1);
				g_usleep(100000);
			}
		}
	}
}

static bool should_disable_fingerprint(const struct FingerprintState *state)
{
	return state->fail_count >= 10 || state->restart_count >= 3;
}

static void display_message(struct FingerprintState *state, const char *fmt, ...)
{
	va_list(args);
	va_start(args, fmt);
	vsnprintf(state->status, sizeof(state->status), fmt, args);
	va_end(args);

	state->sw_state->auth_state = AUTH_STATE_FINGERPRINT;
	state->sw_state->fingerprint_msg = state->status;
	damage_state(state->sw_state);
	schedule_auth_idle(state->sw_state);
}

static void display_driver_message(struct FingerprintState *state, const char *fmt, ...)
{
	va_list(args);
	va_start(args, fmt);
	vsnprintf(state->driver_status, sizeof(state->driver_status), fmt, args);
	va_end(args);

	state->sw_state->fingerprint_driver_msg = state->driver_status;
	damage_state(state->sw_state);
	schedule_auth_idle(state->sw_state);
}

static void create_manager(struct FingerprintState *state)
{
	g_autoptr(GError) error = NULL;
	state->connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
	if (state->connection == NULL)
	{
		swaylock_log(LOG_ERROR, "Failed to connect to session bus: %s", error->message);
		display_driver_message(state, "Failed to connect to session bus: %s", error->message);
		return;
	}

	state->manager = fprint_dbus_manager_proxy_new_sync(
		state->connection,
		G_DBUS_PROXY_FLAGS_NONE,
		"net.reactivated.Fprint",
		"/net/reactivated/Fprint/Manager",
		NULL, &error);
	if (state->manager == NULL)
	{
		swaylock_log(LOG_ERROR, "Failed to get Fprintd manager: %s", error->message);
		display_driver_message(state, "Failed to get Fprintd manager: %s", error->message);
		return;
	}

	swaylock_log(LOG_DEBUG, "FPrint manager created");
}

static void destroy_manager(struct FingerprintState *state)
{
	g_clear_object(&state->manager);
	g_clear_object(&state->connection);
}

struct FingerprintStateWithInitId
{
	struct FingerprintState *state;
	int init_id;
	char *path;
	FprintDBusDevice *device;
};

static void start_verify(struct FingerprintState *state);
static void proxy_signal_cb(GDBusProxy *proxy,
							const gchar *sender_name,
							const gchar *signal_name,
							GVariant *parameters,
							gpointer user_data);
static void connect_signal_and_start_verify(struct FingerprintState *state)
{
	if (!state->device_signal_connected)
	{
		state->device_signal_connected = true;
		g_signal_connect(state->device, "g-signal", G_CALLBACK(proxy_signal_cb),
						 state);
		start_verify(state);
	}
}

static gboolean restart_verify_step_1(gpointer user_data);
static void open_device_async_device_claim_cb(GObject *source_object,
											  GAsyncResult *res,
											  gpointer data)
{
	struct FingerprintStateWithInitId *state_wrapper = data;
	if (state_wrapper->init_id != state_wrapper->state->init_id)
	{
		g_object_unref(state_wrapper->device);
		g_free(state_wrapper->path);
		g_free(state_wrapper);
		return;
	}
	GError *error = NULL;
	if (!fprint_dbus_device_call_claim_finish(state_wrapper->device, res, &error))
	{
		swaylock_log(LOG_ERROR, "failed to claim the device: %s(%d)", error->message, error->code);
		display_driver_message(state_wrapper->state, "Failed to claim the device: %s", error->message);
		if (++state_wrapper->state->claim_device_fail_count < 3)
		{
			fprint_dbus_device_call_claim(state_wrapper->device, "", NULL,
										  open_device_async_device_claim_cb,
										  state_wrapper);
			return;
		}

		restart_fingerprint_usb_device(false, false);

		struct FingerprintState *state = state_wrapper->state;
		state_wrapper->state->openning_device = 0;
		g_object_unref(state_wrapper->device);
		g_free(state_wrapper->path);
		g_free(state_wrapper);

		state->restarting = true;
		state->rebind_usb = true;
		g_timeout_add_seconds(1, restart_verify_step_1, state);
		return;
	}

	swaylock_log(LOG_DEBUG, "FPrint device opened %s", state_wrapper->path);
	state_wrapper->state->openning_device = 0;
	state_wrapper->state->device = g_steal_pointer(&state_wrapper->device);
	connect_signal_and_start_verify(state_wrapper->state);
	g_free(state_wrapper->path);
	g_free(state_wrapper);
}

static void open_device_async_device_proxy_new_cb(GObject *source_object,
												  GAsyncResult *res,
												  gpointer data)
{
	struct FingerprintStateWithInitId *state_wrapper = data;
	if (state_wrapper->init_id != state_wrapper->state->init_id)
	{
		g_free(state_wrapper->path);
		g_free(state_wrapper);
		return;
	}
	FprintDBusDevice *dev = NULL;
	GError *error = NULL;
	dev = fprint_dbus_device_proxy_new_finish(res, &error);
	if (error)
	{
		swaylock_log(LOG_ERROR, "failed to connect to device: %s (%d)", error->message, error->code);
		display_driver_message(state_wrapper->state, "Failed to connect to device: %s", error->message);
		state_wrapper->state->openning_device = 0;
		g_free(state_wrapper->path);
		g_free(state_wrapper);
		return;
	}

	display_driver_message(state_wrapper->state, "FP Claiming");
	state_wrapper->device = dev;
	fprint_dbus_device_call_claim(dev, "", NULL,
								  open_device_async_device_claim_cb,
								  state_wrapper);
}

static void open_device_async_get_default_device_cb(GObject *source_object,
													GAsyncResult *res,
													gpointer data)
{
	struct FingerprintStateWithInitId *state_wrapper = data;
	if (state_wrapper->init_id != state_wrapper->state->init_id)
	{
		g_free(state_wrapper);
		return;
	}
	char *path = NULL;
	GError *error = NULL;

	if (!fprint_dbus_manager_call_get_default_device_finish(state_wrapper->state->manager, &path, res, &error))
	{
		swaylock_log(LOG_ERROR, "open_device_async_get_default_device:Error: %s", error->message);
		g_clear_error(&error);
		display_driver_message(state_wrapper->state, "Failed to get default device");
		int ntry = ++state_wrapper->state->open_device_fail_count;
		if (ntry >= 2 && ntry <= 3)
		{
			restart_fingerprint_usb_device(ntry == 3, false);
			if (!run_main_context(state_wrapper->init_id, state_wrapper->state, 3))
			{
				g_free(state_wrapper);
				return;
			}
		}
		if (ntry < 5)
		{
			fprint_dbus_manager_call_get_default_device(state_wrapper->state->manager, NULL,
														open_device_async_get_default_device_cb,
														state_wrapper);
			return;
		}
		else
		{
			state_wrapper->state->openning_device = 0;
			g_free(state_wrapper);
			return;
		}
	}

	swaylock_log(LOG_DEBUG, "Fingerprint: using device %s after %d queries", path, state_wrapper->state->open_device_fail_count);

	display_driver_message(state_wrapper->state, "FP Proxying");
	state_wrapper->state->open_device_fail_count = 0;
	state_wrapper->path = path;
	fprint_dbus_device_proxy_new(state_wrapper->state->connection,
								 G_DBUS_PROXY_FLAGS_NONE,
								 "net.reactivated.Fprint",
								 path,
								 NULL,
								 open_device_async_device_proxy_new_cb,
								 state_wrapper);
}

static void open_device_async(struct FingerprintState *state)
{
	if (state->openning_device)
	{
		return;
	}
	int current_init_id = state->init_id;
	state->device_signal_connected = false;
	state->device = NULL;
	state->openning_device = 1;
	g_autoptr(FprintDBusDevice) dev = NULL;
	g_autoptr(GError) error = NULL;
	state->open_device_fail_count = 0;
	struct FingerprintStateWithInitId *state_wrapper = g_new(struct FingerprintStateWithInitId, 1);
	state_wrapper->state = state;
	state_wrapper->init_id = current_init_id;
	state_wrapper->path = NULL;
	state_wrapper->device = NULL;
	display_driver_message(state, "Getting default device...");
	fprint_dbus_manager_call_get_default_device(state->manager, NULL,
												open_device_async_get_default_device_cb,
												state_wrapper);
}

static void fingerprint_init2(struct FingerprintState *fingerprint_state)
{
	int current_init_id = ++fingerprint_state->init_id;
	fingerprint_state->initialized = true;
	fingerprint_state->last_signal_time = time(NULL);
	fingerprint_state->continous_unknown_error_count = 0;
	fingerprint_state->openning_device = 0;
	fingerprint_state->verifying = false;
	display_driver_message(fingerprint_state, "Initializing...");
	create_manager(fingerprint_state);
	__time_t start_time = time(NULL);
	__time_t last_try_time = start_time;
	int try_count = 1;
	while (fingerprint_state->manager == NULL || fingerprint_state->connection == NULL)
	{
		g_main_context_iteration(NULL, TRUE);
		if (current_init_id != fingerprint_state->init_id)
		{
			return;
		}
		__time_t current_time = time(NULL);
		if (try_count > 5 || current_time - start_time > 60)
		{
			swaylock_log(LOG_ERROR, "Failed to initialize fingerprint");
			display_driver_message(fingerprint_state, "Failed to initialize fingerprint");
			return;
		}
		if (current_time - last_try_time > 3)
		{
			last_try_time = current_time;
			++try_count;
			if (try_count % 2 == 0)
			{
				restart_fingerprint_usb_device(false, false);
			}
			fingerprint_state->last_signal_time = time(NULL);
			create_manager(fingerprint_state);
		}
	}
}

static gboolean restart_verify_step_2(gpointer user_data)
{
	swaylock_log(LOG_DEBUG, "Restarting verification step 2");
	struct FingerprintState *state = user_data;
	state->last_signal_time = time(NULL);
	state->restart_count++;
	state->restarting = false;
	if (!should_disable_fingerprint(state))
	{
		fingerprint_init2(state);
		display_message(state, "");
		fingerprint_verify(state);
	}
	else
	{
		if (!*state->status)
		{
			display_driver_message(state, "Disabled");
		}
	}
	return G_SOURCE_REMOVE;
}

static gboolean restart_verify_step_1(gpointer user_data)
{
	struct FingerprintState *state = user_data;
	state->last_signal_time = time(NULL);
	state->init_id++;
	swaylock_log(LOG_DEBUG, "Restarting verification step 1");
	fingerprint_deinit(state);
	state->started = 0;
	state->completed = 0;
	state->match = 0;
	if (state->rebind_usb)
	{
		state->rebind_usb = false;
		restart_fingerprint_usb_device(false, false);
	}
	g_timeout_add_seconds_full(G_PRIORITY_HIGH, 1, restart_verify_step_2, state, NULL);
	return G_SOURCE_REMOVE;
}

static void verify_result(GObject *object, const char *result, gboolean done, void *user_data)
{
	struct FingerprintState *state = user_data;
	state->last_signal_time = time(NULL);
	swaylock_log(LOG_INFO, "Verify result: %s (%s)", result, done ? "done" : "not done");

	const char *status = NULL;
	state->match = g_str_equal(result, "verify-match");
	bool should_restart = false;
	bool is_unknown = false;
	if (g_str_equal(result, "verify-retry-scan"))
	{
		state->continous_unknown_error_count = 0;
		display_message(state, "Retry");
		return;
	}
	else if (g_str_equal(result, "verify-swipe-too-short"))
	{
		state->continous_unknown_error_count = 0;
		display_message(state, "Retry, too short");
		return;
	}
	else if (g_str_equal(result, "verify-finger-not-centered"))
	{
		state->continous_unknown_error_count = 0;
		display_message(state, "Retry, not centered");
		return;
	}
	else if (g_str_equal(result, "verify-remove-and-retry"))
	{
		state->continous_unknown_error_count = 0;
		display_message(state, "Remove and retry");
		return;
	}
	else if (g_str_equal(result, "verify-unknown-error"))
	{
		if (++state->continous_unknown_error_count > 3)
		{
			should_restart = true;
		}
		is_unknown = true;
		status = "Unknown error";
	}
	else if (g_str_equal(result, "verify-disconnected"))
	{
		status = "Device disconnected";
	}
	else if (g_str_equal(result, "verify-match"))
	{
		state->continous_unknown_error_count = 0;
	}
	else if (g_str_equal(result, "verify-no-match"))
	{
		// should_restart = true;
		state->continous_unknown_error_count = 0;
		state->fail_count++;
	}
	else
	{
		status = result;
	}

	bool kill = false;
	if (should_disable_fingerprint(state))
	{
		status = "FP Disabled";
		should_restart = false;
		kill = true;
	}

	if (status)
	{
		if (state->match)
		{
			display_message(state, "FP OK: %s", status);
		}
		else if (is_unknown)
		{
			display_message(state, "FP Failed (%d): %s", state->continous_unknown_error_count, status);
		}
		else
		{
			display_message(state, "FP Failed (%d): %s", state->fail_count, status);
		}
	}
	else
	{
		if (state->match)
		{
			display_message(state, "FP OK");
		}
		else
		{
			display_message(state, "FP Failed (%d)", state->fail_count);
		}
	}

	state->completed = TRUE;
	state->verifying = FALSE;
	g_autoptr(GError) error = NULL;
	if (!fprint_dbus_device_call_verify_stop_sync(state->device, NULL, &error))
	{
		swaylock_log(LOG_ERROR, "VerifyStop failed: %s", error->message);
		display_driver_message(state, "Failed to stop verification: %s", error->message);
		return;
	}

	if (kill)
	{
		fingerprint_deinit(state);
	}
	else if (should_restart && !state->match)
	{
		__time_t current_time = time(NULL);
		if (current_time - state->last_activity_time > 60)
		{
			fingerprint_deinit(state);
			return;
		}
		swaylock_log(LOG_DEBUG, "Restarting verification");
		state->restarting = true;
		state->rebind_usb = true;
		g_timeout_add_seconds(1, restart_verify_step_1, state);
	}
}

static void verify_started_cb(GObject *obj, GAsyncResult *res, gpointer user_data)
{
	struct FingerprintState *state = user_data;
	if (!fprint_dbus_device_call_verify_start_finish(FPRINT_DBUS_DEVICE(obj), res, &state->error))
	{
		return;
	}

	swaylock_log(LOG_DEBUG, "Verify started!");
	state->started = TRUE;
	display_driver_message(state, "Scan your finger");
}

static void proxy_signal_cb(GDBusProxy *proxy,
							const gchar *sender_name,
							const gchar *signal_name,
							GVariant *parameters,
							gpointer user_data)
{
	struct FingerprintState *state = user_data;
	if (!state->started || state->restarting)
	{
		return;
	}

	if (g_str_equal(signal_name, "VerifyFingerSelected"))
	{
		return;
	}
	else if (!g_str_equal(signal_name, "VerifyStatus"))
	{
		swaylock_log(LOG_DEBUG, "Received unexpected signal %s", signal_name);
		return;
	}

	const gchar *result;
	gboolean done;
	g_variant_get(parameters, "(&sb)", &result, &done);
	verify_result(G_OBJECT(proxy), result, done, user_data);
}

static void start_verify(struct FingerprintState *state)
{
	if (should_disable_fingerprint(state))
	{
		return;
	}
	if (state->verifying || state->restarting || !state->device)
	{
		return;
	}
	state->last_start_verify_time = time(NULL);
	swaylock_log(LOG_DEBUG, "Starting verification");
	state->verifying = true;
	state->started = 0;
	state->completed = 0;
	state->match = 0;
	int current_init_id = state->init_id;
	/* This one is funny. We connect to the signal immediately to avoid
	 * race conditions. However, we must ignore any authentication results
	 * that happen before our start call returns.
	 * This is because the verify call itself may internally try to verify
	 * against fprintd (possibly using a separate account).
	 *
	 * To do so, we *must* use the async version of the verify call, as the
	 * sync version would cause the signals to be queued and only processed
	 * after it returns.
	 */
	g_autoptr(GCancellable) cancellable = g_cancellable_new();
	fprint_dbus_device_call_verify_start(state->device, "any", cancellable,
										 verify_started_cb,
										 state);

	__time_t start_time = time(NULL);
	/* Wait for verify start while discarding any VerifyStatus signals */
	while (!state->started && !state->error)
	{
		g_main_context_iteration(NULL, TRUE);
		if (current_init_id != state->init_id)
		{
			return;
		}
		if (time(NULL) - start_time > 10)
		{
			g_cancellable_cancel(cancellable);
			swaylock_log(LOG_ERROR, "VerifyStart timeout");
			display_driver_message(state, "Failed to start verification (timeout)");
			state->restarting = true;
			g_timeout_add_seconds(1, restart_verify_step_1, state);
			return;
		}
	}

	swaylock_log(LOG_DEBUG, "Verify started, state->error=%p", state->error);

	if (state->error)
	{
		swaylock_log(LOG_ERROR, "VerifyStart failed: %s", state->error->message);
		display_driver_message(state, "Failed to start verification: %s", state->error->message);
		g_clear_error(&state->error);
	}
	else if (!*state->status)
	{
		display_message(state, "...");
	}
}

static void release_callback(GObject *source_object, GAsyncResult *res,
							 gpointer user_data)
{
}

static void handle_sleep_signal(GDBusProxy *proxy,
								const gchar *sender_name,
								const gchar *signal_name,
								GVariant *parameters,
								gpointer user_data)
{
	if (g_strcmp0(signal_name, "PrepareForSleep"))
	{
		return;
	}
	struct FingerprintState *state = user_data;
	gboolean going_to_sleep;
	g_variant_get(parameters, "(b)", &going_to_sleep);

	if (!going_to_sleep)
	{ // System is resuming
		swaylock_log(LOG_DEBUG, "System resumed, restarting fingerprint verification.");
		fingerprint_deinit(state);
		restart_fingerprint_usb_device(false, true);
		fingerprint_init2(state);
	}
	else
	{
		swaylock_log(LOG_DEBUG, "System going to sleep, stopping fingerprint verification.");
		fingerprint_deinit(state);
	}
}

void fingerprint_init(struct FingerprintState *fingerprint_state,
					  struct swaylock_state *swaylock_state)
{
	memset(fingerprint_state, 0, sizeof(struct FingerprintState));
	fingerprint_state->sw_state = swaylock_state;

	fingerprint_init2(fingerprint_state);

	// Connect to the PrepareForSleep signal
	GDBusProxy *login_manager_proxy = g_dbus_proxy_new_for_bus_sync(
		G_BUS_TYPE_SYSTEM,
		G_DBUS_PROXY_FLAGS_NONE,
		NULL,
		"org.freedesktop.login1",
		"/org/freedesktop/login1",
		"org.freedesktop.login1.Manager",
		NULL, NULL);
	g_signal_connect(login_manager_proxy, "g-signal",
					 G_CALLBACK(handle_sleep_signal), fingerprint_state);
}

int fingerprint_verify(struct FingerprintState *fingerprint_state)
{
	int current_init_id = fingerprint_state->init_id;
	/* VerifyStatus signals are processing, do not wait for completion. */
	g_main_context_iteration(NULL, FALSE);
	if (current_init_id != fingerprint_state->init_id)
	{
		return false;
	}
	if (fingerprint_state->restarting)
	{
		return false;
	}

	__time_t current_time = time(NULL);
	if (fingerprint_state->flag_idle_restart)
	{
		bool force = (fingerprint_state->flag_idle_restart & 2) != 0;
		fingerprint_state->flag_idle_restart = 0;

		if (
			!should_disable_fingerprint(fingerprint_state) && !fingerprint_state->match && !fingerprint_state->restarting)
		{
			if (!fingerprint_state->initialized)
			{
				fingerprint_init2(fingerprint_state);
				// fingerprint_state->rebind_usb = true;
				// fingerprint_state->restarting = true;
				// restart_verify_step_1(fingerprint_state);
				return false;
			}
			if (current_time - fingerprint_state->last_start_verify_time > 3 && force)
			{
				fingerprint_state->rebind_usb = false;
				fingerprint_state->restarting = true;
				restart_verify_step_1(fingerprint_state);
				return false;
			}
			if (current_time - fingerprint_state->last_start_verify_time > 60)
			{
				swaylock_log(LOG_DEBUG, "run startVerify again due to idle");

				fingerprint_state->verifying = false;
				start_verify(fingerprint_state);
				return false;
			}
			if (current_time - fingerprint_state->last_signal_time > 60)
			{
				swaylock_log(LOG_DEBUG, "Restarting verification due to idle");

				fingerprint_state->rebind_usb = false;
				fingerprint_state->restarting = true;
				restart_verify_step_1(fingerprint_state);
				return false;
			}
		}
	}
	else
	{
		if (current_time - fingerprint_state->last_start_verify_time > 60 && fingerprint_state->verifying)
		{
			swaylock_log(LOG_DEBUG, "Idle verification timeout, disbaling fingerprint");
			fingerprint_deinit(fingerprint_state);
			return false;
		}
	}

	if (fingerprint_state->manager == NULL ||
		fingerprint_state->connection == NULL)
	{
		return false;
	}

	if (fingerprint_state->device == NULL)
	{
		open_device_async(fingerprint_state);
		return false;
	}

	if (!fingerprint_state->completed)
	{
		return false;
	}

	if (!fingerprint_state->match)
	{
		start_verify(fingerprint_state);
		return false;
	}

	return true;
}

static void fingerprint_close_device(struct FingerprintState *fingerprint_state)
{
	if (!fingerprint_state->device)
	{
		return;
	}

	g_signal_handlers_disconnect_by_func(fingerprint_state->device, proxy_signal_cb,
										 fingerprint_state);
	fprint_dbus_device_call_release(fingerprint_state->device, NULL, release_callback, NULL);
	fingerprint_state->device = NULL;
}

void fingerprint_deinit(struct FingerprintState *fingerprint_state)
{
	if (!fingerprint_state->match)
	{
		display_driver_message(fingerprint_state, "Press any key to reenable fingerprint");
	}
	fingerprint_state->initialized = false;
	fingerprint_state->init_id++;
	fingerprint_state->verifying = false;
	fingerprint_close_device(fingerprint_state);
	destroy_manager(fingerprint_state);
}

void fingerprint_set_restart_flag(struct FingerprintState *fingerprint_state, bool force)
{
	fingerprint_state->flag_idle_restart |= force ? 2 : 1;
	fingerprint_state->last_activity_time = time(NULL);
}