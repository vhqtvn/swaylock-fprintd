/*
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

#pragma once

// Forward declaration
struct fingerprint_state;
struct swaylock_state;

#ifdef __cplusplus
extern "C"
{
#endif

	/**
	 * Initialize the fingerprint verification system
	 *
	 * @param swaylock_state The swaylock state to update during verification
	 * @return Pointer to the internal fingerprint state
	 */
	struct fingerprint_state *fingerprint_init(struct swaylock_state *swaylock_state);

	/**
	 * Perform fingerprint verification
	 *
	 * @param fp_state Pointer to the fingerprint state
	 * @return True if verified, false otherwise
	 */
	bool fingerprint_verify(struct fingerprint_state *fp_state);

	/**
	 * Clean up and deinitialize the fingerprint system
	 * This function also frees the fingerprint_state memory.
	 * After calling this function, the fp_state pointer is no longer valid.
	 *
	 * @param fp_state Pointer to the fingerprint state
	 */
	void fingerprint_deinit(struct fingerprint_state *fp_state);

	/**
	 * Flag the fingerprint system to restart
	 *
	 * @param fp_state Pointer to the fingerprint state
	 * @param force If true, force a restart
	 */
	void fingerprint_set_restart_flag(struct fingerprint_state *fp_state, bool force);

	/**
	 * Set whether the fingerprint system is running
	 *
	 * @param fp_state Pointer to the fingerprint state
	 * @param is_running True if running, false otherwise
	 */
	void fingerprint_set_is_running(struct fingerprint_state *fp_state, bool is_running);

	/**
	 * Process pending display messages in the main thread
	 * Call this function from the main thread to ensure UI updates
	 * are properly handled in a thread-safe manner
	 *
	 * @param fp_state Pointer to the fingerprint state
	 */
	void fingerprint_process_display_messages(struct fingerprint_state *fp_state);

#ifdef __cplusplus
}
#endif