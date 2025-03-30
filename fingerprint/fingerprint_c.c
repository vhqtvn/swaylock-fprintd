#include "fingerprint-internal.h"
#include "swaylock.h"
#include "log.h"

void fp_display_message(struct swaylock_state *sw_state, const char *msg)
{
	swaylock_log(LOG_DEBUG, "Display message: %s", msg);
	sw_state->auth_state = AUTH_STATE_FINGERPRINT;
	sw_state->fingerprint_msg = msg;
	damage_state(sw_state);
	schedule_auth_idle(sw_state);
}

void fp_display_driver_message(struct swaylock_state *sw_state, const char *msg)
{
	swaylock_log(LOG_DEBUG, "Display driver message: %s", msg);
	sw_state->fingerprint_driver_msg = msg;
	damage_state(sw_state);
	schedule_auth_idle(sw_state);
}
