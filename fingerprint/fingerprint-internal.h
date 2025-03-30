#ifndef FINGERPRINT_INTERNAL_H
#define FINGERPRINT_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif

struct swaylock_state;
void fp_display_message(struct swaylock_state *sw_state, const char *msg);
void fp_display_driver_message(struct swaylock_state *sw_state, const char *msg);

#ifdef __cplusplus
}
#endif

#endif
