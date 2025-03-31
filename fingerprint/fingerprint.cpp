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

#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <memory>
#include <functional>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <map>
#include <unordered_map>
#include <atomic>
#include <sys/wait.h>
#include <string>
#include <algorithm>
#include <vector>

#include "fingerprint.h"
#include "fingerprint-internal.h"
extern "C"
{
#include <gio/gio.h>
#include "fingerprint/fprintd-dbus.h"
#include "log.h"
}
// Maximum attempts before disabling fingerprint
constexpr int MAX_FAIL_COUNT = 10;
constexpr int MAX_RESTART_COUNT = 3;
constexpr int MAX_UNKNOWN_ERROR_COUNT = 3;

// Event system to handle all GLib tasks in a dedicated thread
class EventLoop
{
private:
    std::atomic<bool> main_loop_running{false};
    std::atomic<bool> running{false};
    std::thread worker_thread;
    std::mutex mutex;
    GMainContext* main_context{nullptr};
    GMainLoop* main_loop{nullptr};
    std::atomic<size_t> next_id{0};
    using EventCallback = std::function<void()>;
    std::unordered_map<size_t, EventCallback> callbacks;
    std::mutex callbacks_mutex;

public:
    EventLoop() = default;

    ~EventLoop()
    {
        stop();
        callbacks.clear();
    }

    void start()
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (running)
        {
            return;
        }

        running = true;
        main_context = g_main_context_new();
        main_loop = g_main_loop_new(main_context, FALSE);
        worker_thread = std::thread(&EventLoop::run, this);
        worker_thread.detach();
    }

    void stop()
    {
        {
            std::lock_guard<std::mutex> lock(mutex);
            if (!running)
            {
                return;
            }

            swaylock_log(LOG_DEBUG, "FP EventLoop::stop: quitting main loop");
            if (main_loop)
            {
                g_main_loop_quit(main_loop);
            }
        }

        if (worker_thread.joinable())
        {
            try
            {
                worker_thread.join();
            }
            catch (const std::exception &e)
            {
                swaylock_log(LOG_DEBUG, "FP EventLoop::stop: worker thread join failed: %s", e.what());
            }
            catch (...)
            {
                swaylock_log(LOG_DEBUG, "FP EventLoop::stop: worker thread join failed");
            }
        }

        {
            std::lock_guard<std::mutex> lock(mutex);
            if (main_loop)
            {
                g_main_loop_unref(main_loop);
                main_loop = nullptr;
            }
            if (main_context)
            {
                g_main_context_unref(main_context);
                main_context = nullptr;
            }
        }

        swaylock_log(LOG_DEBUG, "FP EventLoop::stop: done");
    }

    void post(EventCallback callback)
    {
        postDelayed(0, std::move(callback));
    }

    void postDelayed(int milliseconds, EventCallback callback)
    {
        size_t id = next_id++;
        {
            std::lock_guard<std::mutex> lock(callbacks_mutex);
            callbacks[id] = std::move(callback);
        }

        struct TimeoutData
        {
            EventLoop *self;
            size_t id;
        };

        auto *data = new TimeoutData{this, id};
        GSource *source = g_timeout_source_new(milliseconds);
        g_source_set_callback(source, [](void *user_data) -> gboolean
                             {
            auto *data = static_cast<TimeoutData *>(user_data);
            data->self->executeCallback(data->id);
            delete data;
            return FALSE; }, data, nullptr);
        g_source_attach(source, main_context);
        g_source_unref(source);
    }

    void postSyncImmediately(EventCallback callback)
    {
        bool run_immediately = false;
        {
            std::lock_guard<std::mutex> lock(mutex);
            if (!running)
            {
                run_immediately = true;
            }
        }

        if (run_immediately)
        {
            executeCallbackSafely(std::move(callback));
            return;
        }

        std::condition_variable sync_cv;
        bool completed = false;
        std::mutex sync_mutex;

        auto wrapper = [callback = std::move(callback), &sync_cv, &completed, &sync_mutex]()
        {
            executeCallbackSafely(callback);
            std::lock_guard<std::mutex> lock(sync_mutex);
            completed = true;
            sync_cv.notify_one();
        };

        GSource *source = g_timeout_source_new(0);
        g_source_set_priority(source, G_PRIORITY_HIGH);
        g_source_set_callback(source, [](void *data) -> gboolean
                             {
            auto *callback = static_cast<EventCallback *>(data);
            (*callback)();
            delete callback;
            return FALSE; }, new EventCallback(std::move(wrapper)), nullptr);
        g_source_attach(source, main_context);
        g_source_unref(source);

        std::unique_lock<std::mutex> lock(sync_mutex);
        for (int i = 0; i < 50; i++)
        {
            if (sync_cv.wait_for(lock, std::chrono::milliseconds(100), [&completed]
                                 { return completed; }))
            {
                return;
            }
            if (!main_loop_running.load())
            {
                break;
            }
        }

        if (!main_loop_running.load() && !completed)
        {
            executeCallbackSafely(std::move(callback));
        }
    }

private:
    void run()
    {
        main_loop_running.store(true);
        swaylock_log(LOG_DEBUG, "FP EventLoop running");
        g_main_context_push_thread_default(main_context);
        g_main_loop_run(main_loop);
        swaylock_log(LOG_DEBUG, "FP EventLoop stopped");
        main_loop_running.store(false);
    }

    void executeCallback(size_t id)
    {
        EventCallback callback;
        {
            std::lock_guard<std::mutex> lock(callbacks_mutex);
            auto it = callbacks.find(id);
            if (it != callbacks.end())
            {
                callback = std::move(it->second);
                callbacks.erase(it);
            }
        }
        if (callback)
        {
            executeCallbackSafely(std::move(callback));
        }
    }

    static void executeCallbackSafely(EventCallback callback)
    {
        try
        {
            callback();
        }
        catch (const std::exception &e)
        {
            swaylock_log(LOG_DEBUG, "FP EventLoop::executeCallbackSafely: callback failed: %s", e.what());
        }
        catch (...)
        {
            swaylock_log(LOG_DEBUG, "FP EventLoop::executeCallbackSafely: callback failed");
        }
    }
};

class FingerprintManager
{
private:
    struct swaylock_state *sw_state;
    
    // State flags
    std::atomic<bool> is_running{true};
    std::atomic<bool> initialized{false};
    std::atomic<bool> rebind_usb{false};
    std::atomic<bool> restarting{false};
    std::atomic<bool> started{false};
    std::atomic<bool> completed{false};
    std::atomic<bool> match{false};
    std::atomic<bool> verifying{false};
    std::atomic<bool> device_signal_connected{false};
    std::atomic<bool> device_opening{false};
    std::atomic<bool> manager_creating{false};

    // Message handling
    struct DisplayMessage {
        std::string message;
        bool updated;
    };
    std::mutex message_mutex;
    DisplayMessage latest_message{std::string(), false};
    DisplayMessage latest_driver_message{std::string(), false};

    // Counters and timers
    std::atomic<int> init_id{0};
    std::atomic<int> continuous_unknown_error_count{0};
    std::atomic<int> fail_count{0};
    std::atomic<int> restart_count{0};
    std::atomic<int> flag_idle_restart{0};
    std::atomic<time_t> last_signal_time{0};
    std::atomic<time_t> last_start_verify_time{0};
    std::atomic<time_t> last_activity_time{0};

    // Status buffers
    char status[128]{};
    char driver_status[128]{};

    // D-Bus resources
    GDBusConnection* connection{nullptr};
    FprintDBusManager* manager{nullptr};
    FprintDBusDevice* device{nullptr};
    GError* error{nullptr};

    // Static members
    static std::atomic<int> restart_count_static;
    static std::atomic<time_t> last_usb_restart_time;
    static std::atomic<time_t> last_usb_full_restart_time;

    // Event loop
    EventLoop event_loop;

    // Operation tracking
    class ClaimOperation {
    public:
        FingerprintManager* state;
        int init_id;
        char* path;
        FprintDBusDevice* device;

        ClaimOperation(FingerprintManager* state, int init_id)
            : state(state), init_id(init_id), path(nullptr), device(nullptr) {}

        ~ClaimOperation() {
            g_free(path);
            if (device) {
                g_object_unref(device);
            }
        }
    };

    // Helper functions
    void displayMessage(const char* fmt, ...) {
        va_list args;
        va_start(args, fmt);
        char buffer[256];
        vsnprintf(buffer, sizeof(buffer), fmt, args);
        va_end(args);

        std::lock_guard<std::mutex> lock(message_mutex);
        latest_message.message = buffer;
        latest_message.updated = true;
    }

    void displayDriverMessage(const char* fmt, ...) {
        va_list args;
        va_start(args, fmt);
        char buffer[256];
        vsnprintf(buffer, sizeof(buffer), fmt, args);
        va_end(args);

        std::lock_guard<std::mutex> lock(message_mutex);
        latest_driver_message.message = buffer;
        latest_driver_message.updated = true;
    }

    bool shouldDisableFingerprint() const {
        return fail_count >= MAX_FAIL_COUNT || restart_count >= MAX_RESTART_COUNT;
    }

    bool sleepFor(int check_init_id, int seconds) {
        for (int i = 0; i < seconds && check_init_id == init_id; i++) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        return check_init_id == init_id;
    }

    static void restartFingerprintUsbDevice_(bool full) {
        if (full) {
            system("sudo /usr/local/bin/vh-special-sudo restart-fingerprint full");
        } else {
            system("sudo /usr/local/bin/vh-special-sudo restart-fingerprint");
        }
    }

    static void forceKill(pid_t pid) {
        kill(pid, SIGKILL);
        for (int i = 0; i < 10; i++) {
            if (waitpid(pid, nullptr, WNOHANG)) {
                return;
            }
            g_usleep(100000);
        }
        kill(pid, SIGTERM);
        waitpid(pid, nullptr, 0);
    }

    void restartFingerprintUsbDevice(bool full, bool wait) {
        swaylock_log(LOG_DEBUG, "Restarting fingerprint device full=%d", full);
        time_t current_time = time(nullptr);

        if (current_time - last_usb_full_restart_time < 3) {
            swaylock_log(LOG_DEBUG, "Skipping fingerprint device restart");
            return;
        }

        if (current_time - last_usb_restart_time < 3 || restart_count_static >= 1) {
            if (!full) {
                full = true;
            }
        }

        last_usb_restart_time = current_time;
        if (full) {
            last_usb_full_restart_time = current_time;
        }

        restart_count_static++;
        int max_wait_time = wait ? 120 : 5;

        pid_t pid = fork();
        if (pid < 0) {
            restartFingerprintUsbDevice_(full);
            return;
        }

        if (pid == 0) {
            restartFingerprintUsbDevice_(full);
            swaylock_log(LOG_DEBUG, "Fingerprint device restarted");
            exit(0);
        } else {
            std::thread wait_thread([this, pid, max_wait_time]() {
                time_t start_time = time(nullptr);
                while (waitpid(pid, nullptr, WNOHANG) == 0 && 
                       time(nullptr) - start_time < max_wait_time) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    if (!is_running) {
                        break;
                    }
                }
                
                if (waitpid(pid, nullptr, WNOHANG) == 0) {
                    if (!is_running) {
                        forceKill(pid);
                    } else {
                        pid_t pid2 = fork();
                        if (pid2 < 0) {
                            swaylock_log(LOG_DEBUG, "Error forking");
                            return;
                        }
                        if (!pid2) {
                            while (waitpid(pid, nullptr, WNOHANG) == 0 && is_running) {
                                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                            }
                            if (waitpid(pid, nullptr, WNOHANG) == 0) {
                                forceKill(pid);
                            }
                            exit(0);
                        }
                    }
                }
            });
            wait_thread.detach();
        }
    }

    void createManager() {
        if (manager_creating) {
            swaylock_log(LOG_DEBUG, "Manager creation already in progress, skipping");
            return;
        }

        GError* error = nullptr;
        if (!connection) {
            connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, nullptr, &error);
            if (!connection) {
                swaylock_log(LOG_ERROR, "Failed to connect to session bus: %s", error->message);
                displayDriverMessage("Failed to connect to session bus: %s", error->message);
                g_clear_error(&error);
                return;
            }
        }

        if (!manager) {
            int current_init_id = init_id;
            manager_creating = true;
            displayDriverMessage("Creating FPrint manager...");
            swaylock_log(LOG_DEBUG, "Creating FPrint manager");

            struct ManagerCreationData {
                FingerprintManager* self;
                int init_id;
            };

            auto* data = new ManagerCreationData{this, current_init_id};

            fprint_dbus_manager_proxy_new(
                connection,
                G_DBUS_PROXY_FLAGS_NONE,
                "net.reactivated.Fprint",
                "/net/reactivated/Fprint/Manager",
                nullptr,
                [](GObject* source_object, GAsyncResult* res, gpointer user_data) {
                    auto* data = static_cast<ManagerCreationData*>(user_data);
                    auto* self = data->self;

                    GError* local_error = nullptr;
                    FprintDBusManager* mgr = fprint_dbus_manager_proxy_new_finish(res, &local_error);

                    self->event_loop.post([self, mgr, data, local_error]() {
                        delete data;

                        if (data->init_id != self->init_id) {
                            swaylock_log(LOG_DEBUG, "Init ID changed during manager creation, discarding result");
                            if (local_error) g_error_free(local_error);
                            if (mgr) g_object_unref(mgr);
                            return;
                        }

                        self->manager_creating = false;

                        if (local_error) {
                            swaylock_log(LOG_ERROR, "Failed to create FPrint manager: %s", local_error->message);
                            self->displayDriverMessage("Failed to create FPrint manager: %s", local_error->message);
                            g_error_free(local_error);
                            return;
                        }

                        self->manager = mgr;
                        swaylock_log(LOG_DEBUG, "FPrint manager created asynchronously");
                        self->displayDriverMessage("FPrint manager ready");

                        if (self->initialized && !self->device) {
                            self->openDeviceAsync();
                        }
                    });
                },
                data);
        }
    }

    void destroyManager() {
        g_clear_object(&manager);
        g_clear_object(&connection);
    }

    static void proxySignalCb(GDBusProxy* proxy,
                            const gchar* sender_name,
                            const gchar* signal_name,
                            GVariant* parameters,
                            gpointer user_data) {
        auto* self = static_cast<FingerprintManager*>(user_data);

        if (!self->started || self->restarting) {
            return;
        }

        if (g_str_equal(signal_name, "VerifyFingerSelected")) {
            return;
        }
        if (!g_str_equal(signal_name, "VerifyStatus")) {
            swaylock_log(LOG_DEBUG, "Received unexpected signal %s", signal_name);
            return;
        }

        const gchar* result;
        gboolean done;
        g_variant_get(parameters, "(&sb)", &result, &done);

        std::string result_str(result);
        self->event_loop.post([self, result_str, done]() {
            self->verifyResult(result_str.c_str(), done);
        });
    }

    void verifyResult(const char* result, bool done) {
        last_signal_time = time(nullptr);
        swaylock_log(LOG_INFO, "Verify result: %s (%s)", result, done ? "done" : "not done");

        const char* status = nullptr;
        match = g_str_equal(result, "verify-match");
        bool should_restart = false;
        bool is_unknown = false;

        if (g_str_equal(result, "verify-retry-scan")) {
            continuous_unknown_error_count = 0;
            displayMessage("Retry");
            return;
        }
        if (g_str_equal(result, "verify-swipe-too-short")) {
            continuous_unknown_error_count = 0;
            displayMessage("Retry, too short");
            return;
        }
        if (g_str_equal(result, "verify-finger-not-centered")) {
            continuous_unknown_error_count = 0;
            displayMessage("Retry, not centered");
            return;
        }
        if (g_str_equal(result, "verify-remove-and-retry")) {
            continuous_unknown_error_count = 0;
            displayMessage("Remove and retry");
            return;
        }
        if (g_str_equal(result, "verify-unknown-error")) {
            if (++continuous_unknown_error_count > MAX_UNKNOWN_ERROR_COUNT) {
                should_restart = true;
            }
            is_unknown = true;
            status = "Unknown error";
        }
        else if (g_str_equal(result, "verify-disconnected")) {
            status = "Device disconnected";
        }
        else if (g_str_equal(result, "verify-match")) {
            continuous_unknown_error_count = 0;
        }
        else if (g_str_equal(result, "verify-no-match")) {
            continuous_unknown_error_count = 0;
            fail_count++;
        }
        else {
            status = result;
        }

        bool kill = false;
        if (shouldDisableFingerprint()) {
            status = "FP Disabled";
            should_restart = false;
            kill = true;
        }

        if (status) {
            if (match) {
                displayMessage("FP OK: %s", status);
            }
            else if (is_unknown) {
                displayMessage("FP Failed (%d): %s", continuous_unknown_error_count.load(), status);
            }
            else {
                displayMessage("FP Failed (%d): %s", fail_count.load(), status);
            }
        }
        else {
            if (match) {
                displayMessage("FP OK");
            }
            else {
                displayMessage("FP Failed (%d)", fail_count.load());
            }
        }

        completed = true;
        verifying = false;

        GError* error = nullptr;
        if (!fprint_dbus_device_call_verify_stop_sync(device, nullptr, &error)) {
            swaylock_log(LOG_ERROR, "VerifyStop failed: %s", error->message);
            displayDriverMessage("Failed to stop verification: %s", error->message);
            g_clear_error(&error);
            return;
        }

        if (kill) {
            fingerprint_deinit();
        }
        else if (should_restart && !match) {
            time_t current_time = time(nullptr);
            if (current_time - last_activity_time > 60) {
                fingerprint_deinit();
                return;
            }
            swaylock_log(LOG_DEBUG, "Restarting verification");
            restarting = true;
            rebind_usb = true;
            event_loop.postDelayed(1000, [this]() {
                this->restartVerifyStep1();
            });
        }
    }

    static void verifyStartedCb(GObject* obj, GAsyncResult* res, gpointer user_data) {
        auto* self = static_cast<FingerprintManager*>(user_data);

        GError* local_error = nullptr;
        bool success = fprint_dbus_device_call_verify_start_finish(FPRINT_DBUS_DEVICE(obj), res, &local_error);

        self->event_loop.post([self, success, local_error]() {
            if (local_error) {
                if (self->error) {
                    g_error_free(self->error);
                }
                self->error = local_error;
                return;
            }

            if (success) {
                swaylock_log(LOG_DEBUG, "Verify started!");
                self->started = true;
                self->displayDriverMessage("Scan your finger");
            }
        });
    }

    void startVerify() {
        if (shouldDisableFingerprint()) {
            return;
        }

        if (verifying || restarting || !device) {
            return;
        }

        last_start_verify_time = time(nullptr);
        swaylock_log(LOG_DEBUG, "Starting verification");
        verifying = true;
        started = false;
        completed = false;
        match = false;

        int current_init_id = init_id;

        struct TimeoutData {
            FingerprintManager* manager;
            int init_id;
            std::shared_ptr<GCancellable> cancellable;
        };

        auto* timeout_data = new TimeoutData{
            this,
            current_init_id,
            std::shared_ptr<GCancellable>(g_cancellable_new(), g_object_unref)
        };

        fprint_dbus_device_call_verify_start(device, "any", timeout_data->cancellable.get(),
                                          verifyStartedCb, this);

        std::thread([timeout_data]() {
            for (int i = 0; i < 100 && !timeout_data->manager->started && 
                          !timeout_data->manager->error && 
                          timeout_data->init_id == timeout_data->manager->init_id; i++) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }

            if (!timeout_data->manager->started && !timeout_data->manager->error && 
                timeout_data->init_id == timeout_data->manager->init_id) {
                timeout_data->manager->event_loop.post([timeout_data]() {
                    g_cancellable_cancel(timeout_data->cancellable.get());
                    swaylock_log(LOG_ERROR, "VerifyStart timeout");
                    timeout_data->manager->displayDriverMessage("Failed to start verification (timeout)");
                    timeout_data->manager->restarting = true;

                    timeout_data->manager->event_loop.postDelayed(1000, [timeout_data]() {
                        timeout_data->manager->restartVerifyStep1();
                    });

                    delete timeout_data;
                });
            } else {
                delete timeout_data;
            }
        }).detach();

        event_loop.post([this]() {
            if (error) {
                swaylock_log(LOG_ERROR, "VerifyStart failed: %s", error->message);
                displayDriverMessage("Failed to start verification: %s", error->message);
                g_clear_error(&error);
            } else if (!*status) {
                displayMessage("...");
            }
        });
    }

    void connectSignalAndStartVerify() {
        if (!device_signal_connected) {
            device_signal_connected = true;
            g_signal_connect(device, "g-signal", G_CALLBACK(proxySignalCb), this);
            startVerify();
        }
    }

    static void openDeviceAsyncDeviceClaimCb(GObject *source_object,
                                             GAsyncResult *res,
                                             gpointer data)
    {
        auto *op = static_cast<ClaimOperation *>(data);
        auto *self = op->state;

        if (op->init_id != self->init_id)
        {
            delete op;
            return;
        }

        // Create a local variable for the error
        GError *local_error = nullptr;
        bool success = fprint_dbus_device_call_claim_finish(op->device, res, &local_error);

        self->event_loop.post([self, success, local_error, op]() {
            if (local_error) {
                if (self->error) {
                    g_error_free(self->error);
                }
                self->error = local_error;
                self->displayDriverMessage("Claim failed (%d): %s", self->restart_count.load(), local_error->message);
                return;
            }

            swaylock_log(LOG_DEBUG, "FPrint device opened %s", op->path);
            self->device = g_object_ref(op->device);
            self->device_opening = false;
            self->connectSignalAndStartVerify();
            delete op;
        });
    }

    static void openDeviceAsyncDeviceProxyNewCb(GObject *source_object,
                                                GAsyncResult *res,
                                                gpointer data)
    {
        auto *op = static_cast<ClaimOperation *>(data);
        auto *self = op->state;

        if (op->init_id != self->init_id)
        {
            delete op;
            return;
        }

        // Create local variables
        FprintDBusDevice *dev = nullptr;
        GError *local_error = nullptr;
        dev = fprint_dbus_device_proxy_new_finish(res, &local_error);

        // Post the result to the event loop
        self->event_loop.post([self, op, dev, local_error]() mutable
                              {
            if (local_error) {
                swaylock_log(LOG_ERROR, "failed to connect to device: %s (%d)", local_error->message, local_error->code);
                self->displayDriverMessage("Failed to connect to device: %s", local_error->message);
                self->device_opening = false;
                g_error_free(local_error);
                delete op;
                return;
            }

            self->displayDriverMessage("FP Claiming");
            op->device = dev;
            fprint_dbus_device_call_claim(dev, "", nullptr,
                                        openDeviceAsyncDeviceClaimCb, op); });
    }

    static void openDeviceAsyncGetDefaultDeviceCb(GObject *source_object,
                                                  GAsyncResult *res,
                                                  gpointer data)
    {
        auto *op = static_cast<ClaimOperation *>(data);
        auto *self = op->state;

        if (op->init_id != self->init_id)
        {
            delete op;
            return;
        }

        // Create local variables
        char *path = nullptr;
        GError *local_error = nullptr;
        bool success = fprint_dbus_manager_call_get_default_device_finish(self->manager, &path, res, &local_error);

        // Post the result to the event loop
        self->event_loop.post([self, op, success, path, local_error]() mutable
                              {
            if (!success) {
                swaylock_log(LOG_ERROR, "openDeviceAsyncGetDefaultDevice:Error: %s", local_error->message);
                self->displayDriverMessage("Failed to get default device (%d): %s", self->restart_count.load(), local_error->message);
                
                int open_fail_count = ++self->restart_count;
                if (open_fail_count >= 2 && open_fail_count <= 3) {
                    self->restartFingerprintUsbDevice(open_fail_count == 3, true);
                    if (!self->sleepFor(op->init_id, 3)) {
                        self->device_opening = false;
                        delete op;
                        g_error_free(local_error);
                        return;
                    }
                }
                
                if (open_fail_count < 5) {
                    fprint_dbus_manager_call_get_default_device(self->manager, nullptr,
                                                            openDeviceAsyncGetDefaultDeviceCb, op);
                    g_error_free(local_error);
                    return;
                } else {
                    self->device_opening = false;
                    delete op;
                    g_error_free(local_error);
                    return;
                }
            }

            swaylock_log(LOG_DEBUG, "Fingerprint: using device %s", path);

            self->displayDriverMessage("FP Proxying");
            self->restart_count = 0;
            op->path = g_strdup(path); // Make our own copy
            g_free(path); // Free the original
            
            fprint_dbus_device_proxy_new(self->connection,
                                      G_DBUS_PROXY_FLAGS_NONE,
                                      "net.reactivated.Fprint",
                                      op->path,
                                      nullptr,
                                      openDeviceAsyncDeviceProxyNewCb,
                                      op); });
    }

    void openDeviceAsync()
    {
        if (verifying || device_opening)
        {
            return;
        }

        int current_init_id = init_id;
        device_opening = true;
        device_signal_connected = false;
        if (device)
        {
            g_object_unref(device);
            device = nullptr;
        }

        auto *op = new ClaimOperation(this, current_init_id);
        displayDriverMessage("Getting default device...");
        fprint_dbus_manager_call_get_default_device(manager, nullptr,
                                                    openDeviceAsyncGetDefaultDeviceCb,
                                                    op);
    }

    static bool isSuspendingOrHibernatingOrLidClosed()
    {
        GError *error = nullptr;
        GDBusProxy *proxy = g_dbus_proxy_new_for_bus_sync(
            G_BUS_TYPE_SYSTEM,
            G_DBUS_PROXY_FLAGS_NONE,
            nullptr,
            "org.freedesktop.login1",
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
            nullptr, &error);

        if (error)
        {
            g_error_free(error);
            return false;
        }

        bool flag = false;
        GVariant *result = g_dbus_proxy_get_cached_property(proxy, "PreparingForShutdown");
        if (result)
        {
            flag = g_variant_get_boolean(result);
            g_variant_unref(result);
        }

        if (!flag)
        {
            result = g_dbus_proxy_get_cached_property(proxy, "PreparingForSleep");
            if (result)
            {
                flag = g_variant_get_boolean(result);
                g_variant_unref(result);
            }
        }

        if (!flag)
        {
            result = g_dbus_proxy_get_cached_property(proxy, "LidClosed");
            if (result)
            {
                flag = g_variant_get_boolean(result);
                g_variant_unref(result);
            }
        }

        g_object_unref(proxy);
        return flag;
    }

    void fingerprintInnerInit()
    {
        int current_init_id = ++init_id;
        initialized = true;
        last_signal_time = time(nullptr);
        last_start_verify_time = time(nullptr);
        continuous_unknown_error_count = 0;
        verifying = false;
        displayDriverMessage("Initializing...");

        // if device is suspending or hibernating, don't initialize
        if (isSuspendingOrHibernatingOrLidClosed())
        {
            displayDriverMessage("Suspended");
            return;
        }

        createManager();

        // Handle the case where we failed to start manager creation
        if (!manager && !manager_creating)
        {
            // Create a shared state object on the heap for the retries
            struct RetryState
            {
                time_t start_time;
                time_t last_try_time;
                int try_count;
                int init_id;

                RetryState(int id) : start_time(time(nullptr)),
                                     last_try_time(time(nullptr)),
                                     try_count(1),
                                     init_id(id) {}
            };

            // Create a shared state
            auto state = std::make_shared<RetryState>(current_init_id);

            int retry_count = 0;

            // Schedule a retry task
            auto retry_task = [this, state, &retry_count]()
            {
                if (state->init_id != init_id)
                {
                    return;
                }
                displayDriverMessage("Init retry... %d", retry_count++);

                time_t current_time = time(nullptr);
                if (state->try_count > 5 || current_time - state->start_time > 60)
                {
                    swaylock_log(LOG_ERROR, "Failed to initialize fingerprint");
                    displayDriverMessage("Failed to initialize fingerprint");
                    return;
                }

                if (current_time - state->last_try_time > 3)
                {
                    state->last_try_time = current_time;
                    ++state->try_count;
                    if (state->try_count % 2 == 0)
                    {
                        restartFingerprintUsbDevice(false, true);
                    }
                    last_signal_time = time(nullptr);
                    createManager();
                }

                // If still no manager and no creation in progress, schedule another retry
                if (!manager && !manager_creating)
                {
                    event_loop.post([this, state]()
                                    {
                        // Schedule the next retry with a delay
                        event_loop.postDelayed(1000, [this, state]() {
                            auto *data = new std::pair<FingerprintManager*, std::shared_ptr<RetryState>>(this, state);
                            data->first->event_loop.post([data]() {
                                // Create a new retry task
                                data->first->createManager();
                                
                                // If still no manager and not creating, schedule another retry
                                if (!data->first->manager && !data->first->manager_creating) {
                                    data->second->last_try_time = time(nullptr);
                                    ++data->second->try_count;
                                    
                                    if (data->second->try_count % 2 == 0) {
                                        data->first->restartFingerprintUsbDevice(false, true);
                                    }
                                    
                                    // Check again after a delay
                                    data->first->event_loop.postDelayed(3000, [data]() {
                                        data->first->event_loop.post([data]() {
                                            // Try to create manager again
                                            data->first->createManager();
                                            delete data;
                                        });
                                    });
                                }
                                
                                delete data;
                            });
                        }); });
                }
            };

            // Start the first retry
            retry_task();
        }
    }

    void restartVerifyStep2()
    {
        swaylock_log(LOG_DEBUG, "Restarting verification step 2");
        last_signal_time = time(nullptr);
        restart_count++;
        restarting = false;

        if (!shouldDisableFingerprint())
        {
            fingerprintInnerInit();
            displayMessage("");
            verifying = false;
            openDeviceAsync();
        }
        else
        {
            if (!*status)
            {
                displayDriverMessage("Disabled");
            }
        }
    }

    void restartVerifyStep1()
    {
        last_signal_time = time(nullptr);
        init_id++;
        // Reset the manager_creating flag when init_id changes
        manager_creating = false;
        device_opening = false;
        swaylock_log(LOG_DEBUG, "Restarting verification step 1");
        fingerprint_deinit();

        if (rebind_usb)
        {
            rebind_usb = false;
            restartFingerprintUsbDevice(false, true);
        }

        // Use event_loop.postDelayed instead of g_timeout_add_seconds_full
        event_loop.postDelayed(1000, [this]()
                               {
            // Post the restart task to the event loop
            this->restartVerifyStep2(); });
    }

    static void handleSleepSignal(GDBusProxy *proxy,
                                  const gchar *sender_name,
                                  const gchar *signal_name,
                                  GVariant *parameters,
                                  gpointer user_data)
    {
        if (g_strcmp0(signal_name, "PrepareForSleep") != 0)
        {
            return;
        }

        auto *self = static_cast<FingerprintManager *>(user_data);
        gboolean going_to_sleep;
        g_variant_get(parameters, "(b)", &going_to_sleep);

        // Post the event to the event loop
        self->event_loop.post([self, going_to_sleep]()
                              {
            if (!going_to_sleep) { // System is resuming
                swaylock_log(LOG_DEBUG, "System resumed, restarting fingerprint verification.");
                self->fingerprint_deinit();
                self->fingerprintInnerInit();
            } else {
                swaylock_log(LOG_DEBUG, "System going to sleep, stopping fingerprint verification.");
                self->fingerprint_deinit();
            } });
    }

    void closeDevice()
    {
        if (!device)
        {
            return;
        }

        g_signal_handlers_disconnect_by_func(device, (gpointer)proxySignalCb, this);
        fprint_dbus_device_call_release(device, nullptr, [](GObject *source_object, GAsyncResult *res, gpointer user_data) {}, nullptr);
        g_object_unref(device);
        device = nullptr;
    }

public:
    void processDisplayMessages()
    {
        // Process the latest messages if updated
        {
            std::lock_guard<std::mutex> lock(message_mutex);

            if (latest_message.updated)
            {
                strncpy(status, latest_message.message.c_str(), sizeof(status) - 1);
                status[sizeof(status) - 1] = '\0';
                fp_display_message(sw_state, status);
                latest_message.updated = false;
            }

            if (latest_driver_message.updated)
            {
                strncpy(driver_status, latest_driver_message.message.c_str(), sizeof(driver_status) - 1);
                driver_status[sizeof(driver_status) - 1] = '\0';
                fp_display_driver_message(sw_state, driver_status);
                latest_driver_message.updated = false;
            }
        }
    }

public:
    FingerprintManager(struct swaylock_state *swaylock_state)
        : sw_state(swaylock_state),
          is_running(true),
          initialized(false),
          rebind_usb(false),
          restarting(false),
          started(false),
          completed(false),
          match(false),
          verifying(false),
          device_signal_connected(false),
          device_opening(false),
          manager_creating(false),
          init_id(0),
          continuous_unknown_error_count(0),
          fail_count(0),
          restart_count(0),
          flag_idle_restart(0),
          last_signal_time(0),
          last_start_verify_time(0),
          last_activity_time(0),
          connection(nullptr),
          manager(nullptr),
          device(nullptr),
          error(nullptr)
    {

        memset(status, 0, sizeof(status));
        memset(driver_status, 0, sizeof(driver_status));

        // Start the event loop
        event_loop.start();

        // Schedule initialization task
        event_loop.post([this]
                        {
            // Connect to the PrepareForSleep signal
            GDBusProxy *login_manager_proxy = g_dbus_proxy_new_for_bus_sync(
                G_BUS_TYPE_SYSTEM,
                G_DBUS_PROXY_FLAGS_NONE,
                nullptr,
                "org.freedesktop.login1",
                "/org/freedesktop/login1",
                "org.freedesktop.login1.Manager",
                nullptr, nullptr);
            g_signal_connect(login_manager_proxy, "g-signal",
                            G_CALLBACK(handleSleepSignal), this);
            
            fingerprintInnerInit(); });
    }

    ~FingerprintManager()
    {
        swaylock_log(LOG_DEBUG, "FingerprintManager destructor");
        // Schedule cleanup before stopping the event loop
        event_loop.postSyncImmediately([this]
                                       { fingerprint_deinit(); });
        swaylock_log(LOG_DEBUG, "FingerprintManager destructor after postSyncImmediately");
        // Stop the event loop
        event_loop.stop();
        swaylock_log(LOG_DEBUG, "FingerprintManager destructor after stop");
    }

    bool verify()
    {
        // Process any pending display messages in the main thread
        processDisplayMessages();

        // We don't need g_main_context_iteration here anymore,
        // as all GLib operations are handled in the event loop thread

        if (restarting)
        {
            return false;
        }

        time_t current_time = time(nullptr);
        if (flag_idle_restart)
        {
            bool force = (flag_idle_restart & 2) != 0;
            flag_idle_restart = 0;

            if (!shouldDisableFingerprint() && !match && !restarting)
            {
                swaylock_log(LOG_DEBUG, "Handle flag_idle_restart: %d", flag_idle_restart.load());

                if (!initialized)
                {
                    event_loop.post([this]
                                    { fingerprintInnerInit(); });
                    return false;
                }

                if (current_time - last_start_verify_time > 3 && force)
                {
                    rebind_usb = false;
                    restarting = true;
                    event_loop.post([this]
                                    { restartVerifyStep1(); });
                    return false;
                }

                if (current_time - last_start_verify_time > 60)
                {
                    swaylock_log(LOG_DEBUG, "run startVerify again due to idle");
                    verifying = false;
                    event_loop.post([this]
                                    { startVerify(); });
                    return false;
                }

                if (current_time - last_signal_time > 60)
                {
                    swaylock_log(LOG_DEBUG, "Restarting verification due to idle");
                    rebind_usb = false;
                    restarting = true;
                    event_loop.post([this]
                                    { restartVerifyStep1(); });
                    return false;
                }
            }
        }
        else
        {
            if (!initialized)
            {
                return false;
            }

            if (current_time - last_signal_time > 120 && !match)
            {
                swaylock_log(LOG_DEBUG, "Idle verification timeout, disabling fingerprint");
                restarting = false;
                event_loop.post([this]
                                { fingerprint_deinit(); });
                return false;
            }
        }

        if (!manager || !connection)
        {
            return false;
        }

        if (!device)
        {
            event_loop.post([this]
                            { openDeviceAsync(); });
            return false;
        }

        if (!completed)
        {
            return false;
        }

        if (!match)
        {
            event_loop.post([this]
                            { startVerify(); });
            return false;
        }

        return true;
    }

    void fingerprint_deinit()
    {
        if (!match)
        {
            displayDriverMessage("Press any key to reenable fingerprint");
        }

        initialized = false;
        init_id++;
        verifying = false;
        device_opening = false;
        // Reset manager_creating since we're explicitly deinitializing
        manager_creating = false;
        closeDevice();
        destroyManager();
    }

    void setRestartFlag(bool force)
    {
        flag_idle_restart |= force ? 2 : 1;
        last_activity_time = time(nullptr);
    }

    void setIsRunning(bool running)
    {
        is_running = running;

        if (!running)
        {
            // Signal the event loop to stop if not running
            swaylock_log(LOG_DEBUG, "FingerprintManager::setIsRunning: posting stop event loop");
            event_loop.post([this]()
                            { event_loop.stop(); });
        }
    }
};

// Initialize static members
std::atomic<int> FingerprintManager::restart_count_static{0};
std::atomic<time_t> FingerprintManager::last_usb_restart_time{0};
std::atomic<time_t> FingerprintManager::last_usb_full_restart_time{0};

// Define the opaque fingerprint_state struct that wraps our C++ implementation
struct fingerprint_state
{
    FingerprintManager *manager;
    std::mutex *mutex; // For thread-safe access to the manager

    // Constructor
    explicit fingerprint_state(struct swaylock_state *sw_state)
        : manager(nullptr), mutex(nullptr)
    {
        // Create the mutex first
        mutex = new std::mutex();
        // Then create the manager
        manager = new FingerprintManager(sw_state);
    }

    // Destructor
    ~fingerprint_state()
    {
        // Clean up resources if they haven't been cleaned up yet
        if (manager)
        {
            delete manager;
            manager = nullptr;
        }

        if (mutex)
        {
            delete mutex;
            mutex = nullptr;
        }
    }
};

// C wrapper functions
extern "C"
{

    struct fingerprint_state *fingerprint_init(struct swaylock_state *swaylock_state)
    {
        return new fingerprint_state(swaylock_state);
    }

    bool fingerprint_verify(struct fingerprint_state *fp_state)
    {
        if (!fp_state || !fp_state->manager || !fp_state->mutex)
        {
            return false;
        }

        std::lock_guard<std::mutex> lock(*fp_state->mutex);
        return fp_state->manager->verify();
    }

    void fingerprint_deinit(struct fingerprint_state *fp_state)
    {
        if (!fp_state)
        {
            return;
        }

        // Clean up the manager first
        if (fp_state->manager && fp_state->mutex)
        {
            std::lock_guard<std::mutex> lock(*fp_state->mutex);
            delete fp_state->manager;
            fp_state->manager = nullptr;
        }
        else if (fp_state->manager)
        {
            // No mutex, but still need to clean up manager
            delete fp_state->manager;
            fp_state->manager = nullptr;
        }

        // Clean up the mutex
        if (fp_state->mutex)
        {
            delete fp_state->mutex;
            fp_state->mutex = nullptr;
        }

        // Now delete the structure itself
        delete fp_state;
    }

    void fingerprint_set_restart_flag(struct fingerprint_state *fp_state, bool force)
    {
        if (!fp_state || !fp_state->manager || !fp_state->mutex)
        {
            return;
        }

        std::lock_guard<std::mutex> lock(*fp_state->mutex);
        fp_state->manager->setRestartFlag(force);
    }

    void fingerprint_set_is_running(struct fingerprint_state *fp_state, bool is_running)
    {
        if (!fp_state || !fp_state->manager || !fp_state->mutex)
        {
            return;
        }

        std::lock_guard<std::mutex> lock(*fp_state->mutex);
        fp_state->manager->setIsRunning(is_running);
    }

    void fingerprint_process_display_messages(struct fingerprint_state *fp_state)
    {
        if (!fp_state || !fp_state->manager || !fp_state->mutex)
        {
            return;
        }

        std::lock_guard<std::mutex> lock(*fp_state->mutex);
        fp_state->manager->processDisplayMessages();
    }

} // extern "C"