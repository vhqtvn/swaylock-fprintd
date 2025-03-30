gnome = import('gnome')

dbus = dependency('dbus-1')
glib = dependency('glib-2.0', version: '>=2.64.0')
gio_dep = dependency('gio-2.0')
thread_dep = dependency('threads')
# Add missing dependencies needed by the headers
gdk_pixbuf = dependency('gdk-pixbuf-2.0')
cairo = dependency('cairo')

fprintd_dbus_interfaces = files(
    '/usr/share/dbus-1/interfaces/net.reactivated.Fprint.Manager.xml',
    '/usr/share/dbus-1/interfaces/net.reactivated.Fprint.Device.xml',
)

fprintd_dbus_sources = gnome.gdbus_codegen('fprintd-dbus',
    sources: fprintd_dbus_interfaces,
    autocleanup: 'all',
    interface_prefix: 'net.reactivated.Fprint.',
    namespace: 'FprintDBus',
    object_manager: true,
)

# Define include directories properly
fingerprint_includes = [
    include_directories('..'),
    include_directories('../include'),
]

# Compile the C++ file into a static library
fingerprint_lib = static_library(
    'fingerprint',
    sources: [
        fprintd_dbus_sources,
        'fingerprint.cpp',
        'fingerprint_c.c',
    ],
    include_directories: fingerprint_includes,
    dependencies: [
        gio_dep,
        glib,
        dbus,
        thread_dep,
        gdk_pixbuf,
        cairo
    ],
    cpp_args: ['-Wno-narrowing', '-std=c++17', '-Wno-format-security', '-fpermissive']
)

fingerprint = declare_dependency(
    link_with: fingerprint_lib,
    include_directories: include_directories('.'),
)