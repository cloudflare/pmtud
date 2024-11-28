project('outlier', 'c',
	default_options : [
		'c_std=c99',
		'buildtype=debugoptimized',
		'warning_level=1',
	],
	license : 'BSD 3-clause',
	version : 'v0.6',
	meson_version : '>= 0.44.0',
)

conf = configuration_data()
conf.set('_GNU_SOURCE', 1)
config_h = configure_file(
        output : 'config.h',
        configuration : conf)

add_project_arguments('-include', 'config.h', language : 'c')

pmtud_sources = '''
	src/bitmap.c
	src/csiphash.c
	src/hashlimit.c
	src/hashlimit.h
	src/main.c
	src/net.c
	src/nflog.c
	src/pmtud.h
	src/sched.c
	src/uevent.c
	src/uevent.h
	src/utils.c
'''.split()

libpcap_dep = dependency('pcap')
libnfnetlink_dep = dependency('libnfnetlink')
libnetfilter_log_dep = dependency('libnetfilter_log')

executable('pmtud',
	pmtud_sources,
	dependencies: [
		libpcap_dep,
		libnfnetlink_dep,
		libnetfilter_log_dep,
	],
	install: true,
)
