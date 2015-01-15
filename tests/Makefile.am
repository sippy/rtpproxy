TESTS = startstop basic_versions command_parser makeann extractaudio \
  playback1
extractaudio_EXTRA_DIST = call1_alaw.a.rtp call1_alaw.o.rtp call1_g722.a.rtp \
  call1_g722.o.rtp call1_g729.a.rtp call1_g729.o.rtp call1_ulaw.a.rtp \
  call1_ulaw.o.rtp call1_gsm.a.rtp call1_gsm.o.rtp extractaudio.checksums
extractaudio_CLEANFILES = call1_alaw.mono.wav call1_alaw.stereo.wav \
  call1_g722.mono.wav call1_g722.stereo.wav call1_g729.mono.wav \
  call1_g729.stereo.wav call1_ulaw.mono.wav call1_ulaw.stereo.wav \
  call1_gsm.mono.wav call1_gsm.stereo.wav
playback1_EXTRA_DIST = playback1.input playback1.output playback1.checksums
playback1_CLEANFILES = playback1.0.a.rtp playback1.18.a.rtp playback1.3.a.rtp \
  playback1.8.a.rtp playback1.9.a.rtp playback1.0 playback1.18 playback1.3 \
  playback1.8 playback1.9 playback1.rout playback1.0.wav playback1.18.wav \
  playback1.3.wav playback1.8.wav playback1.9.wav
EXTRA_DIST = Makefile.am startstop basic_versions basic_versions.input \
    basic_versions.output command_parser command_parser.input \
    command_parser.output ringback.sln makeann makeann.output \
    extractaudio ${extractaudio_EXTRA_DIST} playback1 ${playback1_EXTRA_DIST}
# NB: AM_TESTS_ENVIRONMENT not available until automake 1.12
TESTS_ENVIRONMENT = \
        BASEDIR=${abs_srcdir} ; export BASEDIR ; \
        BUILDDIR=${abs_builddir} ; export BUILDDIR ; \
        TOP_BUILDDIR=${abs_top_builddir} ; export TOP_BUILDDIR ;
CLEANFILES = ringback.0 ringback.3 ringback.8 ringback.18 ringback.9 \
  ${extractaudio_CLEANFILES} ${playback1_CLEANFILES}
