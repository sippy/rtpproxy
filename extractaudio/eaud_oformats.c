/*
 * Copyright (c) 2016 Sippy Software, Inc., http://www.sippysoft.com
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdint.h>
#include <strings.h>
#include <sndfile.h>

#include "eaud_oformats.h"

const struct supported_fmt eaud_file_fmts[] = {
    {"wav",   SF_FORMAT_WAV,   "Microsoft WAV format (little endian default)"},
    {"aiff",  SF_FORMAT_AIFF,  "Apple/SGI AIFF format (big endian)"},
    {"au",    SF_FORMAT_AU,    "Sun/NeXT AU format (big endian)"},
    {"raw",   SF_FORMAT_RAW,   "RAW PCM data"},
    {"paf",   SF_FORMAT_PAF,   "Ensoniq PARIS file format"},
    {"svx",   SF_FORMAT_SVX,   "Amiga IFF / SVX8 / SV16 format"},
    {"nist",  SF_FORMAT_NIST,  "Sphere NIST format"},
    {"voc",   SF_FORMAT_VOC,   "VOC files"},
    {"ircam", SF_FORMAT_IRCAM, "Berkeley/IRCAM/CARL"},
    {"w64",   SF_FORMAT_W64,   "Sonic Foundry's 64 bit RIFF/WAV"},
    {"mat4",  SF_FORMAT_MAT4,  "Matlab (tm) V4.2 / GNU Octave 2.0"},
    {"mat5",  SF_FORMAT_MAT5,  "Matlab (tm) V5.0 / GNU Octave 2.1"},
    {"pvf",   SF_FORMAT_PVF,   "Portable Voice Format"},
    {"xi",    SF_FORMAT_XI,    "Fasttracker 2 Extended Instrument"},
    {"htk",   SF_FORMAT_HTK,   "HMM Tool Kit format"},
    {"sds",   SF_FORMAT_SDS,   "Midi Sample Dump Standard"},
    {"avr",   SF_FORMAT_AVR,   "Audio Visual Research"},
    {"wavex", SF_FORMAT_WAVEX, "MS WAVE with WAVEFORMATEX"},
    {"sd2",   SF_FORMAT_SD2,   "Sound Designer 2"},
    {"flac",  SF_FORMAT_FLAC,  "FLAC lossless file format"},
    {"caf",   SF_FORMAT_CAF,   "Core Audio File format"},
    {"wve",   SF_FORMAT_WVE,   "Psion WVE format"},
    {"ogg",   SF_FORMAT_OGG,   "Xiph OGG container"},
    {"mpc2k", SF_FORMAT_MPC2K, "Akai MPC 2000 sampler"},
    {"rf64",  SF_FORMAT_RF64,  "RF64 WAV file"},
    {.name = NULL}
};

const struct supported_fmt eaud_data_fmts[] = {
    {"pcm_s8",    SF_FORMAT_PCM_S8,    "Signed 8 bit data"},
    {"pcm_16",    SF_FORMAT_PCM_16,    "Signed 16 bit data"},
    {"pcm_24",    SF_FORMAT_PCM_24,    "Signed 24 bit data"},
    {"pcm_32",    SF_FORMAT_PCM_32,    "Signed 32 bit data"},
    {"pcm_u8",    SF_FORMAT_PCM_U8,    "Unsigned 8 bit data (WAV and RAW only)"},
    {"float",     SF_FORMAT_FLOAT,     "32 bit float data"},
    {"double",    SF_FORMAT_DOUBLE,    "64 bit float data"},
    {"ulaw",      SF_FORMAT_ULAW,      "U-Law encoded"},
    {"alaw",      SF_FORMAT_ALAW,      "A-Law encoded"},
    {"ima_adpcm", SF_FORMAT_IMA_ADPCM, "IMA ADPCM"},
    {"ms_adpcm",  SF_FORMAT_MS_ADPCM,  "Microsoft ADPCM"},
    {"gsm610",    SF_FORMAT_GSM610,    "GSM 6.10 encoding"},
    {"vox_adpcm", SF_FORMAT_VOX_ADPCM, "OKI / Dialogix ADPCM"},
    {"g721_32",   SF_FORMAT_G721_32,   "32kbs G721 ADPCM encoding"},
    {"g723_24",   SF_FORMAT_G723_24,   "24kbs G723 ADPCM encoding"},
    {"g723_40",   SF_FORMAT_G723_40,   "40kbs G723 ADPCM encoding"},
    {"dwvw_12",   SF_FORMAT_DWVW_12,   "12 bit Delta Width Variable Word encoding"},
    {"dwvw_16",   SF_FORMAT_DWVW_16,   "16 bit Delta Width Variable Word encoding"},
    {"dwvw_24",   SF_FORMAT_DWVW_24,   "24 bit Delta Width Variable Word encoding"},
    {"dwvw_n",    SF_FORMAT_DWVW_N,    "N bit Delta Width Variable Word encoding"},
    {"dpcm_8",    SF_FORMAT_DPCM_8,    "8 bit differential PCM (XI only)"},
    {"dpcm_16",   SF_FORMAT_DPCM_16,   "16 bit differential PCM (XI only)"},
    {"vorbis",    SF_FORMAT_VORBIS,    "Xiph Vorbis encoding"},
    {.name = NULL}
};

const struct supported_fmt eaud_data_ends[] = {
    {"file",   SF_ENDIAN_FILE, "Default file endian-ness"},
    {"little", SF_ENDIAN_LITTLE, "Force little endian-ness"},
    {"big",    SF_ENDIAN_BIG, "Force big endian-ness"},
    {"cpu",    SF_ENDIAN_CPU, "Force CPU endian-ness"},
    {.name = NULL}
};

const struct supported_fmt *
pick_format(const char *name, const struct supported_fmt ftable[])
{
    int i;

    for (i = 0; ftable[i].name != NULL; i++) {
        if (strcasecmp(name, ftable[i].name) == 0) {
            return (&ftable[i]);
        }
    }
    return (NULL);
}

void
dump_formats_descr(const char *msg, const struct supported_fmt ftable[])
{
    int i;

    fprintf(stderr, "%s", msg);
    for (i = 0; ftable[i].name != NULL; i++) {
        fprintf(stderr, "    \"%s\"\t- %s\n", ftable[i].name, ftable[i].descr);
    }
}
