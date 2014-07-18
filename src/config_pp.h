#ifndef _CONFIG_PP_H
#define _CONFIG_PP_H

#include "config.h"

#if defined(HAVE_ERR_H)
#undef NO_ERR_H
#else
#define NO_ERR_H 1
#endif

#endif
