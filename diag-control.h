/* -*- Mode: c; tab-width: 8; indent-tabs-mode: 1; c-basic-offset: 8; -*- */
/*
 * Copyright (c) 1993, 1994, 1995, 1996, 1997
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the Computer Systems
 *	Engineering Group at Lawrence Berkeley Laboratory.
 * 4. Neither the name of the University nor of the Laboratory may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _diag_control_h
#define _diag_control_h

#include "compiler-tests.h"

#ifndef _MSC_VER
  /*
   * Clang and GCC both support this way of putting pragmas into #defines.
   * We don't use it unless we have a compiler that supports it; the
   * warning-suppressing pragmas differ between Clang and GCC, so we test
   * for both of those separately.
   */
  #define DIAG_DO_PRAGMA(x) _Pragma (#x)
#endif

/*
 * The current clang compilers also define __GNUC__ and __GNUC_MINOR__
 * thus we need to test the clang case before the GCC one
 */
#if ND_IS_AT_LEAST_CLANG_VERSION(2,8)
  /*
   * Clang complains if you OR together multiple enum values of a
   * given enum type and them pass it as an argument of that enum
   * type.  Some libcap-ng routines use enums to define bit flags;
   * we want to squelch the warnings that produces.
   */
  #define DIAG_OFF_ASSIGN_ENUM \
    DIAG_DO_PRAGMA(clang diagnostic push) \
    DIAG_DO_PRAGMA(clang diagnostic ignored "-Wassign-enum")
  #define DIAG_ON_ASSIGN_ENUM \
    DIAG_DO_PRAGMA(clang diagnostic pop)

  /*
   * It also legitimately complains about some code in the BSD
   * getopt_long() - that code explicitly and deliberately
   * violates the contract by permuting the argument vector
   * (declared as char const *argv[], meaning "I won't change
   * the vector by changing any of its elements), as do the
   * GNU and Solaris getopt_long().  This is documented in the
   * man pages for all versions; it can be suppressed by setting
   * the environment variable POSIXLY_CORRECT or by putting a "+"
   * at the beginning of the option string.
   *
   * We suppress the warning.
   */
  #define DIAG_OFF_CAST_QUAL \
    DIAG_DO_PRAGMA(clang diagnostic push) \
    DIAG_DO_PRAGMA(clang diagnostic ignored "-Wcast-qual")
  #define DIAG_ON_CAST_QUAL \
    DIAG_DO_PRAGMA(clang diagnostic pop)

  /*
   * Suppress deprecation warnings.
   */
  #define DIAG_OFF_DEPRECATION \
    DIAG_DO_PRAGMA(clang diagnostic push) \
    DIAG_DO_PRAGMA(clang diagnostic ignored "-Wdeprecated-declarations")
  #define DIAG_ON_DEPRECATION \
    DIAG_DO_PRAGMA(clang diagnostic pop)
  #define DIAG_OFF_FORMAT_TRUNCATION
  #define DIAG_ON_FORMAT_TRUNCATION
#elif ND_IS_AT_LEAST_GNUC_VERSION(4,2)
  /* GCC apparently doesn't complain about ORing enums together. */
  #define DIAG_OFF_ASSIGN_ENUM
  #define DIAG_ON_ASSIGN_ENUM

  /*
   * It does, however, complain about casting away constness in
   * missing/getopt_long.c.
   */
  #define DIAG_OFF_CAST_QUAL \
    DIAG_DO_PRAGMA(GCC diagnostic push) \
    DIAG_DO_PRAGMA(GCC diagnostic ignored "-Wcast-qual")
  #define DIAG_ON_CAST_QUAL \
    DIAG_DO_PRAGMA(GCC diagnostic pop)

  /*
   * Suppress deprecation warnings.
   */
  #define DIAG_OFF_DEPRECATION \
    DIAG_DO_PRAGMA(GCC diagnostic push) \
    DIAG_DO_PRAGMA(GCC diagnostic ignored "-Wdeprecated-declarations")
  #define DIAG_ON_DEPRECATION \
    DIAG_DO_PRAGMA(GCC diagnostic pop)
#else
  #define DIAG_OFF_ASSIGN_ENUM
  #define DIAG_ON_ASSIGN_ENUM
  #define DIAG_OFF_CAST_QUAL
  #define DIAG_ON_CAST_QUAL
  #define DIAG_OFF_DEPRECATION
  #define DIAG_ON_DEPRECATION
#endif

#endif /* _diag_control_h */