AC_PREREQ([2.69])
AC_INIT([libtun2sock], [0.1], [wzypublic@gmail.com])

AC_CONFIG_MACRO_DIR([m4])

AC_SUBST([VERSION_MAJOR], [0])
AC_SUBST([VERSION_MINOR], [1])

AM_INIT_AUTOMAKE([-Wall foreign])

AC_CONFIG_SRCDIR([include/tun2sock.h])
AC_CONFIG_SRCDIR([src/tun2sock.c])

AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC_C99
AM_PROG_AR

LT_INIT

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([stddef.h stdint.h string.h], [],
   [AC_MSG_ERROR([Missing header file])])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_CHECK_FUNCS([memmove memset strchr], [],
    [AC_MSG_ERROR([Missing function])])

AC_CONFIG_FILES([
    Makefile
    src/Makefile
    include/Makefile
    include/tun2sock.h
])

AC_OUTPUT
