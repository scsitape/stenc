AC_INIT([stenc],[1.1.1])
AC_CONFIG_SRCDIR([src/main.cpp])
AM_INIT_AUTOMAKE([foreign subdir-objects])

AC_CONFIG_HEADERS([config.h])
AC_CHECK_HEADER([sys/types.h])
AC_CHECK_HEADER([sys/machine.h])
# Checks for programs
AC_PROG_CXX

# Checks for header files.
m4_warn([obsolete],
[The preprocessor macro `STDC_HEADERS' is obsolete.
  Except in unusual embedded environments, you can safely include all
  ISO C90 headers unconditionally.])dnl
# Autoupdate added the next two lines to ensure that your configure
# script's behavior did not change.  They are probably safe to remove.

# Disable AC_CHECK_INCLUDES_DEFAULT, because this macro requires autoconf at 
# least version 2.70 which is not default yet in many distributions.
# See: https://github.com/scsitape/stenc/issues/33
# AC_CHECK_INCLUDES_DEFAULT
AC_PROG_EGREP



AC_MSG_CHECKING(whether to output raw SCSI messages)
AC_ARG_WITH([scsi-debug],
            [AS_HELP_STRING([--with-scsi-debug],[enable scsi communication debug])],
	    [AC_DEFINE([DEBUGSCSI],[1],[Define if you want to debug SCSI Communication])
	     AC_MSG_RESULT(yes)],
	    [AC_MSG_RESULT(no)])

AC_MSG_CHECKING(default encryption algorithm index to use)
AC_ARG_WITH([default-algorithm],
            [AS_HELP_STRING([--with-default-algorithm=<number>],[the default algorithm index to set for encryption.  Defaults to 0])],
	    [AC_DEFINE_UNQUOTED([DEFAULT_ALGORITHM],$withval,"") AC_MSG_RESULT($withval)],
	    [AC_DEFINE([DEFAULT_ALGORITHM],0,"") AC_MSG_RESULT(0)])

AC_MSG_CHECKING(your OS)
system=`uname`
case $system in
	Linux)
		AC_DEFINE(OS_LINUX,1,"")
		AC_MSG_RESULT(Linux)
		;;
	FreeBSD)
		AC_DEFINE(OS_FREEBSD,1,"")
		AC_MSG_RESULT(FreeBSD)
		;;
	*)
		AC_MSG_ERROR(unknown OS type: $system)
		;;
esac

AC_MSG_CHECKING(whether to build with static libgcc)
AC_ARG_WITH([static-libgcc],
            [AS_HELP_STRING([--with-static-libgcc],[build with static libgcc library])],
            [
	     AC_MSG_RESULT(yes)
	     LDFLAGS="${LDFLAGS} -static-libgcc -Wl,-static -lstdc++ -lsupc++"
	     ],
            [AC_MSG_RESULT(no)])

AC_CHECK_PROG(PANDOC, [pandoc], [yes])
AM_CONDITIONAL([FOUND_PANDOC], [test "x$PANDOC" = xyes])
AM_COND_IF([FOUND_PANDOC],,[AC_MSG_ERROR([required program 'pandoc' not found.])])

if test "${system}" = "FreeBSD"; then
	  LIBS="${LIBS} -lcam"
fi

# BASH completion
PKG_CHECK_VAR([BASH_COMPLETION_DIR], [bash-completion >= 2.0], [completionsdir],
    [
        with_bash_completion_dir=yes;
        AC_MSG_NOTICE(BASH_COMPLETION_DIR is $BASH_COMPLETION_DIR);
        AC_SUBST([BASH_COMPLETION_DIR])
    ],
    [with_bash_completion_dir=no])

AM_CONDITIONAL([ENABLE_BASH_COMPLETION],[test "x$with_bash_completion_dir" != "xno"])

AC_CONFIG_FILES([Makefile src/Makefile man/Makefile tests/Makefile bash-completion/Makefile])
AC_OUTPUT 
