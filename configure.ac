PACKAGE=stenc
VERSION=1.0.7

AC_INIT($PACKAGE, $VERSION)
AC_CONFIG_SRCDIR([src/main.cpp])
AM_INIT_AUTOMAKE

AC_CONFIG_HEADERS([config.h])
AC_CHECK_HEADER([sys/types.h])
AC_CHECK_HEADER([sys/machine.h])
# Checks for programs
AC_PROG_CXX

# Checks for header files.
AC_HEADER_STDC


AC_MSG_CHECKING(whether to output raw SCSI messages)
AC_ARG_WITH([scsi-debug],
            [AS_HELP_STRING([--with-scsi-debug],[enable scsi communication debug])],
	    [AC_DEFINE([DEBUGSCSI],[1],[Define if you want to debug SCSI Communication])
	     AC_MSG_RESULT(yes)],
	    [AC_MSG_RESULT(no)])

AC_MSG_CHECKING(max tape read blocks for volume status)
AC_ARG_WITH([max-tape-read-blocks],
            [AS_HELP_STRING([--with-max-tape-read-blocks=<number>],[how many blocks the tape drive will seek to determine the encryption status on the volume.  Defaults to 100])],
	    [AC_DEFINE_UNQUOTED([MAX_TAPE_READ_BLOCKS],$withval,"") AC_MSG_RESULT($withval)],
	    [AC_DEFINE([MAX_TAPE_READ_BLOCKS],100,"") AC_MSG_RESULT(100)])

AC_MSG_CHECKING(default encryption algorithm index to use)
AC_ARG_WITH([default-algorithm],
            [AS_HELP_STRING([--with-default-algorithm=<number>],[the default algorithm index to set for encryption.  Defaults to 0])],
	    [AC_DEFINE_UNQUOTED([DEFAULT_ALGORITHM],$withval,"") AC_MSG_RESULT($withval)],
	    [AC_DEFINE([DEFAULT_ALGORITHM],0,"") AC_MSG_RESULT(0)])

AC_MSG_CHECKING(default CEEM flag to use)
AC_ARG_WITH([default-ceem],
            [AS_HELP_STRING([--with-default-ceem=<number>],[the default CEEM flag when setting options.  Defaults to 0])],
	    [AC_DEFINE_UNQUOTED([DEFAULT_CEEM],$withval,"") AC_MSG_RESULT($withval)],
	    [AC_DEFINE([DEFAULT_CEEM],0,"") AC_MSG_RESULT(0)])
AC_MSG_CHECKING(default key size to use)
AC_ARG_WITH([default-key-size],
            [AS_HELP_STRING([--with-default-key-size=<bytes>],[the default key size for your drive.  Only used when turning off encryption.  Defaults to 32 (256 bit)])],
	    [AC_DEFINE_UNQUOTED([DEFAULT_KEYSIZE],$withval,"") AC_MSG_RESULT($withval)],
	    [AC_DEFINE([DEFAULT_KEYSIZE],32,"") AC_MSG_RESULT(32)])

AC_MSG_CHECKING(your OS)
system=`uname`
case $system in
        Linux)
	        AC_DEFINE(OS_LINUX,1,"")
	        AC_MSG_RESULT(Linux)
	        ;;
	AIX)
        	AC_DEFINE(OS_AIX,1,"")
		AC_MSG_RESULT(AIX)
		;;
esac

AC_MSG_CHECKING(whether to build with static libgcc)
AC_ARG_WITH([static-libgcc],
            [AS_HELP_STRING([--with-static-libgcc],[build with static libgcc library])],
            [
	     AC_MSG_RESULT(yes)
	     if test "${system}" = "AIX"; then
	        LDFLAGS="${LDFLAGS} -static-libgcc -Wl,-bstatic -lstdc++ -Wl,-bdynamic -lsupc++"
	     else
		LDFLAGS="${LDFLAGS} -static-libgcc -Wl,-static -lstdc++ -lsupc++"
	   	
	     fi
	     ],
            [AC_MSG_RESULT(no)])


AC_MSG_CHECKING(whether to convert rewinding device names to non-rewinding device names)
AC_ARG_ENABLE([device-name-conversion],
            [AS_HELP_STRING([--enable-device-name-conversion],[converts /dev/st* to /dev/st*.1 and /dev/rmt* to /dev/rmt*.1 to prevent rewinds.  Enabled by default.])],
	    [enable_dnc=$enableval],
	    [enable_dnc="yes"]
	    )

if test "$enable_dnc" = "yes"; then
	  AC_MSG_RESULT(yes)
else
	  AC_DEFINE(DISABLE_DEVICE_NAME_CONVERSION,1,"")
	  AC_MSG_RESULT(no)
fi
	  


AC_OUTPUT(Makefile src/Makefile man/Makefile) 

