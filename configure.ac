    AC_INIT(mobster, 0.1dev)
    m4_ifndef([AM_SILENT_RULES], [m4_define([AM_SILENT_RULES],[])])AM_SILENT_RULES([yes])
    AC_CONFIG_HEADERS([config.h])
    AC_CONFIG_SRCDIR([src/mobster.c])
    AC_CONFIG_MACRO_DIR(m4)
    AM_INIT_AUTOMAKE

    AC_LANG_C
    AC_PROG_CC_C99
    AC_PROG_LIBTOOL
    PKG_PROG_PKG_CONFIG(0.21) # 0.21 is the CentOS 5.11 version

    dnl Taken from https://llvm.org/svn/llvm-project/llvm/trunk/autoconf/configure.ac
    dnl check if we compile using clang or gcc. On some systems the gcc binary is
    dnl is actually clang, so do a compile test.
    AC_MSG_CHECKING([whether GCC or Clang is our compiler])
    AC_LANG_PUSH([C])
    compiler=unknown
    AC_COMPILE_IFELSE([AC_LANG_SOURCE([[#if ! __clang__
                                        #error
                                        #endif
                                      ]])],
                       compiler=clang,
                      [AC_COMPILE_IFELSE([AC_LANG_SOURCE([[#if ! __GNUC__
                                                           #error
                                                           #endif
                                                         ]])],
                       compiler=gcc, [])])
    AC_LANG_POP([C])
    AC_MSG_RESULT([${compiler}])

    case "$compiler" in
        clang)
            CLANG_CFLAGS="-Wextra -Werror-implicit-function-declaration"
            AC_MSG_CHECKING([clang __sync_bool_compare_and_swap support])
            AC_TRY_COMPILE([#include <stdio.h>],
                [ unsigned int i = 0; (void)__sync_bool_compare_and_swap(&i, 1, 1);],
                [
                    AC_DEFINE([__GCC_HAVE_SYNC_COMPARE_AND_SWAP_1], [1], [Fake GCC atomic support])
                    AC_DEFINE([__GCC_HAVE_SYNC_COMPARE_AND_SWAP_2], [1], [Fake GCC atomic support])
                    AC_DEFINE([__GCC_HAVE_SYNC_COMPARE_AND_SWAP_4], [1], [Fake GCC atomic support])
                    AC_DEFINE([__GCC_HAVE_SYNC_COMPARE_AND_SWAP_8], [1], [Fake GCC atomic support])
                    AC_MSG_RESULT([yes]) ],
                [AC_MSG_RESULT([no])])
            AC_SUBST(CLANG_CFLAGS)
            ;;
        gcc)
            dnl get gcc version
            AC_MSG_CHECKING([gcc version])
                    gccver=$($CC -dumpversion)
                    gccvermajor=$(echo $gccver | cut -d . -f1)
                    gccverminor=$(echo $gccver | cut -d . -f2)
                    gccvernum=$(expr $gccvermajor "*" 100 + $gccverminor)
            AC_MSG_RESULT($gccver)

            if test "$gccvernum" -ge "400"; then
                dnl gcc 4.0 or later
                GCC_CFLAGS="-Wextra -Werror-implicit-function-declaration"
                # remove optimization options that break our code
                # VJ 2010/06/27: no-tree-pre added. It breaks ringbuffers code.
                GCC_CFLAGS="$GCC_CFLAGS -fno-tree-pre"
            else
                GCC_CFLAGS="-W"
            fi
            AC_SUBST(GCC_CFLAGS)
            ;;
        *)
            AC_MSG_WARN([unsupported/untested compiler, this may or may not work])
            ;;
    esac

    # Checks for programs.
    AC_PROG_AWK
    AC_PROG_CC
    AC_PROG_CPP
    AC_PROG_INSTALL
    AC_PROG_LN_S
    AC_PROG_MAKE_SET

    AC_PATH_PROG(HAVE_PKG_CONFIG, pkg-config, "no")
    if test "$HAVE_PKG_CONFIG" = "no"; then
        echo
        echo "   ERROR! pkg-config not found, go get it  "
        echo "   http://pkg-config.freedesktop.org/wiki/ "
        echo "   or install from your distribution       "
        echo
        exit 1
    fi

    AC_PATH_PROG(HAVE_PYTHON_CONFIG, python, "no")
    if test "$HAVE_PYTHON_CONFIG" = "no"; then
        echo
        echo "   Warning! python not found, you will not be     "
        echo "   able to install surictasc unix socket client   "
        echo
        enable_python="no"
    else
        enable_python="yes"
    fi
    AM_CONDITIONAL([HAVE_PYTHON], [test "$HAVE_PYTHON_CONFIG" != "no"])

    AC_PATH_PROG(HAVE_WGET, wget, "no")
    if test "$HAVE_WGET" = "no"; then
        AC_PATH_PROG(HAVE_CURL, curl, "no")
        if test "$HAVE_CURL" = "no"; then
            echo
            echo "   Warning curl or wget not found, you won't be able to"
            echo "   download latest ruleset with 'make install-rules'"
        fi
    fi
    AM_CONDITIONAL([HAVE_FETCH_COMMAND], [test "x$HAVE_WGET" != "xno" || test "x$HAVE_CURL" != "xno"])
    AM_CONDITIONAL([HAVE_WGET_COMMAND], [test "x$HAVE_WGET" != "xno"])

    # Checks for libraries.

    # Checks for header files.
    AC_CHECK_HEADERS([arpa/inet.h assert.h ctype.h errno.h fcntl.h inttypes.h])
    AC_CHECK_HEADERS([getopt.h])
    AC_CHECK_HEADERS([limits.h netdb.h netinet/in.h poll.h sched.h signal.h])
    AC_CHECK_HEADERS([stdarg.h stdint.h stdio.h stdlib.h string.h sys/ioctl.h])
    AC_CHECK_HEADERS([syslog.h sys/prctl.h sys/socket.h sys/stat.h sys/syscall.h])
    AC_CHECK_HEADERS([sys/time.h time.h unistd.h])
    AC_CHECK_HEADERS([sys/ioctl.h linux/if_ether.h linux/if_packet.h linux/filter.h])
    AC_CHECK_HEADERS([linux/ethtool.h linux/sockios.h])
    AC_CHECK_HEADER(glob.h,,[AC_ERROR(glob.h not found ...)])

    AC_CHECK_HEADERS([sys/socket.h net/if.h sys/mman.h linux/if_arp.h], [], [],
    [[#ifdef HAVE_SYS_SOCKET_H
        #include <sys/types.h>
        #include <sys/socket.h>
        #endif
    ]])

    AC_CHECK_HEADERS([windows.h winsock2.h ws2tcpip.h w32api/wtypes.h], [], [],
                    [[
                        #ifndef _X86_
                        #define _X86_
                        #endif
                     ]])
    AC_CHECK_HEADERS([w32api/winbase.h], [], [],
                    [[
                        #ifndef _X86_
                        #define _X86_
                        #endif
                        #include <windows.h>
                     ]])

    # Checks for typedefs, structures, and compiler characteristics.
    AC_C_INLINE
    AC_TYPE_PID_T
    AC_TYPE_SIZE_T
    AC_TYPE_INT32_T
    AC_TYPE_UINT16_T
    AC_TYPE_UINT32_T
    AC_TYPE_UINT64_T
    AC_TYPE_UINT8_T
    AC_HEADER_STDBOOL

    # Checks for library functions.
    AC_FUNC_MALLOC
    AC_FUNC_REALLOC
    AC_CHECK_FUNCS([gettimeofday memset strcasecmp strchr strdup strerror strncasecmp strtol strtoul memchr memrchr])

    OCFLAGS=$CFLAGS
    CFLAGS=""
    AC_CHECK_FUNCS([strlcpy strlcat])
    CFLAGS=$OCFLAGS

    # Add large file support
    AC_SYS_LARGEFILE

    #check for os
    AC_MSG_CHECKING([host os])

    # lua pkg-config name differs per OS
    LUA_PC_NAME="lua5.1"
    LUA_LIB_NAME="lua5.1"

    # If no host os was detected, try with uname
    if test -z "$host" ; then
	    host="`uname`"
    fi
    echo -n "installation for $host OS... "

    e_magic_file="/usr/share/file/magic"
    case "$host" in
        *-*-*freebsd*)
            LUA_PC_NAME="lua-5.1"
            LUA_LIB_NAME="lua-5.1"
            CFLAGS="${CFLAGS} -DOS_FREEBSD"
            CPPFLAGS="${CPPFLAGS} -I/usr/local/include -I/usr/local/include/libnet11"
            LDFLAGS="${LDFLAGS} -L/usr/local/lib -L/usr/local/lib/libnet11"
            e_magic_file="/usr/share/misc/magic"
            ;;
        *-*-openbsd*)
            LUA_PC_NAME="lua51"
            CFLAGS="${CFLAGS} -D__OpenBSD__"
            CPPFLAGS="${CPPFLAGS} -I/usr/local/include -I/usr/local/include/libnet-1.1"
            LDFLAGS="${LDFLAGS} -L/usr/local/lib -I/usr/local/lib/libnet-1.1"
            e_magic_file="/usr/local/share/misc/magic.mgc"
            ;;
        *darwin*|*Darwin*)
            LUA_PC_NAME="lua-5.1"
            LUA_LIB_NAME="lua-5.1"
            CFLAGS="${CFLAGS} -DOS_DARWIN"
            CPPFLAGS="${CPPFLAGS} -I/opt/local/include"
            LDFLAGS="${LDFLAGS} -L/opt/local/lib"
            ;;
        *-*-linux*)
            #for now do nothing
            ;;
        *-*-mingw32*)
            CFLAGS="${CFLAGS} -DOS_WIN32"
            LDFLAGS="${LDFLAGS} -lws2_32"
            WINDOWS_PATH="yes"
            ;;
        *-*-cygwin)
            LUA_PC_NAME="lua"
            LUA_LIB_NAME="lua"
            WINDOWS_PATH="yes"
            ;;
        *)
            AC_MSG_WARN([unsupported OS this may or may not work])
            ;;
    esac
    AC_MSG_RESULT(ok)

  # disable TLS on user request
    AC_ARG_ENABLE(threading-tls,
           AS_HELP_STRING([--disable-threading-tls], [Disable TLS (thread local storage)])], [enable_tls="$enableval"],[enable_tls=yes])
    AS_IF([test "x$enable_tls" = "xyes"], [
        # check if our target supports thread local storage
        AC_MSG_CHECKING(for thread local storage __thread support)
        AC_TRY_COMPILE([#include <stdlib.h>],
            [ static __thread int i; i = 1; i++; ],
            [AC_DEFINE([TLS], [1], [Thread local storage])
             AC_MSG_RESULT([yes]) ],
            [AC_MSG_RESULT([no])])
    ])

    #Enable support for gcc compile time security options. There is no great way to do detection of valid cflags that I have found
    #AX_CFLAGS_GCC_OPTION don't seem to do a better job than the code below and are a pain because of extra m4 files etc.
    #These flags seem to be supported on CentOS 5+, Ubuntu 8.04+, and FedoreCore 11+
    #Options are taken from https://wiki.ubuntu.com/CompilerFlags
    AC_ARG_ENABLE(gccprotect,
           AS_HELP_STRING([--enable-gccprotect], [Detect and use gcc hardening options]),,[enable_gccprotect=no])

    AS_IF([test "x$enable_gccprotect" = "xyes"], [
        #buffer overflow protection
        AC_MSG_CHECKING(for -fstack-protector)
        TMPCFLAGS="${CFLAGS}"
        CFLAGS="${CFLAGS} -fstack-protector"
        AC_TRY_LINK(,,SECCFLAGS="-fstack-protector"
            AC_MSG_RESULT(yes),
            AC_MSG_RESULT(no))
        CFLAGS="${TMPCFLAGS}"

        #compile-time best-practices errors for certain libc functions, provides checks of buffer lengths and memory regions
        AC_MSG_CHECKING(for -D_FORTIFY_SOURCE=2)
        TMPCFLAGS="${CFLAGS}"
        CFLAGS="${CFLAGS} -D_FORTIFY_SOURCE=2"
        AC_TRY_COMPILE(,,SECCFLAGS="${SECCFLAGS} -D_FORTIFY_SOURCE=2"
            AC_MSG_RESULT(yes),
            AC_MSG_RESULT(no))
        CFLAGS="${TMPCFLAGS}"

        #compile-time warnings about misuse of format strings
        AC_MSG_CHECKING(for -Wformat -Wformat-security)
        TMPCFLAGS="${CFLAGS}"
        CFLAGS="${CFLAGS} -Wformat -Wformat-security"
        AC_TRY_COMPILE(,,SECCFLAGS="${SECCFLAGS} -Wformat -Wformat-security"
            AC_MSG_RESULT(yes),
            AC_MSG_RESULT(no))
        CFLAGS="${TMPCFLAGS}"

        #provides a read-only relocation table area in the final ELF
        AC_MSG_CHECKING(for -z relro)
        TMPLDFLAGS="${LDFLAGS}"
        LDFLAGS="${LDFLAGS} -z relro"
        AC_TRY_LINK(,,SECLDFLAGS="${SECLDFLAGS} -z relro"
            AC_MSG_RESULT(yes),
            AC_MSG_RESULT(no))
        LDFLAGS="${TMPLDFLAGS}"

        #forces all relocations to be resolved at run-time
        AC_MSG_CHECKING(for -z now)
        TMPLDFLAGS="${LDFLAGS}"
        LDFLAGS="${LDFLAGS} -z now"
        AC_TRY_LINK(,,SECLDFLAGS="${SECLDFLAGS} -z now"
            AC_MSG_RESULT(yes),
            AC_MSG_RESULT(no))
        LDFLAGS="${TMPLDFLAGS}"

        AC_SUBST(SECCFLAGS)
        AC_SUBST(SECLDFLAGS)
    ])

    #enable profile generation
    AC_ARG_ENABLE(gccprofile,
           AS_HELP_STRING([--enable-gccprofile], [Enable gcc profile info i.e -pg flag is set]),,[enable_gccprofile=no])
    AS_IF([test "x$enable_gccprofile" = "xyes"], [
        CFLAGS="${CFLAGS} -pg"
    ])

    #enable gcc march=native gcc 4.2 or later
    AC_ARG_ENABLE(gccmarch_native,
           AS_HELP_STRING([--enable-gccmarch-native], [Enable gcc march=native gcc 4.2 and later only]),,[enable_gccmarch_native=yes])
    AS_IF([test "x$enable_gccmarch_native" = "xyes"], [
            OFLAGS="$CFLAGS"
            CFLAGS="$CFLAGS -march=native"
            AC_MSG_CHECKING([checking if $CC supports -march=native])
            AC_COMPILE_IFELSE(  [AC_LANG_PROGRAM([[#include <stdlib.h>]])],
                        [
                          AC_MSG_RESULT([yes])
                          OPTIMIZATION_CFLAGS="-march=native"
                          AC_SUBST(OPTIMIZATION_CFLAGS)
                        ],
                        [
                          AC_MSG_RESULT([no])
                          CFLAGS="$OFLAGS"
                          enable_gccmarch_native=no
                        ]
                     )
    ])

# options

  # enable debug output
    AC_ARG_ENABLE(debug,
           AS_HELP_STRING([--enable-debug], [Enable debug output]),,[enable_debug=no])
    AS_IF([test "x$enable_debug" = "xyes"], [
        AC_DEFINE([DEBUG],[1],[Enable debug output])
    ])
    AM_CONDITIONAL([DEBUG], [test "x$enable_debug" = "xyes"])

  # libpthread
    AC_ARG_WITH(libpthread_includes,
            [  --with-libpthread-includes=DIR  libpthread include directory],
            [with_libpthread_includes="$withval"],[with_libpthread_includes=no])
    AC_ARG_WITH(libpthread_libraries,
            [  --with-libpthread-libraries=DIR    libpthread library directory],
            [with_libpthread_libraries="$withval"],[with_libpthread_libraries="no"])

    if test "$with_libpthread_includes" != "no"; then
        CPPFLAGS="${CPPFLAGS} -I${with_libpthread_includes}"
    fi

    dnl AC_CHECK_HEADER(pthread.h,,[AC_ERROR(pthread.h not found ...)])

    if test "$with_libpthread_libraries" != "no"; then
        LDFLAGS="${LDFLAGS}  -L${with_libpthread_libraries}"
    fi

    PTHREAD=""
    AC_CHECK_LIB(pthread, pthread_create,, PTHREAD="no")

    if test "$PTHREAD" = "no"; then
        echo
        echo "   ERROR! libpthread library not found, glibc problem?"
        echo
        exit 1
    fi

  # liblua
    AC_ARG_ENABLE(lua,
	        AS_HELP_STRING([--enable-lua],[Enable Lua support]),
	        [ enable_lua="yes"],
	        [ enable_lua="no"])
    AC_ARG_ENABLE(luajit,
	        AS_HELP_STRING([--enable-luajit],[Enable Luajit support]),
	        [ enable_luajit="yes"],
	        [ enable_luajit="no"])
    if test "$enable_lua" = "yes"; then
        if test "$enable_luajit" = "yes"; then
            echo "ERROR: can't enable liblua and luajit at the same time."
            echo "For LuaJIT, just use --enable-luajit. For liblua (no jit)"
            echo "support, use just --enable-lua."
            echo "Both options will enable the Lua scripting capabilities"
            echo "in Mobster".
            echo
            exit 1
        fi
    fi

    AC_ARG_WITH(liblua_includes,
            [  --with-liblua-includes=DIR  liblua include directory],
            [with_liblua_includes="$withval"],[with_liblua_includes="no"])
    AC_ARG_WITH(liblua_libraries,
            [  --with-liblua-libraries=DIR    liblua library directory],
            [with_liblua_libraries="$withval"],[with_liblua_libraries="no"])

    if test "$enable_lua" = "yes"; then
        if test "$with_liblua_includes" != "no"; then
            CPPFLAGS="${CPPFLAGS} -I${with_liblua_includes}"
        else
            # lua lua51 lua5.1 lua-5.1
            PKG_CHECK_MODULES([LUA], [lua], [LUA="yes"], [
                PKG_CHECK_MODULES([LUA], [lua5.1], [LUA="yes"], [
                    PKG_CHECK_MODULES([LUA], [lua-5.1], [LUA="yes"], [
                        PKG_CHECK_MODULES([LUA], [lua51], [LUA="yes"], [
                            LUA="no"
                        ])
                    ])
                ])
            ])
            CPPFLAGS="${CPPFLAGS} ${LUA_CFLAGS}"
        fi

        AC_CHECK_HEADER(lualib.h,LUA="yes",LUA="no")
        if test "$LUA" = "yes"; then
            if test "$with_liblua_libraries" != "no"; then
                LDFLAGS="${LDFLAGS}  -L${with_liblua_libraries}"
                AC_CHECK_LIB(${LUA_LIB_NAME}, luaL_openlibs,, LUA="no")
                if test "$LUA" = "no"; then
                    echo
                    echo "   ERROR!  liblua library not found, go get it"
                    echo "   from http://lua.org/index.html or your distribution:"
                    echo
                    echo "   Ubuntu: apt-get install liblua-5.1-dev"
                    echo "   CentOS/Fedora: yum install lua-devel"
                    echo
                    echo "   If you installed software in a non-standard prefix"
                    echo "   consider adjusting the PKG_CONFIG_PATH environment variable"
                    echo "   or use --with-liblua-libraries configure option."
                    echo
                    exit 1
                fi
            else
                # lua lua51 lua5.1 lua-5.1
                PKG_CHECK_MODULES([LUA], [lua], [LUA="yes"], [
                    PKG_CHECK_MODULES([LUA], [lua5.1], [LUA="yes"], [
                        PKG_CHECK_MODULES([LUA], [lua-5.1], [LUA="yes"], [
                            PKG_CHECK_MODULES([LUA], [lua51], [LUA="yes"], [
                                LUA="no"
                            ])
                        ])
                    ])
                ])
                LDFLAGS="${LDFLAGS} ${LUA_LIBS}"
            fi

            AC_DEFINE([HAVE_LUA],[1],[liblua available])
            enable_lua="yes"
        else
	        echo
                echo "   ERROR!  liblua headers not found, go get them"
                echo "   from http://lua.org/index.html or your distribution:"
                echo
                echo "   Ubuntu: apt-get install liblua-5.1-dev"
                echo "   CentOS/Fedora: yum install lua-devel"
                echo
                echo "   If you installed software in a non-standard prefix"
                echo "   consider adjusting the PKG_CONFIG_PATH environment variable"
                echo "   or use --with-liblua-includes and --with-liblua-libraries"
                echo "   configure option."
                echo
                exit 1
        fi
    fi

  # libluajit
    AC_ARG_WITH(libluajit_includes,
            [  --with-libluajit-includes=DIR  libluajit include directory],
            [with_libluajit_includes="$withval"],[with_libluajit_includes="no"])
    AC_ARG_WITH(libluajit_libraries,
            [  --with-libluajit-libraries=DIR    libluajit library directory],
            [with_libluajit_libraries="$withval"],[with_libluajit_libraries="no"])

    if test "$enable_luajit" = "yes"; then
        if test "$with_libluajit_includes" != "no"; then
            CPPFLAGS="${CPPFLAGS} -I${with_libluajit_includes}"
        else
            PKG_CHECK_MODULES([LUAJIT], [luajit], , LUAJIT="no")
            CPPFLAGS="${CPPFLAGS} ${LUAJIT_CFLAGS}"
        fi

        AC_CHECK_HEADER(lualib.h,LUAJIT="yes",LUAJIT="no")
        if test "$LUAJIT" = "yes"; then
            if test "$with_libluajit_libraries" != "no"; then
                LDFLAGS="${LDFLAGS}  -L${with_libluajit_libraries}"
            else
                PKG_CHECK_MODULES([LUAJIT], [luajit])
                LDFLAGS="${LDFLAGS} ${LUAJIT_LIBS}"
            fi

            AC_CHECK_LIB(luajit-5.1, luaL_openlibs,, LUAJIT="no")

            if test "$LUAJIT" = "no"; then
                echo
                echo "   ERROR!  libluajit library not found, go get it"
                echo "   from http://luajit.org/index.html or your distribution:"
                echo
                echo "   Ubuntu: apt-get install libluajit-5.1-dev"
                echo
                echo "   If you installed software in a non-standard prefix"
                echo "   consider adjusting the PKG_CONFIG_PATH environment variable"
                echo "   or use --with-libluajit-libraries configure option."
                echo
                exit 1
            fi

            AC_DEFINE([HAVE_LUA],[1],[lua support available])
            AC_DEFINE([HAVE_LUAJIT],[1],[libluajit available])
            enable_lua="yes, through luajit"
            enable_luajit="yes"
        else
	        echo
                echo "   ERROR!  libluajit headers not found, go get them"
                echo "   from http://luajit.org/index.html or your distribution:"
                echo
                echo "   Ubuntu: apt-get install libluajit-5.1-dev"
                echo
                echo "   If you installed software in a non-standard prefix"
                echo "   consider adjusting the PKG_CONFIG_PATH environment variable"
                echo "   or use --with-libluajit-includes and --with-libluajit-libraries"
                echo "   configure option."
                echo
                exit 1
        fi
    fi

  # Position Independent Executable
    AC_ARG_ENABLE(pie,
                AS_HELP_STRING([--enable-pie],[Enable compiling as a position independent executable]),
                [ enable_pie="yes"],
                [ enable_pie="no"])
    if test "$enable_pie" = "yes"; then
        CPPFLAGS="${CPPFLAGS} -fPIC"
        LDFLAGS="${LDFLAGS} -pie"
    fi

# libhiredis
    enable_hiredis="yes"
    AC_ARG_ENABLE(hiredis,
	        AS_HELP_STRING([--enable-hiredis],[Enable Redis support]),
	        ,
	        [ enable_hiredis="yes"])
    AC_ARG_WITH(libhiredis_includes,
            [  --with-libhiredis-includes=DIR  libhiredis include directory],
            [with_libhiredis_includes="$withval"],[with_libhiredis_includes="no"])
    AC_ARG_WITH(libhiredis_libraries,
            [  --with-libhiredis-libraries=DIR    libhiredis library directory],
            [with_libhiredis_libraries="$withval"],[with_libhiredis_libraries="no"])

    if test "$enable_hiredis" = "yes"; then
        if test "$with_libhiredis_includes" != "no"; then
            CPPFLAGS="${CPPFLAGS} -I${with_libhiredis_includes}"
        fi

        AC_CHECK_HEADER("hiredis/hiredis.h",HIREDIS="yes",HIREDIS="no")
        if test "$HIREDIS" = "yes"; then
            if test "$with_libhiredis_libraries" != "no"; then
                LDFLAGS="${LDFLAGS}  -L${with_libhiredis_libraries}"
            fi
            AC_CHECK_LIB(hiredis, redisConnect,, HIREDIS="no")
        fi
        if test "$HIREDIS" = "no"; then
            echo
            echo "   ERROR!  libhiredis library not found, go get it"
            echo "   from https://github.com/redis/hiredis or your distribution:"
            echo
            echo "   Ubuntu: apt-get install libhiredis-dev"
            echo "   Fedora: yum install libhiredis-devel"
            echo
            exit 1
        fi
        if test "$HIREDIS" = "yes"; then
            AC_DEFINE([HAVE_LIBHIREDIS],[1],[libhiredis available])
            enable_hiredis="yes"
        fi
    fi

# libevent2
    enable_event2="yes"
    AC_ARG_ENABLE(event2,
	        AS_HELP_STRING([--enable-event2],[Enable libevent2 support]),
	        ,
	        [ enable_event2="yes"])
    AC_ARG_WITH(libevent2_includes,
            [  --with-libevent2-includes=DIR  libevent2 include directory],
            [with_libevent2_includes="$withval"],[with_libevent2_includes="no"])
    AC_ARG_WITH(libevent2_libraries,
            [  --with-libevent2-libraries=DIR    libevent2 library directory],
            [with_libevent2_libraries="$withval"],[with_libevent2_libraries="no"])

    if test "$enable_event2" = "yes"; then
        if test "$with_libevent2_includes" != "no"; then
            CPPFLAGS="${CPPFLAGS} -I${with_libevent2_includes}"
        fi

        AC_CHECK_HEADER("event2/listener.h",EVENT2="yes",EVENT2="no")
        if test "$EVENT2" = "yes"; then
            if test "$with_libevent2_libraries" != "no"; then
                LDFLAGS="${LDFLAGS}  -L${with_libevent2_libraries}"
            fi
            AC_CHECK_LIB(event, evconnlistener_enable,, EVENT2="no")
        fi
        if test "$EVENT2" = "no"; then
            echo
            echo "   ERROR!  libevent2 library not found"
            echo
            exit 1
        fi
        if test "$EVENT2" = "yes"; then
            AC_DEFINE([HAVE_LIBEVENT2],[1],[libevent2 available])
            enable_event2="yes"
        fi
    fi

# get cache line size
    AC_PATH_PROG(HAVE_GETCONF_CMD, getconf, "no")
    if test "$HAVE_GETCONF_CMD" != "no"; then
        CLS=$(getconf LEVEL1_DCACHE_LINESIZE)
        if [test "$CLS" != "" && test "$CLS" != "0"]; then
            AC_DEFINE_UNQUOTED([CLS],[${CLS}],[L1 cache line size])
        else
            AC_DEFINE([CLS],[64],[L1 cache line size])
        fi
    else
        AC_DEFINE([CLS],[64],[L1 cache line size])
    fi

# get revision
    if test -f ./revision; then
        REVISION=`cat ./revision`
        AC_DEFINE_UNQUOTED([REVISION],[${REVISION}],[Git revision])
    else
        AC_PATH_PROG(HAVE_GIT_CMD, git, "no")
        if test "$HAVE_GIT_CMD" != "no"; then
            if [ test -d .git ]; then
                REVISION=`git rev-parse --short HEAD`
                AC_DEFINE_UNQUOTED([REVISION],[${REVISION}],[Git revision])
            fi
        fi
    fi

AC_SUBST(CFLAGS)
AC_SUBST(LDFLAGS)
AC_SUBST(CPPFLAGS)

define([EXPAND_VARIABLE],
[$2=[$]$1
if test $prefix = 'NONE'; then
	prefix="/usr/local"
fi
while true; do
  case "[$]$2" in
    *\[$]* ) eval "$2=[$]$2" ;;
    *) break ;;
  esac
done
eval "$2=[$]$2$3"
])dnl EXPAND_VARIABLE

# mobster log dir
if test "$WINDOWS_PATH" = "yes"; then
  systemtype="`systeminfo | grep \"based PC\"`"
  case "$systemtype" in
    *x64*)
      e_winbase="C:\\\\Program Files (x86)\\\\Mobster"
      ;;
    *)
      e_winbase="C:\\\\Program Files\\\\Mobster"
      ;;
  esac

  e_sysconfdir="$e_winbase\\\\"
  e_sysconfrulesdir="$e_winbase\\\\rules\\\\"
  e_magic_file="$e_winbase\\\\magic.mgc"
  e_logdir="$e_winbase\\\\log"
  e_logfilesdir="$e_logdir\\\\files"
  e_logcertsdir="$e_logdir\\\\certs"
else
  EXPAND_VARIABLE(localstatedir, e_logdir, "/log/mobster/")
  EXPAND_VARIABLE(localstatedir, e_rundir, "/run/")
  EXPAND_VARIABLE(localstatedir, e_logfilesdir, "/log/mobster/files")
  EXPAND_VARIABLE(localstatedir, e_logcertsdir, "/log/mobster/certs")
  EXPAND_VARIABLE(sysconfdir, e_sysconfdir, "/mobster/")
  EXPAND_VARIABLE(sysconfdir, e_sysconfrulesdir, "/mobster/rules")
  EXPAND_VARIABLE(localstatedir, e_localstatedir, "/run/mobster")
fi
AC_SUBST(e_logdir)
AC_SUBST(e_rundir)
AC_SUBST(e_logfilesdir)
AC_SUBST(e_logcertsdir)
AC_SUBST(e_sysconfdir)
AC_SUBST(e_sysconfrulesdir)
AC_SUBST(e_localstatedir)
AC_DEFINE_UNQUOTED([CONFIG_DIR],["$e_sysconfdir"],[Our CONFIG_DIR])
AC_SUBST(e_magic_file)

EXPAND_VARIABLE(prefix, CONFIGURE_PREFIX)
EXPAND_VARIABLE(sysconfdir, CONFIGURE_SYSCONDIR)
EXPAND_VARIABLE(localstatedir, CONFIGURE_LOCALSTATEDIR)
AC_SUBST(CONFIGURE_PREFIX)
AC_SUBST(CONFIGURE_SYSCONDIR)
AC_SUBST(CONFIGURE_LOCALSTATEDIR)

AC_OUTPUT(Makefile src/Makefile)

MOBSTER_BUILD_CONF="Mobster Configuration:
  libjansson support:                      ${enable_jansson}
  hiredis support:                         ${enable_hiredis}
  LUA support:                             ${enable_lua}
  libluajit:                               ${enable_luajit}
  Debug output enabled:                    ${enable_debug}

Generic build parameters:
  Installation prefix:                     ${prefix}
  Configuration directory:                 ${e_sysconfdir}
  Log directory:                           ${e_logdir}

  --prefix                                 ${CONFIGURE_PREFIX}
  --sysconfdir                             ${CONFIGURE_SYSCONDIR}
  --localstatedir                          ${CONFIGURE_LOCALSTATEDIR}

  Host:                                    ${host}
  Compiler:                                ${CC} (exec name) / ${compiler} (real)
  GCC Protect enabled:                     ${enable_gccprotect}
  GCC march native enabled:                ${enable_gccmarch_native}
  GCC Profile enabled:                     ${enable_gccprofile}
  Position Independent Executable enabled: ${enable_pie}
  CFLAGS                                   ${CFLAGS}
  PCAP_CFLAGS                              ${PCAP_CFLAGS}
  SECCFLAGS                                ${SECCFLAGS}"

echo
echo "$MOBSTER_BUILD_CONF"
echo "printf(" >src/build-info.h
echo "$MOBSTER_BUILD_CONF" | sed -e 's/^/"/' | sed -e 's/$/\\n"/' >>src/build-info.h
echo ");" >>src/build-info.h

echo "
To build and install run 'make' and 'make install'."
